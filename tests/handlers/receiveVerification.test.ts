// Whole-file verification as the receive queue drives it: the real queueing
// layer, receive handler and db.worker handler (over fake-indexeddb) on real
// sealed frames. Only the worker's verification call is wrapped, so a test can
// hold a file "being verified" open while other things happen on the edge.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { createHash } from "node:crypto";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import { initRatchet, ratchetEncrypt } from "../../src/cryptography/ratchet";
import { getMerkleProof, getMerkleRoot } from "../../src/cryptography/merkle";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { createChunkReceiptToken } from "../../src/utils/receiptToken";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  METADATA_LEN,
  PROOF_LEN,
} from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { RatchetState } from "../../src/cryptography/ratchet";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type {
  MessageData,
  ReceiveChunk,
  ReceiveChunkStoreResult,
  ReceiveVerificationOutcome,
  ReceiveVerificationVerdict,
} from "../../src/db/types";
import type { ReceiveStorageError } from "../../src/handlers/handleReceiveMessage";

// Process-wide state this file changes, restored in afterAll so the rest of
// the run sees what it saw before.
const globals = globalThis as unknown as {
  indexedDB: IDBFactory;
  postMessage?: unknown;
  localStorage?: unknown;
};
const indexedDBBefore = globals.indexedDB;
const postMessageBefore = Object.getOwnPropertyDescriptor(
  globalThis,
  "postMessage",
);
const localStorageBefore = Object.getOwnPropertyDescriptor(
  globalThis,
  "localStorage",
);

// The Redux store reads localStorage at module initialisation; install the
// same stand-in as the neighbouring handler tests before importing it.
const memory = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage ??= {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

const { store } = await import("../../src/store");
const { deleteRoom, setRoom } = await import("../../src/reducers/roomSlice");
const { DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy");
const { normalizeRoomCapability } = await import("../../src/roomInvite");
const { enqueue } = await import("../../src/handlers/handleMessageQueueing");
const { claimRatchetGate, openRatchetGate, resetRatchetGate } =
  await import("../../src/handlers/ratchetGate");
const { allowClassicalOnlyReceiveForTests } =
  await import("../../src/handlers/ratchetPersist");
const { sealChunkClassicalOnlyForTests } =
  await import("../../src/handlers/messageChunkCrypto");
const { onReceiveStorageError } =
  await import("../../src/handlers/handleReceiveMessage");

const ROOM = "00000000-0000-4000-8000-0000000000a6";
const PEER = "00000000-0000-4000-8000-0000000000a7";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
  store.dispatch(
    setRoom({
      url: normalizeRoomCapability("a6".repeat(32)),
      id: ROOM,
      rtcConfig: {},
      policy: DEFAULT_ROOM_POLICY_V1,
    }),
  );
});

// ── the real worker, replies routed by id so calls may overlap ───────────────

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}
let nextId = 1;
const pendingReplies = new Map<number, (reply: WorkerResponse) => void>();
const callWorker = async (
  method: string,
  args: unknown[],
): Promise<unknown> => {
  await import("../../src/db/db.worker");
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (message: unknown) => {
      const reply = structuredClone(message) as WorkerResponse;
      pendingReplies.get(reply.id)?.(reply);
      pendingReplies.delete(reply.id);
    };
  const id = nextId++;
  const reply = new Promise<WorkerResponse>((resolve) =>
    pendingReplies.set(id, resolve),
  );
  await (
    globalThis as unknown as { onmessage: (e: MessageEvent) => Promise<void> }
  ).onmessage({ data: structuredClone({ id, method, args }) } as MessageEvent);
  const { result, error } = await reply;
  if (error !== undefined) throw new Error(String(error));
  return result;
};

const deferred = <T = void>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

const waitFor = async (condition: () => boolean): Promise<void> => {
  for (let attempt = 0; attempt < 400 && !condition(); attempt++)
    await new Promise((resolve) => setTimeout(resolve, 5));
  expect(condition()).toBe(true);
};

// Worker-backed storage for the queue, with verification held at a gate the
// test opens. The real worker call is made at once (as production makes it),
// only its answer waits.
const storage = () => {
  const gate = deferred();
  const started = deferred();
  const settled = deferred<ReceiveVerificationOutcome>();
  const hashed = deferred<ReceiveVerificationVerdict>();
  let verifications = 0;
  return {
    gate,
    started,
    settled,
    hashed,
    verifications: () => verifications,
    dependencies: {
      persistRatchetState: async () => undefined,
      storeReceiveChunk: async (chunk: ReceiveChunk) =>
        (await callWorker("storeReceiveChunk", [
          chunk,
        ])) as ReceiveChunkStoreResult,
      verifyReceivedFile: async (merkleRoot: string, token: string) => {
        verifications += 1;
        const verdict = callWorker("verifyReceivedFile", [merkleRoot, token]);
        void verdict.then((value) =>
          hashed.resolve(value as ReceiveVerificationVerdict),
        );
        started.resolve();
        await gate.promise;
        return (await verdict) as ReceiveVerificationVerdict;
      },
      settleReceivedFileVerification: async (
        merkleRoot: string,
        token: string,
        commit: boolean,
      ) => {
        const outcome = (await callWorker("settleReceivedFileVerification", [
          merkleRoot,
          token,
          commit,
        ])) as ReceiveVerificationOutcome;
        settled.resolve(outcome);
        return outcome;
      },
      abortReceivedFileVerification: async (
        merkleRoot: string,
        token: string,
      ): Promise<undefined> => {
        await callWorker("abortReceivedFileVerification", [merkleRoot, token]);
        return undefined;
      },
      closeReceiveFile: async (merkleRoot: string) => {
        await callWorker("closeReceiveFile", [merkleRoot]);
      },
    },
  };
};

// ── sealed messages on an opted-in classical edge ────────────────────────────

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

// A message of `lengths.length` chunks; its metadata claims `claimedHash` or
// the SHA-512 of its real bytes.
const buildMessage = async (
  messageType: number,
  lengths: number[],
  claimedHash?: Uint8Array,
) => {
  const padded = lengths.map(() => rand(CHUNK_LEN));
  const leaves = new Uint8Array(
    Math.max(2, lengths.length) * crypto_hash_sha512_BYTES,
  );
  const leafHashes = padded.map((data) => hashMerkleLeafWasm(data, module));
  leafHashes.forEach((leaf, i) => leaves.set(leaf, i * leaf.length));
  if (lengths.length === 1)
    leaves.set(
      hashMerkleLeafWasm(rand(CHUNK_LEN), module),
      leafHashes[0].length,
    );
  const root = await getMerkleRoot(leaves, module);
  const totalSize = lengths.reduce((sum, length) => sum + length, 0);
  const real = createHash("sha512");
  padded.forEach((data, i) => real.update(data.subarray(0, lengths[i])));
  const hash = claimedHash ?? Uint8Array.from(real.digest());
  const plaintexts: Uint8Array[] = [];
  const receipts: Uint8Array[] = [];
  for (let i = 0; i < lengths.length; i++) {
    const plaintext = new Uint8Array(DECRYPTED_LEN);
    plaintext.set(
      serializeMetadata({
        schemaVersion: 1,
        messageType,
        hash,
        totalSize,
        date: new Date(1),
        name: messageType === MessageType.Text ? "" : "a6.bin",
        chunkStartIndex: 0,
        chunkEndIndex: lengths[i],
        chunkIndex: i,
      }),
    );
    plaintext.set(
      await getMerkleProof(leaves, leafHashes[i], module, PROOF_LEN),
      METADATA_LEN,
    );
    plaintext.set(padded[i], METADATA_LEN + PROOF_LEN);
    plaintexts.push(plaintext);
    receipts.push(await createChunkReceiptToken(root, i, leafHashes[i]));
  }
  return {
    root,
    rootHex: uint8ArrayToHex(root),
    hash,
    totalSize,
    plaintexts,
    receipts,
  };
};

const channel = () => {
  const sent: string[] = [];
  return {
    sent,
    channel: {
      label: "a6",
      readyState: "open",
      bufferedAmount: 0,
      send: (data: ArrayBuffer) =>
        sent.push(uint8ArrayToHex(new Uint8Array(data).subarray(1))),
    } as unknown as IRTCDataChannel,
  };
};

const edge = () => {
  const seed = rand(32);
  const bob = initRatchet(seed, false, null, module);
  const alice = initRatchet(Uint8Array.from(seed), true, bob.dhSelfPub, module);
  const lease = claimRatchetGate(ROOM, PEER);
  const epc = {
    withPeerId: PEER,
    withPeerPublicKey: "a7".repeat(32),
    ratchetState: bob,
    messageKeyCache: new Map<string, Uint8Array>(),
    ratchetGateLease: lease,
  } as unknown as IRTCPeerConnection;
  allowClassicalOnlyReceiveForTests(epc);
  openRatchetGate(ROOM, PEER, lease);
  return { alice, epc };
};

const seal = (alice: RatchetState, plaintext: Uint8Array, root: Uint8Array) => {
  const { messageKey, header } = ratchetEncrypt(alice, module);
  return sealChunkClassicalOnlyForTests(
    messageKey,
    header,
    plaintext,
    root,
    module,
  );
};

const api = {
  dispatch: store.dispatch,
  getState: store.getState,
} as unknown as BaseQueryApi;

// One message channel's receive queue on the edge.
const lane = (
  message: Awaited<ReturnType<typeof buildMessage>>,
  epc: IRTCPeerConnection,
  dependencies: ReturnType<typeof storage>["dependencies"],
  signal?: AbortSignal,
) => {
  const queue: Uint8Array[] = [];
  const seen = new Set<string>();
  const draining = { value: false };
  const wire = channel();
  return {
    sent: wire.sent,
    push: (frame: Uint8Array) =>
      enqueue(
        frame,
        queue,
        seen,
        draining,
        api,
        ROOM,
        PEER,
        "chat",
        message.rootHex,
        message.root,
        wire.channel,
        epc,
        module,
        signal,
        dependencies,
      ),
  };
};

const messageView = (rootHex: string) =>
  store
    .getState()
    .rooms.find((room) => room.id === ROOM)
    ?.messages.find((message) => message.merkleRootHex === rootHex);

const row = async (rootHex: string) =>
  (await callWorker("getDBMessageData", [rootHex])) as MessageData | undefined;

const restores: Array<() => void> = [];
beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});
afterEach(() => {
  while (restores.length > 0) restores.pop()!();
  resetRatchetGate(ROOM, PEER);
});
afterAll(() => {
  store.dispatch(deleteRoom(ROOM));
  globals.indexedDB = indexedDBBefore;
  if (postMessageBefore)
    Object.defineProperty(globalThis, "postMessage", postMessageBefore);
  else delete globals.postMessage;
  if (localStorageBefore)
    Object.defineProperty(globalThis, "localStorage", localStorageBefore);
  else delete globals.localStorage;
});

const quietConsole = () => {
  const errorLog = spyOn(console, "error").mockImplementation(() => {});
  restores.push(() => errorLog.mockRestore());
};

const collectErrors = (): ReceiveStorageError[] => {
  const errors: ReceiveStorageError[] = [];
  restores.push(onReceiveStorageError((error) => errors.push(error)));
  return errors;
};

describe("a received file is verified outside the edge's receive lock", () => {
  test("other frames on the edge are handled while a file is being verified", async () => {
    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const text = await buildMessage(MessageType.Text, [5]);
    const fileLane = lane(file, epc, io.dependencies);
    const textLane = lane(text, epc, io.dependencies);

    expect(fileLane.push(seal(alice, file.plaintexts[0], file.root))).toBe(
      true,
    );
    await io.started.promise;
    // The file's chunk is acknowledged as held; the file is not complete.
    await waitFor(() => fileLane.sent.length === 1);
    expect(fileLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);

    // With the file still being verified, a chat message on the same edge is
    // decrypted, stored, acknowledged and shown complete.
    expect(textLane.push(seal(alice, text.plaintexts[0], text.root))).toBe(
      true,
    );
    await waitFor(() => textLane.sent.length === 2);
    expect(textLane.sent).toEqual([
      uint8ArrayToHex(text.receipts[0]),
      uint8ArrayToHex(text.hash),
    ]);
    expect(messageView(text.rootHex)?.savedSize).toBe(5);
    expect(messageView(file.rootHex)?.savedSize ?? 0).toBe(0);

    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
    // Only now is the file complete and its final receipt sent.
    await waitFor(() => fileLane.sent.length === 2);
    expect(fileLane.sent[1]).toBe(uint8ArrayToHex(file.hash));
    expect(messageView(file.rootHex)?.savedSize).toBe(8);
  });

  test("teardown during verification does not complete the file", async () => {
    quietConsole();
    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const channelClosed = new AbortController();
    const fileLane = lane(file, epc, io.dependencies, channelClosed.signal);

    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    // The edge is torn down: its gate lease is retired and its channels close.
    resetRatchetGate(ROOM, PEER);
    channelClosed.abort(new Error("edge torn down"));
    io.gate.resolve();

    expect(await io.settled.promise).toBe("aborted");
    expect(fileLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);
    expect(messageView(file.rootHex)?.savedSize ?? 0).toBe(0);
    // Not complete, and left for the next copy of its chunk to verify again.
    const stored = await row(file.rootHex);
    expect(stored?.savedSize).toBe(0);
    expect(stored?.receiveVerification).toBeDefined();
    expect(io.verifications()).toBe(1);
  });

  test("a file that verified after its edge went away is not completed", async () => {
    quietConsole();
    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const channelClosed = new AbortController();
    const fileLane = lane(file, epc, io.dependencies, channelClosed.signal);

    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    // The worker has finished hashing, and the file matches...
    expect(await io.hashed.promise).toBe("match");
    // ...but the edge is torn down before the verdict is committed.
    resetRatchetGate(ROOM, PEER);
    channelClosed.abort(new Error("edge torn down"));
    io.gate.resolve();

    expect(await io.settled.promise).toBe("aborted");
    expect(fileLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);
    const stored = await row(file.rootHex);
    expect(stored?.savedSize).toBe(0);
    expect(stored?.receiveVerification).toBeDefined();
  });

  test("the sender gets no final receipt for a file that failed verification", async () => {
    quietConsole();
    const { alice, epc } = edge();
    const io = storage();
    io.gate.resolve();
    // The file's bytes do not hash to the whole-file hash its message claims.
    const file = await buildMessage(
      MessageType.ImagePNG,
      [8, 3],
      rand(crypto_hash_sha512_BYTES),
    );
    const errors = collectErrors();
    const fileLane = lane(file, epc, io.dependencies);

    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    fileLane.push(seal(alice, file.plaintexts[1], file.root));
    expect(await io.settled.promise).toBe("integrity");
    // Both chunks were acknowledged as stored; the message-hash receipt that
    // completes the transfer never went out.
    await waitFor(() => fileLane.sent.length === 2);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fileLane.sent).toEqual(file.receipts.map(uint8ArrayToHex));
    expect(fileLane.sent).not.toContain(uint8ArrayToHex(file.hash));
    expect(errors.map((error) => error.code)).toEqual(["integrity"]);
  });

  test("progress resets when a file fails verification", async () => {
    quietConsole();
    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(
      MessageType.ImagePNG,
      [8, 3],
      rand(crypto_hash_sha512_BYTES),
    );
    const fileLane = lane(file, epc, io.dependencies);

    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await waitFor(() => messageView(file.rootHex)?.savedSize === 8);
    fileLane.push(seal(alice, file.plaintexts[1], file.root));
    await io.started.promise;
    // While it is verified, the held last chunk is not counted yet.
    expect(messageView(file.rootHex)?.savedSize).toBe(8);
    io.gate.resolve();
    expect(await io.settled.promise).toBe("integrity");
    // The app sees the reset at once, matching the dropped chunks on disk.
    await waitFor(() => messageView(file.rootHex)?.savedSize === 0);
    expect(messageView(file.rootHex)?.totalSize).toBe(11);
    expect((await row(file.rootHex))?.savedSize).toBe(0);
  });
});
