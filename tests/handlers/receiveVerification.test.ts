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
  RECEIVE_VERIFY_BATCH_CHUNKS,
  RECEIVE_VERIFY_PROGRESS_BYTES,
  RECEIVER_SILENCE_LIMIT_MS,
} from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { RatchetState } from "../../src/cryptography/ratchet";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type {
  HeldFileProgressNotice,
  HeldFileSettledNotice,
  MessageData,
  ReceiveChunk,
  ReceiveChunkStoreResult,
  ReceiveVerificationOutcome,
  ReceiveVerificationVerdict,
} from "../../src/db/types";
import type { ReceiveStorageError } from "../../src/handlers/handleReceiveMessage";
import type { CoverRuntime } from "../../src/handlers/coverRuntime";
import type { CoverJob, CoverJobSlot } from "../../src/handlers/coverScheduler";
import type { CoverCellContent } from "../../src/cryptography/coverCell";
import type { TransferWaitClock } from "../../src/handlers/reconcile";
import type { TransferFrameSource } from "../../src/handlers/handleSendMessage";

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
const { applyHeldFileSettled, enqueue } =
  await import("../../src/handlers/handleMessageQueueing");
const { claimRatchetGate, openRatchetGate, resetRatchetGate } =
  await import("../../src/handlers/ratchetGate");
const { allowClassicalOnlyReceiveForTests } =
  await import("../../src/handlers/ratchetPersist");
const { sealChunkClassicalOnlyForTests } =
  await import("../../src/handlers/messageChunkCrypto");
const { onReceiveStorageError } =
  await import("../../src/handlers/handleReceiveMessage");
const { releaseScheduledReceipts } =
  await import("../../src/handlers/coverTransfer");
const { waitForScheduledVerifiedDelivery, waitForVerifiedDelivery } =
  await import("../../src/handlers/handleSendMessage");
const {
  clearTransfer,
  markTransferComplete,
  noteTransferActivity,
  reportedCompletionCapMs,
} = await import("../../src/handlers/reconcile");

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
const notices: HeldFileSettledNotice[] = [];
// Progress reports the worker posts while it verifies, delivered to the queue
// through its onVerificationProgress seam; a test may also post its own.
const progressListeners = new Set<(notice: HeldFileProgressNotice) => void>();
const reportProgress = (notice: HeldFileProgressNotice): void => {
  for (const listener of [...progressListeners]) listener(notice);
};
const onVerificationProgress = (
  listener: (notice: HeldFileProgressNotice) => void,
) => {
  progressListeners.add(listener);
  return () => {
    progressListeners.delete(listener);
  };
};
const callWorker = async (
  method: string,
  args: unknown[],
): Promise<unknown> => {
  await import("../../src/db/db.worker");
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (message: unknown) => {
      const { notice, progress } = message as {
        notice?: HeldFileSettledNotice;
        progress?: HeldFileProgressNotice;
      };
      if (notice) {
        notices.push(structuredClone(notice));
        return;
      }
      if (progress) {
        reportProgress(structuredClone(progress));
        return;
      }
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

// Stall the worker's first batch read of one file's chunks: the read runs in
// its transaction at once, only its answer waits for release().
const stallFirstChunkRead = (rootHex: string) => {
  const proto = (
    globalThis as unknown as { IDBObjectStore: { prototype: IDBObjectStore } }
  ).IDBObjectStore.prototype;
  const getAll = proto.getAll;
  let hit = false;
  let released = false;
  const waiting: Array<() => void> = [];
  proto.getAll = function (
    this: IDBObjectStore,
    query?: IDBValidKey | IDBKeyRange | null,
    count?: number,
  ) {
    const request = getAll.call(this, query, count);
    const lower = query instanceof IDBKeyRange ? query.lower : undefined;
    if (
      hit ||
      this.name !== "chunks" ||
      !Array.isArray(lower) ||
      lower[0] !== rootHex
    )
      return request;
    hit = true;
    return new Proxy(request, {
      get(target, property) {
        if (property === "addEventListener")
          return (
            type: string,
            listener: (event: Event) => void,
            options?: AddEventListenerOptions,
          ) =>
            target.addEventListener(
              type,
              type === "success"
                ? (event: Event) => {
                    if (released) listener.call(target, event);
                    else waiting.push(() => listener.call(target, event));
                  }
                : listener,
              options,
            );
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    });
  } as typeof getAll;
  return {
    hit: () => hit,
    release: () => {
      released = true;
      for (const resume of waiting.splice(0)) resume();
    },
    restore: () => {
      proto.getAll = getAll;
    },
  };
};

// Worker-backed storage for the queue, with verification held at a gate the
// test opens. The real worker call is made at once (as production makes it),
// only its answer waits.
const storage = () => {
  const gate = deferred();
  const started = deferred();
  const settled = deferred<ReceiveVerificationOutcome>();
  const hashed = deferred<ReceiveVerificationVerdict>();
  const outcomes: ReceiveVerificationOutcome[] = [];
  let verifications = 0;
  return {
    gate,
    started,
    settled,
    hashed,
    outcomes,
    verifications: () => verifications,
    dependencies: {
      onVerificationProgress,
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
        outcomes.push(outcome);
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

const channel = (onSend?: (frameHex: string) => void) => {
  const sent: string[] = [];
  return {
    sent,
    channel: {
      label: "a6",
      readyState: "open",
      bufferedAmount: 0,
      send: (data: ArrayBuffer) => {
        const frame = uint8ArrayToHex(new Uint8Array(data).subarray(1));
        sent.push(frame);
        onSend?.(frame);
      },
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
  onSend?: (frameHex: string) => void,
) => {
  const queue: Uint8Array[] = [];
  const seen = new Set<string>();
  const draining = { value: false };
  const wire = channel(onSend);
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
    const position = () =>
      store
        .getState()
        .rooms.find((room) => room.id === ROOM)!
        .messages.findIndex(
          (message) => message.merkleRootHex === file.rootHex,
        );
    const before = position();
    // The app sees the reset at once, matching the dropped chunks on disk,
    // and the message keeps its place in the room's list.
    await waitFor(() => messageView(file.rootHex)?.savedSize === 0);
    expect(position()).toBe(before);
    expect(messageView(file.rootHex)?.totalSize).toBe(11);
    expect((await row(file.rootHex))?.savedSize).toBe(0);
  });

  test("a reconnect during verification completes the file without a second reconnect", async () => {
    quietConsole();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const before = edge();
    const closed = new AbortController();
    const oldLane = lane(file, before.epc, io.dependencies, closed.signal);
    oldLane.push(seal(before.alice, file.plaintexts[0], file.root));
    await io.started.promise;

    // The connection drops: its channel closes first, while its gate lease is
    // still current, so the run is not stopped and keeps hashing.
    closed.abort(new Error("channel closed"));
    // Then the old edge is torn down and the reconnect builds a new one,
    // whose sender resends the held last chunk.
    resetRatchetGate(ROOM, PEER);
    const after = edge();
    const newLane = lane(file, after.epc, io.dependencies);
    newLane.push(seal(after.alice, file.plaintexts[0], file.root));
    await waitFor(() => io.verifications() === 2);

    io.gate.resolve();
    await waitFor(() => io.outcomes.length === 2);
    // The old connection does not commit; the new one does, on this reconnect.
    expect([...io.outcomes].sort()).toEqual(["aborted", "complete"]);
    await waitFor(() => newLane.sent.includes(uint8ArrayToHex(file.hash)));
    expect(oldLane.sent).not.toContain(uint8ArrayToHex(file.hash));
    expect(messageView(file.rootHex)?.savedSize).toBe(8);
    expect((await row(file.rootHex))?.savedSize).toBe(8);
  });

  test("a sender that reconnects during a start-up verification gets receipts from then on", async () => {
    quietConsole();
    notices.length = 0;
    let offset = 0;
    const base = Date.now();
    const dateNow = spyOn(Date, "now").mockImplementation(() => base + offset);
    restores.push(() => dateNow.mockRestore());
    const file = await buildMessage(MessageType.ImagePNG, [8]);

    // The page that received the file went away before verifying it.
    const deadPage = {
      ...storage().dependencies,
      verifyReceivedFile: () =>
        new Promise<ReceiveVerificationVerdict>(() => {}),
    };
    const gone = new AbortController();
    const first = edge();
    const firstLane = lane(file, first.epc, deadPage, gone.signal);
    firstLane.push(seal(first.alice, file.plaintexts[0], file.root));
    await waitFor(() => firstLane.sent.length === 1);
    gone.abort(new Error("page closed"));
    resetRatchetGate(ROOM, PEER);
    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";

    // The next start verifies it without the sender; its first read stalls.
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore);
    await callWorker("getDBRoomMessageData", [ROOM]);
    await waitFor(() => stall.hit());
    // No sender, no channel: a report goes nowhere.
    reportProgress({ merkleRoot: file.rootHex, token, hashedBytes: 0 });
    expect(firstLane.sent).toHaveLength(1);

    // The sender reconnects and resends the held chunk: it joins the run.
    const io = storage();
    io.gate.resolve();
    const second = edge();
    const secondLane = lane(file, second.epc, io.dependencies);
    secondLane.push(seal(second.alice, file.plaintexts[0], file.root));
    await waitFor(() => io.verifications() === 1);
    expect(secondLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);

    // The read finishes 10 s later: the worker reports, the receipt is re-sent
    // to the reconnected sender, then the file completes.
    offset += 10_000;
    stall.release();
    await waitFor(() => secondLane.sent.includes(uint8ArrayToHex(file.hash)));
    expect(secondLane.sent).toEqual([
      uint8ArrayToHex(file.receipts[0]),
      uint8ArrayToHex(file.receipts[0]),
      uint8ArrayToHex(file.hash),
    ]);
    expect(firstLane.sent).toHaveLength(1);
  });

  test("a resent last chunk for an already verified file gets the final receipt without a second verification", async () => {
    quietConsole();
    notices.length = 0;
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    // The page that received it went away before verifying it.
    const gone = storage();
    const deadPage = {
      ...gone.dependencies,
      verifyReceivedFile: () =>
        new Promise<ReceiveVerificationVerdict>(() => {}),
    };
    const first = edge();
    const firstLane = lane(file, first.epc, deadPage);
    firstLane.push(seal(first.alice, file.plaintexts[0], file.root));
    await waitFor(() => firstLane.sent.length === 1);

    // The next start loads the room; the worker verifies the file on its own
    // and the app shows the outcome.
    await callWorker("getDBRoomMessageData", [ROOM]);
    await waitFor(() => notices.length === 1);
    expect(notices[0]).toMatchObject({
      merkleRoot: file.rootHex,
      outcome: "complete",
    });
    await applyHeldFileSettled(notices[0], store.dispatch);
    expect(messageView(file.rootHex)?.savedSize).toBe(8);

    // The sender's resume resends the last chunk: it is answered from the
    // recorded outcome, with the final receipt, and not verified again.
    const io = storage();
    const second = edge();
    const secondLane = lane(file, second.epc, io.dependencies);
    secondLane.push(seal(second.alice, file.plaintexts[0], file.root));
    await waitFor(() => secondLane.sent.length === 2);
    expect(secondLane.sent).toEqual([
      uint8ArrayToHex(file.receipts[0]),
      uint8ArrayToHex(file.hash),
    ]);
    expect(io.verifications()).toBe(0);
  });

  test("a failed verification start is reported as a storage failure", async () => {
    quietConsole();
    const io = storage();
    io.gate.resolve();
    // The start's lease write fails for lack of space.
    const proto = (
      globalThis as unknown as {
        IDBObjectStore: { prototype: { put: (...a: unknown[]) => unknown } };
      }
    ).IDBObjectStore.prototype;
    const put = proto.put;
    let armed = false;
    proto.put = function (this: { name: string }, ...args: unknown[]) {
      if (armed && this.name === "receiveActivity") {
        armed = false;
        throw new DOMException("injected", "QuotaExceededError");
      }
      return put.apply(this, args);
    };
    restores.push(() => {
      proto.put = put;
    });
    const dependencies = {
      ...io.dependencies,
      verifyReceivedFile: (merkleRoot: string, token: string) => {
        armed = true;
        return io.dependencies.verifyReceivedFile(merkleRoot, token);
      },
    };
    const errors = collectErrors();
    const { alice, epc } = edge();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    lane(file, epc, dependencies).push(
      seal(alice, file.plaintexts[0], file.root),
    );
    expect(await io.settled.promise).toBe("aborted");
    await waitFor(() => errors.length === 1);
    expect(errors.map((error) => error.code)).toEqual(["storage-failed"]);
  });

  test("the receiver re-sends its receipt on verification progress", async () => {
    // Just over RECEIVE_VERIFY_PROGRESS_BYTES of real bytes: the worker reports
    // progress once while it hashes.
    const lengths = Array.from({ length: 140 }, () => CHUNK_LEN);
    const file = await buildMessage(MessageType.ImagePNG, lengths);
    const { alice, epc } = edge();
    const io = storage();
    io.gate.resolve();
    const reports: HeldFileProgressNotice[] = [];
    restores.push(onVerificationProgress((notice) => reports.push(notice)));
    const fileLane = lane(file, epc, io.dependencies);
    // The channel queue holds at most 64 frames; feed it as it drains.
    for (const plaintext of file.plaintexts) {
      const frame = seal(alice, plaintext, file.root);
      while (!fileLane.push(frame))
        await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(await io.settled.promise).toBe("complete");
    await waitFor(() => fileLane.sent.includes(uint8ArrayToHex(file.hash)));

    expect(reports).toHaveLength(
      Math.floor(file.totalSize / RECEIVE_VERIFY_PROGRESS_BYTES),
    );
    // Every chunk receipt once, except the held chunk's (whichever chunk
    // completed the file): once when it was held, then once per progress
    // report. The final receipt only after the last of them.
    const counts = new Map<string, number>();
    for (const frame of fileLane.sent)
      counts.set(frame, (counts.get(frame) ?? 0) + 1);
    const repeated = [...counts].filter(([, count]) => count > 1);
    expect(repeated).toHaveLength(1);
    const [heldReceipt, sends] = repeated[0];
    expect(file.receipts.map(uint8ArrayToHex)).toContain(heldReceipt);
    expect(sends).toBe(1 + reports.length);
    expect(fileLane.sent.indexOf(uint8ArrayToHex(file.hash))).toBeGreaterThan(
      fileLane.sent.lastIndexOf(heldReceipt),
    );
    expect(counts.size).toBe(file.receipts.length + 1);
  }, 30_000);

  test("the receiver re-sends its receipt on verification progress, in scheduled mode", async () => {
    // Scheduled mode: the receipt rides a reverse cover control job, never the
    // message channel, so the cover cadence is the runtime's own.
    const { alice, epc } = edge();
    const enqueued: CoverJob[] = [];
    const sealed: CoverCellContent[] = [];
    const settles = new Map<string, () => void>();
    (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = {
      cellsPerLanePerCycle: () => 8,
      randomLaneLabel: () => `${"00".repeat(32)}~${"11".repeat(64)}`,
      sealCoverContent: (content: CoverCellContent) => {
        sealed.push(structuredClone(content));
        return new Uint8Array(8);
      },
      enqueue: (job: CoverJob) => {
        enqueued.push(job);
      },
      onJobSettled: (id: string, callback: () => void) => {
        settles.set(id, callback);
      },
      cancel: () => "not-found",
    } as unknown as CoverRuntime;
    restores.push(() => releaseScheduledReceipts(epc));
    const slot = {} as CoverJobSlot;
    // Run one cover slot of the newest control job, then settle it.
    const runSlot = async () => {
      const job = enqueued[enqueued.length - 1];
      await job.nextCell(slot);
      settles.get(job.id)!();
    };
    const tokensSealed = () =>
      sealed.flatMap((cell) =>
        cell.subtype === "chunk-receipts"
          ? cell.tokens.map((token) => uint8ArrayToHex(token))
          : [],
      );

    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const fileLane = lane(file, epc, io.dependencies);
    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    await waitFor(() => enqueued.length === 1);
    await runSlot();
    const receipt = uint8ArrayToHex(file.receipts[0]);
    expect(tokensSealed()).toEqual([receipt]);

    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";
    reportProgress({ merkleRoot: file.rootHex, token, hashedBytes: 8 });
    await waitFor(() => enqueued.length === 2);
    await runSlot();
    expect(tokensSealed()).toEqual([receipt, receipt]);
    expect(fileLane.sent).toEqual([]);

    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
  });

  test("a stalled verification sends nothing", async () => {
    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const fileLane = lane(file, epc, io.dependencies);
    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    await waitFor(() => fileLane.sent.length === 1);
    // No progress is reported, so time passing alone sends no receipt.
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(fileLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);
    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
  });

  test("no receipt is sent after a verification ends, is aborted or its message is deleted", async () => {
    quietConsole();
    const progressOf = (rootHex: string, token: string) => ({
      merkleRoot: rootHex,
      token,
      hashedBytes: 1,
    });
    const tokenOf = async (rootHex: string) =>
      (await row(rootHex))?.receiveVerification?.token ?? "";

    // While it runs, a report re-sends the receipt.
    const live = edge();
    const io = storage();
    const ended = await buildMessage(MessageType.ImagePNG, [8]);
    const endedLane = lane(ended, live.epc, io.dependencies);
    endedLane.push(seal(live.alice, ended.plaintexts[0], ended.root));
    await io.started.promise;
    const token = await tokenOf(ended.rootHex);
    reportProgress(progressOf(ended.rootHex, token));
    expect(endedLane.sent).toEqual([
      uint8ArrayToHex(ended.receipts[0]),
      uint8ArrayToHex(ended.receipts[0]),
    ]);
    // Once it has ended, a late report sends nothing.
    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
    await waitFor(() => endedLane.sent.length === 3);
    reportProgress(progressOf(ended.rootHex, token));
    expect(endedLane.sent).toHaveLength(3);
    resetRatchetGate(ROOM, PEER);

    // Aborted: the edge closes; reports for it send nothing.
    const closing = edge();
    const abortIo = storage();
    const aborted = await buildMessage(MessageType.ImagePNG, [8]);
    const closed = new AbortController();
    const abortedLane = lane(
      aborted,
      closing.epc,
      abortIo.dependencies,
      closed.signal,
    );
    abortedLane.push(seal(closing.alice, aborted.plaintexts[0], aborted.root));
    await abortIo.started.promise;
    const abortedToken = await tokenOf(aborted.rootHex);
    resetRatchetGate(ROOM, PEER);
    closed.abort(new Error("edge torn down"));
    reportProgress(progressOf(aborted.rootHex, abortedToken));
    expect(abortedLane.sent).toEqual([uint8ArrayToHex(aborted.receipts[0])]);
    abortIo.gate.resolve();
    expect(await abortIo.settled.promise).toBe("aborted");

    // Deleted: the message is removed while it is verified.
    const owner = edge();
    const deleteIo = storage();
    const deleted = await buildMessage(MessageType.ImagePNG, [8]);
    const deletedLane = lane(deleted, owner.epc, deleteIo.dependencies);
    deletedLane.push(seal(owner.alice, deleted.plaintexts[0], deleted.root));
    await deleteIo.started.promise;
    const deletedToken = await tokenOf(deleted.rootHex);
    await callWorker("deleteDBMessageData", [deleted.rootHex]);
    deleteIo.gate.resolve();
    await deleteIo.settled.promise;
    reportProgress(progressOf(deleted.rootHex, deletedToken));
    expect(deletedLane.sent).toEqual([uint8ArrayToHex(deleted.receipts[0])]);
  });
});

// ── the sender's completion wait against the receiver's emission ─────────────

// One clock for both sides. It moves only as the worker reads the held file
// (each batch read takes BATCH_MS), so the verification's length on it is the
// same on any machine.
const controllableClock = () => {
  let now = Date.now();
  let sequence = 0;
  const timers = new Map<number, { at: number; callback: () => void }>();
  const clock: TransferWaitClock = {
    now: () => now,
    setTimeout: (callback, ms) => {
      const id = ++sequence;
      timers.set(id, { at: now + ms, callback });
      return id;
    },
    clearTimeout: (id) => {
      timers.delete(id as number);
    },
  };
  return {
    clock,
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
    // Run every sender timer that is due, earliest first.
    fireDue: () => {
      for (;;) {
        const due = [...timers]
          .filter(([, timer]) => timer.at <= now)
          .sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) return;
        timers.delete(due[0]);
        due[1].callback();
      }
    },
  };
};

describe("the sender waits while its receiver verifies", () => {
  // 400 full chunks (about 23.6 MiB) in 25 batches of 1.26 s: the
  // verification takes 31.5 s, longer than the 30 s silence bound and inside
  // the sender's cap for this size (about 33 s).
  const CHUNKS = 400;
  const BATCH_MS = 1_260;

  const run = async (mode: "immediate" | "scheduled") => {
    const file = await buildMessage(
      MessageType.ImagePNG,
      Array.from({ length: CHUNKS }, () => CHUNK_LEN),
    );
    const { alice, epc } = edge();
    const time = controllableClock();
    const dateNow = spyOn(Date, "now").mockImplementation(() => time.now());
    restores.push(() => dateNow.mockRestore());
    const transferId = `a6-${mode}`;
    restores.push(() => clearTransfer(ROOM, PEER, transferId));

    // The sender's side of the fake channel: every frame for the transfer is
    // activity (immediate: a message on its channel; scheduled: what coverEdge
    // notes for an authenticated receipt), the final receipt completes it.
    const frameListeners = new Set<() => void>();
    const senderChannel: TransferFrameSource = {
      addEventListener: (_type, listener) => frameListeners.add(listener),
      removeEventListener: (_type, listener) => {
        frameListeners.delete(listener);
      },
    };
    const activityAt: number[] = [];
    let completedAt: number | undefined;
    const deliver = (final: boolean) => {
      activityAt.push(time.now());
      if (mode === "immediate")
        for (const listener of [...frameListeners]) listener();
      else noteTransferActivity(ROOM, PEER, transferId);
      if (final) {
        completedAt = time.now();
        markTransferComplete(ROOM, PEER, transferId);
      }
    };

    // Scheduled: the receiver's receipts ride control jobs of a cover
    // runtime, delivered as their slots run.
    const enqueued: CoverJob[] = [];
    const ran = new Set<CoverJob>();
    const settles = new Map<string, () => void>();
    let lanes = 0;
    if (mode === "scheduled") {
      (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = {
        cellsPerLanePerCycle: () => 8,
        randomLaneLabel: () =>
          `${(++lanes).toString(16).padStart(64, "0")}~${"11".repeat(64)}`,
        sealCoverContent: (content: CoverCellContent) => {
          if (
            (content.subtype === "receipt" ||
              content.subtype === "chunk-receipts") &&
            uint8ArrayToHex(content.merkleRoot) === file.rootHex
          )
            deliver(content.subtype === "receipt");
          return new Uint8Array(8);
        },
        enqueue: (job: CoverJob) => {
          enqueued.push(job);
        },
        onJobSettled: (id: string, callback: () => void) => {
          settles.set(id, callback);
        },
        cancel: () => "not-found",
      } as unknown as CoverRuntime;
      restores.push(() => releaseScheduledReceipts(epc));
    }
    const runSlots = async () => {
      for (;;) {
        const job = enqueued.find((candidate) => !ran.has(candidate));
        if (!job) return;
        ran.add(job);
        for (let cell = 0; cell < job.declaredCellCount; cell++)
          await job.nextCell({} as CoverJobSlot);
        settles.get(job.id)?.();
      }
    };

    // Each batch read of the held file takes BATCH_MS on the clock.
    const store = (
      globalThis as unknown as { IDBObjectStore: { prototype: IDBObjectStore } }
    ).IDBObjectStore.prototype;
    const getAll = store.getAll;
    let batches = 0;
    store.getAll = function (
      this: IDBObjectStore,
      query?: IDBValidKey | IDBKeyRange | null,
      count?: number,
    ) {
      const lower = query instanceof IDBKeyRange ? query.lower : undefined;
      if (
        this.name === "chunks" &&
        Array.isArray(lower) &&
        lower[0] === file.rootHex
      ) {
        batches += 1;
        time.advance(BATCH_MS);
        queueMicrotask(() => {
          time.fireDue();
          void runSlots();
        });
      }
      return getAll.call(this, query, count);
    } as typeof getAll;
    restores.push(() => {
      store.getAll = getAll;
    });

    const io = storage();
    io.gate.resolve();
    const startedAt = time.now();
    const waiting =
      mode === "immediate"
        ? waitForVerifiedDelivery(
            senderChannel,
            ROOM,
            PEER,
            transferId,
            file.totalSize,
            { clock: time.clock },
          )
        : waitForScheduledVerifiedDelivery(
            ROOM,
            PEER,
            transferId,
            file.totalSize,
            RECEIVER_SILENCE_LIMIT_MS,
            { clock: time.clock },
          );
    const finalHex = uint8ArrayToHex(file.hash);
    const fileLane = lane(file, epc, io.dependencies, undefined, (frame) =>
      deliver(frame === finalHex),
    );
    for (const plaintext of file.plaintexts) {
      const frame = seal(alice, plaintext, file.root);
      while (!fileLane.push(frame))
        await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(await io.settled.promise).toBe("complete");
    // The final receipt goes out at once (immediate) or in the next slots.
    for (let slot = 0; slot < 20 && completedAt === undefined; slot++) {
      time.advance(100);
      time.fireDue();
      await runSlots();
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    expect(await waiting).toBe(true);
    expect(batches).toBe(Math.ceil(CHUNKS / RECEIVE_VERIFY_BATCH_CHUNKS));
    expect(completedAt! - startedAt).toBeGreaterThan(RECEIVER_SILENCE_LIMIT_MS);
    expect(completedAt! - startedAt).toBeLessThan(
      reportedCompletionCapMs(file.totalSize, RECEIVER_SILENCE_LIMIT_MS),
    );
    // The receiver kept the sender's silence bound from expiring.
    const gaps = activityAt.map(
      (at, index) => at - (index === 0 ? startedAt : activityAt[index - 1]),
    );
    expect(Math.max(...gaps)).toBeLessThan(RECEIVER_SILENCE_LIMIT_MS);
  };

  test("the completion wait outlasts a verification longer than the silence bound, in immediate mode", async () => {
    await run("immediate");
  }, 120_000);

  test("the completion wait outlasts a verification longer than the silence bound, in scheduled mode", async () => {
    await run("scheduled");
  }, 120_000);
});
