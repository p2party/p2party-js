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
import { untilTurns } from "../db/fakeClock";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  METADATA_LEN,
  PROOF_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
  RECEIVE_VERIFY_BATCH_CHUNKS,
  RECEIVE_VERIFY_RECEIPT_INTERVAL_MS,
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
import type { NewChunk } from "../../src/db/types";
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
const { deleteMessageStateOnly, deleteRoom, setMessage, setRoom } =
  await import("../../src/reducers/roomSlice");
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
const { releaseScheduledReceipts, scheduledDeliveryTimeoutMs } =
  await import("../../src/handlers/coverTransfer");
const {
  OutboundMessage,
  sendScheduled,
  waitForTransferConfirmation,
  waitForVerifiedDelivery,
} = await import("../../src/handlers/handleSendMessage");
const {
  clearTransfer,
  hasChunkAcked,
  isTransferComplete,
  markChunkAcked,
  markTransferComplete,
  onTransferActivity,
  onTransferProgress,
  reportedCompletionCapMs,
} = await import("../../src/handlers/reconcile");
const { installCoverEdge, teardownCoverEdge, trackScheduledSend } =
  await import("../../src/handlers/coverEdge");
const { SparsePqHealingState } =
  await import("../../src/handlers/pqHealingRuntime");
const { sealCoverCell } = await import("../../src/cryptography/coverCell");

const ROOM = "00000000-0000-4000-8000-0000000000a6";
const PEER = "00000000-0000-4000-8000-0000000000a7";
// The receiver, as the sender of the wiring tests knows it.
const RECEIVER = "00000000-0000-4000-8000-0000000000a8";

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

// These tests wait in turns of the event loop and never in time.
//
// waitFor: until the condition holds, however many turns that takes
// (untilTurns says why there is no limit).
// flush: for work that has no condition to wait on ("nothing more is sent").
// What these tests wait for runs on the event loop and hashes on the
// runtime's WebCrypto threads, so a flush is FLUSH_ROUNDS round trips through
// both: one digest, then FLUSH_TURNS turns. A delete that nothing holds up
// answers within a dozen turns. It is a margin and not a proof: an assertion
// that something did happen waits for it with waitFor first.
const FLUSH_ROUNDS = 8;
const FLUSH_TURNS = 50;
const FLUSH_INPUT = new Uint8Array(64);
const waitFor = untilTurns;
const flush = async (): Promise<void> => {
  for (let round = 0; round < FLUSH_ROUNDS; round++) {
    await crypto.subtle.digest("SHA-512", FLUSH_INPUT);
    for (let turns = 0; turns < FLUSH_TURNS; turns++)
      await new Promise((resolve) => setImmediate(resolve));
  }
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
  let aborts = 0;
  return {
    gate,
    started,
    settled,
    hashed,
    outcomes,
    verifications: () => verifications,
    /** Detaches the worker has carried out. */
    aborts: () => aborts,
    dependencies: {
      onVerificationProgress,
      beforeRatchetCommit: async () => undefined,
      storeReceiveChunk: async (chunk: ReceiveChunk) =>
        (await callWorker("storeReceiveChunk", [
          chunk,
        ])) as ReceiveChunkStoreResult,
      verifyReceivedFile: async (
        merkleRoot: string,
        token: string,
        holder: string,
      ) => {
        verifications += 1;
        const verdict = callWorker("verifyReceivedFile", [
          merkleRoot,
          token,
          holder,
        ]);
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
        holder: string,
      ) => {
        const outcome = (await callWorker("settleReceivedFileVerification", [
          merkleRoot,
          token,
          commit,
          holder,
        ])) as ReceiveVerificationOutcome;
        outcomes.push(outcome);
        settled.resolve(outcome);
        return outcome;
      },
      abortReceivedFileVerification: async (
        merkleRoot: string,
        token: string,
        holder: string,
      ): Promise<undefined> => {
        await callWorker("abortReceivedFileVerification", [
          merkleRoot,
          token,
          holder,
        ]);
        aborts += 1;
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
    leaves,
    leafHashes,
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
    await flush();
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
    // Another message arrives after it, so it is not last in the list.
    const later = "e4".repeat(64);
    store.dispatch(
      setMessage({
        roomId: ROOM,
        merkleRootHex: later,
        sha512Hex: "e5".repeat(64),
        fromPeerId: PEER,
        chunkSize: 1,
        totalSize: 1,
        messageType: MessageType.Text,
        filename: "",
        channelLabel: "chat",
        timestamp: 2,
      }),
    );
    restores.push(() =>
      store.dispatch(
        deleteMessageStateOnly({ roomId: ROOM, merkleRootHex: later }),
      ),
    );
    const roots = () =>
      store
        .getState()
        .rooms.find((room) => room.id === ROOM)!
        .messages.map((message) => message.merkleRootHex);
    const before = roots();
    expect(before.indexOf(file.rootHex)).toBeLessThan(before.indexOf(later));
    fileLane.push(seal(alice, file.plaintexts[1], file.root));
    await io.started.promise;
    // While it is verified, the held last chunk is not counted yet.
    expect(messageView(file.rootHex)?.savedSize).toBe(8);
    io.gate.resolve();
    expect(await io.settled.promise).toBe("integrity");
    // The app sees the reset at once, matching the dropped chunks on disk,
    // and the message keeps its place in the room's list.
    await waitFor(() => messageView(file.rootHex)?.savedSize === 0);
    expect(roots()).toEqual(before);
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

  test("one holder's abort does not abort the attempt for the others", async () => {
    quietConsole();
    const io = storage();
    io.gate.resolve();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    // The file's first read waits, so the attempt is still running when the
    // old edge leaves.
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore);
    const before = edge();
    const closed = new AbortController();
    const oldLane = lane(file, before.epc, io.dependencies, closed.signal);
    oldLane.push(seal(before.alice, file.plaintexts[0], file.root));
    await waitFor(() => stall.hit());

    // The edge is torn down and a reconnect's copy of the held chunk joins
    // the attempt; then the old edge's channel closes, and it detaches.
    resetRatchetGate(ROOM, PEER);
    const after = edge();
    const newLane = lane(file, after.epc, io.dependencies);
    newLane.push(seal(after.alice, file.plaintexts[0], file.root));
    await waitFor(() => io.verifications() === 2);
    closed.abort(new Error("channel closed"));
    await waitFor(() => io.aborts() === 1);
    stall.release();

    // The new edge completes the file; only the old one is aborted.
    await waitFor(() => io.outcomes.length === 2);
    expect([...io.outcomes].sort()).toEqual(["aborted", "complete"]);
    await waitFor(() => newLane.sent.includes(uint8ArrayToHex(file.hash)));
    expect(oldLane.sent).not.toContain(uint8ArrayToHex(file.hash));
    expect((await row(file.rootHex))?.savedSize).toBe(8);
  });

  test("a holder that joins after the last one left gets a verdict, not an abort", async () => {
    quietConsole();
    const io = storage();
    io.gate.resolve();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    // The file's first read waits, so the run is still going when its only
    // holder leaves.
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore, stall.release);
    const before = edge();
    const closed = new AbortController();
    const oldLane = lane(file, before.epc, io.dependencies, closed.signal);
    oldLane.push(seal(before.alice, file.plaintexts[0], file.root));
    await untilTurns(() => stall.hit());

    // A reconnect's copy of the held chunk is stored while the run has its
    // holder. Before that copy asks for the verdict, the old edge is gone and
    // its channel closes: the run has no holder left and is told to stop,
    // which it only sees once its read returns.
    resetRatchetGate(ROOM, PEER);
    const after = edge();
    const newLane = lane(file, after.epc, {
      ...io.dependencies,
      verifyReceivedFile: async (merkleRoot, token, holder) => {
        closed.abort(new Error("channel closed"));
        await untilTurns(() => io.aborts() === 1);
        return io.dependencies.verifyReceivedFile(merkleRoot, token, holder);
      },
    });
    newLane.push(seal(after.alice, file.plaintexts[0], file.root));
    await untilTurns(() => io.verifications() === 2);
    stall.release();

    // The new edge did not leave, so it is owed a verdict: the file is
    // verified again from the start and the new edge completes it.
    await untilTurns(() => io.outcomes.includes("complete"));
    await untilTurns(() => newLane.sent.includes(uint8ArrayToHex(file.hash)));
    expect(oldLane.sent).not.toContain(uint8ArrayToHex(file.hash));
    expect((await row(file.rootHex))?.savedSize).toBe(8);
  });

  test("a copy that arrives while a left verification is ending gets a verdict", async () => {
    quietConsole();
    const io = storage();
    io.gate.resolve();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore, stall.release);
    const before = edge();
    const closed = new AbortController();
    const oldLane = lane(file, before.epc, io.dependencies, closed.signal);
    oldLane.push(seal(before.alice, file.plaintexts[0], file.root));
    await untilTurns(() => stall.hit());

    // The old edge is torn down and its channel closes: the run has no
    // holder left and is told to stop.
    resetRatchetGate(ROOM, PEER);
    closed.abort(new Error("channel closed"));
    await untilTurns(() => io.aborts() === 1);

    // A reconnect's copy of the held chunk arrives while that run is ending.
    // It is not refused over the lease the run still holds: it waits for the
    // run to end.
    const after = edge();
    const newLane = lane(file, after.epc, io.dependencies);
    newLane.push(seal(after.alice, file.plaintexts[0], file.root));
    for (let turns = 0; turns < 200; turns++)
      await new Promise((resolve) => setImmediate(resolve));
    expect(io.verifications()).toBe(1);
    stall.release();

    // Then the file is verified again and this copy completes it, without
    // the sender sending it once more.
    await untilTurns(() => io.outcomes.includes("complete"));
    expect(io.verifications()).toBe(2);
    await untilTurns(() => newLane.sent.includes(uint8ArrayToHex(file.hash)));
    expect(oldLane.sent).not.toContain(uint8ArrayToHex(file.hash));
    expect((await row(file.rootHex))?.savedSize).toBe(8);
  });

  test("a connection that does not hold a run is answered without waiting for it", async () => {
    quietConsole();
    const io = storage();
    io.gate.resolve();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore, stall.release);
    const { alice, epc } = edge();
    const only = lane(file, epc, io.dependencies);
    only.push(seal(alice, file.plaintexts[0], file.root));
    await untilTurns(() => stall.hit());
    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";
    expect(token).not.toBe("");

    // A connection that left an earlier run of this attempt settles while
    // the run that replaced it is still reading: it has nothing to commit
    // and nothing to wait for.
    let answered: unknown = "pending";
    void callWorker("settleReceivedFileVerification", [
      file.rootHex,
      token,
      false,
      "an-earlier-connection",
    ]).then((outcome) => {
      answered = outcome;
    });
    await untilTurns(() => answered !== "pending");
    expect(answered).toBe("aborted");
    expect(io.outcomes).toEqual([]);

    // The run is untouched: its own holder completes the file.
    stall.release();
    await untilTurns(() => io.outcomes.includes("complete"));
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
    await callWorker("getDBRoomMessageData", [ROOM, { verifyHeld: true }]);
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
    await callWorker("getDBRoomMessageData", [ROOM, { verifyHeld: true }]);
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
      verifyReceivedFile: (
        merkleRoot: string,
        token: string,
        holder: string,
      ) => {
        armed = true;
        return io.dependencies.verifyReceivedFile(merkleRoot, token, holder);
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
    // 140 full chunks (8.67 MB) in 9 batch reads of 1.2 s: the worker reports
    // once, at the last batch (past 8 MiB and past the interval), and the
    // page re-sends the held chunk's receipt for it.
    const lengths = Array.from({ length: 140 }, () => CHUNK_LEN);
    const file = await buildMessage(MessageType.ImagePNG, lengths);
    batchClock(file.rootHex, 1_200);
    const { alice, epc } = edge();
    const io = storage();
    io.gate.resolve();
    const reports: HeldFileProgressNotice[] = [];
    restores.push(onVerificationProgress((notice) => reports.push(notice)));
    const fileLane = lane(file, epc, io.dependencies);
    await feed(fileLane, alice, file);
    expect(await io.settled.promise).toBe("complete");
    await waitFor(() => fileLane.sent.includes(uint8ArrayToHex(file.hash)));

    expect(reports).toHaveLength(1);
    // Every chunk receipt once, except the held chunk's (whichever chunk
    // completed the file): once when it was held, then once for the report.
    // The final receipt only after it.
    const counts = new Map<string, number>();
    for (const frame of fileLane.sent)
      counts.set(frame, (counts.get(frame) ?? 0) + 1);
    const repeated = [...counts].filter(([, count]) => count > 1);
    expect(repeated).toHaveLength(1);
    const [heldReceipt, sends] = repeated[0];
    expect(file.receipts.map(uint8ArrayToHex)).toContain(heldReceipt);
    expect(sends).toBe(2);
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
    const time = batchClock(file.rootHex, 0);
    const fileLane = lane(file, epc, io.dependencies);
    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    await waitFor(() => enqueued.length === 1);
    await runSlot();
    const receipt = uint8ArrayToHex(file.receipts[0]);
    expect(tokensSealed()).toEqual([receipt]);

    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";
    time.advance(RECEIVE_VERIFY_RECEIPT_INTERVAL_MS);
    reportProgress({ merkleRoot: file.rootHex, token, hashedBytes: 8 });
    await waitFor(() => enqueued.length === 2);
    await runSlot();
    expect(tokensSealed()).toEqual([receipt, receipt]);
    expect(fileLane.sent).toEqual([]);

    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
  });

  test("at most one receipt per interval is sent during verification", async () => {
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const time = batchClock(file.rootHex, 0);
    const { alice, epc } = edge();
    const io = storage();
    const fileLane = lane(file, epc, io.dependencies);
    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    await waitFor(() => fileLane.sent.length === 1);
    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";

    // A report every second for 25 s, each with more bytes hashed: a fast
    // device. The held chunk's receipt went out at 0 s.
    const sentAt: number[] = [];
    for (let second = 1; second <= 25; second++) {
      time.advance(1_000);
      const before = fileLane.sent.length;
      reportProgress({ merkleRoot: file.rootHex, token, hashedBytes: second });
      if (fileLane.sent.length > before) sentAt.push(second);
    }
    expect(RECEIVE_VERIFY_RECEIPT_INTERVAL_MS).toBe(10_000);
    expect(sentAt).toEqual([10, 20]);
    const receipt = uint8ArrayToHex(file.receipts[0]);
    expect(fileLane.sent).toEqual([receipt, receipt, receipt]);

    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
  });

  test("a stalled verification sends nothing", async () => {
    // Time runs ahead for the page: the clock, and every page timer of a
    // second or more, which runs as soon as it would be due. A receipt sent
    // from a page timer would go out here.
    const time = batchClock("", 0);
    const pending: Array<{ at: number; run: () => void; every?: number }> = [];
    const timers = globalThis as unknown as {
      setTimeout: typeof setTimeout;
      setInterval: typeof setInterval;
    };
    const realTimeout = timers.setTimeout;
    const realInterval = timers.setInterval;
    const hold =
      (every: boolean) =>
      (callback: (...args: unknown[]) => void, ms = 0, ...args: unknown[]) => {
        if (ms < 1_000)
          return (every ? realInterval : realTimeout)(callback, ms, ...args);
        pending.push({
          at: time.now() + ms,
          run: () => callback(...args),
          ...(every ? { every: ms } : {}),
        });
        return 0 as unknown as ReturnType<typeof setTimeout>;
      };
    timers.setTimeout = hold(false) as unknown as typeof setTimeout;
    timers.setInterval = hold(true) as unknown as typeof setInterval;
    restores.push(() => {
      timers.setTimeout = realTimeout;
      timers.setInterval = realInterval;
    });

    const { alice, epc } = edge();
    const io = storage();
    const file = await buildMessage(MessageType.ImagePNG, [8]);
    const fileLane = lane(file, epc, io.dependencies);
    fileLane.push(seal(alice, file.plaintexts[0], file.root));
    await io.started.promise;
    await waitFor(() => fileLane.sent.length === 1);
    // A minute passes and nothing is reported: no receipt goes out.
    for (let second = 0; second < 60; second++) {
      time.advance(1_000);
      for (const timer of [...pending])
        if (timer.at <= time.now()) {
          if (timer.every) timer.at += timer.every;
          else pending.splice(pending.indexOf(timer), 1);
          timer.run();
        }
      await Promise.resolve();
    }
    await flush();
    expect(fileLane.sent).toEqual([uint8ArrayToHex(file.receipts[0])]);
    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
  });

  test("no receipt is sent after a verification ends, is aborted or its message is deleted", async () => {
    quietConsole();
    // A manual clock: each report below comes a full interval after the last
    // receipt and with more bytes hashed, so only the end of the run can
    // keep it off the wire.
    const time = batchClock("", 0);
    let hashed = 0;
    const reportFor = (rootHex: string, token: string) => {
      time.advance(RECEIVE_VERIFY_RECEIPT_INTERVAL_MS);
      reportProgress({ merkleRoot: rootHex, token, hashedBytes: ++hashed });
    };
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
    reportFor(ended.rootHex, token);
    expect(endedLane.sent).toEqual([
      uint8ArrayToHex(ended.receipts[0]),
      uint8ArrayToHex(ended.receipts[0]),
    ]);
    // Once it has ended, a late report sends nothing.
    io.gate.resolve();
    expect(await io.settled.promise).toBe("complete");
    await waitFor(() => endedLane.sent.length === 3);
    reportFor(ended.rootHex, token);
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
    reportFor(aborted.rootHex, abortedToken);
    expect(abortedLane.sent).toEqual([uint8ArrayToHex(aborted.receipts[0])]);
    abortIo.gate.resolve();
    expect(await abortIo.settled.promise).toBe("aborted");

    // Deleted: the message is removed (by the delete the app's calls use)
    // while its file is being read. The run stops, and its next batch, due a
    // full interval later with more hashed, reports nothing.
    const owner = edge();
    const deleteIo = storage();
    deleteIo.gate.resolve();
    const deleted = await buildMessage(MessageType.ImagePNG, [8]);
    const stall = stallFirstChunkRead(deleted.rootHex);
    restores.push(stall.restore);
    const deletedLane = lane(deleted, owner.epc, deleteIo.dependencies);
    deletedLane.push(seal(owner.alice, deleted.plaintexts[0], deleted.root));
    await waitFor(() => stall.hit());
    let removed = false;
    const deleting = callWorker("deleteReceiveTransfer", [
      deleted.rootHex,
    ]).then(() => {
      removed = true;
    });
    // The delete reaches the running verification, stops it and waits for
    // its read to end.
    await flush();
    expect(removed).toBe(false);
    time.advance(RECEIVE_VERIFY_RECEIPT_INTERVAL_MS);
    stall.release();
    await deleting;
    expect(await deleteIo.settled.promise).toBe("aborted");
    await waitFor(() => deletedLane.sent.length === 1);
    await flush();
    expect(deletedLane.sent).toEqual([uint8ArrayToHex(deleted.receipts[0])]);
  });
});

// ── clocks and the sender's side ─────────────────────────────────────────────

// Push every chunk of a file, as the channel queue (at most 64 frames) drains.
const feed = async (
  fileLane: ReturnType<typeof lane>,
  alice: RatchetState,
  file: Awaited<ReturnType<typeof buildMessage>>,
) => {
  for (const plaintext of file.plaintexts) {
    const frame = seal(alice, plaintext, file.root);
    while (!fileLane.push(frame)) await flush();
  }
};

// One clock for the page, the worker and the sender. Date.now reads it. It
// moves when the worker reads one of `rootHex`'s batches (`batchMs` each) or
// when a test advances it, so a verification's length on it is the same on
// any machine. Sender timers armed on it fire when it moves.
const batchClock = (rootHex: string, batchMs: number) => {
  let now = Date.now();
  let sequence = 0;
  let batches = 0;
  const timers = new Map<number, { at: number; callback: () => void }>();
  const moved: Array<() => void> = [];
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
  const afterMove = () => {
    for (;;) {
      const due = [...timers]
        .filter(([, timer]) => timer.at <= now)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      timers.delete(due[0]);
      due[1].callback();
    }
    for (const listener of moved) listener();
  };
  const dateNow = spyOn(Date, "now").mockImplementation(() => now);
  restores.push(() => dateNow.mockRestore());
  const proto = (
    globalThis as unknown as { IDBObjectStore: { prototype: IDBObjectStore } }
  ).IDBObjectStore.prototype;
  const getAll = proto.getAll;
  proto.getAll = function (
    this: IDBObjectStore,
    query?: IDBValidKey | IDBKeyRange | null,
    count?: number,
  ) {
    const lower = query instanceof IDBKeyRange ? query.lower : undefined;
    if (
      this.name === "chunks" &&
      Array.isArray(lower) &&
      lower[0] === rootHex
    ) {
      batches += 1;
      now += batchMs;
      queueMicrotask(afterMove);
    }
    return getAll.call(this, query, count);
  } as typeof getAll;
  restores.push(() => {
    proto.getAll = getAll;
  });
  return {
    clock,
    now: () => now,
    batches: () => batches,
    advance: (ms: number) => {
      now += ms;
      afterMove();
    },
    onMove: (listener: () => void) => {
      moved.push(listener);
    },
  };
};

// The sender's side of an immediate transfer: every frame the receiver sends
// on the transfer's channel is a `message` event there (what
// waitForVerifiedDelivery listens to); the final receipt completes it, as the
// sender's receipt handler does.
const immediateSender = (
  time: ReturnType<typeof batchClock>,
  transferId: string,
  finalHex: string,
) => {
  const listeners = new Set<() => void>();
  const activityAt: number[] = [];
  // An open channel; only its "message" events are ever dispatched.
  const channel = {
    readyState: "open",
    addEventListener: (type: string, listener: () => void) => {
      if (type === "message") listeners.add(listener);
    },
    removeEventListener: (type: string, listener: () => void) => {
      if (type === "message") listeners.delete(listener);
    },
  } as unknown as TransferFrameSource;
  return {
    channel,
    activityAt,
    deliver: (frameHex: string) => {
      activityAt.push(time.now());
      for (const listener of [...listeners]) listener();
      if (frameHex === finalHex)
        markTransferComplete(ROOM, RECEIVER, transferId);
    },
  };
};

const pqState = (amInitiator: boolean) =>
  new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: amInitiator ? "local" : "remote",
    amInitiator,
    now: 0,
  });

// The sender's real scheduled edge (installCoverEdge, tracking the transfer)
// and the receiver's way onto it: each cover cell the receiver's control jobs
// produce is sealed as the receiver's CoverRuntime seals one (its responder
// context, its outbound counter from 0) and handed to the sender's inbound
// cover path, which authenticates it, attributes it to the tracked transfer
// and only then wakes the sender's wait.
const scheduledSender = (
  file: Awaited<ReturnType<typeof buildMessage>>,
  transferId: string,
  schedule: {
    readonly coverCadenceMs: number;
    readonly coverLanes: number;
    readonly coverFramesPerCell: number;
    readonly coverDurationEpochs: number;
  } = {
    coverCadenceMs: 400,
    coverLanes: 2,
    coverFramesPerCell: 2,
    coverDurationEpochs: 1,
  },
) => {
  const senderPq = pqState(true);
  const receiverPq = pqState(false);
  const epc = {
    roomId: ROOM,
    withPeerId: RECEIVER,
    withPeerPublicKey: "a8".repeat(32),
    connectionState: "connected",
    pqHealingState: senderPq,
    ratchetState: initRatchet(
      rand(32),
      true,
      initRatchet(rand(32), false, null, module).dhSelfPub,
      module,
    ),
    createDataChannel: (label: string) => {
      const lane = {
        label,
        readyState: "open",
        bufferedAmount: 0,
        send: () => undefined,
        close: () => {
          lane.readyState = "closed";
        },
        addEventListener: () => undefined,
      };
      return lane as unknown as IRTCDataChannel;
    },
  } as unknown as IRTCPeerConnection;
  const chunkOf = new Map(
    file.receipts.map((token, index) => [uint8ArrayToHex(token), index]),
  );
  const policy = {
    ...DEFAULT_ROOM_POLICY_V1,
    coverMode: "scheduled" as const,
    ...schedule,
  };
  installCoverEdge({
    epc,
    roomId: ROOM,
    policy,
    policyHash: new Uint8Array(32),
    amInitiator: true,
    module,
    receiptDependencies: {
      getChunk: async (root, token) =>
        root === file.rootHex && chunkOf.has(token)
          ? {
              transferId,
              merkleRoot: root,
              receiptToken: token,
              chunkIndex: chunkOf.get(token)!,
            }
          : undefined,
      persist: async () => true,
    },
  });
  trackScheduledSend(epc, ROOM, RECEIVER, file.rootHex, transferId);
  restores.push(() => {
    teardownCoverEdge(epc);
    senderPq.destroy();
    receiverPq.destroy();
  });
  // The jobs a scheduled send enqueues on this edge. No lane ever opens here,
  // so the scheduler never runs them: a test pulls their cells itself.
  const jobs: CoverJob[] = [];
  const runtime = epc.coverRuntime!;
  const enqueue = runtime.enqueue.bind(runtime);
  runtime.enqueue = (job) => {
    jobs.push(job);
    return enqueue(job);
  };
  let counter = 0n;
  let refused = 0;
  return {
    epc,
    policy,
    jobs,
    /** The message step a scheduled send takes on this edge. */
    ratchetStep: async () => {
      const stepped = ratchetEncrypt(epc.ratchetState!, module);
      const live = senderPq.currentMessageContext();
      return {
        messageKey: stepped.messageKey,
        header: stepped.header,
        pqContext: {
          rootKey: Uint8Array.from(live.rootKey),
          binding: Uint8Array.from(live.binding),
          rootSuite: live.rootSuite,
          epoch: live.epoch,
        },
      };
    },
    refused: () => refused,
    deliverCell: (content: CoverCellContent) => {
      const context = receiverPq.currentMessageContext();
      const frame = sealCoverCell({
        module,
        rootSuite: context.rootSuite,
        rootKey: context.rootKey,
        binding: context.binding,
        direction: "responder-to-initiator",
        keyEpoch: context.epoch,
        counter,
        content,
      });
      counter += 1n;
      if (!epc.coverRuntime!.processInboundCoverCell(frame)) refused += 1;
    },
  };
};

// The sender's staged message for `file`: its rows carry each cell's
// metadata, proof, chunk and receipt token as the sender staged them.
const outboundMessage = (
  file: Awaited<ReturnType<typeof buildMessage>>,
  transferId: string,
) => {
  const hashHex = uint8ArrayToHex(file.hash);
  const rows = new Map<number, NewChunk>(
    file.plaintexts.map((plaintext, chunkIndex) => [
      chunkIndex,
      {
        transferId,
        hash: hashHex,
        merkleRoot: file.rootHex,
        chunkIndex,
        leafHash: uint8ArrayToHex(file.leafHashes[chunkIndex]),
        receiptToken: uint8ArrayToHex(file.receipts[chunkIndex]),
        metadata: plaintext.slice(0, METADATA_LEN).buffer as ArrayBuffer,
        merkleProof: plaintext.slice(METADATA_LEN, METADATA_LEN + PROOF_LEN)
          .buffer as ArrayBuffer,
        data: plaintext.slice(METADATA_LEN + PROOF_LEN).buffer as ArrayBuffer,
      },
    ]),
  );
  const message = new OutboundMessage({
    transferId,
    hashHex,
    merkleRoot: file.root,
    totalChunks: file.plaintexts.length,
    chunkHashes: file.leaves.slice(
      0,
      file.plaintexts.length * crypto_hash_sha512_BYTES,
    ),
    merkleModule: module,
    store: {
      get: async (_transferId, index) => {
        const row = rows.get(index);
        return row ? structuredClone(row) : undefined;
      },
      put: async (chunk) => {
        rows.set(chunk.chunkIndex, structuredClone(chunk));
      },
    },
  });
  restores.push(() => message.close());
  return message;
};

// A receiver-side cover runtime whose control jobs run as the clock moves.
const receiverCoverRuntime = (
  epc: IRTCPeerConnection,
  time: ReturnType<typeof batchClock>,
  deliverCell: (content: CoverCellContent) => void,
) => {
  const enqueued: CoverJob[] = [];
  const ran = new Set<CoverJob>();
  const settles = new Map<string, () => void>();
  let lanes = 0;
  (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = {
    cellsPerLanePerCycle: () => 8,
    randomLaneLabel: () =>
      `${(++lanes).toString(16).padStart(64, "0")}~${"11".repeat(64)}`,
    sealCoverContent: (content: CoverCellContent) => {
      if (content.subtype !== "dummy") deliverCell(content);
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
  time.onMove(() => void runSlots());
  return runSlots;
};

describe("the sender waits while its receiver verifies", () => {
  // 400 full chunks (about 23.6 MiB), verified in 25 batches.
  const CHUNKS = 400;
  // A scheduled room whose one-lane cycle holds the whole file: F×D = 400 at
  // the 25 ms slot floor. Its delivery idle budget, and with it the sender's
  // silence bound while the receiver verifies, is 40.025 s.
  const SCHEDULE = {
    coverCadenceMs: 10_000,
    coverLanes: 1,
    coverFramesPerCell: CHUNKS,
    coverDurationEpochs: 1,
  };
  // Immediate: 25 batches of 1.26 s, 31.5 s from the last chunk receipt,
  // past the 30 s silence bound and inside the cap (about 33 s). Scheduled:
  // the receipts reach the sender in the first batch's slots, and the
  // remaining 24 batches of 1.72 s (41.28 s) run past the 40.025 s bound and
  // inside the cap (about 43 s).
  const BATCH_MS = { immediate: 1_260, scheduled: 1_720 } as const;
  const silenceMs = {
    immediate: RECEIVER_SILENCE_LIMIT_MS,
    scheduled: Math.max(
      RECEIVER_SILENCE_LIMIT_MS,
      scheduledDeliveryTimeoutMs(SCHEDULE),
    ),
  } as const;
  const fullFile = () =>
    buildMessage(
      MessageType.ImagePNG,
      Array.from({ length: CHUNKS }, () => CHUNK_LEN),
    );

  const run = async (mode: "immediate" | "scheduled") => {
    const file = await fullFile();
    const { alice, epc } = edge();
    const time = batchClock(file.rootHex, BATCH_MS[mode]);
    const transferId = `a6-${mode}`;
    restores.push(() => clearTransfer(ROOM, RECEIVER, transferId));
    const finalHex = uint8ArrayToHex(file.hash);

    let completedAt: number | undefined;
    restores.push(
      onTransferProgress(ROOM, RECEIVER, transferId, () => {
        if (
          completedAt === undefined &&
          isTransferComplete(ROOM, RECEIVER, transferId)
        )
          completedAt = time.now();
      }),
    );
    const immediate = immediateSender(time, transferId, finalHex);
    const scheduledActivityAt: number[] = [];
    let scheduled: ReturnType<typeof scheduledSender> | undefined;
    let runSlots: () => Promise<void> = async () => {};
    if (mode === "scheduled") {
      scheduled = scheduledSender(file, transferId, SCHEDULE);
      runSlots = receiverCoverRuntime(epc, time, scheduled.deliverCell);
      restores.push(
        onTransferActivity(ROOM, RECEIVER, transferId, () =>
          scheduledActivityAt.push(time.now()),
        ),
      );
    }

    const io = storage();
    io.gate.resolve();
    const message = outboundMessage(file, transferId);
    const allAcknowledged = () =>
      message.allRealsAcknowledged((index) =>
        hasChunkAcked(ROOM, RECEIVER, transferId, index),
      );
    const chunkOf = new Map(
      file.receipts.map((token, index) => [uint8ArrayToHex(token), index]),
    );
    const sentAt = time.now();
    // When the sender's wait for the receiver's verification began.
    let waitStartedAt: number | undefined;
    let batchesAtStart = -1;
    let waiting: Promise<boolean> | undefined;
    let deliver = (frameHex: string): void => immediate.deliver(frameHex);
    if (mode === "immediate") {
      // The sender's first pass read every cell once.
      for (let index = 0; index < message.totalChunks; index++)
        await message.read(index);
      // The sender's receipt handler acknowledges each chunk receipt; at the
      // receipt that acknowledges the last one, the sender's next
      // confirmation round starts.
      deliver = (frameHex) => {
        const index = chunkOf.get(frameHex);
        if (index !== undefined)
          markChunkAcked(ROOM, RECEIVER, transferId, index);
        immediate.deliver(frameHex);
        if (waiting === undefined && allAcknowledged()) {
          waitStartedAt = time.now();
          batchesAtStart = time.batches();
          waiting = waitForTransferConfirmation(
            message,
            immediate.channel,
            ROOM,
            RECEIVER,
            0,
            undefined,
            time.clock,
          ).then((confirmation) => {
            expect(confirmation.verifying).toBe(true);
            return confirmation.done;
          });
        }
      };
    } else {
      // The real scheduled send on the sender's real cover edge. Its delivery
      // wait is the scheduler's: it pulls every cell of the job, and runs out
      // once every chunk is acknowledged and no cell is left to send.
      waiting = sendScheduled(
        ROOM,
        "chat",
        scheduled!.policy,
        [{ peerId: RECEIVER, epc: scheduled!.epc }],
        message,
        module,
        undefined,
        undefined,
        [scheduled!.epc],
        {
          waitForGate: async () => undefined,
          ratchetStep: scheduled!.ratchetStep,
          waitForDelivery: async (options) => {
            const job = scheduled!.jobs[0];
            for (let cell = 0; cell <= message.totalChunks; cell++)
              if ((await job.nextCell({} as CoverJobSlot)) === null) break;
            await new Promise<void>((resolve) => {
              const check = () => {
                if (!allAcknowledged() && !options.isComplete()) return;
                unsubscribe();
                resolve();
              };
              const unsubscribe = onTransferProgress(
                ROOM,
                RECEIVER,
                transferId,
                check,
              );
              check();
            });
            waitStartedAt = time.now();
            batchesAtStart = time.batches();
            return options.isComplete();
          },
          resumeWaitMs: 1,
          clock: time.clock,
        },
      ).then(({ outcomes }) => {
        expect(outcomes).toEqual([{ peerId: RECEIVER, status: "delivered" }]);
        return true;
      });
    }
    const fileLane = lane(file, epc, io.dependencies, undefined, (frame) =>
      deliver(frame),
    );
    await feed(fileLane, alice, file);
    expect(await io.settled.promise).toBe("complete");
    // The final receipt goes out at once (immediate) or in the next slots.
    for (let slot = 0; slot < 20 && completedAt === undefined; slot++) {
      time.advance(100);
      await runSlots();
      await flush();
    }

    expect(await waiting).toBe(true);
    expect(time.batches()).toBe(
      Math.ceil(CHUNKS / RECEIVE_VERIFY_BATCH_CHUNKS),
    );
    // The sender's wait for the verification began once every chunk was
    // acknowledged (before the first batch, immediate; in its slots,
    // scheduled), and lasted past its silence bound and inside its cap.
    expect(batchesAtStart).toBe(mode === "immediate" ? 0 : 1);
    expect(silenceMs.scheduled).toBe(40_025);
    expect(completedAt! - waitStartedAt!).toBeGreaterThan(silenceMs[mode]);
    expect(completedAt! - waitStartedAt!).toBeLessThan(
      reportedCompletionCapMs(file.totalSize, silenceMs[mode]),
    );
    // The receiver kept the sender's silence bound from expiring: every gap
    // between frames the sender attributed to the transfer is under it.
    const activityAt =
      mode === "immediate" ? immediate.activityAt : scheduledActivityAt;
    const gaps = activityAt.map(
      (at, index) => at - (index === 0 ? sentAt : activityAt[index - 1]),
    );
    expect(Math.max(...gaps)).toBeLessThan(RECEIVER_SILENCE_LIMIT_MS);
    if (scheduled) {
      expect(scheduled.refused()).toBe(0);
      expect(fileLane.sent).toEqual([]);
    }
  };

  test("the completion wait outlasts a verification longer than the silence bound, in immediate mode", async () => {
    await run("immediate");
  }, 120_000);

  test("the completion wait outlasts a verification longer than the silence bound, in scheduled mode", async () => {
    await run("scheduled");
  }, 120_000);

  test("no receipt is sent when verification has not advanced", async () => {
    const file = await fullFile();
    const { alice, epc } = edge();
    const time = batchClock(file.rootHex, 0);
    const transferId = "a6-stuck";
    restores.push(() => clearTransfer(ROOM, RECEIVER, transferId));
    const sender = immediateSender(
      time,
      transferId,
      uint8ArrayToHex(file.hash),
    );
    // The verification is stuck on its first read.
    const stall = stallFirstChunkRead(file.rootHex);
    restores.push(stall.restore);

    const io = storage();
    io.gate.resolve();
    const startedAt = time.now();
    let endedAt: number | undefined;
    const waiting = waitForVerifiedDelivery(
      sender.channel,
      ROOM,
      RECEIVER,
      transferId,
      file.totalSize,
      { clock: time.clock },
    ).then((done) => {
      endedAt = time.now();
      return done;
    });
    const fileLane = lane(file, epc, io.dependencies, undefined, (frame) =>
      sender.deliver(frame),
    );
    await feed(fileLane, alice, file);
    await waitFor(() => stall.hit());
    const token = (await row(file.rootHex))?.receiveVerification?.token ?? "";

    // Reports that show nothing hashed since the last receipt, every 5 s:
    // none goes on the wire, and the sender's wait ends at its silence bound,
    // well before its cap.
    for (let step = 0; step < 10 && endedAt === undefined; step++) {
      time.advance(5_000);
      reportProgress({ merkleRoot: file.rootHex, token, hashedBytes: 0 });
      await flush();
    }
    expect(await waiting).toBe(false);
    expect(endedAt! - startedAt).toBeGreaterThanOrEqual(
      RECEIVER_SILENCE_LIMIT_MS,
    );
    expect(endedAt! - startedAt).toBeLessThan(
      reportedCompletionCapMs(file.totalSize, RECEIVER_SILENCE_LIMIT_MS),
    );
    expect(fileLane.sent).toHaveLength(CHUNKS);
    expect(new Set(fileLane.sent).size).toBe(CHUNKS);

    stall.release();
    expect(await io.settled.promise).toBe("complete");
  }, 120_000);
});
