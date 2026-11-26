import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

// Process-wide state this file changes, restored in afterAll.
const indexedDBBefore = (globalThis as unknown as { indexedDB: IDBFactory })
  .indexedDB;
const postMessageBefore = Object.getOwnPropertyDescriptor(
  globalThis,
  "postMessage",
);
afterAll(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    indexedDBBefore;
  if (postMessageBefore)
    Object.defineProperty(globalThis, "postMessage", postMessageBefore);
  else delete (globalThis as { postMessage?: unknown }).postMessage;
});
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

import { createHash } from "node:crypto";

import {
  assertReceivedFileIntact,
  handleReceiveMessage,
  onReceiveStorageError,
  ReceiveIntegrityError,
  settleHeldFile,
  storeReceiveChunkFailClosed,
  verifyHeldFile,
  type ReceiveStorageError,
} from "../../src/handlers/handleReceiveMessage";
import {
  createDatabaseClient,
  type DatabaseWorkerPort,
} from "../../src/db/api";
import { sendReceiveFrameReceipt } from "../../src/handlers/handleMessageQueueing";
import { allowClassicalOnlyReceiveForTests } from "../../src/handlers/ratchetPersist";
import * as chunkCrypto from "../../src/handlers/messageChunkCrypto";
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
  MAX_REPORTED_RECEIVE_STORAGE_ERRORS,
  METADATA_LEN,
  PROOF_LEN,
} from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  RatchetHeader,
  RatchetState,
} from "../../src/cryptography/ratchet";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type {
  ReceiveChunk,
  ReceiveChunkStoreResult,
  ReceiveVerificationOutcome,
  ReceiveVerificationVerdict,
} from "../../src/db/types";

const storedChunk = (): Omit<ReceiveChunk, "data"> => ({
  schemaVersion: 1,
  roomId: "room-1",
  fromPeerId: "peer-1",
  channelLabel: "chat",
  timestamp: 1,
  merkleRoot: "ab".repeat(64),
  hash: "cd".repeat(64),
  filename: "",
  messageType: 1,
  chunkIndex: 0,
  mimeType: "text/plain",
  leafHash: "ef".repeat(64),
  realLen: 4,
  totalSize: 4,
  storage: "indexeddb",
});

describe("receive storage durability boundary", () => {
  test("a worker failure yields drop semantics and wipes the owned real-byte copy", async () => {
    const realChunk = Uint8Array.of(1, 2, 3, 4);
    let clonedBeforeFailure: Uint8Array | undefined;
    const errorLog = spyOn(console, "error").mockImplementation(() => {});

    try {
      const result = await storeReceiveChunkFailClosed(
        storedChunk(),
        realChunk,
        async (chunk) => {
          clonedBeforeFailure = Uint8Array.from(new Uint8Array(chunk.data));
          throw new Error("injected storage fault");
        },
      );

      expect(result).toBeNull();
      expect(Array.from(clonedBeforeFailure ?? [])).toEqual([1, 2, 3, 4]);
      expect(Array.from(realChunk)).toEqual([0, 0, 0, 0]);
    } finally {
      errorLog.mockRestore();
    }
  });
});

// ── a storage failure is surfaced, never acknowledged ─────────────────────────
//
// These drive the real receive handler on real sealed frames, and store through
// the real db.worker onmessage handler over fake-indexeddb: the seam between the
// worker's result and the handler's receipt decision is exercised, not mocked.

const ROOM = "room-a5";
const PEER = "peer-a5";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}

let nextWorkerId = 1;
const callWorker = async (
  method: string,
  args: unknown[],
): Promise<WorkerResponse> => {
  await import("../../src/db/db.worker");
  const id = nextWorkerId++;
  let captured: WorkerResponse | undefined;
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (message: unknown) => {
      captured = structuredClone(message) as WorkerResponse;
    };
  const handler = (
    globalThis as unknown as { onmessage: (e: MessageEvent) => Promise<void> }
  ).onmessage;
  await handler({
    data: structuredClone({ id, method, args }),
  } as MessageEvent);
  if (!captured || captured.id !== id)
    throw new Error(`worker did not respond to message id ${id}`);
  return captured;
};

// The same contract as src/db/api.ts: a posted `error` rejects, else resolves.
const workerStore = async (
  chunk: ReceiveChunk,
): Promise<ReceiveChunkStoreResult> => {
  const reply = await callWorker("storeReceiveChunk", [chunk]);
  if (reply.error !== undefined) throw new Error(String(reply.error));
  return reply.result as ReceiveChunkStoreResult;
};

// The worker's verification calls, reached the same way.
const workerCall =
  <T>(method: string) =>
  async (...args: unknown[]): Promise<T> => {
    const reply = await callWorker(method, args);
    if (reply.error !== undefined) throw new Error(String(reply.error));
    return reply.result as T;
  };
const workerVerification = {
  verifyReceivedFile:
    workerCall<ReceiveVerificationVerdict>("verifyReceivedFile"),
  settleReceivedFileVerification: workerCall<ReceiveVerificationOutcome>(
    "settleReceivedFileVerification",
  ),
  abortReceivedFileVerification: workerCall<undefined>(
    "abortReceivedFileVerification",
  ),
  closeReceiveFile: workerCall<undefined>("closeReceiveFile"),
};

// Verify and settle a held file as the queueing layer does, edge current.
const finishHeld = async (
  result: Awaited<ReturnType<typeof handleReceiveMessage>>,
  root: Uint8Array,
) => {
  const merkleRoot = uint8ArrayToHex(root);
  const token = result.verification!;
  const verdict = await verifyHeldFile(
    merkleRoot,
    token,
    undefined,
    () => true,
    workerVerification,
  );
  return settleHeldFile(
    {
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRoot,
      filename: result.filename,
      totalSize: result.totalSize,
      chunkIndex: result.chunkIndex,
    },
    token,
    verdict,
    true,
    workerVerification,
  );
};

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

// A one-chunk message of `realLen` bytes under a two-leaf Merkle tree. Its
// metadata carries the SHA-512 of those bytes unless `claimedHash` overrides it.
const buildMessage = async (
  messageType: number,
  realLen: number,
  claimedHash?: Uint8Array,
) => {
  const data = rand(CHUNK_LEN);
  const leaves = new Uint8Array(2 * crypto_hash_sha512_BYTES);
  const leaf = hashMerkleLeafWasm(data, module);
  leaves.set(leaf, 0);
  leaves.set(hashMerkleLeafWasm(rand(CHUNK_LEN), module), leaf.length);
  const root = await getMerkleRoot(leaves, module);
  const proof = await getMerkleProof(leaves, leaf, module, PROOF_LEN);
  const plaintext = new Uint8Array(DECRYPTED_LEN);
  plaintext.set(
    serializeMetadata({
      schemaVersion: 1,
      messageType,
      hash:
        claimedHash ??
        Uint8Array.from(
          createHash("sha512").update(data.subarray(0, realLen)).digest(),
        ),
      totalSize: realLen,
      date: new Date(1),
      name: messageType === MessageType.Text ? "" : "a5.bin",
      chunkStartIndex: 0,
      chunkEndIndex: realLen,
      chunkIndex: 0,
    }),
  );
  plaintext.set(proof, METADATA_LEN);
  plaintext.set(data, METADATA_LEN + PROOF_LEN);
  const rootedReceipt = await createChunkReceiptToken(root, 0, leaf);
  return { root, plaintext, rootedReceipt };
};

const edgePair = () => {
  const seed = rand(32);
  const bob = initRatchet(seed, false, null, module);
  const alice = initRatchet(Uint8Array.from(seed), true, bob.dhSelfPub, module);
  const epc = {
    withPeerId: PEER,
    withPeerPublicKey: "aa".repeat(32),
    ratchetState: bob,
    messageKeyCache: new Map<string, Uint8Array>(),
  } as unknown as IRTCPeerConnection;
  // A PQ-less edge must opt into the test-only classical receive path.
  allowClassicalOnlyReceiveForTests(epc);
  return { alice, epc };
};

// Seal under the raw classical key, for the opted-in PQ-less test edge. A
// concurrent change moves that path from sealChunk's optional PQ context to an
// explicit test-only sealer; use whichever this tree has.
type ClassicalSeal = (
  messageKey: Uint8Array,
  header: RatchetHeader,
  chunk: Uint8Array,
  merkleRoot: Uint8Array,
  module: LibCrypto,
) => Uint8Array;
const sealChunk: ClassicalSeal =
  (chunkCrypto as unknown as { sealChunkClassicalOnlyForTests?: ClassicalSeal })
    .sealChunkClassicalOnlyForTests ??
  (chunkCrypto.sealChunk as unknown as ClassicalSeal);

// Every (re)transmission is a fresh ratchet step, as a real sender's would be.
const seal = (
  alice: RatchetState,
  plaintext: Uint8Array,
  root: Uint8Array,
): Uint8Array => {
  const { messageKey, header } = ratchetEncrypt(alice, module);
  return sealChunk(messageKey, header, plaintext, root, module);
};

const receive = (
  frame: Uint8Array,
  epc: IRTCPeerConnection,
  root: Uint8Array,
) =>
  handleReceiveMessage(frame, ROOM, "chat", epc, root, module, undefined, {
    persistRatchetState: async () => undefined,
    storeReceiveChunk: workerStore,
  });

// The receipt the queueing layer would put on the wire for this result.
const wireReceipt = (
  result: Awaited<ReturnType<typeof handleReceiveMessage>>,
): Uint8Array => {
  const sent: Uint8Array[] = [];
  const channel = {
    readyState: "open",
    send: (data: ArrayBuffer) => sent.push(new Uint8Array(data)),
  } as unknown as IRTCDataChannel;
  expect(sendReceiveFrameReceipt(result, channel)).toBe(true);
  expect(sent).toHaveLength(1);
  return sent[0].subarray(1);
};

const navigatorDescriptor = Object.getOwnPropertyDescriptor(
  globalThis,
  "navigator",
);
const installStorage = (storage: Record<string, unknown>): void => {
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { storage },
  });
};

describe("receive storage failure is surfaced and not acknowledged", () => {
  const restores: Array<() => void> = [];
  beforeEach(() => {
    (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
      new IDBFactory();
  });
  afterEach(() => {
    while (restores.length > 0) restores.pop()!();
    if (navigatorDescriptor)
      Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
    else delete (globalThis as { navigator?: unknown }).navigator;
  });

  // Make the next `count` writes to the chunks store fail as a full disk does.
  const failChunkWrites = (count: number, name = "QuotaExceededError") => {
    const proto = (
      globalThis as unknown as {
        IDBObjectStore: { prototype: { add: (...a: unknown[]) => unknown } };
      }
    ).IDBObjectStore.prototype;
    const add = proto.add;
    let remaining = count;
    proto.add = function (this: { name: string }, ...args: unknown[]) {
      if (this.name === "chunks" && remaining > 0) {
        remaining -= 1;
        throw new DOMException("injected storage fault", name);
      }
      return add.apply(this, args);
    };
    restores.push(() => {
      proto.add = add;
    });
  };

  const collectErrors = (): ReceiveStorageError[] => {
    const errors: ReceiveStorageError[] = [];
    restores.push(onReceiveStorageError((error) => errors.push(error)));
    return errors;
  };

  const quietConsole = () => {
    const errorLog = spyOn(console, "error").mockImplementation(() => {});
    restores.push(() => errorLog.mockRestore());
  };

  test("quota error is surfaced and not acknowledged", async () => {
    quietConsole();
    const { root, plaintext, rootedReceipt } = await buildMessage(
      MessageType.Text,
      8,
    );
    const { alice, epc } = edgePair();
    const errors = collectErrors();
    failChunkWrites(1);

    const refused = await receive(seal(alice, plaintext, root), epc, root);

    // The app is told, with enough to name the transfer and the peer.
    expect(errors).toEqual([
      {
        code: "quota-exceeded",
        roomId: ROOM,
        fromPeerId: PEER,
        merkleRootHex: uint8ArrayToHex(root),
        filename: "",
        totalSize: 8,
        chunkIndex: 0,
      },
    ]);
    // The sender gets no receipt it can match: what goes on the wire is an
    // unlinkable decoy, and nothing is queued for a scheduled-cover ack.
    expect(refused.chunkIndex).toBe(-1);
    expect(refused.chunkHash.length).toBe(0);
    expect(uint8ArrayToHex(wireReceipt(refused))).not.toBe(
      uint8ArrayToHex(rootedReceipt),
    );
    // Nothing was committed for the chunk.
    const count = await callWorker("getDBAllChunksCount", [
      uint8ArrayToHex(root),
    ]);
    expect(count.result).toBe(0);

    // The sender's retransmission after space is freed is stored and acked
    // with the rooted receipt; the app is not told a second time.
    const stored = await receive(seal(alice, plaintext, root), epc, root);
    expect(stored.receivedFullSize).toBe(true);
    expect(uint8ArrayToHex(wireReceipt(stored))).toBe(
      uint8ArrayToHex(rootedReceipt),
    );
    expect(errors).toHaveLength(1);
  });

  test("any other storage fault is surfaced as storage-failed", async () => {
    quietConsole();
    const { root, plaintext, rootedReceipt } = await buildMessage(
      MessageType.Text,
      8,
    );
    const { alice, epc } = edgePair();
    const errors = collectErrors();
    failChunkWrites(1, "UnknownError");

    const refused = await receive(seal(alice, plaintext, root), epc, root);
    expect(errors.map((error) => error.code)).toEqual(["storage-failed"]);
    expect(uint8ArrayToHex(wireReceipt(refused))).not.toBe(
      uint8ArrayToHex(rootedReceipt),
    );
  });

  test("a transfer refused for quota is reported once and never acknowledged", async () => {
    quietConsole();
    installStorage({
      estimate: async () => ({ quota: 1_000, usage: 993 }),
    });
    const { root, plaintext, rootedReceipt } = await buildMessage(
      MessageType.Text,
      8,
    );
    const { alice, epc } = edgePair();
    const errors = collectErrors();

    for (let attempt = 0; attempt < 3; attempt++) {
      const refused = await receive(seal(alice, plaintext, root), epc, root);
      expect(refused.chunkIndex).toBe(-1);
      expect(uint8ArrayToHex(wireReceipt(refused))).not.toBe(
        uint8ArrayToHex(rootedReceipt),
      );
    }
    expect(errors).toEqual([
      {
        code: "insufficient-quota",
        roomId: ROOM,
        fromPeerId: PEER,
        merkleRootHex: uint8ArrayToHex(root),
        filename: "",
        totalSize: 8,
        chunkIndex: 0,
        requiredBytes: 8,
        availableBytes: 7,
      },
    ]);
  });

  test("persistent storage is requested once for received files and a refusal is ignored", async () => {
    quietConsole();
    let persistCalls = 0;
    installStorage({
      estimate: async () => ({ quota: 1 << 30, usage: 0 }),
      persist: async () => {
        persistCalls += 1;
        return false;
      },
    });
    const errors = collectErrors();
    const { alice, epc } = edgePair();

    const text = await buildMessage(MessageType.Text, 8);
    await receive(seal(alice, text.plaintext, text.root), epc, text.root);
    expect(persistCalls).toBe(0);

    for (let file = 0; file < 2; file++) {
      const message = await buildMessage(MessageType.ImagePNG, 8);
      const result = await receive(
        seal(alice, message.plaintext, message.root),
        epc,
        message.root,
      );
      // The file's only chunk is held and acknowledged; the file completes
      // once it verifies.
      expect(result.receivedFullSize).toBe(false);
      expect(result.verification).toBeDefined();
      expect(uint8ArrayToHex(wireReceipt(result))).toBe(
        uint8ArrayToHex(message.rootedReceipt),
      );
      expect(await finishHeld(result, message.root)).toBe("complete");
    }
    expect(persistCalls).toBe(1);
    expect(errors).toEqual([]);
  });

  test("a file that fails verification is reported and its read throws", async () => {
    quietConsole();
    // The file's bytes do not hash to the whole-file hash its message claims.
    const { root, plaintext } = await buildMessage(
      MessageType.ImagePNG,
      8,
      rand(crypto_hash_sha512_BYTES),
    );
    const { alice, epc } = edgePair();
    const errors = collectErrors();

    const held = await receive(seal(alice, plaintext, root), epc, root);
    expect(held.receivedFullSize).toBe(false);
    expect(await finishHeld(held, root)).toBe("integrity");
    expect(errors.map((error) => error.code)).toEqual(["integrity"]);
    // Nothing is held, so a reconnect replays no receipt for it either.
    const progress = await callWorker("getDBMessageData", [
      uint8ArrayToHex(root),
    ]);
    expect(progress.result).toMatchObject({
      savedSize: 0,
      totalSize: 8,
      integrityFailed: true,
    });
    // Reading it through the public API's check throws the typed error.
    const readProgress = async (merkleRootHex: string) =>
      (await callWorker("getDBMessageData", [merkleRootHex])).result as
        { integrityFailed?: true } | undefined;
    const read = assertReceivedFileIntact(
      uint8ArrayToHex(root),
      readProgress as never,
    );
    await expect(read).rejects.toBeInstanceOf(ReceiveIntegrityError);
    await expect(read).rejects.toMatchObject({
      code: "integrity",
      merkleRootHex: uint8ArrayToHex(root),
    });
  });

  test("a worker crash during a store is reported as a storage failure", async () => {
    quietConsole();
    const { root, plaintext, rootedReceipt } = await buildMessage(
      MessageType.Text,
      8,
    );
    const { alice, epc } = edgePair();
    const errors = collectErrors();
    // The real database client over a worker that dies while the store is
    // in flight: its onerror rejects the pending call.
    const port: DatabaseWorkerPort = {
      postMessage: () => {
        queueMicrotask(() =>
          port.onerror!({ message: "injected crash" } as ErrorEvent),
        );
      },
      onmessage: null,
      onerror: null,
      onmessageerror: null,
    };
    const client = createDatabaseClient(port, true);
    const crashed = await handleReceiveMessage(
      seal(alice, plaintext, root),
      ROOM,
      "chat",
      epc,
      root,
      module,
      undefined,
      {
        persistRatchetState: async () => undefined,
        storeReceiveChunk: (chunk) =>
          client.call("storeReceiveChunk", [
            chunk,
          ]) as Promise<ReceiveChunkStoreResult>,
      },
    );
    expect(errors.map((error) => error.code)).toEqual(["storage-failed"]);
    expect(crashed.chunkIndex).toBe(-1);
    expect(uint8ArrayToHex(wireReceipt(crashed))).not.toBe(
      uint8ArrayToHex(rootedReceipt),
    );

    // A chunk the worker refused is not a storage failure: no event.
    const refused = await buildMessage(MessageType.Text, 8);
    await handleReceiveMessage(
      seal(alice, refused.plaintext, refused.root),
      ROOM,
      "chat",
      epc,
      refused.root,
      module,
      undefined,
      {
        persistRatchetState: async () => undefined,
        storeReceiveChunk: async () => {
          throw new Error("Error: invalid receive chunk bounds");
        },
      },
    );
    expect(errors).toHaveLength(1);
  });

  test("reported failures are capped and a forgotten one is reported again", async () => {
    quietConsole();
    const errors = collectErrors();
    const failing = {
      settleReceivedFileVerification: async () => "integrity" as const,
    };
    const report = (index: number) =>
      settleHeldFile(
        {
          roomId: ROOM,
          fromPeerId: PEER,
          merkleRoot: index.toString(16).padStart(128, "0"),
          filename: "f.bin",
          totalSize: 8,
          chunkIndex: 0,
        },
        "token",
        "mismatch",
        true,
        failing,
      );
    // Whatever earlier tests left behind, a repeat is reported once.
    const repeated = MAX_REPORTED_RECEIVE_STORAGE_ERRORS * 2;
    await report(repeated);
    await report(repeated);
    expect(errors).toHaveLength(1);
    // The memory holds at most the cap: after that many other transfers fail,
    // it has been reset rather than grown, so the repeat is reported again.
    for (let index = 0; index < MAX_REPORTED_RECEIVE_STORAGE_ERRORS; index++)
      await report(index);
    expect(errors).toHaveLength(1 + MAX_REPORTED_RECEIVE_STORAGE_ERRORS);
    await report(repeated);
    expect(errors).toHaveLength(2 + MAX_REPORTED_RECEIVE_STORAGE_ERRORS);
  });
});
