import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import {
  handleReceiveMessage,
  onReceiveStorageError,
  storeReceiveChunkFailClosed,
  type ReceiveStorageError,
} from "../../src/handlers/handleReceiveMessage";
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
import type { ReceiveChunk, ReceiveChunkStoreResult } from "../../src/db/types";

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

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

// A one-chunk message of `realLen` bytes under a two-leaf Merkle tree.
const buildMessage = async (messageType: number, realLen: number) => {
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
      hash: rand(crypto_hash_sha512_BYTES),
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
      expect(result.receivedFullSize).toBe(true);
      expect(uint8ArrayToHex(wireReceipt(result))).toBe(
        uint8ArrayToHex(message.rootedReceipt),
      );
    }
    expect(persistCalls).toBe(1);
    expect(errors).toEqual([]);
  });
});
