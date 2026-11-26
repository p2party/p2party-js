import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
import { initRatchet, ratchetEncrypt } from "../../src/cryptography/ratchet";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import {
  deserializeMetadata,
  serializeMetadata,
} from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  MAX_BUFFERED_AMOUNT,
  METADATA_LEN,
  PROOF_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { CoverJob, CoverJobSlot } from "../../src/handlers/coverScheduler";
import type { CoverRuntime } from "../../src/handlers/coverRuntime";
import type { MessageChunkSealer } from "../../src/handlers/messageChunkCrypto";
import type { NewChunk } from "../../src/db/types";

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation (same preamble as
// handleSendMessage.test.ts).
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

type SendModule = typeof import("../../src/handlers/handleSendMessage");
let OutboundMessage: SendModule["OutboundMessage"];
let withOutboundMessage: SendModule["withOutboundMessage"];
let sendChunks: SendModule["sendChunks"];
let sendScheduled: SendModule["sendScheduled"];
let waitForSendBuffer: SendModule["waitForSendBuffer"];
let SEND_BUFFER_LOW_THRESHOLD: number;
let SEND_BUFFER_FALLBACK_MS: number;
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];
let clearTransfer: (typeof import("../../src/handlers/reconcile"))["clearTransfer"];

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({
    OutboundMessage,
    SEND_BUFFER_FALLBACK_MS,
    SEND_BUFFER_LOW_THRESHOLD,
    sendChunks,
    sendScheduled,
    waitForSendBuffer,
    withOutboundMessage,
  } = await import("../../src/handlers/handleSendMessage"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
  ({ clearTransfer } = await import("../../src/handlers/reconcile"));
});

const ROOM = "room-a4";
const PEER = "peer-a4";
const TRANSFER_ID = "a4".repeat(32);
const HASH_HEX = "e4".repeat(64);

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
  clearTransfer(ROOM, PEER, TRANSFER_ID);
});

interface StagedMessage {
  readonly rows: NewChunk[];
  readonly leaves: Uint8Array;
  readonly merkleRoot: Uint8Array;
  readonly merkleRootHex: string;
  readonly totalChunks: number;
  readonly realIndexes: number[];
}

/** Stage cells the way splitToChunks does: reals first, then decoys. */
const stageMessage = async (
  realCount: number,
  decoyCount: number,
): Promise<StagedMessage> => {
  const totalChunks = realCount + decoyCount;
  const totalSize = realCount * 100;
  const hash = rand(crypto_hash_sha512_BYTES);
  const rows: NewChunk[] = [];
  const leaves = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  for (let i = 0; i < totalChunks; i++) {
    const data = rand(CHUNK_LEN);
    const real = i < realCount;
    const metadata = serializeMetadata({
      schemaVersion: 1,
      messageType: MessageType.Text,
      hash,
      name: "a4",
      totalSize,
      date: new Date(0),
      chunkStartIndex: 10,
      // A decoy's range is longer than the whole message.
      chunkEndIndex: real ? 110 : 10 + totalSize + 1 + i,
      chunkIndex: i,
    });
    const leaf = hashMerkleLeafWasm(data, module);
    leaves.set(leaf, i * crypto_hash_sha512_BYTES);
    rows.push({
      transferId: TRANSFER_ID,
      hash: HASH_HEX,
      merkleRoot: "",
      chunkIndex: i,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: metadata.buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRoot = await getMerkleRoot(leaves, module);
  return {
    rows,
    leaves,
    merkleRoot,
    merkleRootHex: uint8ArrayToHex(merkleRoot),
    totalChunks,
    realIndexes: Array.from({ length: realCount }, (_, i) => i),
  };
};

/**
 * The newChunks store as the worker behaves: every get is a structured copy,
 * every put replaces the row. Counts what crosses the storage boundary.
 */
class CountingStore {
  readonly rows = new Map<number, NewChunk>();
  readonly readsByIndex = new Map<number, number>();
  puts = 0;
  onGet?: (index: number, reads: number) => void;

  constructor(rows: readonly NewChunk[]) {
    for (const row of rows) this.rows.set(row.chunkIndex, structuredClone(row));
  }

  get reads(): number {
    let total = 0;
    for (const count of this.readsByIndex.values()) total += count;
    return total;
  }

  resetCounts(): void {
    this.readsByIndex.clear();
    this.puts = 0;
  }

  readonly get = async (
    transferId: string,
    chunkIndex: number,
  ): Promise<NewChunk | undefined> => {
    await Promise.resolve();
    expect(transferId).toBe(TRANSFER_ID);
    this.readsByIndex.set(
      chunkIndex,
      (this.readsByIndex.get(chunkIndex) ?? 0) + 1,
    );
    this.onGet?.(chunkIndex, this.reads);
    const row = this.rows.get(chunkIndex);
    return row ? structuredClone(row) : undefined;
  };

  readonly put = async (chunk: NewChunk): Promise<void> => {
    await Promise.resolve();
    this.puts++;
    this.rows.set(chunk.chunkIndex, structuredClone(chunk));
  };
}

/** The module, with its SHA-512 inits and whole-tree WASM proofs counted. */
const countingModule = (): {
  module: LibCrypto;
  counts: { sha512Init: number; wasmProof: number };
} => {
  const counts = { sha512Init: 0, wasmProof: 0 };
  const counted = new Proxy(module, {
    get(object, property, receiver) {
      if (property === "_sha512_init")
        return (state: number) => {
          counts.sha512Init++;
          return object._sha512_init(state);
        };
      if (property === "_get_merkle_proof")
        return (...args: Parameters<LibCrypto["_get_merkle_proof"]>) => {
          counts.wasmProof++;
          return object._get_merkle_proof(...args);
        };
      return Reflect.get(object, property, receiver) as unknown;
    },
  });
  return { module: counted, counts };
};

/** A data channel: an EventTarget whose buffer the test drains by hand. */
class FakeChannel extends EventTarget {
  readonly label: string;
  readyState: RTCDataChannelState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  /** Bytes each send adds to the buffer; 0 = drains instantly. */
  fillPerSend = 0;
  closeAfterSends = Number.POSITIVE_INFINITY;
  readonly sent: Uint8Array[] = [];
  listenerCount = 0;
  withPeerId = PEER;
  roomIds: [string] = [ROOM];

  constructor(label: string) {
    super();
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    if (this.readyState !== "open") throw new Error("InvalidStateError");
    this.sent.push(new Uint8Array(data));
    this.bufferedAmount += this.fillPerSend;
    if (this.sent.length >= this.closeAfterSends) this.close();
  }

  close(): void {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }

  drainTo(amount: number): void {
    const crossed =
      this.bufferedAmount > this.bufferedAmountLowThreshold &&
      amount <= this.bufferedAmountLowThreshold;
    this.bufferedAmount = amount;
    if (crossed) this.dispatchEvent(new Event("bufferedamountlow"));
  }

  override addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
  ): void {
    this.listenerCount++;
    super.addEventListener(type, listener);
  }

  override removeEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
  ): void {
    this.listenerCount--;
    super.removeEventListener(type, listener);
  }
}

const openChannel = async (staged: StagedMessage): Promise<FakeChannel> =>
  new FakeChannel(
    await compileChannelMessageLabel("chat", staged.merkleRootHex),
  );

/** Cells go out as plaintext, so the test reads what the receiver would. */
const plaintextSealer: MessageChunkSealer = {
  seal: (chunk) => chunk.slice(),
  wipe: () => undefined,
};

/** Parse one sent cell and check its proof reaches the message root. */
const verifySentCell = async (
  cell: Uint8Array,
  merkleRoot: Uint8Array,
): Promise<number> => {
  expect(cell.length).toBe(DECRYPTED_LEN);
  const metadata = deserializeMetadata(cell.subarray(0, METADATA_LEN));
  const framed = cell.subarray(METADATA_LEN, METADATA_LEN + PROOF_LEN);
  const proofLength = new DataView(
    framed.buffer,
    framed.byteOffset,
    4,
  ).getUint32(0, false);
  const proof = framed.slice(4, 4 + proofLength);
  const data = cell.subarray(METADATA_LEN + PROOF_LEN);
  expect(await verifyMerkleProof(data, merkleRoot, proof, module)).toBe(true);
  return metadata.chunkIndex;
};

const sentIndexes = async (
  channel: FakeChannel,
  merkleRoot: Uint8Array,
  from = 0,
): Promise<number[]> => {
  const indexes: number[] = [];
  for (const cell of channel.sent.slice(from))
    indexes.push(await verifySentCell(cell, merkleRoot));
  return indexes.sort((a, b) => a - b);
};

const messageFor = (
  staged: StagedMessage,
  store: CountingStore,
  merkleModule: LibCrypto,
) =>
  new OutboundMessage({
    transferId: TRANSFER_ID,
    hashHex: HASH_HEX,
    merkleRoot: staged.merkleRoot,
    totalChunks: staged.totalChunks,
    chunkHashes: staged.leaves,
    merkleModule,
    store,
  });

describe("one OutboundMessage builds the proof levels once for every peer and pass", () => {
  test("tree is built once per message", async () => {
    const staged = await stageMessage(7, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const message = messageFor(staged, store, merkleModule);

    // Peer A's first pass is cut off after two cells, so most rows still have
    // no stored proof when peer B's first pass reads them.
    const a = await openChannel(staged);
    a.closeAfterSends = 2;
    await sendChunks(a as unknown as IRTCDataChannel, plaintextSealer, message);
    const b = await openChannel(staged);
    await sendChunks(b as unknown as IRTCDataChannel, plaintextSealer, message);
    // Peer A resumes on a new channel; peer B retransmits one real.
    const a2 = await openChannel(staged);
    await sendChunks(
      a2 as unknown as IRTCDataChannel,
      plaintextSealer,
      message,
      undefined,
      new Set<number>(),
    );
    await sendChunks(
      b as unknown as IRTCDataChannel,
      plaintextSealer,
      message,
      undefined,
      new Set(staged.realIndexes.filter((index) => index !== 3)),
    );

    // One build: N − 1 node hashes. getMerkleProof would have rebuilt the
    // whole tree in WASM once per proof.
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(counts.wasmProof).toBe(0);
    expect(message.proofLevelBytes).toBeGreaterThan(0);

    expect(a.sent.length).toBe(2);
    expect(await sentIndexes(b, staged.merkleRoot)).toEqual(
      [...Array.from({ length: staged.totalChunks }, (_, i) => i), 3].sort(
        (x, y) => x - y,
      ),
    );
    expect(await sentIndexes(a2, staged.merkleRoot)).toEqual(
      staged.realIndexes,
    );
    message.close();
  });

  test("concurrent first passes to two peers share one build", async () => {
    const staged = await stageMessage(12, 4);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const message = messageFor(staged, store, merkleModule);
    const a = await openChannel(staged);
    const b = await openChannel(staged);
    await Promise.all([
      sendChunks(a as unknown as IRTCDataChannel, plaintextSealer, message),
      sendChunks(b as unknown as IRTCDataChannel, plaintextSealer, message),
    ]);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(counts.wasmProof).toBe(0);
    const all = Array.from({ length: staged.totalChunks }, (_, i) => i);
    expect(await sentIndexes(a, staged.merkleRoot)).toEqual(all);
    expect(await sentIndexes(b, staged.merkleRoot)).toEqual(all);
    message.close();
  });

  test("a resume whose leaves do not reach the root is refused before any cell is sent", async () => {
    const staged = await stageMessage(3, 1);
    const store = new CountingStore(staged.rows);
    const wrongLeaves = staged.leaves.slice();
    wrongLeaves[0] ^= 1;
    const { module: merkleModule, counts } = countingModule();
    const message = new OutboundMessage({
      transferId: TRANSFER_ID,
      hashHex: HASH_HEX,
      merkleRoot: staged.merkleRoot,
      totalChunks: staged.totalChunks,
      chunkHashes: wrongLeaves,
      merkleModule,
      store,
    });
    const channel = await openChannel(staged);
    await expect(
      sendChunks(
        channel as unknown as IRTCDataChannel,
        plaintextSealer,
        message,
      ),
    ).rejects.toThrow("do not reach its Merkle root");
    expect(channel.sent.length).toBe(0);
    // A second peer of the same delivery gets the same refusal without
    // hashing the tree again.
    const second = await openChannel(staged);
    await expect(
      sendChunks(
        second as unknown as IRTCDataChannel,
        plaintextSealer,
        message,
      ),
    ).rejects.toThrow("do not reach its Merkle root");
    expect(second.sent.length).toBe(0);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    message.close();
  });
});

describe("the sender reads each staged slice once", () => {
  test("sender reads each slice once", async () => {
    // Fresh send: the first pass reads every cell once; the retransmit pass
    // reads only the two reals the receiver has not acknowledged.
    const staged = await stageMessage(6, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const message = messageFor(staged, store, merkleModule);
    const channel = await openChannel(staged);

    await sendChunks(
      channel as unknown as IRTCDataChannel,
      plaintextSealer,
      message,
    );
    expect(store.reads).toBe(staged.totalChunks);
    for (let i = 0; i < staged.totalChunks; i++)
      expect(store.readsByIndex.get(i)).toBe(1);
    // Root, receipt token and proof are bound into each row once.
    expect(store.puts).toBe(staged.totalChunks);

    const missing = [1, 4];
    const acked = new Set(
      staged.realIndexes.filter((i) => !missing.includes(i)),
    );
    store.resetCounts();
    const sentBefore = channel.sent.length;
    await sendChunks(
      channel as unknown as IRTCDataChannel,
      plaintextSealer,
      message,
      undefined,
      acked,
    );
    expect(store.reads).toBe(missing.length);
    expect([...store.readsByIndex.keys()].sort()).toEqual(missing);
    expect(store.puts).toBe(0);
    expect(await sentIndexes(channel, staged.merkleRoot, sentBefore)).toEqual(
      missing,
    );

    // Resumed on a replacement channel in the same page: the receiver
    // replays its receipts, and again only the missing reals are read.
    store.resetCounts();
    const replacement = await openChannel(staged);
    await sendChunks(
      replacement as unknown as IRTCDataChannel,
      plaintextSealer,
      message,
      undefined,
      acked,
    );
    expect(store.reads).toBe(missing.length);
    expect(await sentIndexes(replacement, staged.merkleRoot)).toEqual(missing);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    message.close();

    // Resumed after a page reload: a new OutboundMessage over the same rows,
    // which already carry their proofs. Every cell is read once on the first
    // pass, nothing is rewritten and the levels are never built.
    store.resetCounts();
    const reloaded = countingModule();
    const resumed = messageFor(staged, store, reloaded.module);
    const afterReload = await openChannel(staged);
    await sendChunks(
      afterReload as unknown as IRTCDataChannel,
      plaintextSealer,
      resumed,
    );
    expect(store.reads).toBe(staged.totalChunks);
    for (let i = 0; i < staged.totalChunks; i++)
      expect(store.readsByIndex.get(i)).toBe(1);
    expect(store.puts).toBe(0);
    expect(reloaded.counts.sha512Init).toBe(0);
    store.resetCounts();
    await sendChunks(
      afterReload as unknown as IRTCDataChannel,
      plaintextSealer,
      resumed,
      undefined,
      acked,
    );
    expect(store.reads).toBe(missing.length);
    resumed.close();
  });

  test("a reload that interrupted the first pass builds the levels once on resume", async () => {
    const staged = await stageMessage(6, 2);
    const store = new CountingStore(staged.rows);
    const first = messageFor(staged, store, module);
    const channel = await openChannel(staged);
    channel.closeAfterSends = 3;
    await sendChunks(
      channel as unknown as IRTCDataChannel,
      plaintextSealer,
      first,
    );
    first.close();

    store.resetCounts();
    const { module: merkleModule, counts } = countingModule();
    const resumed = messageFor(staged, store, merkleModule);
    const afterReload = await openChannel(staged);
    await sendChunks(
      afterReload as unknown as IRTCDataChannel,
      plaintextSealer,
      resumed,
    );
    expect(store.reads).toBe(staged.totalChunks);
    // The interrupted pass bound four rows (it staged a fourth as the channel
    // closed); only the four it never reached are written now.
    expect(store.puts).toBe(staged.totalChunks - 4);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(await sentIndexes(afterReload, staged.merkleRoot)).toEqual(
      Array.from({ length: staged.totalChunks }, (_, i) => i),
    );
    resumed.close();
  });
});

// ── scheduled delivery: a cover runtime that hands its job to the test ──────

const scheduledPolicy = (): RoomPolicyV1 => ({
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
});

interface ScheduledEdge {
  readonly epc: IRTCPeerConnection;
  readonly jobs: CoverJob[];
  /** Tear the edge down: the runtime stops admitting and settles its job. */
  readonly tearDown: () => void;
}

const scheduledEdge = (): ScheduledEdge => {
  const jobs: CoverJob[] = [];
  const settled = new Map<string, () => void>();
  let status: CoverRuntime["status"] = "active";
  const runtime = {
    get status() {
      return status;
    },
    cellsPerLanePerCycle: () => 1_000_000,
    enqueue: (job: CoverJob) => {
      jobs.push(job);
    },
    onJobSettled: (jobId: string, callback: () => void) => {
      settled.set(jobId, callback);
    },
    complete: () => undefined,
    cancel: () => "cancel-pending" as const,
    getJobProgress: () => undefined,
  } as unknown as CoverRuntime;
  const pq = new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: "local",
    amInitiator: true,
    now: 0,
  });
  cleanups.push(() => {
    pq.destroy();
  });
  const epc = {
    roomId: ROOM,
    withPeerId: PEER,
    withPeerPublicKey: "aa".repeat(32),
    connectionState: "connected",
    pqHealingState: pq,
    ratchetState: initRatchet(
      rand(32),
      true,
      initRatchet(rand(32), false, null, module).dhSelfPub,
      module,
    ),
    coverRuntime: runtime,
  } as unknown as IRTCPeerConnection;
  return {
    epc,
    jobs,
    tearDown: () => {
      status = "stopped";
      for (const callback of settled.values()) callback();
      settled.clear();
    },
  };
};

const scheduledDependencies = (
  waitForDelivery: () => Promise<boolean>,
): Parameters<SendModule["sendScheduled"]>[9] => ({
  waitForGate: async () => undefined,
  ratchetStep: async (epc) => {
    const stepped = ratchetEncrypt(epc.ratchetState!, module);
    const live = epc.pqHealingState!.currentMessageContext();
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
  waitForDelivery,
  resumeWaitMs: 1,
});

const slot = {} as CoverJobSlot;

describe("the proof levels do not outlive the delivery", () => {
  test("cache is released on abort", async () => {
    const staged = await stageMessage(5, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const controller = new AbortController();
    const cancelled = new Error("Message transfer cancelled");
    let captured: InstanceType<SendModule["OutboundMessage"]> | undefined;
    let bytesWhileSending = 0;
    // The user cancels while the fourth cell is being read.
    store.onGet = (_index, reads) => {
      bytesWhileSending = captured?.proofLevelBytes ?? 0;
      if (reads === 4) controller.abort(cancelled);
    };
    const channel = await openChannel(staged);
    await expect(
      withOutboundMessage(
        {
          transferId: TRANSFER_ID,
          hashHex: HASH_HEX,
          merkleRoot: staged.merkleRoot,
          totalChunks: staged.totalChunks,
          chunkHashes: staged.leaves,
          merkleModule,
          store,
        },
        async (message) => {
          captured = message;
          await sendChunks(
            channel as unknown as IRTCDataChannel,
            plaintextSealer,
            message,
            controller.signal,
          );
        },
      ),
    ).rejects.toBe(cancelled);

    expect(bytesWhileSending).toBeGreaterThan(0);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(captured!.closed).toBe(true);
    expect(captured!.proofLevelBytes).toBe(0);
    // Nothing can rebuild them afterwards.
    await expect(captured!.read(0)).rejects.toThrow("already ended");
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
  });

  test("cache is released when a scheduled send is cancelled", async () => {
    const staged = await stageMessage(5, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const edge = scheduledEdge();
    const controller = new AbortController();
    let captured: InstanceType<SendModule["OutboundMessage"]> | undefined;
    const pulled: (Uint8Array | null)[] = [];

    const result = await withOutboundMessage(
      {
        transferId: TRANSFER_ID,
        hashHex: HASH_HEX,
        merkleRoot: staged.merkleRoot,
        totalChunks: staged.totalChunks,
        chunkHashes: staged.leaves,
        merkleModule,
        store,
      },
      async (message) => {
        captured = message;
        return await sendScheduled(
          ROOM,
          "chat",
          scheduledPolicy(),
          [{ peerId: PEER, epc: edge.epc }],
          message,
          module,
          controller.signal,
          undefined,
          [edge.epc],
          scheduledDependencies(async () => {
            pulled.push(await edge.jobs[0].nextCell(slot));
            pulled.push(await edge.jobs[0].nextCell(slot));
            controller.abort(new Error("Message transfer cancelled"));
            return false;
          }),
        );
      },
    );

    expect(result.outcomes[0].status).toBe("failed");
    expect(pulled.map((cell) => cell?.length)).toEqual([
      WIRE_CHUNK_FRAME_LEN,
      WIRE_CHUNK_FRAME_LEN,
    ]);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(captured!.closed).toBe(true);
    expect(captured!.proofLevelBytes).toBe(0);
    // Asked for another cell after the cancel, the job refuses and builds
    // nothing.
    await expect(edge.jobs[0].nextCell(slot)).rejects.toThrow("cancelled");
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
  });

  test("cache is released when the scheduled edge is torn down", async () => {
    const staged = await stageMessage(5, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const edge = scheduledEdge();
    let captured: InstanceType<SendModule["OutboundMessage"]> | undefined;

    const result = await withOutboundMessage(
      {
        transferId: TRANSFER_ID,
        hashHex: HASH_HEX,
        merkleRoot: staged.merkleRoot,
        totalChunks: staged.totalChunks,
        chunkHashes: staged.leaves,
        merkleModule,
        store,
      },
      async (message) => {
        captured = message;
        return await sendScheduled(
          ROOM,
          "chat",
          scheduledPolicy(),
          [{ peerId: PEER, epc: edge.epc }],
          message,
          module,
          undefined,
          undefined,
          [edge.epc],
          scheduledDependencies(async () => {
            await edge.jobs[0].nextCell(slot);
            // No replacement edge ever comes (resumeWaitMs: 1).
            edge.tearDown();
            return false;
          }),
        );
      },
    );

    expect(result.outcomes[0]).toMatchObject({
      status: "failed",
      phase: "transfer",
    });
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
    expect(captured!.closed).toBe(true);
    expect(captured!.proofLevelBytes).toBe(0);
    expect(await edge.jobs[0].nextCell(slot)).toBeNull();
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
  });

  test("cache is released when an immediate edge is torn down mid-pass", async () => {
    // The per-message channel dies under the pass; with no transport to
    // resume on, the transfer ends in error (sendWithReconcile's
    // "ended without receiver confirmation") and the delivery settles.
    const staged = await stageMessage(5, 2);
    const store = new CountingStore(staged.rows);
    const { module: merkleModule, counts } = countingModule();
    const channel = await openChannel(staged);
    channel.closeAfterSends = 2;
    let captured: InstanceType<SendModule["OutboundMessage"]> | undefined;
    const ended = new Error(
      "Message transfer ended without receiver confirmation",
    );
    await expect(
      withOutboundMessage(
        {
          transferId: TRANSFER_ID,
          hashHex: HASH_HEX,
          merkleRoot: staged.merkleRoot,
          totalChunks: staged.totalChunks,
          chunkHashes: staged.leaves,
          merkleModule,
          store,
        },
        async (message) => {
          captured = message;
          await sendChunks(
            channel as unknown as IRTCDataChannel,
            plaintextSealer,
            message,
          );
          expect(captured.proofLevelBytes).toBeGreaterThan(0);
          throw ended;
        },
      ),
    ).rejects.toBe(ended);
    expect(channel.sent.length).toBe(2);
    expect(captured!.proofLevelBytes).toBe(0);
    expect(counts.sha512Init).toBe(staged.totalChunks - 1);
  });
});

// ── backpressure ────────────────────────────────────────────────────────────

/** Timers the test fires by hand: what is armed is what is counted. */
const manualTimers = () => {
  const armed = new Map<number, { callback: () => void; ms: number }>();
  let next = 1;
  return {
    armed,
    timers: {
      setTimeout: (callback: () => void, ms: number) => {
        const id = next++;
        armed.set(id, { callback, ms });
        return id;
      },
      clearTimeout: (handle: unknown) => {
        armed.delete(handle as number);
      },
    },
    fireAll: () => {
      const due = [...armed.entries()];
      for (const [id, timer] of due) {
        armed.delete(id);
        timer.callback();
      }
    },
  };
};

const settledState = async <T>(promise: Promise<T>) => {
  let state: "pending" | "resolved" | "rejected" = "pending";
  let value: unknown;
  promise.then(
    (v) => {
      state = "resolved";
      value = v;
    },
    (e: unknown) => {
      state = "rejected";
      value = e;
    },
  );
  for (let i = 0; i < 10; i++) await Promise.resolve();
  return { state, value };
};

describe("sender backpressure", () => {
  test("send waits for bufferedamountlow", async () => {
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    const { armed, timers } = manualTimers();
    const waiting = waitForSendBuffer(channel, undefined, timers);

    expect((await settledState(waiting)).state).toBe("pending");
    expect(channel.bufferedAmountLowThreshold).toBe(SEND_BUFFER_LOW_THRESHOLD);
    // One fallback timer, not a poll every 25 ms.
    expect([...armed.values()].map((timer) => timer.ms)).toEqual([
      SEND_BUFFER_FALLBACK_MS,
    ]);

    // Draining without crossing the threshold is not enough.
    channel.drainTo(SEND_BUFFER_LOW_THRESHOLD + 1);
    expect((await settledState(waiting)).state).toBe("pending");

    channel.drainTo(SEND_BUFFER_LOW_THRESHOLD);
    expect(await waiting).toBe(true);
    expect(armed.size).toBe(0);
    expect(channel.listenerCount).toBe(0);
  });

  test("a buffer below the high watermark does not wait or listen", async () => {
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT - 1;
    const { armed, timers } = manualTimers();
    expect(await waitForSendBuffer(channel, undefined, timers)).toBe(true);
    expect(armed.size).toBe(0);
    expect(channel.listenerCount).toBe(0);
  });

  test("a channel that closes ends the wait as not open", async () => {
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    const { armed, timers } = manualTimers();
    const waiting = waitForSendBuffer(channel, undefined, timers);
    channel.close();
    expect(await waiting).toBe(false);
    expect(armed.size).toBe(0);
    expect(channel.listenerCount).toBe(0);
  });

  test("an abort ends the wait with the transfer's abort reason", async () => {
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    const { armed, timers } = manualTimers();
    const controller = new AbortController();
    const reason = new Error("Message transfer cancelled");
    const waiting = waitForSendBuffer(channel, controller.signal, timers);
    controller.abort(reason);
    await expect(waiting).rejects.toBe(reason);
    expect(armed.size).toBe(0);
    expect(channel.listenerCount).toBe(0);
  });

  test("a drain the event never reports is caught by the fallback, which re-arms once", async () => {
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    const { armed, timers, fireAll } = manualTimers();
    const waiting = waitForSendBuffer(channel, undefined, timers);
    fireAll();
    expect((await settledState(waiting)).state).toBe("pending");
    expect(armed.size).toBe(1);
    channel.bufferedAmount = 0; // no event dispatched
    fireAll();
    expect(await waiting).toBe(true);
    expect(armed.size).toBe(0);
  });

  test("a drain between the first check and listener registration is not missed", async () => {
    // The listener is registered BEFORE the amount is checked again.
    const channel = new FakeChannel("m~r");
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    const register = channel.addEventListener.bind(channel);
    channel.addEventListener = (type, listener) => {
      register(type, listener);
      if (type === "bufferedamountlow") channel.bufferedAmount = 0;
    };
    const { timers } = manualTimers();
    expect(await waitForSendBuffer(channel, undefined, timers)).toBe(true);
  });

  test("a full buffer pauses the pass until bufferedamountlow, with no polling timer", async () => {
    const staged = await stageMessage(6, 2);
    const store = new CountingStore(staged.rows);
    const message = messageFor(staged, store, module);
    const channel = await openChannel(staged);
    // Two sends fill the buffer to the high watermark.
    channel.fillPerSend = MAX_BUFFERED_AMOUNT / 2;

    const realSetTimeout = globalThis.setTimeout;
    const armedMs: number[] = [];
    globalThis.setTimeout = ((
      callback: () => void,
      ms?: number,
      ...rest: unknown[]
    ) => {
      armedMs.push(ms ?? 0);
      return realSetTimeout(callback, ms, ...rest);
    }) as typeof setTimeout;
    try {
      let done = false;
      const pass = sendChunks(
        channel as unknown as IRTCDataChannel,
        plaintextSealer,
        message,
      ).then(() => {
        done = true;
      });
      let pauses = 0;
      while (!done) {
        await new Promise((resolve) => setImmediate(resolve));
        if (channel.listenerCount === 0) continue;
        // Paused on the full buffer: listening, and nothing more is sent
        // until the buffer reports it drained.
        const sent = channel.sent.length;
        await new Promise((resolve) => setImmediate(resolve));
        expect(channel.sent.length).toBe(sent);
        pauses++;
        channel.drainTo(0);
        expect(channel.listenerCount).toBe(0);
      }
      await pass;
      expect(channel.sent.length).toBe(staged.totalChunks);
      // Every second send fills the buffer: three pauses for eight cells.
      expect(pauses).toBe(3);
      // No 25 ms polling: only the fallback timer, armed once per pause.
      expect(armedMs).toEqual([
        SEND_BUFFER_FALLBACK_MS,
        SEND_BUFFER_FALLBACK_MS,
        SEND_BUFFER_FALLBACK_MS,
      ]);
    } finally {
      globalThis.setTimeout = realSetTimeout;
      message.close();
    }
  });
});
