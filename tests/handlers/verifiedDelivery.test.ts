import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import { getMerkleRoot } from "../../src/cryptography/merkle";
import { initRatchet, ratchetEncrypt } from "../../src/cryptography/ratchet";
import { sealCoverCell } from "../../src/cryptography/coverCell";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { hexToUint8Array, uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  MIN_RECEIVER_VERIFY_BYTES_PER_SECOND,
  RATCHET_ROOT_SUITE_MLKEM512,
  RECEIVER_SILENCE_LIMIT_MS,
  RETRANSMIT_TIMEOUT_MS,
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
import type { NewChunk } from "../../src/db/types";

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation.
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
let sendChunks: SendModule["sendChunks"];
let sendScheduled: SendModule["sendScheduled"];
let waitForTransferConfirmation: SendModule["waitForTransferConfirmation"];
type Reconcile = typeof import("../../src/handlers/reconcile");
let clearTransfer: Reconcile["clearTransfer"];
let markChunkAcked: Reconcile["markChunkAcked"];
let markTransferComplete: Reconcile["markTransferComplete"];
let reportedCompletionCapMs: Reconcile["reportedCompletionCapMs"];
type CoverEdgeModule = typeof import("../../src/handlers/coverEdge");
let installCoverEdge: CoverEdgeModule["installCoverEdge"];
let teardownCoverEdge: CoverEdgeModule["teardownCoverEdge"];
let scheduledDeliveryTimeoutMs: (typeof import("../../src/handlers/coverTransfer"))["scheduledDeliveryTimeoutMs"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({ OutboundMessage, sendChunks, sendScheduled, waitForTransferConfirmation } =
    await import("../../src/handlers/handleSendMessage"));
  ({
    clearTransfer,
    markChunkAcked,
    markTransferComplete,
    reportedCompletionCapMs,
  } = await import("../../src/handlers/reconcile"));
  ({ installCoverEdge, teardownCoverEdge } =
    await import("../../src/handlers/coverEdge"));
  ({ scheduledDeliveryTimeoutMs } =
    await import("../../src/handlers/coverTransfer"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
});

const ROOM = "room-a4-verify";
const PEER = "peer-a4-verify";
const TRANSFER_ID = "a6".repeat(32);
const HASH_HEX = "e6".repeat(64);
const MIB = 1024 * 1024;

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
  clearTransfer(ROOM, PEER, TRANSFER_ID);
});

/** A clock the test advances; every wait arms its timers on it. */
class ManualClock {
  private time = 0;
  private nextId = 1;
  fired = 0;
  private readonly timers = new Map<
    number,
    { id: number; at: number; callback: () => void }
  >();

  readonly now = (): number => this.time;

  readonly setTimeout = (callback: () => void, ms: number): number => {
    const id = this.nextId++;
    this.timers.set(id, { id, at: this.time + ms, callback });
    return id;
  };

  readonly clearTimeout = (handle: unknown): void => {
    this.timers.delete(handle as number);
  };

  /**
   * Run every timer due up to `target` in order, then stop at `target`. A wait
   * that keeps re-arming a deadline already passed would spin here forever,
   * so that is a failure instead.
   */
  advanceTo(target: number): void {
    for (let firings = 0; ; firings++) {
      if (firings > 10_000) throw new Error("a timer re-armed without end");
      const due = [...this.timers.values()]
        .filter(({ at }) => at <= target)
        .sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!due) break;
      this.time = Math.max(this.time, due.at);
      this.timers.delete(due.id);
      this.fired++;
      due.callback();
    }
    this.time = target;
  }
}

/** Real time for queued work (crypto, receipt queues) to run between steps. */
const settle = async (): Promise<void> => {
  for (let i = 0; i < 4; i++)
    await new Promise((resolve) => setImmediate(resolve));
};

/** Settlement within a few real milliseconds (the resume watch is 1 ms). */
const settledSoon = async <T>(
  promise: Promise<T>,
): Promise<{ settled: boolean; value?: T }> => {
  let outcome: { settled: boolean; value?: T } = { settled: false };
  void promise.then((value) => {
    outcome = { settled: true, value };
  });
  for (let i = 0; i < 40 && !outcome.settled; i++)
    await new Promise((resolve) => setTimeout(resolve, 5));
  return outcome;
};

const settledWithin = async <T>(
  promise: Promise<T>,
): Promise<{ settled: boolean; value?: T }> => {
  let outcome: { settled: boolean; value?: T } = { settled: false };
  void promise.then((value) => {
    outcome = { settled: true, value };
  });
  await settle();
  return outcome;
};

/** Stage `reals` + `decoys` cells of a message whose metadata says `totalSize`. */
const stageMessage = async (
  reals: number,
  decoys: number,
  totalSize: number,
) => {
  const totalChunks = reals + decoys;
  const hash = rand(crypto_hash_sha512_BYTES);
  const rows = new Map<number, NewChunk>();
  const leaves = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  for (let i = 0; i < totalChunks; i++) {
    const data = rand(CHUNK_LEN);
    const leaf = hashMerkleLeafWasm(data, module);
    leaves.set(leaf, i * crypto_hash_sha512_BYTES);
    rows.set(i, {
      transferId: TRANSFER_ID,
      hash: HASH_HEX,
      merkleRoot: "",
      chunkIndex: i,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash,
        name: "a4",
        totalSize,
        date: new Date(0),
        chunkStartIndex: 10,
        // A decoy's range is longer than the whole message.
        chunkEndIndex: i < reals ? 110 : 10 + totalSize + 1,
        chunkIndex: i,
      }).buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRoot = await getMerkleRoot(leaves, module);
  const message = new OutboundMessage({
    transferId: TRANSFER_ID,
    hashHex: HASH_HEX,
    merkleRoot,
    totalChunks,
    chunkHashes: leaves,
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
  cleanups.push(() => {
    message.close();
  });
  return {
    message,
    merkleRoot,
    merkleRootHex: uint8ArrayToHex(merkleRoot),
    realIndexes: Array.from({ length: reals }, (_, i) => i),
  };
};

const ackAll = (indexes: readonly number[]): void => {
  for (const index of indexes) markChunkAcked(ROOM, PEER, TRANSFER_ID, index);
};

// ── immediate mode ─────────────────────────────────────────────────────────

/** The transfer's own channel; the fake receiver sends on it. */
class TransferChannel extends EventTarget {
  readonly label: string;
  readyState: RTCDataChannelState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  withPeerId = PEER;
  roomIds: [string] = [ROOM];
  constructor(label: string) {
    super();
    this.label = label;
  }
  send(): void {}
  /** The receiver re-sends its receipt: one inbound frame. */
  receiveFrame(): void {
    this.dispatchEvent(new Event("message"));
  }
}

/** A message whose every cell has gone out once, on a fresh channel. */
const sentMessage = async (totalSize: number) => {
  const staged = await stageMessage(3, 1, totalSize);
  const channel = new TransferChannel(
    await compileChannelMessageLabel("chat", staged.merkleRootHex),
  );
  await sendChunks(
    channel as unknown as IRTCDataChannel,
    { seal: (chunk) => chunk.slice(), wipe: () => undefined },
    staged.message,
  );
  return { ...staged, channel };
};

describe("immediate mode: the completion wait outlasts the receiver's verification", () => {
  test("the completion wait is re-armed by a receipt after every chunk is acknowledged", async () => {
    // 800 MiB: a cap of 100 s + 30 s, far past this test's 75 s.
    const { message, channel, realIndexes } = await sentMessage(800 * MIB);
    const clock = new ManualClock();

    // One real still missing: the round's fixed wait, which frames do not
    // re-arm, so there is something left to retransmit.
    ackAll(realIndexes.slice(1));
    const round = waitForTransferConfirmation(
      message,
      channel,
      ROOM,
      PEER,
      0,
      undefined,
      clock,
    );
    clock.advanceTo(RETRANSMIT_TIMEOUT_MS - 1);
    channel.receiveFrame();
    expect((await settledWithin(round)).settled).toBe(false);
    clock.advanceTo(RETRANSMIT_TIMEOUT_MS);
    expect(await settledWithin(round)).toEqual({
      settled: true,
      value: { done: false, verifying: false },
    });

    // Every chunk acknowledged: the receiver is verifying and re-sends a
    // receipt every 10 s. 75 s passes, far past the 30 s silence bound.
    ackAll(realIndexes);
    const verifying = waitForTransferConfirmation(
      message,
      channel,
      ROOM,
      PEER,
      1,
      undefined,
      clock,
    );
    const start = clock.now();
    for (let t = 10_000; t <= 70_000; t += 10_000) {
      clock.advanceTo(start + t);
      channel.receiveFrame();
    }
    clock.advanceTo(start + 75_000);
    expect((await settledWithin(verifying)).settled).toBe(false);

    // The final receipt.
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    expect(await settledWithin(verifying)).toEqual({
      settled: true,
      value: { done: true, verifying: true },
    });
  });

  test("cells the sender has not read yet are not taken as acknowledged", async () => {
    // A first pass cut off after two cells (a reload resume starts the same
    // way): the reals it read are acknowledged, the rest are unknown.
    const staged = await stageMessage(3, 1, 800 * MIB);
    const channel = new TransferChannel(
      await compileChannelMessageLabel("chat", staged.merkleRootHex),
    );
    let sends = 0;
    channel.send = () => {
      sends++;
      if (sends === 2) channel.readyState = "closed";
    };
    await sendChunks(
      channel as unknown as IRTCDataChannel,
      { seal: (chunk) => chunk.slice(), wipe: () => undefined },
      staged.message,
    );
    ackAll(staged.realIndexes);
    channel.readyState = "open";
    const clock = new ManualClock();
    const round = waitForTransferConfirmation(
      staged.message,
      channel,
      ROOM,
      PEER,
      0,
      undefined,
      clock,
    );
    clock.advanceTo(RETRANSMIT_TIMEOUT_MS);
    expect(await settledWithin(round)).toEqual({
      settled: true,
      value: { done: false, verifying: false },
    });
  });

  test("a receiver that goes silent during verification ends the wait with the same failure as before", async () => {
    const { message, channel, realIndexes } = await sentMessage(800 * MIB);
    const clock = new ManualClock();
    ackAll(realIndexes);
    const verifying = waitForTransferConfirmation(
      message,
      channel,
      ROOM,
      PEER,
      0,
      undefined,
      clock,
    );
    clock.advanceTo(10_000);
    channel.receiveFrame();
    clock.advanceTo(20_000);
    channel.receiveFrame();
    // Silent from 20 s: still waiting just before 20 s + 30 s...
    clock.advanceTo(20_000 + RECEIVER_SILENCE_LIMIT_MS - 1);
    expect((await settledWithin(verifying)).settled).toBe(false);
    // ...and done waiting at it: not confirmed, nothing left to retransmit,
    // which sendWithReconcile reports as "Message transfer ended without
    // receiver confirmation", as it did after its retransmit rounds.
    clock.advanceTo(20_000 + RECEIVER_SILENCE_LIMIT_MS);
    expect(await settledWithin(verifying)).toEqual({
      settled: true,
      value: { done: false, verifying: true },
    });
    expect(RECEIVER_SILENCE_LIMIT_MS).toBe(30_000);
  });

  test("the completion wait is capped for a receiver that keeps reporting but never finishes", async () => {
    // 80 MiB at 8 MiB/s: a 10 s verification allowance plus the 30 s bound.
    const totalSize = 80 * MIB;
    const cap = reportedCompletionCapMs(totalSize, RECEIVER_SILENCE_LIMIT_MS);
    expect(cap).toBe(
      (totalSize / MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) * 1000 +
        RECEIVER_SILENCE_LIMIT_MS,
    );
    expect(cap).toBe(40_000);
    const { message, channel, realIndexes } = await sentMessage(totalSize);
    const clock = new ManualClock();
    ackAll(realIndexes);
    const verifying = waitForTransferConfirmation(
      message,
      channel,
      ROOM,
      PEER,
      0,
      undefined,
      clock,
    );
    for (let t = 5_000; t < cap; t += 5_000) {
      clock.advanceTo(t);
      channel.receiveFrame();
    }
    clock.advanceTo(cap - 1);
    channel.receiveFrame();
    expect((await settledWithin(verifying)).settled).toBe(false);
    clock.advanceTo(cap);
    expect(await settledWithin(verifying)).toEqual({
      settled: true,
      value: { done: false, verifying: true },
    });
  });
});

// ── scheduled mode ─────────────────────────────────────────────────────────

// A cadence far longer than the test, so the runtime's own timers never open
// a cycle; the test pulls the job's cells itself.
const policy: RoomPolicyV1 = {
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 4,
  coverDurationEpochs: 1,
};

/** The sender's authenticated scheduled edge, with a real cover runtime. */
const scheduledEdge = () => {
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
    createDataChannel: (label: string) =>
      new TransferChannel(label) as unknown as IRTCDataChannel,
  } as unknown as IRTCPeerConnection;
  installCoverEdge({
    epc,
    roomId: ROOM,
    policy,
    policyHash: new Uint8Array(32),
    amInitiator: true,
    module,
    receiptDependencies: {
      // The receipts here are repeats: none resolves to a new chunk.
      getChunk: async () => undefined,
      persist: async () => true,
    },
  });
  const jobs: CoverJob[] = [];
  const runtime = epc.coverRuntime!;
  const enqueue = runtime.enqueue.bind(runtime);
  runtime.enqueue = (job) => {
    jobs.push(job);
    enqueue(job);
  };
  cleanups.push(() => {
    teardownCoverEdge(epc);
    pq.destroy();
  });
  let counter = 0n;
  return {
    epc,
    jobs,
    /** The receiver re-sends a chunk receipt in one of its cover cells. */
    receiveReceipt: (merkleRootHex: string): void => {
      counter += 1n;
      const context = pq.currentMessageContext();
      const cell = sealCoverCell({
        module,
        rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
        rootKey: context.rootKey,
        binding: context.binding,
        direction: "responder-to-initiator",
        keyEpoch: 0n,
        counter,
        content: {
          subtype: "chunk-receipts",
          merkleRoot: hexToUint8Array(merkleRootHex),
          tokens: [new Uint8Array(64).fill(0x71)],
        },
      });
      expect(runtime.processInboundCoverCell(cell)).toBe(true);
    },
  };
};

/**
 * Start a scheduled send whose every cell goes out and is acknowledged, then
 * whose delivery wait runs out with no final receipt: the receiver is now
 * verifying the file.
 */
const startScheduledVerification = async (totalSize: number) => {
  const staged = await stageMessage(3, 1, totalSize);
  const edge = scheduledEdge();
  const clock = new ManualClock();
  let verificationStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    verificationStarted = resolve;
  });
  const sending = sendScheduled(
    ROOM,
    "chat",
    policy,
    [{ peerId: PEER, epc: edge.epc }],
    staged.message,
    module,
    undefined,
    undefined,
    [edge.epc],
    {
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
      waitForDelivery: async () => {
        for (let i = 0; i < 8; i++) {
          const cell = await edge.jobs[0].nextCell({} as CoverJobSlot);
          if (cell === null) break;
        }
        ackAll(staged.realIndexes);
        verificationStarted();
        return false;
      },
      resumeWaitMs: 1,
      clock,
    },
  );
  await started;
  await settle();
  return { ...staged, edge, clock, sending };
};

const scheduledSilence = (): number =>
  Math.max(
    RECEIVER_SILENCE_LIMIT_MS,
    scheduledDeliveryTimeoutMs({
      coverCadenceMs: policy.coverCadenceMs,
      coverLanes: policy.coverLanes,
      coverFramesPerCell: policy.coverFramesPerCell,
      coverDurationEpochs: policy.coverDurationEpochs,
    }),
  );

describe("scheduled mode: the delivery wait outlasts the receiver's verification", () => {
  test("the completion wait is re-armed by a scheduled receipt after every chunk is acknowledged", async () => {
    const silence = scheduledSilence();
    // A cap far past the test: the file's allowance is ten silence bounds.
    const totalSize = Math.ceil(
      (10 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const { edge, clock, sending, merkleRootHex } =
      await startScheduledVerification(totalSize);

    // A receipt every half silence bound, for three silence bounds.
    for (let t = silence / 2; t <= 3 * silence; t += silence / 2) {
      clock.advanceTo(t);
      edge.receiveReceipt(merkleRootHex);
      await settle();
    }
    expect((await settledSoon(sending)).settled).toBe(false);

    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    const result = await settledWithin(sending);
    expect(result.settled).toBe(true);
    expect(result.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
  });

  test("a receiver that goes silent during verification ends the scheduled wait with the same failure as before", async () => {
    const silence = scheduledSilence();
    const totalSize = Math.ceil(
      (10 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const { edge, clock, sending, merkleRootHex } =
      await startScheduledVerification(totalSize);
    clock.advanceTo(silence / 2);
    edge.receiveReceipt(merkleRootHex);
    await settle();
    clock.advanceTo(silence / 2 + silence - 1);
    expect((await settledSoon(sending)).settled).toBe(false);
    clock.advanceTo(silence / 2 + silence);
    // The outcome a scheduled send gives when its delivery wait runs out.
    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    const result = settled.value!;
    expect(result.outcomes).toHaveLength(1);
    expect(result.outcomes[0]).toMatchObject({
      peerId: PEER,
      status: "failed",
      phase: "transfer",
    });
    expect((result.outcomes[0] as { reason: Error }).reason.message).toBe(
      "scheduled delivery not confirmed",
    );
  });

  test("silence does not accrue while the sender's own schedule is suspended", async () => {
    // A pagehide, freeze or offline suspends this edge's scheduler, the same
    // gap the delivery idle budget is held through.
    const silence = scheduledSilence();
    const totalSize = Math.ceil(
      (10 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const { edge, clock, sending } =
      await startScheduledVerification(totalSize);
    edge.epc.coverRuntime!.suspend("pagehide");
    clock.advanceTo(2 * silence);
    // Real milliseconds too: a send that gave up settles after its 1 ms
    // resume watch.
    expect((await settledSoon(sending)).settled).toBe(false);
    edge.epc.coverRuntime!.resume();
    // Silence counts again from the last check while suspended.
    clock.advanceTo(3 * silence);
    await settle();
    clock.advanceTo(4 * silence);
    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    expect(settled.value!.outcomes[0]).toMatchObject({ status: "failed" });
  });

  test("the scheduled completion wait is capped for a receiver that keeps reporting but never finishes", async () => {
    const silence = scheduledSilence();
    const totalSize = Math.ceil(
      (2 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const cap = reportedCompletionCapMs(totalSize, silence);
    const { edge, clock, sending, merkleRootHex } =
      await startScheduledVerification(totalSize);
    for (let t = silence / 4; t < cap; t += silence / 4) {
      clock.advanceTo(t);
      edge.receiveReceipt(merkleRootHex);
      await settle();
    }
    clock.advanceTo(cap - 1);
    expect((await settledSoon(sending)).settled).toBe(false);
    clock.advanceTo(cap);
    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    const result = settled.value!;
    expect(result.outcomes[0]).toMatchObject({
      status: "failed",
      phase: "transfer",
    });
  });
});
