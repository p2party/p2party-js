import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import { getMerkleRoot } from "../../src/cryptography/merkle";
import { initRatchet, ratchetEncrypt } from "../../src/cryptography/ratchet";
import { sealCoverCell } from "../../src/cryptography/coverCell";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { roomSendQueueLabel } from "../../src/utils/sendQueueKey";
import {
  FRAME_TYPE_IMMEDIATE_DISPOSITION,
  IMMEDIATE_RESUME_PROTOCOL,
  acceptImmediateDisposition,
  bindImmediateDisposition,
} from "../../src/handlers/immediateDisposition";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { hexToUint8Array, uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  MAX_SCHEDULED_SEND_RESUMES,
  MAX_TIMER_DELAY_MS,
  MIN_RECEIVER_VERIFY_BYTES_PER_SECOND,
  REPORTED_COMPLETION_CHECK_MS,
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
let sendWithReconcile: SendModule["sendWithReconcile"];
type Reconcile = typeof import("../../src/handlers/reconcile");
let clearTransfer: Reconcile["clearTransfer"];
let markChunkAcked: Reconcile["markChunkAcked"];
let markTransferComplete: Reconcile["markTransferComplete"];
let hasChunkAcked: Reconcile["hasChunkAcked"];
let reportedCompletionCapMs: Reconcile["reportedCompletionCapMs"];
let waitForReportedCompletion: Reconcile["waitForReportedCompletion"];
let armTimer: Reconcile["armTimer"];
let clampTimerDelayMs: Reconcile["clampTimerDelayMs"];
let noteTransferActivity: Reconcile["noteTransferActivity"];
let onTransferActivity: Reconcile["onTransferActivity"];
type CoverEdgeModule = typeof import("../../src/handlers/coverEdge");
let installCoverEdge: CoverEdgeModule["installCoverEdge"];
let teardownCoverEdge: CoverEdgeModule["teardownCoverEdge"];
let scheduledDeliveryTimeoutMs: (typeof import("../../src/handlers/coverTransfer"))["scheduledDeliveryTimeoutMs"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];
type GateModule = typeof import("../../src/handlers/ratchetGate");
let claimRatchetGate: GateModule["claimRatchetGate"];
let openRatchetGate: GateModule["openRatchetGate"];
let resetRatchetGate: GateModule["resetRatchetGate"];

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({
    OutboundMessage,
    sendChunks,
    sendScheduled,
    sendWithReconcile,
    waitForTransferConfirmation,
  } = await import("../../src/handlers/handleSendMessage"));
  ({
    clearTransfer,
    markChunkAcked,
    markTransferComplete,
    hasChunkAcked,
    reportedCompletionCapMs,
    waitForReportedCompletion,
    armTimer,
    clampTimerDelayMs,
    noteTransferActivity,
    onTransferActivity,
  } = await import("../../src/handlers/reconcile"));
  ({ installCoverEdge, teardownCoverEdge } =
    await import("../../src/handlers/coverEdge"));
  ({ scheduledDeliveryTimeoutMs } =
    await import("../../src/handlers/coverTransfer"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
  ({ claimRatchetGate, openRatchetGate, resetRatchetGate } =
    await import("../../src/handlers/ratchetGate"));
});

const ROOM = "room-a4-verify";
const PEER = "peer-a4-verify";
// Each test sends its own transfer: a send a failed test leaves running can
// then never wake another test's wait.
let TRANSFER_ID = "";
beforeEach(() => {
  TRANSFER_ID = uint8ArrayToHex(crypto.getRandomValues(new Uint8Array(32)));
});
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

  /** The page runs nothing: time moves on, no timer fires. */
  jumpTo(target: number): void {
    this.time = target;
  }

  get armed(): number {
    return this.timers.size;
  }

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
  attempts = 40,
): Promise<{ settled: boolean; value?: T }> => {
  let outcome: { settled: boolean; value?: T } = { settled: false };
  void promise.then((value) => {
    outcome = { settled: true, value };
  });
  for (let i = 0; i < attempts && !outcome.settled; i++)
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
  protocol = "raw";
  withPeerId = PEER;
  roomIds: [string] = [ROOM];
  constructor(label: string) {
    super();
    this.label = label;
  }
  send(): void {}
  close(): void {
    this.readyState = "closed";
  }
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
const scheduledEdge = (peerId: string = PEER) => {
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
    withPeerId: peerId,
    withPeerPublicKey: peerId === PEER ? "aa".repeat(32) : "ab".repeat(32),
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
  // This connection is the peer's current authenticated transport.
  resetRatchetGate(ROOM, peerId);
  const lease = claimRatchetGate(ROOM, peerId);
  openRatchetGate(ROOM, peerId, lease);
  epc.ratchetGateLease = lease;
  cleanups.push(() => {
    resetRatchetGate(ROOM, peerId);
    clearTransfer(ROOM, peerId, TRANSFER_ID);
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
const ratchetStep = async (epc: IRTCPeerConnection) => {
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
};

/** Pull every cell of a job, as the scheduler's slots would. */
const pullAllCells = async (job: CoverJob): Promise<void> => {
  for (let i = 0; i < 8; i++)
    if ((await job.nextCell({} as CoverJobSlot)) === null) return;
};

/**
 * Start a scheduled send whose every cell goes out and is acknowledged, then
 * whose delivery wait runs out with no final receipt: the receiver is now
 * verifying the file. `beforeFirstReturn` runs just before that wait returns;
 * `laterDelivery` answers every later delivery wait (a resumed attempt).
 */
const startScheduledVerification = async (
  totalSize: number,
  options: {
    readonly beforeFirstReturn?: () => void;
    readonly laterDelivery?: () => Promise<boolean>;
    readonly peerConnections?: IRTCPeerConnection[];
    readonly clock?: ManualClock;
  } = {},
) => {
  // Every subscription the verification wait makes to receipt activity.
  let activitySubscriptions = 0;
  const staged = await stageMessage(3, 1, totalSize);
  const edge = scheduledEdge();
  const peerConnections = options.peerConnections ?? [edge.epc];
  if (!peerConnections.includes(edge.epc)) peerConnections.push(edge.epc);
  const clock = options.clock ?? new ManualClock();
  let verificationStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    verificationStarted = resolve;
  });
  let deliveryWaits = 0;
  const sending = sendScheduled(
    ROOM,
    "chat",
    policy,
    [{ peerId: PEER, epc: edge.epc }],
    staged.message,
    module,
    undefined,
    undefined,
    peerConnections,
    {
      waitForGate: async () => undefined,
      ratchetStep,
      waitForDelivery: async () => {
        deliveryWaits++;
        if (deliveryWaits > 1)
          return (await options.laterDelivery?.()) ?? false;
        await pullAllCells(edge.jobs[0]);
        ackAll(staged.realIndexes);
        options.beforeFirstReturn?.();
        verificationStarted();
        return false;
      },
      resumeWaitMs: 1,
      clock,
      subscribeActivity: (roomId, peerId, transferId, listener) => {
        activitySubscriptions++;
        return onTransferActivity(roomId, peerId, transferId, listener);
      },
    },
  );
  await started;
  await settle();
  return {
    ...staged,
    edge,
    clock,
    sending,
    peerConnections,
    deliveryWaits: () => deliveryWaits,
    activitySubscriptions: () => activitySubscriptions,
  };
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

  test("a suspended schedule that no longer holds the job does not hold the silence", async () => {
    const silence = scheduledSilence();
    const totalSize = Math.ceil(
      (10 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const { edge, clock, sending, merkleRootHex } =
      await startScheduledVerification(totalSize);
    // The job has left the scheduler; the page is then suspended.
    edge.epc.coverRuntime!.complete(
      await compileChannelMessageLabel("chat", merkleRootHex),
    );
    edge.epc.coverRuntime!.suspend("pagehide");
    clock.advanceTo(silence - 1);
    expect((await settledSoon(sending)).settled).toBe(false);
    clock.advanceTo(silence);
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

// ── the wait ends at once when the edge goes ───────────────────────────────

const PEER_TWO = "peer-a4-verify-two";

/**
 * One immediate transfer through the real sendWithReconcile: every cell goes
 * out, the receiver acknowledges them all as the last one is sent, and the
 * sender is then in its verification wait on the manual clock.
 */
const startImmediateVerification = async (totalSize: number) => {
  const staged = await stageMessage(3, 1, totalSize);
  const channel = new TransferChannel(
    await compileChannelMessageLabel("chat", staged.merkleRootHex),
  );
  let sent = 0;
  channel.send = () => {
    sent++;
    if (sent === 4) ackAll(staged.realIndexes);
  };
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
  resetRatchetGate(ROOM, PEER);
  const lease = claimRatchetGate(ROOM, PEER);
  openRatchetGate(ROOM, PEER, lease);
  const epc = {
    roomId: ROOM,
    withPeerId: PEER,
    withPeerPublicKey: "aa".repeat(32),
    connectionState: "connected",
    pqHealingState: pq,
    ratchetGateLease: lease,
    ratchetState: initRatchet(
      rand(32),
      true,
      initRatchet(rand(32), false, null, module).dhSelfPub,
      module,
    ),
  } as unknown as IRTCPeerConnection;
  cleanups.push(() => {
    resetRatchetGate(ROOM, PEER);
    pq.destroy();
  });
  const clock = new ManualClock();
  const cancellations: string[] = [];
  const queueDeletes: [string, string][] = [];
  const sending = sendWithReconcile(
    channel as unknown as IRTCDataChannel,
    {
      dispatch: () => undefined,
      getState: () => ({}),
    } as unknown as Parameters<SendModule["sendWithReconcile"]>[1],
    ROOM,
    epc,
    staged.message,
    PEER,
    module,
    [epc],
    [],
    undefined,
    undefined,
    {
      ratchetStep,
      deleteSendQueue: async (label, peerId) => {
        queueDeletes.push([label, peerId]);
      },
      persistCancellation: async (receipt) => {
        cancellations.push(receipt.transferId);
        return true;
      },
      resumeTimeoutMs: 1,
      clock,
    },
  );
  // Settle the send's async staging until it waits on the manual clock.
  for (let turn = 0; turn < 200 && clock.armed === 0; turn++) await settle();
  expect(sent).toBe(4);
  expect(clock.armed).toBe(1);
  return {
    ...staged,
    channel,
    epc,
    clock,
    sending,
    cancellations,
    queueDeletes,
  };
};

const closeFromTheFarSide = (channel: TransferChannel): void => {
  channel.readyState = "closed";
  channel.dispatchEvent(new Event("close"));
};

describe("immediate mode: a closing channel ends the verification wait at once", () => {
  test("the completion wait ends at once when the channel closes", async () => {
    const { channel, epc, clock, sending, cancellations } =
      await startImmediateVerification(800 * MIB);
    // The transport goes: what a close did before this wait existed, a
    // resume attempt, and with nothing to resume on, the usual failure.
    (epc as { connectionState: string }).connectionState = "disconnected";
    closeFromTheFarSide(channel);
    const settled = await settledSoon(
      sending.catch((error: Error) => error),
      400,
    );
    expect(settled.settled).toBe(true);
    expect((settled.value as Error).message).toBe(
      "Message transfer ended without receiver confirmation",
    );
    // Settled with the clock never advanced, and the wait left no timer.
    expect(clock.armed).toBe(0);
    expect(cancellations).toEqual([]);
  });

  test("a receiver's cancel during verification is reported as a cancel without waiting", async () => {
    const { channel, clock, sending, cancellations } =
      await startImmediateVerification(800 * MIB);
    // Still connected, on the same authenticated generation: this close is
    // the receiver refusing the file.
    closeFromTheFarSide(channel);
    const settled = await settledSoon(
      sending.catch((error: Error) => error),
      400,
    );
    expect(settled.settled).toBe(true);
    expect((settled.value as Error).message).toBe(
      "Message transfer cancelled by peer",
    );
    expect(cancellations).toEqual([TRANSFER_ID]);
    expect(clock.armed).toBe(0);
  });

  test("a silent receiver ends sendWithReconcile after one silence bound, not one per retry", async () => {
    const { clock, sending } = await startImmediateVerification(800 * MIB);
    const outcome = sending.catch((error: Error) => error);
    clock.advanceTo(RECEIVER_SILENCE_LIMIT_MS - 1);
    expect((await settledSoon(outcome)).settled).toBe(false);
    clock.advanceTo(RECEIVER_SILENCE_LIMIT_MS);
    const settled = await settledSoon(outcome, 400);
    expect(settled.settled).toBe(true);
    expect((settled.value as Error).message).toBe(
      "Message transfer ended without receiver confirmation",
    );
    // Ended by the first silence bound: no further retransmit round ran.
    expect(clock.now()).toBe(RECEIVER_SILENCE_LIMIT_MS);
  });
});

describe("scheduled mode: a replaced edge ends the verification wait at once", () => {
  test("an edge replaced during the scheduled verification wait resumes on the new edge at once", async () => {
    const {
      edge,
      clock,
      sending,
      peerConnections,
      deliveryWaits,
      activitySubscriptions,
    } = await startScheduledVerification(800 * MIB, {
      laterDelivery: async () => true,
    });
    // The verification wait was entered and is listening.
    expect(activitySubscriptions()).toBe(1);
    // The receiver is verifying; the sender's edge is replaced: torn down, and
    // a fresh connection with its own runtime becomes the current transport.
    expect(clock.armed).toBe(1);
    teardownCoverEdge(edge.epc);
    peerConnections.splice(0, peerConnections.length);
    const replacement = scheduledEdge();
    peerConnections.push(replacement.epc);

    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
    // Re-derived and re-offered on the new edge, settled with the clock never
    // advanced, and the wait left no timer.
    expect(replacement.jobs).toHaveLength(1);
    expect(deliveryWaits()).toBe(2);
    expect(clock.armed).toBe(0);
  });

  test("the scheduled verification wait is not entered for a replaced edge", async () => {
    let replacement: ReturnType<typeof scheduledEdge> | undefined;
    const peerConnections: IRTCPeerConnection[] = [];
    let armedAtFirstReturn = -1;
    const clock = new ManualClock();
    const started = await startScheduledVerification(800 * MIB, {
      peerConnections,
      clock,
      // The edge is replaced while the delivery wait is still running.
      beforeFirstReturn: () => {
        teardownCoverEdge(peerConnections[0]);
        peerConnections.splice(0, peerConnections.length);
        replacement = scheduledEdge();
        peerConnections.push(replacement.epc);
      },
      laterDelivery: async () => {
        armedAtFirstReturn = clock.armed;
        return true;
      },
    });
    const settled = await settledSoon(started.sending);
    expect(settled.settled).toBe(true);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
    expect(replacement!.jobs).toHaveLength(1);
    // The verification wait was never entered: it made no subscription and
    // armed no timer (its first check inside would have subscribed first).
    expect(started.activitySubscriptions()).toBe(0);
    expect(armedAtFirstReturn).toBe(0);
    expect(clock.armed).toBe(0);
  });
});

describe("scheduled mode: every peer's send is observed", () => {
  test("a peer whose send throws outside its own handling does not take the other peers' outcomes with it", async () => {
    const staged = await stageMessage(3, 1, 800 * MIB);
    const second = scheduledEdge(PEER_TWO);
    // A connection still coming up, without the event methods the admission
    // wait needs: that peer's send throws before its own try/catch.
    const broken = {
      roomId: ROOM,
      withPeerId: PEER,
      connectionState: "connecting",
    } as unknown as IRTCPeerConnection;
    const sending = sendScheduled(
      ROOM,
      "chat",
      policy,
      [
        { peerId: PEER, epc: broken },
        { peerId: PEER_TWO, epc: second.epc },
      ],
      staged.message,
      module,
      undefined,
      undefined,
      [broken, second.epc],
      {
        waitForGate: async () => undefined,
        ratchetStep,
        waitForDelivery: async () => true,
        resumeWaitMs: 1,
      },
    );
    const settled = await settledSoon(sending.catch((error: Error) => error));
    expect(settled.settled).toBe(true);
    const result = settled.value as Awaited<typeof sending>;
    expect(result.outcomes).toHaveLength(2);
    expect(result.outcomes[0]).toMatchObject({
      peerId: PEER,
      status: "failed",
      phase: "transfer",
    });
    expect(result.outcomes[1]).toEqual({
      peerId: PEER_TWO,
      status: "delivered",
    });
  });
});

describe("scheduled mode: one peer's verification does not hold back the next", () => {
  test("a second peer's send starts while the first peer is still verifying", async () => {
    const staged = await stageMessage(3, 1, 800 * MIB);
    const first = scheduledEdge(PEER);
    const second = scheduledEdge(PEER_TWO);
    const clock = new ManualClock();
    const order: string[] = [];
    let firstVerifying!: () => void;
    const verifying = new Promise<void>((resolve) => {
      firstVerifying = resolve;
    });
    const sending = sendScheduled(
      ROOM,
      "chat",
      policy,
      [
        { peerId: PEER, epc: first.epc },
        { peerId: PEER_TWO, epc: second.epc },
      ],
      staged.message,
      module,
      undefined,
      undefined,
      [first.epc, second.epc],
      {
        waitForGate: async () => undefined,
        ratchetStep,
        waitForDelivery: async (_options, peerId) => {
          if (peerId === PEER) {
            await pullAllCells(first.jobs[0]);
            ackAll(staged.realIndexes);
            order.push("first verifying");
            firstVerifying();
            return false;
          }
          await verifying;
          order.push("second delivery wait");
          return true;
        },
        resumeWaitMs: 1,
        clock,
      },
    );
    await verifying;
    await settle();
    // The second peer's job was enqueued and its delivery wait ran while the
    // first peer's verification is still open.
    expect(second.jobs).toHaveLength(1);
    expect(order).toEqual(["first verifying", "second delivery wait"]);
    expect((await settledSoon(sending)).settled).toBe(false);

    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
      { peerId: PEER_TWO, status: "delivered" },
    ]);
  });
});

// ── suspension and timer bounds of the wait itself ─────────────────────────

describe("the verification wait does not count time the page did not run", () => {
  const waitOn = (
    clock: ManualClock,
    silenceMs: number,
    capMs: number,
  ): Promise<boolean> =>
    waitForReportedCompletion(ROOM, PEER, TRANSFER_ID, {
      silenceMs,
      capMs,
      onActivity: (wake) => onTransferActivity(ROOM, PEER, TRANSFER_ID, wake),
      clock,
    });

  test("time spent frozen does not count toward the silence bound", async () => {
    const clock = new ManualClock();
    const waiting = waitOn(clock, RECEIVER_SILENCE_LIMIT_MS, 3_600_000);
    // Off a check boundary: checks fall every REPORTED_COMPLETION_CHECK_MS.
    const frozenAt = 2 * REPORTED_COMPLETION_CHECK_MS + 2_300;
    clock.advanceTo(frozenAt);
    // Frozen for a minute: nothing runs, no timer fires.
    const wokeAt = frozenAt + 60_000;
    clock.jumpTo(wokeAt);
    clock.advanceTo(wokeAt);
    expect((await settledWithin(waiting)).settled).toBe(false);
    // Silence counts again from the wake, not from before the freeze.
    clock.advanceTo(wokeAt + RECEIVER_SILENCE_LIMIT_MS - 1);
    expect((await settledWithin(waiting)).settled).toBe(false);
    clock.advanceTo(wokeAt + RECEIVER_SILENCE_LIMIT_MS);
    expect(await settledWithin(waiting)).toEqual({
      settled: true,
      value: false,
    });
  });

  test("a wake after a long sleep does not end the wait at once", async () => {
    const clock = new ManualClock();
    // A cap of 40 s, and two hours asleep.
    const waiting = waitOn(clock, RECEIVER_SILENCE_LIMIT_MS, 40_000);
    clock.advanceTo(12_000);
    clock.jumpTo(12_000 + 2 * 3_600_000);
    // The first thing to run on waking is the receipt that was waiting.
    noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    expect((await settledWithin(waiting)).settled).toBe(false);
    clock.advanceTo(clock.now() + REPORTED_COMPLETION_CHECK_MS);
    expect((await settledWithin(waiting)).settled).toBe(false);
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    expect(await settledWithin(waiting)).toEqual({
      settled: true,
      value: true,
    });
  });

  test("a silence bound above the largest timer delay does not spin", async () => {
    // A platform timer fires a delay above 2^31 - 1 ms at once.
    const clock = new ManualClock();
    const delays: number[] = [];
    const platform = {
      now: clock.now,
      clearTimeout: clock.clearTimeout,
      setTimeout: (callback: () => void, ms: number) => {
        delays.push(ms);
        return clock.setTimeout(callback, ms > MAX_TIMER_DELAY_MS ? 0 : ms);
      },
    };
    // About 4.7×10^11 ms: twice a 3,600,000 ms cadence × 65,535 epochs.
    const silenceMs = 2 * 3_600_000 * 65_535;
    const waiting = waitForReportedCompletion(ROOM, PEER, TRANSFER_ID, {
      silenceMs,
      capMs: 2 * silenceMs,
      onActivity: (wake) => onTransferActivity(ROOM, PEER, TRANSFER_ID, wake),
      clock: platform,
    });
    clock.advanceTo(60_000);
    expect((await settledWithin(waiting)).settled).toBe(false);
    expect(delays.every((ms) => ms <= MAX_TIMER_DELAY_MS)).toBe(true);
    // One re-check per REPORTED_COMPLETION_CHECK_MS, not a loop.
    expect(clock.fired).toBe(60_000 / REPORTED_COMPLETION_CHECK_MS);
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    expect((await settledWithin(waiting)).settled).toBe(true);
  });
});

// ── round 3: the cap, rekeys, retirement, completion on a failing resume ───

/** A clock whose timers fire only on whole periods, as a throttled page's. */
const periodicClock = (periodMs: number) => {
  const clock = new ManualClock();
  return {
    clock,
    transferClock: {
      now: clock.now,
      clearTimeout: clock.clearTimeout,
      setTimeout: (callback: () => void, ms: number) => {
        const due = Math.ceil((clock.now() + ms) / periodMs) * periodMs;
        return clock.setTimeout(
          callback,
          Math.max(periodMs, due) - clock.now(),
        );
      },
    },
  };
};

const silentWait = (
  clock: Parameters<Reconcile["waitForReportedCompletion"]>[3]["clock"],
  silenceMs: number,
  capMs: number,
): Promise<boolean> =>
  waitForReportedCompletion(ROOM, PEER, TRANSFER_ID, {
    silenceMs,
    capMs,
    onActivity: (wake) => onTransferActivity(ROOM, PEER, TRANSFER_ID, wake),
    clock,
  });

describe("the verification wait's cap is fixed when it starts", () => {
  test("the cap bounds the wait on a page whose timers fire once a minute", async () => {
    const period = 60_000;
    const cap = 40_000;
    for (const silence of [30_000, 321_200]) {
      const { clock, transferClock } = periodicClock(period);
      const waiting = silentWait(transferClock, silence, cap);
      let endedAt: number | undefined;
      for (
        let t = period;
        t <= 2 * 3_600_000 && endedAt === undefined;
        t += period
      ) {
        clock.advanceTo(t);
        if ((await settledWithin(waiting)).settled) endedAt = t;
      }
      // Every check ran late, so silence never ended it; the cap did, within
      // one silence bound and one timer period of it.
      expect(endedAt).toBeDefined();
      expect(endedAt!).toBeGreaterThanOrEqual(cap);
      expect(endedAt!).toBeLessThanOrEqual(cap + silence + period);
      expect(await waiting).toBe(false);
      clearTransfer(ROOM, PEER, TRANSFER_ID);
    }
  });

  test("a wake past the cap leaves one silence bound, once", async () => {
    const clock = new ManualClock();
    const silence = RECEIVER_SILENCE_LIMIT_MS;
    const cap = 40_000;
    const waiting = silentWait(clock, silence, cap);
    clock.advanceTo(12_000);
    // Asleep past the cap; the overdue check on waking extends it once.
    clock.jumpTo(100_000);
    clock.advanceTo(100_000);
    expect((await settledWithin(waiting)).settled).toBe(false);
    // Asleep again, past the extended cap: no second extension.
    clock.jumpTo(200_000);
    clock.advanceTo(200_000);
    expect(await settledWithin(waiting)).toEqual({
      settled: true,
      value: false,
    });
  });

  test("receipts arriving after the cap do not extend it", async () => {
    // On a page that runs on time, receipts every 10 s right up to the cap:
    // the wait still ends at it.
    const onTime = new ManualClock();
    const atCap = silentWait(onTime, RECEIVER_SILENCE_LIMIT_MS, 40_000);
    for (let t = 10_000; t < 40_000; t += 10_000) {
      onTime.advanceTo(t);
      noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    }
    onTime.advanceTo(39_999);
    noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    expect((await settledWithin(atCap)).settled).toBe(false);
    onTime.advanceTo(40_000);
    expect(await settledWithin(atCap)).toEqual({ settled: true, value: false });
    clearTransfer(ROOM, PEER, TRANSFER_ID);

    // After a sleep past the cap the first receipt on waking takes the one
    // extension; a receipt after the next sleep takes none.
    const clock = new ManualClock();
    const waiting = silentWait(clock, RECEIVER_SILENCE_LIMIT_MS, 40_000);
    clock.advanceTo(12_000);
    clock.jumpTo(100_000);
    noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    expect((await settledWithin(waiting)).settled).toBe(false);
    clock.jumpTo(200_000);
    noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    expect(await settledWithin(waiting)).toEqual({
      settled: true,
      value: false,
    });
    clearTransfer(ROOM, PEER, TRANSFER_ID);

    // Receipts on time during the extension do not push it either: it still
    // ends one silence bound after the wake.
    const extended = new ManualClock();
    const afterWake = silentWait(extended, RECEIVER_SILENCE_LIMIT_MS, 40_000);
    extended.advanceTo(12_000);
    extended.jumpTo(100_000);
    extended.advanceTo(100_000);
    for (let t = 110_000; t < 130_000; t += 10_000) {
      extended.advanceTo(t);
      noteTransferActivity(ROOM, PEER, TRANSFER_ID);
    }
    extended.advanceTo(129_999);
    expect((await settledWithin(afterWake)).settled).toBe(false);
    extended.advanceTo(130_000);
    expect(await settledWithin(afterWake)).toEqual({
      settled: true,
      value: false,
    });
  });

  test("on a throttled page the cap's bound is one silence bound and two periods", async () => {
    // The cap falls just past a wake-up: the first check past it runs almost
    // a period late and leaves one silence bound, which the next wake-up
    // after it sees almost a period late again.
    const period = 60_000;
    const silence = 30_000;
    const cap = 61_000;
    const { clock, transferClock } = periodicClock(period);
    const waiting = silentWait(transferClock, silence, cap);
    let endedAt: number | undefined;
    for (let t = period; t <= 600_000 && endedAt === undefined; t += period) {
      clock.advanceTo(t);
      if ((await settledWithin(waiting)).settled) endedAt = t;
    }
    expect(endedAt).toBe(180_000);
    expect(endedAt!).toBeGreaterThan(cap + silence + period);
    expect(endedAt!).toBeLessThanOrEqual(cap + silence + 2 * period);
  });
});

describe("a key-epoch change is not an edge going away", () => {
  test("a key-epoch change during the verification wait does not end it", async () => {
    const started = await startScheduledVerification(800 * MIB);
    // A PQ heal on the same edge publishes a new cover generation.
    started.edge.epc.coverRuntime!.onPqEpochChanged();
    await settle();
    expect((await settledSoon(started.sending)).settled).toBe(false);
    // Not re-entered, not resumed, nothing re-offered.
    expect(started.activitySubscriptions()).toBe(1);
    expect(started.deliveryWaits()).toBe(1);
    expect(started.edge.jobs).toHaveLength(1);
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    const settled = await settledSoon(started.sending);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
  });

  test("rekeys during a long verification do not spend the resume budget", async () => {
    const silence = scheduledSilence();
    const totalSize = Math.ceil(
      (10 * silence * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) / 1000,
    );
    const started = await startScheduledVerification(totalSize);
    for (let rekey = 0; rekey <= MAX_SCHEDULED_SEND_RESUMES + 1; rekey++) {
      started.clock.advanceTo(started.clock.now() + silence / 2);
      started.edge.receiveReceipt(started.merkleRootHex);
      await settle();
      started.edge.epc.coverRuntime!.onPqEpochChanged();
      await settle();
    }
    expect((await settledSoon(started.sending)).settled).toBe(false);
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    const settled = await settledSoon(started.sending);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
    expect(started.deliveryWaits()).toBe(1);
    expect(started.edge.jobs).toHaveLength(1);
  });
});

describe("a replacement that arrives before the old edge is torn down", () => {
  test("a replacement installed after a rekey, before the old teardown, ends the wait at once", async () => {
    const { edge, clock, sending, peerConnections, deliveryWaits } =
      await startScheduledVerification(800 * MIB, {
        laterDelivery: async () => true,
      });
    // A rekey first: the generation watch must keep listening after it.
    edge.epc.coverRuntime!.onPqEpochChanged();
    await settle();
    expect((await settledSoon(sending)).settled).toBe(false);
    // The peer's fresh connection authenticates and installs its runtime;
    // the old edge is not torn down yet.
    const replacement = scheduledEdge();
    peerConnections.push(replacement.epc);
    const settled = await settledSoon(sending);
    expect(settled.settled).toBe(true);
    expect(settled.value?.outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
    expect(replacement.jobs).toHaveLength(1);
    expect(deliveryWaits()).toBe(2);
    expect(clock.armed).toBe(0);
  });
});

describe("an edge retired with no replacement", () => {
  test("an edge retired without a replacement ends the scheduled wait at once", async () => {
    const started = await startScheduledVerification(800 * MIB);
    expect(started.clock.armed).toBe(1);
    // Torn down; nothing replaces it, so no generation is published.
    teardownCoverEdge(started.edge.epc);
    const settled = await settledSoon(started.sending);
    // Settled with the clock never advanced, and the wait left no timer.
    expect(settled.settled).toBe(true);
    expect(started.clock.armed).toBe(0);
    expect(settled.value?.outcomes[0]).toMatchObject({
      peerId: PEER,
      status: "failed",
      phase: "transfer",
    });
    expect(
      (settled.value?.outcomes[0] as { reason: Error }).reason.message,
    ).toBe("scheduled delivery not confirmed");
  });
});

describe("immediate mode: completion and the receiver's CANCEL around a close", () => {
  test("a completion recorded while the resume was failing is reported as delivered", async () => {
    const { channel, epc, sending, realIndexes } =
      await startImmediateVerification(800 * MIB);
    const outcome = sending.then(
      () => "delivered",
      (error: Error) => error.message,
    );
    // The peer's connection is gone, and the final receipt is recorded while
    // the resume looks for its replacement: the first time the connection is
    // read after the resume has reset the transfer's have-set. The resume
    // still finds no transport and gives up.
    let recorded = false;
    Object.defineProperty(epc, "connectionState", {
      configurable: true,
      get: () => {
        if (
          !recorded &&
          !hasChunkAcked(ROOM, PEER, TRANSFER_ID, realIndexes[0])
        ) {
          recorded = true;
          markTransferComplete(ROOM, PEER, TRANSFER_ID);
        }
        return "disconnected";
      },
    });
    closeFromTheFarSide(channel);
    const settled = await settledSoon(outcome, 400);
    expect(recorded).toBe(true);
    expect(settled).toEqual({ settled: true, value: "delivered" });
  });

  test("a resume drops the legacy queue through the same seam as the send", async () => {
    const { channel, epc, sending, realIndexes, queueDeletes } =
      await startImmediateVerification(800 * MIB);
    const outcome = sending.then(
      () => "delivered",
      (error: Error) => error.message,
    );
    const label = roomSendQueueLabel(ROOM, channel.label);
    expect(queueDeletes).toEqual([[label, PEER]]);
    // The transport drops, then comes back before the resume looks for it;
    // opening the new channel fails, so the resume gives up.
    Object.defineProperty(epc, "connectionState", {
      configurable: true,
      get: () =>
        hasChunkAcked(ROOM, PEER, TRANSFER_ID, realIndexes[0])
          ? "disconnected"
          : "connected",
    });
    closeFromTheFarSide(channel);
    const settled = await settledSoon(outcome, 400);
    expect(settled).toEqual({
      settled: true,
      value: "Message transfer ended without receiver confirmation",
    });
    expect(queueDeletes.length).toBeGreaterThan(1);
    for (const call of queueDeletes) expect(call).toEqual([label, PEER]);
  });

  test("a receiver's CANCEL frame then close is reported as a cancel without waiting", async () => {
    const { channel, clock, sending, cancellations, merkleRoot } =
      await startImmediateVerification(800 * MIB);
    // The channel carries the disposition protocol, and the receiver has
    // said a bare close would only pause the transfer...
    channel.protocol = IMMEDIATE_RESUME_PROTOCOL;
    bindImmediateDisposition(
      channel as unknown as IRTCDataChannel,
      merkleRoot,
      false,
      () => true,
    );
    const disposition = (kind: number): Uint8Array => {
      const frame = new Uint8Array(66);
      frame[0] = FRAME_TYPE_IMMEDIATE_DISPOSITION;
      frame[1] = kind;
      frame.set(merkleRoot, 2);
      return frame;
    };
    expect(
      acceptImmediateDisposition(
        channel as unknown as IRTCDataChannel,
        disposition(0),
      ),
    ).toBe("capability");
    // ...then refuses the file: its CANCEL frame arrives, then the close.
    expect(
      acceptImmediateDisposition(
        channel as unknown as IRTCDataChannel,
        disposition(1),
      ),
    ).toBe("cancel");
    channel.receiveFrame();
    closeFromTheFarSide(channel);
    const settled = await settledSoon(
      sending.catch((error: Error) => error),
      400,
    );
    expect(settled.settled).toBe(true);
    expect((settled.value as Error).message).toBe(
      "Message transfer cancelled by peer",
    );
    expect(cancellations).toEqual([TRANSFER_ID]);
    expect(clock.armed).toBe(0);
  });
});

describe("timers above the platform limit", () => {
  test("clampTimerDelayMs and armTimer at the largest delay and one more", () => {
    expect(clampTimerDelayMs(MAX_TIMER_DELAY_MS)).toBe(MAX_TIMER_DELAY_MS);
    expect(clampTimerDelayMs(MAX_TIMER_DELAY_MS + 1)).toBe(MAX_TIMER_DELAY_MS);
    expect(clampTimerDelayMs(-1)).toBe(0);

    const clock = new ManualClock();
    const delays: number[] = [];
    const recording = {
      now: clock.now,
      clearTimeout: clock.clearTimeout,
      setTimeout: (callback: () => void, ms: number) => {
        delays.push(ms);
        return clock.setTimeout(callback, ms);
      },
    };
    let fired = 0;
    armTimer(recording, () => fired++, MAX_TIMER_DELAY_MS);
    expect(delays).toEqual([MAX_TIMER_DELAY_MS]);
    clock.advanceTo(MAX_TIMER_DELAY_MS);
    expect(fired).toBe(1);

    // One more: armed at the limit, then re-armed for the 1 ms remainder.
    delays.length = 0;
    const start = clock.now();
    armTimer(recording, () => fired++, MAX_TIMER_DELAY_MS + 1);
    clock.advanceTo(start + MAX_TIMER_DELAY_MS);
    expect(fired).toBe(1);
    expect(delays).toEqual([MAX_TIMER_DELAY_MS, 1]);
    clock.advanceTo(start + MAX_TIMER_DELAY_MS + 1);
    expect(fired).toBe(2);

    // Cancelled before it is due: it never fires.
    const cancel = armTimer(recording, () => fired++, 10);
    cancel();
    clock.advanceTo(clock.now() + 10);
    expect(fired).toBe(2);
  });
});
