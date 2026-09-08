import { beforeAll, describe, expect, test } from "bun:test";

import {
  cancelScheduledSend,
  installCoverEdge,
  teardownCoverEdge,
} from "../../src/handlers/coverEdge";
import { CoverRuntime } from "../../src/handlers/coverRuntime";
import {
  buildScheduledSendJob,
  scheduledSendProgressToken,
  waitForScheduledDelivery,
} from "../../src/handlers/coverTransfer";
import {
  shouldSweepCancelledInboundTransfer,
  sweepCancelledInboundTransfer,
} from "../../src/handlers/inboundTransferSweep";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { InboundTransferSweepDeps } from "../../src/handlers/inboundTransferSweep";
import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type { CoverClock } from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { MessageData } from "../../src/db/types";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

const PEER_ID = "peer-a";
const ROOM_ID = "room-1";
const ROOT_HEX = "cd".repeat(64);
const ROOT = new Uint8Array(64).fill(0xcd);

const flush = async (): Promise<void> => {
  for (let i = 0; i < 16; i++) await Promise.resolve();
};

// ── deterministic storage double ─────────────────────────────────────────────
//
// The production deps go through the IndexedDB Worker; the sweep takes them as
// a parameter (the same convention forgetMappedReceiveMessageKey already uses)
// so a test can hand it a synchronous store and read what it did.

interface SweepSpy {
  readonly deps: InboundTransferSweepDeps;
  readonly rows: Map<string, MessageData>;
  readonly reads: (string | undefined)[];
  readonly deleted: string[];
  readonly forgotten: string[];
}

const rowFor = (overrides: Partial<MessageData> = {}): MessageData => ({
  roomId: ROOM_ID,
  timestamp: 0,
  fromPeerId: PEER_ID,
  channelLabel: "chat",
  hash: "ab".repeat(64),
  merkleRoot: ROOT_HEX,
  filename: "big.bin",
  messageType: 1,
  savedSize: 40,
  totalSize: 100,
  ...overrides,
});

const makeSweepSpy = (rows: Record<string, MessageData> = {}): SweepSpy => {
  const store = new Map<string, MessageData>(Object.entries(rows));
  const reads: (string | undefined)[] = [];
  const deleted: string[] = [];
  const forgotten: string[] = [];
  return {
    rows: store,
    reads,
    deleted,
    forgotten,
    deps: {
      readProgress: async (merkleRootHex?: string) => {
        reads.push(merkleRootHex);

        return merkleRootHex === undefined
          ? undefined
          : store.get(merkleRootHex);
      },
      forgetKey: async (
        _epc: IRTCPeerConnection,
        _roomId: string,
        merkleRootHex: string,
      ) => {
        forgotten.push(merkleRootHex);
        return true;
      },
      deleteReceive: async (merkleRootHex: string) => {
        deleted.push(merkleRootHex);
        store.delete(merkleRootHex);
      },
    } as InboundTransferSweepDeps,
  };
};

// ── cover-edge harness ───────────────────────────────────────────────────────

class FakeChannel implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];
  closes = 0;
  binaryType = "arraybuffer";
  withPeerId = PEER_ID;
  roomIds: [string] = [ROOM_ID];

  constructor(label: string) {
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    this.sent.push(new Uint8Array(data));
  }

  close(): void {
    this.closes += 1;
    this.readyState = "closed";
  }

  addEventListener(): void {
    /* the registry only needs close notification, which these tests never use */
  }
}

interface FakeTimer {
  readonly id: number;
  readonly at: number;
  readonly callback: () => void;
}

class FakeClock implements CoverClock {
  private time: number;
  private nextId = 1;
  private readonly timers = new Map<number, FakeTimer>();

  constructor(now = 0) {
    this.time = now;
  }

  now(): number {
    return this.time;
  }

  setTimeout(callback: () => void, delayMs: number): number {
    const id = this.nextId++;
    this.timers.set(id, { id, at: this.time + delayMs, callback });
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") this.timers.delete(handle);
  }

  private nextDue(target: number): FakeTimer | undefined {
    return [...this.timers.values()]
      .filter(({ at }) => at <= target)
      .sort((left, right) => left.at - right.at || left.id - right.id)[0];
  }

  private async drain(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    for (;;) {
      await this.drain();
      const timer = this.nextDue(target);
      if (!timer) break;
      this.time = Math.max(this.time, timer.at);
      this.timers.delete(timer.id);
      timer.callback();
    }
    this.time = target;
    await this.drain();
  }
}

const makePq = (amInitiator: boolean): SparsePqHealingState =>
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

// A cadence far longer than any test run, so the receiver's real-timer edge
// never opens a cycle: these tests only need it to authenticate inbound cells.
const receiverPolicy = (): RoomPolicyV1 => ({
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
});

interface Receiver {
  readonly epc: IRTCPeerConnection;
  readonly pq: SparsePqHealingState;
  readonly spy: SweepSpy;
  readonly outboundAborts: string[];
  destroy(): void;
}

const makeReceiver = (spy: SweepSpy): Receiver => {
  const pq = makePq(false); // responder: opens the initiator's cells
  const outboundAborts: string[] = [];
  const epc = {
    withPeerId: PEER_ID,
    pqHealingState: pq,
    createDataChannel: (label: string) =>
      new FakeChannel(label) as unknown as IRTCDataChannel,
  } as unknown as IRTCPeerConnection;
  installCoverEdge({
    epc,
    roomId: ROOM_ID,
    policy: receiverPolicy(),
    policyHash: new Uint8Array(32),
    amInitiator: false,
    module,
    onRemoteCancel: (root) => outboundAborts.push(root),
    inboundSweepDeps: spy.deps,
  });
  return {
    epc,
    pq,
    spy,
    outboundAborts,
    destroy: () => {
      teardownCoverEdge(epc);
      pq.destroy();
    },
  };
};

/** The peer's runtime, used only to seal authentic CANCEL cells. */
const makeSender = (): { runtime: CoverRuntime; pq: SparsePqHealingState } => {
  const pq = makePq(true);
  const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM_ID,
    module,
    amInitiator: true,
    schedule: {
      coverCadenceMs: 600_000,
      coverLanes: 2,
      coverFramesPerCell: 2,
      coverDurationEpochs: 1,
    },
    policyHash: new Uint8Array(32),
    laneLabelName: "party",
    openLaneChannel: (label) => new FakeChannel(label),
  });
  return { runtime, pq };
};

describe("shouldSweepCancelledInboundTransfer (what a CANCEL may destroy)", () => {
  test("only an incomplete receive from the cancelling peer", () => {
    expect(shouldSweepCancelledInboundTransfer(rowFor(), PEER_ID)).toBe(true);
  });

  test("never a completed message", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ savedSize: 100, totalSize: 100 }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never another peer's transfer", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ fromPeerId: "peer-b" }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never a row this device sent (transferId marks our own copy)", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ transferId: "ff".repeat(32) }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never an unknown root", () => {
    expect(shouldSweepCancelledInboundTransfer(undefined, PEER_ID)).toBe(false);
  });
});

describe("sweepCancelledInboundTransfer", () => {
  test("forgets the receive key before deleting the partial", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps),
    ).toBe(true);
    expect(spy.forgotten).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
  });

  test("a malformed root is never handed to storage", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, "not-a-root", spy.deps),
    ).toBe(false);
    // Refused before the Worker is asked anything at all — a well-formed root
    // DOES reach it, so this is the guard and not an empty store.
    expect(spy.reads).toEqual([]);
    expect(spy.deleted).toEqual([]);
    await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps);
    expect(spy.reads).toEqual([ROOT_HEX]);
  });
});

describe("an authenticated remote CANCEL sweeps the inbound partial (finding B)", () => {
  test("the receiver's partial is deleted, and the caller's outbound abort still runs", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    const cancelCell = sender.runtime.sealCoverContent({
      subtype: "cancel",
      merkleRoot: ROOT,
    });
    expect(receiver.epc.coverRuntime!.processInboundCoverCell(cancelCell)).toBe(
      true,
    );
    await flush();

    expect(receiver.outboundAborts).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
    expect(spy.rows.has(ROOT_HEX)).toBe(false);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("a CANCEL never destroys a completed message or another peer's transfer", async () => {
    const otherRoot = "ee".repeat(64);
    const spy = makeSweepSpy({
      [ROOT_HEX]: rowFor({ savedSize: 100, totalSize: 100 }),
      [otherRoot]: rowFor({ merkleRoot: otherRoot, fromPeerId: "peer-b" }),
    });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    for (const root of [ROOT, new Uint8Array(64).fill(0xee)]) {
      const cell = sender.runtime.sealCoverContent({
        subtype: "cancel",
        merkleRoot: root,
      });
      expect(receiver.epc.coverRuntime!.processInboundCoverCell(cell)).toBe(
        true,
      );
    }
    await flush();

    expect(spy.deleted).toEqual([]);
    expect(spy.rows.size).toBe(2);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("a forged CANCEL sweeps nothing, because it never authenticates", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    const cell = sender.runtime.sealCoverContent({
      subtype: "cancel",
      merkleRoot: ROOT,
    });
    cell[WIRE_CHUNK_FRAME_LEN - 1] ^= 1;
    expect(receiver.epc.coverRuntime!.processInboundCoverCell(cell)).toBe(
      false,
    );
    await flush();

    expect(spy.deleted).toEqual([]);
    expect(spy.rows.has(ROOT_HEX)).toBe(true);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });
});

describe("A + B together: a healthy in-progress transfer survives", () => {
  // A cadence wide enough that ONE job spans most of a cycle, so a bound can
  // expire while the transfer is genuinely mid-flight — the only situation in
  // which a spurious cancellation can destroy data.
  const SEND_SCHEDULE = {
    coverCadenceMs: 4_000,
    coverLanes: 2,
    coverFramesPerCell: 20,
    coverDurationEpochs: 1,
  };
  const CYCLE_MS =
    SEND_SCHEDULE.coverCadenceMs * SEND_SCHEDULE.coverDurationEpochs;
  // coverTransfer.scheduledDeliveryTimeoutMs without its fixed 20 s head-room,
  // which exists to absorb real-world jitter and would swamp a scaled clock:
  // 2 x cycle + the last lane's first slot. This IS the arithmetic floor the
  // shipped bound is built from, and treating it as a deadline is finding A.
  const ARITHMETIC_FLOOR_MS =
    2 * CYCLE_MS +
    Math.ceil(
      ((2 * SEND_SCHEDULE.coverLanes - 1) * SEND_SCHEDULE.coverCadenceMs) /
        (2 * SEND_SCHEDULE.coverLanes * SEND_SCHEDULE.coverFramesPerCell),
    );
  const CELLS = SEND_SCHEDULE.coverFramesPerCell;

  interface SendRig {
    readonly epc: IRTCPeerConnection;
    readonly runtime: CoverRuntime;
    readonly pq: SparsePqHealingState;
    readonly clock: FakeClock;
    readonly lanes: FakeChannel[];
    readonly jobLabel: string;
  }

  const makeSendRig = (): SendRig => {
    const pq = makePq(true);
    const clock = new FakeClock(0);
    const lanes: FakeChannel[] = [];
    const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
    const runtime = new CoverRuntime({
      epc,
      roomId: ROOM_ID,
      module,
      amInitiator: true,
      schedule: SEND_SCHEDULE,
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (label) => {
        const lane = new FakeChannel(label);
        lanes.push(lane);
        return lane;
      },
      maxTimerDriftMs: 0,
      clock,
    });
    epc.coverRuntime = runtime;

    // Four other messages ahead of ours on a two-lane edge, so ours is admitted
    // only at the third cycle open — after the arithmetic floor assumes it was
    // already confirmed. Exactly the contention of finding A.
    for (let i = 0; i < 4; i++)
      runtime.enqueue({
        id: `${(i + 1).toString(16).repeat(64)}~${(i + 1).toString(16).repeat(128)}`,
        kind: "real",
        declaredCellCount: CELLS,
        nextCell: () => runtime.sealCoverContent({ subtype: "dummy" }),
      });
    const jobLabel = `${"ab".repeat(32)}~${ROOT_HEX}`;
    runtime.enqueue(
      buildScheduledSendJob({
        runtime,
        channelMessageLabel: jobLabel,
        totalChunks: CELLS,
        merkleRoot: ROOT,
        // Real chunk cells are sealed under the message key; sealing them as
        // authentic dummy cover cells lets the receiver ingest every byte this
        // send puts on the wire and prove no CANCEL is among them.
        sealSlotCell: () => runtime.sealCoverContent({ subtype: "dummy" }),
      }),
    );
    runtime.start();
    return { epc, runtime, pq, clock, lanes, jobLabel };
  };

  const feedEverythingSent = (rig: SendRig, receiver: Receiver): void => {
    for (const lane of rig.lanes)
      for (const cell of lane.sent)
        receiver.epc.coverRuntime!.processInboundCoverCell(cell);
  };

  test("the progress-gated wait never cancels a send that is still emitting, so the receiver keeps its partial", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const rig = makeSendRig();

    let receiptLanded = false;
    const delivered = await waitForScheduledDelivery({
      isComplete: () => receiptLanded,
      progressToken: () =>
        scheduledSendProgressToken(rig.runtime, rig.jobLabel),
      idleTimeoutMs: ARITHMETIC_FLOOR_MS,
      pollMs: 50,
      now: () => rig.clock.now(),
      sleep: async (ms) => {
        await rig.clock.advanceTo(rig.clock.now() + ms);
        // The terminal receipt can only exist once every cell is out; model it
        // as the job leaving the scheduler.
        if (rig.runtime.getJobProgress(rig.jobLabel) === undefined)
          receiptLanded = true;
      },
    });

    expect(delivered).toBe(true);
    // Confirmed well past the deadline the arithmetic bound would have set.
    expect(rig.clock.now()).toBeGreaterThan(ARITHMETIC_FLOOR_MS);

    // The whole message reached the wire, so the receiver's partial was
    // filling the entire time the old bound would have been cancelling it.
    const jobLane = rig.lanes.find((lane) => lane.label === rig.jobLabel);
    expect(jobLane?.sent.length).toBe(CELLS);

    // Production cancels only when delivery was NOT confirmed. It was, so every
    // cell this send emitted reaches the receiver and none of them is a CANCEL.
    feedEverythingSent(rig, receiver);
    await flush();
    expect(receiver.outboundAborts).toEqual([]);
    expect(spy.deleted).toEqual([]);
    expect(spy.rows.get(ROOT_HEX)?.savedSize).toBe(40);

    rig.runtime.destroy();
    rig.pq.destroy();
    receiver.destroy();
  });

  test("CONTROL: the same floor used as a DEADLINE cancels mid-flight, and the receiver's partial IS destroyed", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const rig = makeSendRig();

    const delivered = await waitForScheduledDelivery({
      isComplete: () => false,
      // The pre-fix bound: elapsed time only, blind to the job's own advance.
      progressToken: () => undefined,
      idleTimeoutMs: ARITHMETIC_FLOOR_MS,
      pollMs: 50,
      now: () => rig.clock.now(),
      sleep: async (ms) => {
        await rig.clock.advanceTo(rig.clock.now() + ms);
      },
    });
    expect(delivered).toBe(false);

    // The job was admitted and part-way through emitting when the deadline
    // expired: the receiver is holding a partial that is still filling.
    const midFlight = rig.runtime.getJobProgress(rig.jobLabel);
    expect(midFlight?.state).toBe("admitted");
    expect(midFlight!.sentCells).toBeGreaterThan(0);
    expect(midFlight!.sentCells).toBeLessThan(CELLS);

    // Exactly what sendScheduled does on a failed delivery.
    expect(cancelScheduledSend(rig.epc, rig.jobLabel)).toBe("cancel-pending");
    await rig.clock.advanceTo(rig.clock.now() + CYCLE_MS);

    feedEverythingSent(rig, receiver);
    await flush();
    expect(receiver.outboundAborts).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
    expect(spy.rows.has(ROOT_HEX)).toBe(false);

    rig.runtime.destroy();
    rig.pq.destroy();
    receiver.destroy();
  });
});
