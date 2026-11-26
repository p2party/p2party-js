import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";

// A hidden page keeps scheduled cover armed (suspending it made tab visibility
// readable off the wire), and the browser throttles its timers. A cycle whose
// cells fire late degrades without sending, so a hidden SENDER's only progress
// signal freezes while its transfer is perfectly healthy, exactly as it did
// when a hidden page suspended cover. Its delivery idle budget must be held
// exactly as it was then: spending the budget through the gap gives the send
// up, and the CANCEL that follows deletes the partial the receiver holds.
//
// The rig mirrors inboundCancelSweep.test.ts's "A + B" rig: a real
// CoverRuntime on a fake clock as the sender, a real installCoverEdge receiver
// over a synchronous storage double, and the real waitForScheduledDelivery.

// The production state-row deletion dispatches into the real Redux store,
// whose identity slice reads localStorage at module initialization.
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

import {
  cancelScheduledSend,
  installCoverEdge,
  teardownCoverEdge,
} from "../../src/handlers/coverEdge";
import { CoverRuntime } from "../../src/handlers/coverRuntime";
import {
  buildScheduledSendJob,
  scheduledCoverIsSuspended,
  scheduledSendProgress,
  waitForScheduledDelivery,
} from "../../src/handlers/coverTransfer";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import { RATCHET_ROOT_SUITE_MLKEM512 } from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { InboundTransferSweepDeps } from "../../src/handlers/inboundTransferSweep";
import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverSchedulerStatus,
} from "../../src/handlers/coverScheduler";
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

// ── the page ─────────────────────────────────────────────────────────────────

class FakeDocument {
  visibilityState: DocumentVisibilityState = "visible";
  private readonly listeners = new Map<string, Set<EventListener>>();

  addEventListener(type: string, listener: EventListener): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  setHidden(hidden: boolean): void {
    this.visibilityState = hidden ? "hidden" : "visible";
    for (const listener of [...(this.listeners.get("visibilitychange") ?? [])])
      listener(new Event("visibilitychange"));
  }
}

let page: FakeDocument;
const globals = globalThis as unknown as { document?: unknown };
let hadDocument = false;
let previousDocument: unknown;

beforeEach(() => {
  hadDocument = "document" in globals;
  previousDocument = globals.document;
  page = new FakeDocument();
  globals.document = page;
});

afterEach(() => {
  if (hadDocument) globals.document = previousDocument;
  else delete globals.document;
});

// ── deterministic storage double for the receiver's inbound sweep ───────────

interface SweepSpy {
  readonly deps: InboundTransferSweepDeps;
  readonly rows: Map<string, MessageData>;
  readonly deleted: string[];
}

const partialRow = (): MessageData => ({
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
});

const makeSweepSpy = (): SweepSpy => {
  const rows = new Map<string, MessageData>([[ROOT_HEX, partialRow()]]);
  const deleted: string[] = [];
  return {
    rows,
    deleted,
    deps: {
      waitForReceiveIdle: async () => undefined,
      dropStateRow: () => undefined,
      readProgress: async (merkleRootHex?: string) =>
        merkleRootHex === undefined ? undefined : rows.get(merkleRootHex),
      forgetKey: async () => true,
      deleteReceive: async (merkleRootHex: string) => {
        deleted.push(merkleRootHex);
        rows.delete(merkleRootHex);
        return true;
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
  private time = 0;
  private nextId = 1;
  private readonly timers = new Map<number, FakeTimer>();

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

  /** Timers fire on time. */
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

  /** Throttled timers: everything due by `target` fires late, AT `target`. */
  async jumpTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    this.time = target;
    await this.advanceTo(target);
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

interface Receiver {
  readonly epc: IRTCPeerConnection;
  readonly outboundAborts: string[];
  destroy(): void;
}

/** The peer: authenticates the sender's cells and sweeps on a CANCEL. */
const makeReceiver = (spy: SweepSpy): Receiver => {
  const pq = makePq(false);
  const outboundAborts: string[] = [];
  const epc = {
    withPeerId: PEER_ID,
    pqHealingState: pq,
    createDataChannel: (label: string) =>
      new FakeChannel(label) as unknown as IRTCDataChannel,
  } as unknown as IRTCPeerConnection;
  // A cadence far longer than any test run, so the receiver's real-timer edge
  // never opens a cycle: it only authenticates inbound cells.
  const policy: RoomPolicyV1 = {
    ...DEFAULT_ROOM_POLICY_V1,
    coverMode: "scheduled",
    coverCadenceMs: 600_000,
    coverLanes: 2,
    coverFramesPerCell: 2,
    coverDurationEpochs: 1,
  };
  installCoverEdge({
    epc,
    roomId: ROOM_ID,
    policy,
    policyHash: new Uint8Array(32),
    amInitiator: false,
    module,
    onRemoteCancel: (root) => outboundAborts.push(root),
    inboundSweepDeps: spy.deps,
  });
  return {
    epc,
    outboundAborts,
    destroy: () => {
      teardownCoverEdge(epc);
      pq.destroy();
    },
  };
};

// One job spans most of a cycle, so a budget can expire while the transfer is
// genuinely mid-flight.
const SEND_SCHEDULE = {
  coverCadenceMs: 4_000,
  coverLanes: 2,
  coverFramesPerCell: 20,
  coverDurationEpochs: 1,
};
const CYCLE_MS =
  SEND_SCHEDULE.coverCadenceMs * SEND_SCHEDULE.coverDurationEpochs;
// coverTransfer.scheduledDeliveryTimeoutMs without its fixed real-world
// head-room: 2 x cycle + the last lane's first slot.
const IDLE_BUDGET_MS =
  2 * CYCLE_MS +
  Math.ceil(
    ((2 * SEND_SCHEDULE.coverLanes - 1) * SEND_SCHEDULE.coverCadenceMs) /
      (2 * SEND_SCHEDULE.coverLanes * SEND_SCHEDULE.coverFramesPerCell),
  );
const CELLS = SEND_SCHEDULE.coverFramesPerCell;
// Three whole budgets hidden.
const HIDDEN_MS = 3 * IDLE_BUDGET_MS;
// A hidden tab's clamped timers arrive about once a second. Deliberately not a
// divisor of the cycle or slot grid, so no throttled timer lands on time.
const THROTTLED_TICK_MS = 1_037;

interface SendRig {
  readonly epc: IRTCPeerConnection;
  readonly runtime: CoverRuntime;
  readonly pq: SparsePqHealingState;
  readonly clock: FakeClock;
  readonly lanes: FakeChannel[];
  readonly statuses: CoverSchedulerStatus[];
  readonly jobLabel: string;
}

const makeSendRig = (): SendRig => {
  const pq = makePq(true);
  const clock = new FakeClock();
  const lanes: FakeChannel[] = [];
  const statuses: CoverSchedulerStatus[] = [];
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
    onStatusChange: ({ status }) => statuses.push(status),
    maxTimerDriftMs: 0,
    clock,
  });
  epc.coverRuntime = runtime;
  // Four other messages ahead of ours on a two-lane edge: ours is admitted at
  // the third cycle open.
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
      // Authentic dummy cells let the receiver ingest every byte this send
      // puts on the wire and prove no CANCEL is among them.
      sealSlotCell: () => runtime.sealCoverContent({ subtype: "dummy" }),
    }),
  );
  runtime.start();
  return { epc, runtime, pq, clock, lanes, statuses, jobLabel };
};

const jobCellsOnWire = (rig: SendRig): number =>
  rig.lanes
    .filter((lane) => lane.label === rig.jobLabel)
    .reduce((total, lane) => total + lane.sent.length, 0);

interface HiddenRun {
  readonly delivered: boolean;
  readonly hiddenUntilMs: number;
  readonly cellsAtHide: number;
  readonly cellsAtShow: number;
}

/**
 * Admit the send, emit part of it, hide the page, and wait the way
 * sendScheduled does. While hidden every timer arrives late; the page becomes
 * visible again HIDDEN_MS later, from inside the wait's own sleep, so a wait
 * that gave up earlier never sees it come back.
 */
const runHidden = async (
  rig: SendRig,
  isSuspended: () => boolean,
): Promise<HiddenRun> => {
  await rig.clock.advanceTo(2 * CYCLE_MS + CYCLE_MS / 2);
  const midFlight = rig.runtime.getJobProgress(rig.jobLabel);
  expect(midFlight?.state).toBe("admitted");
  expect(midFlight!.sentCells).toBeGreaterThan(0);
  expect(midFlight!.sentCells).toBeLessThan(CELLS);

  page.setHidden(true);
  // Cover stays armed while hidden.
  expect(rig.runtime.status).toBe("active");

  const cellsAtHide = jobCellsOnWire(rig);
  const hiddenUntilMs = rig.clock.now() + HIDDEN_MS;
  let cellsAtShow = -1;
  let receiptLanded = false;
  const delivered = await waitForScheduledDelivery({
    isComplete: () => receiptLanded,
    progress: () => scheduledSendProgress(rig.runtime, rig.jobLabel),
    isSuspended,
    idleTimeoutMs: IDLE_BUDGET_MS,
    pollMs: 50,
    now: () => rig.clock.now(),
    sleep: async (ms) => {
      if (page.visibilityState === "hidden") {
        await rig.clock.jumpTo(rig.clock.now() + THROTTLED_TICK_MS);
        if (rig.clock.now() >= hiddenUntilMs) {
          cellsAtShow = jobCellsOnWire(rig);
          page.setHidden(false);
        }
      } else {
        await rig.clock.advanceTo(rig.clock.now() + ms);
      }
      // The terminal receipt cannot exist before every cell is out; model it
      // as the job leaving the scheduler.
      if (rig.runtime.getJobProgress(rig.jobLabel) === undefined)
        receiptLanded = true;
    },
  });
  return { delivered, hiddenUntilMs, cellsAtHide, cellsAtShow };
};

describe("a hidden sender is not a stalled sender", () => {
  test("a hidden sender's idle budget is held", async () => {
    const rig = makeSendRig();
    try {
      const run = await runHidden(rig, () =>
        scheduledCoverIsSuspended(rig.runtime),
      );

      expect(run.delivered).toBe(true);
      // It waited out the whole hidden interval instead of giving up inside it.
      expect(rig.clock.now()).toBeGreaterThan(run.hiddenUntilMs);
      // The throttled timers really did stop all progress while hidden: three
      // budgets went by without a single cell of this job.
      expect(run.cellsAtShow).toBe(run.cellsAtHide);
      // ...and cover degraded honestly rather than being suspended.
      expect(rig.statuses).toContain("degraded");
      expect(rig.statuses).not.toContain("suspended");
      // The transfer continued once the page came back.
      expect(jobCellsOnWire(rig)).toBeGreaterThan(run.cellsAtShow);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("CONTROL: without the hold, the hidden sender's budget expires while it is hidden", async () => {
    const rig = makeSendRig();
    try {
      const run = await runHidden(rig, () => false);
      expect(run.delivered).toBe(false);
      expect(rig.clock.now()).toBeLessThan(run.hiddenUntilMs);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a hidden sender does not cancel a transfer because its timers were throttled", async () => {
    const spy = makeSweepSpy();
    const receiver = makeReceiver(spy);
    const rig = makeSendRig();
    try {
      const run = await runHidden(rig, () =>
        scheduledCoverIsSuspended(rig.runtime),
      );

      // Exactly what sendScheduled does when delivery is not confirmed.
      if (!run.delivered) cancelScheduledSend(rig.epc, rig.jobLabel);
      await rig.clock.advanceTo(rig.clock.now() + 2 * CYCLE_MS);

      for (const lane of rig.lanes)
        for (const cell of lane.sent)
          receiver.epc.coverRuntime!.processInboundCoverCell(cell);
      await flush();

      expect(receiver.outboundAborts).toEqual([]);
      expect(spy.deleted).toEqual([]);
      expect(spy.rows.get(ROOT_HEX)?.savedSize).toBe(40);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
      receiver.destroy();
    }
  });

  test("a hidden page does not hold the budget of an edge whose cover is gone", () => {
    page.setHidden(true);
    expect(scheduledCoverIsSuspended(undefined)).toBe(false);
    expect(scheduledCoverIsSuspended({ status: "stopped" })).toBe(false);
    expect(scheduledCoverIsSuspended({ status: "degraded" })).toBe(true);
    page.setHidden(false);
    expect(scheduledCoverIsSuspended({ status: "degraded" })).toBe(false);
    expect(scheduledCoverIsSuspended({ status: "suspended" })).toBe(true);
  });
});
