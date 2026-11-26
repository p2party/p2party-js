import { afterEach, beforeAll, describe, expect, spyOn, test } from "bun:test";

// The production state-row deletion behind installCoverEdge dispatches into
// the Redux store, whose identity slice reads localStorage at module
// initialization.
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

import { CoverRuntime } from "../../src/handlers/coverRuntime";
import {
  installCoverEdge,
  teardownCoverEdge,
} from "../../src/handlers/coverEdge";
import {
  COVER_TIMER_WORKER_SOURCE,
  createCoverTimerClock,
} from "../../src/handlers/coverTimerWorker";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import { setDebugLogging } from "../../src/utils/debug";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import { RATCHET_ROOT_SUITE_MLKEM512 } from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";
import { CoverTimeline } from "./coverTimerFakes";

import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type { CoverSchedulerStatus } from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

// Scheduled cover on a hidden page (transport audit 2026-11, item 15, review
// round 1). A hidden page's timers are throttled to about one wake-up a second,
// far past the drift tolerance of a slot, so on page timers every cycle
// degraded and cover visibly collapsed while the tab was hidden. Slot wake-ups
// now come from a dedicated timer worker, which a hidden page does not
// throttle; page timers are the fallback.

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

afterEach(() => {
  setDebugLogging(false);
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000f8";
const PEER_ID = "00000000-0000-4000-8000-0000000000f9";
const PQ_ROOT = new Uint8Array(32).fill(0x19);

// 2 lanes x 2 frames x 1 epoch per 400 ms cycle: one slot every 100 ms, and a
// drift tolerance of 99 ms, as the runtime derives it.
const SCHEDULE = {
  coverCadenceMs: 400,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
};
const CELLS_PER_CYCLE = 4;

class FakeLane implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];

  constructor(label: string) {
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    this.sent.push(new Uint8Array(data));
  }

  close(): void {
    this.readyState = "closed";
  }
}

const makePq = (): SparsePqHealingState =>
  new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: Uint8Array.from(PQ_ROOT),
    nextOfferer: "local",
    amInitiator: true,
    now: 0,
  });

const makeRuntime = (timeline: CoverTimeline) => {
  const pq = makePq();
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    pqHealingState: pq,
  } as unknown as IRTCPeerConnection;
  const lanes: FakeLane[] = [];
  const statuses: CoverSchedulerStatus[] = [];
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM_ID,
    module,
    amInitiator: true,
    schedule: SCHEDULE,
    policyHash: new Uint8Array(32),
    laneLabelName: "party",
    openLaneChannel: (label) => {
      const lane = new FakeLane(label);
      lanes.push(lane);
      return lane;
    },
    onStatusChange: ({ status }) => statuses.push(status),
    timerEnvironment: timeline.env,
  });
  const sentCells = (): number =>
    lanes.reduce((total, lane) => total + lane.sent.length, 0);
  return { runtime, pq, lanes, statuses, sentCells };
};

describe("scheduled cover's wake-ups come from a timer worker", () => {
  test("slot wake-ups come from the worker, not page timers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      expect(rig.runtime.timerSource).toBe("worker");
      await timeline.advanceTo(4 * SCHEDULE.coverCadenceMs - 1);

      expect(rig.sentCells()).toBe(4 * CELLS_PER_CYCLE);
      expect(rig.statuses).toEqual(["starting", "active"]);
      const [worker] = timeline.workers;
      const arms = worker.posted.filter(
        (message) => (message as { op: string }).op === "arm",
      );
      // One worker wake-up per slot and per boundary...
      expect(arms.length).toBeGreaterThanOrEqual(4 * CELLS_PER_CYCLE);
      // ...and not one page-timer callback: the page timers are only the
      // stall backstops, each cleared when its worker wake-up arrived.
      expect(timeline.pageTimerRuns).toBe(0);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a hidden page's throttled timers do not degrade the cycle", async () => {
    // The same hidden minute twice: once on the timer worker, once on the page
    // timers a runtime without a worker falls back to.
    const runHidden = async (workersAvailable: boolean) => {
      const timeline = new CoverTimeline();
      timeline.workersAvailable = workersAvailable;
      timeline.hidden = true;
      const rig = makeRuntime(timeline);
      try {
        rig.runtime.start();
        await timeline.advanceTo(60_000 - 1);
        return {
          source: rig.runtime.timerSource,
          sentCells: rig.sentCells(),
          degraded: rig.statuses.includes("degraded"),
        };
      } finally {
        rig.runtime.destroy();
        rig.pq.destroy();
      }
    };

    const onWorker = await runHidden(true);
    expect(onWorker.source).toBe("worker");
    expect(onWorker.degraded).toBe(false);
    expect(onWorker.sentCells).toBe(
      (60_000 / SCHEDULE.coverCadenceMs) * CELLS_PER_CYCLE,
    );

    // CONTROL: the page timers degrade cycles and lose cells while hidden.
    const onPage = await runHidden(false);
    expect(onPage.source).toBe("page");
    expect(onPage.degraded).toBe(true);
    expect(onPage.sentCells).toBeLessThan(onWorker.sentCells / 2);
  });

  test("a dead worker falls back to page timers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(SCHEDULE.coverCadenceMs + 150);
      const before = rig.sentCells();
      expect(before).toBeGreaterThan(0);

      // The worker crashes mid-cycle: its error event.
      timeline.workers[0].fail();
      expect(rig.runtime.timerSource).toBe("page");
      expect(timeline.workers[0].terminated).toBe(true);

      await timeline.advanceTo(6 * SCHEDULE.coverCadenceMs - 1);
      // The schedule kept running, on time, on page timers.
      expect(rig.sentCells()).toBe(6 * CELLS_PER_CYCLE);
      expect(rig.statuses).not.toContain("stopped");
      expect(rig.statuses).not.toContain("degraded");
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a worker that stops answering is replaced by page timers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(SCHEDULE.coverCadenceMs + 150);
      // Terminated by the browser, or wedged: it takes requests and never
      // answers, and no error event says so.
      timeline.workers[0].wedged = true;

      await timeline.advanceTo(20 * SCHEDULE.coverCadenceMs);
      expect(rig.runtime.timerSource).toBe("page");
      // The overdue wake-up ran late (honestly degrading one cycle) and the
      // schedule then continued on page timers.
      expect(rig.statuses).not.toContain("stopped");
      const late = rig.sentCells();
      await timeline.advanceTo(30 * SCHEDULE.coverCadenceMs - 1);
      expect(rig.sentCells()).toBe(late + 10 * CELLS_PER_CYCLE);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("nothing posted to the timer worker contains key material or peer identifiers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(3 * SCHEDULE.coverCadenceMs);
      const posted = timeline.workers[0].posted;
      expect(posted.length).toBeGreaterThan(0);

      // Slot delays and opaque integer handles, nothing else.
      for (const message of posted) {
        const fields = message as Record<string, unknown>;
        expect(["arm", "cancel"]).toContain(fields.op as string);
        expect(Number.isSafeInteger(fields.id)).toBe(true);
        const keys = Object.keys(fields).sort();
        if (fields.op === "arm") {
          expect(keys).toEqual(["delayMs", "id", "op"]);
          expect(typeof fields.delayMs).toBe("number");
        } else expect(keys).toEqual(["id", "op"]);
      }

      // And none of what the edge holds appears anywhere in it.
      const wire = JSON.stringify(posted);
      const context = rig.pq.currentMessageContext();
      for (const forbidden of [
        ROOM_ID,
        PEER_ID,
        uint8ArrayToHex(PQ_ROOT),
        uint8ArrayToHex(context.rootKey),
        uint8ArrayToHex(context.binding),
        ...rig.lanes.map((lane) => lane.label),
      ])
        expect(wire).not.toContain(forbidden);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("destroy terminates the timer worker and a retired edge leaves no timer in it", async () => {
    const timeline = new CoverTimeline();
    const pq = makePq();
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: "33".repeat(32),
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        ({
          label,
          readyState: "open",
          bufferedAmount: 0,
          binaryType: "arraybuffer",
          send: () => undefined,
          close: () => undefined,
          addEventListener: () => undefined,
        }) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    const policy: RoomPolicyV1 = {
      ...DEFAULT_ROOM_POLICY_V1,
      coverMode: "scheduled",
      ...SCHEDULE,
    };
    try {
      installCoverEdge({
        epc,
        roomId: ROOM_ID,
        policy,
        policyHash: new Uint8Array(32),
        amInitiator: true,
        module,
        timerEnvironment: timeline.env,
      });
      await timeline.advanceTo(SCHEDULE.coverCadenceMs + 150);
      const [worker] = timeline.workers;
      expect(worker.armedTimers()).toBeGreaterThan(0);

      // The edge is retired.
      teardownCoverEdge(epc);

      expect(worker.terminated).toBe(true);
      expect(worker.armedTimers()).toBe(0);
      expect(timeline.armedPageTimers()).toBe(0);
      // Nothing fires for it afterwards.
      const runsBefore = timeline.pageTimerRuns;
      await timeline.advanceTo(20 * SCHEDULE.coverCadenceMs);
      expect(timeline.pageTimerRuns).toBe(runsBefore);
    } finally {
      teardownCoverEdge(epc);
      pq.destroy();
    }
  });

  test("where no worker can be created the fallback is logged once, never silently", () => {
    setDebugLogging(true);
    const log = spyOn(console, "log").mockImplementation(() => undefined);
    try {
      const timeline = new CoverTimeline();
      timeline.workersAvailable = false;
      const clock = createCoverTimerClock(timeline.env);
      expect(clock.source).toBe("page");
      clock.setTimeout(() => undefined, 10);
      clock.setTimeout(() => undefined, 20);
      const lines = log.mock.calls.map((args) => args.map(String).join(" "));
      expect(lines.filter((line) => /page timers/.test(line))).toHaveLength(1);
      clock.destroy();
    } finally {
      log.mockRestore();
    }
  });
});

describe("the timer worker's own script", () => {
  /** Run the worker source against a fake worker global scope. */
  const loadWorker = () => {
    const posted: unknown[] = [];
    const timers = new Map<number, () => void>();
    let nextTimer = 1;
    const scope: {
      onmessage: ((event: { data: unknown }) => void) | null;
      postMessage: (message: unknown) => void;
    } = {
      onmessage: null,
      postMessage: (message) => posted.push(message),
    };
    const run = new Function(
      "self",
      "setTimeout",
      "clearTimeout",
      COVER_TIMER_WORKER_SOURCE,
    ) as (
      self: typeof scope,
      setTimeout: (callback: () => void) => number,
      clearTimeout: (handle: number) => void,
    ) => void;
    run(
      scope,
      (callback) => {
        const handle = nextTimer++;
        timers.set(handle, callback);
        return handle;
      },
      (handle) => {
        timers.delete(handle);
      },
    );
    const fireAll = () => {
      const due = [...timers.values()];
      timers.clear();
      for (const callback of due) callback();
    };
    return { scope, posted, timers, fireAll };
  };

  test("it arms, cancels and fires by handle, and ignores anything else", () => {
    const worker = loadWorker();
    worker.scope.onmessage?.({ data: { op: "arm", id: 1, delayMs: 100 } });
    worker.scope.onmessage?.({ data: { op: "arm", id: 2, delayMs: 100 } });
    worker.scope.onmessage?.({ data: { op: "cancel", id: 2 } });
    worker.scope.onmessage?.({ data: { op: "arm", id: "x", delayMs: 1 } });
    worker.scope.onmessage?.({ data: null });
    expect(worker.timers.size).toBe(1);

    worker.fireAll();

    expect(worker.posted).toEqual([{ op: "fire", id: 1 }]);
  });
});
