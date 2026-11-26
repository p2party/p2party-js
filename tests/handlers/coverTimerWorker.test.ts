import { beforeAll, describe, expect, spyOn, test } from "bun:test";

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
  getCoverTimerSource,
  pendingCoverTimerWakeUps,
} from "../../src/handlers/coverTimerWorker";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
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

/** Every log line written so far by a console method spy. */
const lines = (spy: ReturnType<typeof spyOn>): string[] =>
  spy.mock.calls.map((args: unknown[]) => args.map(String).join(" "));

const cycles = (count: number): number => count * SCHEDULE.coverCadenceMs;

describe("scheduled cover's wake-ups come from a timer worker", () => {
  test("slot wake-ups come from the worker, not page timers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      expect(rig.runtime.timerSource).toBe("worker");
      expect(getCoverTimerSource(timeline.env)).toBe("worker");
      await timeline.advanceTo(cycles(4) - 1);

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
      timeline.browserPage = false;
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

  test("nothing posted to the timer worker contains key material or peer identifiers", async () => {
    const timeline = new CoverTimeline();
    // At the thaw the page's overdue backstop runs first, so it probes.
    timeline.timersFirstAtThaw = true;
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(3));
      // A freeze makes the page probe the worker, so a ping is posted too.
      timeline.freezePage(20_000);
      await timeline.advanceTo(timeline.time + 25_000);
      const posted = timeline.workers[0].posted;
      expect(
        posted.some((message) => (message as { op: string }).op === "ping"),
      ).toBe(true);

      // Slot delays and opaque integer handles, nothing else.
      for (const message of posted) {
        const fields = message as Record<string, unknown>;
        expect(["arm", "cancel", "ping"]).toContain(fields.op as string);
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
      await timeline.advanceTo(cycles(1) + 150);
      const [worker] = timeline.workers;
      expect(worker.armedTimers()).toBeGreaterThan(0);

      // The edge is retired.
      teardownCoverEdge(epc);

      expect(worker.terminated).toBe(true);
      expect(worker.armedTimers()).toBe(0);
      expect(timeline.armedPageTimers()).toBe(0);
      expect(pendingCoverTimerWakeUps(timeline.env)).toBe(0);
      expect(getCoverTimerSource(timeline.env)).toBe("none");
      // Nothing fires for it afterwards.
      const runsBefore = timeline.pageTimerRuns;
      await timeline.advanceTo(cycles(20));
      expect(timeline.pageTimerRuns).toBe(runsBefore);
    } finally {
      teardownCoverEdge(epc);
      pq.destroy();
    }
  });

  test("a schedule the scheduler refuses does not keep the timer worker", () => {
    const timeline = new CoverTimeline();
    const pq = makePq();
    try {
      expect(
        () =>
          new CoverRuntime({
            epc: { pqHealingState: pq } as unknown as IRTCPeerConnection,
            roomId: ROOM_ID,
            module,
            amInitiator: true,
            // 10 ms over 4 slots is under the 25 ms slot minimum.
            schedule: { ...SCHEDULE, coverCadenceMs: 10 },
            policyHash: new Uint8Array(32),
            laneLabelName: "party",
            openLaneChannel: (label) => new FakeLane(label),
            maxTimerDriftMs: 0,
            timerEnvironment: timeline.env,
          }),
      ).toThrow("25ms");
      expect(timeline.workers.every((worker) => worker.terminated)).toBe(true);
      expect(getCoverTimerSource(timeline.env)).toBe("none");
    } finally {
      pq.destroy();
    }
  });
});

describe("one timer worker serves every edge on the page", () => {
  test("every edge on the page shares one timer worker", async () => {
    const timeline = new CoverTimeline();
    const first = makeRuntime(timeline);
    const second = makeRuntime(timeline);
    try {
      first.runtime.start();
      second.runtime.start();
      await timeline.advanceTo(cycles(3) - 1);
      expect(timeline.workers).toHaveLength(1);
      expect(first.sentCells()).toBe(3 * CELLS_PER_CYCLE);
      expect(second.sentCells()).toBe(3 * CELLS_PER_CYCLE);
      // One counter for the whole page: no handle repeats across the edges.
      const ids = timeline.workers[0].posted
        .filter((message) => (message as { op: string }).op === "arm")
        .map((message) => (message as { id: number }).id);
      expect(new Set(ids).size).toBe(ids.length);
    } finally {
      first.runtime.destroy();
      second.runtime.destroy();
      first.pq.destroy();
      second.pq.destroy();
    }
  });

  test("the shared worker is terminated when the last runtime is destroyed", async () => {
    const timeline = new CoverTimeline();
    const first = makeRuntime(timeline);
    const second = makeRuntime(timeline);
    try {
      first.runtime.start();
      second.runtime.start();
      await timeline.advanceTo(cycles(1));
      const [worker] = timeline.workers;

      first.runtime.destroy();
      expect(worker.terminated).toBe(false);
      second.runtime.destroy();
      expect(worker.terminated).toBe(true);
      expect(getCoverTimerSource(timeline.env)).toBe("none");
    } finally {
      first.pq.destroy();
      second.pq.destroy();
    }
  });

  test("destroying one runtime cancels only its own timers", async () => {
    const timeline = new CoverTimeline();
    const first = makeRuntime(timeline);
    const second = makeRuntime(timeline);
    try {
      first.runtime.start();
      second.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      const [worker] = timeline.workers;
      const firstCells = first.sentCells();
      const pendingBoth = pendingCoverTimerWakeUps(timeline.env);
      expect(pendingBoth).toBe(2);
      // Let the worker fire the destroyed runtime's handle anyway, as a tick
      // already in flight would: it must be dropped, not run.
      worker.ignoreCancels = true;
      const handlesBefore = worker.armedIds();

      first.runtime.destroy();
      worker.ignoreCancels = false;

      // The destroyed runtime's one pending wake-up was cancelled, and only
      // it: the other edge's is still armed in the worker and keeps running.
      expect(pendingCoverTimerWakeUps(timeline.env)).toBe(1);
      expect(handlesBefore).toHaveLength(2);
      // Every cancel was for the destroyed runtime: none names a handle the
      // other edge still uses.
      const cancelled = worker.posted
        .filter((message) => (message as { op: string }).op === "cancel")
        .map((message) => (message as { id: number }).id);
      expect(cancelled.length).toBeGreaterThan(0);
      const secondHandle = handlesBefore.find(
        (handle) => !cancelled.includes(handle),
      );
      expect(secondHandle).toBeDefined();
      await timeline.advanceTo(cycles(5) - 1);
      expect(first.sentCells()).toBe(firstCells);
      expect(second.sentCells()).toBe(5 * CELLS_PER_CYCLE);
    } finally {
      second.runtime.destroy();
      first.pq.destroy();
      second.pq.destroy();
    }
  });

  test("creating and destroying 100 runtimes leaves no worker and no pending timer", async () => {
    const timeline = new CoverTimeline();
    for (let i = 0; i < 100; i++) {
      const rig = makeRuntime(timeline);
      rig.runtime.start();
      await timeline.advanceTo(timeline.time + 150);
      rig.runtime.destroy();
      rig.pq.destroy();
    }
    expect(timeline.workers.every((worker) => worker.terminated)).toBe(true);
    expect(
      timeline.workers.reduce(
        (total, worker) => total + worker.armedTimers(),
        0,
      ),
    ).toBe(0);
    expect(pendingCoverTimerWakeUps(timeline.env)).toBe(0);
    expect(timeline.armedPageTimers()).toBe(0);
    expect(getCoverTimerSource(timeline.env)).toBe("none");
  });
});

describe("a worker is not dropped for a late page, and a dead one is replaced", () => {
  test("a freeze longer than the stall bound does not drop a healthy worker", async () => {
    const timeline = new CoverTimeline();
    // At the thaw the page's overdue backstops run before the worker's queued
    // messages: the order that used to drop a healthy worker.
    timeline.timersFirstAtThaw = true;
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      // The page is frozen for 20 s, four times the stall bound; the worker
      // keeps ticking and its messages wait for the page.
      timeline.freezePage(20_000);
      await timeline.advanceTo(timeline.time + 21_000);

      const [worker] = timeline.workers;
      expect(timeline.workers).toHaveLength(1);
      expect(worker.terminated).toBe(false);
      expect(rig.runtime.timerSource).toBe("worker");
      // It was asked, and it answered.
      expect(
        worker.posted.some(
          (message) => (message as { op: string }).op === "ping",
        ),
      ).toBe(true);
      // The schedule went on on the worker after the thaw.
      const after = rig.sentCells();
      await timeline.advanceTo(timeline.time + cycles(5));
      expect(rig.sentCells()).toBeGreaterThanOrEqual(
        after + 4 * CELLS_PER_CYCLE,
      );
      expect(timeline.pageTimerRuns).toBeLessThan(10);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a system sleep does not drop a healthy worker", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      // The whole process sleeps for a minute: page and worker alike.
      await timeline.sleep(60_000);
      await timeline.advanceTo(timeline.time + 100);

      expect(timeline.workers).toHaveLength(1);
      expect(timeline.workers[0].terminated).toBe(false);
      expect(rig.runtime.timerSource).toBe("worker");
      const after = rig.sentCells();
      await timeline.advanceTo(timeline.time + cycles(5));
      expect(rig.sentCells()).toBeGreaterThanOrEqual(
        after + 4 * CELLS_PER_CYCLE,
      );
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a dead worker falls back to page timers", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      expect(rig.sentCells()).toBeGreaterThan(0);

      // The worker crashes mid-cycle: its error event.
      timeline.workers[0].fail();
      expect(rig.runtime.timerSource).toBe("page");
      expect(timeline.workers[0].terminated).toBe(true);

      await timeline.advanceTo(cycles(6) - 1);
      // The schedule kept running, on time, without a gap.
      expect(rig.sentCells()).toBe(6 * CELLS_PER_CYCLE);
      expect(rig.statuses).not.toContain("stopped");
      expect(rig.statuses).not.toContain("degraded");
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a dead worker is replaced at the next cycle boundary", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      // Mid-cycle 2 (cycles are 400 ms).
      await timeline.advanceTo(cycles(2) + 150);
      timeline.workers[0].fail();
      expect(rig.runtime.timerSource).toBe("page");

      // The backoff is 1 s (to 1,950 ms), so the boundary at 2,000 ms is the
      // first one a replacement may carry. Its wake-up is armed at 1,950 ms,
      // after the cycle's last slot: still page timers just before that...
      await timeline.advanceTo(1_949);
      expect(timeline.workers).toHaveLength(1);
      expect(rig.runtime.timerSource).toBe("page");
      // ...and the replacement worker, created for that boundary's wake-up,
      // carries the next cycle.
      await timeline.advanceTo(cycles(5) + 1);
      expect(timeline.workers).toHaveLength(2);
      expect(rig.runtime.timerSource).toBe("worker");
      const boundaryArm = timeline.workers[1].posted[0] as {
        op: string;
        delayMs: number;
      };
      expect(boundaryArm.op).toBe("arm");
      expect(1_950 + boundaryArm.delayMs).toBe(cycles(5));
      await timeline.advanceTo(cycles(8) - 1);
      const arms = timeline.workers[1].posted.filter(
        (message) => (message as { op: string }).op === "arm",
      );
      expect(arms.length).toBeGreaterThanOrEqual(2 * CELLS_PER_CYCLE);
      expect(rig.sentCells()).toBe(8 * CELLS_PER_CYCLE);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a worker that does not answer its ping is replaced", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      // Terminated by the browser, or wedged: it takes requests and never
      // answers, and no error event says so.
      timeline.workers[0].wedged = true;

      // 5 s stall, then 10 s for the ping, then a replacement at a boundary.
      await timeline.advanceTo(cycles(1) + 20_000);
      expect(timeline.workers[0].terminated).toBe(true);
      expect(timeline.workers).toHaveLength(2);
      expect(rig.runtime.timerSource).toBe("worker");
      expect(rig.statuses).not.toContain("stopped");
      const late = rig.sentCells();
      await timeline.advanceTo(timeline.time + cycles(10));
      expect(rig.sentCells()).toBeGreaterThanOrEqual(
        late + 9 * CELLS_PER_CYCLE,
      );
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("after the attempts are exhausted the runtime stays on page timers and says so", async () => {
    const warn = spyOn(console, "warn").mockImplementation(() => undefined);
    const timeline = new CoverTimeline();
    const rig = makeRuntime(timeline);
    try {
      rig.runtime.start();
      await timeline.advanceTo(cycles(1) + 150);
      // From now on no worker can be made, and the one that runs dies.
      timeline.failWorkerCreation = true;
      timeline.workers[0].fail();

      // Replacements are tried after 1, 2 and 4 s, each at a boundary.
      await timeline.advanceTo(timeline.time + 15_000);
      expect(rig.runtime.timerSource).toBe("page");
      expect(getCoverTimerSource(timeline.env)).toBe("page");
      expect(timeline.workers).toHaveLength(1);

      // Said once, without debug logging, and naming nothing of the edge.
      const reports = lines(warn).filter((line) =>
        /page timers for good/.test(line),
      );
      expect(reports).toHaveLength(1);
      expect(reports[0]).toContain("3 replacements failed");
      for (const forbidden of [ROOM_ID, PEER_ID, uint8ArrayToHex(PQ_ROOT)])
        expect(reports[0]).not.toContain(forbidden);

      // And it stays there: no further attempt, the schedule still runs.
      await timeline.advanceTo(timeline.time + 30_000);
      expect(rig.runtime.timerSource).toBe("page");
      expect(
        lines(warn).filter((line) => /page timers/.test(line)),
      ).toHaveLength(1);
      const sent = rig.sentCells();
      await timeline.advanceTo(timeline.time + cycles(5));
      expect(rig.sentCells()).toBeGreaterThanOrEqual(
        sent + 4 * CELLS_PER_CYCLE,
      );
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
      warn.mockRestore();
    }
  });

  test("where no worker can be created it is reported once, without debug logging", () => {
    const warn = spyOn(console, "warn").mockImplementation(() => undefined);
    const log = spyOn(console, "log").mockImplementation(() => undefined);
    try {
      const timeline = new CoverTimeline();
      timeline.workersAvailable = false;
      const clock = createCoverTimerClock(timeline.env);
      expect(clock.source).toBe("page");
      clock.setTimeout(() => undefined, 10);
      clock.setTimeout(() => undefined, 20);
      const reports = lines(warn).filter((line) => /page timers/.test(line));
      expect(reports).toHaveLength(1);
      expect(reports[0]).toContain("no timer worker can be created");
      expect(log).not.toHaveBeenCalled();
      clock.destroy();
    } finally {
      warn.mockRestore();
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

  test("it answers a ping with the same handle", () => {
    const worker = loadWorker();
    worker.scope.onmessage?.({ data: { op: "ping", id: 7 } });
    expect(worker.posted).toEqual([{ op: "pong", id: 7 }]);
  });
});
