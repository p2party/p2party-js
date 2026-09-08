import { describe, expect, test } from "bun:test";

import { createCoverScheduler, validateCoverSchedule } from "../../src/handlers/coverScheduler";

import type {
  CoverClock,
  CoverJob,
  CoverLane,
  CoverLaneOpenContext,
  CoverSchedule,
  CoverSchedulerStatus,
  CoverSendRequest,
} from "../../src/handlers/coverScheduler";

interface FakeTimer {
  readonly id: number;
  readonly at: number;
  readonly callback: () => void;
}

class FakeClock implements CoverClock {
  private time: number;
  private nextId = 1;
  private readonly timers = new Map<number, FakeTimer>();

  /**
   * One-shot: refuse the next timer request, the way a host under memory
   * pressure can. `CoverScheduler.openCycle` contains no `await`, so a refused
   * slot timer is the only way its promise rejects — which is exactly the
   * route into the boundary-handler catch that used to park the scheduler.
   */
  failNextSetTimeout = false;

  constructor(now = 0) {
    this.time = now;
  }

  now(): number {
    return this.time;
  }

  setTimeout(callback: () => void, delayMs: number): number {
    if (this.failNextSetTimeout) {
      this.failNextSetTimeout = false;
      throw new Error("fake clock refused a timer");
    }
    const id = this.nextId++;
    this.timers.set(id, {
      id,
      at: this.time + delayMs,
      callback,
    });
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") this.timers.delete(handle);
  }

  /** How many timers the scheduler is holding. Zero means it is parked. */
  armedTimerCount(): number {
    return this.timers.size;
  }

  /** Absolute deadline of the soonest armed timer. */
  nextTimerDeadline(): number {
    const soonest = [...this.timers.values()].sort(
      (left, right) => left.at - right.at || left.id - right.id,
    )[0];
    if (!soonest) throw new Error("fake clock holds no armed timer");
    return soonest.at;
  }

  private nextDue(target: number): FakeTimer | undefined {
    return [...this.timers.values()]
      .filter(({ at }) => at <= target)
      .sort((left, right) => left.at - right.at || left.id - right.id)[0];
  }

  private async flush(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    while (true) {
      await this.flush();
      const timer = this.nextDue(target);
      if (!timer) break;
      this.time = Math.max(this.time, timer.at);
      this.timers.delete(timer.id);
      timer.callback();
    }
    this.time = target;
    await this.flush();
  }

  /** Fire overdue callbacks at the jumped-to time to model timer suspension. */
  async jumpTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    this.time = target;
    while (true) {
      await this.flush();
      const timer = this.nextDue(target);
      if (!timer) break;
      this.timers.delete(timer.id);
      timer.callback();
    }
    await this.flush();
  }
}

const schedule = (overrides: Partial<CoverSchedule> = {}): CoverSchedule => ({
  phaseOffsetMs: 0,
  coverCadenceMs: 400,
  coverLanes: 1,
  coverFramesPerCell: 4,
  coverDurationEpochs: 1,
  ...overrides,
});

const bytes = (value: number): Uint8Array => new Uint8Array([value]);

const job = (
  id: string,
  kind: "real" | "control",
  values: readonly number[],
  cancelValue = 0xcc,
): CoverJob => {
  let next = 0;
  return {
    id,
    kind,
    declaredCellCount: values.length,
    async nextCell() {
      return bytes(values[next++]);
    },
    async cancelCell() {
      return bytes(cancelValue);
    },
  };
};

interface Harness {
  readonly clock: FakeClock;
  readonly trace: string[];
  readonly statuses: CoverSchedulerStatus[];
  /** Positional companion of `statuses`; "-" where a change carried none. */
  readonly statusReasons: string[];
  readonly interruptions: string[];
  readonly scheduler: ReturnType<typeof createCoverScheduler>;
}

const harness = (
  selectedSchedule: CoverSchedule,
  startAt = 0,
  accept?: (
    request: CoverSendRequest,
    context: CoverLaneOpenContext,
  ) => boolean | void,
): Harness => {
  const clock = new FakeClock(startAt);
  const trace: string[] = [];
  const statuses: CoverSchedulerStatus[] = [];
  const statusReasons: string[] = [];
  const interruptions: string[] = [];

  const scheduler = createCoverScheduler({
    schedule: selectedSchedule,
    clock,
    makeDummy: () => bytes(0xdd),
    laneFactory(context): CoverLane {
      trace.push(
        `open@${clock.now()}:c${context.cycleIndex}:l${context.laneIndex}:${context.job?.id ?? "-"}`,
      );
      return {
        send(request) {
          trace.push(
            `send@${clock.now()}:d${request.slot.deadlineMs}:e${request.slot.epochIndex}:l${request.slot.laneIndex}:f${request.slot.frameIndex}:${request.source}:${request.cell[0]}`,
          );
          return accept?.(request, context);
        },
        close(closeContext) {
          trace.push(
            `close@${clock.now()}:c${closeContext.cycleIndex}:l${closeContext.laneIndex}:${closeContext.reason}`,
          );
        },
      };
    },
    onStatusChange({ status, reason }) {
      statuses.push(status);
      statusReasons.push(reason ?? "-");
    },
    onJobInterrupted({ jobId, reason }) {
      interruptions.push(`${jobId}:${reason}`);
    },
  });
  return { clock, trace, statuses, statusReasons, interruptions, scheduler };
};

describe("store-free scheduled cover core", () => {
  test("validates non-overlapping schedule geometry and declared capacity", () => {
    expect(() => validateCoverSchedule(schedule({ coverLanes: 17 }))).toThrow(
      "between 1 and 16",
    );
    expect(() =>
      validateCoverSchedule(
        schedule({
          coverCadenceMs: 399,
          coverLanes: 4,
          coverFramesPerCell: 4,
        }),
      ),
    ).toThrow("at least 25ms");

    const { scheduler } = harness(
      schedule({ coverFramesPerCell: 2, coverDurationEpochs: 2 }),
    );
    expect(() =>
      scheduler.enqueue(job("too-large", "real", [1, 2, 3, 4, 5])),
    ).toThrow("F x D lane capacity");
  });

  test("uses absolute phase-shifted cycles and deterministic C x F staggering", async () => {
    const selected = schedule({
      phaseOffsetMs: 100,
      coverCadenceMs: 400,
      coverLanes: 2,
      coverFramesPerCell: 2,
      coverDurationEpochs: 2,
    });
    const { clock, trace, scheduler, statuses } = harness(selected, 50);
    scheduler.enqueue(job("real", "real", [0xa1, 0xa2]));
    scheduler.enqueue(job("control", "control", [0xc1]));

    expect(scheduler.start()).toBe(true);
    expect(scheduler.getStatus()).toBe("starting");
    await clock.advanceTo(900);

    expect(trace).toEqual([
      "open@100:c0:l0:control",
      "open@100:c0:l1:real",
      "send@150:d150:e0:l0:f0:control:193",
      "send@250:d250:e0:l1:f0:real:161",
      "send@350:d350:e0:l0:f1:dummy:221",
      "send@450:d450:e0:l1:f1:real:162",
      "send@550:d550:e1:l0:f0:dummy:221",
      "send@650:d650:e1:l1:f0:dummy:221",
      "send@750:d750:e1:l0:f1:dummy:221",
      "send@850:d850:e1:l1:f1:dummy:221",
      "close@900:c0:l0:boundary",
      "close@900:c0:l1:boundary",
      "open@900:c1:l0:-",
      "open@900:c1:l1:-",
    ]);
    expect(statuses).toEqual(["starting", "active"]);
  });

  test("keeps pre-admission cancel dummy and gives admitted cancel/completion fixed tails", async () => {
    const { clock, trace, scheduler } = harness(schedule(), 10);
    scheduler.enqueue(job("never-admitted", "real", [0x01]));
    expect(scheduler.cancel("never-admitted")).toBe(
      "cancelled-before-admission",
    );
    scheduler.start();

    await clock.advanceTo(410);
    scheduler.enqueue(job("cancel-me", "real", [0xa0, 0xa1, 0xa2], 0xca));
    await clock.advanceTo(850);
    expect(scheduler.cancel("cancel-me")).toBe("cancel-pending");
    scheduler.enqueue(job("one-cell", "real", [0xb0]));
    await clock.advanceTo(1_600);

    expect(trace).toEqual([
      "open@400:c1:l0:-",
      "send@450:d450:e1:l0:f0:dummy:221",
      "send@550:d550:e1:l0:f1:dummy:221",
      "send@650:d650:e1:l0:f2:dummy:221",
      "send@750:d750:e1:l0:f3:dummy:221",
      "close@800:c1:l0:boundary",
      "open@800:c2:l0:cancel-me",
      "send@850:d850:e2:l0:f0:real:160",
      "send@950:d950:e2:l0:f1:cancel:202",
      "send@1050:d1050:e2:l0:f2:dummy:221",
      "send@1150:d1150:e2:l0:f3:dummy:221",
      "close@1200:c2:l0:boundary",
      "open@1200:c3:l0:one-cell",
      "send@1250:d1250:e3:l0:f0:real:176",
      "send@1350:d1350:e3:l0:f1:dummy:221",
      "send@1450:d1450:e3:l0:f2:dummy:221",
      "send@1550:d1550:e3:l0:f3:dummy:221",
      "close@1600:c3:l0:boundary",
      "open@1600:c4:l0:-",
    ]);
  });

  test("backpressure degrades without a catch-up burst and requeues exact bytes", async () => {
    let rejectFirstReal = true;
    const { clock, trace, scheduler, statuses, interruptions } = harness(
      schedule({
        coverCadenceMs: 200,
        coverFramesPerCell: 2,
      }),
      0,
      (request) => {
        if (request.source === "real" && rejectFirstReal) {
          rejectFirstReal = false;
          return false;
        }
        return undefined;
      },
    );
    scheduler.enqueue(job("retry", "real", [0x44]));
    scheduler.start();
    await clock.advanceTo(400);

    expect(trace).toEqual([
      "open@0:c0:l0:retry",
      "send@50:d50:e0:l0:f0:real:68",
      "close@200:c0:l0:boundary",
      "open@200:c1:l0:retry",
      "send@250:d250:e1:l0:f0:real:68",
      "send@350:d350:e1:l0:f1:dummy:221",
      "close@400:c1:l0:boundary",
      "open@400:c2:l0:-",
    ]);
    expect(trace.some((entry) => entry.startsWith("send@150"))).toBe(false);
    expect(statuses).toEqual(["starting", "active", "degraded", "active"]);
    expect(interruptions).toEqual(["retry:backpressure"]);
  });

  test("suspends an open cycle at its boundary and resumes only at a strictly future cycle", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 0);
    scheduler.start();
    await clock.advanceTo(60);
    expect(scheduler.suspend("pagehide")).toBe(true);
    scheduler.enqueue(job("queued-control", "control", [0xc0]));

    await clock.advanceTo(800);
    expect(trace).toEqual([
      "open@0:c0:l0:-",
      "send@50:d50:e0:l0:f0:dummy:221",
      "close@400:c0:l0:boundary",
    ]);

    expect(scheduler.resume()).toBe(true);
    await clock.advanceTo(1_200);
    expect(trace).toEqual([
      "open@0:c0:l0:-",
      "send@50:d50:e0:l0:f0:dummy:221",
      "close@400:c0:l0:boundary",
      "open@1200:c3:l0:queued-control",
    ]);
    expect(statuses).toEqual([
      "starting",
      "active",
      "suspended",
      "starting",
      "active",
    ]);
  });

  test("a late slot is skipped, marks degraded, and cannot catch up", async () => {
    const { clock, trace, scheduler, statuses } = harness(
      schedule({
        coverCadenceMs: 200,
        coverFramesPerCell: 2,
      }),
      0,
    );
    scheduler.enqueue(job("late", "real", [0x77]));
    scheduler.start();
    await clock.advanceTo(0);
    await clock.jumpTo(60);
    expect(scheduler.getStatus()).toBe("degraded");
    expect(trace).toEqual(["open@0:c0:l0:late"]);

    await clock.advanceTo(200);
    expect(trace).toEqual([
      "open@0:c0:l0:late",
      "close@200:c0:l0:boundary",
      "open@200:c1:l0:late",
    ]);
    expect(statuses).toEqual(["starting", "active", "degraded", "active"]);
  });
});

// C5: a boundary timer that fired past its own drift tolerance used to call
// setStatus("suspended", "timer-drift") and arm NOTHING, with `running` still
// true. resume() is the only exit from "suspended", and its only callers are a
// public method no src/ file calls, visibilitychange -> visible, and online --
// none of which a visible, online tab will ever fire. So a single 500 ms stall
// over a boundary parked scheduled cover permanently while both handshakes
// stayed authenticated and the transport stayed connected, and every send in
// both directions then failed at its delivery budget. Same park through the
// two boundary-handler rejection catches.
describe("a late boundary degrades and re-arms instead of parking (C5)", () => {
  test("a late cycle boundary degrades, closes the dead cycle, and re-arms", async () => {
    const { clock, trace, scheduler, statuses, statusReasons } = harness(
      schedule(),
      0,
    );
    scheduler.start();
    await clock.advanceTo(350);
    expect(scheduler.getStatus()).toBe("active");
    const boundary = clock.nextTimerDeadline();
    expect(boundary).toBe(400);

    // Fire the cycle boundary five seconds late: a stall the browser imposed.
    await clock.jumpTo(boundary + 5_000);

    expect(scheduler.getStatus()).toBe("degraded");
    expect(statuses).not.toContain("suspended");
    expect(statusReasons).toContain("timer-drift");
    // The gap is closed and never claimed...
    expect(trace.at(-1)).toBe("close@5400:c0:l0:late-cleanup");
    // ...and exactly one boundary is armed, strictly after the moment it fired.
    expect(clock.armedTimerCount()).toBe(1);
    expect(clock.nextTimerDeadline()).toBeGreaterThan(boundary + 5_000);

    // It really runs again, which is the whole point.
    await clock.advanceTo(5_600);
    expect(scheduler.getStatus()).toBe("active");
    expect(trace).toContain("open@5600:c14:l0:-");
  });

  test("a late open boundary degrades and re-arms too", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 10);
    scheduler.start();
    expect(clock.nextTimerDeadline()).toBe(400);

    await clock.jumpTo(5_400);

    expect(scheduler.getStatus()).toBe("degraded");
    expect(statuses).not.toContain("suspended");
    expect(trace).toEqual([]);
    expect(clock.armedTimerCount()).toBe(1);
    expect(clock.nextTimerDeadline()).toBe(5_600);

    await clock.advanceTo(5_600);
    expect(trace).toEqual(["open@5600:c14:l0:-"]);
    expect(scheduler.getStatus()).toBe("active");
  });

  test("an open-boundary handler that rejects degrades and keeps the schedule", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 0);
    scheduler.enqueue(job("waiting", "control", [0xc0]));
    scheduler.start();
    // start() consumed one timer request; refuse the slot timer openCycle arms
    // last, so its promise rejects into the arm-site catch.
    clock.failNextSetTimeout = true;
    await clock.advanceTo(0);

    expect(scheduler.getStatus()).toBe("degraded");
    expect(statuses).not.toContain("suspended");
    // The cycle it failed inside is still closed at its authenticated
    // boundary, not early, so the failure is invisible on the wire.
    expect(clock.armedTimerCount()).toBe(1);
    expect(clock.nextTimerDeadline()).toBe(400);

    await clock.advanceTo(1_200);
    expect(trace.filter((entry) => entry.startsWith("open@"))).toEqual([
      "open@0:c0:l0:waiting",
      "open@400:c1:l0:waiting",
      "open@800:c2:l0:-",
      "open@1200:c3:l0:-",
    ]);
  });

  test("a cycle-boundary reopen that rejects degrades and keeps the schedule", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 0);
    scheduler.start();
    await clock.advanceTo(350);
    // Refuse the slot timer of the cycle the BOUNDARY handler opens, so the
    // rejection lands in handleCycleBoundary's own catch instead.
    clock.failNextSetTimeout = true;
    await clock.advanceTo(400);

    expect(scheduler.getStatus()).toBe("degraded");
    expect(statuses).not.toContain("suspended");

    await clock.advanceTo(800);
    expect(trace).toContain("close@800:c1:l0:boundary");
    expect(trace).toContain("open@800:c2:l0:-");
    expect(scheduler.getStatus()).toBe("active");
  });

  test("a late slot still only degrades, under its own reason", async () => {
    const { clock, scheduler, statusReasons } = harness(
      schedule({ coverCadenceMs: 200, coverFramesPerCell: 2 }),
      0,
    );
    scheduler.start();
    await clock.advanceTo(0);
    await clock.jumpTo(60);

    expect(scheduler.getStatus()).toBe("degraded");
    expect(statusReasons).toEqual(["-", "-", "missed-deadline"]);
    expect(statusReasons).not.toContain("timer-drift");
  });

  test("a late boundary on a suspended scheduler waits for its wake event", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 0);
    scheduler.start();
    await clock.advanceTo(50);
    expect(scheduler.suspend("page-hidden")).toBe(true);

    await clock.jumpTo(5_400);

    // "suspended" is the one status a browser event is guaranteed to lift.
    // Degrading here would resurrect cover on a hidden page and claim a gap
    // the runtime has deliberately refused to claim.
    expect(scheduler.getStatus()).toBe("suspended");
    expect(statuses).not.toContain("degraded");
    expect(clock.armedTimerCount()).toBe(0);
    expect(trace.at(-1)).toBe("close@5400:c0:l0:late-cleanup");

    expect(scheduler.resume()).toBe(true);
    await clock.advanceTo(5_600);
    expect(scheduler.getStatus()).toBe("active");
  });

  test("a late boundary on a stopped scheduler stays stopped and arms nothing", async () => {
    const { clock, trace, scheduler, statuses } = harness(schedule(), 0);
    scheduler.start();
    await clock.advanceTo(50);
    expect(scheduler.stop()).toBe(true);
    expect(clock.armedTimerCount()).toBe(1);

    await clock.jumpTo(5_400);

    expect(scheduler.getStatus()).toBe("stopped");
    expect(statuses).not.toContain("degraded");
    expect(clock.armedTimerCount()).toBe(0);
    expect(trace.at(-1)).toBe("close@5400:c0:l0:late-cleanup");
  });
});
