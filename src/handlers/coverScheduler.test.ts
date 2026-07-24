import { describe, expect, test } from "bun:test";

import { createCoverScheduler, validateCoverSchedule } from "./coverScheduler";

import type {
  CoverClock,
  CoverJob,
  CoverLane,
  CoverLaneOpenContext,
  CoverSchedule,
  CoverSchedulerStatus,
  CoverSendRequest,
} from "./coverScheduler";

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
    onStatusChange({ status }) {
      statuses.push(status);
    },
    onJobInterrupted({ jobId, reason }) {
      interruptions.push(`${jobId}:${reason}`);
    },
  });
  return { clock, trace, statuses, interruptions, scheduler };
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
