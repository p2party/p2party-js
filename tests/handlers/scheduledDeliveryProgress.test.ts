import { beforeAll, describe, expect, test } from "bun:test";

import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { createCoverScheduler } from "../../src/handlers/coverScheduler";
import {
  buildScheduledSendJob,
  isForwardScheduledProgress,
  scheduledSendProgress,
  waitForScheduledDelivery,
} from "../../src/handlers/coverTransfer";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";

import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverJob,
  CoverLane,
  CoverSchedule,
  CoverSendRequest,
} from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

test("explicit rekey invalidation ends a suspended attempt without spending its idle budget", async () => {
  let now = 0;
  expect(
    await waitForScheduledDelivery({
      isComplete: () => false,
      progress: () => ({ state: "queued", queuePosition: 0, sentCells: 0 }),
      isSuspended: () => true,
      isInvalidated: () => now >= 200,
      idleTimeoutMs: 600_000,
      now: () => now,
      sleep: async (ms) => {
        now += ms;
        if (now > 1000) throw new Error("rekey left a stale attempt waiting");
      },
    }),
  ).toBe(false);
  expect(now).toBe(200);
});

// ── fake clock (mirrors tests/handlers/coverRuntime.test.ts) ─────────────────

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

  private async flush(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    for (;;) {
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
}

class FakeChannel implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];
  closes = 0;

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
}

/** The raw scheduler lane (CoverRuntime is the adapter that wraps a channel). */
class FakeLane implements CoverLane {
  readonly sent: CoverSendRequest[] = [];
  closes = 0;

  send(request: CoverSendRequest): boolean {
    this.sent.push(request);
    return true;
  }

  close(): void {
    this.closes += 1;
  }
}

const SCHEDULE: CoverSchedule = {
  coverCadenceMs: 400,
  coverLanes: 2,
  // Eight slots per lane per cycle, so an admitted job spends most of its cycle
  // emitting: the window in which the ONLY thing that can move is its cell
  // count.
  coverFramesPerCell: 8,
  coverDurationEpochs: 1,
  phaseOffsetMs: 0,
};

const label = (byte: string): string => `${byte.repeat(32)}~${byte.repeat(64)}`;

const cellJob = (id: string, cells: number): CoverJob => ({
  id,
  kind: "real",
  declaredCellCount: cells,
  nextCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
});

describe("scheduledSendProgress (what the sender can actually observe)", () => {
  test("moves when the job's queue position moves and when it emits a cell, and vanishes at settlement", async () => {
    const clock = new FakeClock(0);
    const scheduler = createCoverScheduler({
      schedule: SCHEDULE,
      clock,
      maxTimerDriftMs: 0,
      laneFactory: () => new FakeLane(),
      makeDummy: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
    });
    // Three jobs, two lanes: the third cannot be admitted this cycle. This is
    // exactly the contention the arithmetic bound ignores.
    scheduler.enqueue(cellJob(label("11"), 8));
    scheduler.enqueue(cellJob(label("22"), 8));
    const mine = label("33");
    scheduler.enqueue(cellJob(mine, 8));

    const runtimeView = {
      getJobProgress: (jobId: string) => scheduler.getJobProgress(jobId),
    };

    const queued = scheduledSendProgress(runtimeView, mine);
    expect(queued).toEqual({ state: "queued", queuePosition: 2, sentCells: 0 });
    scheduler.start();

    // Cycle 0 admits the first two; ours advances to the head of the queue.
    // Compared by VALUE, never by identity: getJobProgress builds a fresh
    // object per call, so `not.toBe` would pass for two identical readings.
    await clock.advanceTo(399);
    const atHead = scheduledSendProgress(runtimeView, mine);
    expect(atHead).toEqual({ state: "queued", queuePosition: 0, sentCells: 0 });
    expect(isForwardScheduledProgress(queued, atHead!)).toBe(true);

    // Cycle 1 admits ours; every emitted cell moves the reading again.
    await clock.advanceTo(500);
    const admitted = scheduledSendProgress(runtimeView, mine);
    expect(admitted?.state).toBe("admitted");
    expect(isForwardScheduledProgress(atHead, admitted!)).toBe(true);

    // Within the admitted phase nothing but the cell count can move: the state
    // is "admitted" and the queue position is already -1. This is the term that
    // dates the receipt window from the LAST cell rather than from admission.
    await clock.advanceTo(650);
    const oneMoreCell = scheduledSendProgress(runtimeView, mine);
    expect(oneMoreCell).toBeDefined();
    expect(oneMoreCell).not.toEqual(admitted!);
    expect(oneMoreCell!.sentCells).toBeGreaterThan(admitted!.sentCells);
    expect(isForwardScheduledProgress(admitted, oneMoreCell!)).toBe(true);
    expect(scheduler.getJobProgress(mine)?.state).toBe("admitted");
    expect(scheduler.getJobProgress(mine)?.queuePosition).toBe(-1);

    // Once every declared cell is out the job settles and the scheduler drops
    // it: no local progress signal remains, only the receipt can end the wait.
    await clock.advanceTo(1_200);
    expect(scheduledSendProgress(runtimeView, mine)).toBeUndefined();
    scheduler.stop();
  });

  test("an edge with no cover runtime has no progress signal at all", () => {
    expect(scheduledSendProgress(undefined, label("44"))).toBeUndefined();
  });
});

describe("waitForScheduledDelivery (idle budget, not a total deadline)", () => {
  const virtualWait = (
    options: Omit<
      Parameters<typeof waitForScheduledDelivery>[0],
      "now" | "sleep"
    >,
    clock: { now: number },
  ) =>
    waitForScheduledDelivery({
      ...options,
      now: () => clock.now,
      sleep: async (ms: number) => {
        clock.now += ms;
        await Promise.resolve();
      },
    });

  test("resolves true as soon as the receipt lands", async () => {
    const clock = { now: 0 };
    let complete = false;
    const wait = virtualWait(
      {
        isComplete: () => complete,
        progress: () => undefined,
        idleTimeoutMs: 10_000,
        pollMs: 100,
      },
      clock,
    );
    complete = true;
    expect(await wait).toBe(true);
  });

  test("gives up after the idle budget when nothing ever moves", async () => {
    const clock = { now: 0 };
    expect(
      await virtualWait(
        {
          isComplete: () => false,
          progress: () => ({
            state: "queued" as const,
            queuePosition: 0,
            sentCells: 0,
          }),
          idleTimeoutMs: 1_000,
          pollMs: 100,
        },
        clock,
      ),
    ).toBe(false);
    expect(clock.now).toBeGreaterThanOrEqual(1_000);
  });

  test("an aborted send stops waiting and reports failure", async () => {
    const clock = { now: 0 };
    const controller = new AbortController();
    controller.abort();
    expect(
      await virtualWait(
        {
          isComplete: () => true,
          progress: () => ({
            state: "admitted" as const,
            queuePosition: -1,
            sentCells: 1,
          }),
          idleTimeoutMs: 1_000,
          pollMs: 100,
          signal: controller.signal,
        },
        clock,
      ),
    ).toBe(false);
  });

  test("a send that keeps moving is NOT abandoned, however long it takes in total", async () => {
    const clock = { now: 0 };
    let ticks = 0;
    // Progress every 900 ms — inside the 1 s idle budget, but the run lasts
    // 90 s, ninety times any total deadline the arithmetic bound would set.
    const delivered = await virtualWait(
      {
        isComplete: () => clock.now >= 90_000,
        progress: () => {
          ticks = Math.floor(clock.now / 900);
          return {
            state: "admitted" as const,
            queuePosition: -1,
            sentCells: ticks,
          };
        },
        idleTimeoutMs: 1_000,
        pollMs: 100,
      },
      clock,
    );
    expect(delivered).toBe(true);
    expect(clock.now).toBeGreaterThanOrEqual(90_000);
  });
});

// ── finding 2: only FORWARD movement is progress ─────────────────────────────
//
// The progress signal is not monotone. A control job jumps the admission queue
// (jobTier puts `control` ahead of `real`), which pushes a waiting real job's
// position BACKWARDS, and every requeue — backpressure, a missed deadline, a
// suspension — sends an admitted job back to "queued". Counting any CHANGE as
// progress means an oscillating signal resets the budget forever: the send is
// never abandoned, and because `sendScheduled` fans out serially, every later
// peer in the room waits behind it with no bound at all.

describe("only forward movement resets the idle budget (finding 2)", () => {
  const virtualWait = (
    options: Omit<
      Parameters<typeof waitForScheduledDelivery>[0],
      "now" | "sleep"
    >,
    clock: { now: number },
  ) =>
    waitForScheduledDelivery({
      ...options,
      now: () => clock.now,
      sleep: async (ms: number) => {
        clock.now += ms;
        await Promise.resolve();
      },
    });

  // Far past any budget under test: a wait that reaches it never tripped.
  const RUNAWAY_MS = 10_000_000;
  const BUDGET_MS = 8_000;

  test("a token that oscillates between two positions still trips the budget", async () => {
    const clock = { now: 0 };
    let flip = false;
    const delivered = await virtualWait(
      {
        // A hard stop: without the fix this wait does not end on its own.
        isComplete: () => clock.now >= RUNAWAY_MS,
        progress: () => {
          flip = !flip;
          return {
            state: "queued" as const,
            queuePosition: flip ? 3 : 4,
            sentCells: 0,
          };
        },
        idleTimeoutMs: BUDGET_MS,
        pollMs: 100,
      },
      clock,
    );
    expect(delivered).toBe(false);
    expect(clock.now).toBeLessThan(2 * BUDGET_MS);
  });

  test("a token that only moves backwards still trips the budget", async () => {
    const clock = { now: 0 };
    let position = 1;
    const delivered = await virtualWait(
      {
        isComplete: () => clock.now >= RUNAWAY_MS,
        // Control jobs keep arriving, so this send keeps losing ground.
        progress: () => ({
          state: "queued" as const,
          queuePosition: position++,
          sentCells: 0,
        }),
        idleTimeoutMs: BUDGET_MS,
        pollMs: 100,
      },
      clock,
    );
    expect(delivered).toBe(false);
    expect(clock.now).toBeLessThan(2 * BUDGET_MS);
  });

  test("a send climbing the queue, then admitted, then emitting is never abandoned", async () => {
    // The other direction, which matters just as much: every genuine advance —
    // queue position DOWN, then queued → admitted, then cells UP — must reset
    // the budget, across a run many times longer than the budget itself.
    const clock = { now: 0 };
    const STEP_MS = 900;
    const step = (): number => Math.floor(clock.now / STEP_MS);
    const delivered = await virtualWait(
      {
        isComplete: () => clock.now >= 54_000,
        progress: () => {
          const n = step();
          return n < 20
            ? { state: "queued" as const, queuePosition: 20 - n, sentCells: 0 }
            : {
                state: "admitted" as const,
                queuePosition: -1,
                sentCells: n - 20,
              };
        },
        idleTimeoutMs: 1_000,
        pollMs: 100,
      },
      clock,
    );
    expect(delivered).toBe(true);
    // Fifty-four budgets' worth of run, none of them spent.
    expect(clock.now).toBeGreaterThanOrEqual(54_000);
  });

  test("a token frozen at the head of the queue trips exactly one budget later", async () => {
    // The genuinely stuck case must still be caught: nothing about this send
    // moves, in any component.
    const clock = { now: 0 };
    const delivered = await virtualWait(
      {
        isComplete: () => clock.now >= RUNAWAY_MS,
        progress: () => ({
          state: "queued" as const,
          queuePosition: 0,
          sentCells: 0,
        }),
        idleTimeoutMs: BUDGET_MS,
        pollMs: 100,
      },
      clock,
    );
    expect(delivered).toBe(false);
    expect(clock.now).toBeGreaterThanOrEqual(BUDGET_MS);
    expect(clock.now).toBeLessThan(2 * BUDGET_MS);
  });
});

describe("queue contention on a real scheduler (finding A, end to end)", () => {
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

  test("a send queued behind five cycles of other jobs still completes, while a bound with no progress signal abandons it", async () => {
    const pq = makePq(true);
    const clock = new FakeClock(0);
    const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
    const runtime = new CoverRuntime({
      epc,
      roomId: "room",
      module,
      amInitiator: true,
      schedule: {
        coverCadenceMs: SCHEDULE.coverCadenceMs,
        coverLanes: SCHEDULE.coverLanes,
        coverFramesPerCell: SCHEDULE.coverFramesPerCell,
        coverDurationEpochs: SCHEDULE.coverDurationEpochs,
      },
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (laneLabel) => new FakeChannel(laneLabel),
      maxTimerDriftMs: 0,
      clock,
    });

    // Ten other messages ahead of ours on a two-lane edge: ours is admitted
    // only at the sixth cycle boundary.
    for (let i = 0; i < 10; i++)
      runtime.enqueue(cellJob(label(i.toString(16).repeat(2)), 2));
    const mineLabel = `${"ab".repeat(32)}~${"cd".repeat(64)}`;
    runtime.enqueue(
      buildScheduledSendJob({
        runtime,
        channelMessageLabel: mineLabel,
        totalChunks: 2,
        merkleRoot: new Uint8Array(64).fill(0xcd),
        sealSlotCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      }),
    );
    runtime.start();

    // The delivery bound is 1 s — two and a half cycles, the shape of the
    // arithmetic floor (2 x cycle + a slot). The run takes six cycles.
    const IDLE_BUDGET_MS = 1_000;
    let receiptLanded = false;
    const delivered = await waitForScheduledDelivery({
      isComplete: () => receiptLanded,
      progress: () => scheduledSendProgress(runtime, mineLabel),
      idleTimeoutMs: IDLE_BUDGET_MS,
      pollMs: 50,
      now: () => clock.now(),
      sleep: async (ms) => {
        await clock.advanceTo(clock.now() + ms);
        // The receiver's terminal receipt arrives one cycle after the job
        // finished emitting; model that as the job leaving the scheduler.
        if (
          clock.now() > 2_400 &&
          runtime.getJobProgress(mineLabel) === undefined
        )
          receiptLanded = true;
      },
    });
    expect(delivered).toBe(true);
    expect(clock.now()).toBeGreaterThan(2 * IDLE_BUDGET_MS);

    runtime.destroy();
    pq.destroy();
  });

  test("the receipt window runs from the LAST cell on the wire, not from admission", async () => {
    const pq = makePq(true);
    const clock = new FakeClock(0);
    const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
    const runtime = new CoverRuntime({
      epc,
      roomId: "room",
      module,
      amInitiator: true,
      schedule: {
        coverCadenceMs: SCHEDULE.coverCadenceMs,
        coverLanes: SCHEDULE.coverLanes,
        coverFramesPerCell: SCHEDULE.coverFramesPerCell,
        coverDurationEpochs: SCHEDULE.coverDurationEpochs,
      },
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (laneLabel) => new FakeChannel(laneLabel),
      maxTimerDriftMs: 0,
      clock,
    });

    // Two fillers fill cycle 0's two lanes; ours is admitted at t = 400 and
    // then spends nearly the whole of cycle 1 emitting its eight cells.
    runtime.enqueue(cellJob(label("11"), 8));
    runtime.enqueue(cellJob(label("22"), 8));
    const mineLabel = `${"ab".repeat(32)}~${"cd".repeat(64)}`;
    runtime.enqueue(
      buildScheduledSendJob({
        runtime,
        channelMessageLabel: mineLabel,
        totalChunks: 8,
        merkleRoot: new Uint8Array(64).fill(0xcd),
        sealSlotCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      }),
    );
    runtime.start();

    // The arithmetic floor for this schedule: 2 x 400 ms + the last lane's
    // first slot. A receipt cannot exist before the last cell has landed, so
    // dating the window from ADMISSION (t = 400) would give up at ~1238 ms and
    // abandon a receipt that is still inside its own budget.
    const FLOOR_MS = 838;
    const RECEIPT_AT_MS = 1_400;
    const delivered = await waitForScheduledDelivery({
      isComplete: () => clock.now() >= RECEIPT_AT_MS,
      progress: () => scheduledSendProgress(runtime, mineLabel),
      idleTimeoutMs: FLOOR_MS,
      pollMs: 25,
      now: () => clock.now(),
      sleep: async (ms) => {
        await clock.advanceTo(clock.now() + ms);
      },
    });
    expect(delivered).toBe(true);
    expect(clock.now()).toBeGreaterThanOrEqual(RECEIPT_AT_MS);
    expect(clock.now()).toBeLessThan(400 + FLOOR_MS + 400);

    runtime.destroy();
    pq.destroy();
  });
});
