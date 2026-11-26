import { MAX_TIMER_DELAY_MS } from "../utils/constants";

export type CoverSchedulerStatus =
  "starting" | "active" | "degraded" | "suspended" | "stopped";

export type CoverJobKind = "real" | "control";
export type CoverCellSource = CoverJobKind | "cancel" | "dummy";

type MaybePromise<T> = T | PromiseLike<T>;

/** What a scheduler wake-up is for; a clock may route on it. */
export type CoverTimerKind = "open-boundary" | "cycle-boundary" | "slot";

export interface CoverClock {
  now(): number;
  /**
   * `kind` says whether the wake-up opens or closes a cycle or runs a slot;
   * the timer-worker clock brings a replacement worker up only at a boundary.
   */
  setTimeout(
    callback: () => void,
    delayMs: number,
    kind?: CoverTimerKind,
  ): unknown;
  clearTimeout(handle: unknown): void;
}

/**
 * The phase is an absolute clock offset. Epoch zero starts at phaseOffsetMs;
 * negative epoch/cycle indices are valid when a test or monotonic clock starts
 * before that offset.
 */
export interface CoverSchedule {
  phaseOffsetMs: number;
  coverCadenceMs: number;
  coverLanes: number;
  coverFramesPerCell: number;
  coverDurationEpochs: number;
}

export interface CoverSlot {
  readonly deadlineMs: number;
  readonly cycleIndex: number;
  readonly cycleStartMs: number;
  readonly cycleEndMs: number;
  readonly epochIndex: number;
  readonly epochInCycle: number;
  readonly laneIndex: number;
  readonly frameIndex: number;
  readonly laneSlotIndex: number;
}

export interface CoverJobSlot extends CoverSlot {
  readonly jobId: string;
  readonly jobKind: CoverJobKind;
  /** Index of the next not-yet-accepted job cell. */
  readonly jobCellIndex: number;
}

/**
 * A producer is deliberately lazy: ratchet state and encrypted cell bytes are
 * prepared one slot ahead (see CoverScheduler.prepare) instead of buffering a
 * complete cycle. Returning null substitutes a dummy for this slot without
 * consuming a job cell. declaredCellCount enforces the authenticated F x D
 * capacity class.
 */
export interface CoverJob {
  readonly id: string;
  readonly kind: CoverJobKind;
  readonly declaredCellCount: number;
  readonly priority?: number;
  nextCell(slot: CoverJobSlot): MaybePromise<Uint8Array | null>;
  /** No further real cells after a selective producer skips its have-set. */
  exhausted?(): boolean;
  cancelCell?(slot: CoverJobSlot): MaybePromise<Uint8Array>;
}

export interface CoverJobSummary {
  readonly id: string;
  readonly kind: CoverJobKind;
  readonly declaredCellCount: number;
}

export interface CoverLaneOpenContext {
  readonly cycleIndex: number;
  readonly cycleStartMs: number;
  readonly cycleEndMs: number;
  readonly laneIndex: number;
  readonly job: CoverJobSummary | null;
}

export interface CoverSendRequest {
  readonly cell: Uint8Array;
  readonly source: CoverCellSource;
  readonly slot: CoverSlot;
  readonly jobId?: string;
  readonly jobCellIndex?: number;
}

export interface CoverLaneCloseContext extends CoverLaneOpenContext {
  readonly reason: "boundary" | "late-cleanup";
}

export interface CoverLane {
  /**
   * Return false only when the transport rejected the cell for backpressure.
   * A thrown/rejected send is treated as a transport failure.
   */
  send(request: CoverSendRequest): MaybePromise<boolean | void>;
  close(context: CoverLaneCloseContext): void;
}

export type CoverJobOutcome =
  "completed" | "cancelled-before-admission" | "cancelled" | "failed";

export interface CoverJobResult {
  readonly jobId: string;
  readonly outcome: CoverJobOutcome;
  readonly reason?: "capacity-exhausted" | "stopped" | "key-epoch-changed";
}

export interface CoverJobInterruption {
  readonly jobId: string;
  readonly reason:
    | "backpressure"
    | "cell-production-failed"
    | "lane-open-failed"
    | "missed-deadline"
    | "send-failed"
    | "suspended";
}

export interface CoverStatusChange {
  readonly previous: CoverSchedulerStatus;
  readonly status: CoverSchedulerStatus;
  readonly reason?: string;
}

export interface CoverSchedulerOptions {
  readonly schedule: CoverSchedule;
  readonly clock: CoverClock;
  readonly laneFactory: (context: CoverLaneOpenContext) => CoverLane;
  readonly makeDummy: (slot: CoverSlot) => MaybePromise<Uint8Array>;
  /**
   * Defaults to zero. A runtime may opt into a small, explicit timer tolerance;
   * deadlines and metadata remain the absolute unshifted values.
   */
  readonly maxTimerDriftMs?: number;
  readonly onStatusChange?: (change: CoverStatusChange) => void;
  readonly onJobResult?: (result: CoverJobResult) => void;
  readonly onJobInterrupted?: (interruption: CoverJobInterruption) => void;
}

export type CoverCancelResult =
  "not-found" | "cancelled-before-admission" | "cancel-pending";

/**
 * What one enqueued job has actually achieved so far.
 *
 * A scheduled sender has NO receiver-side progress signal to poll: scheduled
 * mode can receive batched chunk receipts, but older peers emit only terminal
 * completion. Local progress remains useful during admission and receipt lag.
 * This is therefore the only evidence a send is alive, and it is what
 * separates "still working" from "stuck" — a distinction a wall-clock bound
 * cannot make, because a job admitted only at a cycle open waits behind every
 * other job in the room.
 */
export interface CoverJobProgress {
  readonly state: "queued" | "admitted" | "terminal";
  /** Index in the admission order, or -1 once admitted (nothing to wait for). */
  readonly queuePosition: number;
  /** Cells this job has put on the wire and had accepted. */
  readonly sentCells: number;
}

interface JobRuntime {
  readonly job: CoverJob;
  readonly sequence: number;
  state: "queued" | "admitted" | "terminal";
  everAdmitted: boolean;
  sentCells: number;
  cancelRequested: boolean;
  cancelSent: boolean;
  completed: boolean;
  settled: boolean;
  keyEpochVersion: number;
  /**
   * A produced cell belongs to its job until it is sent: a slot that gives up
   * on it (late, degraded, backpressure) leaves it here for the job's next
   * slot, and settling the job zeroes it.
   */
  pendingCell?: Uint8Array;
  pendingCancelCell?: Uint8Array;
  /** Set while this job's producer runs: one production per job at a time. */
  producing?: Promise<void>;
}

/**
 * The cell for the next slot of the open cycle, produced ahead of the slot so
 * that the slot's wake-up only sends it.
 */
interface PreparedCell {
  readonly ordinal: number;
  readonly lane: LaneRuntime;
  state: "producing" | "ready" | "failed";
  request?: CoverSendRequest;
  /** Its slot gave up on it; whatever it produces is released, not sent. */
  abandoned: boolean;
}

interface LaneRuntime {
  readonly laneIndex: number;
  readonly handle: CoverLane;
  readonly openContext: CoverLaneOpenContext;
  job?: JobRuntime;
}

interface CycleRuntime {
  readonly index: number;
  readonly startMs: number;
  readonly endMs: number;
  readonly lanes: LaneRuntime[];
  nextSlotOrdinal: number;
  prepared?: PreparedCell;
}

type TimerKind = CoverTimerKind;

const MAX_COVER_LANES = 16;
const MIN_COVER_SLOT_MS = 25;

const assertSafeInteger = (name: string, value: number): void => {
  if (!Number.isSafeInteger(value))
    throw new Error(`coverScheduler: ${name} must be a safe integer`);
};

const assertCell = (name: string, cell: unknown): Uint8Array => {
  if (!(cell instanceof Uint8Array))
    throw new Error(`coverScheduler: ${name} must return a Uint8Array`);
  return cell;
};

const jobTier = (runtime: JobRuntime): number =>
  runtime.cancelRequested ? 0 : runtime.job.kind === "control" ? 1 : 2;

const compareQueuedJobs = (left: JobRuntime, right: JobRuntime): number => {
  const tierDifference = jobTier(left) - jobTier(right);
  if (tierDifference !== 0) return tierDifference;
  const priorityDifference =
    (right.job.priority ?? 0) - (left.job.priority ?? 0);
  return priorityDifference || left.sequence - right.sequence;
};

const jobSummary = (runtime: JobRuntime): CoverJobSummary => ({
  id: runtime.job.id,
  kind: runtime.job.kind,
  declaredCellCount: runtime.job.declaredCellCount,
});

export class CoverScheduler {
  readonly schedule: Readonly<CoverSchedule>;

  private readonly clock: CoverClock;
  private readonly laneFactory: (context: CoverLaneOpenContext) => CoverLane;
  private readonly makeDummy: (slot: CoverSlot) => MaybePromise<Uint8Array>;
  private readonly maxTimerDriftMs: number;
  private readonly onStatusChange?: (change: CoverStatusChange) => void;
  private readonly onJobResult?: (result: CoverJobResult) => void;
  private readonly onJobInterrupted?: (
    interruption: CoverJobInterruption,
  ) => void;
  private readonly cycleDurationMs: number;
  private readonly slotsPerEpoch: number;
  private readonly slotsPerLane: number;

  private status: CoverSchedulerStatus = "stopped";
  private running = false;
  private sequence = 0;
  private generation = 0;
  private timer: unknown;
  private hasTimer = false;
  private cycle?: CycleRuntime;
  private readonly queued: JobRuntime[] = [];
  private readonly jobs = new Map<string, JobRuntime>();

  constructor(options: CoverSchedulerOptions) {
    validateCoverSchedule(options.schedule);
    this.schedule = Object.freeze({ ...options.schedule });
    this.clock = options.clock;
    this.laneFactory = options.laneFactory;
    this.makeDummy = options.makeDummy;
    this.onStatusChange = options.onStatusChange;
    this.onJobResult = options.onJobResult;
    this.onJobInterrupted = options.onJobInterrupted;
    this.maxTimerDriftMs = options.maxTimerDriftMs ?? 0;

    if (
      !Number.isFinite(this.maxTimerDriftMs) ||
      this.maxTimerDriftMs < 0 ||
      this.maxTimerDriftMs >= coverSlotSpacingMs(this.schedule)
    )
      throw new Error(
        "coverScheduler: max timer drift must be non-negative and less than one slot",
      );

    this.cycleDurationMs =
      this.schedule.coverCadenceMs * this.schedule.coverDurationEpochs;
    this.slotsPerEpoch =
      this.schedule.coverLanes * this.schedule.coverFramesPerCell;
    this.slotsPerLane =
      this.schedule.coverFramesPerCell * this.schedule.coverDurationEpochs;
    this.assertClockNow();
  }

  getStatus(): CoverSchedulerStatus {
    return this.status;
  }

  getQueuedJobIds(): readonly string[] {
    return [...this.queued].sort(compareQueuedJobs).map(({ job }) => job.id);
  }

  /** Queued and admitted application jobs both hold old-epoch message keys. */
  hasPendingRealJobs(): boolean {
    for (const runtime of this.jobs.values())
      if (!runtime.settled && runtime.job.kind === "real") return true;
    return false;
  }

  /** Retire old-key producers while keeping this cycle's fixed dummy tail. */
  invalidateRealJobsForRekey(): void {
    for (const runtime of [...this.jobs.values()]) {
      if (runtime.job.kind !== "real" || runtime.settled) continue;
      runtime.keyEpochVersion++;
      if (runtime.cancelRequested) {
        // Explicit user cancellation still needs its control cell. Its producer
        // uses the live epoch and no message key, so re-seal any cached cancel.
        runtime.pendingCancelCell?.fill(0);
        runtime.pendingCancelCell = undefined;
        continue;
      }
      runtime.completed = true;
      this.settle(runtime, {
        jobId: runtime.job.id,
        outcome: "failed",
        reason: "key-epoch-changed",
      });
    }
    // The next slot's cell was produced under the old epoch: produce it again
    // under the new one (a retired job's lane carries a dummy).
    this.reprepare();
  }

  /**
   * Live progress for one job, or undefined once the scheduler no longer holds
   * it (settled: completed, cancelled or failed — `settle` drops it from the
   * map). Read-only: polling it never perturbs the fixed schedule.
   */
  getJobProgress(jobId: string): CoverJobProgress | undefined {
    const runtime = this.jobs.get(jobId);
    if (!runtime) return undefined;

    return {
      state: runtime.state,
      queuePosition: [...this.queued].sort(compareQueuedJobs).indexOf(runtime),
      sentCells: runtime.sentCells,
    };
  }

  enqueue(job: CoverJob): void {
    if (typeof job.id !== "string" || job.id.length === 0)
      throw new Error("coverScheduler: job id must not be empty");
    if (this.jobs.has(job.id))
      throw new Error("coverScheduler: job id is already queued or admitted");
    if (job.kind !== "real" && job.kind !== "control")
      throw new Error("coverScheduler: unsupported job kind");
    assertSafeInteger("declared cell count", job.declaredCellCount);
    if (job.declaredCellCount < 1 || job.declaredCellCount > this.slotsPerLane)
      throw new Error(
        "coverScheduler: job does not fit the configured F x D lane capacity",
      );
    if (typeof job.nextCell !== "function")
      throw new Error("coverScheduler: job nextCell must be a function");
    if (job.priority !== undefined)
      assertSafeInteger("job priority", job.priority);

    const runtime: JobRuntime = {
      job,
      sequence: this.sequence++,
      state: "queued",
      everAdmitted: false,
      sentCells: 0,
      cancelRequested: false,
      cancelSent: false,
      completed: false,
      settled: false,
      keyEpochVersion: 0,
    };
    this.jobs.set(job.id, runtime);
    this.queued.push(runtime);
    this.sortQueue();
  }

  cancel(jobId: string): CoverCancelResult {
    const runtime = this.jobs.get(jobId);
    if (!runtime || runtime.settled) return "not-found";

    if (!runtime.everAdmitted) {
      this.removeQueued(runtime);
      this.settle(runtime, {
        jobId,
        outcome: "cancelled-before-admission",
      });
      return "cancelled-before-admission";
    }

    if (typeof runtime.job.cancelCell !== "function")
      throw new Error(
        "coverScheduler: an admitted cancellable job requires cancelCell",
      );
    runtime.cancelRequested = true;
    runtime.completed = false;
    this.sortQueue();
    // Its lane's next cell is already produced: the CANCEL takes that slot.
    this.reprepare(runtime);
    return "cancel-pending";
  }

  /**
   * Mark a producer complete without adding a terminal frame. Receipt/control
   * traffic is queued as its own control job; this lane becomes dummy tail.
   */
  complete(jobId: string): boolean {
    const runtime = this.jobs.get(jobId);
    if (!runtime || runtime.settled) return false;
    this.finishJob(runtime);
    // A cell of it already produced for its lane's next slot is not sent.
    this.reprepare(runtime);
    return true;
  }

  private finishJob(runtime: JobRuntime): void {
    this.removeQueued(runtime);
    runtime.completed = true;
    this.settle(runtime, { jobId: runtime.job.id, outcome: "completed" });
  }

  start(): boolean {
    if (this.status !== "stopped") return false;
    this.running = true;
    this.setStatus("starting");

    const now = this.assertClockNow();
    if (this.cycle) {
      this.armCycleBoundary(this.cycle.endMs);
      return true;
    }
    this.armOpenBoundary(this.nextCycleBoundary(now, true));
    return true;
  }

  suspend(reason = "suspended"): boolean {
    if (this.status === "stopped" || this.status === "suspended") return false;
    this.disarm();
    this.setStatus("suspended", reason);

    const now = this.assertClockNow();
    if (!this.cycle) return true;
    this.interruptCycle("suspended");
    if (now <= this.cycle.endMs) {
      this.armCycleBoundary(this.cycle.endMs);
    } else {
      this.closeCurrentCycle("late-cleanup");
    }
    return true;
  }

  resume(): boolean {
    if (this.status !== "suspended") return false;
    this.running = true;
    this.disarm();
    this.setStatus("starting");

    const now = this.assertClockNow();
    if (this.cycle && now < this.cycle.endMs) {
      this.armCycleBoundary(this.cycle.endMs);
      return true;
    }
    if (this.cycle) this.closeCurrentCycle("late-cleanup");
    this.armOpenBoundary(this.nextCycleBoundary(now, false));
    return true;
  }

  /**
   * Stop is graceful for an already-open cover cycle: sends cease immediately,
   * but channel close remains pinned to the authenticated cycle boundary.
   */
  stop(): boolean {
    if (this.status === "stopped" && !this.cycle) return false;
    this.running = false;
    this.disarm();
    this.setStatus("stopped");

    // Teardown: a cell produced for a slot that will not come is zeroed here
    // (a dummy) or with its job when the job settles below.
    this.abandonPrepared();
    for (const runtime of [...this.jobs.values()]) {
      this.removeQueued(runtime);
      this.settle(runtime, {
        jobId: runtime.job.id,
        outcome: "failed",
        reason: "stopped",
      });
    }
    if (this.cycle) {
      for (const lane of this.cycle.lanes) lane.job = undefined;
      const now = this.assertClockNow();
      if (now <= this.cycle.endMs) {
        this.armCycleBoundary(this.cycle.endMs);
      } else {
        this.closeCurrentCycle("late-cleanup");
      }
    }
    return true;
  }

  private assertClockNow(): number {
    const now = this.clock.now();
    if (!Number.isFinite(now))
      throw new Error("coverScheduler: clock returned a non-finite time");
    return now;
  }

  private nextCycleBoundary(now: number, inclusive: boolean): number {
    const relative = (now - this.schedule.phaseOffsetMs) / this.cycleDurationMs;
    let cycleIndex = Math.ceil(relative);
    let boundary =
      this.schedule.phaseOffsetMs + cycleIndex * this.cycleDurationMs;
    if (!inclusive && boundary <= now) {
      cycleIndex++;
      boundary =
        this.schedule.phaseOffsetMs + cycleIndex * this.cycleDurationMs;
    }
    if (!Number.isSafeInteger(boundary))
      throw new Error("coverScheduler: next cycle boundary is out of range");
    return boundary;
  }

  private cycleIndexAtBoundary(boundaryMs: number): number {
    const cycleIndex = Math.round(
      (boundaryMs - this.schedule.phaseOffsetMs) / this.cycleDurationMs,
    );
    assertSafeInteger("cycle index", cycleIndex);
    return cycleIndex;
  }

  private sortQueue(): void {
    this.queued.sort(compareQueuedJobs);
  }

  private removeQueued(runtime: JobRuntime): void {
    const index = this.queued.indexOf(runtime);
    if (index !== -1) this.queued.splice(index, 1);
  }

  private dequeue(): JobRuntime | undefined {
    this.sortQueue();
    return this.queued.shift();
  }

  private requeue(
    runtime: JobRuntime,
    reason: CoverJobInterruption["reason"],
  ): void {
    if (runtime.settled || runtime.completed || runtime.cancelSent) return;
    runtime.state = "queued";
    if (!this.queued.includes(runtime)) this.queued.push(runtime);
    this.sortQueue();
    this.safeNotify(() =>
      this.onJobInterrupted?.({ jobId: runtime.job.id, reason }),
    );
  }

  private settle(runtime: JobRuntime, result: CoverJobResult): void {
    if (runtime.settled) return;
    runtime.settled = true;
    runtime.state = "terminal";
    // A settled job sends nothing more: its produced but unsent cells die
    // with it.
    runtime.pendingCell?.fill(0);
    runtime.pendingCell = undefined;
    runtime.pendingCancelCell?.fill(0);
    runtime.pendingCancelCell = undefined;
    this.removeQueued(runtime);
    if (this.jobs.get(runtime.job.id) === runtime)
      this.jobs.delete(runtime.job.id);
    this.safeNotify(() => this.onJobResult?.(result));
  }

  private setStatus(status: CoverSchedulerStatus, reason?: string): void {
    if (this.status === status) return;
    const previous = this.status;
    this.status = status;
    this.safeNotify(() => this.onStatusChange?.({ previous, status, reason }));
  }

  private safeNotify(callback: () => void): void {
    try {
      callback();
    } catch {
      // Observers cannot perturb the fixed traffic schedule.
    }
  }

  private disarm(): void {
    this.generation++;
    if (this.hasTimer) {
      this.clock.clearTimeout(this.timer);
      this.hasTimer = false;
      this.timer = undefined;
    }
  }

  private arm(
    deadlineMs: number,
    kind: TimerKind,
    handler: (generation: number) => MaybePromise<void>,
  ): void {
    this.disarm();
    const generation = this.generation;
    const armRemaining = (): void => {
      if (generation !== this.generation) return;
      const now = this.assertClockNow();
      const remaining = deadlineMs - now;
      const delayMs = Math.min(MAX_TIMER_DELAY_MS, Math.max(0, remaining));
      this.hasTimer = true;
      this.timer = this.clock.setTimeout(
        () => {
          if (generation !== this.generation) return;
          this.hasTimer = false;
          this.timer = undefined;
          const firedAt = this.assertClockNow();
          if (firedAt < deadlineMs) {
            armRemaining();
            return;
          }
          if (firedAt > deadlineMs + this.maxTimerDriftMs) {
            this.handleLateTimer(kind, deadlineMs, firedAt);
            return;
          }
          void Promise.resolve(handler(generation)).catch(() => {
            if (kind === "slot") this.degrade("cell-production-failed");
            // Never suspend: "suspended" is only left by resume(), whose callers
            // are all browser wake events, so a boundary handler that rejected on
            // a visible, online tab parked cover forever (C5).
            else this.degrade("lane-open-failed", "boundary-handler-failed");
          });
        },
        delayMs,
        kind,
      );
    };
    armRemaining();
  }

  private armOpenBoundary(deadlineMs: number): void {
    this.arm(deadlineMs, "open-boundary", (generation) =>
      this.openCycle(deadlineMs, generation),
    );
  }

  private armCycleBoundary(deadlineMs: number): void {
    this.arm(deadlineMs, "cycle-boundary", () =>
      this.handleCycleBoundary(deadlineMs),
    );
  }

  private armSlot(cycle: CycleRuntime): void {
    const slot = this.slotAt(cycle, cycle.nextSlotOrdinal);
    this.arm(slot.deadlineMs, "slot", (generation) =>
      this.sendSlot(generation),
    );
  }

  /**
   * A timer that fired past its own drift tolerance.
   *
   * The cycle it belonged to is over: it must be closed and it must NOT be
   * claimed. What must not happen is parking. Before C5 a late boundary called
   * setStatus("suspended", "timer-drift") and armed nothing while `running`
   * stayed true, and "suspended" is left only by resume(), whose callers are
   * the public method (no src/ caller), visibilitychange -> visible, the Page
   * Lifecycle `resume` event, and online. A visible, online tab that stalled
   * 500 ms over a boundary therefore parked scheduled cover permanently: both
   * handshakes stayed authenticated and the transport stayed connected while
   * every send in both directions failed at its delivery budget. Degrading
   * instead re-arms, which is what coverRuntime's own drift comment already
   * promised.
   *
   * A scheduler that is already suspended or stopped keeps its state: those
   * are deliberate, and each has an event or a caller that will leave it. Only
   * their dead cycle is swept, exactly as before.
   */
  private handleLateTimer(
    kind: TimerKind,
    _deadlineMs: number,
    _firedAt: number,
  ): void {
    if (kind === "slot") {
      this.degrade("missed-deadline");
      return;
    }

    if (this.status === "stopped" || this.status === "suspended") {
      if (this.cycle) {
        this.interruptCycle("suspended");
        this.closeCurrentCycle("late-cleanup");
      }
      return;
    }
    this.degrade("missed-deadline", "timer-drift");
  }

  private async openCycle(
    boundaryMs: number,
    generation: number,
  ): Promise<void> {
    if (
      generation !== this.generation ||
      !this.running ||
      this.status === "stopped" ||
      this.status === "suspended"
    )
      return;

    const cycleIndex = this.cycleIndexAtBoundary(boundaryMs);
    const cycleEndMs = boundaryMs + this.cycleDurationMs;
    if (!Number.isSafeInteger(cycleEndMs))
      throw new Error("coverScheduler: cycle end is out of range");

    const selected: Array<JobRuntime | undefined> = [];
    for (let laneIndex = 0; laneIndex < this.schedule.coverLanes; laneIndex++)
      selected.push(this.dequeue());
    for (const runtime of selected) {
      if (!runtime) continue;
      runtime.state = "admitted";
      runtime.everAdmitted = true;
    }

    const lanes: LaneRuntime[] = [];
    let openFailed = false;
    for (let laneIndex = 0; laneIndex < this.schedule.coverLanes; laneIndex++) {
      const runtime = selected[laneIndex];
      const context: CoverLaneOpenContext = {
        cycleIndex,
        cycleStartMs: boundaryMs,
        cycleEndMs,
        laneIndex,
        job: runtime ? jobSummary(runtime) : null,
      };
      try {
        const handle = this.laneFactory(context);
        if (
          handle === null ||
          typeof handle !== "object" ||
          typeof handle.send !== "function" ||
          typeof handle.close !== "function"
        )
          throw new Error("invalid lane");
        lanes.push({ laneIndex, handle, openContext: context, job: runtime });
      } catch {
        openFailed = true;
      }
    }

    this.cycle = {
      index: cycleIndex,
      startMs: boundaryMs,
      endMs: cycleEndMs,
      lanes,
      nextSlotOrdinal: 0,
    };

    if (openFailed) {
      this.setStatus("degraded", "lane-open-failed");
      for (const lane of this.cycle.lanes) lane.job = undefined;
      for (const runtime of selected) {
        if (runtime) this.requeue(runtime, "lane-open-failed");
      }
      this.armCycleBoundary(cycleEndMs);
      return;
    }

    this.setStatus("active");
    if (
      generation !== this.generation ||
      this.status !== "active" ||
      this.cycle?.index !== cycleIndex
    )
      return;
    this.prepare(this.cycle);
    this.armSlot(this.cycle);
  }

  private slotAt(cycle: CycleRuntime, ordinal: number): CoverSlot {
    const epochInCycle = Math.floor(ordinal / this.slotsPerEpoch);
    const withinEpoch = ordinal % this.slotsPerEpoch;
    const frameIndex = Math.floor(withinEpoch / this.schedule.coverLanes);
    const laneIndex = withinEpoch % this.schedule.coverLanes;
    const epochStartMs =
      cycle.startMs + epochInCycle * this.schedule.coverCadenceMs;
    const numerator = (2 * withinEpoch + 1) * this.schedule.coverCadenceMs;
    const deadlineMs =
      epochStartMs + Math.floor(numerator / (2 * this.slotsPerEpoch));

    return {
      deadlineMs,
      cycleIndex: cycle.index,
      cycleStartMs: cycle.startMs,
      cycleEndMs: cycle.endMs,
      epochIndex:
        cycle.index * this.schedule.coverDurationEpochs + epochInCycle,
      epochInCycle,
      laneIndex,
      frameIndex,
      laneSlotIndex:
        epochInCycle * this.schedule.coverFramesPerCell + frameIndex,
    };
  }

  private jobSlot(runtime: JobRuntime, slot: CoverSlot): CoverJobSlot {
    return {
      ...slot,
      jobId: runtime.job.id,
      jobKind: runtime.job.kind,
      jobCellIndex: runtime.sentCells,
    };
  }

  /** The cell for one slot; undefined when its slot gave up on it first. */
  private async requestForSlot(
    lane: LaneRuntime,
    slot: CoverSlot,
    prepared: PreparedCell,
  ): Promise<CoverSendRequest | undefined> {
    const runtime = lane.job;
    if (runtime && !runtime.settled) {
      const produced = await this.produceJobCell(runtime, slot);
      if (produced)
        return {
          cell: produced.cell,
          source: produced.source,
          slot,
          jobId: runtime.job.id,
          jobCellIndex: runtime.sentCells,
        };
    }
    // No dummy for a slot that will not send it (a torn-down edge among them).
    if (prepared.abandoned) return undefined;

    return {
      cell: assertCell("makeDummy", await this.makeDummy(slot)),
      source: "dummy",
      slot,
      ...(runtime ? { jobId: runtime.job.id } : {}),
    };
  }

  /**
   * The job's next cell for its lane, or null for a dummy. What it produces
   * is the job's (pendingCell / pendingCancelCell) until it is sent, so a slot
   * that gives up on it loses nothing and the job never sends a cell twice;
   * and one production runs per job at a time, so a production still running
   * when its slot gave up is waited for, never raced by a second nextCell.
   */
  private async produceJobCell(
    runtime: JobRuntime,
    slot: CoverSlot,
  ): Promise<{ cell: Uint8Array; source: CoverCellSource } | null> {
    while (runtime.producing) await runtime.producing;
    if (runtime.settled) return null;
    let finished!: () => void;
    runtime.producing = new Promise<void>((resolve) => {
      finished = resolve;
    });
    try {
      for (;;) {
        if (runtime.settled) return null;
        const withJob = this.jobSlot(runtime, slot);
        if (runtime.cancelRequested && !runtime.cancelSent) {
          if (runtime.pendingCancelCell)
            return { cell: runtime.pendingCancelCell, source: "cancel" };
          const keyEpochVersion = runtime.keyEpochVersion;
          const cell = assertCell(
            "cancelCell",
            await runtime.job.cancelCell?.(withJob),
          );
          // Sealed against an epoch a rekey retired meanwhile: seal again.
          if (runtime.settled || keyEpochVersion !== runtime.keyEpochVersion) {
            cell.fill(0);
            continue;
          }
          runtime.pendingCancelCell = cell;
          continue;
        }
        if (
          runtime.completed ||
          runtime.sentCells >= runtime.job.declaredCellCount
        )
          return null;
        if (runtime.pendingCell)
          return { cell: runtime.pendingCell, source: runtime.job.kind };
        const produced = await runtime.job.nextCell(withJob);
        // A durable PQ commit or explicit completion may retire this producer
        // while its storage/sealing promise is pending. Never emit its old key.
        if (runtime.settled || runtime.completed) {
          produced?.fill(0);
          return null;
        }
        if (produced === null) {
          if (runtime.job.exhausted?.()) this.finishJob(runtime);
          return null;
        }
        // Kept by the job, then offered again by the loop: a CANCEL requested
        // while it was produced still takes precedence.
        runtime.pendingCell = assertCell("nextCell", produced);
      }
    } finally {
      runtime.producing = undefined;
      finished();
    }
  }

  /**
   * Produce the cell for the open cycle's next slot now, one slot ahead of it.
   * The slot's wake-up then only sends what is ready, so the time a cell
   * leaves is the time its wake-up runs, whatever the cell carries: a dummy
   * sealed in memory and a real chunk read from the outbox store, its receipt
   * token written back and sealed leave alike (docs/e2e/cover-timers/,
   * sealed mode). A cell still being produced when its slot comes is a late
   * slot, never a late send.
   */
  private prepare(cycle: CycleRuntime): void {
    const slot = this.slotAt(cycle, cycle.nextSlotOrdinal);
    const lane = cycle.lanes.find(
      ({ laneIndex }) => laneIndex === slot.laneIndex,
    );
    if (!lane) return;
    const prepared: PreparedCell = {
      ordinal: cycle.nextSlotOrdinal,
      lane,
      state: "producing",
      abandoned: false,
    };
    cycle.prepared = prepared;
    // Started in a microtask: the page's timer host runs the wake-ups of every
    // edge due at once in one task, so all of them have sent (or opened their
    // lanes) before any edge's production runs.
    void Promise.resolve()
      .then(() => this.requestForSlot(lane, slot, prepared))
      .then(
        (request) => {
          if (!request) return;
          if (prepared.abandoned) {
            this.releaseUnsent(request);
            return;
          }
          prepared.request = request;
          prepared.state = "ready";
        },
        () => {
          prepared.state = "failed";
        },
      );
  }

  /** The prepared cell's slot will not send it: release it. */
  private abandonPrepared(): void {
    const cycle = this.cycle;
    const prepared = cycle?.prepared;
    if (!cycle || !prepared) return;
    cycle.prepared = undefined;
    prepared.abandoned = true;
    if (prepared.request) this.releaseUnsent(prepared.request);
  }

  /**
   * A job's state changed after the next slot's cell was produced (a cancel,
   * a completion, a rekey): produce that slot's cell again. With a job, only
   * when the prepared slot is that job's lane.
   */
  private reprepare(runtime?: JobRuntime): void {
    const cycle = this.cycle;
    const prepared = cycle?.prepared;
    if (!cycle || !prepared || this.status !== "active") return;
    if (runtime && prepared.lane.job !== runtime) return;
    this.abandonPrepared();
    this.prepare(cycle);
  }

  /**
   * A produced cell that will not be sent. A dummy is zeroed. A job's cell
   * stays its job's (pendingCell), for the job's next slot, and is zeroed
   * when the job settles.
   */
  private releaseUnsent(request: CoverSendRequest): void {
    if (request.source === "dummy") request.cell.fill(0);
  }

  private acceptSent(lane: LaneRuntime, request: CoverSendRequest): void {
    const runtime = lane.job;
    if (!runtime || runtime.settled) return;
    if (request.source === "cancel") {
      runtime.pendingCancelCell = undefined;
      runtime.cancelSent = true;
      this.settle(runtime, {
        jobId: runtime.job.id,
        outcome: "cancelled",
      });
      return;
    }
    if (request.source !== "real" && request.source !== "control") return;

    runtime.pendingCell = undefined;
    runtime.sentCells++;
    if (
      runtime.sentCells === runtime.job.declaredCellCount ||
      runtime.job.exhausted?.()
    ) {
      runtime.completed = true;
      this.settle(runtime, {
        jobId: runtime.job.id,
        outcome: "completed",
      });
    }
  }

  private async sendSlot(generation: number): Promise<void> {
    const cycle = this.cycle;
    if (generation !== this.generation || !cycle || this.status !== "active")
      return;
    const prepared = cycle.prepared;
    if (prepared?.ordinal !== cycle.nextSlotOrdinal) {
      this.degrade("lane-open-failed");
      return;
    }
    cycle.prepared = undefined;
    // Its cell was produced during the slot before; this wake-up only sends
    // it. One that is not ready is a late slot: sending it when it is ready
    // would make the send time tell what the cell carries.
    if (prepared.state !== "ready" || !prepared.request) {
      prepared.abandoned = true;
      this.degrade(
        prepared.state === "failed"
          ? "cell-production-failed"
          : "missed-deadline",
      );
      return;
    }
    const { lane, request } = prepared;

    let accepted: boolean | void;
    try {
      accepted = await lane.handle.send(request);
    } catch {
      this.releaseUnsent(request);
      this.degrade("send-failed");
      return;
    }
    if (accepted === false) {
      this.releaseUnsent(request);
      this.degrade("backpressure");
      return;
    }
    this.acceptSent(lane, request);

    if (generation !== this.generation || this.cycle !== cycle) return;
    cycle.nextSlotOrdinal++;
    const totalCycleSlots =
      this.slotsPerEpoch * this.schedule.coverDurationEpochs;
    if (cycle.nextSlotOrdinal < totalCycleSlots) {
      this.prepare(cycle);
      this.armSlot(cycle);
    } else {
      this.armCycleBoundary(cycle.endMs);
    }
  }

  /**
   * Degrade honestly and keep the schedule alive: the cycle closes at its own
   * authenticated boundary when there still is one, otherwise the gap is swept
   * and the next strictly-future boundary is armed. This is the only recovery
   * path a late or failed boundary is allowed to take (C5).
   *
   * `statusReason` is the free-form CoverStatusChange reason, which is not the
   * same vocabulary as the CoverJobInterruption reason handed to requeued jobs;
   * it defaults to it where they do coincide.
   */
  private degrade(
    reason: CoverJobInterruption["reason"],
    statusReason: string = reason,
  ): void {
    if (this.status === "stopped" || this.status === "suspended") return;
    this.disarm();
    this.setStatus("degraded", statusReason);

    const now = this.assertClockNow();
    if (this.cycle) {
      this.interruptCycle(reason);
      if (now <= this.cycle.endMs) {
        this.armCycleBoundary(this.cycle.endMs);
        return;
      }
      this.closeCurrentCycle("late-cleanup");
    }
    if (this.running) this.armOpenBoundary(this.nextCycleBoundary(now, false));
  }

  private interruptCycle(reason: CoverJobInterruption["reason"]): void {
    if (!this.cycle) return;
    this.abandonPrepared();
    for (const lane of this.cycle.lanes) {
      const runtime = lane.job;
      lane.job = undefined;
      if (runtime) this.requeue(runtime, reason);
    }
  }

  private finalizeCycleJobs(): void {
    if (!this.cycle) return;
    for (const lane of this.cycle.lanes) {
      const runtime = lane.job;
      lane.job = undefined;
      if (!runtime || runtime.settled) continue;
      if (runtime.cancelRequested && !runtime.cancelSent) {
        this.requeue(runtime, "missed-deadline");
      } else {
        this.settle(runtime, {
          jobId: runtime.job.id,
          outcome: "failed",
          reason: "capacity-exhausted",
        });
      }
    }
  }

  private closeCurrentCycle(reason: CoverLaneCloseContext["reason"]): boolean {
    const cycle = this.cycle;
    if (!cycle) return true;
    this.abandonPrepared();
    let closedCleanly = true;
    for (const lane of [...cycle.lanes].sort(
      (left, right) => left.laneIndex - right.laneIndex,
    )) {
      try {
        lane.handle.close({ ...lane.openContext, reason });
      } catch {
        closedCleanly = false;
      }
    }
    this.cycle = undefined;
    return closedCleanly;
  }

  private handleCycleBoundary(boundaryMs: number): void {
    const cycle = this.cycle;
    if (!cycle || cycle.endMs !== boundaryMs) return;
    this.finalizeCycleJobs();
    const closedCleanly = this.closeCurrentCycle("boundary");

    if (!closedCleanly) {
      if (this.status !== "stopped")
        this.setStatus("degraded", "lane-close-failed");
      if (this.running)
        this.armOpenBoundary(
          this.nextCycleBoundary(this.assertClockNow(), false),
        );
      return;
    }
    if (
      !this.running ||
      this.status === "stopped" ||
      this.status === "suspended"
    )
      return;
    this.openCycle(boundaryMs, this.generation).catch(() => {
      // Suspending here parked the scheduler: this very method is the only
      // thing that reopens a cycle, and it returns early while suspended (C5).
      this.degrade("lane-open-failed", "boundary-handler-failed");
    });
  }
}

export const coverSlotSpacingMs = (schedule: CoverSchedule): number =>
  schedule.coverCadenceMs / (schedule.coverLanes * schedule.coverFramesPerCell);

export const validateCoverSchedule = (schedule: CoverSchedule): void => {
  if (schedule === null || typeof schedule !== "object")
    throw new Error("coverScheduler: schedule must be an object");
  assertSafeInteger("phase offset", schedule.phaseOffsetMs);
  assertSafeInteger("cover cadence", schedule.coverCadenceMs);
  assertSafeInteger("cover lanes", schedule.coverLanes);
  assertSafeInteger("cover frames per cell", schedule.coverFramesPerCell);
  assertSafeInteger("cover duration epochs", schedule.coverDurationEpochs);

  if (schedule.coverCadenceMs < 1)
    throw new Error("coverScheduler: cover cadence must be positive");
  if (schedule.coverLanes < 1 || schedule.coverLanes > MAX_COVER_LANES)
    throw new Error("coverScheduler: cover lanes must be between 1 and 16");
  if (schedule.coverFramesPerCell < 1)
    throw new Error("coverScheduler: cover frames per cell must be positive");
  if (schedule.coverDurationEpochs < 1)
    throw new Error("coverScheduler: cover duration epochs must be positive");

  const slotsPerEpoch = schedule.coverLanes * schedule.coverFramesPerCell;
  const slotsPerLane =
    schedule.coverFramesPerCell * schedule.coverDurationEpochs;
  const cycleDuration = schedule.coverCadenceMs * schedule.coverDurationEpochs;
  if (
    !Number.isSafeInteger(slotsPerEpoch) ||
    !Number.isSafeInteger(slotsPerLane) ||
    !Number.isSafeInteger(cycleDuration)
  )
    throw new Error("coverScheduler: schedule geometry is out of range");
  if (coverSlotSpacingMs(schedule) < MIN_COVER_SLOT_MS)
    throw new Error(
      "coverScheduler: schedule requires at least 25ms per staggered slot",
    );
};

export const createCoverScheduler = (
  options: CoverSchedulerOptions,
): CoverScheduler => new CoverScheduler(options);
