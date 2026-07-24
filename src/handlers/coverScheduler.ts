export type CoverSchedulerStatus =
  "starting" | "active" | "degraded" | "suspended" | "stopped";

export type CoverJobKind = "real" | "control";
export type CoverCellSource = CoverJobKind | "cancel" | "dummy";

type MaybePromise<T> = T | PromiseLike<T>;

export interface CoverClock {
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
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
 * A producer is deliberately lazy: ratchet state and encrypted cell bytes can
 * be prepared at the scheduled slot instead of buffering a complete cycle.
 * Returning null substitutes a dummy for this slot without consuming a job
 * cell. declaredCellCount enforces the authenticated F x D capacity class.
 */
export interface CoverJob {
  readonly id: string;
  readonly kind: CoverJobKind;
  readonly declaredCellCount: number;
  readonly priority?: number;
  nextCell(slot: CoverJobSlot): MaybePromise<Uint8Array | null>;
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
  readonly reason?: "capacity-exhausted" | "stopped";
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
  pendingCell?: Uint8Array;
  pendingCancelCell?: Uint8Array;
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
}

type TimerKind = "open-boundary" | "cycle-boundary" | "slot";

const MAX_COVER_LANES = 16;
const MIN_COVER_SLOT_MS = 25;
const MAX_TIMER_DELAY_MS = 0x7fffffff;

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
    return "cancel-pending";
  }

  /**
   * Mark a producer complete without adding a terminal frame. Receipt/control
   * traffic is queued as its own control job; this lane becomes dummy tail.
   */
  complete(jobId: string): boolean {
    const runtime = this.jobs.get(jobId);
    if (!runtime || runtime.settled) return false;
    this.removeQueued(runtime);
    runtime.completed = true;
    runtime.pendingCell = undefined;
    this.settle(runtime, { jobId, outcome: "completed" });
    return true;
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
      this.timer = this.clock.setTimeout(() => {
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
          else this.suspend("boundary-handler-failed");
        });
      }, delayMs);
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
      this.sendSlot(slot, generation),
    );
  }

  private handleLateTimer(
    kind: TimerKind,
    _deadlineMs: number,
    _firedAt: number,
  ): void {
    if (kind === "slot") {
      this.degrade("missed-deadline");
      return;
    }

    if (this.cycle) {
      this.interruptCycle("suspended");
      this.closeCurrentCycle("late-cleanup");
    }
    if (this.status !== "stopped") this.setStatus("suspended", "timer-drift");
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

  private async requestForSlot(
    lane: LaneRuntime,
    slot: CoverSlot,
  ): Promise<CoverSendRequest> {
    const runtime = lane.job;
    if (runtime && !runtime.settled) {
      const withJob = this.jobSlot(runtime, slot);
      if (runtime.cancelRequested && !runtime.cancelSent) {
        const cell =
          runtime.pendingCancelCell ??
          assertCell("cancelCell", await runtime.job.cancelCell?.(withJob));
        return {
          cell,
          source: "cancel",
          slot,
          jobId: runtime.job.id,
          jobCellIndex: runtime.sentCells,
        };
      }

      if (
        !runtime.completed &&
        runtime.sentCells < runtime.job.declaredCellCount
      ) {
        const produced =
          runtime.pendingCell ?? (await runtime.job.nextCell(withJob));
        if (produced !== null) {
          const cell = assertCell("nextCell", produced);
          return {
            cell,
            source: runtime.job.kind,
            slot,
            jobId: runtime.job.id,
            jobCellIndex: runtime.sentCells,
          };
        }
      }
    }

    return {
      cell: assertCell("makeDummy", await this.makeDummy(slot)),
      source: "dummy",
      slot,
      ...(runtime ? { jobId: runtime.job.id } : {}),
    };
  }

  private cacheUnsent(lane: LaneRuntime, request: CoverSendRequest): void {
    const runtime =
      (request.jobId ? this.jobs.get(request.jobId) : undefined) ?? lane.job;
    if (!runtime || runtime.settled) return;
    if (request.source === "cancel") {
      runtime.pendingCancelCell = request.cell;
    } else if (request.source === "real" || request.source === "control") {
      runtime.pendingCell = request.cell;
    }
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
    if (runtime.sentCells === runtime.job.declaredCellCount) {
      runtime.completed = true;
      this.settle(runtime, {
        jobId: runtime.job.id,
        outcome: "completed",
      });
    }
  }

  private async sendSlot(slot: CoverSlot, generation: number): Promise<void> {
    const cycle = this.cycle;
    if (generation !== this.generation || !cycle || this.status !== "active")
      return;
    const lane = cycle.lanes.find(
      ({ laneIndex }) => laneIndex === slot.laneIndex,
    );
    if (!lane) {
      this.degrade("lane-open-failed");
      return;
    }

    let request: CoverSendRequest;
    try {
      request = await this.requestForSlot(lane, slot);
    } catch {
      this.degrade("cell-production-failed");
      return;
    }

    if (generation !== this.generation) {
      this.cacheUnsent(lane, request);
      return;
    }
    if (this.assertClockNow() > slot.deadlineMs + this.maxTimerDriftMs) {
      this.cacheUnsent(lane, request);
      this.degrade("missed-deadline");
      return;
    }

    let accepted: boolean | void;
    try {
      accepted = await lane.handle.send(request);
    } catch {
      this.cacheUnsent(lane, request);
      this.degrade("send-failed");
      return;
    }
    if (accepted === false) {
      this.cacheUnsent(lane, request);
      this.degrade("backpressure");
      return;
    }
    this.acceptSent(lane, request);

    if (generation !== this.generation || this.cycle !== cycle) return;
    cycle.nextSlotOrdinal++;
    const totalCycleSlots =
      this.slotsPerEpoch * this.schedule.coverDurationEpochs;
    if (cycle.nextSlotOrdinal < totalCycleSlots) {
      this.armSlot(cycle);
    } else {
      this.armCycleBoundary(cycle.endMs);
    }
  }

  private degrade(reason: CoverJobInterruption["reason"]): void {
    if (this.status === "stopped" || this.status === "suspended") return;
    this.disarm();
    this.setStatus("degraded", reason);

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
      this.suspend("boundary-handler-failed");
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
