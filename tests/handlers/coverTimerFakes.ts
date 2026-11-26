// A controllable timeline for the scheduled-cover clock: page timers that a
// "hidden" page throttles the way Chromium does (aligned to one wake-up per
// throttle period), and a fake dedicated timer worker whose timers are never
// throttled. Both run on one virtual clock, so a test decides exactly when
// every wake-up lands.
import type {
  CoverTimerEnvironment,
  CoverTimerRequest,
  CoverTimerWorkerPort,
} from "../../src/handlers/coverTimerWorker";

interface QueuedEvent {
  readonly id: number;
  /** When it is due. A page timer on a hidden page runs later than this. */
  readonly at: number;
  readonly page: boolean;
  readonly run: () => void;
}

export class CoverTimeline {
  time = 0;
  /** While true, page timers are throttled; worker timers never are. */
  hidden = false;
  /** Chromium aligns a hidden page's timers to about one wake-up a second. */
  throttleMs = 1_000;
  /** Where in each throttle period the aligned wake-up lands. */
  throttlePhaseMs = 0;
  /** How many page-timer callbacks have run (backstops included). */
  pageTimerRuns = 0;
  readonly workers: FakeTimerWorker[] = [];
  /** Set to false to model a runtime that cannot create a worker. */
  workersAvailable = true;
  private nextId = 1;
  private readonly queue = new Map<number, QueuedEvent>();
  private readonly pageTimers = new Set<number>();

  schedule(at: number, run: () => void, page = false): number {
    const id = this.nextId++;
    this.queue.set(id, { id, at, page, run });
    return id;
  }

  /**
   * When an event actually runs: a page timer on a hidden page waits for the
   * next throttle boundary at or after its due time. Judged at run time, so
   * a timer armed while visible is throttled once the page is hidden.
   */
  private runsAt(event: QueuedEvent): number {
    if (!event.page || !this.hidden) return event.at;
    const aligned =
      Math.ceil((event.at - this.throttlePhaseMs) / this.throttleMs) *
        this.throttleMs +
      this.throttlePhaseMs;
    return Math.max(aligned, this.time);
  }

  cancel(id: number): void {
    this.queue.delete(id);
    this.pageTimers.delete(id);
  }

  /** Page timers still armed (backstops included). */
  armedPageTimers(): number {
    return this.pageTimers.size;
  }

  readonly env: CoverTimerEnvironment = {
    now: () => this.time,
    setTimeout: (callback, delayMs) => {
      const id = this.schedule(
        this.time + Math.max(0, delayMs),
        () => {
          this.pageTimers.delete(id);
          this.pageTimerRuns += 1;
          callback();
        },
        true,
      );
      this.pageTimers.add(id);
      return id;
    },
    clearTimeout: (handle) => {
      if (typeof handle === "number") this.cancel(handle);
    },
    createWorker: () => {
      if (!this.workersAvailable) throw new Error("Worker is not available");
      const worker = new FakeTimerWorker(this);
      this.workers.push(worker);
      return worker;
    },
  };

  private async drain(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("timeline cannot go backwards");
    for (;;) {
      await this.drain();
      let next: QueuedEvent | undefined;
      let nextAt = Infinity;
      for (const event of this.queue.values()) {
        const at = this.runsAt(event);
        if (
          at <= target &&
          (at < nextAt || (at === nextAt && next && event.id < next.id))
        ) {
          next = event;
          nextAt = at;
        }
      }
      if (!next) break;
      this.queue.delete(next.id);
      this.time = Math.max(this.time, nextAt);
      next.run();
    }
    this.time = target;
    await this.drain();
  }
}

/** A dedicated timer worker on the timeline: arms, cancels and fires by handle. */
export class FakeTimerWorker implements CoverTimerWorkerPort {
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onmessageerror: ((event: unknown) => void) | null = null;
  /** Every message the page posted, exactly as posted. */
  readonly posted: unknown[] = [];
  terminated = false;
  /** A wedged worker takes messages and never answers. */
  wedged = false;
  private readonly timers = new Map<number, number>();

  constructor(private readonly timeline: CoverTimeline) {}

  postMessage(message: CoverTimerRequest): void {
    if (this.terminated) throw new Error("worker is terminated");
    // What a real postMessage delivers: a structured clone.
    this.posted.push(structuredClone(message));
    if (this.wedged) return;
    if (message.op === "arm") {
      const previous = this.timers.get(message.id);
      if (previous !== undefined) this.timeline.cancel(previous);
      this.timers.set(
        message.id,
        this.timeline.schedule(this.timeline.time + message.delayMs, () => {
          this.timers.delete(message.id);
          if (!this.terminated)
            this.onmessage?.({ data: { op: "fire", id: message.id } });
        }),
      );
    } else if (message.op === "cancel") {
      const timer = this.timers.get(message.id);
      if (timer !== undefined) this.timeline.cancel(timer);
      this.timers.delete(message.id);
    }
  }

  terminate(): void {
    this.terminated = true;
    for (const timer of this.timers.values()) this.timeline.cancel(timer);
    this.timers.clear();
  }

  /** Timers the worker still holds. */
  armedTimers(): number {
    return this.timers.size;
  }

  /** The worker's error event, as a crashed worker raises it. */
  fail(): void {
    this.onerror?.({ type: "error" });
  }
}
