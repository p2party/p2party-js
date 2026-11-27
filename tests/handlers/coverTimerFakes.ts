// A controllable timeline for the scheduled-cover clock: page timers that a
// "hidden" page throttles the way Chromium does (aligned to one wake-up per
// throttle period), a page that can be frozen or a process that can sleep, and
// a fake dedicated timer worker whose timers are never throttled. Everything
// runs on one virtual clock, so a test decides exactly when every wake-up
// lands and in which order the page sees it.
import type {
  CoverTimerEnvironment,
  CoverTimerRequest,
  CoverTimerWorkerPort,
} from "../../src/handlers/coverTimerWorker";

interface QueuedEvent {
  readonly id: number;
  /** When it is due. A page event can run later than this. */
  readonly at: number;
  /** Page events are its timers and the messages delivered to it. */
  readonly page: boolean;
  readonly timer: boolean;
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
  /** False: this runtime cannot create a worker at all. */
  workersAvailable = true;
  /** True: creating a worker throws (blocked, out of resources). */
  failWorkerCreation = false;
  /** Whether the environment is a browser page (console.warn reporting). */
  browserPage = true;
  /** Page events (its timers, messages to it) wait until then: a freeze. */
  pagePausedUntil = -Infinity;
  /** At a thaw, run the page's due timers before the messages queued for it. */
  timersFirstAtThaw = false;
  private nextId = 1;
  private readonly queue = new Map<number, QueuedEvent>();
  private readonly pageTimers = new Set<number>();
  private cachedEnv: CoverTimerEnvironment | undefined;

  schedule(
    at: number,
    run: () => void,
    { page = false, timer = true }: { page?: boolean; timer?: boolean } = {},
  ): number {
    const id = this.nextId++;
    this.queue.set(id, { id, at, page, timer, run });
    return id;
  }

  cancel(id: number): void {
    this.queue.delete(id);
    this.pageTimers.delete(id);
  }

  /** A message to the page: a page task, queued now. */
  deliverToPage(run: () => void): void {
    this.schedule(this.time, run, { page: true, timer: false });
  }

  /** Page timers still armed (backstops included). */
  armedPageTimers(): number {
    return this.pageTimers.size;
  }

  /** Freeze the page (not the worker) for `ms` from now. */
  freezePage(ms: number): void {
    this.pagePausedUntil = this.time + ms;
  }

  /**
   * The page's thread is busy for `ms`, inside a synchronous call that is
   * running now: time moves on, the worker's timers fire and their messages
   * queue for the page in the order they fell due, and nothing on the page
   * runs until the call returns.
   */
  busyPage(ms: number): void {
    const until = this.time + ms;
    for (;;) {
      let next: QueuedEvent | undefined;
      for (const event of this.queue.values())
        if (
          !event.page &&
          event.at <= until &&
          (!next ||
            event.at < next.at ||
            (event.at === next.at && event.id < next.id))
        )
          next = event;
      if (!next) break;
      this.queue.delete(next.id);
      this.time = Math.max(this.time, next.at);
      next.run();
    }
    this.time = until;
  }

  /**
   * The whole process sleeps (a laptop lid): nothing runs for `ms`, then
   * everything that fell due runs at once, in the order it fell due.
   */
  async sleep(ms: number): Promise<void> {
    this.time += ms;
    await this.advanceTo(this.time);
  }

  /**
   * One object per timeline, as the browser has one per page, so every clock
   * built on it shares one host. Read once, so set `workersAvailable` and
   * `browserPage` before the first runtime is built.
   */
  get env(): CoverTimerEnvironment {
    this.cachedEnv ??= {
      now: () => this.time,
      browserPage: this.browserPage,
      setTimeout: (callback, delayMs) => {
        const id = this.schedule(
          this.time + Math.max(0, delayMs),
          () => {
            this.pageTimers.delete(id);
            this.pageTimerRuns += 1;
            callback();
          },
          { page: true },
        );
        this.pageTimers.add(id);
        return id;
      },
      clearTimeout: (handle) => {
        if (typeof handle === "number") this.cancel(handle);
      },
      createWorker: this.workersAvailable
        ? () => {
            if (this.failWorkerCreation)
              throw new Error("Worker could not be created");
            const worker = new FakeTimerWorker(this);
            this.workers.push(worker);
            return worker;
          }
        : undefined,
    };
    return this.cachedEnv;
  }

  /** When an event actually runs. */
  private runsAt(event: QueuedEvent): number {
    let at = event.at;
    if (event.page && event.timer && this.hidden)
      at = Math.max(
        Math.ceil((at - this.throttlePhaseMs) / this.throttleMs) *
          this.throttleMs +
          this.throttlePhaseMs,
        this.time,
      );
    if (event.page && at < this.pagePausedUntil) at = this.pagePausedUntil;
    return at;
  }

  private before(a: QueuedEvent, aAt: number, b: QueuedEvent, bAt: number) {
    if (aAt !== bAt) return aAt < bAt;
    if (this.timersFirstAtThaw && a.timer !== b.timer) return a.timer;
    if (a.at !== b.at) return a.at < b.at;
    return a.id < b.id;
  }

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
        if (at > target) continue;
        if (!next || this.before(event, at, next, nextAt)) {
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

/** A dedicated timer worker on the timeline: arms, cancels, fires, answers pings. */
export class FakeTimerWorker implements CoverTimerWorkerPort {
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onmessageerror: ((event: unknown) => void) | null = null;
  /** Every message the page posted, exactly as posted. */
  readonly posted: unknown[] = [];
  terminated = false;
  /** A wedged worker takes messages and never answers. */
  wedged = false;
  /** Cancels lost in flight: the worker still fires the handle. */
  ignoreCancels = false;
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
          this.reply({ op: "fire", id: message.id });
        }),
      );
    } else if (message.op === "cancel" && !this.ignoreCancels) {
      const timer = this.timers.get(message.id);
      if (timer !== undefined) this.timeline.cancel(timer);
      this.timers.delete(message.id);
    } else if (message.op === "ping") {
      this.reply({ op: "pong", id: message.id });
    }
  }

  private reply(data: { op: "fire" | "pong"; id: number }): void {
    if (this.terminated || this.wedged) return;
    this.timeline.deliverToPage(() => {
      if (!this.terminated) this.onmessage?.({ data });
    });
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

  /** The handles of the timers it still holds. */
  armedIds(): number[] {
    return [...this.timers.keys()];
  }

  /** The worker's error event, as a crashed worker raises it. */
  fail(): void {
    this.onerror?.({ type: "error" });
  }
}
