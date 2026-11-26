import { debugLog } from "../utils/debug";

import type { CoverClock } from "./coverScheduler";

// ── scheduled-cover wake-ups from a dedicated timer worker ───────────────────
//
// A hidden page's timers are throttled: Chromium aligns them to about one
// wake-up per second, and after five minutes hidden to one per minute. A cover
// slot that fires past its drift tolerance degrades its cycle, so on page
// timers a hidden tab's cover collapses and tab visibility becomes readable off
// the wire. A dedicated worker's timers are not subject to that throttling, so
// the scheduler's wake-ups come from one: the worker owns the timers and posts
// a message when one is due, and the page runs the slot (and its send) in the
// message handler. Measured in Chrome for Testing 159 on macOS, a hidden page
// handled those messages up to 143 ms late (median 50 ms), so at 100 ms slots
// some cycles still degrade while hidden; see
// docs/protocol-v4-pq-cover-architecture.md and docs/e2e/cover-timers/.
//
// Lateness is judged on ONE clock, the page's `Date.now()`, read when the page
// runs the callback: the scheduler compares that against the slot's deadline.
// The worker only decides when to wake the page. If the worker ticks on time
// but the page's event loop is busy, the message is handled late and the slot
// is late, exactly as a late page timer would be; that is honest, because the
// send happens on the page.
//
// What crosses to the worker is a delay and an opaque integer handle, nothing
// else: no key material, no peer or room identifier, no plaintext.
//
// Where no worker can be created (no `window`, as in tests and non-browser
// runtimes, or no Worker/Blob/URL support) the clock falls back to page timers
// and says so once through the debug log. A worker that fails (its error
// event) or stops answering (a wake-up STALL_MS overdue) is dropped for page
// timers too: the schedule keeps running, it never stops.

/** One request from the page to the timer worker. */
export type CoverTimerRequest =
  | { readonly op: "arm"; readonly id: number; readonly delayMs: number }
  | { readonly op: "cancel"; readonly id: number };

/** The worker's only message to the page: this handle is due. */
export interface CoverTimerFire {
  readonly op: "fire";
  readonly id: number;
}

/**
 * The worker, as source text. It is loaded from a Blob URL exactly as the
 * database worker is, so a page that admits that worker (`worker-src blob:`)
 * needs nothing new. It keeps no state but its own timer handles.
 */
export const COVER_TIMER_WORKER_SOURCE = `"use strict";
const timers = new Map();
self.onmessage = (event) => {
  const message = event.data;
  if (message === null || typeof message !== "object") return;
  if (!Number.isSafeInteger(message.id)) return;
  if (message.op === "arm" && Number.isFinite(message.delayMs)) {
    const previous = timers.get(message.id);
    if (previous !== undefined) clearTimeout(previous);
    timers.set(
      message.id,
      setTimeout(() => {
        timers.delete(message.id);
        self.postMessage({ op: "fire", id: message.id });
      }, Math.max(0, message.delayMs)),
    );
  } else if (message.op === "cancel") {
    const handle = timers.get(message.id);
    if (handle !== undefined) {
      clearTimeout(handle);
      timers.delete(message.id);
    }
  }
};
`;

/** The surface of a dedicated Worker the clock uses. */
export interface CoverTimerWorkerPort {
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessageerror: ((event: unknown) => void) | null;
  postMessage(message: CoverTimerRequest): void;
  terminate(): void;
}

/** Where the clock reads time and sets page timers, and how it makes a worker. */
export interface CoverTimerEnvironment {
  readonly now: () => number;
  readonly setTimeout: (callback: () => void, delayMs: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
  /** Absent, or throwing, means no worker: page timers are used. */
  readonly createWorker?: () => CoverTimerWorkerPort;
}

/** A CoverClock driven by the timer worker while it lives. */
export interface CoverTimerClock extends CoverClock {
  /** What drives wake-ups now. */
  readonly source: "worker" | "page";
  /** Terminate the worker and drop every pending wake-up. */
  destroy(): void;
}

/**
 * How long a wake-up may be overdue before the worker is taken to have stopped
 * answering (terminated by the browser, wedged). Far beyond any on-time
 * delivery, so only a worker that is really gone trips it; the backstop that
 * measures it is a page timer, which a hidden page may run up to a minute late.
 * Constant to move to src/utils/constants.ts.
 */
const COVER_TIMER_WORKER_STALL_MS = 5_000;
/** The largest delay a platform timer honours (2^31 - 1 ms). */
const MAX_TIMER_DELAY_MS = 0x7fffffff;

const isCoverTimerFire = (data: unknown): data is CoverTimerFire =>
  data !== null &&
  typeof data === "object" &&
  (data as { op?: unknown }).op === "fire" &&
  Number.isSafeInteger((data as { id?: unknown }).id);

let coverTimerWorkerUrl: string | undefined;

/** The browser: page timers on the global, a worker where one can exist. */
export const browserCoverTimerEnvironment = (): CoverTimerEnvironment => {
  const canCreateWorker =
    typeof window !== "undefined" &&
    typeof Worker === "function" &&
    typeof Blob === "function" &&
    typeof URL !== "undefined" &&
    typeof URL.createObjectURL === "function";
  return {
    now: () => Date.now(),
    setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimeout: (handle) =>
      clearTimeout(handle as Parameters<typeof clearTimeout>[0]),
    createWorker: canCreateWorker
      ? () => {
          // One Blob URL per page, never revoked, like the database worker's.
          coverTimerWorkerUrl ??= URL.createObjectURL(
            new Blob([COVER_TIMER_WORKER_SOURCE], {
              type: "application/javascript",
            }),
          );
          return new Worker(
            coverTimerWorkerUrl,
          ) as unknown as CoverTimerWorkerPort;
        }
      : undefined,
  };
};

interface PendingWakeUp {
  readonly callback: () => void;
  /** Page-clock deadline, so a fallback can re-arm what is left of it. */
  readonly deadline: number;
  pageTimer?: unknown;
  backstop?: unknown;
}

class WorkerCoverClock implements CoverTimerClock {
  readonly #env: CoverTimerEnvironment;
  readonly #pending = new Map<number, PendingWakeUp>();
  #worker: CoverTimerWorkerPort | undefined;
  #nextId = 1;
  #destroyed = false;
  #loggedFallback = false;

  constructor(env: CoverTimerEnvironment) {
    this.#env = env;
    if (!env.createWorker) {
      this.#logFallback("no timer worker can be created here");
      return;
    }
    try {
      const worker = env.createWorker();
      worker.onmessage = (event) => {
        if (this.#worker !== worker || !isCoverTimerFire(event.data)) return;
        this.#run(event.data.id);
      };
      worker.onerror = () => {
        if (this.#worker === worker) this.#fallBack("the timer worker failed");
      };
      worker.onmessageerror = () => {
        if (this.#worker === worker) this.#fallBack("the timer worker failed");
      };
      this.#worker = worker;
    } catch {
      this.#logFallback("the timer worker could not be created");
    }
  }

  get source(): "worker" | "page" {
    return this.#worker ? "worker" : "page";
  }

  now(): number {
    return this.#env.now();
  }

  setTimeout(callback: () => void, delayMs: number): number {
    const id = this.#nextId++;
    if (this.#destroyed) return id;
    const wakeUp: PendingWakeUp = {
      callback,
      deadline: this.#env.now() + Math.max(0, delayMs),
    };
    this.#pending.set(id, wakeUp);
    const worker = this.#worker;
    if (worker) {
      this.#armBackstop(id, wakeUp);
      try {
        worker.postMessage({ op: "arm", id, delayMs });
      } catch {
        this.#fallBack("the timer worker could not be reached");
      }
    } else {
      this.#armPageTimer(id, wakeUp);
    }
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle !== "number") return;
    const wakeUp = this.#pending.get(handle);
    if (!wakeUp) return;
    this.#pending.delete(handle);
    this.#clearPageTimers(wakeUp);
    try {
      this.#worker?.postMessage({ op: "cancel", id: handle });
    } catch {
      // A worker that cannot be reached holds nothing the page will run.
    }
  }

  destroy(): void {
    this.#destroyed = true;
    const worker = this.#worker;
    this.#worker = undefined;
    for (const wakeUp of this.#pending.values()) this.#clearPageTimers(wakeUp);
    this.#pending.clear();
    worker?.terminate();
  }

  #run(id: number): void {
    const wakeUp = this.#pending.get(id);
    if (!wakeUp) return;
    this.#pending.delete(id);
    this.#clearPageTimers(wakeUp);
    wakeUp.callback();
  }

  /**
   * A page timer that notices a worker which stopped answering. It only trips
   * once the wake-up is STALL_MS overdue on the page clock; a backstop that
   * fires early (a delay past the platform's timer range) re-arms instead.
   */
  #armBackstop(id: number, wakeUp: PendingWakeUp): void {
    const trippedAt = wakeUp.deadline + COVER_TIMER_WORKER_STALL_MS;
    wakeUp.backstop = this.#env.setTimeout(
      () => {
        wakeUp.backstop = undefined;
        if (this.#pending.get(id) !== wakeUp || !this.#worker) return;
        if (this.#env.now() < trippedAt) this.#armBackstop(id, wakeUp);
        else this.#fallBack("the timer worker stopped answering");
      },
      Math.min(MAX_TIMER_DELAY_MS, Math.max(0, trippedAt - this.#env.now())),
    );
  }

  #armPageTimer(id: number, wakeUp: PendingWakeUp): void {
    // The scheduler re-arms a wake-up that arrives before its deadline, so a
    // delay clipped to the platform's range is safe here.
    wakeUp.pageTimer = this.#env.setTimeout(
      () => this.#run(id),
      Math.min(
        MAX_TIMER_DELAY_MS,
        Math.max(0, wakeUp.deadline - this.#env.now()),
      ),
    );
  }

  #clearPageTimers(wakeUp: PendingWakeUp): void {
    if (wakeUp.pageTimer !== undefined)
      this.#env.clearTimeout(wakeUp.pageTimer);
    if (wakeUp.backstop !== undefined) this.#env.clearTimeout(wakeUp.backstop);
    wakeUp.pageTimer = undefined;
    wakeUp.backstop = undefined;
  }

  /** Drop the worker for page timers; every pending wake-up moves over. */
  #fallBack(reason: string): void {
    const worker = this.#worker;
    if (!worker || this.#destroyed) return;
    this.#worker = undefined;
    try {
      worker.terminate();
    } catch {
      // Already gone.
    }
    this.#logFallback(reason);
    for (const [id, wakeUp] of this.#pending) {
      this.#clearPageTimers(wakeUp);
      this.#armPageTimer(id, wakeUp);
    }
  }

  #logFallback(reason: string): void {
    if (this.#loggedFallback) return;
    this.#loggedFallback = true;
    debugLog(
      `p2party: scheduled cover is on page timers (${reason}); a hidden page's timers may be throttled, so its cycles can degrade`,
    );
  }
}

/**
 * A CoverClock whose wake-ups come from a dedicated timer worker, falling back
 * to page timers where none can run. One per CoverRuntime; destroy it with the
 * runtime.
 */
export const createCoverTimerClock = (
  env: CoverTimerEnvironment = browserCoverTimerEnvironment(),
): CoverTimerClock => new WorkerCoverClock(env);
