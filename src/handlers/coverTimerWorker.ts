import { debugLog } from "../utils/debug";
import {
  COVER_TIMER_WORKER_MAX_RESTARTS,
  COVER_TIMER_WORKER_PING_TIMEOUT_MS,
  COVER_TIMER_WORKER_RESTART_BACKOFF_MS,
  COVER_TIMER_WORKER_STALL_MS,
  MAX_TIMER_DELAY_MS,
} from "../utils/constants";

import type { CoverClock, CoverTimerKind } from "./coverScheduler";

// ── scheduled-cover wake-ups from a shared timer worker ──────────────────────
//
// A hidden page's timers are throttled: Chromium aligns them to about one
// wake-up per second, and after five minutes hidden to one per minute. A cover
// slot that fires past its drift tolerance degrades its cycle, so on page
// timers a hidden tab's cover collapses and tab visibility becomes readable off
// the wire. The scheduler's wake-ups therefore come from a dedicated worker:
// the worker owns the timers and posts a message when one is due, and the page
// runs the slot (and its send) in the message handler.
//
// Measured in Chrome for Testing 159 on macOS (docs/e2e/cover-timers/), a
// hidden page ran those wake-ups up to 143 ms late, median 50 ms. The harness
// timestamps only the page side, so it cannot tell a late worker timer from a
// late page task; that the worker's own timers are not throttled is an
// inference from Chromium's documented behaviour, not a measurement. The send
// still happens on the page, so cell timing on a hidden page shifts by tens of
// milliseconds against the slot grid even when no cycle degrades.
//
// Lateness is judged on ONE clock, the page's `Date.now()`, read when the page
// runs the callback: the scheduler compares that against the slot's deadline.
// The worker only decides when to wake the page. If the worker ticks on time
// but the page's event loop is busy, the slot is late, exactly as a late page
// timer would be.
//
// One worker serves every scheduled-cover edge on the page (a CoverTimerHost
// per timer environment, the browser's being one). It is created on first use
// and terminated when the last clock using it is destroyed. What crosses to it
// is a delay and an opaque integer handle drawn from one page-wide counter,
// nothing else: no key material, no peer or room identifier, no plaintext, and
// nothing that groups the handles of one edge or one room.
//
// Lateness on the page's clock is not proof the worker is dead: a freeze, a
// system sleep or a long task makes every wake-up overdue too. So a wake-up
// STALL_MS overdue only makes the host ask the worker to answer a ping. A
// worker that answers is kept. One that raises its error event, cannot be
// reached, or does not answer within PING_TIMEOUT_MS is dropped: every pending
// wake-up moves to page timers, and a new worker is created at a later cycle
// boundary, after a backoff, at most MAX_RESTARTS times. Only then does the
// page stay on page timers for good.
//
// Every clock reports, once, when it is on page timers for good (no worker can
// be created, or the restarts are spent): through console.warn on a browser
// page, through the debug log elsewhere (tests, non-browser runtimes, where a
// hidden page does not exist). The message names no peer, room or key.
// `getCoverTimerSource()` reads what drives the page's schedules now.

/** One request from the page to the timer worker. */
export type CoverTimerRequest =
  | { readonly op: "arm"; readonly id: number; readonly delayMs: number }
  | { readonly op: "cancel"; readonly id: number }
  | { readonly op: "ping"; readonly id: number };

/** What the worker posts back: a handle is due, or a ping's answer. */
export interface CoverTimerReply {
  readonly op: "fire" | "pong";
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
  } else if (message.op === "ping") {
    self.postMessage({ op: "pong", id: message.id });
  }
};
`;

/** The surface of a dedicated Worker the host uses. */
export interface CoverTimerWorkerPort {
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessageerror: ((event: unknown) => void) | null;
  postMessage(message: CoverTimerRequest): void;
  terminate(): void;
}

/** Where a host reads time and sets page timers, and how it makes a worker. */
export interface CoverTimerEnvironment {
  readonly now: () => number;
  readonly setTimeout: (callback: () => void, delayMs: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
  /** Absent means no worker can exist here: page timers for good. */
  readonly createWorker?: () => CoverTimerWorkerPort;
  /**
   * True on a browser page, where being on page timers for good is reported
   * with console.warn. Elsewhere it goes to the debug log only.
   */
  readonly browserPage: boolean;
}

/** A CoverClock served by the page's shared timer host. */
export interface CoverTimerClock extends CoverClock {
  /** What drives this clock's wake-ups now. */
  readonly source: "worker" | "page";
  /** Cancel this clock's wake-ups and release the shared worker. */
  destroy(): void;
}

const isCoverTimerReply = (data: unknown): data is CoverTimerReply =>
  data !== null &&
  typeof data === "object" &&
  ((data as { op?: unknown }).op === "fire" ||
    (data as { op?: unknown }).op === "pong") &&
  Number.isSafeInteger((data as { id?: unknown }).id);

const isBoundary = (kind: CoverTimerKind | undefined): boolean =>
  kind === "open-boundary" || kind === "cycle-boundary";

let browserEnvironment: CoverTimerEnvironment | undefined;
let coverTimerWorkerUrl: string | undefined;

/** The browser's environment: one object per page, so one host per page. */
export const browserCoverTimerEnvironment = (): CoverTimerEnvironment => {
  if (browserEnvironment) return browserEnvironment;
  const browserPage = typeof window !== "undefined";
  const canCreateWorker =
    browserPage &&
    typeof Worker === "function" &&
    typeof Blob === "function" &&
    typeof URL !== "undefined" &&
    typeof URL.createObjectURL === "function";
  browserEnvironment = {
    now: () => Date.now(),
    setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimeout: (handle) =>
      clearTimeout(handle as Parameters<typeof clearTimeout>[0]),
    browserPage,
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
  return browserEnvironment;
};

interface WakeUp {
  readonly clock: HostedCoverClock;
  readonly callback: () => void;
  /** Page-clock deadline, so a fallback can re-arm what is left of it. */
  readonly deadline: number;
  /** When an unanswered wake-up makes the host probe the worker. */
  stallAt: number;
  onWorker: boolean;
  pageTimer?: unknown;
  backstop?: unknown;
}

/** The page's one timer worker, shared by every scheduled-cover clock. */
class CoverTimerHost {
  readonly env: CoverTimerEnvironment;
  readonly #clocks = new Set<HostedCoverClock>();
  readonly #wakeUps = new Map<number, WakeUp>();
  #worker: CoverTimerWorkerPort | undefined;
  #nextId = 1;
  #restarts = 0;
  #restartNotBefore = 0;
  #permanent: string | undefined;
  #ping: { readonly id: number; readonly timer: unknown } | undefined;

  constructor(env: CoverTimerEnvironment) {
    this.env = env;
  }

  get source(): "worker" | "page" {
    return this.#worker ? "worker" : "page";
  }

  get clockCount(): number {
    return this.#clocks.size;
  }

  acquire(clock: HostedCoverClock): void {
    this.#clocks.add(clock);
    if (this.#clocks.size === 1) {
      // First use (again): a fresh start, with the full restart budget.
      this.#restarts = 0;
      this.#restartNotBefore = 0;
      this.#permanent = undefined;
      this.#start();
    }
    if (this.#permanent) clock.reportPageTimersForGood(this.#permanent);
  }

  release(clock: HostedCoverClock): void {
    if (!this.#clocks.delete(clock)) return;
    for (const [id, wakeUp] of this.#wakeUps)
      if (wakeUp.clock === clock) this.cancel(id);
    if (this.#clocks.size > 0) return;
    this.#clearPing();
    const worker = this.#worker;
    this.#worker = undefined;
    try {
      worker?.terminate();
    } catch {
      // Already gone.
    }
  }

  arm(
    clock: HostedCoverClock,
    callback: () => void,
    delayMs: number,
    kind: CoverTimerKind | undefined,
  ): number {
    // A replacement worker comes up at a cycle boundary, so a cycle runs on
    // one source from its open to its close.
    if (
      !this.#worker &&
      !this.#permanent &&
      isBoundary(kind) &&
      this.env.now() >= this.#restartNotBefore
    )
      this.#start();
    const id = this.#nextId++;
    const deadline = this.env.now() + Math.max(0, delayMs);
    const wakeUp: WakeUp = {
      clock,
      callback,
      deadline,
      stallAt: deadline + COVER_TIMER_WORKER_STALL_MS,
      onWorker: false,
    };
    this.#wakeUps.set(id, wakeUp);
    const worker = this.#worker;
    if (worker) {
      wakeUp.onWorker = true;
      this.#armBackstop(id, wakeUp);
      try {
        worker.postMessage({ op: "arm", id, delayMs });
      } catch {
        this.#lose("the timer worker could not be reached");
      }
    } else {
      this.#armPageTimer(id, wakeUp);
    }
    return id;
  }

  cancel(id: number): void {
    const wakeUp = this.#wakeUps.get(id);
    if (!wakeUp) return;
    this.#wakeUps.delete(id);
    this.#clearPageTimers(wakeUp);
    if (!wakeUp.onWorker) return;
    try {
      this.#worker?.postMessage({ op: "cancel", id });
    } catch {
      // A worker that cannot be reached holds nothing the page will run.
    }
  }

  #start(): void {
    if (!this.env.createWorker) {
      this.#permanent = "no timer worker can be created here";
      for (const clock of this.#clocks)
        clock.reportPageTimersForGood(this.#permanent);
      return;
    }
    let worker: CoverTimerWorkerPort;
    try {
      worker = this.env.createWorker();
    } catch {
      this.#lose("the timer worker could not be created", false);
      return;
    }
    worker.onmessage = (event) => {
      if (this.#worker === worker) this.#onReply(event.data);
    };
    worker.onerror = () => {
      if (this.#worker === worker) this.#lose("the timer worker failed");
    };
    worker.onmessageerror = () => {
      if (this.#worker === worker) this.#lose("the timer worker failed");
    };
    this.#worker = worker;
  }

  #onReply(data: unknown): void {
    if (!isCoverTimerReply(data)) return;
    if (data.op === "pong") {
      if (this.#ping?.id !== data.id) return;
      this.#clearPing();
      // The worker is alive: the overdue wake-ups wait for it again.
      const now = this.env.now();
      for (const [id, wakeUp] of this.#wakeUps)
        if (wakeUp.onWorker && wakeUp.backstop === undefined) {
          wakeUp.stallAt = now + COVER_TIMER_WORKER_STALL_MS;
          this.#armBackstop(id, wakeUp);
        }
      return;
    }
    const wakeUp = this.#wakeUps.get(data.id);
    // A tick for a cancelled wake-up, or a destroyed clock's, is dropped.
    if (!wakeUp) return;
    this.#wakeUps.delete(data.id);
    this.#clearPageTimers(wakeUp);
    wakeUp.callback();
  }

  /**
   * A page timer that notices a wake-up the worker has not delivered by its
   * stall bound. It does not drop the worker: it asks it to answer. A
   * backstop that fires early (a delay past the platform's range) re-arms.
   */
  #armBackstop(id: number, wakeUp: WakeUp): void {
    wakeUp.backstop = this.env.setTimeout(
      () => {
        wakeUp.backstop = undefined;
        if (this.#wakeUps.get(id) !== wakeUp || !this.#worker) return;
        if (this.env.now() < wakeUp.stallAt) this.#armBackstop(id, wakeUp);
        else this.#probe();
      },
      Math.min(
        MAX_TIMER_DELAY_MS,
        Math.max(0, wakeUp.stallAt - this.env.now()),
      ),
    );
  }

  #probe(): void {
    const worker = this.#worker;
    if (!worker || this.#ping) return;
    const id = this.#nextId++;
    this.#ping = {
      id,
      timer: this.env.setTimeout(() => {
        if (this.#ping?.id === id)
          this.#lose("the timer worker did not answer");
      }, COVER_TIMER_WORKER_PING_TIMEOUT_MS),
    };
    try {
      worker.postMessage({ op: "ping", id });
    } catch {
      this.#lose("the timer worker could not be reached");
    }
  }

  #clearPing(): void {
    if (this.#ping) this.env.clearTimeout(this.#ping.timer);
    this.#ping = undefined;
  }

  /**
   * The worker is gone (or could not be created): every pending wake-up moves
   * to page timers now, and a replacement is attempted at a later cycle
   * boundary after a backoff, until the restarts are spent.
   */
  #lose(reason: string, terminate = true): void {
    const worker = this.#worker;
    this.#worker = undefined;
    this.#clearPing();
    if (terminate && worker)
      try {
        worker.terminate();
      } catch {
        // Already gone.
      }
    for (const [id, wakeUp] of this.#wakeUps)
      if (wakeUp.onWorker) {
        wakeUp.onWorker = false;
        this.#clearPageTimers(wakeUp);
        this.#armPageTimer(id, wakeUp);
      }
    this.#restarts += 1;
    if (this.#restarts > COVER_TIMER_WORKER_MAX_RESTARTS) {
      this.#permanent = `${reason}, and ${COVER_TIMER_WORKER_MAX_RESTARTS} replacements failed`;
      for (const clock of this.#clocks)
        clock.reportPageTimersForGood(this.#permanent);
      return;
    }
    this.#restartNotBefore =
      this.env.now() +
      COVER_TIMER_WORKER_RESTART_BACKOFF_MS * 2 ** (this.#restarts - 1);
    debugLog(
      `p2party: scheduled cover is on page timers until a new timer worker starts at a later cycle boundary (${reason})`,
    );
  }

  #armPageTimer(id: number, wakeUp: WakeUp): void {
    // The scheduler re-arms a wake-up that arrives before its deadline, so a
    // delay clipped to the platform's range is safe here.
    wakeUp.pageTimer = this.env.setTimeout(
      () => {
        if (this.#wakeUps.get(id) !== wakeUp) return;
        this.#wakeUps.delete(id);
        this.#clearPageTimers(wakeUp);
        wakeUp.callback();
      },
      Math.min(
        MAX_TIMER_DELAY_MS,
        Math.max(0, wakeUp.deadline - this.env.now()),
      ),
    );
  }

  #clearPageTimers(wakeUp: WakeUp): void {
    if (wakeUp.pageTimer !== undefined) this.env.clearTimeout(wakeUp.pageTimer);
    if (wakeUp.backstop !== undefined) this.env.clearTimeout(wakeUp.backstop);
    wakeUp.pageTimer = undefined;
    wakeUp.backstop = undefined;
  }

  /** Wake-ups still pending, for every clock (tests and diagnostics). */
  get pendingWakeUps(): number {
    return this.#wakeUps.size;
  }
}

const hosts = new WeakMap<CoverTimerEnvironment, CoverTimerHost>();

const hostFor = (env: CoverTimerEnvironment): CoverTimerHost => {
  let host = hosts.get(env);
  if (!host) {
    host = new CoverTimerHost(env);
    hosts.set(env, host);
  }
  return host;
};

class HostedCoverClock implements CoverTimerClock {
  readonly #host: CoverTimerHost;
  readonly #ids = new Set<number>();
  #destroyed = false;
  #reported = false;

  constructor(host: CoverTimerHost) {
    this.#host = host;
    host.acquire(this);
  }

  get source(): "worker" | "page" {
    return this.#host.source;
  }

  now(): number {
    return this.#host.env.now();
  }

  setTimeout(
    callback: () => void,
    delayMs: number,
    kind?: CoverTimerKind,
  ): number {
    if (this.#destroyed) return 0;
    const id = this.#host.arm(
      this,
      () => {
        this.#ids.delete(id);
        callback();
      },
      delayMs,
      kind,
    );
    this.#ids.add(id);
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle !== "number" || !this.#ids.delete(handle)) return;
    this.#host.cancel(handle);
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    for (const id of this.#ids) this.#host.cancel(id);
    this.#ids.clear();
    this.#host.release(this);
  }

  /** Once per clock: this schedule is on page timers for good. */
  reportPageTimersForGood(reason: string): void {
    if (this.#reported || this.#destroyed) return;
    this.#reported = true;
    const message = `p2party: scheduled cover is on page timers for good (${reason}); a hidden page's timers are throttled, so its cover cycles can degrade while it is hidden`;
    if (this.#host.env.browserPage) console.warn(message);
    else debugLog(message);
  }
}

/**
 * A CoverClock whose wake-ups come from the page's shared timer worker,
 * falling back to page timers where none can run. One per CoverRuntime;
 * destroy it with the runtime.
 */
export const createCoverTimerClock = (
  env: CoverTimerEnvironment = browserCoverTimerEnvironment(),
): CoverTimerClock => new HostedCoverClock(hostFor(env));

/**
 * What drives this page's scheduled-cover wake-ups now: its timer worker,
 * page timers (no worker can run, or it is being replaced), or nothing (no
 * scheduled-cover edge is open).
 */
export const getCoverTimerSource = (
  env: CoverTimerEnvironment = browserCoverTimerEnvironment(),
): "worker" | "page" | "none" => {
  const host = hosts.get(env);
  if (!host || host.clockCount === 0) return "none";
  return host.source;
};

/** Wake-ups the environment's host still holds (tests). */
export const pendingCoverTimerWakeUps = (env: CoverTimerEnvironment): number =>
  hosts.get(env)?.pendingWakeUps ?? 0;
