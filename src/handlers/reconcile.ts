import {
  COMPLETION_WAIT_FALLBACK_MS,
  MAX_TIMER_DELAY_MS,
  MIN_RECEIVER_VERIFY_BYTES_PER_SECOND,
  REPORTED_COMPLETION_CHECK_MS,
} from "../utils/constants";

// Selective retransmit / resume state — in-memory, per
// (roomId, peerId, random transferId). Content hashes are not identities:
// concurrent sends of the same bytes must never share acknowledgements.
//
// The receipts ARE the have-set: the sender resolves each received leaf-hash
// receipt to a chunk index (handleReadReceipt → getDBNewChunk → chunkIndex) and
// records it here. reconcile() then resends ONLY the un-acked real chunks (read
// real-vs-decoy from each chunk's metadata; decoys are cover and never resent).
// The same operation serves live retransmit (timeout trigger) and resume
// (reconnect trigger, where the receiver re-emits its receipts first).
//
// This live view is rebuilt from the durable outbox or verified receipts.
// Chunk data and per-recipient outcomes are persisted before this view advances.
type Edge = { acked: Set<number>; complete: boolean; cancelled: boolean };

const edges = new Map<string, Edge>();
const key = (roomId: string, peerId: string, transferId: string): string =>
  `${roomId}\u0000${peerId}\u0000${transferId}`;

const edge = (roomId: string, peerId: string, transferId: string): Edge => {
  const k = key(roomId, peerId, transferId);
  let e = edges.get(k);
  if (!e) {
    e = { acked: new Set<number>(), complete: false, cancelled: false };
    edges.set(k, e);
  }
  return e;
};

// Waiters on one edge's state. Every change below notifies them, so a wait
// re-checks when what it waits for changed instead of on a polling timer.
const progressListeners = new Map<string, Set<() => void>>();

const notifyProgress = (k: string): void => {
  const listeners = progressListeners.get(k);
  if (!listeners) return;
  for (const listener of [...listeners]) {
    try {
      listener();
    } catch (error) {
      console.error(error);
    }
  }
};

/**
 * Call `listener` after every change to this edge's transfer state: a newly
 * acknowledged chunk, completion, cancellation, or a clear. It is a wake-up,
 * not a value: the listener reads the state it cares about. Returns the
 * unsubscribe, which a wait must call when it settles.
 */
export const onTransferProgress = (
  roomId: string,
  peerId: string,
  transferId: string,
  listener: () => void,
): (() => void) => {
  const k = key(roomId, peerId, transferId);
  let listeners = progressListeners.get(k);
  if (!listeners) {
    listeners = new Set();
    progressListeners.set(k, listeners);
  }
  listeners.add(listener);
  return () => {
    const current = progressListeners.get(k);
    if (!current) return;
    current.delete(listener);
    if (current.size === 0) progressListeners.delete(k);
  };
};

// Wake-ups for frames that change no state but show the receiver is still at
// work on a transfer: a receipt it re-sends while it verifies the whole file.
const activityListeners = new Map<string, Set<() => void>>();

/**
 * Record that a frame for this transfer arrived from this peer. Called where
 * an authenticated receipt is first attributed to its transfer, before it is
 * checked against the have-set (a repeat changes nothing there).
 */
export const noteTransferActivity = (
  roomId: string,
  peerId: string,
  transferId: string,
): void => {
  const listeners = activityListeners.get(key(roomId, peerId, transferId));
  if (!listeners) return;
  for (const listener of [...listeners]) {
    try {
      listener();
    } catch (error) {
      console.error(error);
    }
  }
};

/** Call `listener` on every noteTransferActivity for this edge's transfer. */
export const onTransferActivity = (
  roomId: string,
  peerId: string,
  transferId: string,
  listener: () => void,
): (() => void) => {
  const k = key(roomId, peerId, transferId);
  let listeners = activityListeners.get(k);
  if (!listeners) {
    listeners = new Set();
    activityListeners.set(k, listeners);
  }
  listeners.add(listener);
  return () => {
    const current = activityListeners.get(k);
    if (!current) return;
    current.delete(listener);
    if (current.size === 0) activityListeners.delete(k);
  };
};

export const markChunkAcked = (
  roomId: string,
  peerId: string,
  transferId: string,
  chunkIndex: number,
): boolean => {
  const state = edge(roomId, peerId, transferId);
  if (state.cancelled) return false;
  const acked = state.acked;
  const previousSize = acked.size;
  acked.add(chunkIndex);
  if (acked.size === previousSize) return false;
  notifyProgress(key(roomId, peerId, transferId));
  return true;
};

// A defensive copy — the caller (sendChunks reconcile filter) must not mutate
// the live set, which keeps growing as more receipts arrive.
export const getAckedChunks = (
  roomId: string,
  peerId: string,
  transferId: string,
): Set<number> => new Set(edge(roomId, peerId, transferId).acked);

/** Constant-time membership without allocating one Set copy per scheduled cell. */
export const hasChunkAcked = (
  roomId: string,
  peerId: string,
  transferId: string,
  chunkIndex: number,
): boolean =>
  edges.get(key(roomId, peerId, transferId))?.acked.has(chunkIndex) ?? false;

// Live size of the acked set, polled by the sender's receipt window without
// copying the set on every tick.
export const getAckedChunkCount = (
  roomId: string,
  peerId: string,
  transferId: string,
): number => edge(roomId, peerId, transferId).acked.size;

export const markTransferComplete = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => {
  const state = edge(roomId, peerId, transferId);
  if (state.complete || state.cancelled) return false;
  state.complete = true;
  notifyProgress(key(roomId, peerId, transferId));
  return true;
};

export interface PeerTransferOutcome {
  readonly roomId: string;
  readonly peerId: string;
  readonly transferId: string;
  readonly ackedChunks: ReadonlySet<number>;
  readonly complete: boolean;
}

/** Accurate, defensive per-peer delivery state for UI/diagnostics consumers. */
export const getPeerTransferOutcome = (
  roomId: string,
  peerId: string,
  transferId: string,
): PeerTransferOutcome => {
  const state = edges.get(key(roomId, peerId, transferId));
  return {
    roomId,
    peerId,
    transferId,
    ackedChunks: new Set(state?.acked ?? []),
    complete: state?.complete ?? false,
  };
};

export const isTransferComplete = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => edges.get(key(roomId, peerId, transferId))?.complete ?? false;

/** A recipient's refusal is terminal only for this edge, never the whole send. */
export const markTransferCancelled = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => {
  const state = edge(roomId, peerId, transferId);
  if (state.cancelled || state.complete) return false;
  state.cancelled = true;
  notifyProgress(key(roomId, peerId, transferId));
  return true;
};

export const isTransferCancelled = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => edges.get(key(roomId, peerId, transferId))?.cancelled ?? false;

export interface TransferAck {
  readonly peerId: string;
  /**
   * Distinct chunks this peer has receipted so far, counting decoys: a receipt
   * is emitted per inbound frame, and the padding is what makes every frame
   * indistinguishable, so excluding it would report a fraction of a denominator
   * that includes it.
   */
  readonly ackedChunks: number;
  readonly complete: boolean;
}

/**
 * Live outbound progress for one logical send, per peer.
 *
 * The sender already knows this -- every receipt lands in the have-set above --
 * but nothing outside this module could read it, so a UI could say "sending"
 * and then nothing at all until the transfer settled. On a large file that is
 * a progress bar's worth of silence.
 *
 * Derived from the same state selective retransmit uses, so it cannot drift
 * from what the sender actually believes was delivered. Read-only and
 * defensively copied; polling it never affects the transfer.
 */
export const getTransferAcks = (
  roomId: string,
  transferId: string,
): TransferAck[] => {
  const prefix = `${roomId}\u0000`;
  const suffix = `\u0000${transferId}`;
  const acks: TransferAck[] = [];
  for (const [edgeKey, state] of edges) {
    if (!edgeKey.startsWith(prefix) || !edgeKey.endsWith(suffix)) continue;
    acks.push({
      peerId: edgeKey.slice(prefix.length, edgeKey.length - suffix.length),
      ackedChunks: state.acked.size,
      complete: state.complete,
    });
  }
  return acks;
};

export const clearTransfer = (
  roomId: string,
  peerId: string,
  transferId: string,
): void => {
  const k = key(roomId, peerId, transferId);
  edges.delete(k);
  notifyProgress(k);
};

/** The clock a transfer wait arms its timers on; injectable for tests. */
export interface TransferWaitClock {
  readonly now: () => number;
  readonly setTimeout: (callback: () => void, ms: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
}

export const transferWaitClock: TransferWaitClock = {
  now: () => Date.now(),
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
};

export interface CompletionWaitDependencies {
  readonly clock?: TransferWaitClock;
  /** How the wait is woken; `onTransferProgress` in production. */
  readonly subscribe?: typeof onTransferProgress;
}

/**
 * Wait up to timeoutMs for this edge's transfer to complete. Woken by the
 * final receipt (markTransferComplete), a refusal (markTransferCancelled) or
 * an abort, with a COMPLETION_WAIT_FALLBACK_MS re-check in case a wake-up is
 * lost. Resolves true only when complete and not aborted.
 *
 * It does not end early when the channel closes, as the 200 ms poll it
 * replaces did not: a final receipt already read off a closing channel is
 * still being persisted when `close` fires, and only lands in this state
 * after that.
 */
export const waitForCompletion = async (
  roomId: string,
  peerId: string,
  transferId: string,
  timeoutMs: number,
  signal?: AbortSignal,
  dependencies: CompletionWaitDependencies = {},
): Promise<boolean> => {
  const clock = dependencies.clock ?? transferWaitClock;
  const subscribe = dependencies.subscribe ?? onTransferProgress;
  const deadline = clock.now() + timeoutMs;
  const settled = (): boolean =>
    clock.now() >= deadline ||
    isTransferComplete(roomId, peerId, transferId) ||
    isTransferCancelled(roomId, peerId, transferId) ||
    signal?.aborted === true;

  if (!settled())
    await new Promise<void>((resolve) => {
      let done = false;
      let cancelTimer = (): void => undefined;
      let unsubscribe = (): void => undefined;
      const check = (): void => {
        if (done || !settled()) return;
        done = true;
        cancelTimer();
        unsubscribe();
        signal?.removeEventListener("abort", check);
        resolve();
      };
      const arm = (): void => {
        cancelTimer = armTimer(
          clock,
          onTimer,
          Math.min(COMPLETION_WAIT_FALLBACK_MS, deadline - clock.now()),
        );
      };
      const onTimer = (): void => {
        cancelTimer = () => undefined;
        check();
        if (!done) arm();
      };
      // Registered before the state is checked again, so a change between
      // the first check and the subscription cannot be missed.
      unsubscribe = subscribe(roomId, peerId, transferId, check);
      signal?.addEventListener("abort", check);
      check();
      if (!done) arm();
    });
  return !signal?.aborted && isTransferComplete(roomId, peerId, transferId);
};

/**
 * The longest a sender waits for the final receipt of a fully acknowledged
 * transfer while its receiver keeps reporting: the file at
 * MIN_RECEIVER_VERIFY_BYTES_PER_SECOND, plus the silence bound.
 */
export const reportedCompletionCapMs = (
  totalSize: number,
  silenceMs: number,
): number =>
  Math.ceil((totalSize / MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) * 1000) +
  silenceMs;

export interface ReportedCompletionOptions {
  /** End once this long has passed without any activity. */
  readonly silenceMs: number;
  /** End at the latest this long after the wait starts. */
  readonly capMs: number;
  /** Subscribe to the frames that show the receiver is still at work. */
  readonly onActivity: (wake: () => void) => () => void;
  /**
   * Subscribe to what can end the wait at once — the transfer's channel
   * closing, the edge being replaced. An event only wakes the wait: it ends
   * when `isInterrupted` holds, which is also read before the wait starts.
   */
  readonly onInterrupt?: (interrupt: () => void) => () => void;
  readonly isInterrupted?: () => boolean;
  /** While true, silence does not accrue (a suspended sender schedule). */
  readonly isHeld?: () => boolean;
  readonly signal?: AbortSignal;
  readonly clock?: TransferWaitClock;
  /** How the wait learns of completion; `onTransferProgress` in production. */
  readonly subscribe?: typeof onTransferProgress;
}

/** A timer delay a platform honours: a longer one fires at once. */
export const clampTimerDelayMs = (delayMs: number): number =>
  Math.min(MAX_TIMER_DELAY_MS, Math.max(0, delayMs));

/**
 * Run `callback` once `clock`'s timers have run for `delayMs`, however long
 * that is: a delay above MAX_TIMER_DELAY_MS is armed in clamped steps, each
 * re-armed for the remainder. The remainder is counted in the timers' own
 * time, never read off the wall clock, so a wall clock stepped backwards does
 * not hold the callback back. Returns the cancel.
 */
export const armTimer = (
  clock: TransferWaitClock,
  callback: () => void,
  delayMs: number,
): (() => void) => {
  let remainingMs = Math.max(0, delayMs);
  let handle: unknown;
  let cancelled = false;
  const step = (): void => {
    const stepMs = clampTimerDelayMs(remainingMs);
    remainingMs -= stepMs;
    handle = clock.setTimeout(() => {
      handle = undefined;
      if (cancelled) return;
      if (remainingMs > 0) step();
      else callback();
    }, stepMs);
  };
  step();
  return () => {
    cancelled = true;
    if (handle !== undefined) clock.clearTimeout(handle);
  };
};

/**
 * Wait for the final receipt of a transfer whose every chunk is acknowledged,
 * for as long as the receiver shows it is still at work.
 *
 * Each activity re-arms the silence bound. The wait ends on the final receipt
 * (true); a refusal, an abort or an interrupt, at once (false); `silenceMs`
 * without activity (false); or at the cap (false). It checks again at least
 * every REPORTED_COMPLETION_CHECK_MS, its timers armed through armTimer.
 *
 * A check is late when it runs more than REPORTED_COMPLETION_CHECK_MS after
 * its timer was due: the page ran nothing in between (it was frozen, asleep
 * or offline, or its timers are throttled). That time never counts as
 * silence: a late check restarts the silence clock, as every check does while
 * `isHeld` holds.
 *
 * The cap is fixed when the wait starts, `capMs` later on the clock, and moves
 * at most once: the first late check that finds it passed (a timer's, or a
 * receipt's) extends it to that check plus one silence bound, so a final
 * receipt queued behind the thaw can still arrive. Nothing else moves it, and
 * receipts after the cap never do.
 *
 * So on a page whose timers fire up to P after they are due, the wait ends no
 * later than one silence bound and two periods after the cap: the first check
 * at or past the cap runs within P of it and, if late, leaves one silence
 * bound, which a check sees within P of its end. With P at most
 * REPORTED_COMPLETION_CHECK_MS no check is late, and the wait ends within P of
 * the cap. On a page throttled to one wake-up every P above twice
 * REPORTED_COMPLETION_CHECK_MS (a hidden page, once a minute) every timer
 * check but the wait's first is late. That first one runs on time only within
 * twice REPORTED_COMPLETION_CHECK_MS of the wait's start, and a check a
 * receipt runs counts the receipt as activity, so with a silence bound longer
 * than that (every bound here is at least RECEIVER_SILENCE_LIMIT_MS) silence
 * never ends the wait: a receiver that goes silent there is detected only
 * through the cap, within one silence bound and two periods of it.
 */
export const waitForReportedCompletion = async (
  roomId: string,
  peerId: string,
  transferId: string,
  options: ReportedCompletionOptions,
): Promise<boolean> => {
  const clock = options.clock ?? transferWaitClock;
  const subscribe = options.subscribe ?? onTransferProgress;
  const { signal } = options;
  let capAt = clock.now() + options.capMs;
  let capExtended = false;
  let lastActivityAt = clock.now();
  let timerDueAt = Number.POSITIVE_INFINITY;
  const ended = (): boolean =>
    options.isInterrupted?.() === true ||
    isTransferComplete(roomId, peerId, transferId) ||
    isTransferCancelled(roomId, peerId, transferId) ||
    signal?.aborted === true;

  if (!ended())
    await new Promise<void>((resolve) => {
      let done = false;
      let cancelTimer = (): void => undefined;
      let unsubscribeProgress = (): void => undefined;
      let unsubscribeActivity = (): void => undefined;
      let unsubscribeInterrupt = (): void => undefined;
      const noteSuspension = (now: number): void => {
        if (now - timerDueAt > REPORTED_COMPLETION_CHECK_MS) {
          // The page ran nothing between the timer's due time and now.
          lastActivityAt = now;
          if (now >= capAt && !capExtended) {
            capExtended = true;
            capAt = now + options.silenceMs;
          }
        } else if (options.isHeld?.() === true) lastActivityAt = now;
      };
      const check = (): void => {
        if (done) return;
        const now = clock.now();
        noteSuspension(now);
        if (!ended() && now < capAt && now - lastActivityAt < options.silenceMs)
          return;
        done = true;
        cancelTimer();
        unsubscribeProgress();
        unsubscribeActivity();
        unsubscribeInterrupt();
        signal?.removeEventListener("abort", check);
        resolve();
      };
      const arm = (): void => {
        const now = clock.now();
        timerDueAt = Math.min(
          capAt,
          lastActivityAt + options.silenceMs,
          now + REPORTED_COMPLETION_CHECK_MS,
        );
        cancelTimer = armTimer(clock, onTimer, timerDueAt - now);
      };
      const onTimer = (): void => {
        cancelTimer = () => undefined;
        check();
        if (!done) arm();
      };
      const onActivity = (): void => {
        if (done) return;
        const now = clock.now();
        noteSuspension(now);
        lastActivityAt = now;
        check();
      };
      // Registered before the state is checked again.
      unsubscribeProgress = subscribe(roomId, peerId, transferId, check);
      unsubscribeActivity = options.onActivity(onActivity);
      unsubscribeInterrupt = options.onInterrupt?.(check) ?? (() => undefined);
      signal?.addEventListener("abort", check);
      check();
      if (!done) arm();
    });
  return !signal?.aborted && isTransferComplete(roomId, peerId, transferId);
};
