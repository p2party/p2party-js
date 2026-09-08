/**
 * Bounded-backoff reconnect for the signaling WebSocket.
 *
 * Owns no browser globals: the caller injects the timer scheduler, the
 * "is a reconnect wanted right now" predicate and the attempt starter, so this
 * is exactly testable and inert outside a browser.
 *
 * Lifecycle: `arm()` when a socket reaches `open` (a close before that belongs
 * to the caller of connect(), which surfaces the error itself). `succeeded()`
 * when the socket proves useful — the server pings every 10 s from its own
 * connection handler, so the first heartbeat is the earliest honest signal
 * that this socket is worth counting as a fresh start. `cancel()` on a
 * deliberate disconnect. `schedule()` on every close the SDK did not initiate,
 * plus the heartbeat watchdog's own close, which detects but does not repair.
 */

export type SignalingReconnectReason =
  "socket-closed" | "socket-error" | "heartbeat-lost";

export interface SignalingReconnectScheduler<Handle> {
  readonly setTimeout: (callback: () => void, delayMs: number) => Handle;
  readonly clearTimeout: (handle: Handle) => void;
}

export interface SignalingReconnectControllerOptions<Handle> {
  readonly delaysMs: readonly number[];
  readonly schedule: SignalingReconnectScheduler<Handle>;
  /**
   * Whether a reconnect is wanted at this instant: some room still has
   * signaling active, a server URL is known, and no attempt is already in
   * flight. Re-read when the timer fires, not only when it is armed.
   */
  readonly shouldReconnect: () => boolean;
  readonly reconnect: (attempt: number) => void;
}

export interface SignalingReconnectController {
  /** A socket reached `open`: later unsolicited closes are worth retrying. */
  arm(): void;
  /** Schedule the next attempt. False when disarmed, pending, or unwanted. */
  schedule(reason: SignalingReconnectReason): boolean;
  /** The socket proved useful (a server heartbeat arrived): reset the ladder. */
  succeeded(): void;
  /** The app disconnected on purpose: cancel and disarm. */
  cancel(): void;
  readonly attempts: number;
  readonly pending: boolean;
}

export const createSignalingReconnectController = <Handle>(
  options: SignalingReconnectControllerOptions<Handle>,
): SignalingReconnectController => {
  const { delaysMs, schedule, shouldReconnect, reconnect } = options;
  if (delaysMs.length === 0)
    throw new Error("Signaling reconnect ladder must not be empty");
  for (const delayMs of delaysMs)
    if (!Number.isFinite(delayMs) || delayMs <= 0)
      throw new Error("Signaling reconnect delay must be a positive duration");

  let armed = false;
  let attempts = 0;
  let timer: Handle | undefined;

  const clear = (): void => {
    if (timer === undefined) return;
    schedule.clearTimeout(timer);
    timer = undefined;
  };

  return {
    arm: (): void => {
      armed = true;
    },

    schedule: (_reason: SignalingReconnectReason): boolean => {
      if (!armed || timer !== undefined) return false;
      if (!shouldReconnect()) {
        // Nothing wants a socket any more (every room left, or the app is
        // already establishing one). Disarm rather than poll: the next
        // successful open re-arms.
        armed = false;
        attempts = 0;
        return false;
      }
      const delayMs = delaysMs[Math.min(attempts, delaysMs.length - 1)];
      attempts += 1;
      const attempt = attempts;
      timer = schedule.setTimeout(() => {
        timer = undefined;
        if (!armed || !shouldReconnect()) return;
        reconnect(attempt);
      }, delayMs);
      return true;
    },

    succeeded: (): void => {
      clear();
      attempts = 0;
    },

    cancel: (): void => {
      clear();
      attempts = 0;
      armed = false;
    },

    get attempts(): number {
      return attempts;
    },

    get pending(): boolean {
      return timer !== undefined;
    },
  };
};
