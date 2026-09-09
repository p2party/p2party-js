/**
 * Wall-clock watchdog over the signaling server's heartbeats.
 *
 * A WebSocket that the platform silently half-opened (page frozen with the
 * radio off, NAT binding dropped) fires no `close` event until the TCP stack
 * notices, which can take minutes. Meanwhile the server, which pings on a
 * fixed interval, has already closed its end. This watchdog owns no browser
 * globals: the caller injects the clock, the interval scheduler and the wake
 * event source, so it is exactly testable and inert outside a browser.
 *
 * `check()` runs on the interval and immediately on every wake event
 * (`visibilitychange` while visible, `pageshow`, `online`, `focus`), because
 * timers are throttled or suspended while a page is hidden and the first
 * useful moment to notice a dead socket is the moment the page wakes up.
 */

export type SignalingWakeEventName =
  "visibilitychange" | "pageshow" | "online" | "focus";

export interface SignalingHeartbeatWatchdogScheduler<Handle> {
  readonly setInterval: (callback: () => void, intervalMs: number) => Handle;
  readonly clearInterval: (handle: Handle) => void;
}

export interface SignalingHeartbeatWatchdogEnv {
  readonly addListener: (
    name: SignalingWakeEventName,
    listener: () => void,
  ) => void;
  readonly removeListener: (
    name: SignalingWakeEventName,
    listener: () => void,
  ) => void;
  /** Consulted on `visibilitychange`; a page going hidden is not a wake. */
  readonly isVisible: () => boolean;
}

export interface SignalingHeartbeatWatchdogOptions<Handle> {
  /** Wall clock in milliseconds; must keep advancing while the page sleeps. */
  readonly now: () => number;
  readonly timeoutMs: number;
  readonly checkEveryMs: number;
  readonly schedule: SignalingHeartbeatWatchdogScheduler<Handle>;
  readonly env?: SignalingHeartbeatWatchdogEnv;
  /** Invoked at most once; the watchdog has already stopped itself. */
  readonly onDead: () => void;
}

export interface SignalingHeartbeatWatchdog {
  /** Record that a server heartbeat was just answered. */
  beat(): void;
  /** Declare the socket dead if the heartbeat window has elapsed. */
  check(): void;
  /** Release the interval and wake listeners; idempotent and terminal. */
  stop(): void;
}

const assertPositiveDuration = (value: number, label: string): void => {
  if (!Number.isFinite(value) || value <= 0)
    throw new Error(`Signaling heartbeat ${label} must be a positive duration`);
};

export const createSignalingHeartbeatWatchdog = <Handle>(
  options: SignalingHeartbeatWatchdogOptions<Handle>,
): SignalingHeartbeatWatchdog => {
  const { now, timeoutMs, checkEveryMs, schedule, env, onDead } = options;
  assertPositiveDuration(timeoutMs, "timeout");
  assertPositiveDuration(checkEveryMs, "check interval");

  let lastHeartbeatAt = now();
  let stopped = false;
  let interval: Handle | null = null;

  const stop = (): void => {
    if (stopped) return;
    stopped = true;
    if (interval !== null) {
      schedule.clearInterval(interval);
      interval = null;
    }
    for (const [name, listener] of wakeListeners)
      env?.removeListener(name, listener);
  };

  const check = (): void => {
    if (stopped) return;
    if (now() - lastHeartbeatAt <= timeoutMs) return;
    // Stop first so a reentrant beat/check from onDead is inert and the
    // interval cannot fire again while the socket is being torn down.
    stop();
    onDead();
  };

  const beat = (): void => {
    if (stopped) return;
    lastHeartbeatAt = now();
  };

  const onWake = (): void => check();
  const onVisibilityChange = (): void => {
    if (env?.isVisible()) check();
  };
  const wakeListeners: ReadonlyArray<
    readonly [SignalingWakeEventName, () => void]
  > = env
    ? [
        ["visibilitychange", onVisibilityChange],
        ["pageshow", onWake],
        ["online", onWake],
        ["focus", onWake],
      ]
    : [];
  for (const [name, listener] of wakeListeners)
    env?.addListener(name, listener);
  interval = schedule.setInterval(check, checkEveryMs);

  return { beat, check, stop };
};
