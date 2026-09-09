import { describe, expect, test } from "bun:test";

import {
  createSignalingHeartbeatWatchdog,
  type SignalingHeartbeatWatchdogEnv,
  type SignalingWakeEventName,
} from "../../src/utils/signalingHeartbeatWatchdog";

const TIMEOUT_MS = 25_000;
const CHECK_MS = 5_000;

interface Harness {
  readonly clock: { now: number };
  readonly intervals: Array<{ callback: () => void; ms: number }>;
  readonly cleared: number[];
  readonly listeners: Map<SignalingWakeEventName, Set<() => void>>;
  readonly visibility: { visible: boolean };
  readonly deaths: { count: number };
  readonly env: SignalingHeartbeatWatchdogEnv;
  fire(name: SignalingWakeEventName): void;
  tickInterval(): void;
}

const harness = (): Harness => {
  const clock = { now: 1_000_000 };
  const intervals: Array<{ callback: () => void; ms: number }> = [];
  const cleared: number[] = [];
  const listeners = new Map<SignalingWakeEventName, Set<() => void>>();
  const visibility = { visible: true };
  const deaths = { count: 0 };
  const env: SignalingHeartbeatWatchdogEnv = {
    addListener: (name, listener) => {
      const set = listeners.get(name) ?? new Set<() => void>();
      set.add(listener);
      listeners.set(name, set);
    },
    removeListener: (name, listener) => {
      const set = listeners.get(name);
      if (!set) return;
      set.delete(listener);
      if (set.size === 0) listeners.delete(name);
    },
    isVisible: () => visibility.visible,
  };
  return {
    clock,
    intervals,
    cleared,
    listeners,
    visibility,
    deaths,
    env,
    fire: (name) => {
      for (const listener of listeners.get(name) ?? []) listener();
    },
    tickInterval: () => {
      for (const { callback } of intervals) callback();
    },
  };
};

const build = (h: Harness, withEnv = true) =>
  createSignalingHeartbeatWatchdog({
    now: () => h.clock.now,
    timeoutMs: TIMEOUT_MS,
    checkEveryMs: CHECK_MS,
    schedule: {
      setInterval: (callback, ms) => {
        h.intervals.push({ callback, ms });
        return h.intervals.length;
      },
      clearInterval: (handle) => {
        h.cleared.push(handle);
      },
    },
    env: withEnv ? h.env : undefined,
    onDead: () => {
      h.deaths.count += 1;
    },
  });

describe("signaling heartbeat watchdog", () => {
  test("declares the socket dead exactly once when no heartbeat arrives within the timeout", () => {
    const h = harness();
    const watchdog = build(h);

    h.clock.now += TIMEOUT_MS;
    watchdog.check();
    expect(h.deaths.count).toBe(0);

    h.clock.now += 1;
    watchdog.check();
    expect(h.deaths.count).toBe(1);

    watchdog.check();
    watchdog.check();
    h.tickInterval();
    h.fire("focus");
    expect(h.deaths.count).toBe(1);
    // Death is terminal: the interval and wake listeners are released.
    expect(h.cleared).toEqual([1]);
    expect(h.listeners.size).toBe(0);
  });

  test("heartbeats inside the window keep the socket alive", () => {
    const h = harness();
    const watchdog = build(h);

    // 40 s since creation, but only 20 s since the last beat.
    h.clock.now += 20_000;
    watchdog.beat();
    h.clock.now += 20_000;
    watchdog.check();
    h.tickInterval();
    expect(h.deaths.count).toBe(0);

    // A beat resets the window; exactly the timeout is still alive.
    watchdog.beat();
    h.clock.now += TIMEOUT_MS;
    watchdog.check();
    expect(h.deaths.count).toBe(0);

    h.clock.now += 1;
    watchdog.check();
    expect(h.deaths.count).toBe(1);
  });

  test("the scheduled interval runs the check", () => {
    const h = harness();
    build(h);

    expect(h.intervals).toHaveLength(1);
    expect(h.intervals[0].ms).toBe(CHECK_MS);

    h.tickInterval();
    expect(h.deaths.count).toBe(0);
    h.clock.now += TIMEOUT_MS + 1;
    h.tickInterval();
    expect(h.deaths.count).toBe(1);
  });

  test("a visibilitychange while visible checks immediately; hidden does not", () => {
    const h = harness();
    build(h);
    h.clock.now += TIMEOUT_MS + 1;

    h.visibility.visible = false;
    h.fire("visibilitychange");
    expect(h.deaths.count).toBe(0);

    h.visibility.visible = true;
    h.fire("visibilitychange");
    expect(h.deaths.count).toBe(1);
  });

  test.each(["pageshow", "online", "focus"] as const)(
    "a %s wake event checks immediately",
    (name) => {
      const h = harness();
      build(h);

      h.fire(name);
      expect(h.deaths.count).toBe(0);

      h.clock.now += TIMEOUT_MS + 1;
      h.fire(name);
      expect(h.deaths.count).toBe(1);
    },
  );

  test("stop() clears the interval and removes listeners, idempotently, and makes the watchdog inert", () => {
    const h = harness();
    const watchdog = build(h);
    expect(h.listeners.size).toBe(4);

    watchdog.stop();
    watchdog.stop();
    expect(h.cleared).toEqual([1]);
    expect(h.listeners.size).toBe(0);

    h.clock.now += TIMEOUT_MS + 1;
    watchdog.check();
    watchdog.beat();
    h.tickInterval();
    expect(h.deaths.count).toBe(0);
  });

  test("runs without a wake-event environment", () => {
    const h = harness();
    const watchdog = build(h, false);

    h.clock.now += TIMEOUT_MS + 1;
    h.tickInterval();
    expect(h.deaths.count).toBe(1);
    watchdog.stop();
    expect(h.cleared).toEqual([1]);
  });

  test("rejects a non-positive timeout or check interval", () => {
    const h = harness();
    expect(() =>
      createSignalingHeartbeatWatchdog({
        now: () => h.clock.now,
        timeoutMs: 0,
        checkEveryMs: CHECK_MS,
        schedule: { setInterval: () => 1, clearInterval: () => undefined },
        onDead: () => undefined,
      }),
    ).toThrow("timeout");
    expect(() =>
      createSignalingHeartbeatWatchdog({
        now: () => h.clock.now,
        timeoutMs: TIMEOUT_MS,
        checkEveryMs: Number.NaN,
        schedule: { setInterval: () => 1, clearInterval: () => undefined },
        onDead: () => undefined,
      }),
    ).toThrow("check interval");
    expect(h.intervals).toHaveLength(0);
  });
});
