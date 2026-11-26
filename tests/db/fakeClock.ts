// A clock a test moves. While installed, Date.now reads it and every timer
// armed with a delay above zero waits on it: nothing fires until the test
// advances the clock, and then in due order. A timer with no delay stays the
// engine's own, since that is how queued work is yielded to.
//
// A timer armed here is an object of its own, never a number: clearing it
// after the clock was restored reaches the engine's clearTimeout, which
// ignores it instead of clearing some real timer with the same number.
import { spyOn } from "bun:test";

export interface FakeClock {
  now: () => number;
  /** Timers armed and not yet fired or cleared. */
  pending: () => number;
  /** Timers armed since the clock was installed. */
  armed: () => number;
  /** Move time forward by `ms`, firing each timer that falls due, in order. */
  advance: (ms: number) => void;
  restore: () => void;
}

export const installFakeClock = (startAt: number = Date.now()): FakeClock => {
  let now = startAt;
  let armed = 0;
  interface FakeTimer {
    order: number;
    at: number;
    callback: () => void;
  }
  const timers = new Set<FakeTimer>();
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  const dateNow = spyOn(Date, "now").mockImplementation(() => now);
  const globals = globalThis as unknown as {
    setTimeout: (
      callback: (...args: unknown[]) => void,
      delay?: number,
      ...args: unknown[]
    ) => unknown;
    clearTimeout: (handle?: unknown) => void;
  };
  globals.setTimeout = (callback, delay, ...args) => {
    if (delay === undefined || delay <= 0)
      return realSetTimeout(callback, delay, ...args);
    armed += 1;
    const timer: FakeTimer = {
      order: armed,
      at: now + delay,
      callback: () => callback(...args),
    };
    timers.add(timer);
    return timer;
  };
  globals.clearTimeout = (handle) => {
    if (timers.delete(handle as FakeTimer)) return;
    realClearTimeout(handle as Parameters<typeof realClearTimeout>[0]);
  };
  return {
    now: () => now,
    pending: () => timers.size,
    armed: () => armed,
    advance: (ms) => {
      const target = now + ms;
      for (;;) {
        const due = [...timers]
          .filter((timer) => timer.at <= target)
          .sort((a, b) => a.at - b.at || a.order - b.order)[0];
        if (!due) break;
        timers.delete(due);
        now = Math.max(now, due.at);
        due.callback();
      }
      now = target;
    },
    restore: () => {
      dateNow.mockRestore();
      globalThis.setTimeout = realSetTimeout;
      globalThis.clearTimeout = realClearTimeout;
    },
  };
};

/**
 * Let queued work run until `condition` holds: turns of the event loop, not
 * time, and as many as it takes.
 *
 * There is no limit on the turns, because their number is not the same in
 * every run. An idle turn takes about a microsecond, and work that leaves the
 * event loop (a WebCrypto digest on the runtime's threads, a zero-delay
 * timer) is away for as many turns as fit in the time it takes: a limit on
 * turns is a limit on that time. A condition that never holds fails the test
 * at the runner's timeout, as an awaited promise that never settles does.
 */
export const untilTurns = async (condition: () => boolean): Promise<void> => {
  while (!condition()) await new Promise((resolve) => setImmediate(resolve));
};
