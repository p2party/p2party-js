import { describe, expect, test } from "bun:test";

import { createSignalingReconnectController } from "../../src/utils/signalingReconnectController";
import { SIGNALING_RECONNECT_DELAYS_MS } from "../../src/utils/constants";

interface FakeClock {
  readonly schedule: {
    setTimeout: (callback: () => void, delayMs: number) => number;
    clearTimeout: (handle: number) => void;
  };
  readonly delays: number[];
  fire: () => void;
  readonly cleared: number[];
  readonly liveTimers: number;
}

const fakeClock = (): FakeClock => {
  const delays: number[] = [];
  const cleared: number[] = [];
  const timers = new Map<number, () => void>();
  let next = 1;
  return {
    schedule: {
      setTimeout: (callback, delayMs) => {
        delays.push(delayMs);
        const handle = next++;
        timers.set(handle, callback);
        return handle;
      },
      clearTimeout: (handle) => {
        cleared.push(handle);
        timers.delete(handle);
      },
    },
    delays,
    cleared,
    get liveTimers() {
      return timers.size;
    },
    fire: () => {
      const entry = [...timers.entries()][0];
      if (!entry) throw new Error("no timer armed");
      timers.delete(entry[0]);
      entry[1]();
    },
  };
};

const build = (
  overrides: { shouldReconnect?: () => boolean } = {},
): {
  controller: ReturnType<typeof createSignalingReconnectController>;
  clock: FakeClock;
  attempts: number[];
} => {
  const clock = fakeClock();
  const attempts: number[] = [];
  const controller = createSignalingReconnectController({
    delaysMs: SIGNALING_RECONNECT_DELAYS_MS,
    schedule: clock.schedule,
    shouldReconnect: overrides.shouldReconnect ?? (() => true),
    reconnect: (attempt) => attempts.push(attempt),
  });
  return { controller, clock, attempts };
};

describe("signaling reconnect controller", () => {
  test("a close before any socket opened is not retried", () => {
    const { controller, clock } = build();
    expect(controller.schedule("socket-closed")).toBe(false);
    expect(clock.delays).toEqual([]);
  });

  test("an unsolicited close after open walks the backoff ladder", () => {
    const { controller, clock, attempts } = build();
    controller.arm();
    for (let i = 0; i < SIGNALING_RECONNECT_DELAYS_MS.length + 2; i++) {
      expect(controller.schedule("socket-closed")).toBe(true);
      clock.fire();
    }
    // Six ladder rungs, then the cap repeats forever.
    expect(clock.delays).toEqual([
      1_000, 2_000, 4_000, 8_000, 15_000, 30_000, 30_000, 30_000,
    ]);
    expect(attempts).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  test("a second close while an attempt is pending does not double-arm", () => {
    const { controller, clock } = build();
    controller.arm();
    expect(controller.schedule("socket-closed")).toBe(true);
    expect(controller.schedule("socket-error")).toBe(false);
    expect(controller.schedule("heartbeat-lost")).toBe(false);
    expect(clock.delays).toEqual([1_000]);
    expect(clock.liveTimers).toBe(1);
  });

  test("a heartbeat resets the ladder to its first rung", () => {
    const { controller, clock } = build();
    controller.arm();
    controller.schedule("socket-closed");
    clock.fire();
    controller.schedule("socket-closed");
    clock.fire();
    expect(clock.delays).toEqual([1_000, 2_000]);
    controller.succeeded();
    expect(controller.attempts).toBe(0);
    controller.schedule("socket-closed");
    expect(clock.delays).toEqual([1_000, 2_000, 1_000]);
  });

  test("succeeded() cancels a pending attempt without disarming", () => {
    const { controller, clock } = build();
    controller.arm();
    controller.schedule("socket-closed");
    expect(controller.pending).toBe(true);
    controller.succeeded();
    expect(controller.pending).toBe(false);
    expect(clock.liveTimers).toBe(0);
    expect(controller.schedule("socket-closed")).toBe(true);
  });

  test("cancel() disarms: a later close is not retried until a socket opens again", () => {
    const { controller, clock } = build();
    controller.arm();
    controller.schedule("socket-closed");
    controller.cancel();
    expect(clock.liveTimers).toBe(0);
    expect(controller.attempts).toBe(0);
    expect(controller.schedule("socket-closed")).toBe(false);
    controller.arm();
    expect(controller.schedule("socket-closed")).toBe(true);
  });

  test("a room-less client disarms instead of retrying forever", () => {
    let wanted = true;
    const { controller, clock } = build({ shouldReconnect: () => wanted });
    controller.arm();
    wanted = false;
    expect(controller.schedule("socket-closed")).toBe(false);
    expect(clock.delays).toEqual([]);
    wanted = true;
    // Disarmed by the refusal: a bare want does not resurrect it.
    expect(controller.schedule("socket-closed")).toBe(false);
  });

  test("shouldReconnect is re-read when the timer fires, not only when armed", () => {
    let wanted = true;
    const { controller, clock, attempts } = build({
      shouldReconnect: () => wanted,
    });
    controller.arm();
    controller.schedule("socket-closed");
    wanted = false;
    clock.fire();
    expect(attempts).toEqual([]);
    expect(controller.pending).toBe(false);
  });

  test("a non-positive or empty ladder is rejected at construction", () => {
    const clock = fakeClock();
    expect(() =>
      createSignalingReconnectController({
        delaysMs: [],
        schedule: clock.schedule,
        shouldReconnect: () => true,
        reconnect: () => undefined,
      }),
    ).toThrow("Signaling reconnect ladder must not be empty");
    expect(() =>
      createSignalingReconnectController({
        delaysMs: [1_000, 0],
        schedule: clock.schedule,
        shouldReconnect: () => true,
        reconnect: () => undefined,
      }),
    ).toThrow("Signaling reconnect delay must be a positive duration");
  });
});
