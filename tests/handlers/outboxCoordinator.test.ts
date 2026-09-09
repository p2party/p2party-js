import { describe, expect, test } from "bun:test";
import { createOutboxResumeCoordinator } from "../../src/handlers/outboxCoordinator";

class Clock {
  time = 0;
  timers: Array<{ at: number; resolve(): void }> = [];
  now = () => this.time;
  sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      this.timers.push({ at: this.time + ms, resolve });
    });
  async advance(ms: number): Promise<void> {
    this.time += ms;
    const due = this.timers.filter((timer) => timer.at <= this.time);
    this.timers = this.timers.filter((timer) => timer.at > this.time);
    for (const timer of due) timer.resolve();
    await flush();
  }
}
const flush = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};

describe("outbox authentication event coalescing", () => {
  test("a second member authenticating inside the debounce gets a trailing pass", async () => {
    const clock = new Clock();
    const coordinator = createOutboxResumeCoordinator(clock);
    const authenticated = new Set(["B"]);
    const remaining = new Set(["B", "C"]);
    let calls = 0;
    coordinator.register(async () => {
      calls++;
      for (const peer of authenticated) remaining.delete(peer);
    });
    await coordinator.resume("room");
    expect([...remaining]).toEqual(["C"]);
    await clock.advance(2000);
    authenticated.add("C");
    const trailing = coordinator.resume("room");
    expect(clock.timers).toHaveLength(1);
    await clock.advance(2999);
    expect(calls).toBe(1);
    await clock.advance(1);
    await trailing;
    expect(calls).toBe(2);
    expect([...remaining]).toEqual([]);
    await clock.advance(60000);
    expect(calls).toBe(2);
    expect(clock.timers).toHaveLength(0);
  });

  test("several events during a running pass coalesce into one additional pass", async () => {
    const clock = new Clock();
    const coordinator = createOutboxResumeCoordinator(clock);
    let release!: () => void;
    let calls = 0;
    coordinator.register(async () => {
      calls++;
      if (calls === 1)
        await new Promise<void>((resolve) => {
          release = resolve;
        });
    });
    const first = coordinator.resume("room");
    await flush();
    expect(calls).toBe(1);
    const later = [
      coordinator.resume("room"),
      coordinator.resume("room"),
      coordinator.resume("room"),
    ];
    release();
    await flush();
    expect(clock.timers).toHaveLength(1);
    await clock.advance(5000);
    await Promise.all([first, ...later]);
    expect(calls).toBe(2);
    expect(clock.timers).toHaveLength(0);
  });

  test("failure alone never creates a background retry", async () => {
    const clock = new Clock();
    const coordinator = createOutboxResumeCoordinator(clock);
    let calls = 0;
    coordinator.register(async () => {
      calls++;
      throw new Error("offline");
    });
    await expect(coordinator.resume("room")).rejects.toThrow("offline");
    await clock.advance(60000);
    expect(calls).toBe(1);
    expect(clock.timers).toHaveLength(0);
  });

  test("failure does not discard a real event received while that pass was running", async () => {
    const clock = new Clock();
    const coordinator = createOutboxResumeCoordinator(clock);
    let release!: () => void;
    let calls = 0;
    coordinator.register(async () => {
      calls++;
      if (calls === 1) {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        throw new Error("first pass failed");
      }
    });
    const work = coordinator.resume("room");
    const result = work.catch((error) => error);
    await flush();
    coordinator.resume("room");
    release();
    await flush();
    await clock.advance(5000);
    expect(await result).toBeInstanceOf(Error);
    expect(calls).toBe(2);
    await clock.advance(60000);
    expect(calls).toBe(2);
  });

  test("rooms have independent event budgets", async () => {
    const clock = new Clock();
    const coordinator = createOutboxResumeCoordinator(clock);
    const calls: string[] = [];
    coordinator.register(async (room) => {
      calls.push(room);
    });
    await coordinator.resume("A");
    const waiting = coordinator.resume("A");
    await coordinator.resume("B");
    expect(calls).toEqual(["A", "B"]);
    await clock.advance(5000);
    await waiting;
    expect(calls).toEqual(["A", "B", "A"]);
  });
});
