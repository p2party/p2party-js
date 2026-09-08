import { describe, expect, test } from "bun:test";

import { SignalingPeerRequestDebouncer } from "../../src/utils/signalingPeerRequestDebouncer";

describe("signaling peer request debounce", () => {
  const fakeClock = () => {
    let now = 0;
    let next = 0;
    const timers = new Map<number, { at: number; callback: () => void }>();
    return {
      now: () => now,
      setTimeout: (callback: () => void, ms: number) => {
        const id = ++next;
        timers.set(id, { at: now + ms, callback });
        return id as unknown as ReturnType<typeof setTimeout>;
      },
      clearTimeout: (timer: ReturnType<typeof setTimeout>) => {
        timers.delete(timer as unknown as number);
      },
      advance: (ms: number) => {
        now += ms;
        for (const [id, timer] of [...timers])
          if (timer.at <= now) {
            timers.delete(id);
            timer.callback();
          }
      },
      pending: () => timers.size,
    };
  };

  test("the last redial in a burst is flushed exactly once", () => {
    const clock = fakeClock(),
      debouncer = new SignalingPeerRequestDebouncer(clock),
      calls: number[] = [];
    debouncer.request("redial", "room", 2000, () => {
      calls.push(1);
    });
    clock.advance(100);
    debouncer.request("redial", "room", 2000, () => {
      calls.push(2);
    });
    debouncer.request("redial", "room", 2000, () => {
      calls.push(3);
    });
    expect(calls).toEqual([1]);
    clock.advance(1900);
    expect(calls).toEqual([1, 3]);
    expect(clock.pending()).toBe(0);
    clock.advance(60000);
    expect(calls).toEqual([1, 3]);
  });

  test("leave and socket replacement cancel deferred redials and invalidate snapshots", () => {
    for (const reset of ["room", "socket"]) {
      const clock = fakeClock(),
        debouncer = new SignalingPeerRequestDebouncer(clock);
      let calls = 0;
      debouncer.request("redial", "room", 2000, () => {
        calls++;
      });
      debouncer.request("redial", "room", 2000, () => {
        calls++;
      });
      const requestId = debouncer.beginRosterRequest("room");
      debouncer.confirmRosterSnapshots();
      if (reset === "room") debouncer.cancelRoom("room");
      else debouncer.resetSocketLifecycle();
      clock.advance(2000);
      expect(calls).toBe(1);
      expect(debouncer.isCurrentRosterRequest("room", requestId)).toBe(false);
      if (reset === "socket")
        expect(debouncer.supportsRosterSnapshots).toBe(false);
    }
  });

  test("a newer request fences an older snapshot but does not affect another room", () => {
    const debouncer = new SignalingPeerRequestDebouncer();
    const old = debouncer.beginRosterRequest("room"),
      other = debouncer.beginRosterRequest("other"),
      latest = debouncer.beginRosterRequest("room");
    expect(debouncer.isCurrentRosterRequest("room", old)).toBe(false);
    expect(debouncer.isCurrentRosterRequest("room", latest)).toBe(true);
    expect(debouncer.isCurrentRosterRequest("other", other)).toBe(true);
    expect(debouncer.isCurrentRosterRequest("room", undefined)).toBe(false);
  });
  test("debounces within a socket but permits the first request after reconnect", () => {
    const debouncer = new SignalingPeerRequestDebouncer();

    expect(debouncer.shouldSend("join", "room-id", 2000, 10_000)).toBe(true);
    expect(debouncer.shouldSend("join", "room-id", 2000, 10_001)).toBe(false);

    debouncer.resetSocketLifecycle();
    expect(debouncer.shouldSend("join", "room-id", 2000, 10_001)).toBe(true);
  });

  test("keeps join and empty-roster retry budgets independent", () => {
    const debouncer = new SignalingPeerRequestDebouncer();

    expect(debouncer.shouldSend("join", "room-id", 2000, 10_000)).toBe(true);
    expect(debouncer.shouldSend("empty-roster", "room-id", 5000, 10_000)).toBe(
      true,
    );
  });

  test("a re-dial after an edge teardown is not swallowed by the join window", () => {
    const debouncer = new SignalingPeerRequestDebouncer();

    expect(debouncer.shouldSend("join", "room-id", 2000, 10_000)).toBe(true);
    expect(debouncer.shouldSend("redial", "room-id", 2000, 10_001)).toBe(true);
    expect(debouncer.shouldSend("redial", "room-id", 2000, 10_002)).toBe(false);
  });
});
