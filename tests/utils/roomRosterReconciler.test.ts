import { describe, expect, test } from "bun:test";

import {
  createRoomRosterReconciler,
  isRoomRosterStranded,
} from "../../src/utils/roomRosterReconciler";

/** A virtual timeout queue: nothing in the reconciler may touch a real clock. */
class FakeTimeouts {
  #next = 1;
  #now = 0;
  readonly #timers = new Map<number, { at: number; run: () => void }>();

  readonly setTimeout = (run: () => void, delayMs: number): number => {
    const handle = this.#next++;
    this.#timers.set(handle, { at: this.#now + delayMs, run });
    return handle;
  };

  readonly clearTimeout = (handle: number): void => {
    this.#timers.delete(handle);
  };

  get pending(): number {
    return this.#timers.size;
  }

  /** Delay of the single armed timer, relative to now. */
  get nextDelay(): number | null {
    const entries = [...this.#timers.values()];
    if (entries.length === 0) return null;
    return Math.min(...entries.map((t) => t.at)) - this.#now;
  }

  advance(ms: number): void {
    const target = this.#now + ms;
    for (;;) {
      const due = [...this.#timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      this.#now = due[1].at;
      this.#timers.delete(due[0]);
      due[1].run();
    }
    this.#now = target;
  }
}

const ROOM = "room-a";
const OTHER = "room-b";

const reconciler = (
  timeouts: FakeTimeouts,
  overrides: { delaysMs?: readonly number[]; maxAttempts?: number } = {},
) =>
  createRoomRosterReconciler({
    schedule: {
      setTimeout: timeouts.setTimeout,
      clearTimeout: timeouts.clearTimeout,
    },
    delaysMs: overrides.delaysMs ?? [5_000, 10_000, 20_000, 40_000, 60_000],
    maxAttempts: overrides.maxAttempts ?? 8,
  });

describe("room roster reconciler backoff", () => {
  test("asks again on 5/10/20/40/60 and then holds at the cap", () => {
    const timeouts = new FakeTimeouts();
    const asked: number[] = [];
    const clock = { t: 0 };
    const subject = reconciler(timeouts);

    subject.arm(ROOM, () => {
      asked.push(clock.t);
      return true;
    });

    const step = (ms: number) => {
      clock.t += ms;
      timeouts.advance(ms);
    };

    expect(timeouts.nextDelay).toBe(5_000);
    step(5_000);
    expect(asked).toEqual([5_000]);
    expect(timeouts.nextDelay).toBe(10_000);
    step(10_000);
    step(20_000);
    step(40_000);
    step(60_000);
    expect(asked).toEqual([5_000, 15_000, 35_000, 75_000, 135_000]);
    // Capped: every further attempt waits the last delay, never longer.
    expect(timeouts.nextDelay).toBe(60_000);
    step(60_000);
    step(60_000);
    expect(asked.length).toBe(7);
  });

  test("re-arming an already armed room neither reschedules nor rewinds", () => {
    const timeouts = new FakeTimeouts();
    let asked = 0;
    const subject = reconciler(timeouts);

    subject.arm(ROOM, () => {
      asked += 1;
      return true;
    });
    timeouts.advance(4_000);
    subject.arm(ROOM, () => {
      asked += 1;
      return true;
    });
    expect(timeouts.pending).toBe(1);
    expect(timeouts.nextDelay).toBe(1_000);
    timeouts.advance(1_000);
    expect(asked).toBe(1);
    // The second attempt still waits the SECOND delay, not the first.
    expect(timeouts.nextDelay).toBe(10_000);
  });

  test("stops for good the first time the room reports it is no longer stranded", () => {
    const timeouts = new FakeTimeouts();
    let asked = 0;
    let stranded = true;
    const subject = reconciler(timeouts);

    subject.arm(ROOM, () => {
      asked += 1;
      return stranded;
    });
    timeouts.advance(5_000);
    expect(asked).toBe(1);

    stranded = false;
    timeouts.advance(10_000);
    expect(asked).toBe(2);
    expect(timeouts.pending).toBe(0);
    expect(subject.armedRooms()).toEqual([]);
  });

  test("gives up after the attempt cap and does not re-arm until cancelled", () => {
    const timeouts = new FakeTimeouts();
    let asked = 0;
    const tick = () => {
      asked += 1;
      return true;
    };
    const subject = reconciler(timeouts, {
      delaysMs: [1_000],
      maxAttempts: 3,
    });

    subject.arm(ROOM, tick);
    timeouts.advance(10_000);
    expect(asked).toBe(3);
    expect(timeouts.pending).toBe(0);
    // Still armed, so a caller that keeps observing the room cannot restart it.
    expect(subject.armedRooms()).toEqual([ROOM]);
    subject.arm(ROOM, tick);
    timeouts.advance(10_000);
    expect(asked).toBe(3);

    // Something changed: the room is cancelled, and a fresh strand starts over.
    subject.cancel(ROOM);
    subject.arm(ROOM, tick);
    timeouts.advance(1_000);
    expect(asked).toBe(4);
  });

  test("cancel and cancelAll release their timers", () => {
    const timeouts = new FakeTimeouts();
    let asked = 0;
    const tick = () => {
      asked += 1;
      return true;
    };
    const subject = reconciler(timeouts);

    subject.arm(ROOM, tick);
    subject.arm(OTHER, tick);
    expect([...subject.armedRooms()].sort()).toEqual([ROOM, OTHER].sort());

    subject.cancel(ROOM);
    expect(timeouts.pending).toBe(1);
    subject.cancelAll();
    expect(timeouts.pending).toBe(0);
    expect(subject.armedRooms()).toEqual([]);
    timeouts.advance(600_000);
    expect(asked).toBe(0);
  });

  test("a tick that throws stops that room instead of escaping the timer", () => {
    const timeouts = new FakeTimeouts();
    const subject = reconciler(timeouts);

    subject.arm(ROOM, () => {
      throw new Error("dispatch failed");
    });
    expect(() => {
      timeouts.advance(5_000);
    }).not.toThrow();
    expect(subject.armedRooms()).toEqual([]);
    expect(timeouts.pending).toBe(0);
  });

  test("rejects a delay list that could schedule a busy loop", () => {
    const timeouts = new FakeTimeouts();
    expect(() => reconciler(timeouts, { delaysMs: [] })).toThrow();
    expect(() => reconciler(timeouts, { delaysMs: [0] })).toThrow();
    expect(() => reconciler(timeouts, { maxAttempts: 0 })).toThrow();
  });
});

describe("stranded-room predicate", () => {
  const room = (over: Record<string, unknown> = {}) => ({
    id: "00000000-0000-4000-8000-0000000000aa",
    signalingActive: true,
    peers: [],
    ...over,
  });
  const verified = { isConnected: true, isVerified: true };

  test("an active verified room with nobody in it is stranded", () => {
    expect(isRoomRosterStranded(room(), verified)).toBe(true);
  });

  test("terminal failures stop reconciliation even after their roster entries are deleted", () => {
    for (const reason of ["pin-mismatch", "pin-throttled", "policy"])
      for (const peers of [[], [{ peerId: "p1" }]])
        expect(
          isRoomRosterStranded(
            room({
              peers,
              handshakeStatusByPeer: { p1: { status: "failed", reason } },
            }),
            verified,
          ),
        ).toBe(false);
  });

  test("another recoverable peer keeps reconciliation alive beside a terminal failure", () => {
    expect(
      isRoomRosterStranded(
        room({
          peers: [{ peerId: "p1" }, { peerId: "p2" }],
          handshakeStatusByPeer: {
            p1: { status: "failed", reason: "pin-mismatch" },
            p2: { status: "failed", reason: "transport" },
          },
        }),
        verified,
      ),
    ).toBe(true);
  });

  test("peers that are all still authenticating are still nobody to talk to", () => {
    expect(
      isRoomRosterStranded(
        room({
          peers: [{ peerId: "p1" }, { peerId: "p2" }],
          handshakeStatusByPeer: {
            p1: { status: "authenticating" },
            p2: { status: "failed" },
          },
        }),
        verified,
      ),
    ).toBe(true);
  });

  test("one authenticated peer ends it", () => {
    expect(
      isRoomRosterStranded(
        room({
          peers: [{ peerId: "p1" }, { peerId: "p2" }],
          handshakeStatusByPeer: {
            p1: { status: "failed" },
            p2: { status: "authenticated" },
          },
        }),
        verified,
      ),
    ).toBe(false);
  });

  test("never for an unverified or disconnected socket", () => {
    expect(
      isRoomRosterStranded(room(), { isConnected: true, isVerified: false }),
    ).toBe(false);
    expect(
      isRoomRosterStranded(room(), { isConnected: false, isVerified: true }),
    ).toBe(false);
  });

  test("never for a room the user left or that has no signaling identity yet", () => {
    expect(
      isRoomRosterStranded(room({ signalingActive: false }), verified),
    ).toBe(false);
    expect(isRoomRosterStranded(room({ id: "" }), verified)).toBe(false);
    expect(isRoomRosterStranded(room({ id: "not-a-uuid" }), verified)).toBe(
      false,
    );
  });
});
