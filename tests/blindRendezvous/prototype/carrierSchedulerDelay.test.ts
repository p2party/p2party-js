import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import { CarrierRuntime } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";

import type { CarrierEvent } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type {
  PrototypeStoreClient,
  WindowScan,
} from "../../../src/blindRendezvous/prototype/storeClient";

const module = await loadTestModule();
const profile = PROTOTYPE_DELIVERY_PROFILE_V0;
const profileHash = await deliveryProfileHash(profile);

interface Calls {
  readonly tokens: { readonly window: bigint; readonly atMs: bigint }[];
  readonly scans: bigint[];
}

/**
 * Whether a transport call is made at all, and when. This store models no
 * HTTP and no answer worth having: every call is recorded and refused.
 */
const recordingStore = (
  calls: Calls,
  clock: { nowMs(): bigint },
): PrototypeStoreClient =>
  ({
    storeIdHex: "aa".repeat(32),
    carrierContextId: new Uint8Array(32).fill(0xaa),
    inert: false,
    faults: [],
    issueToken: (window: bigint): Promise<boolean> => {
      calls.tokens.push({ window, atMs: clock.nowMs() });
      return Promise.resolve(true);
    },
    allocate: (): Promise<null> => Promise.resolve(null),
    append: (): Promise<null> => Promise.resolve(null),
    scanWindow: (window: bigint): Promise<WindowScan> => {
      calls.scans.push(window);
      return Promise.resolve({
        window,
        status: "finalized",
        objects: [],
        checkpointHash: null,
      });
    },
    recordReceipt: (): void => undefined,
    checkpointHashFor: (): null => null,
  }) as unknown as PrototypeStoreClient;

interface Harness {
  readonly runtime: CarrierRuntime;
  readonly calls: Calls;
  readonly events: CarrierEvent[];
  readonly pending: Map<number, { atMs: bigint; callback(): void }>;
  nowMs: bigint;
}

const startAtZero = (): Harness => {
  const calls: Calls = { tokens: [], scans: [] };
  const events: CarrierEvent[] = [];
  const pending = new Map<number, { atMs: bigint; callback(): void }>();
  let nextId = 0;
  const harness: Harness = {
    calls,
    events,
    pending,
    nowMs: 0n,
    runtime: null as unknown as CarrierRuntime,
  };
  const clock = { nowMs: (): bigint => harness.nowMs };
  const runtime = new CarrierRuntime({
    module,
    roomRoot: new Uint8Array(32).fill(0x1a),
    profile,
    profileHash,
    stores: [recordingStore(calls, clock)],
    validationContextAt: () => {
      throw new Error("no object is opened in this test");
    },
    logicalWindowMs: 4_000n,
    clock,
    timers: {
      setTimeout: (callback, delayMs) => {
        const id = ++nextId;
        pending.set(id, { atMs: harness.nowMs + BigInt(delayMs), callback });
        return id;
      },
      clearTimeout: (handle) => {
        pending.delete(handle as number);
      },
    },
    onOperations: () => {},
    onEvent: (event) => events.push(event),
  });
  return Object.assign(harness, { runtime });
};

/**
 * Deliver the first armed timer `lateness` ms after it was due — the way a
 * suspended or busy page delivers it: at the resumed wall clock, never
 * rewound to the due time.
 */
const deliverFirstTimerLate = async (
  harness: Harness,
  lateness: bigint,
): Promise<void> => {
  harness.runtime.start();
  const first = harness.pending.entries().next().value;
  if (first === undefined) throw new Error("the schedule was not armed");
  const [id, timer] = first;
  expect(timer.atMs).toBe(profile.tokenIssueOffsetMs);
  harness.pending.delete(id);
  harness.nowMs = timer.atMs + lateness;
  timer.callback();
  await harness.runtime.drain();
};

const tooLate = (harness: Harness, window: bigint): CarrierEvent[] =>
  harness.events.filter(
    (event) =>
      event.kind === "missed" &&
      event.window === window &&
      (event.detail ?? "").includes("more than one delivery window late"),
  );

describe("carrier timer delivery", () => {
  for (const lateness of [
    profile.maxScheduleSkewMs,
    profile.maxScheduleSkewMs + 1n,
    profile.deliveryWindowMs,
  ]) {
    test(`sends an event whose timer is ${lateness} ms late, at the late instant`, async () => {
      const harness = startAtZero();
      try {
        await deliverFirstTimerLate(harness, lateness);

        // Window 0's token names window 1, and it left when the timer fired.
        expect(
          harness.calls.tokens.filter((token) => token.window === 1n),
        ).toEqual([
          { window: 1n, atMs: profile.tokenIssueOffsetMs + lateness },
        ]);
        expect(tooLate(harness, 0n)).toEqual([]);
        expect(harness.pending.size).toBe(1);
        for (const next of harness.pending.values())
          expect(next.atMs).toBeGreaterThanOrEqual(harness.nowMs);
      } finally {
        harness.runtime.stop();
      }
      expect(harness.pending.size).toBe(0);
    });
  }

  test("skips and reports uploads more than one delivery window late, and still reads", async () => {
    const harness = startAtZero();
    try {
      // Window 0's token was due at 100 and fires at 9,100: window 2.
      await deliverFirstTimerLate(harness, 9_000n);

      expect(
        harness.calls.tokens.filter((token) => token.window <= 2n),
      ).toEqual([]);
      // Window 0's and window 1's token and allocation are reported, not sent.
      expect(tooLate(harness, 0n)).toHaveLength(1);
      expect(tooLate(harness, 1n)).toHaveLength(1);
      // No read is dropped. The read due at 8,600 is half a second late and
      // is made at once; the one due at 4,600 is more than a window late and
      // is caught up after it. (The read due at 600 is of window -1, which
      // does not exist.)
      expect(harness.calls.scans).toEqual([1n, 0n]);
      expect(harness.pending.size).toBe(1);
      for (const next of harness.pending.values())
        expect(next.atMs).toBeGreaterThanOrEqual(harness.nowMs);
    } finally {
      harness.runtime.stop();
    }
  });

  test("gives up whole windows past its catch-up reach and reports them", async () => {
    const harness = startAtZero();
    try {
      // A page suspended for a hundred windows.
      const lateness = profile.deliveryWindowMs * 100n;
      await deliverFirstTimerLate(harness, lateness);

      const givenUp = harness.events.filter(
        (event) =>
          event.kind === "missed" &&
          (event.detail ?? "").includes("windows behind the clock"),
      );
      expect(givenUp).toHaveLength(1);
      expect(givenUp[0].window).toBe(0n);
      // The clock is in window 100; the reach is 64 windows, so the schedule
      // resumes at window 36. The read of window 98 is due within the last
      // window and is made at once; windows 97 down to 35 are caught up,
      // newest first.
      expect(givenUp[0].count).toBe(36);
      expect(harness.calls.scans).toHaveLength(64);
      expect(harness.calls.scans[0]).toBe(98n);
      expect(harness.calls.scans[1]).toBe(97n);
      expect(harness.calls.scans[63]).toBe(35n);
      expect(harness.pending.size).toBe(1);
    } finally {
      harness.runtime.stop();
    }
  });
});

/**
 * A store whose every scan is held until the test releases it, recording
 * which scans were in flight when each one started.
 */
const heldStore = (): {
  readonly store: PrototypeStoreClient;
  readonly started: bigint[];
  readonly inFlightAtStart: Map<bigint, readonly bigint[]>;
  readonly inFlight: () => readonly bigint[];
  readonly release: (window: bigint) => void;
  readonly releaseAll: () => void;
} => {
  const started: bigint[] = [];
  const inFlightAtStart = new Map<bigint, readonly bigint[]>();
  const held = new Map<bigint, () => void>();
  const store = {
    storeIdHex: "bb".repeat(32),
    carrierContextId: new Uint8Array(32).fill(0xbb),
    inert: false,
    faults: [],
    issueToken: (): Promise<boolean> => Promise.resolve(true),
    allocate: (): Promise<null> => Promise.resolve(null),
    append: (): Promise<null> => Promise.resolve(null),
    scanWindow: (window: bigint): Promise<WindowScan> => {
      inFlightAtStart.set(window, [...held.keys()]);
      started.push(window);
      return new Promise<WindowScan>((resolve) => {
        held.set(window, () => {
          held.delete(window);
          resolve({
            window,
            status: "finalized",
            objects: [],
            checkpointHash: null,
          });
        });
      });
    },
    recordReceipt: (): void => undefined,
    checkpointHashFor: (): null => null,
  } as unknown as PrototypeStoreClient;
  return {
    store,
    started,
    inFlightAtStart,
    inFlight: () => [...held.keys()],
    release: (window) => {
      const resolve = held.get(window);
      if (resolve === undefined)
        throw new Error(`no scan of window ${String(window)} is held`);
      resolve();
    },
    releaseAll: () => {
      for (const resolve of [...held.values()]) resolve();
    },
  };
};

/**
 * Let the runtime run what it has queued: a bounded number of microtask
 * turns and event-loop yields, never a wall-clock wait. Microtask turns alone
 * are not enough: some of a released handler's work resolves on a later
 * event-loop turn.
 */
const turns = async (rounds = 3, count = 2_000): Promise<void> => {
  for (let round = 0; round < rounds; round += 1) {
    for (let turn = 0; turn < count; turn += 1) await Promise.resolve();
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
};

describe("carrier catch-up gate", () => {
  test("a catch-up requested while one runs is refused and reported, not queued twice", async () => {
    const held = heldStore();
    const events: CarrierEvent[] = [];
    const pending = new Map<number, { atMs: bigint; callback(): void }>();
    let nextId = 0;
    let nowMs = 0n;
    const runtime = new CarrierRuntime({
      module,
      roomRoot: new Uint8Array(32).fill(0x1b),
      profile,
      profileHash,
      stores: [held.store],
      validationContextAt: () => {
        throw new Error("no object is opened in this test");
      },
      logicalWindowMs: 4_000n,
      clock: { nowMs: () => nowMs },
      timers: {
        setTimeout: (callback, delayMs) => {
          const id = ++nextId;
          pending.set(id, { atMs: nowMs + BigInt(delayMs), callback });
          return id;
        },
        clearTimeout: (handle) => {
          pending.delete(handle as number);
        },
      },
      onOperations: () => {},
      onEvent: (event) => events.push(event),
    });
    /** Deliver the one armed timer at `atMs`, as a resumed page does. */
    const resumeAt = (atMs: bigint): void => {
      const armed = pending.entries().next().value;
      if (armed === undefined) throw new Error("the schedule is not armed");
      pending.delete(armed[0]);
      nowMs = atMs;
      armed[1].callback();
    };
    const scansOf = (window: bigint): number =>
      events.filter((event) => event.kind === "scan" && event.window === window)
        .length;

    runtime.start();
    try {
      // Resumed in window 2: the read of window 1 (due at 8,600) is on time
      // and scheduled; the read of window 0 (due at 4,600) is caught up.
      resumeAt(9_100n);
      await turns();
      // The catch-up is refused while the store has a scheduled read in
      // flight: it waits rather than share the store with it.
      expect(held.started).toEqual([1n]);

      // A second resume, in window 4, while that read is still out: the
      // read of window 3 is scheduled, the one of window 2 is caught up. The
      // catch-up already waiting takes it; none is started beside it.
      resumeAt(17_100n);
      await turns();
      expect(held.started).toEqual([1n, 3n]);

      held.release(1n);
      held.release(3n);
      await turns();
      // Newest first, and alone: nothing else of this store is in flight.
      expect(held.started).toEqual([1n, 3n, 2n]);
      expect(held.inFlightAtStart.get(2n)).toEqual([]);
      held.release(2n);
      await turns();
      expect(held.started).toEqual([1n, 3n, 2n, 0n]);
      expect(held.inFlightAtStart.get(0n)).toEqual([]);
      held.release(0n);
      await turns();

      // Every window was read once and reported once.
      expect(held.started).toHaveLength(4);
      expect([0n, 1n, 2n, 3n].map(scansOf)).toEqual([1, 1, 1, 1]);
      expect(held.inFlight()).toEqual([]);
    } finally {
      runtime.stop();
      held.releaseAll();
    }
  });
});
