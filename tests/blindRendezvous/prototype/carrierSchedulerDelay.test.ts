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
        status: "not-final",
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
      // A read is made however late: the reads due at 600 (of window -1,
      // which does not exist) and at 4,600 and 8,600 (of windows 0 and 1).
      expect(harness.calls.scans).toEqual([0n, 1n]);
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
      // resumes at window 36 and reads windows 35 to 98 on the way.
      expect(givenUp[0].count).toBe(36);
      expect(harness.calls.scans).toHaveLength(64);
      expect(harness.calls.scans[0]).toBe(35n);
      expect(harness.calls.scans[63]).toBe(98n);
      expect(harness.pending.size).toBe(1);
    } finally {
      harness.runtime.stop();
    }
  });
});
