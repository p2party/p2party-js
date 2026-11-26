import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import { CarrierRuntime } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import type { PrototypeStoreClient } from "../../../src/blindRendezvous/prototype/storeClient";

const module = await loadTestModule();
const profile = PROTOTYPE_DELIVERY_PROFILE_V0;
const profileHash = await deliveryProfileHash(profile);

describe("carrier timer delivery", () => {
  for (const lateness of [
    profile.maxScheduleSkewMs,
    profile.maxScheduleSkewMs + 1n,
    9_000n,
  ]) {
    test(`respects the schedule skew bound after a ${lateness} ms timer delay`, async () => {
      let nowMs = 0n;
      let nextId = 0;
      const pending = new Map<number, { atMs: bigint; callback(): void }>();
      const issued: { window: bigint; atMs: bigint }[] = [];
      // This test concerns whether a transport call is made at all. It does
      // not model HTTP arrival times or claim resistance to traffic analysis.
      const store = {
        storeIdHex: "aa".repeat(32),
        issueToken: async (window: bigint): Promise<boolean> => {
          issued.push({ window, atMs: nowMs });
          return true;
        },
      } as unknown as PrototypeStoreClient;
      const runtime = new CarrierRuntime({
        module,
        roomRoot: new Uint8Array(32).fill(0x1a),
        profile,
        profileHash,
        stores: [store],
        validationContextAt: () => {
          throw new Error("no read should run in this token-only test");
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
      });

      try {
        runtime.start();
        const first = pending.entries().next().value;
        if (first === undefined) throw new Error("the schedule was not armed");
        const [id, event] = first;
        expect(event.atMs).toBe(profile.tokenIssueOffsetMs);
        pending.delete(id);
        // Browser suspension delivers a previously armed callback at the
        // resumed wall clock; it does not rewind the clock to the due time.
        nowMs = event.atMs + lateness;
        event.callback();
        await runtime.drain();

        expect(issued).toHaveLength(
          lateness <= profile.maxScheduleSkewMs ? 1 : 0,
        );
        if (issued.length > 0) expect(issued[0].window).toBe(1n);
        expect(pending.size).toBe(1);
        for (const next of pending.values())
          expect(next.atMs).toBeGreaterThanOrEqual(nowMs);
      } finally {
        runtime.stop();
      }
      expect(pending.size).toBe(0);
    });
  }
});
