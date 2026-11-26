import { readFileSync } from "node:fs";

import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import { bytesEqual } from "../../../src/blindRendezvous/canonicalSchema";
import { ingressWindowStartMs } from "../../../src/blindRendezvous/publicWindow";
import { runBlindRendezvousPrototype } from "../../../src/blindRendezvous/prototype/index";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";

import type { CarrierTimers } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type { StoreAdmissionRequestV1 } from "../../../src/blindRendezvous/prototype/store/storeCore";
import type { StoreAdmissionTokenRequest } from "../../../src/blindRendezvous/prototype/storeClient";

const module = await loadTestModule();

const wasmFileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(wasmFileBytes.byteLength);
new Uint8Array(wasmBinary).set(wasmFileBytes);

const profile = PROTOTYPE_DELIVERY_PROFILE_V0;

/** 1_800_000_000_000 / 4_000 is exact: the run starts on a window edge. */
const CHAIN_START = 450_000_000n;

/**
 * One clock for the store and the run, and a timer pair that fires only when
 * the test says so: the run's time is the test's, and nothing waits on the
 * wall clock.
 */
const fakeTime = (
  startMs: bigint,
): {
  readonly clock: { nowMs(): bigint };
  readonly timers: CarrierTimers;
  /** Fire the earliest armed timer at its own instant; false if none. */
  readonly fireNext: () => boolean;
} => {
  let nowMs = startMs;
  let nextId = 0;
  const pending = new Map<number, { atMs: bigint; callback: () => void }>();
  return {
    clock: { nowMs: () => nowMs },
    timers: {
      setTimeout: (callback, delayMs) => {
        nextId += 1;
        pending.set(nextId, { atMs: nowMs + BigInt(delayMs), callback });
        return nextId;
      },
      clearTimeout: (handle) => {
        pending.delete(handle as number);
      },
    },
    fireNext: () => {
      let earliest: [number, { atMs: bigint; callback: () => void }] | null =
        null;
      for (const entry of pending)
        if (earliest === null || entry[1].atMs < earliest[1].atMs)
          earliest = entry;
      if (earliest === null) return false;
      pending.delete(earliest[0]);
      if (earliest[1].atMs > nowMs) nowMs = earliest[1].atMs;
      earliest[1].callback();
      return true;
    },
  };
};

/** Bounded event-loop turns, never a wall-clock wait. */
const until = async (condition: () => boolean, rounds = 2_000) => {
  for (let round = 0; round < rounds && !condition(); round += 1)
    await new Promise<void>((resolve) => setImmediate(resolve));
};

describe("prototype public entry point", () => {
  test("an admission token provider given at the entry point reaches the store client", async () => {
    const token = new Uint8Array(32).fill(0x7e);
    const quotaKey = new Uint8Array(32).fill(0x7f);
    const time = fakeTime(
      ingressWindowStartMs(CHAIN_START, profile.deliveryWindowMs),
    );
    const asked: StoreAdmissionTokenRequest[] = [];
    const admitted: StoreAdmissionRequestV1[] = [];

    let handler: ((request: Request) => Promise<Response>) | null = null;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request: Request): Response | Promise<Response> =>
        handler === null
          ? new Response("not ready", { status: 503 })
          : handler(request),
    });
    try {
      expect(server.port).toBeGreaterThan(5000);
      const origin = server.url.origin;
      const core = await PrototypeStoreCore.create({
        module,
        seed: new Uint8Array(32).fill(0x3c),
        profile,
        clock: time.clock,
        persistence: new MemoryStorePersistence(),
        chainStartIngressWindow: CHAIN_START,
        origin,
        descriptorValidityMs: 2_592_000_000n,
        // Admits only a request that presents the provider's token.
        allocationAdmission: {
          authorize: (request) => {
            if (!bytesEqual(request.privacyPassToken, token)) return null;
            admitted.push(request);
            return quotaKey;
          },
        },
      });
      handler = createPrototypeStoreHandler({ core });

      const run = await runBlindRendezvousPrototype({
        capability: new Uint8Array(32).fill(0x5d),
        storeOrigins: [origin],
        wasmBinary,
        rtcConfig: { iceServers: [] },
        clock: time.clock,
        timers: time.timers,
        admissionTokens: (request) => {
          asked.push(request);
          return { storeId: request.storeId, token };
        },
        onEvent: () => {},
      });
      try {
        // Started on a window edge: the token request is due at 100 ms and
        // the allocation, the first request that presents a token, at 700.
        for (let fired = 0; fired < 8 && asked.length === 0; fired += 1) {
          expect(time.fireNext()).toBe(true);
          await until(() => asked.length > 0, 50);
        }
        expect(asked.length).toBeGreaterThan(0);
        const request = asked[0];
        expect(bytesEqual(request.storeId, core.storeId)).toBe(true);
        expect(request.origin).toBe(origin);
        expect(request.route).toBe("allocation");
        expect(request.ingressWindow).toBe(CHAIN_START + 1n);
        // And the store saw the token the provider returned.
        await until(() => admitted.length > 0);
        expect(admitted.length).toBeGreaterThan(0);
        expect(bytesEqual(admitted[0].privacyPassToken, token)).toBe(true);
      } finally {
        await run.stop();
      }
    } finally {
      await server.stop(true);
    }
  });
});
