import { readFileSync } from "node:fs";

import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import { bytesEqual } from "../../../src/blindRendezvous/canonicalSchema";
import { ingressWindow } from "../../../src/blindRendezvous/publicWindow";
import { runBlindRendezvousPrototype } from "../../../src/blindRendezvous/prototype/index";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";

import type { StoreAdmissionRequestV1 } from "../../../src/blindRendezvous/prototype/store/storeCore";
import type { StoreAdmissionTokenRequest } from "../../../src/blindRendezvous/prototype/storeClient";

const module = await loadTestModule();

const wasmFileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(wasmFileBytes.byteLength);
new Uint8Array(wasmBinary).set(wasmFileBytes);

const profile = PROTOTYPE_DELIVERY_PROFILE_V0;

/** Resolve with the first value a callback is handed, or fail after a bound. */
const firstCall = <T>(
  boundMs: number,
): {
  readonly called: Promise<T>;
  readonly record: (value: T) => void;
  readonly cancel: () => void;
} => {
  let resolve!: (value: T) => void;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const called = new Promise<T>((settle, reject) => {
    resolve = settle;
    timer = setTimeout(() => {
      reject(new Error(`not called within ${String(boundMs)} ms`));
    }, boundMs);
  });
  return {
    called,
    record: (value) => {
      if (timer !== null) clearTimeout(timer);
      timer = null;
      resolve(value);
    },
    cancel: () => {
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
  };
};

describe("prototype public entry point", () => {
  test("an admission token provider given at the entry point reaches the store client", async () => {
    const token = new Uint8Array(32).fill(0x7e);
    const quotaKey = new Uint8Array(32).fill(0x7f);
    // The first window of a run asks for its first token within a delivery
    // window of starting (the allocation offset, or at once on a cold start
    // past it); two windows is the bound, not a measurement.
    const bound = Number(profile.deliveryWindowMs) * 2;
    const asked = firstCall<StoreAdmissionTokenRequest>(bound);
    const admitted = firstCall<StoreAdmissionRequestV1>(bound);

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
        clock: { nowMs: () => BigInt(Date.now()) },
        persistence: new MemoryStorePersistence(),
        chainStartIngressWindow: ingressWindow(
          profile.deliveryWindowMs,
          BigInt(Date.now()),
        ),
        origin,
        descriptorValidityMs: 2_592_000_000n,
        // Admits only a request that presents the provider's token.
        allocationAdmission: {
          authorize: (request) => {
            if (!bytesEqual(request.privacyPassToken, token)) return null;
            admitted.record(request);
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
        admissionTokens: (request) => {
          asked.record(request);
          return { storeId: request.storeId, token };
        },
        onEvent: () => {},
      });
      try {
        const request = await asked.called;
        expect(bytesEqual(request.storeId, core.storeId)).toBe(true);
        expect(request.origin).toBe(origin);
        expect(["allocation", "append"]).toContain(request.route);
        // And the store saw the token the provider returned.
        const seen = await admitted.called;
        expect(bytesEqual(seen.privacyPassToken, token)).toBe(true);
      } finally {
        await run.stop();
      }
    } finally {
      asked.cancel();
      admitted.cancel();
      await server.stop(true);
    }
  }, 30_000);
});
