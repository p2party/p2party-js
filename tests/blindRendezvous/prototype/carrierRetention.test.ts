import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import {
  deliveryProfileHash,
  policyHash,
  roomRoot,
} from "../../../src/blindRendezvous/derivations";
import {
  createOperationValidationContext,
  operationValidationContextAt,
} from "../../../src/blindRendezvous/operation";
import { copyBlindDefaultPolicy } from "../../../src/blindRendezvous/roomPolicyV4";
import { ingressWindowStartMs } from "../../../src/blindRendezvous/publicWindow";
import { CarrierRuntime } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import { PrototypeStoreClient } from "../../../src/blindRendezvous/prototype/storeClient";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";

import type { CarrierEvent } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type { WindowScan } from "../../../src/blindRendezvous/prototype/storeClient";

const module = await loadTestModule();
const profile = PROTOTYPE_DELIVERY_PROFILE_V0;
const profileHash = await deliveryProfileHash(profile);
const WINDOW_MS = profile.deliveryWindowMs;
/** 1_700_000_000_000 / 4_000 is exact, so the chain starts on a window edge. */
const CHAIN_START = 425_000_000n;
const windowStart = (window: bigint): bigint =>
  ingressWindowStartMs(window, WINDOW_MS);

/** A real room, so a scan's objects are trial-opened as they are in use. */
const POLICY = copyBlindDefaultPolicy();
const LOGICAL_WINDOW_MS = POLICY.protocolLimits.logicalWindowMs;
const CAPABILITY = new Uint8Array(32).fill(0x3c);
const ROOM_ROOT = await roomRoot(CAPABILITY, await policyHash(POLICY));
const ROOM_CONTEXT = await createOperationValidationContext(
  CAPABILITY,
  POLICY,
  windowStart(CHAIN_START) / LOGICAL_WINDOW_MS,
);

interface Harness {
  readonly runtime: CarrierRuntime;
  readonly events: CarrierEvent[];
  readonly pending: Map<number, { atMs: bigint; callback(): void }>;
  nowMs: bigint;
}

const harnessFor = (
  stores: readonly PrototypeStoreClient[],
  startMs: bigint,
): Harness => {
  const events: CarrierEvent[] = [];
  const pending = new Map<number, { atMs: bigint; callback(): void }>();
  let nextId = 0;
  const harness: Harness = {
    events,
    pending,
    nowMs: startMs,
    runtime: null as unknown as CarrierRuntime,
  };
  const clock = { nowMs: (): bigint => harness.nowMs };
  const runtime = new CarrierRuntime({
    module,
    roomRoot: ROOM_ROOT,
    profile,
    profileHash,
    stores,
    validationContextAt: (referenceLogicalWindow) =>
      operationValidationContextAt(ROOM_CONTEXT, referenceLogicalWindow),
    logicalWindowMs: LOGICAL_WINDOW_MS,
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

/** Fire every armed timer due by `untilMs`, in order, at its own instant. */
const fireUntil = async (harness: Harness, untilMs: bigint): Promise<void> => {
  for (;;) {
    let next: [number, { atMs: bigint; callback(): void }] | undefined;
    for (const entry of harness.pending)
      if (next === undefined || entry[1].atMs < next[1].atMs) next = entry;
    if (next === undefined || next[1].atMs > untilMs) return;
    harness.pending.delete(next[0]);
    if (harness.nowMs < next[1].atMs) harness.nowMs = next[1].atMs;
    next[1].callback();
    await harness.runtime.drain();
  }
};

const missedAt = (
  events: readonly CarrierEvent[],
  window: bigint,
  storeIdHex?: string,
): CarrierEvent[] =>
  events.filter(
    (event) =>
      event.kind === "missed" &&
      event.window === window &&
      (storeIdHex === undefined || event.storeIdHex === storeIdHex),
  );

describe("carrier runtime and store retention", () => {
  test("out-of-range beyond the stated retention is reported missed, not empty", async () => {
    const storeIdHex = "aa".repeat(32);
    // A store that has let every window expire: its client answers each
    // scan `beyond-retention`, as it does for a signed out-of-range past the
    // retention the descriptor states.
    const expired = {
      storeIdHex,
      storeId: new Uint8Array(32).fill(0xaa),
      carrierContextId: new Uint8Array(32).fill(0xaa),
      inert: false,
      faults: [],
      issueToken: (): Promise<boolean> => Promise.resolve(true),
      allocate: (): Promise<null> => Promise.resolve(null),
      append: (): Promise<null> => Promise.resolve(null),
      scanWindow: (window: bigint): Promise<WindowScan> =>
        Promise.resolve({
          window,
          status: "beyond-retention",
          objects: [],
          checkpointHash: null,
        }),
      recordReceipt: (): void => undefined,
      checkpointHashFor: (): null => null,
    } as unknown as PrototypeStoreClient;
    const harness = harnessFor([expired], windowStart(CHAIN_START));
    harness.runtime.start();
    try {
      // Through the read of the chain-start window, made in the next one.
      await fireUntil(
        harness,
        windowStart(CHAIN_START + 1n) + profile.publicReadOffsetMs,
      );
      const scans = harness.events.filter(
        (event) => event.kind === "scan" && event.window === CHAIN_START,
      );
      expect(scans.map((event) => event.detail)).toEqual(["beyond-retention"]);
      // Reported at the store, and for the window as a whole: never counted
      // as an empty read.
      expect(
        missedAt(harness.events, CHAIN_START, storeIdHex).filter((event) =>
          (event.detail ?? "").includes("no longer retains this window"),
        ),
      ).toHaveLength(1);
      expect(
        missedAt(harness.events, CHAIN_START).some((event) =>
          (event.detail ?? "").includes("no store served a finalized read"),
        ),
      ).toBe(true);
    } finally {
      await harness.runtime.stop();
    }
  });

  test("a client returning from suspension does not silently lose a catch-up window", async () => {
    const clock = { now: windowStart(CHAIN_START) };
    let handler: ((request: Request) => Promise<Response>) | null = null;
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (request: Request): Response | Promise<Response> =>
        handler === null
          ? new Response("not ready", { status: 503 })
          : handler(request),
    });
    try {
      expect(server.port ?? 0).toBeGreaterThan(5000);
      const origin = server.url.origin;
      const options = {
        module,
        seed: new Uint8Array(32).fill(0x5b),
        profile,
        clock: { nowMs: (): bigint => clock.now },
        persistence: new MemoryStorePersistence(),
        chainStartIngressWindow: CHAIN_START,
        origin,
        descriptorValidityMs: 2_592_000_000n,
      };
      // The shortest retention this store accepts: whatever it is, a client
      // coming back from a long suspension must not lose a window to it.
      let core: PrototypeStoreCore | null = null;
      for (let retention = 1; core === null && retention <= 300; retention++)
        core = await PrototypeStoreCore.create({
          ...options,
          retentionWindows: retention,
        }).catch(() => null);
      if (core === null) throw new Error("no retention was accepted");
      handler = createPrototypeStoreHandler({ core });
      const store = await PrototypeStoreClient.connect({
        origin,
        profile,
        profileHash,
        module,
        nowMs: () => clock.now,
      });

      const harness = harnessFor([store], clock.now);
      const syncClock = (): void => {
        clock.now = harness.nowMs;
      };
      harness.runtime.start();
      try {
        // One window on schedule, then a suspension of 60 windows, inside the
        // runtime's catch-up reach.
        await fireUntil(harness, windowStart(CHAIN_START) + WINDOW_MS - 1n);
        syncClock();
        const resumeWindow = CHAIN_START + 61n;
        harness.nowMs = windowStart(resumeWindow) + profile.publicReadOffsetMs;
        syncClock();
        while ((await core.finalizeDue()).length > 0);
        // The page resumes: the first timer it held fires late, at the
        // resumed clock, and the runtime catches its reads up.
        const first = [...harness.pending.entries()].sort((left, right) =>
          left[1].atMs < right[1].atMs ? -1 : 1,
        )[0];
        if (first === undefined) throw new Error("the schedule was not armed");
        harness.pending.delete(first[0]);
        first[1].callback();
        await harness.runtime.drain();

        const scans = harness.events.filter(
          (event) =>
            event.kind === "scan" &&
            event.window >= CHAIN_START + 1n &&
            event.window < resumeWindow - 1n,
        );
        expect(scans.length).toBeGreaterThan(50);
        // Every caught-up window was read, or reported missed at this store:
        // none came back as an empty success.
        // A report about the read itself, at this store or for the window as
        // a whole; a late upload's report says nothing about the read.
        const readReported = (window: bigint): boolean =>
          harness.events.some(
            (event) =>
              event.kind === "missed" &&
              event.window === window &&
              (event.storeIdHex === undefined ||
                event.storeIdHex === store.storeIdHex) &&
              /\bread\b|retains/.test(event.detail ?? ""),
          );
        const silent = scans.filter(
          (event) =>
            event.detail !== "finalized" && !readReported(event.window),
        );
        expect(
          silent.map(
            (event) => `${String(event.window)} ${event.detail ?? ""}`,
          ),
        ).toEqual([]);
        expect(scans.every((event) => event.detail === "finalized")).toBe(true);
      } finally {
        await harness.runtime.stop();
      }
    } finally {
      void server.stop(true);
    }
  }, 60_000);
});
