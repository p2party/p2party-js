import { describe, expect, test } from "bun:test";

import { keyPairFromSeed, sign } from "../../../src/cryptography/ed25519";
import { loadTestModule } from "../../../src/cryptography/testModule";
import {
  deliveryProfileHash,
  policyHash,
  publicCheckpointStatusSigningHash,
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
import { PROTOTYPE_MAX_READ_WINDOWS } from "../../../src/utils/constants";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";
import { PROTOTYPE_STORE_ROUTES } from "../../../src/blindRendezvous/prototype/storeRoutes";
import { encodePublicStoreCheckpointReadV1 } from "../../../src/blindRendezvous/prototype/storeWire";

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

/**
 * Fire every armed timer due by `untilMs`, in order, at its own instant.
 * `beforeEach` runs once the clock is at that instant and before the timer
 * fires: where a test's store does its own timed work.
 */
const fireUntil = async (
  harness: Harness,
  untilMs: bigint,
  beforeEach: () => Promise<void> = () => Promise.resolve(),
): Promise<void> => {
  for (;;) {
    let next: [number, { atMs: bigint; callback(): void }] | undefined;
    for (const entry of harness.pending)
      if (next === undefined || entry[1].atMs < next[1].atMs) next = entry;
    if (next === undefined || next[1].atMs > untilMs) return;
    harness.pending.delete(next[0]);
    if (harness.nowMs < next[1].atMs) harness.nowMs = next[1].atMs;
    await beforeEach();
    next[1].callback();
    await harness.runtime.drain();
  }
};

/** Bounded event-loop turns, never a wall-clock wait. */
const turns = async (rounds = 50): Promise<void> => {
  for (let round = 0; round < rounds; round += 1)
    await new Promise<void>((resolve) => setImmediate(resolve));
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
      stopped: null,
      backoffUntilMs: null,
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

  test("a clock disagreement is reported missed and the store is read again", async () => {
    const storeIdHex = "bb".repeat(32);
    const scanned: bigint[] = [];
    const disagreeing = {
      storeIdHex,
      storeId: new Uint8Array(32).fill(0xbb),
      carrierContextId: new Uint8Array(32).fill(0xbb),
      inert: false,
      stopped: null,
      backoffUntilMs: null,
      faults: [],
      issueToken: (): Promise<boolean> => Promise.resolve(true),
      allocate: (): Promise<null> => Promise.resolve(null),
      append: (): Promise<null> => Promise.resolve(null),
      scanWindow: (window: bigint): Promise<WindowScan> => {
        scanned.push(window);
        return Promise.resolve({
          window,
          status: window === CHAIN_START ? "clock-disagreement" : "finalized",
          objects: [],
          checkpointHash: null,
        });
      },
      recordReceipt: (): void => undefined,
      checkpointHashFor: (): null => null,
    } as unknown as PrototypeStoreClient;
    const harness = harnessFor([disagreeing], windowStart(CHAIN_START));
    harness.runtime.start();
    try {
      await fireUntil(
        harness,
        windowStart(CHAIN_START + 2n) + profile.publicReadOffsetMs,
      );
      expect(
        missedAt(harness.events, CHAIN_START, storeIdHex).filter((event) =>
          (event.detail ?? "").includes("signed clock disagrees"),
        ),
      ).toHaveLength(1);
      expect(
        missedAt(harness.events, CHAIN_START).some((event) =>
          (event.detail ?? "").includes("no store served a finalized read"),
        ),
      ).toBe(true);
      // Not dropped: the next window's read goes to the same store.
      expect(scanned).toContain(CHAIN_START + 1n);
    } finally {
      await harness.runtime.stop();
    }
  });

  test("a caught-up read that meets a clock disagreement is retried once, then missed", async () => {
    const storeIdHex = "cc".repeat(32);
    const scans = new Map<bigint, number>();
    const disagreeing = {
      storeIdHex,
      storeId: new Uint8Array(32).fill(0xcc),
      carrierContextId: new Uint8Array(32).fill(0xcc),
      inert: false,
      stopped: null,
      backoffUntilMs: null,
      faults: [],
      issueToken: (): Promise<boolean> => Promise.resolve(true),
      allocate: (): Promise<null> => Promise.resolve(null),
      append: (): Promise<null> => Promise.resolve(null),
      scanWindow: (window: bigint): Promise<WindowScan> => {
        scans.set(window, (scans.get(window) ?? 0) + 1);
        return Promise.resolve({
          window,
          status: window === CHAIN_START ? "clock-disagreement" : "finalized",
          objects: [],
          checkpointHash: null,
        });
      },
      recordReceipt: (): void => undefined,
      checkpointHashFor: (): null => null,
    } as unknown as PrototypeStoreClient;
    // Suspended from the start: the chain-start window's read is first made
    // as a catch-up read, when the page resumes five windows later.
    const harness = harnessFor(
      [disagreeing],
      windowStart(CHAIN_START + 1n) + 50n,
    );
    harness.runtime.start();
    try {
      harness.nowMs =
        windowStart(CHAIN_START + 6n) + profile.publicReadOffsetMs;
      const first = [...harness.pending.entries()].sort((left, right) =>
        left[1].atMs < right[1].atMs ? -1 : 1,
      )[0];
      if (first === undefined) throw new Error("the schedule was not armed");
      harness.pending.delete(first[0]);
      first[1].callback();
      await harness.runtime.drain();

      const reads = harness.events.filter(
        (event) => event.kind === "scan" && event.window === CHAIN_START,
      );
      // Read twice, both as catch-up reads, and never a third time.
      expect(reads.map((event) => event.detail)).toEqual([
        "clock-disagreement",
        "clock-disagreement",
      ]);
      expect(scans.get(CHAIN_START)).toBe(2);
      const missed = missedAt(harness.events, CHAIN_START, storeIdHex).map(
        (event) => event.detail ?? "",
      );
      expect(
        missed.filter((detail) => detail.includes("signed clock disagrees")),
      ).toHaveLength(2);
      expect(
        missed.filter((detail) =>
          detail.includes("a catch-up read failed twice (clock-disagreement)"),
        ),
      ).toHaveLength(1);
      // The other caught-up windows were read once each.
      expect(scans.get(CHAIN_START + 1n)).toBe(1);
    } finally {
      await harness.runtime.stop();
    }
  });

  test("a client returning from suspension does not silently lose a catch-up window", async () => {
    // The run starts one window after the chain start, so the chain-start
    // window is the oldest its catch-up can reach.
    const clock = { now: windowStart(CHAIN_START + 1n) + 50n };
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
        // Suspended from the start for the runtime's whole catch-up reach:
        // no timer fires until the page resumes 64 windows later, so the
        // oldest window it reads back is the one 65 behind the clock.
        const resumeWindow =
          CHAIN_START + 1n + BigInt(PROTOTYPE_MAX_READ_WINDOWS);
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
            event.window >= CHAIN_START &&
            event.window < resumeWindow - 1n,
        );
        expect(scans.length).toBeGreaterThan(60);
        // The edge the retention floor is derived from: 65 back, read.
        expect(resumeWindow - CHAIN_START).toBe(65n);
        expect(
          scans
            .filter((event) => event.window === CHAIN_START)
            .map((event) => event.detail),
        ).toEqual(["finalized"]);
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

  test("a not-final for a window the client's clock says is long final is a clock disagreement, not a wait", async () => {
    // The re-review's four runs, with the real client and the real core over
    // HTTP under the runtime: the chain-start window W is finalized, and its
    // checkpoint is answered with a `not-final` the store's key signed.
    const seed = new Uint8Array(32).fill(0x5d);
    const secretKey = (await keyPairFromSeed(Uint8Array.from(seed), module))
      .secretKey;
    const W = CHAIN_START;
    const profileHex = [...profileHash]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const runs: {
      readonly name: string;
      /** The window the store states as its own in the `not-final`. */
      readonly stated: bigint;
      /** `null`: the scheduled read. Otherwise the window a suspended page
       * resumes in, which reads W as a catch-up. */
      readonly resumeWindow: bigint | null;
    }[] = [
      { name: "the scheduled read at W + 1", stated: W, resumeWindow: null },
      { name: "a catch-up at W + 10", stated: W, resumeWindow: W + 10n },
      { name: "a catch-up at W + 60", stated: W, resumeWindow: W + 60n },
      {
        name: "a window a thousand back stated at the scheduled read",
        stated: W - 1_000n,
        resumeWindow: null,
      },
    ];

    for (const run of runs) {
      const clock = {
        now:
          run.resumeWindow === null
            ? windowStart(W)
            : windowStart(W + 1n) + 50n,
      };
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
        const core = await PrototypeStoreCore.create({
          module,
          seed,
          profile,
          clock: { nowMs: (): bigint => clock.now },
          persistence: new MemoryStorePersistence(),
          chainStartIngressWindow: W,
          origin,
          descriptorValidityMs: 2_592_000_000n,
        });
        handler = createPrototypeStoreHandler({ core });

        const value = {
          version: 1 as const,
          storeId: core.storeId,
          descriptorHash: core.descriptorHash,
          deliveryProfileHash: profileHash,
          ingressWindow: W,
          storeIngressWindow: run.stated,
          status: "not-final" as const,
        };
        const notFinal = encodePublicStoreCheckpointReadV1({
          kind: "status",
          value,
          storeSignature: await sign(
            await publicCheckpointStatusSigningHash(value),
            secretKey,
            module,
          ),
        });
        const body = new ArrayBuffer(notFinal.byteLength);
        new Uint8Array(body).set(notFinal);
        let stalled = 0;
        const stalling: typeof fetch = ((
          input: RequestInfo | URL,
          init?: RequestInit,
        ) => {
          const url = new URL(String(input));
          if (
            url.pathname ===
            `${PROTOTYPE_STORE_ROUTES.checkpoint}/${profileHex}/${String(W)}`
          ) {
            stalled += 1;
            return Promise.resolve(
              new Response(body.slice(0), {
                status: 200,
                headers: { "x-p2party-store": "prototype-v1" },
              }),
            );
          }
          return fetch(`${origin}${url.pathname}${url.search}`, init);
        }) as typeof fetch;
        const store = await PrototypeStoreClient.connect({
          origin,
          profile,
          profileHash,
          module,
          fetch: stalling,
          nowMs: () => clock.now,
        });

        const harness = harnessFor([store], clock.now);
        const finalize = async (): Promise<void> => {
          clock.now = harness.nowMs;
          while ((await core.finalizeDue()).length > 0);
        };
        harness.runtime.start();
        try {
          if (run.resumeWindow === null) {
            // Through the read of W, made in the window after it.
            await fireUntil(
              harness,
              windowStart(W + 1n) + profile.publicReadOffsetMs,
              finalize,
            );
          } else {
            // Suspended from the start: no timer fires until the page
            // resumes, and W is first read then, as a catch-up.
            harness.nowMs =
              windowStart(run.resumeWindow) + profile.publicReadOffsetMs;
            await finalize();
            const first = [...harness.pending.entries()].sort((left, right) =>
              left[1].atMs < right[1].atMs ? -1 : 1,
            )[0];
            if (first === undefined)
              throw new Error("the schedule was not armed");
            harness.pending.delete(first[0]);
            first[1].callback();
            await harness.runtime.drain();
          }

          // W is finalized at the store: only the stalled answer says not.
          const direct = await core.readCheckpoint(profileHash, W);
          expect([run.name, direct.kind]).toEqual([run.name, "finalized"]);
          const attempts = run.resumeWindow === null ? 1 : 2;
          expect([run.name, stalled]).toEqual([run.name, attempts]);

          // The scan is never `not-final`: each attempt is a disagreement.
          const scans = harness.events
            .filter((event) => event.kind === "scan" && event.window === W)
            .map((event) => event.detail);
          expect([run.name, scans]).toEqual([
            run.name,
            Array.from({ length: attempts }, () => "clock-disagreement"),
          ]);
          // A fault record at the client for each, and no blame.
          expect([
            run.name,
            store.faults.map((fault) => [fault.kind, fault.window]),
          ]).toEqual([
            run.name,
            Array.from({ length: attempts }, () => [
              "store-clock-disagreement",
              W,
            ]),
          ]);
          expect(store.inert).toBe(false);
          // And the window reported missed at this store each time.
          const missed = missedAt(harness.events, W, store.storeIdHex).map(
            (event) => event.detail ?? "",
          );
          expect([
            run.name,
            missed.filter((detail) => detail.includes("signed clock disagrees"))
              .length,
          ]).toEqual([run.name, attempts]);
          expect([
            run.name,
            missed.filter((detail) =>
              detail.includes(
                "a catch-up read failed twice (clock-disagreement)",
              ),
            ).length,
          ]).toEqual([run.name, run.resumeWindow === null ? 0 : 1]);
          expect(
            missedAt(harness.events, W).some((event) =>
              (event.detail ?? "").includes("no store served a finalized read"),
            ),
          ).toBe(true);
          // Every later window the run read came back finalized.
          const others = harness.events.filter(
            (event) => event.kind === "scan" && event.window > W,
          );
          expect(
            others.filter((event) => event.detail !== "finalized"),
          ).toEqual([]);
          if (run.resumeWindow !== null)
            expect(others.length).toBeGreaterThan(
              Number(run.resumeWindow - W) - 3,
            );
        } finally {
          await harness.runtime.stop();
        }
      } finally {
        void server.stop(true);
      }
    }
  }, 60_000);

  test("a read outside the pinned descriptor's validity is reported missed at its store and not retried", async () => {
    const storeIdHex = "dd".repeat(32);
    const scans = new Map<bigint, number>();
    const lapsed = {
      storeIdHex,
      storeId: new Uint8Array(32).fill(0xdd),
      carrierContextId: new Uint8Array(32).fill(0xdd),
      inert: false,
      stopped: null,
      backoffUntilMs: null,
      faults: [],
      issueToken: (): Promise<boolean> => Promise.resolve(true),
      allocate: (): Promise<null> => Promise.resolve(null),
      append: (): Promise<null> => Promise.resolve(null),
      scanWindow: (window: bigint): Promise<WindowScan> => {
        scans.set(window, (scans.get(window) ?? 0) + 1);
        return Promise.resolve({
          window,
          status: "descriptor-out-of-validity",
          objects: [],
          checkpointHash: null,
        });
      },
      recordReceipt: (): void => undefined,
      checkpointHashFor: (): null => null,
    } as unknown as PrototypeStoreClient;
    // Suspended from the start and resumed five windows later: the oldest
    // windows are read as catch-ups, the newest on the schedule.
    const harness = harnessFor([lapsed], windowStart(CHAIN_START + 1n) + 50n);
    harness.runtime.start();
    try {
      harness.nowMs =
        windowStart(CHAIN_START + 6n) + profile.publicReadOffsetMs;
      const first = [...harness.pending.entries()].sort((left, right) =>
        left[1].atMs < right[1].atMs ? -1 : 1,
      )[0];
      if (first === undefined) throw new Error("the schedule was not armed");
      harness.pending.delete(first[0]);
      first[1].callback();
      await harness.runtime.drain();

      const read = [...scans.keys()].sort((left, right) =>
        left < right ? -1 : 1,
      );
      expect(read.length).toBeGreaterThan(3);
      expect(read[0]).toBe(CHAIN_START);
      for (const window of read) {
        // Once each, catch-up or scheduled: the answer cannot change.
        expect([window, scans.get(window)]).toEqual([window, 1]);
        const missed = missedAt(harness.events, window, storeIdHex).map(
          (event) => event.detail ?? "",
        );
        expect([
          window,
          missed.filter((detail) =>
            detail.includes(
              "outside the validity of the store descriptor this client pinned",
            ),
          ).length,
        ]).toEqual([window, 1]);
        expect(
          missed.filter((detail) => detail.includes("failed twice")),
        ).toEqual([]);
        // Never an empty success: the window as a whole is reported too.
        expect(
          missedAt(harness.events, window).some((event) =>
            (event.detail ?? "").includes("no store served a finalized read"),
          ),
        ).toBe(true);
      }
    } finally {
      await harness.runtime.stop();
    }
  });

  /** A store double: answers every write, and each scan as `scan` says. */
  const doubleStore = (
    storeIdHex: string,
    scan: (window: bigint) => Promise<WindowScan>,
    state: { stopped: unknown; backoffUntilMs: bigint | null } = {
      stopped: null,
      backoffUntilMs: null,
    },
    calls: string[] = [],
  ): PrototypeStoreClient =>
    ({
      storeIdHex,
      storeId: new Uint8Array(32).fill(0xee),
      carrierContextId: new Uint8Array(32).fill(0xee),
      inert: false,
      get stopped() {
        return state.stopped;
      },
      get backoffUntilMs() {
        return state.backoffUntilMs;
      },
      faults: [],
      issueToken: (): Promise<boolean> => {
        calls.push("token");
        return Promise.resolve(true);
      },
      allocate: (): Promise<null> => {
        calls.push("allocation");
        return Promise.resolve(null);
      },
      append: (): Promise<null> => {
        calls.push("append");
        return Promise.resolve(null);
      },
      scanWindow: (window: bigint): Promise<WindowScan> => {
        calls.push(`scan ${String(window)}`);
        return scan(window);
      },
      recordReceipt: (): void => undefined,
      checkpointHashFor: (): null => null,
    }) as unknown as PrototypeStoreClient;

  const unreachableScan = (window: bigint): WindowScan => ({
    window,
    status: "unreachable",
    objects: [],
    checkpointHash: null,
  });

  /** Resume a page suspended since the chain start, five windows later. */
  const resumeAfterSuspension = (harness: Harness): void => {
    harness.nowMs = windowStart(CHAIN_START + 6n) + profile.publicReadOffsetMs;
    const first = [...harness.pending.entries()].sort((left, right) =>
      left[1].atMs < right[1].atMs ? -1 : 1,
    )[0];
    if (first === undefined) throw new Error("the schedule was not armed");
    harness.pending.delete(first[0]);
    first[1].callback();
  };

  test("a caught-up read that fails during stop queues nothing", async () => {
    // Twice: the read held is a window's first catch-up attempt, then its
    // last. The resume releases two scheduled reads first (the newest
    // window's, and the one a window late), then the catch-ups of the four
    // older windows, newest first, then their retries.
    for (const holdScan of [3, 7]) {
      const storeIdHex = "ee".repeat(32);
      const scanned: bigint[] = [];
      let release: ((scan: WindowScan) => void) | null = null;
      const store = doubleStore(storeIdHex, (window) => {
        scanned.push(window);
        if (scanned.length === holdScan)
          return new Promise<WindowScan>((resolve) => {
            release = resolve;
          });
        return Promise.resolve(unreachableScan(window));
      });
      const harness = harnessFor([store], windowStart(CHAIN_START + 1n) + 50n);
      harness.runtime.start();
      resumeAfterSuspension(harness);
      await turns();
      if (release === null) throw new Error("the held scan was not made");
      const heldWindow = scanned[holdScan - 1];
      // The read is out when the runtime stops; it then fails.
      harness.runtime.stop();
      const eventsAtStop = harness.events.length;
      (release as (scan: WindowScan) => void)(unreachableScan(heldWindow));
      await harness.runtime.drain();
      // Nothing reported for it after the stop, and nothing queued: a
      // runtime started again does not read the stale window back.
      expect(harness.events.slice(eventsAtStop)).toEqual([]);
      const scansAtStop = scanned.length;
      harness.runtime.start();
      const next = [...harness.pending.entries()].sort((left, right) =>
        left[1].atMs < right[1].atMs ? -1 : 1,
      )[0];
      if (next !== undefined) {
        harness.pending.delete(next[0]);
        harness.nowMs =
          next[1].atMs > harness.nowMs ? next[1].atMs : harness.nowMs;
        next[1].callback();
      }
      await harness.runtime.drain();
      expect([
        holdScan,
        scanned.slice(scansAtStop).includes(heldWindow),
      ]).toEqual([holdScan, false]);
      harness.runtime.stop();
    }
  });

  test("a catch-up waits out its store's back-off instead of asking again at once", async () => {
    const storeIdHex = "ef".repeat(32);
    const state = { stopped: null, backoffUntilMs: null as bigint | null };
    const at: bigint[] = [];
    let harness: Harness | null = null;
    // Every scan meets a 503, and its client backs off for 250 ms.
    const store = doubleStore(
      storeIdHex,
      (window) => {
        const nowMs = harness?.nowMs ?? 0n;
        at.push(nowMs);
        state.backoffUntilMs = nowMs + 250n;
        return Promise.resolve(unreachableScan(window));
      },
      state,
    );
    harness = harnessFor([store], windowStart(CHAIN_START + 1n) + 50n);
    harness.runtime.start();
    try {
      resumeAfterSuspension(harness);
      await harness.runtime.drain();
      const resumedAt = harness.nowMs;
      // The two scheduled reads went out at the resume; the catch-up did
      // not follow them at once: one timer waits for the back-off's end,
      // and nothing is in flight meanwhile.
      expect(at).toEqual([resumedAt, resumedAt]);
      const resumeTimers = [...harness.pending.values()].filter(
        (timer) => timer.atMs === resumedAt + 250n,
      );
      expect(resumeTimers.length).toBe(1);
      // Each catch-up read is then a back-off after the one before, never at
      // request rate, until the next window's events.
      await fireUntil(harness, resumedAt + 3_500n);
      const caughtUp = at.slice(2);
      expect(caughtUp.length).toBeGreaterThan(3);
      expect(caughtUp[0]).toBe(resumedAt + 250n);
      for (let index = 1; index < caughtUp.length; index++)
        expect(caughtUp[index] - caughtUp[index - 1] >= 250n).toBe(true);
    } finally {
      harness.runtime.stop();
    }
  });

  test("a store its client stopped using is asked nothing and reported once", async () => {
    const storeIdHex = "fa".repeat(32);
    const state = { stopped: null as unknown, backoffUntilMs: null };
    const calls: string[] = [];
    const store = doubleStore(
      storeIdHex,
      (window) =>
        Promise.resolve({
          window,
          status: "finalized",
          objects: [],
          checkpointHash: new Uint8Array(32),
        }),
      state,
      calls,
    );
    const harness = harnessFor([store], windowStart(CHAIN_START + 1n));
    harness.runtime.start();
    try {
      await fireUntil(harness, windowStart(CHAIN_START + 2n) - 1n);
      expect(calls.length).toBeGreaterThan(0);
      // The client stops using the store (its own event said so, once).
      state.stopped = { reason: "descriptor-expired" };
      const callsAtStop = calls.length;
      const eventsAtStop = harness.events.length;
      await fireUntil(harness, windowStart(CHAIN_START + 12n));
      // Not one request in ten windows, and no event per request or per
      // read at this store; each window's read is settled as given up.
      expect(calls.slice(callsAtStop)).toEqual([]);
      const after = harness.events.slice(eventsAtStop);
      expect(after.filter((event) => event.storeIdHex === storeIdHex)).toEqual(
        [],
      );
      expect(
        after.filter((event) =>
          (event.detail ?? "").includes("no store served a finalized read"),
        ).length,
      ).toBe(10);
    } finally {
      harness.runtime.stop();
    }
  });
});
