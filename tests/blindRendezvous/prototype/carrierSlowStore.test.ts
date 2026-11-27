import { createHash, createHmac } from "node:crypto";

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../../src/cryptography/testModule";
import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import {
  ingressWindow,
  ingressWindowStartMs,
} from "../../../src/blindRendezvous/publicWindow";
import { CarrierRuntime } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";

import type {
  CarrierEvent,
  CarrierTimers,
} from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type {
  PrototypeStoreClient,
  WindowScan,
} from "../../../src/blindRendezvous/prototype/storeClient";

/*
 * Stores that take time to answer, behind a connection pool, on a fake clock.
 *
 * The world in `carrierRuntime.test.ts` answers every request as fast as a
 * loopback server can, and settles all of it before the clock moves, so it
 * cannot show what happens while a request is still out. Here every request
 * holds one of a store's connections for a set service time, a store has as
 * many connections as a browser opens to one origin, a request queued behind
 * a full pool waits, and a request that has not answered one delivery window
 * after it was issued fails — which is what `storeClient.ts`'s
 * `requestDeadlineMs` does, counting time spent queued in the browser.
 *
 * Determinism: WebCrypto resolves on a worker thread, so for this file only
 * `crypto.subtle`'s three methods the code under test uses are replaced by
 * node:crypto's synchronous equivalents. Every piece of work a timer starts
 * then settles within one turn of the event loop or waits on a later fake
 * timer, and `SimLoop` runs the timers strictly in fake-time order.
 */

const module = await loadTestModule();
const profile = PROTOTYPE_DELIVERY_PROFILE_V0;
const profileHash = await deliveryProfileHash(profile);
const WINDOW_MS = profile.deliveryWindowMs;
/** 1_800_000_000_000 / 4_000 is exact: the run starts on a window edge. */
const START_MS = 1_800_000_000_000n;
const windowOf = (atMs: bigint): bigint => ingressWindow(WINDOW_MS, atMs);
const startOf = (window: bigint): bigint =>
  ingressWindowStartMs(window, WINDOW_MS);
const CHUNKS_PER_SCAN = profile.sizeClasses.reduce(
  (total, sizeClass) => total + sizeClass.publicChunksPerWindow,
  0,
);
/** Chromium's limit on concurrent HTTP/1.1 connections to one origin. */
const CONNECTIONS_PER_ORIGIN = 6;

/* ------------------------------------------------------------------ *
 * Synchronous digest and HMAC, for this file only
 * ------------------------------------------------------------------ */

const asBytes = (data: ArrayBuffer | ArrayBufferView): Uint8Array =>
  ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data);

const asArrayBuffer = (digest: Uint8Array): ArrayBuffer => {
  const output = new ArrayBuffer(digest.length);
  new Uint8Array(output).set(digest);
  return output;
};

let restoreSubtle = (): void => undefined;

beforeAll(() => {
  const subtle = globalThis.crypto.subtle as unknown as Record<string, unknown>;
  const keys = new WeakMap<object, Uint8Array>();
  const define = (name: string, value: unknown): void => {
    Object.defineProperty(subtle, name, {
      configurable: true,
      writable: true,
      value,
    });
  };
  define("digest", (algorithm: unknown, data: ArrayBuffer | ArrayBufferView) =>
    algorithm === "SHA-256"
      ? Promise.resolve(
          asArrayBuffer(createHash("sha256").update(asBytes(data)).digest()),
        )
      : Promise.reject(new Error("only SHA-256 is simulated")),
  );
  define(
    "importKey",
    (
      format: unknown,
      keyData: ArrayBuffer | ArrayBufferView,
      algorithm: { readonly name?: unknown; readonly hash?: unknown },
    ) => {
      if (
        format !== "raw" ||
        algorithm.name !== "HMAC" ||
        algorithm.hash !== "SHA-256"
      )
        return Promise.reject(new Error("only raw HMAC-SHA-256 is simulated"));
      const key = {};
      keys.set(key, Uint8Array.from(asBytes(keyData)));
      return Promise.resolve(key);
    },
  );
  define(
    "sign",
    (algorithm: unknown, key: object, data: ArrayBuffer | ArrayBufferView) => {
      const raw = keys.get(key);
      if (algorithm !== "HMAC" || raw === undefined)
        return Promise.reject(new Error("only simulated HMAC keys sign"));
      return Promise.resolve(
        asArrayBuffer(createHmac("sha256", raw).update(asBytes(data)).digest()),
      );
    },
  );
  restoreSubtle = (): void => {
    for (const name of ["digest", "importKey", "sign"]) delete subtle[name];
  };
});

afterAll(() => {
  restoreSubtle();
});

/* ------------------------------------------------------------------ *
 * A fake clock that runs every timer in order
 * ------------------------------------------------------------------ */

/** One turn of the event loop: every microtask has run when it returns. */
const turn = (): Promise<void> =>
  new Promise<void>((resolve) => setImmediate(resolve));

class SimLoop {
  nowMs: bigint;
  #nextId = 1;
  #nextSequence = 0;
  readonly #timers = new Map<
    number,
    { readonly atMs: bigint; readonly sequence: number; run(): void }
  >();

  readonly clock = { nowMs: (): bigint => this.nowMs };
  readonly timers: CarrierTimers = {
    setTimeout: (callback, delayMs) =>
      this.at(this.nowMs + BigInt(Math.max(0, Math.trunc(delayMs))), callback),
    clearTimeout: (handle) => {
      this.cancel(handle as number);
    },
  };

  constructor(startMs: bigint) {
    this.nowMs = startMs;
  }

  at(atMs: bigint, run: () => void): number {
    const id = this.#nextId++;
    this.#timers.set(id, { atMs, sequence: this.#nextSequence++, run });
    return id;
  }

  cancel(id: number): void {
    this.#timers.delete(id);
  }

  /** Fire every timer due by `targetMs` in `(atMs, arming order)` order. A
   * timer due before `nowMs` — a page that was frozen — fires late, at
   * `nowMs`; the clock never moves backwards. */
  async runUntil(targetMs: bigint): Promise<void> {
    await turn();
    for (;;) {
      let nextId: number | null = null;
      for (const [id, timer] of this.#timers) {
        if (timer.atMs > targetMs) continue;
        const current = nextId === null ? null : this.#timers.get(nextId);
        if (
          current === null ||
          current === undefined ||
          timer.atMs < current.atMs ||
          (timer.atMs === current.atMs && timer.sequence < current.sequence)
        )
          nextId = id;
      }
      if (nextId === null) break;
      const timer = this.#timers.get(nextId);
      this.#timers.delete(nextId);
      if (timer === undefined) continue;
      if (timer.atMs > this.nowMs) this.nowMs = timer.atMs;
      timer.run();
      await turn();
      await turn();
    }
    if (targetMs > this.nowMs) this.nowMs = targetMs;
  }
}

/* ------------------------------------------------------------------ *
 * One origin: a bounded pool of connections with a service time
 * ------------------------------------------------------------------ */

type Route =
  | "token"
  | "allocation"
  | "append"
  | "checkpoint"
  | "chunk"
  | "witness-post"
  | "witness-get";

interface RequestRecord {
  readonly route: Route;
  /** The window the request names. */
  readonly window: bigint;
  readonly issuedAtMs: bigint;
  settledAtMs: bigint | null;
  /** Answered within the deadline, or not. */
  ok: boolean | null;
}

class OriginPool {
  readonly log: RequestRecord[] = [];
  #active = 0;
  readonly #queued: (() => void)[] = [];

  constructor(
    private readonly loop: SimLoop,
    private readonly serviceMs: (route: Route) => bigint,
  ) {}

  request(route: Route, window: bigint): Promise<boolean> {
    const loop = this.loop;
    const record: RequestRecord = {
      route,
      window,
      issuedAtMs: loop.nowMs,
      settledAtMs: null,
      ok: null,
    };
    this.log.push(record);
    return new Promise<boolean>((resolve) => {
      const settle = (ok: boolean): void => {
        if (record.ok !== null) return;
        record.ok = ok;
        record.settledAtMs = loop.nowMs;
        loop.cancel(deadline);
        resolve(ok);
      };
      // The client's deadline runs from issue, queueing included. A request
      // that times out on a connection keeps it until the service ends.
      const deadline = loop.at(record.issuedAtMs + WINDOW_MS, () => {
        settle(false);
      });
      this.#queued.push(() => {
        if (record.ok !== null) return;
        this.#active += 1;
        loop.at(loop.nowMs + this.serviceMs(route), () => {
          this.#active -= 1;
          settle(true);
          this.#pump();
        });
      });
      this.#pump();
    });
  }

  #pump(): void {
    while (this.#active < CONNECTIONS_PER_ORIGIN && this.#queued.length > 0)
      this.#queued.shift()?.();
  }
}

/* ------------------------------------------------------------------ *
 * A store client over one pool
 * ------------------------------------------------------------------ */

interface ScanRecord {
  readonly window: bigint;
  readonly issuedAtMs: bigint;
  settledAtMs: bigint | null;
  status: WindowScan["status"] | null;
}

interface SlowStore {
  readonly client: PrototypeStoreClient;
  readonly pool: OriginPool;
  readonly scans: ScanRecord[];
}

const slowStore = (
  loop: SimLoop,
  tag: number,
  serviceMs: (route: Route) => bigint,
  options: {
    /** Fail this store's scan of `window` on this attempt, whatever the
     * requests answered. */
    readonly failScan?: (window: bigint, attempt: number) => boolean;
  } = {},
): SlowStore => {
  const pool = new OriginPool(loop, serviceMs);
  const scans: ScanRecord[] = [];
  const finalized = new Set<string>();
  const client = {
    storeIdHex: tag.toString(16).padStart(2, "0").repeat(32),
    storeId: new Uint8Array(32).fill(tag),
    carrierContextId: new Uint8Array(32).fill(tag),
    inert: false,
    stopped: null,
    backoffUntilMs: null,
    faults: [],
    issueToken: (window: bigint): Promise<boolean> =>
      pool.request("token", window),
    allocate: async (window: bigint): Promise<null> => {
      await pool.request("allocation", window);
      return null;
    },
    append: async (window: bigint): Promise<{ status: string } | null> =>
      (await pool.request("append", window))
        ? { status: "unallocated-cover" }
        : null,
    scanWindow: async (window: bigint): Promise<WindowScan> => {
      const record: ScanRecord = {
        window,
        issuedAtMs: loop.nowMs,
        settledAtMs: null,
        status: null,
      };
      scans.push(record);
      const attempt = scans.filter((scan) => scan.window === window).length;
      const answered = await Promise.all([
        pool.request("checkpoint", window),
        ...Array.from({ length: CHUNKS_PER_SCAN }, () =>
          pool.request("chunk", window),
        ),
      ]);
      const status: WindowScan["status"] =
        answered.every(Boolean) && options.failScan?.(window, attempt) !== true
          ? "finalized"
          : "unreachable";
      if (status === "finalized") finalized.add(String(window));
      record.settledAtMs = loop.nowMs;
      record.status = status;
      return {
        window,
        status,
        objects: [],
        checkpointHash: status === "finalized" ? new Uint8Array(32) : null,
      };
    },
    recordReceipt: (): void => undefined,
    checkpointHashFor: (window: bigint): Uint8Array | null =>
      finalized.has(String(window)) ? new Uint8Array(32).fill(0xcc) : null,
    postWitness: (record: { readonly ingressWindow: bigint }) =>
      pool.request("witness-post", record.ingressWindow),
    readWitnesses: async (window: bigint): Promise<never[]> => {
      await pool.request("witness-get", window);
      return [];
    },
  } as unknown as PrototypeStoreClient;
  return { client, pool, scans };
};

const startRuntime = (
  loop: SimLoop,
  stores: readonly SlowStore[],
  events: CarrierEvent[],
): CarrierRuntime => {
  const runtime = new CarrierRuntime({
    module,
    roomRoot: new Uint8Array(32).fill(0x2b),
    profile,
    profileHash,
    stores: stores.map((store) => store.client),
    validationContextAt: () => {
      throw new Error("no scan here returns an object to open");
    },
    logicalWindowMs: 60_000n,
    clock: loop.clock,
    timers: loop.timers,
    onOperations: () => undefined,
    onEvent: (event) => events.push(event),
  });
  runtime.start();
  return runtime;
};

/** Every offset of the profile's fixed requests within one window. */
const SCHEDULED_OFFSETS: Readonly<Record<string, readonly bigint[]>> = {
  token: [profile.tokenIssueOffsetMs],
  allocation: [profile.allocationRequestOffsetMs],
  append: profile.sizeClasses
    .flatMap((sizeClass) => sizeClass.appendSchedule.map((e) => e.offsetMs))
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
  checkpoint: [profile.publicReadOffsetMs],
  chunk: Array.from(
    { length: CHUNKS_PER_SCAN },
    () => profile.publicReadOffsetMs,
  ),
};

/* ------------------------------------------------------------------ *
 * The witness instant
 * ------------------------------------------------------------------ */

describe("prototype carrier runtime with slow stores", () => {
  test("a slow store cannot move the witness instant", async () => {
    const loop = new SimLoop(START_MS);
    const a = slowStore(loop, 0xa1, () => 20n);
    // Store B answers scan requests after 2,500 ms, so its read of the
    // previous window — issued at 600 — answers at 3,100: after the witness
    // instant, `chunkFinalizationOffsetMs - maxScheduleSkewMs` = 2,600.
    const b = slowStore(loop, 0xb2, (route) =>
      route === "checkpoint" || route === "chunk" ? 2_500n : 20n,
    );
    const events: CarrierEvent[] = [];
    const runtime = startRuntime(loop, [a, b], events);
    try {
      const window = windowOf(START_MS) + 2n;
      await loop.runUntil(startOf(window + 1n));

      const witnessRequests = (store: SlowStore): string[] =>
        store.pool.log
          .filter(
            (request) =>
              request.route.startsWith("witness") &&
              request.issuedAtMs >= startOf(window) &&
              request.issuedAtMs < startOf(window + 1n),
          )
          .map(
            (request) =>
              `${request.route} @${String(request.issuedAtMs - startOf(window))}`,
          );
      const instant =
        profile.chunkFinalizationOffsetMs - profile.maxScheduleSkewMs;

      // B's scan answered, finalized, after the instant ...
      const late = b.scans.find((scan) => scan.window === window - 1n);
      expect(late?.status).toBe("finalized");
      expect(late?.settledAtMs).toBe(
        startOf(window) + profile.publicReadOffsetMs + 2_500n,
      );
      // ... so the pair about B is not sent to A at all — not at the
      // instant, and not when B's answer comes in ...
      expect(witnessRequests(a)).toEqual([]);
      expect(
        events.filter(
          (event) =>
            event.kind === "missed" &&
            event.storeIdHex === a.client.storeIdHex &&
            event.window === window - 1n &&
            (event.detail ?? "").includes("had not answered"),
        ),
      ).toHaveLength(1);
      // ... while the pair about A, whose scan had answered, leaves for B at
      // the instant.
      expect(witnessRequests(b)[0]).toBe(`witness-post @${String(instant)}`);
    } finally {
      runtime.stop();
    }
  });
});

/* ------------------------------------------------------------------ *
 * Catch-up after a suspension
 * ------------------------------------------------------------------ */

interface Resumed {
  readonly stores: readonly SlowStore[];
  readonly events: CarrierEvent[];
  readonly resumedAtMs: bigint;
  /** Reads of windows at or below this are the catch-up's: everything older
   * than the last read the resumed timer releases on time. */
  readonly lastCaughtUpWindow: bigint;
}

/**
 * Run two windows, freeze the page for `suspendedWindows` windows, resume it
 * half a second into a window, and run `runWindows` more.
 */
const resumeAfterSuspension = async (options: {
  readonly suspendedWindows: bigint;
  readonly runWindows: bigint;
  readonly failScanAtA?: (window: bigint, attempt: number) => boolean;
}): Promise<Resumed> => {
  const loop = new SimLoop(START_MS);
  // Every request holds a connection for 150 ms: a store under load.
  const stores = [
    slowStore(loop, 0xa1, () => 150n, { failScan: options.failScanAtA }),
    slowStore(loop, 0xb2, () => 150n),
  ];
  const events: CarrierEvent[] = [];
  const runtime = startRuntime(loop, stores, events);
  try {
    await loop.runUntil(startOf(windowOf(START_MS) + 2n));
    // Frozen: nothing runs, then everything that came due is delivered at
    // once, late, at the resumed clock.
    const resumedAtMs =
      loop.nowMs + options.suspendedWindows * WINDOW_MS + 500n;
    loop.nowMs = resumedAtMs;
    await loop.runUntil(resumedAtMs + options.runWindows * WINDOW_MS);
    return {
      stores,
      events,
      resumedAtMs,
      // The resumed timer releases the read due one window before it
      // on time-ish (it is less than a window late); every older read is
      // caught up. That read is of window `windowOf(resumedAtMs) - 2`.
      lastCaughtUpWindow: windowOf(resumedAtMs) - 3n,
    };
  } finally {
    runtime.stop();
  }
};

const catchUpScans = (store: SlowStore, resumed: Resumed): ScanRecord[] =>
  store.scans.filter(
    (scan) =>
      scan.issuedAtMs >= resumed.resumedAtMs &&
      scan.window <= resumed.lastCaughtUpWindow,
  );

/** The most catch-up scans one store ever had out at the same time. */
const mostInFlight = (scans: readonly ScanRecord[]): number => {
  const edges = scans.flatMap((scan) => [
    { atMs: scan.issuedAtMs, delta: 1 },
    { atMs: scan.settledAtMs ?? 2n ** 62n, delta: -1 },
  ]);
  // An end and a start at one instant do not overlap: ends sort first.
  edges.sort((left, right) =>
    left.atMs !== right.atMs
      ? left.atMs < right.atMs
        ? -1
        : 1
      : left.delta - right.delta,
  );
  let current = 0;
  let most = 0;
  for (const edge of edges) {
    current += edge.delta;
    most = Math.max(most, current);
  }
  return most;
};

describe("prototype carrier runtime catching up after a suspension", () => {
  test("catch-up keeps one scan in flight per store", async () => {
    const resumed = await resumeAfterSuspension({
      suspendedWindows: 64n,
      runWindows: 12n,
    });
    // Two windows ran before the freeze, so the oldest read owed is of the
    // window after the first one.
    const oldestOwed = windowOf(START_MS) + 1n;
    for (const store of resumed.stores) {
      const scans = catchUpScans(store, resumed);
      expect(mostInFlight(scans)).toBe(1);
      // Newest first, every one finalized ...
      expect(scans.map((scan) => scan.window)).toEqual(
        Array.from(
          { length: scans.length },
          (_, index) => resumed.lastCaughtUpWindow - BigInt(index),
        ),
      );
      expect(scans.every((scan) => scan.status === "finalized")).toBe(true);
      // ... and what the catch-up did not reach before the reach moved past
      // it is the oldest windows, each reported.
      const dropped = resumed.events
        .filter(
          (event) =>
            event.kind === "missed" &&
            event.storeIdHex === store.client.storeIdHex &&
            (event.detail ?? "").includes("left the catch-up reach"),
        )
        .map((event) => event.window);
      expect([...scans.map((scan) => scan.window), ...dropped]).toEqual(
        Array.from(
          { length: Number(resumed.lastCaughtUpWindow - oldestOwed + 1n) },
          (_, index) => resumed.lastCaughtUpWindow - BigInt(index),
        ),
      );
      expect(scans.length).toBeGreaterThan(dropped.length);
    }
  }, 120_000);

  test("catch-up never delays the current window's events", async () => {
    const resumed = await resumeAfterSuspension({
      suspendedWindows: 64n,
      runWindows: 12n,
    });
    const resumedWindow = windowOf(resumed.resumedAtMs);
    for (const store of resumed.stores) {
      const caughtUp = new Set(catchUpScans(store, resumed));
      const scheduled = store.pool.log.filter(
        (request) =>
          request.issuedAtMs >= resumed.resumedAtMs &&
          !(
            (request.route === "checkpoint" || request.route === "chunk") &&
            request.window <= resumed.lastCaughtUpWindow
          ),
      );
      // Every scheduled request after the resume answered within its
      // deadline, catch-up running or not.
      expect(scheduled.length).toBeGreaterThan(0);
      expect(scheduled.filter((request) => request.ok !== true)).toEqual([]);

      // In each whole window the catch-up was still running, the fixed
      // requests left at their own offsets.
      const lastCatchUpAtMs = [...caughtUp].reduce(
        (latest, scan) => (scan.issuedAtMs > latest ? scan.issuedAtMs : latest),
        0n,
      );
      let windowsChecked = 0;
      for (
        let window = resumedWindow + 1n;
        startOf(window) < lastCatchUpAtMs;
        window += 1n
      ) {
        windowsChecked += 1;
        for (const [route, offsets] of Object.entries(SCHEDULED_OFFSETS))
          expect(
            scheduled
              .filter(
                (request) =>
                  request.route === route &&
                  request.issuedAtMs >= startOf(window) &&
                  request.issuedAtMs < startOf(window + 1n),
              )
              .map((request) => request.issuedAtMs - startOf(window))
              .sort((left, right) =>
                left < right ? -1 : left > right ? 1 : 0,
              ),
          ).toEqual([...offsets]);
      }
      // The catch-up did overlap whole windows; otherwise this proves nothing.
      expect(windowsChecked).toBeGreaterThan(0);
    }
  }, 120_000);

  test("a failed catch-up scan is retried once then reported missed", async () => {
    // Two windows run, six frozen, resume half a second into window R; the
    // catch-up then reads R-3 down to R-7. At store A, R-5 fails every time
    // and R-4 only the first time.
    const suspendedWindows = 6n;
    const resumedWindow = windowOf(START_MS) + 2n + suspendedWindows;
    const alwaysFails = resumedWindow - 5n;
    const failsOnce = resumedWindow - 4n;
    const run = await resumeAfterSuspension({
      suspendedWindows,
      runWindows: 4n,
      failScanAtA: (window, attempt) =>
        window === alwaysFails || (window === failsOnce && attempt === 1),
    });
    expect(windowOf(run.resumedAtMs)).toBe(resumedWindow);
    const [a, b] = run.stores;

    // Newest first; each failure goes to the back, once.
    expect(catchUpScans(a, run).map((scan) => scan.window)).toEqual([
      resumedWindow - 3n,
      resumedWindow - 4n,
      resumedWindow - 5n,
      resumedWindow - 6n,
      resumedWindow - 7n,
      resumedWindow - 4n,
      resumedWindow - 5n,
    ]);
    expect(catchUpScans(b, run).map((scan) => scan.window)).toEqual([
      resumedWindow - 3n,
      resumedWindow - 4n,
      resumedWindow - 5n,
      resumedWindow - 6n,
      resumedWindow - 7n,
    ]);
    const missed = run.events.filter(
      (event) =>
        event.kind === "missed" &&
        (event.detail ?? "").includes("failed twice"),
    );
    expect(missed.map((event) => [event.storeIdHex, event.window])).toEqual([
      [a.client.storeIdHex, alwaysFails],
    ]);
    // Store B served that window, so the window itself was read.
    expect(
      run.events.filter(
        (event) =>
          event.kind === "missed" &&
          (event.detail ?? "").includes("no store served"),
      ),
    ).toEqual([]);
  }, 120_000);
});
