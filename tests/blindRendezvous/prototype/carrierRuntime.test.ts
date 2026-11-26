import { readFileSync } from "node:fs";

import { describe, expect, test } from "bun:test";

import { newKeyPair } from "../../../src/cryptography/ed25519";
import { loadTestModule } from "../../../src/cryptography/testModule";
import {
  buildCarrierPlaintext,
  createCarrierAeadProvider,
  decodeCarrierEnvelope,
  encodeCarrierEnvelope,
  envelopesAreCarrierSeparated,
  openCarrierEnvelope,
  sealCarrierEnvelope,
} from "../../../src/blindRendezvous/carrierEnvelope";
import {
  deliveryProfileHash,
  policyHash,
  roomRoot,
} from "../../../src/blindRendezvous/derivations";
import {
  createOperationValidationContext,
  decodeOperation,
  deriveOperationId,
  encodeOperation,
  operationValidationContextAt,
} from "../../../src/blindRendezvous/operation";
import {
  ingressWindow,
  ingressWindowStartMs,
} from "../../../src/blindRendezvous/publicWindow";
import { copyBlindDefaultPolicy } from "../../../src/blindRendezvous/roomPolicyV4";
import { CarrierRuntime } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import {
  BlindRendezvousRun,
  PrototypeRunTimeoutError,
  assembleRun,
} from "../../../src/blindRendezvous/prototype/index";
import { PairDriver } from "../../../src/blindRendezvous/prototype/pairDriver";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  carrierObjectWireBytes,
  validateDeliveryProfileGeometry,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import {
  PrototypeStoreClient,
  buildAppendAdmission,
} from "../../../src/blindRendezvous/prototype/storeClient";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../../../src/blindRendezvous/prototype/storeRoutes";
import {
  decodePublicAppendRequestV1,
  encodeStoreWitnessRecordsV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";
import { generateSessionIdentity } from "../../../src/session";

import type { CarrierEnvelopeV1 } from "../../../src/blindRendezvous/carrierEnvelope";
import type { OuterValidatedIdentifiedOperationV1 } from "../../../src/blindRendezvous/coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  OperationValidationContext,
} from "../../../src/blindRendezvous/operation";
import type {
  CarrierEvent,
  CarrierTimers,
} from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type {
  RunTransport,
  SessionTransportProvider,
} from "../../../src/blindRendezvous/prototype/index";
import type { DeliveryProfileV1 } from "../../../src/blindRendezvous/prototype/profile";
import type {
  HandoffFacts,
  TransportCandidateProvider,
} from "../../../src/blindRendezvous/prototype/pairDriver";
import type { StoreWitnessRecordV1 } from "../../../src/blindRendezvous/prototype/storeWire";

const module = await loadTestModule();

const wasmFileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(wasmFileBytes.byteLength);
new Uint8Array(wasmBinary).set(wasmFileBytes);

/** One stable identity is enough: every room below uses a fresh capability, a
 * fresh author epoch key and a fresh presence, and none of them pairs. */
const sessionIdentity = await generateSessionIdentity({ wasmBinary });
sessionIdentity.x25519SecretKey.fill(0);

const profile = withDeliveryWindowMs(PROTOTYPE_DELIVERY_PROFILE_V0, 4_000n);
const PROFILE_HASH = await deliveryProfileHash(profile);
const POLICY = copyBlindDefaultPolicy();
const LOGICAL_WINDOW_MS = POLICY.protocolLimits.logicalWindowMs;
const AEAD = createCarrierAeadProvider(module);

/** 1_800_000_000_000 / 4_000 is exact, so the run starts on a window edge. It
 * divides the shorter window used by the stall test below exactly too. */
const START_MS = 1_800_000_000_000n;
/** The chain start of a world running `worldProfile`: whichever window
 * `START_MS` falls on, so a world at any window length starts on its own edge
 * rather than on the pinned profile's. */
const chainStartOf = (worldProfile: DeliveryProfileV1): bigint =>
  START_MS / worldProfile.deliveryWindowMs;
const CHAIN_START = chainStartOf(profile);
const windowStartMs = (window: bigint): bigint =>
  ingressWindowStartMs(window, profile.deliveryWindowMs);

/** Σ over classes of the class's scheduled appends, at one room slot. */
const APPENDS_PER_WINDOW = profile.sizeClasses.reduce(
  (total, sizeClass) => total + sizeClass.appendSchedule.length,
  0,
);
/** Σ over classes of publicChunksPerWindow: the fixed chunk GETs of one scan. */
const CHUNKS_PER_WINDOW = profile.sizeClasses.reduce(
  (total, sizeClass) => total + sizeClass.publicChunksPerWindow,
  0,
);

/**
 * The pinned profile with class 0 too small for a PRESENCE.
 *
 * It is a legitimate profile — `validateDeliveryProfileGeometry` accepts it,
 * because the geometry rules say nothing about whether a class is big enough
 * for the operations a room happens to publish — which is exactly how an
 * operator would arrive at one.
 */
const undersizedProfile: DeliveryProfileV1 = {
  ...profile,
  sizeClasses: profile.sizeClasses.map((sizeClass) =>
    sizeClass.id === 0
      ? { ...sizeClass, fixedCarrierObjectBytes: 1_024 }
      : sizeClass,
  ),
};
validateDeliveryProfileGeometry(undersizedProfile);

/**
 * The pinned geometry rescaled to a 1,000 ms window, for the stall test alone.
 *
 * A stalled request is settled by its own deadline, and that deadline is one
 * delivery window (`storeClient.ts`, `requestDeadlineMs`), so the window length
 * is literally what a stall costs this file in wall clock. `withDeliveryWindowMs`
 * re-validates every geometry inequality, and `START_MS` divides by 1,000
 * exactly, so this world still starts on a window edge like every other.
 */
const stalledStoreProfile = withDeliveryWindowMs(
  PROTOTYPE_DELIVERY_PROFILE_V0,
  1_000n,
);
const STALL_CHAIN_START = chainStartOf(stalledStoreProfile);
const stallWindowStartMs = (window: bigint): bigint =>
  ingressWindowStartMs(window, stalledStoreProfile.deliveryWindowMs);

/**
 * `CarrierTimers` claims the engine's own globals are assignable to it. This
 * is that claim, checked by the compiler on every run: a production caller
 * forced to cast here would mean the type had drifted.
 */
const realTimers: CarrierTimers = { setTimeout, clearTimeout };

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};

/** `lib.dom`'s `BodyInit` is narrower than the codecs' `Uint8Array`. */
const asBody = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

/* ------------------------------------------------------------------ *
 * A deterministic clock and timer queue
 * ------------------------------------------------------------------ */

interface PendingTimer {
  readonly id: number;
  readonly dueMs: bigint;
  readonly sequence: number;
  readonly callback: () => void;
}

/**
 * How late the engine delivers a timer, which is the one thing a page does not
 * control: a busy main thread adds a constant, a background tab clamps every
 * timer up to the next whole second, and a single stall delays one callback.
 */
interface TimerLateness {
  /** Added to every timer. */
  readonly everyMs?: bigint;
  /** Delivery is rounded up to the next `phaseMs + k * alignMs`. */
  readonly alignMs?: bigint;
  readonly phaseMs?: bigint;
  /** One extra delay for the timer that was due at exactly `onceAtMs`. */
  readonly onceAtMs?: bigint;
  readonly onceByMs?: bigint;
}

/**
 * The whole point of the runtime taking its clock and timers from options: the
 * schedule is driven here, event by event, with no wall clock and no real
 * delay. `advanceTo` fires every timer due at or before the target in
 * `(dueMs, arming order)` order and settles the work each one released before
 * the next one fires, so a run is reproducible.
 */
class FakeScheduler {
  nowMs: bigint;
  /** Applied to every timer armed from now on; `null` delivers on time. */
  lateness: TimerLateness | null = null;

  readonly clock = { nowMs: (): bigint => this.nowMs };

  readonly timers = {
    setTimeout: (callback: () => void, delayMs: number): number => {
      const id = this.#nextId++;
      const delay = BigInt(Math.max(0, Math.trunc(delayMs)));
      this.#pending.set(id, {
        id,
        dueMs: this.#deliveredAt(this.nowMs + delay),
        sequence: this.#nextSequence++,
        callback,
      });
      return id;
    },
    clearTimeout: (handle: number): void => {
      this.#pending.delete(handle);
    },
  };

  #nextId = 1;
  #nextSequence = 0;
  readonly #pending = new Map<number, PendingTimer>();

  constructor(startMs: bigint) {
    this.nowMs = startMs;
  }

  get pendingCount(): number {
    return this.#pending.size;
  }

  #deliveredAt(dueMs: bigint): bigint {
    const lateness = this.lateness;
    if (lateness === null) return dueMs;
    let atMs = dueMs + (lateness.everyMs ?? 0n);
    if (lateness.onceAtMs === dueMs) atMs += lateness.onceByMs ?? 0n;
    const alignMs = lateness.alignMs ?? 0n;
    if (alignMs > 0n) {
      const phaseMs = lateness.phaseMs ?? 0n;
      atMs = ((atMs - phaseMs + alignMs - 1n) / alignMs) * alignMs + phaseMs;
    }
    return atMs;
  }

  async advanceTo(
    targetMs: bigint,
    settle: () => Promise<void>,
  ): Promise<void> {
    for (let guard = 0; guard < 10_000; guard += 1) {
      let due: PendingTimer | null = null;
      for (const timer of this.#pending.values()) {
        if (timer.dueMs > targetMs) continue;
        if (
          due === null ||
          timer.dueMs < due.dueMs ||
          (timer.dueMs === due.dueMs && timer.sequence < due.sequence)
        )
          due = timer;
      }
      if (due === null) break;
      // Never backwards: work a callback did may have moved the clock past
      // the next timer, and that timer is then simply delivered late.
      if (due.dueMs > this.nowMs) this.nowMs = due.dueMs;
      this.#pending.delete(due.id);
      await settle();
      due.callback();
      await settle();
    }
    if (targetMs > this.nowMs) this.nowMs = targetMs;
    await settle();
  }
}

/* ------------------------------------------------------------------ *
 * Two store processes, and a transport that records every request
 * ------------------------------------------------------------------ */

interface StoreProcess {
  readonly core: PrototypeStoreCore;
  readonly origin: string;
  readonly stop: () => void;
}

const startStore = async (
  scheduler: FakeScheduler,
  storeProfile: DeliveryProfileV1,
  options: { seed: Uint8Array; fault?: "withhold" | null },
): Promise<StoreProcess> => {
  let handler: ((request: Request) => Promise<Response>) | null = null;
  const server = Bun.serve({
    port: 0,
    fetch: (request: Request): Response | Promise<Response> =>
      handler === null
        ? new Response("not ready", { status: 503 })
        : handler(request),
  });
  const origin = server.url.origin;
  const core = await PrototypeStoreCore.create({
    module,
    seed: options.seed,
    profile: storeProfile,
    clock: { nowMs: (): bigint => scheduler.nowMs },
    persistence: new MemoryStorePersistence(),
    chainStartIngressWindow: chainStartOf(storeProfile),
    origin,
    descriptorValidityMs: 2_592_000_000n,
    fault: options.fault ?? null,
  });
  handler = createPrototypeStoreHandler({ core });
  return {
    core,
    origin,
    stop: (): void => {
      void server.stop(true);
    },
  };
};

interface RequestRecord {
  readonly path: string;
  readonly method: string;
  readonly atMs: bigint;
  readonly body: Uint8Array | null;
}

interface Transport {
  readonly log: RequestRecord[];
  /** Flipped after `connect` so a store can go dark mid-run. */
  down: boolean;
  /**
   * Flipped after `connect` so a store can accept the connection and then
   * never answer — the fault mode a refusal does not cover and the cheapest
   * attack on a two-store design.
   *
   * The returned promise settles only when the request's own deadline aborts
   * it. A client that sent no deadline would wait here forever, which is
   * exactly the defect the deadline exists to close; the test below would then
   * hang rather than fail, and that is the honest RED for this one.
   */
  stalled: boolean;
  /** Replaces the answer to one route, so a store can lie about one thing. */
  intercept: ((path: string, search: string) => Response | null) | null;
  readonly fetch: typeof fetch;
}

const transportTo = (origin: string, scheduler: FakeScheduler): Transport => {
  const transport: Transport = {
    log: [],
    down: false,
    stalled: false,
    intercept: null,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const body =
        init?.body === undefined || init.body === null
          ? null
          : new Uint8Array(init.body as ArrayBuffer);
      transport.log.push({
        path: url.pathname,
        method: init?.method ?? "GET",
        atMs: scheduler.nowMs,
        body,
      });
      if (transport.down) throw new TypeError("this store is unreachable");
      if (transport.stalled)
        return new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal ?? null;
          if (signal === null) return;
          if (signal.aborted) {
            reject(signal.reason as Error);
            return;
          }
          signal.addEventListener(
            "abort",
            () => reject(signal.reason as Error),
            { once: true },
          );
        });
      const intercepted = transport.intercept?.(url.pathname, url.search);
      if (intercepted !== null && intercepted !== undefined) return intercepted;
      return fetch(`${origin}${url.pathname}${url.search}`, init);
    }) as typeof fetch,
  };
  return transport;
};

const connect = (
  world: World,
  store: StoreProcess,
  transport: Transport,
): Promise<PrototypeStoreClient> =>
  PrototypeStoreClient.connect({
    origin: store.origin,
    profile: world.profile,
    profileHash: world.profileHash,
    module,
    fetch: transport.fetch,
    nowMs: (): bigint => world.scheduler.nowMs,
  });

const countRequests = (
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
  method: string,
  path: string,
): number =>
  transport.log.filter(
    (request) =>
      request.atMs >= fromMs &&
      request.atMs < toMs &&
      request.method === method &&
      (request.path === path || request.path.startsWith(`${path}/`)),
  ).length;

/* ------------------------------------------------------------------ *
 * Rooms
 * ------------------------------------------------------------------ */

interface Room {
  readonly capability: Uint8Array;
  readonly roomRoot: Uint8Array;
  readonly validationContextAt: (
    referenceLogicalWindow: bigint,
  ) => OperationValidationContext;
}

const makeRoom = async (
  capability: Uint8Array,
  nowMs: bigint,
): Promise<Room> => {
  const digest = await policyHash(POLICY);
  const base = await createOperationValidationContext(
    capability,
    POLICY,
    nowMs / LOGICAL_WINDOW_MS,
  );
  return {
    capability,
    roomRoot: await roomRoot(capability, digest),
    validationContextAt: (referenceLogicalWindow): OperationValidationContext =>
      operationValidationContextAt(base, referenceLogicalWindow),
  };
};

/** The presence helper never negotiates; it only needs a signed PRESENCE. */
const idleTransport: TransportCandidateProvider = {
  createOffer: (): Promise<Uint8Array> =>
    Promise.reject(new Error("no negotiation in this test")),
  acceptOffer: (): Promise<Uint8Array> =>
    Promise.reject(new Error("no negotiation in this test")),
  acceptAnswer: (): Promise<void> =>
    Promise.reject(new Error("no negotiation in this test")),
};

/**
 * One signed PRESENCE for `room`, minted by the real producer.
 *
 * `PairDriver.start()` is the only thing in the tree that builds a PRESENCE,
 * and building one by hand here would prove the runtime carries a shape this
 * test invented rather than the one the prototype publishes.
 */
const presenceFor = async (
  capability: Uint8Array,
  scheduler: FakeScheduler,
): Promise<AuthenticatedRoomOperationV1> => {
  const published: AuthenticatedRoomOperationV1[] = [];
  const driver = new PairDriver({
    module,
    capability,
    identity: {
      ed25519PublicKey: sessionIdentity.ed25519PublicKey,
      ed25519SecretKey: sessionIdentity.ed25519SecretKey,
      x25519PublicKey: sessionIdentity.x25519PublicKey,
      x25519CrossSignature: sessionIdentity.x25519CrossSignature,
    },
    publish: (operation) => published.push(operation),
    transport: idleTransport,
    clock: { nowMs: (): bigint => scheduler.nowMs },
    random: randomBytes,
  });
  await driver.start();
  if (published.length !== 1)
    throw new Error("expected exactly one published presence");
  return published[0];
};

/* ------------------------------------------------------------------ *
 * The world one test runs in
 * ------------------------------------------------------------------ */

interface Carrier {
  readonly runtime: CarrierRuntime;
  readonly received: OuterValidatedIdentifiedOperationV1[];
  readonly events: CarrierEvent[];
  readonly clients: readonly PrototypeStoreClient[];
}

interface World {
  readonly scheduler: FakeScheduler;
  readonly profile: DeliveryProfileV1;
  readonly profileHash: Uint8Array;
  readonly stores: readonly StoreProcess[];
  readonly transports: Transport[];
  readonly carriers: Carrier[];
  readonly advance: (toMs: bigint) => Promise<void>;
  readonly stop: () => void;
}

const createWorld = async (
  options: {
    readonly faults?: readonly ("withhold" | null)[];
    readonly profile?: DeliveryProfileV1;
    readonly startMs?: bigint;
  } = {},
): Promise<World> => {
  const worldProfile = options.profile ?? profile;
  const scheduler = new FakeScheduler(options.startMs ?? START_MS);
  const stores = [
    await startStore(scheduler, worldProfile, {
      seed: new Uint8Array(32).fill(0x0a),
      fault: options.faults?.[0] ?? null,
    }),
    await startStore(scheduler, worldProfile, {
      seed: new Uint8Array(32).fill(0x0b),
      fault: options.faults?.[1] ?? null,
    }),
  ];
  const transports: Transport[] = [];
  const carriers: Carrier[] = [];
  return {
    scheduler,
    profile: worldProfile,
    profileHash: await deliveryProfileHash(worldProfile),
    stores,
    transports,
    carriers,
    advance: (toMs: bigint): Promise<void> =>
      scheduler.advanceTo(toMs, async () => {
        for (const store of stores) await store.core.finalizeDue();
        for (const carrier of carriers) await carrier.runtime.drain();
      }),
    stop: (): void => {
      for (const carrier of carriers) carrier.runtime.stop();
      for (const store of stores) store.stop();
    },
  };
};

/**
 * Connect one client per named store and start one runtime over them.
 *
 * `onOperations`, when given, is the application callback; `received` still
 * records every batch, before the callback sees it.
 */
const addCarrier = async (
  world: World,
  room: Room,
  storeIndexes: readonly number[],
  options: {
    readonly onOperations?: (
      fresh: readonly OuterValidatedIdentifiedOperationV1[],
    ) => void | Promise<void>;
  } = {},
): Promise<Carrier> => {
  const clients: PrototypeStoreClient[] = [];
  for (const index of storeIndexes) {
    const transport = transportTo(world.stores[index].origin, world.scheduler);
    world.transports.push(transport);
    clients.push(await connect(world, world.stores[index], transport));
  }
  const received: OuterValidatedIdentifiedOperationV1[] = [];
  const events: CarrierEvent[] = [];
  const runtime = new CarrierRuntime({
    module,
    roomRoot: room.roomRoot,
    profile: world.profile,
    profileHash: world.profileHash,
    stores: clients,
    validationContextAt: room.validationContextAt,
    logicalWindowMs: LOGICAL_WINDOW_MS,
    clock: world.scheduler.clock,
    timers: world.scheduler.timers,
    onOperations: (fresh) => {
      received.push(...fresh);
      return options.onOperations?.(fresh);
    },
    onEvent: (event) => events.push(event),
  });
  const carrier: Carrier = { runtime, received, events, clients };
  world.carriers.push(carrier);
  runtime.start();
  return carrier;
};

/** The carrier envelopes this transport posted inside one window. */
const appendedEnvelopes = (
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
): CarrierEnvelopeV1[] =>
  transport.log
    .filter(
      (request) =>
        request.path === PROTOTYPE_STORE_ROUTES.append &&
        request.body !== null &&
        request.atMs >= fromMs &&
        request.atMs < toMs,
    )
    .map((request) =>
      decodeCarrierEnvelope(
        decodePublicAppendRequestV1(request.body as Uint8Array)
          .exactFixedObject,
      ),
    );

const openedOperationIds = async (
  room: Room,
  envelopes: readonly CarrierEnvelopeV1[],
): Promise<string[]> => {
  const identifiers: string[] = [];
  for (const envelope of envelopes) {
    const plaintext = await openCarrierEnvelope(room.roomRoot, envelope, AEAD);
    if (plaintext === null) continue;
    identifiers.push(
      hex(await deriveOperationId(decodeOperation(plaintext.operationBytes))),
    );
  }
  return identifiers;
};

/**
 * Every object one transport posted in a window, grouped by size class and
 * split into the ones that open under the room root and the ones that do not.
 */
const appendedByClass = async (
  room: Room,
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
): Promise<Map<number, { real: number[]; cover: number[] }>> => {
  const byClass = new Map<number, { real: number[]; cover: number[] }>();
  for (const request of transport.log) {
    if (request.path !== PROTOTYPE_STORE_ROUTES.append) continue;
    if (request.body === null) continue;
    if (request.atMs < fromMs || request.atMs >= toMs) continue;
    const decoded = decodePublicAppendRequestV1(request.body);
    const bucket = byClass.get(decoded.bucket.sizeClass) ?? {
      real: [],
      cover: [],
    };
    const opened = await openCarrierEnvelope(
      room.roomRoot,
      decodeCarrierEnvelope(decoded.exactFixedObject),
      AEAD,
    );
    (opened === null ? bucket.cover : bucket.real).push(
      decoded.exactFixedObject.length,
    );
    byClass.set(decoded.bucket.sizeClass, bucket);
  }
  return byClass;
};

/** Every fixed request of one window, per route, for one transport. */
const windowShape = (
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
): Record<string, number> => ({
  token: countRequests(
    transport,
    fromMs,
    toMs,
    "POST",
    PROTOTYPE_STORE_ROUTES.token,
  ),
  allocation: countRequests(
    transport,
    fromMs,
    toMs,
    "POST",
    PROTOTYPE_STORE_ROUTES.allocation,
  ),
  append: countRequests(
    transport,
    fromMs,
    toMs,
    "POST",
    PROTOTYPE_STORE_ROUTES.append,
  ),
  checkpoint: countRequests(
    transport,
    fromMs,
    toMs,
    "GET",
    PROTOTYPE_STORE_ROUTES.checkpoint,
  ),
  chunk: countRequests(
    transport,
    fromMs,
    toMs,
    "GET",
    PROTOTYPE_STORE_ROUTES.chunk,
  ),
});

/** What every window of a running carrier must look like on the wire. */
const FIXED_WINDOW_SHAPE = {
  token: 1,
  allocation: 1,
  append: APPENDS_PER_WINDOW,
  checkpoint: 1,
  chunk: CHUNKS_PER_WINDOW,
};

const firstOpenable = async (
  room: Room,
  envelopes: readonly CarrierEnvelopeV1[],
): Promise<CarrierEnvelopeV1> => {
  for (const envelope of envelopes) {
    const plaintext = await openCarrierEnvelope(room.roomRoot, envelope, AEAD);
    if (plaintext !== null) return envelope;
  }
  throw new Error("no envelope in this window opens under the room root");
};

/* ------------------------------------------------------------------ *
 * Per-store write decorrelation (design doc §3a item 1)
 * ------------------------------------------------------------------ */

/**
 * One profile with its whole ingress schedule — the token, the allocation and
 * every append — moved by `deltaMs`, which is exactly what a per-store phase
 * offset would do to one store's traffic.
 *
 * The read and `chunkFinalizationOffsetMs` stay put: the read is a union over
 * both stores and fires once for the pair, and finalization is the store's own
 * clock rather than the client's, so a client cannot move either.
 */
const shiftIngressSchedule = (
  source: DeliveryProfileV1,
  deltaMs: bigint,
): DeliveryProfileV1 => ({
  ...source,
  tokenIssueOffsetMs: source.tokenIssueOffsetMs + deltaMs,
  allocationRequestOffsetMs: source.allocationRequestOffsetMs + deltaMs,
  sizeClasses: source.sizeClasses.map((sizeClass) => ({
    ...sizeClass,
    appendSchedule: sizeClass.appendSchedule.map((entry) => ({
      ...entry,
      offsetMs: entry.offsetMs + deltaMs,
    })),
  })),
});

const geometryAccepts = (candidate: DeliveryProfileV1): boolean => {
  try {
    validateDeliveryProfileGeometry(candidate);
    return true;
  } catch {
    return false;
  }
};

/**
 * The largest phase offset in one direction the geometry still accepts.
 *
 * Found by asking the real validator one millisecond at a time rather than by
 * re-deriving its inequalities here: the number then tracks the profile, and a
 * profile edit that widens or narrows the band shows up as a failure in the
 * test below instead of as a stale constant in a design document.
 *
 * Stepping out from zero and stopping at the first rejection assumes the
 * accepted region is contiguous in `deltaMs`, which holds because every
 * inequality the validator applies to these offsets is affine in it. A
 * validator that gained a non-monotonic rule would need this to scan the whole
 * range and take the extremes instead.
 */
const largestAcceptedPhaseMs = (sign: bigint): bigint => {
  let accepted = 0n;
  for (let step = 1n; step <= profile.deliveryWindowMs; step += 1n) {
    if (!geometryAccepts(shiftIngressSchedule(profile, sign * step))) break;
    accepted = step;
  }
  return accepted;
};

const PHASE_EARLIER_MS = largestAcceptedPhaseMs(-1n);
const PHASE_LATER_MS = largestAcceptedPhaseMs(1n);
/** The widest separation two stores could be given: one store as early as the
 * geometry allows, the other as late. */
const PHASE_SPAN_MS = PHASE_EARLIER_MS + PHASE_LATER_MS;

const LATEST_APPEND_OFFSET_MS = profile.sizeClasses.reduce(
  (latest, sizeClass) =>
    sizeClass.appendSchedule.reduce(
      (inner, entry) => (entry.offsetMs > inner ? entry.offsetMs : inner),
      latest,
    ),
  0n,
);

const absMs = (value: bigint): bigint => (value < 0n ? -value : value);

const separationStats = (
  samples: readonly bigint[],
): { readonly min: bigint; readonly median: bigint; readonly max: bigint } => {
  if (samples.length === 0)
    throw new Error("a separation measurement needs at least one sample");
  const sorted = [...samples].sort((left, right) =>
    left === right ? 0 : left < right ? -1 : 1,
  );
  const middle = Math.floor(sorted.length / 2);
  return {
    min: sorted[0],
    median:
      sorted.length % 2 === 1
        ? sorted[middle]
        : (sorted[middle - 1] + sorted[middle]) / 2n,
    max: sorted[sorted.length - 1],
  };
};

/** The instant at which one transport posted each operation it carried, keyed
 * by the OperationId, so the same operation can be found in both stores' logs
 * and the two instants compared. */
const realAppendInstants = async (
  room: Room,
  transport: Transport,
): Promise<Map<string, bigint>> => {
  const instants = new Map<string, bigint>();
  for (const request of transport.log) {
    if (request.path !== PROTOTYPE_STORE_ROUTES.append) continue;
    if (request.body === null) continue;
    const plaintext = await openCarrierEnvelope(
      room.roomRoot,
      decodeCarrierEnvelope(
        decodePublicAppendRequestV1(request.body).exactFixedObject,
      ),
      AEAD,
    );
    if (plaintext === null) continue;
    instants.set(
      hex(await deriveOperationId(decodeOperation(plaintext.operationBytes))),
      request.atMs,
    );
  }
  return instants;
};

/** Every request one transport made in a window as `method path @offset`, so
 * two stores' windows can be compared instant by instant. */
const requestGrid = (
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
): string[] =>
  transport.log
    .filter((request) => request.atMs >= fromMs && request.atMs < toMs)
    .map(
      (request) =>
        `${request.method} ${request.path} @${String(request.atMs - fromMs)}`,
    )
    .sort();

/* ------------------------------------------------------------------ *
 * Tests
 * ------------------------------------------------------------------ */

const W1 = CHAIN_START + 1n;
const W2 = CHAIN_START + 2n;
const W3 = CHAIN_START + 3n;

describe("prototype carrier runtime", () => {
  test.each([false, true])(
    "checks every single-store custody promise, including cover (real operation: %s)",
    async (publishReal) => {
      const world = await createWorld({ faults: ["withhold", null] });
      try {
        const capability = new Uint8Array(32).fill(0x18);
        const room = await makeRoom(capability, START_MS);
        const carrier = await addCarrier(world, room, [0]);
        const presence = await presenceFor(capability, world.scheduler);
        await world.advance(windowStartMs(W1));
        if (publishReal) carrier.runtime.publish(presence, "PRESENCE");
        await world.advance(
          windowStartMs(W2) + profile.publicReadOffsetMs + 1n,
        );

        // The store promised to retain every allocated append, then finalized
        // different bytes. A promise about client cover is equally binding.
        const breaches = carrier.runtime.faults.filter(
          (fault) => fault.kind === "custody-breach" && fault.window === W1,
        );
        expect(breaches).toHaveLength(APPENDS_PER_WINDOW);
        expect(carrier.clients[0].inert).toBe(true);
        expect(carrier.runtime.storeTopology).toBe("no-usable-carrier");
        expect(carrier.received).toEqual([]);
        expect(carrier.runtime.counters.appendsReal).toBe(publishReal ? 1 : 0);

        // Blaming a store must not suppress the remaining public schedule.
        await world.advance(windowStartMs(W3) - 1n);
        expect(
          windowShape(
            world.transports[0],
            windowStartMs(W2),
            windowStartMs(W3),
          ),
        ).toEqual(FIXED_WINDOW_SHAPE);
        expect(
          countRequests(
            world.transports[0],
            windowStartMs(W1),
            windowStartMs(W3),
            "POST",
            PROTOTYPE_STORE_ROUTES.witness,
          ),
        ).toBe(0);
      } finally {
        world.stop();
      }
    },
    180_000,
  );

  test("runs the profile's fixed schedule against both stores on an empty outbox", async () => {
    const world = await createWorld();
    try {
      const room = await makeRoom(new Uint8Array(32).fill(0x11), START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);

      // Window W0 has no lease (its allocation is requested inside it, for
      // W1), so the measured window is W1: the first fully scheduled one.
      await world.advance(windowStartMs(W1));
      const before = { ...carrier.runtime.counters };
      await world.advance(windowStartMs(W2) - 1n);
      const after = carrier.runtime.counters;

      for (const transport of world.transports)
        expect(
          windowShape(transport, windowStartMs(W1), windowStartMs(W2)),
        ).toEqual(FIXED_WINDOW_SHAPE);

      expect(after.appendsReal - before.appendsReal).toBe(0);
      expect(after.appendsDummy - before.appendsDummy).toBe(
        APPENDS_PER_WINDOW * 2,
      );
      expect(after.scans - before.scans).toBe(2);
      expect(carrier.runtime.storeTopology).toBe("multi-store-union");
      expect(carrier.runtime.faults).toEqual([]);

      // Every object of one size class is exactly that class's wire length,
      // dummy or not, because both are built through the same encoder.
      for (const transport of world.transports) {
        for (const request of transport.log) {
          if (request.path !== PROTOTYPE_STORE_ROUTES.append) continue;
          if (request.body === null) continue;
          const decoded = decodePublicAppendRequestV1(request.body);
          expect(decoded.exactFixedObject.length).toBe(
            carrierObjectWireBytes(
              world.profile,
              decoded.bucket.sizeClass,
              world.profileHash,
            ),
          );
        }
      }
    } finally {
      world.stop();
    }
  }, 180_000);

  test("replaces a dummy with a real object and seals it separately per store", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x22);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      await world.advance(windowStartMs(W1));
      carrier.runtime.publish(presence, "PRESENCE");
      const before = { ...carrier.runtime.counters };
      await world.advance(windowStartMs(W2) - 1n);
      const after = carrier.runtime.counters;

      // A full outbox must be the same window on the wire as an empty one:
      // one real object took one dummy's place, and nothing else moved.
      for (const transport of world.transports)
        expect(
          windowShape(transport, windowStartMs(W1), windowStartMs(W2)),
        ).toEqual(FIXED_WINDOW_SHAPE);
      expect(after.appendsReal - before.appendsReal).toBe(2);
      expect(after.appendsDummy - before.appendsDummy).toBe(
        APPENDS_PER_WINDOW * 2 - 2,
      );

      // The privacy claim itself: within a size class a real object and a
      // dummy are the same number of bytes, so the one carrying an operation
      // is not the one that stands out.
      for (const transport of world.transports) {
        const byClass = await appendedByClass(
          room,
          transport,
          windowStartMs(W1),
          windowStartMs(W2),
        );
        for (const sizeClass of world.profile.sizeClasses) {
          const bucket = byClass.get(sizeClass.id);
          expect(bucket).toBeDefined();
          if (bucket === undefined) continue;
          expect(bucket.real.length + bucket.cover.length).toBe(
            sizeClass.appendSchedule.length,
          );
          expect([...new Set([...bucket.real, ...bucket.cover])]).toEqual([
            carrierObjectWireBytes(
              world.profile,
              sizeClass.id,
              world.profileHash,
            ),
          ]);
        }
        // A class-0 PRESENCE: one real object in class 0 and none in class 1.
        expect(byClass.get(0)?.real.length).toBe(1);
        expect(byClass.get(1)?.real.length).toBe(0);
      }

      const perStore = world.transports.map((transport) =>
        appendedEnvelopes(transport, windowStartMs(W1), windowStartMs(W2)),
      );
      const openedPerStore = [
        await openedOperationIds(room, perStore[0]),
        await openedOperationIds(room, perStore[1]),
      ];
      expect(openedPerStore[0]).toEqual([presenceId]);
      expect(openedPerStore[1]).toEqual([presenceId]);

      // The one operation, wrapped twice: different context, different nonce,
      // different ciphertext. A store cannot recognize the other store's copy.
      const sealedA = await firstOpenable(room, perStore[0]);
      const sealedB = await firstOpenable(room, perStore[1]);
      expect(hex(sealedA.carrierContextId)).not.toBe(
        hex(sealedB.carrierContextId),
      );
      expect(envelopesAreCarrierSeparated(sealedA, sealedB)).toBe(true);
    } finally {
      world.stop();
    }
  }, 180_000);

  test("unions both stores' copies into one delivery and covers for another room", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x33);
      const room = await makeRoom(capability, START_MS);
      const stranger = await makeRoom(new Uint8Array(32).fill(0x44), START_MS);

      const publisher = await addCarrier(world, room, [0, 1]);
      const reader = await addCarrier(world, room, [0, 1]);
      const outsider = await addCarrier(world, stranger, [0, 1]);

      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      // Both stores carried it; the reader must be handed it exactly once.
      expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
        presenceId,
      ]);
      expect(reader.runtime.counters.operationsSeen).toBe(1);
      // Two real appends over the whole run and no more: an entry both stores
      // acknowledged leaves the outbox instead of going out again every window.
      expect(publisher.runtime.counters.appendsReal).toBe(2);
      expect(reader.runtime.storeTopology).toBe("multi-store-union");
      // Every object of another room is cover to this one: it opens under no
      // key this runtime holds, so it never becomes an operation.
      expect(outsider.received).toEqual([]);
      expect(outsider.runtime.counters.operationsSeen).toBe(0);
    } finally {
      world.stop();
    }
  }, 180_000);

  test("keeps delivering through the surviving store when one goes dark", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x55);
      const room = await makeRoom(capability, START_MS);
      const publisher = await addCarrier(world, room, [0, 1]);
      const reader = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      // Store 0 answers the descriptor, then every request it ever gets fails.
      world.transports[0].down = true;
      world.transports[2].down = true;

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
        presenceId,
      ]);
      expect(reader.runtime.storeTopology).toBe("single-carrier-dependent");
      // Unreachable is not dishonesty: nothing about store 0 is proven here.
      expect(reader.clients[0].inert).toBe(false);
    } finally {
      world.stop();
    }
  }, 180_000);

  test("keeps delivering through the other store when one stalls and answers nothing", async () => {
    // A store that refuses the connection is not the hard case: the fetch
    // rejects and the union moves on. The hard case is a store that ACCEPTS
    // the connection and then answers nothing, because `CarrierRuntime.#read`
    // joins both stores' scans under one `Promise.all` — without a per-request
    // deadline that store holds the union open and takes the honest store's
    // objects down with it. Neither E2E scenario covers this one: a SIGKILLed
    // store refuses, and `withhold` lies at full speed.
    const world = await createWorld({ profile: stalledStoreProfile });
    try {
      const capability = new Uint8Array(32).fill(0x5a);
      const room = await makeRoom(capability, START_MS);
      // The publisher speaks only to store 1, so the operation the reader must
      // still receive exists in exactly one place: the store that answers.
      const publisher = await addCarrier(world, room, [1]);
      const reader = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      const w1 = STALL_CHAIN_START + 1n;
      const w2 = STALL_CHAIN_START + 2n;
      await world.advance(stallWindowStartMs(w1));
      publisher.runtime.publish(presence, "PRESENCE");

      // Let w1's appends land, then take store 0 dark in the way a refusal
      // does not model: every request from here on is accepted and never
      // answered. The flip is before w1's finalization offset, so nothing this
      // client already sent is disturbed.
      await world.advance(
        stallWindowStartMs(w1) +
          stalledStoreProfile.chunkFinalizationOffsetMs -
          1n,
      );
      // `world.transports[1]` is the reader's client of store 0: the publisher
      // took index 0 for store 1, the reader indexes 1 and 2 for stores 0, 1.
      world.transports[1].stalled = true;

      // The read at w2 unions w1. Store 0's half of it never answers.
      await world.advance(
        stallWindowStartMs(w2) + stalledStoreProfile.publicReadOffsetMs + 1n,
      );

      expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
        presenceId,
      ]);
      expect(reader.runtime.storeTopology).toBe("single-carrier-dependent");

      const stalledFaults = reader.clients[0].faults;
      expect(stalledFaults.length).toBeGreaterThan(0);
      // Every one of them is absence, not blame: a store that said nothing
      // must never file in the same class as one caught signing a lie.
      expect([...new Set(stalledFaults.map((fault) => fault.kind))]).toEqual([
        "unreachable",
      ]);
      expect(
        stalledFaults.some((fault) =>
          fault.detail.includes(
            `no answer within the ${String(stalledStoreProfile.deliveryWindowMs)} ms request deadline`,
          ),
        ),
      ).toBe(true);
      // And it stays a carrier this client may come back to.
      expect(reader.clients[0].inert).toBe(false);
    } finally {
      world.stop();
    }
  }, 120_000);

  test("backfills an operation only one store carried to the store that missed it", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x66);
      const room = await makeRoom(capability, START_MS);
      // The publisher knows one store, so store 0 never sees this operation
      // until the two-store reader replicates it there.
      const publisher = await addCarrier(world, room, [1]);
      const reader = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
        presenceId,
      ]);
      expect(reader.runtime.counters.backfills).toBe(1);

      // The backfill goes out at the next state-replication slot of W2, and is
      // readable once W2 finalizes.
      await world.advance(windowStartMs(W3) + profile.publicReadOffsetMs + 1n);

      const audit = transportTo(world.stores[0].origin, world.scheduler);
      const client = await connect(world, world.stores[0], audit);
      const scan = await client.scanWindow(W2);
      expect(scan.status).toBe("finalized");
      const carried: string[] = [];
      for (const object of scan.objects) {
        // Slots nobody claimed are the store's own random cover and decode as
        // no envelope at all, which is exactly what the runtime skips too.
        let envelope: CarrierEnvelopeV1;
        try {
          envelope = decodeCarrierEnvelope(object);
        } catch {
          continue;
        }
        const plaintext = await openCarrierEnvelope(
          room.roomRoot,
          envelope,
          AEAD,
        );
        if (plaintext === null) continue;
        carried.push(
          hex(
            await deriveOperationId(decodeOperation(plaintext.operationBytes)),
          ),
        );
      }
      expect(carried).toContain(presenceId);

      // Once per store, ever: a second read of the same window adds nothing.
      expect(reader.runtime.counters.backfills).toBe(1);
    } finally {
      world.stop();
    }
  }, 180_000);

  test("detects a withheld object as a custody breach and drops the store", async () => {
    const world = await createWorld({ faults: ["withhold", null] });
    try {
      const capability = new Uint8Array(32).fill(0x77);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);

      await world.advance(windowStartMs(W1));
      carrier.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      const breaches = carrier.runtime.faults.filter(
        (fault) => fault.kind === "custody-breach",
      );
      expect(breaches.length).toBeGreaterThan(0);
      expect(breaches[0].storeIdHex).toBe(hex(world.stores[0].core.storeId));
      expect(carrier.clients[0].inert).toBe(true);
      expect(carrier.clients[1].inert).toBe(false);
      // A store excluded from availability leaves one usable carrier.
      expect(carrier.runtime.storeTopology).toBe("single-carrier-dependent");
    } finally {
      world.stop();
    }
  }, 180_000);

  test("records a checkpoint split-view hint when a store gossips another hash", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x88);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);

      // Store 1 answers every witness read with one record that names store 0
      // and a checkpoint hash store 0 never showed this client.
      const witnessed = world.stores[0].core.storeId;
      world.transports[1].intercept = (path): Response | null => {
        if (!path.startsWith(`${PROTOTYPE_STORE_ROUTES.witness}/`)) return null;
        const window = BigInt(path.slice(path.lastIndexOf("/") + 1));
        const record: StoreWitnessRecordV1 = {
          version: 1,
          witnessedStoreId: witnessed,
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: window,
          checkpointHash: new Uint8Array(32).fill(0xc1),
        };
        return new Response(asBody(encodeStoreWitnessRecordsV1([record])), {
          status: 200,
          headers: {
            "x-p2party-store": "prototype-v0",
            "content-type": PROTOTYPE_STORE_MEDIA_TYPES.witness,
          },
        });
      };

      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      const hints = carrier.runtime.faults.filter(
        (fault) => fault.kind === "checkpoint-split-view-hint",
      );
      expect(hints.length).toBeGreaterThan(0);
      expect(hints[0].storeIdHex).toBe(hex(witnessed));
      // Gossip is not proof: a hint excludes nothing.
      expect(carrier.clients[0].inert).toBe(false);
      expect(carrier.runtime.storeTopology).toBe("multi-store-union");
    } finally {
      world.stop();
    }
  }, 180_000);

  test("accepts the engine's own timers with no cast", () => {
    // The type, not the value, is the assertion: `realTimers` is annotated
    // `CarrierTimers` and built from the globals, so this file fails to
    // compile if the handle type ever stops admitting them.
    expect(typeof realTimers.setTimeout).toBe("function");
    expect(typeof realTimers.clearTimeout).toBe("function");
  });

  test("issues one allocation when it starts exactly on the allocation offset", async () => {
    // The cold-start branch is taken at `>=`, so at exactly the offset the
    // window's own queued allocation event is due at this instant too. Both
    // firing would put two allocation requests for one target window on the
    // wire and wipe the first lease's secret.
    const world = await createWorld({
      startMs: windowStartMs(CHAIN_START) + profile.allocationRequestOffsetMs,
    });
    try {
      const room = await makeRoom(new Uint8Array(32).fill(0xa1), START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);

      await world.advance(windowStartMs(W1) - 1n);
      for (const transport of world.transports)
        expect(
          countRequests(
            transport,
            windowStartMs(CHAIN_START),
            windowStartMs(W1),
            "POST",
            PROTOTYPE_STORE_ROUTES.allocation,
          ),
        ).toBe(1);

      // The one lease it did take must still be usable: W1's appends are
      // admitted rather than degraded to unallocated cover.
      await world.advance(windowStartMs(W2) - 1n);
      for (const transport of world.transports)
        expect(
          windowShape(transport, windowStartMs(W1), windowStartMs(W2)),
        ).toEqual(FIXED_WINDOW_SHAPE);
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);
      expect(carrier.runtime.storeTopology).toBe("multi-store-union");
      expect(carrier.runtime.faults).toEqual([]);
    } finally {
      world.stop();
    }
  }, 180_000);

  /**
   * Design §3a item 16's start-window rule, at every boundary the schedule has
   * (item 15 in the September latency documents).
   *
   * `start()` drops every event of the current window whose instant has
   * already passed (a late timer's events are sent late; a cold start's past
   * ones were never its to send), so a runtime armed at phase `p` issues
   * exactly the scheduled events at offsets `>= p`. The allocation is the
   * exception in both directions: at or
   * past `allocationRequestOffsetMs`, `start()` drops the queued allocation and
   * issues a cold-start allocation for the next window immediately, so exactly
   * one allocation POST leaves at every `p`.
   *
   * This exists because the item first stated the count as
   * `2 + (append offsets after p)` and was wrong below the read offset: the
   * sixteen observations it was derived from all fell above it, because
   * sequential E2E runs phase-lock to the delivery-window grid and resample
   * nearly the same `p`. Sampling a phase space cannot establish a rule over
   * it; this can, because the clock is injected. Below `publicReadOffsetMs`
   * the start window carries the **whole** fixed thirteen and is not
   * distinguishable from a later one by count at all — the two rows at
   * `p = 350` and `p = 600` are that result.
   *
   * The carrier is armed in W2 rather than in the chain-start window so the
   * read has a predecessor window in range: below the chain start
   * `scanWindow` answers `out-of-range` without issuing a request, which is a
   * fact about the store's age and not about `p`.
   */
  test("issues exactly the scheduled events still ahead of its start phase", async () => {
    const appendOffsetsMs = profile.sizeClasses
      .flatMap((sizeClass) =>
        sizeClass.appendSchedule.map((entry) => entry.offsetMs),
      )
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    const predicted = (phaseMs: bigint): Record<string, number> => ({
      token: phaseMs <= profile.tokenIssueOffsetMs ? 1 : 0,
      allocation: 1,
      append: appendOffsetsMs.filter((offset) => offset >= phaseMs).length,
      checkpoint: phaseMs <= profile.publicReadOffsetMs ? 1 : 0,
      chunk: phaseMs <= profile.publicReadOffsetMs ? CHUNKS_PER_WINDOW : 0,
    });

    for (const phaseMs of [
      0n,
      profile.tokenIssueOffsetMs,
      profile.tokenIssueOffsetMs + 1n,
      350n,
      profile.publicReadOffsetMs,
      profile.publicReadOffsetMs + 1n,
      profile.allocationRequestOffsetMs,
      profile.allocationRequestOffsetMs + 1n,
      appendOffsetsMs[0],
      appendOffsetsMs[0] + 1n,
      appendOffsetsMs[2],
      appendOffsetsMs[4],
      appendOffsetsMs[4] + 1n,
      profile.deliveryWindowMs - 1n,
    ]) {
      const world = await createWorld();
      try {
        const room = await makeRoom(new Uint8Array(32).fill(0x15), START_MS);
        await world.advance(windowStartMs(W2) + phaseMs);
        await addCarrier(world, room, [0, 1]);
        await world.advance(windowStartMs(W3) - 1n);

        // The phase rides along in the compared value so a failure names the
        // row rather than only the counts.
        for (const transport of world.transports)
          expect({
            atPhaseMs: String(phaseMs),
            ...windowShape(transport, windowStartMs(W2), windowStartMs(W3)),
          }).toEqual({ atPhaseMs: String(phaseMs), ...predicted(phaseMs) });
      } finally {
        world.stop();
      }
    }
  }, 180_000);

  test("keeps the schedule intact when an operation cannot be sealed into its class", async () => {
    const world = await createWorld({ profile: undersizedProfile });
    try {
      const capability = new Uint8Array(32).fill(0xb2);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);
      const presence = await presenceFor(capability, world.scheduler);

      await world.advance(windowStartMs(W1));
      carrier.runtime.publish(presence, "PRESENCE");
      const before = { ...carrier.runtime.counters };
      await world.advance(windowStartMs(W2) - 1n);
      const afterFirst = carrier.runtime.counters;

      // The slot could not carry the operation, so it carried cover — the
      // window on the wire is the profile's, unchanged.
      for (const transport of world.transports) {
        expect(
          windowShape(transport, windowStartMs(W1), windowStartMs(W2)),
        ).toEqual(FIXED_WINDOW_SHAPE);
        const byClass = await appendedByClass(
          room,
          transport,
          windowStartMs(W1),
          windowStartMs(W2),
        );
        for (const sizeClass of world.profile.sizeClasses) {
          const bucket = byClass.get(sizeClass.id);
          expect(bucket?.real).toEqual([]);
          expect([...new Set(bucket?.cover ?? [])]).toEqual([
            carrierObjectWireBytes(
              world.profile,
              sizeClass.id,
              world.profileHash,
            ),
          ]);
        }
      }
      expect(afterFirst.appendsReal - before.appendsReal).toBe(0);
      expect(afterFirst.appendsDummy - before.appendsDummy).toBe(
        APPENDS_PER_WINDOW * 2,
      );
      expect(
        carrier.events.some(
          (event) =>
            event.kind === "missed" &&
            (event.detail ?? "").includes(
              "could not be sealed into size class",
            ),
        ),
      ).toBe(true);

      // And the next window is unaffected: the entry was dropped, not left to
      // be re-selected and to silence this (role, class) slot forever.
      await world.advance(windowStartMs(W3) - 1n);
      const afterSecond = carrier.runtime.counters;
      for (const transport of world.transports)
        expect(
          windowShape(transport, windowStartMs(W2), windowStartMs(W3)),
        ).toEqual(FIXED_WINDOW_SHAPE);
      expect(afterSecond.appendsReal - afterFirst.appendsReal).toBe(0);
      expect(afterSecond.appendsDummy - afterFirst.appendsDummy).toBe(
        APPENDS_PER_WINDOW * 2,
      );
    } finally {
      world.stop();
    }
  }, 180_000);

  test("refuses an object whose header does not match the bucket it came from", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0x99);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);

      const honest = await presenceFor(capability, world.scheduler);
      const relocated = await presenceFor(capability, world.scheduler);
      const foreign = await presenceFor(capability, world.scheduler);

      // A direct client of store 0, so these objects are placed exactly where
      // a store that relocated them would place them.
      const audit = transportTo(world.stores[0].origin, world.scheduler);
      const client = await connect(world, world.stores[0], audit);

      await world.advance(windowStartMs(W1) + 1_000n);
      const keyPair = await newKeyPair(module);
      const lease = await client.allocate(W1, keyPair);
      if (lease === null) throw new Error("expected a lease");

      const sizeClass = world.profile.sizeClasses[0];
      const place = async (
        operation: AuthenticatedRoomOperationV1,
        coordinates: {
          readonly carrierContextId: Uint8Array;
          readonly ingressWindow: bigint;
        },
        objectOrdinal: number,
      ): Promise<void> => {
        const envelope = await sealCarrierEnvelope(
          room.roomRoot,
          {
            deliveryProfileHash: world.profileHash,
            carrierContextId: coordinates.carrierContextId,
            ingressWindow: coordinates.ingressWindow,
            sizeClass: sizeClass.id,
          },
          randomBytes(24),
          buildCarrierPlaintext(
            encodeOperation(operation),
            sizeClass.fixedCarrierObjectBytes,
          ),
          AEAD,
        );
        const object = encodeCarrierEnvelope(envelope);
        const result = await client.append(
          W1,
          sizeClass.id,
          object,
          await buildAppendAdmission(
            lease,
            keyPair.secretKey,
            sizeClass.id,
            objectOrdinal,
            object,
            module,
          ),
        );
        expect(result?.status).toBe("stored");
      };

      await place(
        honest,
        { carrierContextId: client.carrierContextId, ingressWindow: W1 },
        0,
      );
      // Same room, same key, but a header naming another window: this is what a
      // store copying an object between buckets produces, and the AEAD alone
      // would open it because the AEAD is bound to the header, not the bucket.
      await place(
        relocated,
        { carrierContextId: client.carrierContextId, ingressWindow: W1 + 5n },
        1,
      );
      // Same room, but the other store's carrier context.
      await place(
        foreign,
        {
          carrierContextId: carrier.clients[1].carrierContextId,
          ingressWindow: W1,
        },
        2,
      );

      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);

      expect(carrier.received.map((entry) => hex(entry.operationId))).toEqual([
        hex(await deriveOperationId(honest)),
      ]);
    } finally {
      world.stop();
    }
  }, 180_000);

  test("bounds the per-store phase offset this profile's geometry could pay for", () => {
    // Design doc §3a item 1 quotes these three numbers; they are measured
    // against the real validator here rather than written down, so a profile
    // edit that changes the band fails this test instead of quietly making the
    // document wrong.
    expect(PHASE_EARLIER_MS).toBe(100n);
    expect(PHASE_LATER_MS).toBe(499n);
    expect(PHASE_SPAN_MS).toBe(599n);

    // One millisecond past either bound is a profile the validator refuses,
    // which is what "compute the slack from the profile" has to mean: the band
    // is the validator's, not this test's.
    expect(
      geometryAccepts(shiftIngressSchedule(profile, PHASE_LATER_MS + 1n)),
    ).toBe(false);
    expect(
      geometryAccepts(shiftIngressSchedule(profile, -(PHASE_EARLIER_MS + 1n))),
    ).toBe(false);

    // And the property that decides against spending the band at all: the
    // whole of it is a seventh of one delivery window, and the latest append a
    // maximally delayed store could make still lands before this window ends.
    // No write crosses a window boundary, so the set of writes an observer
    // joins over — the ones this window carried at both stores — is exactly the
    // same set with the offset as without it. The literature's mitigation is a
    // delay drawn wide *against the epoch*; this profile has no such delay to
    // give.
    expect(PHASE_SPAN_MS).toBeLessThan(profile.deliveryWindowMs);
    expect(
      LATEST_APPEND_OFFSET_MS + PHASE_LATER_MS + profile.maxScheduleSkewMs,
    ).toBeLessThan(profile.deliveryWindowMs);
  });

  test("writes one operation to both stores in the same millisecond, measured", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0xd1);
      const room = await makeRoom(capability, START_MS);
      const carrier = await addCarrier(world, room, [0, 1]);
      // PRESENCE is state-replication work and a PRESENCE is payload class 0,
      // so exactly one of these leaves per window, at class 0's single
      // state-replication slot: three operations measured over three windows.
      const presences = [
        await presenceFor(capability, world.scheduler),
        await presenceFor(capability, world.scheduler),
        await presenceFor(capability, world.scheduler),
      ];

      await world.advance(windowStartMs(W1));
      for (const presence of presences)
        carrier.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(CHAIN_START + 4n) - 1n);
      expect(carrier.runtime.counters.appendsReal).toBe(presences.length * 2);

      const atStoreA = await realAppendInstants(room, world.transports[0]);
      const atStoreB = await realAppendInstants(room, world.transports[1]);
      expect([...atStoreA.keys()].sort()).toEqual([...atStoreB.keys()].sort());
      expect(atStoreA.size).toBe(presences.length);

      const separations = [...atStoreA.entries()].map(([id, instant]) => {
        const atTheOtherStore = atStoreB.get(id);
        if (atTheOtherStore === undefined)
          throw new Error("an operation reached only one of the two stores");
        return absMs(instant - atTheOtherStore);
      });
      const measured = separationStats(separations);

      // The measurement design doc §3a item 1 reports. The clock here is the
      // injected one, so this is the schedule's own contribution with network
      // jitter removed: the runtime aims both stores at the same instant, and
      // whatever separation a real network adds is jitter the client neither
      // chooses nor controls — and an observer can model it.
      expect(measured.min).toBe(0n);
      expect(measured.median).toBe(0n);
      expect(measured.max).toBe(0n);

      // Not only the appends: every request of a window lands on both stores
      // at the same offset, so the join has the token and the allocation to
      // work with even in a window that carries nothing.
      expect(
        requestGrid(world.transports[0], windowStartMs(W2), windowStartMs(W3)),
      ).toEqual(
        requestGrid(world.transports[1], windowStartMs(W2), windowStartMs(W3)),
      );

      // What the rejected mitigation would have produced, from the inputs it
      // would have used. `PublicCarrierContextId` is `H(StoreId ||
      // DeliveryProfileHash)`: every client of a store shares it and anyone
      // holding the store's published descriptor recomputes it, so the phase it
      // yields is a public constant per store — the same grid under a different
      // name, and a translation an observer subtracts before joining. It is
      // reported here for the record, not applied.
      const phaseFor = (carrierContextId: Uint8Array): bigint =>
        (BigInt(`0x${hex(carrierContextId.subarray(0, 8))}`) %
          (PHASE_SPAN_MS + 1n)) -
        PHASE_EARLIER_MS;
      const wouldHaveSeparated = absMs(
        phaseFor(carrier.clients[0].carrierContextId) -
          phaseFor(carrier.clients[1].carrierContextId),
      );
      expect(wouldHaveSeparated).toBeLessThanOrEqual(PHASE_SPAN_MS);
      expect(wouldHaveSeparated).toBeLessThan(profile.deliveryWindowMs);
    } finally {
      world.stop();
    }
  }, 180_000);
});

/* ------------------------------------------------------------------ *
 * Late timers, the application callback, and the run around them
 * ------------------------------------------------------------------ */

/** Every request one transport made in `[fromMs, toMs)`. */
const requestsIn = (
  transport: Transport,
  fromMs: bigint,
  toMs: bigint,
): RequestRecord[] =>
  transport.log.filter(
    (request) => request.atMs >= fromMs && request.atMs < toMs,
  );

/** The witness requests one transport made in `window`, as `METHOD @offset`. */
const witnessGrid = (transport: Transport, window: bigint): string[] =>
  requestsIn(transport, windowStartMs(window), windowStartMs(window + 1n))
    .filter(
      (request) =>
        request.path === PROTOTYPE_STORE_ROUTES.witness ||
        request.path.startsWith(`${PROTOTYPE_STORE_ROUTES.witness}/`),
    )
    .map(
      (request) =>
        `${request.method} @${String(request.atMs - windowStartMs(window))}`,
    )
    .sort();

const scanStatuses = (
  carrier: Carrier,
  window: bigint,
  storeIdHex: string,
): (string | undefined)[] =>
  carrier.events
    .filter(
      (event) =>
        event.kind === "scan" &&
        event.window === window &&
        event.storeIdHex === storeIdHex,
    )
    .map((event) => event.detail);

describe("prototype carrier runtime under late timers", () => {
  test("a read 201 ms late still scans the window", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0xc1);
      const room = await makeRoom(capability, START_MS);
      const publisher = await addCarrier(world, room, [0]);
      const reader = await addCarrier(world, room, [0]);
      const presence = await presenceFor(capability, world.scheduler);
      const presenceId = hex(await deriveOperationId(presence));

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      // Only the read of W1 is late, by one millisecond past the skew budget:
      // the smallest stall the removed overdue guard used to turn into a
      // window this client never read.
      world.scheduler.lateness = {
        onceAtMs: windowStartMs(W2) + profile.publicReadOffsetMs,
        onceByMs: profile.maxScheduleSkewMs + 1n,
      };
      await world.advance(windowStartMs(W3));

      expect(scanStatuses(reader, W1, reader.clients[0].storeIdHex)).toEqual([
        "finalized",
      ]);
      expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
        presenceId,
      ]);
    } finally {
      world.stop();
    }
  }, 180_000);

  test.each([0n, 500n])(
    "1000 ms timer clamping reads every window (phase %p ms)",
    async (phaseMs) => {
      const world = await createWorld();
      try {
        const capability = new Uint8Array(32).fill(0xc2);
        const room = await makeRoom(capability, START_MS);
        const publisher = await addCarrier(world, room, [0, 1]);
        const reader = await addCarrier(world, room, [0, 1]);
        const presence = await presenceFor(capability, world.scheduler);
        const presenceId = hex(await deriveOperationId(presence));

        await world.advance(windowStartMs(W1));
        publisher.runtime.publish(presence, "PRESENCE");
        // The presence is appended on time in W1. From then on every timer
        // of every page is held to the next whole second, the way a
        // background tab delivers them.
        await world.advance(windowStartMs(W1) + LATEST_APPEND_OFFSET_MS + 1n);
        world.scheduler.lateness = { alignMs: 1_000n, phaseMs };

        const last = W1 + 4n;
        // The read of `last` is due in the window after it and is at most a
        // second late.
        await world.advance(
          windowStartMs(last + 1n) + profile.publicReadOffsetMs + 1_000n,
        );

        for (let window = W1; window <= last; window += 1n)
          for (const client of reader.clients)
            expect(scanStatuses(reader, window, client.storeIdHex)).toEqual([
              "finalized",
            ]);
        expect(reader.received.map((entry) => hex(entry.operationId))).toEqual([
          presenceId,
        ]);
      } finally {
        world.stop();
      }
    },
    180_000,
  );

  test.each([0n, 150n, 1_000n])(
    "13 requests per window at 0, 150 and 1000 ms lateness (%p ms)",
    async (lateMs) => {
      const world = await createWorld();
      try {
        const room = await makeRoom(new Uint8Array(32).fill(0xc3), START_MS);
        // One store, so the conditional witness pair is out of the count and
        // every request below is part of the fixed schedule.
        await addCarrier(world, room, [0]);
        await world.advance(windowStartMs(W2));
        world.scheduler.lateness = { everyMs: lateMs };

        const first = W2 + 2n;
        const end = W2 + 6n;
        await world.advance(windowStartMs(end));
        const transport = world.transports[0];
        for (let window = first; window < end; window += 1n) {
          const fromMs = windowStartMs(window);
          const toMs = windowStartMs(window + 1n);
          expect(windowShape(transport, fromMs, toMs)).toEqual(
            FIXED_WINDOW_SHAPE,
          );
          expect(requestsIn(transport, fromMs, toMs)).toHaveLength(13);
        }
      } finally {
        world.stop();
      }
    },
    180_000,
  );
});

describe("prototype carrier runtime and its application callback", () => {
  test("witness timing is identical with and without decryption hits", async () => {
    const world = await createWorld();
    try {
      const capability = new Uint8Array(32).fill(0xc4);
      const room = await makeRoom(capability, START_MS);
      const publisher = await addCarrier(world, room, [0, 1]);
      // A hit costs the reader 300 ms of its clock: the work an application
      // does with an operation on a real main thread.
      const reader = await addCarrier(world, room, [0, 1], {
        onOperations: () => {
          world.scheduler.nowMs += 300n;
        },
      });
      const presence = await presenceFor(capability, world.scheduler);

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W3 + 1n));

      // W2 reads W1, which carries the presence: a hit. W3 reads W2, which
      // carries nothing for this room.
      expect(
        reader.events
          .filter((event) => event.kind === "operations")
          .map((event) => event.window),
      ).toEqual([W1]);
      for (const transport of world.transports.slice(2, 4)) {
        const withHit = witnessGrid(transport, W2);
        expect(withHit).toHaveLength(2);
        expect(withHit).toEqual(witnessGrid(transport, W3));
      }
    } finally {
      world.stop();
    }
  }, 180_000);

  test("a hanging callback does not delay the witness", async () => {
    const world = await createWorld();
    let release = (): void => undefined;
    const hanging = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      const capability = new Uint8Array(32).fill(0xc5);
      const room = await makeRoom(capability, START_MS);
      const publisher = await addCarrier(world, room, [0, 1]);
      const reader = await addCarrier(world, room, [0, 1], {
        onOperations: () => hanging,
      });
      const presence = await presenceFor(capability, world.scheduler);

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(presence, "PRESENCE");
      await world.advance(windowStartMs(W3 + 1n));

      expect(reader.received).toHaveLength(1);
      for (const transport of world.transports.slice(2, 4)) {
        expect(witnessGrid(transport, W2)).toHaveLength(2);
        expect(witnessGrid(transport, W2)).toEqual(witnessGrid(transport, W3));
        expect(
          windowShape(transport, windowStartMs(W3), windowStartMs(W3 + 1n)),
        ).toEqual(FIXED_WINDOW_SHAPE);
      }
    } finally {
      release();
      world.stop();
    }
  }, 60_000);

  test("concurrent ingests are serialized", async () => {
    const world = await createWorld();
    const gates: (() => void)[] = [];
    const batches: string[][] = [];
    let active = 0;
    let maxActive = 0;
    let secondEntered = (): void => undefined;
    const second = new Promise<void>((resolve) => {
      secondEntered = resolve;
    });
    try {
      const capability = new Uint8Array(32).fill(0xc6);
      const room = await makeRoom(capability, START_MS);
      const publisher = await addCarrier(world, room, [0, 1]);
      // The composition hands `driver.ingest` to the runtime, and an ingest
      // that waits for ICE gathering outlives a delivery window.
      const reader = await addCarrier(world, room, [0, 1], {
        onOperations: async (fresh) => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          batches.push(fresh.map((entry) => hex(entry.operationId)));
          if (batches.length === 2) secondEntered();
          await new Promise<void>((resolve) => gates.push(resolve));
          active -= 1;
        },
      });
      const firstPresence = await presenceFor(capability, world.scheduler);
      const secondPresence = await presenceFor(capability, world.scheduler);
      const firstId = hex(await deriveOperationId(firstPresence));
      const secondId = hex(await deriveOperationId(secondPresence));

      await world.advance(windowStartMs(W1));
      publisher.runtime.publish(firstPresence, "PRESENCE");
      await world.advance(windowStartMs(W2));
      publisher.runtime.publish(secondPresence, "PRESENCE");
      // W2's read delivers the first presence and its callback does not
      // return; W3's read finds the second while that callback is pending.
      await world.advance(windowStartMs(W3) + profile.publicReadOffsetMs + 1n);

      expect(
        reader.events
          .filter((event) => event.kind === "operations")
          .map((event) => event.window),
      ).toEqual([W1, W2]);
      expect(batches).toEqual([[firstId]]);

      gates.shift()?.();
      await second;
      expect(batches).toEqual([[firstId], [secondId]]);
      expect(maxActive).toBe(1);
    } finally {
      for (const gate of gates) gate();
      world.stop();
    }
  }, 60_000);
});

/* ------------------------------------------------------------------ *
 * The run composition around the runtime
 * ------------------------------------------------------------------ */

const runIdentity = await generateSessionIdentity({ wasmBinary });
const peerIdentity = await generateSessionIdentity({ wasmBinary });
peerIdentity.x25519SecretKey.fill(0);

/** What a finished pair exchange hands the run: enough for `createSession`. */
const HANDOFF: HandoffFacts = {
  rendezvousChannelId: new Uint8Array(32).fill(0x31),
  localFingerprint: new Uint8Array(32).fill(0x32),
  remoteFingerprint: new Uint8Array(32).fill(0x33),
  sessionRole: "initiator",
  rendezvousRole: "initiator",
  peerStableEd25519PublicKey: peerIdentity.ed25519PublicKey,
  stableEdgeId: new Uint8Array(32).fill(0x34),
};

/** An open data channel whose peer never answers. */
class SilentChannel extends EventTarget {
  binaryType = "arraybuffer";
  readyState: RTCDataChannelState = "open";
  sent = 0;
  #spoke: (() => void) | null = null;
  /** Settles on the first frame this side sends. */
  readonly spoke = new Promise<void>((resolve) => {
    this.#spoke = resolve;
  });

  send(): void {
    this.sent += 1;
    this.#spoke?.();
  }

  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

/** One end of an in-memory data channel; every frame is kept. */
class PairedChannel extends EventTarget {
  binaryType = "arraybuffer";
  readyState: RTCDataChannelState = "open";
  peer: PairedChannel | null = null;
  readonly frames: Uint8Array[] = [];

  send(bytes: Uint8Array): void {
    const copy = Uint8Array.from(bytes);
    this.frames.push(copy);
    this.peer?.dispatchEvent(
      new MessageEvent("message", { data: Uint8Array.from(copy).buffer }),
    );
  }

  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

interface FakeRunTransport {
  readonly transport: RunTransport;
  readonly channel: SilentChannel;
  closed: number;
}

const providerOver = (
  channel: EventTarget,
  verifyCertificates: SessionTransportProvider["verifyCertificates"],
): SessionTransportProvider => ({
  role: "initiator",
  peerConnection: {
    connectionState: "connected",
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  } as unknown as RTCPeerConnection,
  channel: () => Promise.resolve(channel as unknown as RTCDataChannel),
  verifyCertificates,
});

const fakeRunTransport = (
  verifyCertificates: SessionTransportProvider["verifyCertificates"],
): FakeRunTransport => {
  const channel = new SilentChannel();
  const fake: FakeRunTransport = {
    channel,
    closed: 0,
    transport: {
      provider: providerOver(channel, verifyCertificates),
      // What `WebRtcCandidateProvider.close()` does to its channel.
      close: (): void => {
        fake.closed += 1;
        channel.close();
      },
    },
  };
  return fake;
};

/** Only the two members the run reads; the driver itself is not under test. */
const stubDriver = (handoff: HandoffFacts | null): PairDriver =>
  ({ handoff }) as unknown as PairDriver;

interface RunEvents {
  readonly events: { readonly kind: string; readonly detail?: string }[];
  readonly emit: (kind: string, detail?: string) => void;
  readonly reached: (kind: string) => Promise<string | undefined>;
}

const runEvents = (): RunEvents => {
  const events: { readonly kind: string; readonly detail?: string }[] = [];
  const waiters: {
    readonly kind: string;
    readonly resolve: (detail: string | undefined) => void;
  }[] = [];
  return {
    events,
    emit: (kind, detail) => {
      events.push({ kind, detail });
      for (const waiter of waiters.splice(0))
        if (waiter.kind === kind) waiter.resolve(detail);
        else waiters.push(waiter);
    },
    reached: (kind) => {
      const seen = events.find((event) => event.kind === kind);
      if (seen !== undefined) return Promise.resolve(seen.detail);
      return new Promise((resolve) => waiters.push({ kind, resolve }));
    },
  };
};

interface RunUnderTest extends RunEvents {
  readonly run: BlindRendezvousRun;
}

/** A run whose every deadline is on the world's fake clock. */
const runOver = (
  world: World,
  carrier: Carrier,
  driver: PairDriver,
  transport: RunTransport,
  options: {
    readonly handshakeTimeoutMs: number;
    readonly identity?: typeof runIdentity;
  },
): RunUnderTest => {
  const observed = runEvents();
  const run = new BlindRendezvousRun({
    driver,
    runtime: carrier.runtime,
    transport,
    identity: options.identity ?? runIdentity,
    pqMode: "hybrid-mlkem768",
    wasmBinary,
    handshakeTimeoutMs: options.handshakeTimeoutMs,
    clock: world.scheduler.clock,
    timers: world.scheduler.timers,
    emit: observed.emit,
  });
  return { run, ...observed };
};

/** Every outcome of a promise as a value, so no rejection goes unhandled
 * while the test drives the clock towards it. */
const settled = <T>(promise: Promise<T>): Promise<T | Error> =>
  promise.then(
    (value) => value,
    (error: unknown) =>
      error instanceof Error ? error : new Error(String(error)),
  );

const fingerprintText = (byte: number): string =>
  Array.from({ length: 32 }, () =>
    byte.toString(16).padStart(2, "0").toUpperCase(),
  ).join(":");

/** One canned complete-ICE description, as `pairDriver.test.ts` uses. */
const sdpBytes = (tag: string, fingerprintByte: number): Uint8Array =>
  new TextEncoder().encode(
    [
      "v=0",
      "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
      "s=-",
      "t=0 0",
      "a=group:BUNDLE 0",
      "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
      "c=IN IP4 0.0.0.0",
      "a=ice-ufrag:" + tag,
      "a=ice-pwd:" + tag + tag + tag,
      "a=ice-options:trickle",
      "a=fingerprint:sha-256 " + fingerprintText(fingerprintByte),
      "a=setup:actpass",
      "a=mid:0",
      "a=sctp-port:5000",
      "",
    ].join("\r\n"),
  );

interface Party extends RunEvents {
  readonly run: BlindRendezvousRun;
  readonly transports: Transport[];
  acceptOfferCalls: number;
}

/**
 * One whole endpoint through `assembleRun`, on the world's stores and fake
 * clock. Its WebRTC side is canned SDP; `acceptOffer` — which in a browser
 * waits for ICE gathering and may be called only once — waits for `gate`.
 */
const startParty = async (
  world: World,
  capability: Uint8Array,
  sdp: Uint8Array,
  gate: Promise<void>,
): Promise<Party> => {
  const transports: Transport[] = [];
  const clients: PrototypeStoreClient[] = [];
  for (const store of world.stores) {
    const transport = transportTo(store.origin, world.scheduler);
    world.transports.push(transport);
    transports.push(transport);
    clients.push(await connect(world, store, transport));
  }
  const observed = runEvents();
  const party = {
    ...observed,
    transports,
    acceptOfferCalls: 0,
  } as Party;
  const run = await assembleRun({
    module,
    capability,
    identity: await generateSessionIdentity({ wasmBinary }),
    stores: clients,
    profile: world.profile,
    profileHash: world.profileHash,
    transport: {
      provider: null,
      close: () => undefined,
      createOffer: () => Promise.resolve(Uint8Array.from(sdp)),
      acceptOffer: async () => {
        party.acceptOfferCalls += 1;
        await gate;
        return Uint8Array.from(sdp);
      },
      acceptAnswer: () => Promise.resolve(),
    },
    wasmBinary,
    handshakeTimeoutMs: 60_000,
    clock: world.scheduler.clock,
    timers: world.scheduler.timers,
    emit: observed.emit,
  });
  world.carriers.push({
    runtime: run.runtime,
    received: [],
    events: [],
    clients,
  });
  return Object.assign(party, { run });
};

const kinds = (subject: RunEvents): string[] =>
  subject.events.map((event) => event.kind);

describe("prototype run composition", () => {
  test.each(["dtls-mismatch", "stalled-handshake"] as const)(
    "session failure leaves the schedule armed (%s)",
    async (failure) => {
      const world = await createWorld();
      let ended: RunUnderTest | null = null;
      try {
        const room = await makeRoom(new Uint8Array(32).fill(0xd7), START_MS);
        const carrier = await addCarrier(world, room, [0]);
        await world.advance(windowStartMs(W1));

        const fake = fakeRunTransport(
          failure === "dtls-mismatch"
            ? () =>
                Promise.reject(new Error("DTLS fingerprint mismatch (test)"))
            : () => Promise.resolve("verified"),
        );
        const subject = runOver(
          world,
          carrier,
          stubDriver(HANDOFF),
          fake.transport,
          {
            handshakeTimeoutMs: 1_000,
          },
        );
        ended = subject;
        subject.run.handlePhase("handoff");

        if (failure === "stalled-handshake") {
          // The handshake starts — the initiator speaks first — and nobody
          // answers. Its deadline is on the fake clock, so it fires exactly
          // when the clock passes it and not before.
          await fake.channel.spoke;
          const startedAt = world.scheduler.nowMs;
          await world.advance(startedAt + 999n);
          expect(kinds(subject)).not.toContain("session-failed");
          await world.advance(startedAt + 1_000n);
        }
        const detail = await subject.reached("session-failed");

        if (failure === "stalled-handshake") {
          expect(detail).toContain("session handshake");
          expect(
            await settled(subject.run.sendMessage(new Uint8Array([1]), 1_000)),
          ).toBeInstanceOf(PrototypeRunTimeoutError);
        } else {
          expect(detail).toContain("DTLS fingerprint mismatch");
          const outcome = await settled(
            subject.run.sendMessage(new Uint8Array([1]), 1_000),
          );
          expect(String(outcome)).toContain("DTLS fingerprint mismatch");
        }
        // The session and its peer connection are gone ...
        expect(fake.closed).toBeGreaterThan(0);
        expect(fake.channel.readyState).toBe("closed");
        // ... and nothing else: the run was not stopped, so the schedule
        // goes on at its fixed shape in the windows after the failure.
        expect(kinds(subject)).not.toContain("run-stopped");
        await world.advance(windowStartMs(W3));
        expect(
          windowShape(
            world.transports[0],
            windowStartMs(W2),
            windowStartMs(W3),
          ),
        ).toEqual(FIXED_WINDOW_SHAPE);
      } finally {
        ended?.run.stop();
        world.stop();
      }
    },
    60_000,
  );

  test("sendMessage rejects at its deadline", async () => {
    const world = await createWorld();
    let subject: RunUnderTest | null = null;
    try {
      const room = await makeRoom(new Uint8Array(32).fill(0xd8), START_MS);
      const carrier = await addCarrier(world, room, [0]);
      // No handoff ever comes, so there is no session to send on.
      subject = runOver(
        world,
        carrier,
        stubDriver(null),
        { provider: null, close: () => undefined },
        { handshakeTimeoutMs: 1_000 },
      );
      const startedAt = world.scheduler.nowMs;
      const sending = settled(
        subject.run.sendMessage(new Uint8Array([1, 2, 3]), 20),
      );
      await world.advance(startedAt + 20n);
      expect(await sending).toBeInstanceOf(PrototypeRunTimeoutError);
      // A deadline is not a failure of the edge: the run is still live.
      expect(kinds(subject)).not.toContain("run-stopped");
    } finally {
      subject?.run.stop();
      world.stop();
    }
  }, 30_000);

  test("a send that missed its deadline stays unsent", async () => {
    const world = await createWorld();
    const subjects: RunUnderTest[] = [];
    try {
      const room = await makeRoom(new Uint8Array(32).fill(0xd9), START_MS);
      const carrier = await addCarrier(world, room, [0]);
      const responderIdentity = await generateSessionIdentity({ wasmBinary });
      const initiatorChannel = new PairedChannel();
      const responderChannel = new PairedChannel();
      initiatorChannel.peer = responderChannel;
      responderChannel.peer = initiatorChannel;
      const verified = (): Promise<"verified"> => Promise.resolve("verified");

      const initiator = runOver(
        world,
        carrier,
        stubDriver({
          ...HANDOFF,
          sessionRole: "initiator",
          peerStableEd25519PublicKey: responderIdentity.ed25519PublicKey,
        }),
        {
          provider: providerOver(initiatorChannel, verified),
          close: () => initiatorChannel.close(),
        },
        { handshakeTimeoutMs: 60_000 },
      );
      const responder = runOver(
        world,
        carrier,
        stubDriver({
          ...HANDOFF,
          sessionRole: "responder",
          rendezvousRole: "responder",
          localFingerprint: HANDOFF.remoteFingerprint,
          remoteFingerprint: HANDOFF.localFingerprint,
          peerStableEd25519PublicKey: runIdentity.ed25519PublicKey,
        }),
        {
          provider: providerOver(responderChannel, verified),
          close: () => responderChannel.close(),
        },
        { handshakeTimeoutMs: 60_000, identity: responderIdentity },
      );
      subjects.push(initiator, responder);

      // There is no session yet, so this send waits — past its deadline.
      const early = new TextEncoder().encode("sent too early");
      const startedAt = world.scheduler.nowMs;
      const missed = settled(initiator.run.sendMessage(early, 100));
      await world.advance(startedAt + 100n);
      expect(await missed).toBeInstanceOf(PrototypeRunTimeoutError);

      // Now the session comes up. The missed send must not go out with it.
      initiator.run.handlePhase("handoff");
      responder.run.handlePhase("handoff");
      await initiator.reached("session-authenticated");
      await responder.reached("session-authenticated");
      const appLane = (channel: PairedChannel): Uint8Array[] =>
        channel.frames.filter((frame) => frame[0] === 1);
      expect(appLane(initiatorChannel)).toEqual([]);

      // And the next message is the first one the peer receives.
      await initiator.run.sendMessage(
        new TextEncoder().encode("sent in time"),
        1_000,
      );
      expect(
        new TextDecoder().decode(await responder.run.recvMessage(1_000)),
      ).toBe("sent in time");
    } finally {
      for (const subject of subjects) subject.run.stop();
      world.stop();
    }
  }, 60_000);

  test("the composition hands operations to driver.ingest one call at a time", async () => {
    const world = await createWorld();
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const parties: Party[] = [];
    try {
      const capability = new Uint8Array(32).fill(0xda);
      parties.push(
        await startParty(world, capability, sdpBytes("aaaa", 0xaa), gate),
        await startParty(world, capability, sdpBytes("bbbb", 0xbb), gate),
      );
      // Presence, HELLO, ACCEPT and OFFER travel through the stores until the
      // responder's ingest reaches `acceptOffer` and stays there.
      for (
        let window = CHAIN_START + 1n;
        window <= CHAIN_START + 12n &&
        parties.every((party) => party.acceptOfferCalls === 0);
        window += 1n
      )
        await world.advance(windowStartMs(window));
      const responder = parties.find((party) => party.acceptOfferCalls > 0);
      if (responder === undefined)
        throw new Error("no party reached acceptOffer");
      expect(responder.acceptOfferCalls).toBe(1);

      // A third holder of the capability announces itself. Its presence is
      // read and handed on while the responder's ingest is still waiting.
      const room = await makeRoom(capability, START_MS);
      const announcer = await addCarrier(world, room, [0, 1]);
      announcer.runtime.publish(
        await presenceFor(capability, world.scheduler),
        "PRESENCE",
      );
      const seenBefore = responder.run.runtime.counters.operationsSeen;
      const pausedAt = ingressWindow(
        world.profile.deliveryWindowMs,
        world.scheduler.nowMs,
      );
      await world.advance(windowStartMs(pausedAt + 3n));
      expect(responder.run.runtime.counters.operationsSeen).toBeGreaterThan(
        seenBefore,
      );
      // Delivered to a second `ingest` alongside the first, it would have
      // called `acceptOffer` again, which a browser refuses.
      expect(responder.acceptOfferCalls).toBe(1);

      release();
      for (
        let window = pausedAt + 4n;
        window <= pausedAt + 12n &&
        !parties.every((party) => kinds(party).includes("handoff"));
        window += 1n
      )
        await world.advance(windowStartMs(window));
      for (const party of parties) {
        expect(kinds(party)).toContain("handoff");
        expect(kinds(party)).not.toContain("failed");
      }
      expect(
        parties.reduce((total, party) => total + party.acceptOfferCalls, 0),
      ).toBe(1);
    } finally {
      release();
      for (const party of parties) party.run.stop();
      world.stop();
    }
  }, 120_000);

  test("a window no store served reaches the page as store-missed", async () => {
    const world = await createWorld();
    let party: Party | null = null;
    try {
      party = await startParty(
        world,
        new Uint8Array(32).fill(0xdb),
        sdpBytes("cccc", 0xcc),
        Promise.resolve(),
      );
      await world.advance(windowStartMs(W2));
      // Both stores refuse this client's read of W1, made at W2's read offset.
      for (const transport of party.transports) transport.down = true;
      await world.advance(windowStartMs(W2) + profile.publicReadOffsetMs + 1n);
      for (const transport of party.transports) transport.down = false;

      const forwarded = party.events.filter(
        (event) =>
          event.kind === "store-missed" &&
          (event.detail ?? "").startsWith(`runtime w${String(W1)}:`) &&
          (event.detail ?? "").includes("no store served"),
      );
      expect(forwarded).toHaveLength(1);
    } finally {
      party?.run.stop();
      world.stop();
    }
  }, 60_000);
});
