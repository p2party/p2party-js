/**
 * The carrier runtime: one fixed schedule per store, a union across both
 * (design doc §4.5), and the cross-store checkpoint gossip of §8.
 *
 * This is the component that turns two independently run stores into a
 * fault-tolerant pair. It publishes every operation to both, scans both, unions
 * the results by the private `OperationId`, and re-queues whatever only one of
 * them carried. Either store may fail, withhold, or lie, and the room still
 * converges as long as one honest store stays reachable.
 *
 * Three properties this file is responsible for:
 *
 * - **The schedule is fixed, not event-driven.** The same number of
 *   same-sized requests leave for every store in every window whether the
 *   outbox is empty or full: one token, one allocation, one append per
 *   `appendSchedule` entry, and one read. A real object simply takes a dummy's
 *   place. A store therefore cannot learn from traffic shape whether this
 *   client had anything to say, and a missed event stays missed — retrying
 *   inside a window would make the shape event-driven again, and retrying at
 *   the surviving store after an omission would be an active cross-store
 *   tagging channel.
 * - **The two stores never receive the same bytes.** Each publication is
 *   sealed separately under that store's `carrierContextId` with a fresh
 *   24-byte nonce, so one store cannot recognize the other's copy of an
 *   operation, and neither can a party watching both.
 * - **Nothing room-derived leaves.** Everything this file hands a store is
 *   either an opaque fixed-length object or public geometry. The room root,
 *   the operations, and the private `OperationId` union all stay here.
 *
 * And one it is responsible for NOT doing: every store is scheduled at the
 * same offsets, so the two stores' copies of one operation leave in the same
 * millisecond (design doc §3a item 1, the prototype's worst disclosed leak).
 * `#eventsForWindow` carries the measured reason a per-store phase offset was
 * rejected rather than added.
 *
 * Browser-safe by construction: like `storeClient.ts` it imports no `store/`
 * module (those reach for `node:fs` and `bun:sqlite`) and nothing Node-only.
 * It owns no wall clock either — the clock and the timer pair are injected, so
 * a harness or a test drives the schedule deterministically.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import { newKeyPair } from "../../cryptography/ed25519";
import { bytesEqual } from "../canonicalSchema";
import {
  CARRIER_AEAD_SUITE_1_NONCE_BYTES,
  buildCarrierPlaintext,
  createCarrierAeadProvider,
  decodeCarrierEnvelope,
  encodeCarrierEnvelope,
  openCarrierEnvelope,
  sealCarrierEnvelope,
} from "../carrierEnvelope";
import {
  mergeOperationCandidateSets,
  validateAndIdentifyOperationCandidate,
} from "../coreReduce";
import { sha256 } from "../derivations";
import { decodeOperation, encodeOperation } from "../operation";
import {
  ingressWindow,
  ingressWindowStartMs,
  roomLogicalWindow,
} from "../publicWindow";
import { sizeClassForPayloadClass } from "./profile";
import { buildAppendAdmission } from "./storeClient";
import { operationServiceRole } from "./workKinds";

import type { LibCrypto } from "../../cryptography/libcrypto";
import type {
  CarrierAeadProvider,
  CarrierEnvelopeV1,
  CarrierPlaintextV1,
} from "../carrierEnvelope";
import type { OuterValidatedIdentifiedOperationV1 } from "../coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  OperationPayloadClassV1,
  OperationValidationContext,
} from "../operation";
import type { DeliveryProfileV1, DeliverySizeClassV1 } from "./profile";
import type {
  PrototypeStoreClient,
  StoreFaultRecord,
  WindowScan,
} from "./storeClient";
import type { PublicAllocationLeaseV1 } from "./storeWire";
import type { OperationServiceRoleV1, ServiceWorkKindV1 } from "./workKinds";

/** Re-exported so one import gives a caller the runtime and the work vocabulary
 * it must label a publication with. The definition stays in `workKinds.ts`. */
export type { ServiceWorkKindV1 } from "./workKinds";

/**
 * What this client can currently say about carriage, from what it observed
 * itself and nothing else.
 *
 * It is deliberately not a trust or independence label: two stores on one
 * laptop produce `multi-store-union` exactly like two operators in two
 * jurisdictions would. It says how many carriers answered this client's last
 * read, and no more.
 */
export type StoreTopology =
  "multi-store-union" | "single-carrier-dependent" | "no-usable-carrier";

export interface CarrierEvent {
  readonly kind:
    "allocated" | "append" | "scan" | "operations" | "fault" | "missed";
  readonly storeIdHex?: string;
  readonly window: bigint;
  readonly detail?: string;
  readonly count?: number;
}

/**
 * Whatever the injected `setTimeout` returned, handed back only to the
 * injected `clearTimeout`.
 *
 * Deliberately not `ReturnType<typeof setTimeout>`: that is `number` in a
 * browser and `NodeJS.Timeout` under `@types/node`, and this file is bundled
 * for both. It is `unknown` and not `{}` because `clearTimeout`'s overloads
 * accept `undefined`, which `{}` excludes — the real global would then not be
 * assignable to `CarrierTimers`, and every production caller would need a cast.
 */
export type CarrierTimerHandle = unknown;

/**
 * The timer pair, as call signatures rather than `typeof setTimeout`.
 *
 * The global carries engine-specific extras (`__promisify__` under
 * `@types/node`) that a substitute scheduler cannot supply, and a caller that
 * cannot substitute its own timers cannot drive this schedule
 * deterministically. `{ setTimeout, clearTimeout }` — the real globals — is
 * assignable to this; the test file asserts that with the compiler.
 */
export interface CarrierTimers {
  setTimeout(callback: () => void, delayMs: number): CarrierTimerHandle;
  clearTimeout(handle: CarrierTimerHandle): void;
}

export interface CarrierRuntimeOptions {
  readonly module: LibCrypto;
  readonly roomRoot: Uint8Array;
  readonly profile: DeliveryProfileV1;
  readonly profileHash: Uint8Array;
  readonly stores: readonly PrototypeStoreClient[];
  readonly validationContextAt: (
    referenceLogicalWindow: bigint,
  ) => OperationValidationContext;
  readonly logicalWindowMs: bigint;
  readonly clock: { nowMs(): bigint };
  readonly timers: CarrierTimers;
  readonly onOperations: (
    fresh: readonly OuterValidatedIdentifiedOperationV1[],
  ) => void | Promise<void>;
  readonly onEvent?: (event: CarrierEvent) => void;
}

export interface CarrierCounters {
  /** Scheduled appends that carried an operation. */
  readonly appendsReal: number;
  /** Scheduled appends that carried cover. Their sum is the fixed schedule. */
  readonly appendsDummy: number;
  /** `scanWindow` calls, so one read of two stores counts two. */
  readonly scans: number;
  /** Distinct operations handed to `onOperations`, never redeliveries. */
  readonly operationsSeen: number;
  /** `(operation, store)` pairs queued for replication. */
  readonly backfills: number;
}

export class CarrierRuntimeError extends Error {
  override readonly name = "CarrierRuntimeError";

  constructor(message: string) {
    super(`carrierRuntime: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new CarrierRuntimeError(message);
};

/* ------------------------------------------------------------------ *
 * Bounds
 * ------------------------------------------------------------------ */

/**
 * How much undelivered work one runtime queues.
 *
 * The schedule drains at a fixed rate, so a caller that publishes faster than
 * the profile allows must be bounded somewhere. The oldest undelivered entry
 * is dropped rather than the newest: a stale operation is the one most likely
 * to have expired anyway, and the drop is reported as `missed`.
 */
const MAX_OUTBOX_ENTRIES = 256;

/** OperationIds already handed to `onOperations`, so a redelivery is free. */
const MAX_SEEN_OPERATION_IDS = 8_192;

/** `(OperationId, storeId)` pairs already backfilled: at most once, ever. */
const MAX_BACKFILL_PAIRS = 8_192;

/** Windows already read, so the stores' coincident read events read once. */
const MAX_READ_WINDOWS = 64;

/** Leases are consumed by the window they name; this bounds the rest. */
const MAX_HELD_LEASES = 8;

/** Split-view hints and outbox drops recorded by the runtime itself. */
const MAX_RECORDED_FAULTS = 512;

/** Two window advances always suffice; the cap only stops a corrupt profile. */
const MAX_SCHEDULE_ADVANCES = 1_024;

/** Handlers start no handlers, so one pass drains; the cap only stops a spin. */
const MAX_DRAIN_PASSES = 64;

/* ------------------------------------------------------------------ *
 * Scheduling
 * ------------------------------------------------------------------ */

/** The `kindByte` of the design's `(time, kindByte, class, slot, entry)` order:
 * within one instant a token precedes an allocation precedes an append
 * precedes a read, which is the order the protocol's dependencies run in. */
const EVENT_TOKEN = 0;
const EVENT_ALLOCATION = 1;
const EVENT_APPEND = 2;
const EVENT_READ = 4;

/**
 * The prototype drives exactly one room, so exactly one room slot.
 *
 * `roomSlotsPerClient` sizes the *profile's* chunk capacity for a client that
 * may hold several rooms at once; a runtime is one room and appends into slot
 * zero of its allocation. Publishing into slots this room does not use would
 * add requests no other client makes.
 */
const ROOM_SLOT = 0;

interface ScheduledEvent {
  readonly timeMs: bigint;
  readonly kindByte: number;
  /** The schedule's own window: a token and an allocation name `window + 1`,
   * an append names `window`, and a read names `window - 1`. */
  readonly window: bigint;
  readonly sizeClassId: number;
  readonly roomSlot: number;
  readonly entryIndex: number;
}

interface HeldLease {
  readonly lease: PublicAllocationLeaseV1;
  readonly secretKey: Uint8Array;
}

interface StoreSchedulerState {
  readonly store: PrototypeStoreClient;
  window: bigint;
  queue: readonly ScheduledEvent[];
  index: number;
  handle: CarrierTimerHandle | null;
  /** Leases by the ingress window they admit, keyed by `String(window)`. */
  readonly leases: Map<string, HeldLease>;
  lastScanStatus: WindowScan["status"] | null;
}

interface OutboxEntry {
  /** The exact canonical bytes both stores carry, identical across carriers. */
  readonly operationBytes: Uint8Array;
  readonly sizeClassId: number;
  readonly role: OperationServiceRoleV1;
  readonly workKind: ServiceWorkKindV1;
  /** `storeIdHex` values this entry is still owed to. */
  readonly targets: Set<string>;
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/** `getRandomValues` fills at most 65_536 bytes per call, and the larger size
 * class's body is bigger than that, so a dummy is filled in chunks. */
const RANDOM_CHUNK_BYTES = 65_536;

const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += RANDOM_CHUNK_BYTES)
    globalThis.crypto.getRandomValues(
      bytes.subarray(offset, Math.min(offset + RANDOM_CHUNK_BYTES, length)),
    );
  return bytes;
};

const detailOf = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown error";

/** Drop the oldest keys of an insertion-ordered set until it fits. */
const boundSet = (values: Set<string>, maximum: number): void => {
  while (values.size > maximum) {
    const oldest = values.keys().next();
    if (oldest.done) return;
    values.delete(oldest.value);
  }
};

/* ------------------------------------------------------------------ *
 * The runtime
 * ------------------------------------------------------------------ */

export class CarrierRuntime {
  readonly #module: LibCrypto;
  readonly #roomRoot: Uint8Array;
  readonly #profile: DeliveryProfileV1;
  readonly #profileHash: Uint8Array;
  /** The profile's size classes in id order: the order a scan returns. */
  readonly #classes: readonly DeliverySizeClassV1[];
  readonly #validationContextAt: (
    referenceLogicalWindow: bigint,
  ) => OperationValidationContext;
  readonly #logicalWindowMs: bigint;
  readonly #clock: { nowMs(): bigint };
  readonly #timers: CarrierTimers;
  readonly #onOperations: CarrierRuntimeOptions["onOperations"];
  readonly #onEvent: CarrierRuntimeOptions["onEvent"];
  readonly #aead: CarrierAeadProvider;

  readonly #schedulers: readonly StoreSchedulerState[];
  readonly #outbox: OutboxEntry[] = [];
  readonly #seen = new Set<string>();
  readonly #backfilled = new Set<string>();
  readonly #readWindows = new Set<string>();
  readonly #hinted = new Set<string>();
  readonly #faults: StoreFaultRecord[] = [];
  readonly #inFlight = new Set<Promise<void>>();

  #running = false;
  #counters: CarrierCounters = {
    appendsReal: 0,
    appendsDummy: 0,
    scans: 0,
    operationsSeen: 0,
    backfills: 0,
  };

  constructor(options: CarrierRuntimeOptions) {
    if (options.roomRoot.length !== 32)
      fail("the room root must be exactly 32 bytes");
    if (options.profileHash.length !== 32)
      fail("the delivery profile hash must be exactly 32 bytes");
    if (options.stores.length === 0)
      fail("a carrier runtime needs at least one store");
    if (options.logicalWindowMs <= 0n) fail("logicalWindowMs must be positive");
    // Every per-store book below is keyed by store identity, so two clients
    // for one identity would silently share leases, receipts and backfill
    // bookkeeping — and would not be two carriers in any case.
    if (
      new Set(options.stores.map((store) => store.storeIdHex)).size !==
      options.stores.length
    )
      fail("two stores of one runtime must have distinct identities");

    // Own the caller's secret before anything can await: the room root is the
    // key every publication and every open of this run depends on.
    this.#roomRoot = Uint8Array.from(options.roomRoot);
    this.#profileHash = Uint8Array.from(options.profileHash);
    this.#module = options.module;
    // Owned like the two byte strings above, and for the same reason: every
    // event reads the geometry, so a caller that mutated a size class mid-run
    // would move this client's traffic off the grid its stores expect.
    this.#profile = {
      ...options.profile,
      sizeClasses: options.profile.sizeClasses.map((sizeClass) => ({
        ...sizeClass,
        appendSchedule: sizeClass.appendSchedule.map((entry) => ({ ...entry })),
      })),
    };
    this.#classes = [...this.#profile.sizeClasses].sort(
      (left, right) => left.id - right.id,
    );
    this.#validationContextAt = options.validationContextAt;
    this.#logicalWindowMs = options.logicalWindowMs;
    this.#clock = options.clock;
    this.#timers = options.timers;
    this.#onOperations = options.onOperations;
    this.#onEvent = options.onEvent;
    this.#aead = createCarrierAeadProvider(options.module);
    this.#schedulers = options.stores.map((store) => ({
      store,
      window: 0n,
      queue: [],
      index: 0,
      handle: null,
      leases: new Map<string, HeldLease>(),
      lastScanStatus: null,
    }));
  }

  /* ---------------------------------------------------------------- *
   * Lifecycle
   * ---------------------------------------------------------------- */

  /**
   * Arm every store's schedule from the current instant.
   *
   * A runtime that starts after this window's allocation instant has no lease
   * for the window it is in: its appends still go out, on time and at full
   * size, as unallocated cover, and one immediate allocation is issued for the
   * next window so the schedule is admitted from there on. Suppressing them
   * instead would make the very first window of a session distinguishable.
   */
  start(): void {
    if (this.#running) fail("the runtime is already started");
    this.#running = true;

    const nowMs = this.#clock.nowMs();
    const window = ingressWindow(this.#profile.deliveryWindowMs, nowMs);
    const allocationInstantMs =
      ingressWindowStartMs(window, this.#profile.deliveryWindowMs) +
      this.#profile.allocationRequestOffsetMs;

    for (const state of this.#schedulers) {
      state.window = window;
      state.queue = this.#eventsForWindow(window);
      state.index = 0;
      if (nowMs >= allocationInstantMs) {
        this.#emit({
          kind: "missed",
          storeIdHex: state.store.storeIdHex,
          window,
          detail:
            "cold start past the allocation offset: this window's appends are unallocated cover",
        });
        // The cold-start request *is* this window's allocation. Starting
        // exactly on the offset would otherwise leave the queued event due at
        // this instant as well, and two allocation requests for one target
        // window are one more than the profile's fixed shape.
        state.queue = state.queue.filter(
          (event) => event.kindByte !== EVENT_ALLOCATION,
        );
        this.#spawn(this.#allocate(state, window + 1n));
      }
      this.#arm(state);
    }
  }

  /** Disarm every schedule and wipe the allocation secrets still held. */
  stop(): void {
    this.#running = false;
    for (const state of this.#schedulers) {
      if (state.handle !== null) this.#timers.clearTimeout(state.handle);
      state.handle = null;
      for (const held of state.leases.values()) held.secretKey.fill(0);
      state.leases.clear();
    }
  }

  /**
   * Resolve once every handler this runtime has already started has settled.
   *
   * The scheduler is deliberately fire-and-forget — one slow store must not
   * delay another store's next event — so a caller that drives the clock
   * itself needs one way to await the work a tick released. It starts nothing
   * and arms nothing.
   *
   * Handlers start no handlers, so one pass settles everything. Returning
   * quietly with work still in flight would make a harness that trusts this as
   * its synchronisation point flake for no visible reason, so it throws.
   */
  async drain(): Promise<void> {
    for (let guard = 0; guard < MAX_DRAIN_PASSES; guard += 1) {
      if (this.#inFlight.size === 0) return;
      await Promise.all([...this.#inFlight]);
    }
    if (this.#inFlight.size > 0)
      fail("handlers are still in flight after the drain bound");
  }

  /* ---------------------------------------------------------------- *
   * Publication
   * ---------------------------------------------------------------- */

  /**
   * Queue one operation for every store this runtime carries.
   *
   * Nothing is sent here. The operation waits for the next scheduled append of
   * its service role and size class, which is what makes a publication look
   * exactly like silence from a store's side.
   */
  publish(
    operation: AuthenticatedRoomOperationV1,
    workKind: ServiceWorkKindV1,
  ): void {
    // Snapshot synchronously: these are the exact bytes both stores will carry
    // and the ones the recipients' OperationId is derived from, so the caller
    // must not be able to change them afterwards.
    const operationBytes = encodeOperation(operation);
    const payloadClass = decodeOperation(operationBytes).operationPayloadClass;
    this.#enqueue(
      operationBytes,
      payloadClass,
      workKind,
      this.#schedulers.map((state) => state.store.storeIdHex),
    );
  }

  /* ---------------------------------------------------------------- *
   * What this client currently knows
   * ---------------------------------------------------------------- */

  /**
   * Counted from this client's own last completed read and nothing else.
   *
   * It is never evidence that the stores are independently operated, and it
   * never becomes one: a store's own claims about other stores are not read.
   */
  get storeTopology(): StoreTopology {
    let usable = 0;
    for (const state of this.#schedulers)
      if (!state.store.inert && state.lastScanStatus === "finalized")
        usable += 1;
    if (usable >= 2) return "multi-store-union";
    if (usable === 1) return "single-carrier-dependent";
    return "no-usable-carrier";
  }

  /** Every store's own faults, plus the cross-store hints only this layer can
   * see because only it holds both stores' verified checkpoint hashes. */
  get faults(): readonly StoreFaultRecord[] {
    const collected: StoreFaultRecord[] = [];
    for (const state of this.#schedulers) collected.push(...state.store.faults);
    for (const fault of this.#faults) collected.push({ ...fault });
    return collected;
  }

  get counters(): CarrierCounters {
    return { ...this.#counters };
  }

  /* ---------------------------------------------------------------- *
   * The schedule
   * ---------------------------------------------------------------- */

  /**
   * Every event of one window, in the design's
   * `(time, kindByte, class, slot, entry)` order.
   *
   * Every store gets the same offsets, which is the design's §3a item 1 leak:
   * a party who sees both stores' request logs pairs their two copies of one
   * operation by arrival time alone, with no identifiers involved. This is the
   * one item on that list this scheduler could in principle fix, and it
   * deliberately does not. The band was measured against the pinned profile —
   * `carrierRuntime.test.ts`, "bounds the per-store phase offset this
   * profile's geometry could pay for" — and it does not buy anything:
   *
   * - **It is too narrow to matter.** Moving a store's whole ingress schedule
   *   earlier stops at 100 ms (the token offset reaches zero) and later at
   *   499 ms (`chunkFinalizationOffsetMs` 2800, less `maxScheduleSkewMs` 200,
   *   less the last append at 2100), so two stores can be separated by at most
   *   599 ms of a 4000 ms window. No write crosses a window boundary, and an
   *   observer joining two logs partitions them by window before anything
   *   else, so the candidate set is identical with the offset and without it.
   *   The literature's mitigation is a delay drawn WIDE against the epoch;
   *   this geometry has nothing that wide to give.
   * - **A phase derived from `carrierContextId` is public.** It is
   *   `H(StoreId || DeliveryProfileHash)`: every client of a store shares it,
   *   and anyone holding that store's published descriptor recomputes it. That
   *   is not decorrelation, it is each store running the same grid under a
   *   different name, and an observer subtracts one known constant.
   * - **A per-client phase would be worse.** It breaks the translation, but it
   *   is stable across windows by construction, so it is a timing fingerprint
   *   each store alone can use to link one client's windows to each other, and
   *   it puts that client outside the `maxScheduleSkewMs` band the profile
   *   defines as conforming drift. The anonymity set of a fixed schedule is
   *   everyone on the grid.
   * - **A fresh phase per window per store** spreads no wider — it is the same
   *   599 ms — and costs the fixed schedule itself: this client's own trace
   *   would stop being the same every window, which is the property §4.5 and
   *   the first bullet of this file's header exist to keep. Rejected for that
   *   reason and not for the spread.
   *
   * What would work needs no new geometry at all: hold one store's copy for a
   * whole number of windows drawn from a wide distribution and let its slot
   * carry cover in the meantime. Nothing changes on the wire — a real object
   * and cover are already the same bytes at the same instant — the schedule
   * stays exactly fixed, and the delay is finally wide against the epoch. It
   * costs k windows of replication latency and a longer window in which one
   * store is the only carrier, which is a decision about latency and f=1
   * exposure rather than about this scheduler.
   */
  #eventsForWindow(window: bigint): readonly ScheduledEvent[] {
    const startMs = ingressWindowStartMs(
      window,
      this.#profile.deliveryWindowMs,
    );
    const events: ScheduledEvent[] = [
      {
        timeMs: startMs + this.#profile.tokenIssueOffsetMs,
        kindByte: EVENT_TOKEN,
        window,
        sizeClassId: -1,
        roomSlot: -1,
        entryIndex: -1,
      },
      {
        timeMs: startMs + this.#profile.allocationRequestOffsetMs,
        kindByte: EVENT_ALLOCATION,
        window,
        sizeClassId: -1,
        roomSlot: -1,
        entryIndex: -1,
      },
      {
        timeMs: startMs + this.#profile.publicReadOffsetMs,
        kindByte: EVENT_READ,
        window,
        sizeClassId: -1,
        roomSlot: -1,
        entryIndex: -1,
      },
    ];
    for (const sizeClass of this.#classes)
      for (let entry = 0; entry < sizeClass.appendSchedule.length; entry += 1)
        events.push({
          timeMs: startMs + sizeClass.appendSchedule[entry].offsetMs,
          kindByte: EVENT_APPEND,
          window,
          sizeClassId: sizeClass.id,
          roomSlot: ROOM_SLOT,
          entryIndex: entry,
        });

    return events.sort((left, right) => {
      if (left.timeMs !== right.timeMs)
        return left.timeMs < right.timeMs ? -1 : 1;
      if (left.kindByte !== right.kindByte)
        return left.kindByte - right.kindByte;
      if (left.sizeClassId !== right.sizeClassId)
        return left.sizeClassId - right.sizeClassId;
      if (left.roomSlot !== right.roomSlot)
        return left.roomSlot - right.roomSlot;
      return left.entryIndex - right.entryIndex;
    });
  }

  /**
   * The next event at or after `nowMs`, skipping whatever is already past.
   *
   * Skipping is the point: an event whose instant has gone is missed for good.
   * Firing it late would move this client's traffic off the profile's grid,
   * which is exactly the shape the fixed schedule exists to hide.
   */
  #nextEvent(state: StoreSchedulerState, nowMs: bigint): ScheduledEvent | null {
    for (let guard = 0; guard < MAX_SCHEDULE_ADVANCES; guard += 1) {
      if (state.index < state.queue.length) {
        const event = state.queue[state.index];
        if (event.timeMs >= nowMs) return event;
        state.index += 1;
        continue;
      }
      const current = ingressWindow(this.#profile.deliveryWindowMs, nowMs);
      state.window = state.window + 1n > current ? state.window + 1n : current;
      state.queue = this.#eventsForWindow(state.window);
      state.index = 0;
    }
    return null;
  }

  #arm(state: StoreSchedulerState): void {
    if (!this.#running) return;
    const nowMs = this.#clock.nowMs();
    const event = this.#nextEvent(state, nowMs);
    if (event === null) return;
    const delayMs = event.timeMs - nowMs;
    state.handle = this.#timers.setTimeout(
      () => {
        state.handle = null;
        state.index += 1;
        // The next event is armed before the work runs, so a slow store shifts
        // nothing: its own next request still leaves on the profile's grid.
        this.#arm(state);
        this.#spawn(this.#runEvent(state, event));
      },
      Number(delayMs < 0n ? 0n : delayMs),
    );
  }

  async #runEvent(
    state: StoreSchedulerState,
    event: ScheduledEvent,
  ): Promise<void> {
    if (!this.#running) return;
    switch (event.kindByte) {
      case EVENT_TOKEN:
        return this.#issueToken(state, event.window + 1n);
      case EVENT_ALLOCATION:
        return this.#allocate(state, event.window + 1n);
      case EVENT_APPEND:
        return this.#append(state, event);
      case EVENT_READ:
        // `publicReadLagWindows` is 1; a window below the first has no
        // predecessor to read.
        if (event.window === 0n) return;
        return this.#read(event.window - 1n);
      default:
        return;
    }
  }

  /* ---------------------------------------------------------------- *
   * Ingress events
   * ---------------------------------------------------------------- */

  async #issueToken(
    state: StoreSchedulerState,
    targetWindow: bigint,
  ): Promise<void> {
    // Open mode issues no authority, so the answer is discarded — but the
    // request is part of the profile's shape and a client that skipped it
    // would be distinguishable from one that did not.
    if (!(await state.store.issueToken(targetWindow)))
      this.#emit({
        kind: "missed",
        storeIdHex: state.store.storeIdHex,
        window: targetWindow,
        detail: "the store issued no allocation token",
      });
  }

  async #allocate(
    state: StoreSchedulerState,
    targetWindow: bigint,
  ): Promise<void> {
    // One fresh key per window per store: a reused allocation key would let a
    // store link this client's windows to each other, and two stores holding
    // the same key would link this client across them.
    const keyPair = await newKeyPair(this.#module);
    const lease = await state.store.allocate(targetWindow, keyPair);
    if (lease === null) {
      keyPair.secretKey.fill(0);
      this.#emit({
        kind: "missed",
        storeIdHex: state.store.storeIdHex,
        window: targetWindow,
        detail: "the store granted no allocation lease",
      });
      return;
    }

    const key = String(targetWindow);
    state.leases.get(key)?.secretKey.fill(0);
    state.leases.set(key, { lease, secretKey: keyPair.secretKey });
    while (state.leases.size > MAX_HELD_LEASES) {
      const oldest = state.leases.keys().next();
      if (oldest.done) break;
      state.leases.get(oldest.value)?.secretKey.fill(0);
      state.leases.delete(oldest.value);
    }
    this.#emit({
      kind: "allocated",
      storeIdHex: state.store.storeIdHex,
      window: targetWindow,
      count: lease.allocationOrdinal,
    });
  }

  /**
   * One scheduled append: a real object if the outbox holds compatible work
   * for this role and class, and a dummy of the identical length if not.
   */
  async #append(
    state: StoreSchedulerState,
    event: ScheduledEvent,
  ): Promise<void> {
    const storeIdHex = state.store.storeIdHex;
    const sizeClass = this.#sizeClass(event.sizeClassId);
    const schedule = sizeClass.appendSchedule;
    const objectOrdinal = event.roomSlot * schedule.length + event.entryIndex;
    const window = event.window;

    const built = await this.#buildObject(
      state.store,
      window,
      sizeClass,
      this.#pendingEntry(
        storeIdHex,
        schedule[event.entryIndex].role,
        sizeClass.id,
      ),
    );
    if (built === null) {
      this.#emit({
        kind: "missed",
        storeIdHex,
        window,
        detail: "no carrier object could be built for this slot",
      });
      return;
    }
    const { object, entry } = built;
    // `stop` wipes the allocation secrets, so a runtime stopped while this
    // handler was sealing must not go on to sign an admission with zeroes.
    if (!this.#running) return;

    if (entry === null) this.#count({ appendsDummy: 1 });
    else this.#count({ appendsReal: 1 });

    // No lease for this window means the store answers `unallocated-cover` and
    // discards the object. The request still goes out, at the same instant and
    // the same size, because its absence would be the signal.
    const held = state.leases.get(String(window)) ?? null;
    const admission =
      held === null
        ? null
        : await buildAppendAdmission(
            held.lease,
            held.secretKey,
            sizeClass.id,
            objectOrdinal,
            object,
            this.#module,
          );

    this.#emit({
      kind: "append",
      storeIdHex,
      window,
      detail: entry === null ? "cover" : entry.workKind,
      count: objectOrdinal,
    });

    const result = await state.store.append(
      window,
      sizeClass.id,
      object,
      admission,
    );
    if (
      result === null ||
      (result.status !== "stored" && result.status !== "already-present")
    ) {
      // The entry stays queued: it goes out at the next slot of this role,
      // never as an extra request inside this window.
      this.#emit({
        kind: "missed",
        storeIdHex,
        window,
        detail: `append ${result === null ? "unanswered" : result.status}`,
      });
      return;
    }
    if (entry === null || held === null) return;

    entry.targets.delete(storeIdHex);
    if (entry.targets.size === 0) this.#dropEntry(entry);
    // The receipt is the whole input to the custody check the next scan runs:
    // the store has now signed that these exact bytes are in this exact slot.
    state.store.recordReceipt({
      window,
      sizeClass: sizeClass.id,
      lease: held.lease,
      objectOrdinal,
      objectHash: await sha256(object),
      result,
    });
  }

  /* ---------------------------------------------------------------- *
   * Objects
   * ---------------------------------------------------------------- */

  /**
   * The object this slot will carry and the entry it consumed, or `null` when
   * not even cover could be built.
   *
   * The slot is fixed; the entry is not. An operation that cannot be sealed
   * into its size class — a profile whose class is too small for what this
   * room publishes, say — must not take the slot down with it: unguarded, the
   * throw would leave no request sent at all, and since `#pendingEntry` would
   * select the same entry again next window, that (role, class) slot would go
   * silent for every store forever. That is the exact inverse of the fixed
   * schedule, so the entry is dropped and the slot carries cover instead.
   */
  async #buildObject(
    store: PrototypeStoreClient,
    window: bigint,
    sizeClass: DeliverySizeClassV1,
    entry: OutboxEntry | null,
  ): Promise<{
    readonly object: Uint8Array;
    readonly entry: OutboxEntry | null;
  } | null> {
    if (entry !== null) {
      try {
        return {
          object: await this.#sealObject(
            store,
            window,
            sizeClass,
            entry.operationBytes,
          ),
          entry,
        };
      } catch (error) {
        // Not a store fault: the store did nothing here, and blaming it for
        // what this client was handed would put a false record in the
        // evidence this runtime collects about carriers.
        if (this.#dropEntry(entry))
          this.#emit({
            kind: "missed",
            storeIdHex: store.storeIdHex,
            window,
            detail: `an outbox entry could not be sealed into size class ${String(sizeClass.id)} and was dropped: ${detailOf(error)}`,
          });
      }
    }
    try {
      return {
        object: await this.#coverObject(store, window, sizeClass),
        entry: null,
      };
    } catch {
      // Cover this profile cannot build means its own geometry is unusable;
      // there is nothing honest to put on the wire for this slot.
      return null;
    }
  }

  async #sealObject(
    store: PrototypeStoreClient,
    window: bigint,
    sizeClass: DeliverySizeClassV1,
    operationBytes: Uint8Array,
  ): Promise<Uint8Array> {
    return this.#seal(
      this.#roomRoot,
      store,
      window,
      sizeClass,
      buildCarrierPlaintext(operationBytes, sizeClass.fixedCarrierObjectBytes),
    );
  }

  /**
   * Cover, sealed exactly the way a real object is.
   *
   * Filling `ciphertextAndTag` with random bytes would give the same wire
   * result at the same cost in bytes — but not at the same cost in time: the
   * real path awaits an HKDF and an AEAD before its POST and a synchronous
   * path would not, so a store reading its own clock would see real appends
   * land systematically later than cover. Doing the identical work over a
   * one-off random root removes that difference by construction. The root is
   * discarded here, so this object opens for nobody — not even for another
   * member of this room, who could otherwise tell this client's cover apart
   * from an unrelated room's traffic.
   */
  async #coverObject(
    store: PrototypeStoreClient,
    window: bigint,
    sizeClass: DeliverySizeClassV1,
  ): Promise<Uint8Array> {
    const throwawayRoot = randomBytes(32);
    try {
      return await this.#seal(
        throwawayRoot,
        store,
        window,
        sizeClass,
        buildCarrierPlaintext(
          new Uint8Array(0),
          sizeClass.fixedCarrierObjectBytes,
        ),
      );
    } finally {
      throwawayRoot.fill(0);
    }
  }

  /**
   * One sealed object: the same key schedule, the same AEAD call and the same
   * plaintext length whatever the root is, so a class's exact wire length
   * comes out by construction rather than from a constant that could drift
   * away from the codec.
   */
  async #seal(
    root: Uint8Array,
    store: PrototypeStoreClient,
    window: bigint,
    sizeClass: DeliverySizeClassV1,
    plaintext: CarrierPlaintextV1,
  ): Promise<Uint8Array> {
    const envelope = await sealCarrierEnvelope(
      root,
      {
        deliveryProfileHash: this.#profileHash,
        carrierContextId: store.carrierContextId,
        ingressWindow: window,
        sizeClass: sizeClass.id,
      },
      randomBytes(CARRIER_AEAD_SUITE_1_NONCE_BYTES),
      plaintext,
      this.#aead,
    );
    return encodeCarrierEnvelope(envelope);
  }

  /* ---------------------------------------------------------------- *
   * The read: union, backfill, witnessing
   * ---------------------------------------------------------------- */

  /**
   * Read one window from every store and reduce it to one operation set.
   *
   * Every store's read event for a window lands on the same instant, so the
   * first to arrive performs the whole read: one scan per store, one union,
   * one delivery. A second pass would re-fetch the same windows and hand the
   * caller the same operations again.
   */
  async #read(window: bigint): Promise<void> {
    const key = String(window);
    if (this.#readWindows.has(key)) return;
    this.#readWindows.add(key);
    boundSet(this.#readWindows, MAX_READ_WINDOWS);

    const scans = await Promise.all(
      this.#schedulers.map((state) => state.store.scanWindow(window)),
    );
    this.#count({ scans: scans.length });
    for (let index = 0; index < scans.length; index += 1) {
      this.#schedulers[index].lastScanStatus = scans[index].status;
      this.#emit({
        kind: "scan",
        storeIdHex: this.#schedulers[index].store.storeIdHex,
        window,
        detail: scans[index].status,
        count: scans[index].objects.length,
      });
    }
    if (!this.#running) return;

    const carriedBy = new Map<string, Set<string>>();
    let union: readonly OuterValidatedIdentifiedOperationV1[] = [];
    for (let index = 0; index < scans.length; index += 1) {
      const state = this.#schedulers[index];
      const observed = await this.#openObjects(
        state.store,
        window,
        scans[index].objects,
      );
      for (const candidate of observed) {
        const idHex = hexOf(candidate.operationId);
        const holders = carriedBy.get(idHex) ?? new Set<string>();
        holders.add(state.store.storeIdHex);
        carriedBy.set(idHex, holders);
      }
      union = mergeOperationCandidateSets(union, observed);
    }

    const fresh = union.filter(
      (candidate) => !this.#seen.has(hexOf(candidate.operationId)),
    );
    for (const candidate of fresh) this.#seen.add(hexOf(candidate.operationId));
    boundSet(this.#seen, MAX_SEEN_OPERATION_IDS);
    this.#count({ operationsSeen: fresh.length });

    if (fresh.length > 0) {
      this.#emit({ kind: "operations", window, count: fresh.length });
      // Delivery is the caller's business; replication and witnessing are this
      // runtime's, and a caller whose handler throws must not silently cost
      // the pair a backfill.
      try {
        await this.#onOperations(fresh);
      } catch (error) {
        this.#emit({
          kind: "missed",
          window,
          detail: `the operations handler threw: ${detailOf(error)}`,
        });
      }
      this.#queueBackfills(fresh, carriedBy, window);
    }

    await this.#witness(window, scans);
  }

  /**
   * Decode, filter and open every object of one store's window.
   *
   * The header filter is what stops a store from choosing what this client
   * decrypts: an object copied out of another bucket or out of the other
   * store's carrier context is refused before the AEAD sees it, so the only
   * objects opened are ones whose public coordinates the store itself
   * committed to in the checkpoint the scan already verified.
   */
  async #openObjects(
    store: PrototypeStoreClient,
    window: bigint,
    objects: readonly Uint8Array[],
  ): Promise<readonly OuterValidatedIdentifiedOperationV1[]> {
    if (objects.length === 0) return [];
    // The room's own clock, never the carrier's: which operations are live is
    // a room decision, and letting the delivery geometry set it would give a
    // store a lever over validity.
    const context = this.#validationContextAt(
      roomLogicalWindow(this.#logicalWindowMs, this.#clock.nowMs()),
    );

    const identified: OuterValidatedIdentifiedOperationV1[] = [];
    let index = 0;
    for (const sizeClass of this.#classes) {
      const bucketObjects =
        sizeClass.publicChunksPerWindow * this.#profile.publicChunkObjectCount;
      for (
        let position = 0;
        position < bucketObjects && index < objects.length;
        position += 1, index += 1
      ) {
        const candidate = await this.#openObject(
          store,
          window,
          sizeClass.id,
          objects[index],
          context,
        );
        if (candidate !== null) identified.push(candidate);
      }
    }
    return identified;
  }

  async #openObject(
    store: PrototypeStoreClient,
    window: bigint,
    sizeClassId: number,
    object: Uint8Array,
    context: OperationValidationContext,
  ): Promise<OuterValidatedIdentifiedOperationV1 | null> {
    let envelope: CarrierEnvelopeV1;
    try {
      envelope = decodeCarrierEnvelope(object);
    } catch {
      return null;
    }
    if (
      envelope.version !== 1 ||
      !bytesEqual(envelope.deliveryProfileHash, this.#profileHash) ||
      envelope.ingressWindow !== window ||
      envelope.sizeClass !== sizeClassId ||
      !bytesEqual(envelope.carrierContextId, store.carrierContextId)
    )
      return null;

    let operationBytes: Uint8Array;
    try {
      const plaintext = await openCarrierEnvelope(
        this.#roomRoot,
        envelope,
        this.#aead,
      );
      // A failed open is cover, never a fault: every object of every other
      // room in this bucket looks exactly like this, which is the whole point
      // of unrelated rooms sharing one carrier.
      if (plaintext === null) return null;
      operationBytes = plaintext.operationBytes;
    } catch {
      return null;
    }

    try {
      return await validateAndIdentifyOperationCandidate(
        decodeOperation(operationBytes),
        context,
        this.#module,
      );
    } catch (error) {
      // It opened under this room's key, so it was addressed here and failing
      // is worth reporting — but one bad operation must not end the window.
      this.#emit({
        kind: "missed",
        storeIdHex: store.storeIdHex,
        window,
        detail: `a carried operation did not validate: ${detailOf(error)}`,
      });
      return null;
    }
  }

  /**
   * Re-queue what only some stores carried, for the ones that missed it.
   *
   * This is the whole of the pair's fault tolerance: a store that was down,
   * refused an allocation, or dropped an object is caught up by any client
   * that saw the operation elsewhere. An unbounded replication loop between
   * two clients would be both a beacon and a flood, so each
   * `(operation, store)` pair is queued at most once for as long as this
   * runtime remembers it: `#backfilled` keeps the most recent
   * `MAX_BACKFILL_PAIRS`, and past that the oldest pairs are forgotten and
   * could be replicated once more. That is bounded rework rather than a loop,
   * because the operation must also be freshly seen and still absent from that
   * store for a second one to be queued.
   */
  #queueBackfills(
    fresh: readonly OuterValidatedIdentifiedOperationV1[],
    carriedBy: ReadonlyMap<string, ReadonlySet<string>>,
    window: bigint,
  ): void {
    for (const candidate of fresh) {
      const idHex = hexOf(candidate.operationId);
      const holders = carriedBy.get(idHex);
      if (holders === undefined || holders.size >= this.#schedulers.length)
        continue;

      const missing: string[] = [];
      for (const state of this.#schedulers) {
        const storeIdHex = state.store.storeIdHex;
        if (holders.has(storeIdHex)) continue;
        const pair = `${idHex}:${storeIdHex}`;
        if (this.#backfilled.has(pair)) continue;
        this.#backfilled.add(pair);
        missing.push(storeIdHex);
      }
      boundSet(this.#backfilled, MAX_BACKFILL_PAIRS);
      if (missing.length === 0) continue;

      this.#enqueue(
        encodeOperation(candidate.operation),
        candidate.operation.operationPayloadClass,
        "REPLICATION_OR_BACKFILL",
        missing,
      );
      this.#count({ backfills: missing.length });
      this.#emit({
        kind: "operations",
        window,
        detail: "queued for backfill",
        count: missing.length,
      });
    }
  }

  /**
   * Gossip every verified checkpoint to the other stores and read theirs back
   * (design doc §8).
   *
   * A record that names a store this client verified, carrying a different
   * checkpoint hash than that store showed this client, is a
   * `checkpoint-split-view-hint` and nothing more. It is NOT a proof and it
   * does NOT make the store inert: the specification's conflict proof needs
   * two checkpoints the store itself signed, and a witness record is
   * unauthenticated peer input that any store could have written. Only a
   * re-fetch, or a second observer, can turn a hint into evidence.
   */
  async #witness(window: bigint, scans: readonly WindowScan[]): Promise<void> {
    for (let index = 0; index < this.#schedulers.length; index += 1) {
      const witnessed = this.#schedulers[index];
      if (witnessed.store.inert || scans[index].status !== "finalized")
        continue;
      const checkpointHash = witnessed.store.checkpointHashFor(window);
      if (checkpointHash === null) continue;

      for (const carrier of this.#schedulers) {
        if (carrier === witnessed || carrier.store.inert) continue;
        if (!this.#running) return;
        await carrier.store.postWitness({
          version: 1,
          witnessedStoreId: witnessed.store.storeId,
          deliveryProfileHash: this.#profileHash,
          ingressWindow: window,
          checkpointHash,
        });
        for (const record of await carrier.store.readWitnesses(window)) {
          if (!bytesEqual(record.witnessedStoreId, witnessed.store.storeId))
            continue;
          if (bytesEqual(record.checkpointHash, checkpointHash)) continue;
          this.#hint(
            witnessed.store.storeIdHex,
            window,
            `store ${carrier.store.storeIdHex} holds a different checkpoint for this window than the witnessed store showed this client`,
          );
        }
      }
    }
  }

  /* ---------------------------------------------------------------- *
   * The outbox
   * ---------------------------------------------------------------- */

  #enqueue(
    operationBytes: Uint8Array,
    payloadClass: OperationPayloadClassV1,
    workKind: ServiceWorkKindV1,
    targets: readonly string[],
  ): void {
    if (targets.length === 0) return;
    const sizeClass = sizeClassForPayloadClass(this.#profile, payloadClass);
    while (this.#outbox.length >= MAX_OUTBOX_ENTRIES) {
      this.#outbox.shift();
      this.#emit({
        kind: "missed",
        window: this.#currentWindow(),
        detail:
          "the outbox is full; the oldest undelivered operation was dropped",
      });
    }
    this.#outbox.push({
      operationBytes,
      sizeClassId: sizeClass.id,
      role: operationServiceRole(workKind),
      workKind,
      targets: new Set(targets),
    });
  }

  /** The oldest entry this store still owes for this role and size class. */
  #pendingEntry(
    storeIdHex: string,
    role: OperationServiceRoleV1,
    sizeClassId: number,
  ): OutboxEntry | null {
    for (const entry of this.#outbox)
      if (
        entry.role === role &&
        entry.sizeClassId === sizeClassId &&
        entry.targets.has(storeIdHex)
      )
        return entry;
    return null;
  }

  /** True when this call was the one that removed it. */
  #dropEntry(entry: OutboxEntry): boolean {
    const index = this.#outbox.indexOf(entry);
    if (index < 0) return false;
    this.#outbox.splice(index, 1);
    return true;
  }

  /* ---------------------------------------------------------------- *
   * Internals
   * ---------------------------------------------------------------- */

  #sizeClass(sizeClassId: number): DeliverySizeClassV1 {
    const found = this.#classes.find(
      (sizeClass) => sizeClass.id === sizeClassId,
    );
    if (found === undefined)
      fail(`no size class with id ${String(sizeClassId)} in this profile`);
    return found;
  }

  #currentWindow(): bigint {
    return ingressWindow(this.#profile.deliveryWindowMs, this.#clock.nowMs());
  }

  #count(delta: Partial<CarrierCounters>): void {
    this.#counters = {
      appendsReal: this.#counters.appendsReal + (delta.appendsReal ?? 0),
      appendsDummy: this.#counters.appendsDummy + (delta.appendsDummy ?? 0),
      scans: this.#counters.scans + (delta.scans ?? 0),
      operationsSeen:
        this.#counters.operationsSeen + (delta.operationsSeen ?? 0),
      backfills: this.#counters.backfills + (delta.backfills ?? 0),
    };
  }

  /**
   * Record one split-view hint, once per store per window.
   *
   * It is the only fault this layer originates — everything else a store does
   * wrong is the client adapter's to prove — and a store that gossips the same
   * lie every window must not be able to fill this client's fault log with it.
   */
  #hint(storeIdHex: string, window: bigint, detail: string): void {
    const key = `${storeIdHex}:${String(window)}`;
    if (this.#hinted.has(key)) return;
    this.#hinted.add(key);
    boundSet(this.#hinted, MAX_RECORDED_FAULTS);
    if (this.#faults.length >= MAX_RECORDED_FAULTS) return;
    this.#faults.push({
      storeIdHex,
      kind: "checkpoint-split-view-hint",
      window,
      detail,
    });
    this.#emit({ kind: "fault", storeIdHex, window, detail });
  }

  #emit(event: CarrierEvent): void {
    // A caller's observer must not be able to break the schedule.
    try {
      this.#onEvent?.(event);
    } catch {
      /* Observation is best effort. */
    }
  }

  /**
   * Track one released handler so `drain` can await it and a rejection can
   * never surface as an unhandled promise.
   */
  #spawn(work: Promise<void>): void {
    const tracked: Promise<void> = work
      .catch((error: unknown) => {
        this.#emit({
          kind: "missed",
          window: this.#currentWindow(),
          detail: `a scheduled event failed: ${detailOf(error)}`,
        });
      })
      .finally(() => {
        this.#inFlight.delete(tracked);
      });
    this.#inFlight.add(tracked);
  }
}
