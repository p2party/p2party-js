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
 *   `appendSchedule` entry, and one read — thirteen requests at the pinned
 *   profile. The witness pair is the one exception: it leaves at a fixed
 *   offset, but whether it leaves is conditional on the other store's scan
 *   (design doc §3a item 14). A real object simply takes a dummy's place. A
 *   store therefore cannot learn from traffic shape whether this client had
 *   anything to say. A timer the engine delivers late fires its events late
 *   rather than dropping them — a late request is the same request, a
 *   dropped one changes the count — and nothing is ever retried: retrying
 *   inside a window would make the shape event-driven again, and retrying at
 *   the surviving store after an omission would be an active cross-store
 *   tagging channel. `#takeDue` holds the one bound on lateness.
 * - **The application never holds the schedule.** Fresh operations are
 *   handed to `onOperations` one call at a time and never awaited by a
 *   scheduled event, so a callback that is slow, throws or never returns
 *   moves no request (`#deliver`).
 * - **A suspension is caught up, not replayed.** Reads more than a window
 *   late are read one window at a time per store, in the gaps of the
 *   schedule (`#catchUp`); uploads that late are not sent.
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
import { validateAndIdentifyOperationCandidate } from "../coreReduce";
import { sha256 } from "../derivations";
import { decodeOperation, encodeOperation } from "../operation";
import {
  ingressWindow,
  ingressWindowStartMs,
  roomLogicalWindow,
} from "../publicWindow";
import { PROTOTYPE_MAX_READ_WINDOWS } from "../../utils/constants";
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
  /**
   * Called with every batch of operations this runtime has not delivered
   * before. Never called again while a returned promise is pending, and never
   * awaited by the schedule: batches that arrive meanwhile are merged into the
   * next call.
   */
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

/**
 * How far behind the clock the schedule catches up, in windows.
 *
 * A late timer fires every event it held back, but a page suspended for
 * minutes would otherwise come back as a burst of every window it slept
 * through. Past this many windows the older ones are given up whole and
 * reported `missed`. It also bounds the per-window read bookkeeping, which
 * never needs to reach further back than the schedule does.
 */
const MAX_READ_WINDOWS = PROTOTYPE_MAX_READ_WINDOWS;

/** Leases are consumed by the window they name; this bounds the rest. */
const MAX_HELD_LEASES = 8;

/** Split-view hints and outbox drops recorded by the runtime itself. */
const MAX_RECORDED_FAULTS = 512;

/**
 * Events one timer callback releases. A callback that reaches it re-arms at
 * once and goes on, so the cap bounds one task's synchronous work, not how far
 * the schedule catches up.
 */
const MAX_EVENTS_PER_TIMER = 1_024;

/** Handlers start no handlers, so one pass drains; the cap only stops a spin. */
const MAX_DRAIN_PASSES = 64;

/* ------------------------------------------------------------------ *
 * Scheduling
 * ------------------------------------------------------------------ */

/** The `kindByte` of the design's `(time, kindByte, class, slot, entry)` order:
 * within one instant a token precedes an allocation precedes an append
 * precedes a read precedes a witness, which is the order the protocol's
 * dependencies run in. */
const EVENT_TOKEN = 0;
const EVENT_ALLOCATION = 1;
const EVENT_APPEND = 2;
const EVENT_READ = 4;
const EVENT_WITNESS = 5;

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
   * an append names `window`, and a read and a witness name `window - 1`. */
  readonly window: bigint;
  readonly sizeClassId: number;
  readonly roomSlot: number;
  readonly entryIndex: number;
}

interface HeldLease {
  readonly lease: PublicAllocationLeaseV1;
  readonly secretKey: Uint8Array;
}

/** One window a store still owes a read of, and which attempt is next. */
interface CatchUpRead {
  readonly window: bigint;
  readonly attempt: 1 | 2;
}

/** What one store keeps. Every store runs the same events at the same
 * instants, so the schedule itself is the runtime's, not a store's. */
interface StoreSchedulerState {
  readonly store: PrototypeStoreClient;
  /** Leases by the ingress window they admit, keyed by `String(window)`. */
  readonly leases: Map<string, HeldLease>;
  lastScanStatus: WindowScan["status"] | null;
  /** Reads released more than a delivery window late, newest first; a
   * retry goes to the back. `#catchUp` works through them one at a time. */
  readonly catchUp: CatchUpRead[];
  catchingUp: boolean;
  /** Scheduled handlers in flight for this store. Catch-up waits for zero. */
  busy: number;
  readonly idleWaiters: (() => void)[];
}

/** One window's union across the stores, built by their reads of it. */
interface WindowRead {
  /** Stores whose read of this window has not settled yet. */
  pending: number;
  /** Settled reads that came back `finalized`, and that failed. */
  finalized: number;
  failed: number;
  /** OperationId hex → the stores whose scan carried it. */
  readonly carriedBy: Map<string, Set<string>>;
  /** Operations this window's reads delivered for the first time. */
  readonly fresh: Map<string, OuterValidatedIdentifiedOperationV1>;
}

/** A read made on the schedule, a catch-up read that may still be retried,
 * and a catch-up read that is the window's last chance at this store. */
type ReadAttempt = "scheduled" | "catch-up-first" | "catch-up-last";

/** A scan that came back with something this client can stand on: a
 * finalized window, or one below the chain start that holds nothing — the
 * client decides that one without asking, because the store refuses every
 * write below its chain start. A store's own refusal of a window it no longer
 * retains is `beyond-retention`, which is never a success: the window was not
 * read at that store. */
const readSucceeded = (status: WindowScan["status"]): boolean =>
  status === "finalized" || status === "out-of-range";

/** A scan the catch-up does not retry, and which `#read` has already reported
 * missed at its store: the store's retention has passed, or the read fell
 * outside the validity of the descriptor the client pinned. Retention does
 * not run backwards and neither does a descriptor's end. A refusal stated in
 * the window a descriptor's validity begins in is the one case a later read
 * could change; it is reported like the rest and not asked for again. */
const readIsLost = (status: WindowScan["status"]): boolean =>
  status === "beyond-retention" || status === "descriptor-out-of-validity";

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

const isThenable = (value: unknown): value is PromiseLike<unknown> =>
  typeof (value as { readonly then?: unknown } | null | undefined)?.then ===
  "function";

/** A store's read of one window, as the witness looks it up. */
const readKey = (storeIdHex: string, window: bigint): string =>
  `${storeIdHex}:${String(window)}`;

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
  readonly #hinted = new Set<string>();
  readonly #faults: StoreFaultRecord[] = [];
  readonly #inFlight = new Set<Promise<void>>();

  /** The window the schedule is walking, its events, and the next one due. */
  #window = 0n;
  #queue: readonly ScheduledEvent[] = [];
  #index = 0;
  #handle: CarrierTimerHandle | null = null;

  /** Keyed by `String(window)`. */
  readonly #windowReads = new Map<string, WindowRead>();
  /** Each store's scan status per window (`readKey`): `pending` from the
   * moment the scan is issued until it answers. The witness event reads it
   * at its own instant and waits for nothing. */
  readonly #scanStatuses = new Map<string, WindowScan["status"] | "pending">();

  /** Operations waiting for the application callback to return. */
  readonly #undelivered: OuterValidatedIdentifiedOperationV1[] = [];
  #delivering = false;

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
      leases: new Map<string, HeldLease>(),
      lastScanStatus: null,
      catchUp: [],
      catchingUp: false,
      busy: 0,
      idleWaiters: [],
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

    // What is already past at a cold start was never this run's to send: it
    // is skipped, where a late timer's events are sent late.
    this.#enterWindow(window);
    let queue = this.#queue.filter((event) => event.timeMs >= nowMs);
    if (nowMs >= allocationInstantMs) {
      // The cold-start request *is* this window's allocation. Starting
      // exactly on the offset would otherwise leave the queued event due at
      // this instant as well, and two allocation requests for one target
      // window are one more than the profile's fixed shape.
      queue = queue.filter((event) => event.kindByte !== EVENT_ALLOCATION);
      for (const state of this.#schedulers) {
        this.#emit({
          kind: "missed",
          storeIdHex: state.store.storeIdHex,
          window,
          detail:
            "cold start past the allocation offset: this window's appends are unallocated cover",
        });
        this.#spawn(this.#allocate(state, window + 1n));
      }
    }
    this.#queue = queue;
    this.#index = 0;
    this.#arm();
  }

  /** Disarm the schedule and wipe the allocation secrets still held. */
  stop(): void {
    this.#running = false;
    if (this.#handle !== null) this.#timers.clearTimeout(this.#handle);
    this.#handle = null;
    this.#undelivered.length = 0;
    for (const state of this.#schedulers) {
      for (const held of state.leases.values()) held.secretKey.fill(0);
      state.leases.clear();
      // A catch-up loop waiting for the store to go idle ends here.
      state.catchUp.length = 0;
      for (const wake of state.idleWaiters.splice(0)) wake();
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
   * A call to `onOperations` is not a handler and is not awaited here: the
   * application's callback must not be able to hold the schedule, and that
   * includes the schedule's synchronisation point.
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
   *   less the last append at 2100, less one — that inequality is strict, so
   *   500 itself fails validation), so two stores can be separated by at most
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
      // The witness pair for the window just read leaves at a fixed instant
      // of its own, never as a consequence of what that read found. The
      // instant is the last one this window is still open for writes inside
      // the skew budget: every append is due before it (an append plus the
      // skew precedes finalization), so the pair never interleaves with this
      // client's uploads, and the window it reports is still each store's
      // newest finalized one.
      {
        timeMs:
          startMs +
          this.#profile.chunkFinalizationOffsetMs -
          this.#profile.maxScheduleSkewMs,
        kindByte: EVENT_WITNESS,
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

  /** Make `window` the one the schedule walks, from its first event. */
  #enterWindow(window: bigint): void {
    this.#window = window;
    this.#queue = this.#eventsForWindow(window);
    this.#index = 0;
  }

  /** The next event the schedule has not released. Every window holds a
   * token, an allocation, a read and a witness, so one advance finds one. */
  #peek(): ScheduledEvent {
    if (this.#index >= this.#queue.length) this.#enterWindow(this.#window + 1n);
    return this.#queue[this.#index];
  }

  #arm(): void {
    if (!this.#running) return;
    const delayMs = this.#peek().timeMs - this.#clock.nowMs();
    this.#handle = this.#timers.setTimeout(
      () => {
        this.#fire();
      },
      Number(delayMs < 0n ? 0n : delayMs),
    );
  }

  /**
   * One timer callback: release what is due, arm the next event, start the
   * work.
   *
   * The next event is armed before any work runs, so a slow store shifts
   * nothing: its own next request still leaves on the profile's grid. Every
   * store's events are released together, in schedule order and then store
   * order, so a witness always runs after the reads it reports on.
   */
  #fire(): void {
    this.#handle = null;
    if (!this.#running) return;
    const { due, catchUp } = this.#takeDue(this.#clock.nowMs());
    this.#arm();
    for (const event of due)
      for (const state of this.#schedulers)
        this.#spawnScheduled(state, this.#runEvent(state, event));
    for (const state of this.#schedulers) {
      // Newest first, and ahead of whatever an earlier resume left queued:
      // the windows nearest the present are the ones the room is acting on
      // now, and if the catch-up is cut short it is the oldest that go, the
      // same ones the reach gives up first.
      state.catchUp.unshift(
        ...[...catchUp]
          .reverse()
          .map((window): CatchUpRead => ({ window, attempt: 1 })),
      );
      if (!state.catchingUp && state.catchUp.length > 0) {
        state.catchingUp = true;
        this.#spawn(this.#catchUp(state));
      }
    }
  }

  /** Count a scheduled handler against its store until it settles, so
   * catch-up can wait for the store to have nothing scheduled in flight. */
  #spawnScheduled(state: StoreSchedulerState, work: Promise<void>): void {
    state.busy += 1;
    this.#spawn(
      work.finally(() => {
        state.busy -= 1;
        if (state.busy === 0)
          for (const wake of state.idleWaiters.splice(0)) wake();
      }),
    );
  }

  /**
   * Every event due at `nowMs`, in schedule order, including the ones a late
   * timer held back, and the windows whose reads are to be caught up.
   *
   * An engine delivers a timer late whenever its main thread is busy, and a
   * background tab gets its timers clamped to whole seconds. Dropping what a
   * late timer covered would change how many requests leave in the window —
   * the shape this schedule exists to fix — and would drop reads, which
   * nothing re-makes. So an event at most one delivery window late fires
   * late. The store may refuse a late append; that answer is the store's, and
   * the entry stays queued for its next slot.
   *
   * Further behind than that, the page was suspended or frozen, and firing
   * everything at once would come back as a burst. So:
   *
   * - An upload event (token, allocation, append, witness) more than one
   *   delivery window late is not sent, and is reported `missed`. The window
   *   it was for is over: the store would refuse an allocation for a window
   *   already running and an append to a window already finalized.
   * - A read more than one delivery window late is not dropped and not fired
   *   either: its window goes to each store's catch-up queue (`#catchUp`),
   *   which reads one window at a time.
   * - The schedule never reaches further back than `MAX_READ_WINDOWS`
   *   windows; older windows are given up whole and reported `missed`.
   */
  #takeDue(nowMs: bigint): {
    readonly due: ScheduledEvent[];
    readonly catchUp: bigint[];
  } {
    const deliveryWindowMs = this.#profile.deliveryWindowMs;
    const oldest =
      ingressWindow(deliveryWindowMs, nowMs) - BigInt(MAX_READ_WINDOWS);
    if (this.#window < oldest) {
      const skipped = oldest - this.#window;
      for (const state of this.#schedulers)
        this.#emit({
          kind: "missed",
          storeIdHex: state.store.storeIdHex,
          window: this.#window,
          count: Number(skipped),
          detail: `the schedule fell more than ${String(MAX_READ_WINDOWS)} windows behind the clock; ${String(skipped)} windows of requests and reads were given up`,
        });
      this.#enterWindow(oldest);
    }

    const due: ScheduledEvent[] = [];
    const catchUp: bigint[] = [];
    const tooLate = new Map<bigint, number>();
    for (let released = 0; released < MAX_EVENTS_PER_TIMER; released += 1) {
      const event = this.#peek();
      if (event.timeMs > nowMs) break;
      this.#index += 1;
      if (nowMs - event.timeMs <= deliveryWindowMs) due.push(event);
      else if (event.kindByte === EVENT_READ) {
        // `publicReadLagWindows` is 1, as in `#runEvent`.
        if (event.window > 0n) catchUp.push(event.window - 1n);
      } else tooLate.set(event.window, (tooLate.get(event.window) ?? 0) + 1);
    }
    for (const [window, count] of tooLate)
      for (const state of this.#schedulers)
        this.#emit({
          kind: "missed",
          storeIdHex: state.store.storeIdHex,
          window,
          count,
          detail:
            "scheduled uploads more than one delivery window late were not sent",
        });
    return { due, catchUp };
  }

  /**
   * Read, one window at a time, what this store owes reads of.
   *
   * One catch-up scan is in flight per store at most, and none starts while
   * the store has a scheduled handler in flight: catch-up runs in the gaps of
   * the schedule and never ahead of it, so the current window's requests
   * share the store's connections with at most one catch-up scan. A catch-up
   * read that fails is retried once, after the rest of the queue; if it fails
   * again, or the window has left the catch-up reach by the time its turn
   * comes, the window is reported `missed` for that store.
   */
  async #catchUp(state: StoreSchedulerState): Promise<void> {
    try {
      while (this.#running) {
        while (state.busy > 0 && this.#running)
          await new Promise<void>((resolve) => state.idleWaiters.push(resolve));
        if (!this.#running) return;
        const next = state.catchUp.shift();
        if (next === undefined) return;

        // The same reach as `#takeDue`'s, counted in read windows, which lag
        // the schedule's windows by `publicReadLagWindows`.
        const reach = this.#currentWindow() - BigInt(MAX_READ_WINDOWS) - 1n;
        if (next.window < reach) {
          this.#emit({
            kind: "missed",
            storeIdHex: state.store.storeIdHex,
            window: next.window,
            detail:
              "a caught-up read left the catch-up reach before its turn; this window was not read at this store",
          });
          this.#abandonRead(next.window);
          continue;
        }

        const status = await this.#read(
          state,
          next.window,
          next.attempt === 1 ? "catch-up-first" : "catch-up-last",
        );
        // An expired window stays expired, and so does a descriptor
        // (`readIsLost`): retrying either would only spend six more requests
        // on the same answer, and `#read` already reported it.
        if (readSucceeded(status) || readIsLost(status) || next.attempt === 2) {
          if (!readSucceeded(status) && !readIsLost(status))
            this.#emit({
              kind: "missed",
              storeIdHex: state.store.storeIdHex,
              window: next.window,
              detail: `a catch-up read failed twice (${status}); this window was not read at this store`,
            });
          continue;
        }
        if (state.store.inert) {
          // A store proven dishonest is not asked again.
          this.#emit({
            kind: "missed",
            storeIdHex: state.store.storeIdHex,
            window: next.window,
            detail:
              "a catch-up read failed at an inert store and is not retried; this window was not read at this store",
          });
          this.#abandonRead(next.window);
          continue;
        }
        state.catchUp.push({ window: next.window, attempt: 2 });
      }
    } finally {
      state.catchingUp = false;
    }
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
        await this.#read(state, event.window - 1n, "scheduled");
        return;
      case EVENT_WITNESS:
        if (event.window === 0n) return;
        return this.#witness(state, event.window - 1n);
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
    if (held === null) return;

    if (entry !== null) {
      entry.targets.delete(storeIdHex);
      if (entry.targets.size === 0) this.#dropEntry(entry);
    }
    // The receipt is the whole input to the custody check the next scan runs:
    // the store has now signed that these exact bytes are in this exact slot.
    // A stored cover object carries the same promise as a real operation.
    // Tracking both keeps hashing, receipt occupancy and omission detection
    // independent of whether this scheduled upload contained room work.
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
   * One store's read of one window, folded into that window's union.
   *
   * Each store's read scans that store and no other, so what leaves for a
   * store at its read instant is exactly its own fixed scan, whatever the
   * other store is doing. The stores' reads of one window meet in
   * `#windowReads`: an operation is delivered by whichever read opens it
   * first and never again, and once every store's read has settled the union
   * decides what to backfill and whether the window was read at all.
   *
   * Nothing marks a window read. A scheduled read is made once and not
   * retried: a re-read would be six more requests in a later window. A
   * caught-up read may be retried once by `#catchUp`, so a first catch-up
   * attempt that fails leaves its store's part of the union open.
   */
  async #read(
    state: StoreSchedulerState,
    window: bigint,
    attempt: ReadAttempt,
  ): Promise<WindowScan["status"]> {
    const store = state.store;
    const key = readKey(store.storeIdHex, window);
    const union = this.#windowRead(window);
    let status: WindowScan["status"] = "unreachable";
    this.#rememberScanStatus(key, "pending");
    try {
      let scan: WindowScan;
      try {
        scan = await store.scanWindow(window);
      } catch {
        return status;
      }
      status = scan.status;
      this.#rememberScanStatus(key, status);
      this.#count({ scans: 1 });
      state.lastScanStatus = scan.status;
      this.#emit({
        kind: "scan",
        storeIdHex: store.storeIdHex,
        window,
        detail: scan.status,
        count: scan.objects.length,
      });
      if (scan.status === "beyond-retention")
        this.#emit({
          kind: "missed",
          storeIdHex: store.storeIdHex,
          window,
          detail:
            "the store no longer retains this window (it is past the retention its descriptor states); it was not read at this store",
        });
      // Neither expiry nor blame can be told apart from a store whose clock
      // disagrees with this one, so the window is missed at this store now;
      // a caught-up read is retried, and the store is read again next time.
      if (scan.status === "clock-disagreement")
        this.#emit({
          kind: "missed",
          storeIdHex: store.storeIdHex,
          window,
          detail:
            "the store's signed clock disagrees with this client's beyond the profile's skew; this window was not read at this store this time",
        });
      // The descriptor the client pinned is the store's lease to be read.
      // Outside it nothing the store says is believed or served, short of a
      // refusal that proves a fault, which the client blames first.
      if (scan.status === "descriptor-out-of-validity")
        this.#emit({
          kind: "missed",
          storeIdHex: store.storeIdHex,
          window,
          detail:
            "the read fell outside the validity of the store descriptor this client pinned; this window was not read at this store",
        });
      if (!this.#running) return status;

      const observed = await this.#openObjects(store, window, scan.objects);
      if (!this.#running) return status;
      const fresh: OuterValidatedIdentifiedOperationV1[] = [];
      for (const candidate of observed) {
        const idHex = hexOf(candidate.operationId);
        const holders = union.carriedBy.get(idHex) ?? new Set<string>();
        holders.add(store.storeIdHex);
        union.carriedBy.set(idHex, holders);
        if (this.#seen.has(idHex)) continue;
        this.#seen.add(idHex);
        union.fresh.set(idHex, candidate);
        fresh.push(candidate);
      }
      boundSet(this.#seen, MAX_SEEN_OPERATION_IDS);
      if (fresh.length > 0) {
        this.#count({ operationsSeen: fresh.length });
        this.#emit({
          kind: "operations",
          storeIdHex: store.storeIdHex,
          window,
          count: fresh.length,
        });
        this.#deliver(fresh);
      }
      return status;
    } finally {
      if (this.#scanStatuses.get(key) === "pending")
        this.#rememberScanStatus(key, status);
      if (
        readSucceeded(status) ||
        readIsLost(status) ||
        attempt !== "catch-up-first"
      )
        this.#settleRead(window, union, status);
    }
  }

  /** A store's read of `window` that will not be made after all. */
  #abandonRead(window: bigint): void {
    this.#settleRead(window, this.#windowRead(window), "unreachable");
  }

  /**
   * One store's last word on `window`. When it is the last store's, the
   * union is complete: backfill what only some stores carried, and report a
   * window no store served — its operations were not seen by this client.
   *
   * Replication is this runtime's business and delivery the caller's, so the
   * backfill depends on the scans alone and never waits for a caller.
   */
  #settleRead(
    window: bigint,
    union: WindowRead,
    status: WindowScan["status"],
  ): void {
    if (status === "finalized") union.finalized += 1;
    else if (status !== "out-of-range") union.failed += 1;
    union.pending -= 1;
    if (union.pending > 0) return;
    const key = String(window);
    if (this.#windowReads.get(key) === union) this.#windowReads.delete(key);
    if (!this.#running) return;
    if (union.finalized === 0 && union.failed > 0)
      this.#emit({
        kind: "missed",
        window,
        detail:
          "no store served a finalized read of this window; its operations were not seen",
      });
    this.#queueBackfills([...union.fresh.values()], union.carriedBy, window);
  }

  /** The union of `window` across the stores, opened by its first read. */
  #windowRead(window: bigint): WindowRead {
    const key = String(window);
    const existing = this.#windowReads.get(key);
    if (existing !== undefined) return existing;
    const created: WindowRead = {
      pending: this.#schedulers.length,
      finalized: 0,
      failed: 0,
      carriedBy: new Map<string, Set<string>>(),
      fresh: new Map<string, OuterValidatedIdentifiedOperationV1>(),
    };
    this.#windowReads.set(key, created);
    // Every store settles every window it reads, so an entry only lingers
    // when the runtime stopped mid-read; a catch-up can hold one open per
    // window of the reach, hence the room. The oldest goes first.
    while (this.#windowReads.size > 2 * MAX_READ_WINDOWS) {
      const oldest = this.#windowReads.keys().next();
      if (oldest.done) break;
      this.#windowReads.delete(oldest.value);
    }
    return created;
  }

  #rememberScanStatus(
    key: string,
    status: WindowScan["status"] | "pending",
  ): void {
    this.#scanStatuses.delete(key);
    this.#scanStatuses.set(key, status);
    while (
      this.#scanStatuses.size >
      MAX_READ_WINDOWS * this.#schedulers.length
    ) {
      const oldest = this.#scanStatuses.keys().next();
      if (oldest.done) break;
      this.#scanStatuses.delete(oldest.value);
    }
  }

  /**
   * Hand fresh operations to the application: one call at a time, in the
   * order they were read, and never awaited by a scheduled event. (The call
   * itself can start inside the read that found the operations; what that
   * read does not do is wait for it.)
   *
   * In the composition the callback is `PairDriver.ingest`, which is not
   * reentrant and can wait for ICE gathering longer than a delivery window.
   * So no call starts while a returned promise is pending, and what arrives
   * meanwhile is merged into the next call. No scheduled event waits for it
   * either: a callback that throws costs a `missed` event, and one that never
   * returns stops deliveries and nothing else — the requests, the backfill
   * and the witness all go on.
   */
  #deliver(fresh: readonly OuterValidatedIdentifiedOperationV1[]): void {
    this.#undelivered.push(...fresh);
    // Fresh operations are distinct, so this only binds a callback that has
    // stopped returning; the oldest are the ones given up.
    const excess = this.#undelivered.length - MAX_SEEN_OPERATION_IDS;
    if (excess > 0) {
      this.#undelivered.splice(0, excess);
      this.#emit({
        kind: "missed",
        window: this.#currentWindow(),
        count: excess,
        detail:
          "the operations handler has not returned; the oldest undelivered operations were dropped",
      });
    }
    this.#pumpDeliveries();
  }

  #pumpDeliveries(): void {
    while (!this.#delivering && this.#running && this.#undelivered.length > 0) {
      const batch = this.#undelivered.splice(0);
      // Set before the call, so a delivery reached from inside the callback
      // queues behind it instead of re-entering it.
      this.#delivering = true;
      let returned: unknown;
      try {
        returned = this.#onOperations(batch);
      } catch (error) {
        this.#handlerFailed(error);
      }
      if (!isThenable(returned)) {
        this.#delivering = false;
        continue;
      }
      void Promise.resolve(returned)
        .then(
          () => undefined,
          (error: unknown) => {
            this.#handlerFailed(error);
          },
        )
        .then(() => {
          this.#delivering = false;
          this.#pumpDeliveries();
        });
    }
  }

  #handlerFailed(error: unknown): void {
    this.#emit({
      kind: "missed",
      window: this.#currentWindow(),
      detail: `the operations handler threw: ${detailOf(error)}`,
    });
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
   * Gossip the other stores' verified checkpoints of `window` to `carrier`
   * and read its records back (design doc §8), at the witness event's fixed
   * instant. This is the route design doc §3a item 14 names as the
   * cross-store status oracle: the pair about a store is sent only when this
   * client's scan of that store came back `finalized` and neither store is
   * inert. When it is sent, it is sent at the schedule's instant, whatever the
   * read found and however long the application took with it.
   *
   * Nothing is waited for. What decides is each witnessed store's scan status
   * as it stands at this instant: a scan that has not answered yet means the
   * pair about that store is skipped for this window and reported `missed`.
   * Waiting would let the witnessed store choose when this client's requests
   * reach the other store, by answering late: a cross-store timing channel.
   * Skipping leaves an absence the other store can see, which is the same
   * conditional-presence bit design doc §3a item 14 already discloses.
   *
   * A record that names a store this client verified, carrying a different
   * checkpoint hash than that store showed this client, is a
   * `checkpoint-split-view-hint` and nothing more. It is NOT a proof and it
   * does NOT make the store inert: the specification's conflict proof needs
   * two checkpoints the store itself signed, and a witness record is
   * unauthenticated peer input that any store could have written. Only a
   * re-fetch, or a second observer, can turn a hint into evidence.
   */
  async #witness(carrier: StoreSchedulerState, window: bigint): Promise<void> {
    // Every status is taken now, before the first request goes out, so a
    // scan that answers while this pair is in flight changes nothing.
    const settled = this.#schedulers
      .filter((witnessed) => witnessed !== carrier)
      .map((witnessed) => ({
        witnessed,
        status: this.#scanStatuses.get(
          readKey(witnessed.store.storeIdHex, window),
        ),
      }));
    for (const { witnessed, status } of settled) {
      // A runtime that started after this window's read has nothing to say.
      if (status === undefined) continue;
      if (status === "pending") {
        this.#emit({
          kind: "missed",
          storeIdHex: carrier.store.storeIdHex,
          window,
          detail: `the witness pair about store ${witnessed.store.storeIdHex} was not sent: its scan of this window had not answered by the witness instant`,
        });
        continue;
      }
      if (!this.#running) return;
      if (
        status !== "finalized" ||
        witnessed.store.inert ||
        carrier.store.inert
      )
        continue;
      const checkpointHash = witnessed.store.checkpointHashFor(window);
      if (checkpointHash === null) continue;

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
