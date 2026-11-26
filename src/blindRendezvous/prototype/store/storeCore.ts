/**
 * The prototype store's window machine: allocation, append, finalization, and
 * the checkpoint chain (design doc §4.3, specification §4.3).
 *
 * Routing uses public geometry — a delivery-profile hash, an ingress window,
 * a size class, an ordinal, and opaque fixed-length bytes. No room identifier
 * is required. Optional experimental admission additionally associates leases
 * with opaque grant quota keys; these can link a grant's uses across windows.
 * Shared buckets alone do not establish relationship or participant anonymity.
 *
 * Two properties this file is responsible for and that nothing downstream can
 * repair:
 *
 * - A window closes on the clock, not on when `finalizeDue` happened to run.
 *   An append is refused once `IngressWindowStart(w) + chunkFinalizationOffsetMs`
 *   has passed even if the chunks are not signed yet, so a slow finalizer can
 *   never let one client's object into a chunk another client already read a
 *   checkpoint for.
 * - A read is answered from one reading of the clock, and that reading is
 *   the window a signed status states. `out-of-range` means only that the
 *   window is outside what the store keeps, and `not-final` is signed only
 *   before the window's finalization instant: a window that has closed on
 *   the clock but is not signed yet is answered with
 *   `StoreFinalizationPendingError` (a 503), never a signed `not-final`.
 *   `chain-unavailable` is signed only for a profile other than the one the
 *   descriptor declares, and `no-such-chunk` only for coordinates that
 *   profile does not define. So none of this store's signed statuses can be
 *   shown, from its own words, to contradict its descriptor
 *   (`signedStatusProvesFault` in the client), and a client that blames each
 *   of the four when it does contradict the descriptor never blames this
 *   store, whatever its clock reads. A finalized answer may come from a
 *   precomputed row, but only once that reading has let the read through,
 *   so a row never answers for a window the clock refuses.
 * - A finalized window is never re-signed. Signing two different chunk bodies
 *   for one index, or two checkpoints for one window, is a permanent fault
 *   proof against the store — so `#finalizeWindow` returns early rather than
 *   recompute, and every mutating entry point is serialized.
 * - A refusal costs what the clock costs. An append or allocation the clock
 *   already refuses — a closed window, one past the allocation horizon, one
 *   below the chain start or swept by retention — is answered from the
 *   request and the clock alone: it loads no window and never waits on the
 *   mutation queue, so it cannot stall the store and its cost does not say
 *   which of those it was. The admission hook is asked before the queue too,
 *   and a refusal, a full cohort, a spent grant and an exact replay are
 *   answered from this process's record of the open window when it holds one.
 *   Only work that may change a window waits on the queue, and the queue is
 *   bounded: past `PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH` a request is
 *   refused with `StoreBusyError` before anything of it is queued. Every write
 *   copies the window it loaded, saves the copy, and only then answers, so a
 *   failed write leaves the loaded window exactly as it was.
 *
 * Transport lives in `storeHttp.ts`; durable rows live behind
 * `StorePersistencePort`. This file knows about neither.
 *
 * Status: PROTOTYPE. This is the `prototype-v1` route family, not a frozen
 * registry, and nothing here is a v0.4 release artifact.
 */

import { keyPairFromSeed, sign, verify } from "../../../cryptography/ed25519";
import {
  PROTOTYPE_STORE_ADMISSION_TOKEN_BYTES,
  PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS,
  PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH,
  PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY,
  PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW,
  PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
  PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS,
} from "../../../utils/constants";
import {
  allocationAppendSignedMessage,
  allocationTokenIssueRequestHash,
  allocationTokenIssueResultSignedMessage,
  deliveryProfileHash,
  prototypeStoreCompatibilityHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationRequestHash,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
  sha256,
} from "../../derivations";
import {
  ZERO32,
  appendSlotCoordinates,
  bucketIsReadable,
  checkpointLeafEntries,
  ingressWindow,
  ingressWindowStartMs,
  profileFinalizedChunkCount,
  publicChunkHash,
  publicChunkSigningHash,
  publicStoreCheckpointHash,
  publicStoreCheckpointSigningHash,
  rfc9162MerkleTreeHash,
} from "../../publicWindow";
import {
  descriptorHash as computeDescriptorHash,
  storeDescriptorSignedMessage,
  storeId as computeStoreId,
  storeRouteSignedMessage,
  validateStoreDescriptor,
  validateStoreRoute,
} from "../../storeDescriptor";
import {
  carrierObjectWireBytes,
  profileGeometry,
  validateDeliveryProfileGeometry,
} from "../profile";
import {
  encodePublicChunkReadV1,
  encodePublicStoreCheckpointReadV1,
} from "../storeWire";
import {
  copyBucket,
  copyBytes,
  copyChunk,
  copyCheckpoint,
  copyLease,
  copyWitnessRecord,
  emptyStoreWindowState,
} from "./storePersistence";

import type { LibCrypto } from "../../../cryptography/libcrypto";
import type {
  PublicBucketV1,
  PublicChunkBodyV1,
  PublicChunkV1,
  PublicProfileGeometry,
  PublicStoreCheckpointBodyV1,
  PublicStoreCheckpointV1,
} from "../../publicWindow";
import type { StoreDescriptorV1, StoreRouteV1 } from "../../storeDescriptor";
import type { DeliveryProfileV1, DeliverySizeClassV1 } from "../profile";
import type {
  AllocationTokenIssueRequestV1,
  AllocationTokenIssueResultV1,
  PublicAllocationLeaseBodyV1,
  PublicAllocationLeaseV1,
  PublicAllocationRequestV1,
  PublicAllocationResultV1,
  PublicAllocationStatusBodyV1,
  PublicAllocationStatusKindV1,
  PublicAppendRequestV1,
  PublicAppendResultBodyV1,
  PublicAppendResultV1,
  PublicAppendStatusV1,
  PublicChunkReadV1,
  PublicChunkStatusKindV1,
  PublicStoreCheckpointReadV1,
  PublicStoreCheckpointStatusKindV1,
  PrototypeStoreDescriptorDocumentV1,
  StoreWitnessRecordV1,
} from "../storeWire";
import type {
  StorePersistencePort,
  StoreWindowState,
} from "./storePersistence";

export class StoreRequestError extends Error {
  // Widened to `string` (unlike the other error classes here) so
  // `StoreConfigurationError` can narrow it to its own name.
  override readonly name: string = "StoreRequestError";

  constructor(message: string) {
    super(`storeCore: ${message}`);
  }
}

/**
 * A start-up refusal: the options this process was given contradict what it
 * already signed, or could not produce a servable identity.
 *
 * It extends `StoreRequestError` so a caller that catches the family still
 * catches it, but it is a separate name because the two are acted on
 * differently — a request error is one client's 400, and this one means the
 * process must not run at all.
 */
export class StoreConfigurationError extends StoreRequestError {
  // Widened to `string` so `StoreDescriptorChangedError` can narrow it.
  override readonly name: string = "StoreConfigurationError";
}

/**
 * The persisted chain was signed under another descriptor than this
 * configuration produces, so this process must not extend it: every later
 * checkpoint would name a descriptor the earlier ones do not.
 *
 * A setting the descriptor states changed — the retention, or the identity
 * key — or the chain was written before the descriptor stated its retention.
 * There are two ways out: restore the setting, or start a new chain with a
 * new database and a new identity key (a new chain under the same key would
 * be a second chain start for one store, which clients treat as permanent
 * equivocation).
 */
export class StoreDescriptorChangedError extends StoreConfigurationError {
  override readonly name = "StoreDescriptorChangedError";
}

/**
 * The admission hook refused an append or a witness offer.
 *
 * Not a `StoreRequestError`: the request was well formed, and the transport
 * answers it with its own constant `403 refused` rather than the `400` that
 * family maps to. Allocation has a signed refusal in its status set
 * (`invalid-token`) and never throws this.
 */
export class StoreAdmissionRefusedError extends Error {
  override readonly name = "StoreAdmissionRefusedError";

  constructor(route: StoreAdmissionRouteV1) {
    super(`storeCore: the admission hook refused this ${route} request`);
  }
}

/**
 * The mutation queue is full (`PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH`), so
 * this request was refused before it was queued. The transport answers a
 * constant `503 busy`; a client treats it as it treats any non-200 answer, as
 * one failed request, and never as evidence against the store.
 */
export class StoreBusyError extends Error {
  // Widened to `string` so `StoreFinalizationPendingError` can name itself.
  override readonly name: string = "StoreBusyError";

  constructor(message = "the mutation queue is full") {
    super(`storeCore: ${message}`);
  }
}

/**
 * A read of a window that has closed on this store's clock before the
 * finalizer has signed it: after a restart, while the finalizer catches up,
 * or in the moment between the close and the next finalizer tick. A signed
 * `not-final` would then contradict the store's own clock, so the answer is
 * the transport's unsigned `503 busy`, which a client treats as one failed
 * request. The next read finds the window signed.
 */
export class StoreFinalizationPendingError extends StoreBusyError {
  override readonly name = "StoreFinalizationPendingError";

  constructor(window: bigint) {
    super(`window ${String(window)} has closed but is not signed yet`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new StoreRequestError(message);
};

const failConfiguration: (message: string) => never = (message) => {
  throw new StoreConfigurationError(message);
};

export interface StoreClock {
  nowMs(): bigint;
}

/** The route an admission hook is asked about. */
export type StoreAdmissionRouteV1 = "allocation" | "append" | "witness";

/**
 * What an admission hook is asked: an allocation request's fields, plus the
 * route. See `PrototypeStoreCoreOptions.allocationAdmission` for what each
 * field holds on the append and witness routes.
 */
export interface StoreAdmissionRequestV1 extends PublicAllocationRequestV1 {
  readonly route: StoreAdmissionRouteV1;
}

/**
 * `recorded`: this offer added the record. `already-held`: those exact bytes
 * were already held and nothing was charged. `not-recorded`: the window is
 * not one this store retains, the record names another profile, or the
 * window or the offering quota key has no room left.
 */
export type StoreWitnessOutcomeV1 =
  "recorded" | "already-held" | "not-recorded";

/** What one `sweepRetention` call deleted. */
export interface StoreRetentionSweep {
  /** Window rows, each with its allocation records and their quota keys. */
  readonly windows: number;
  /** Windows whose witness records and per-key counts were deleted. */
  readonly witnessWindows: number;
}

/** The one secret a store process holds; the server writes it to a key file. */
/**
 * A read as the bytes the route answers with, and whether they are a
 * finalized window (which never changes) rather than a signed status (which
 * names the store's window at the time of the request).
 */
export interface StoreEncodedRead {
  readonly bytes: Uint8Array;
  readonly finalized: boolean;
}

export interface StoreIdentityFiles {
  seed: Uint8Array;
}

export interface PrototypeStoreCoreOptions {
  readonly module: LibCrypto;
  readonly seed: Uint8Array;
  readonly profile: DeliveryProfileV1;
  readonly clock: StoreClock;
  readonly persistence: StorePersistencePort;
  readonly chainStartIngressWindow: bigint;
  /** The origin a route advertises, e.g. `"http://127.0.0.1:5910"`. */
  readonly origin: string;
  readonly descriptorValidityMs: bigint;
  /** Test-only: `"withhold"` accepts appends and finalizes them all-dummy. */
  readonly fault?: "withhold" | null;
  /**
   * Experimental server-local admission for the allocation, append and
   * witness routes; absent, the store runs open admission. The name predates
   * the second and third routes and is kept so existing hooks plug in as-is.
   *
   * `authorize` is given the request's public geometry, the route asking
   * (`route`), and the token the caller presented (`privacyPassToken`: the
   * allocation body's own field, or the bearer header on append and witness;
   * 32 zero bytes when the caller presented none). On append,
   * `allocationEd25519PublicKey` is the admitted lease's key, or 32 zero bytes
   * for unallocated cover; on witness it is always 32 zero bytes. A 32-byte
   * return admits the request under that quota key; `null`, any other value,
   * or a throw refuses it.
   *
   * When it is called: only after the core's own checks that need no hook —
   * the profile, the request's shape, and the window being one this store
   * serves on its clock. Allocation: at or after the chain start, inside
   * `[current, current + maxFutureIngressWindows]` and before its
   * finalization instant; the hook runs before the request is queued and
   * before the exact-retry replay, so a revoked grant cannot replay its lease,
   * and the window is checked again inside the queue (a finalized window is
   * always closed on the clock, so that check also covers the race). Append:
   * at or after the chain start, before its window's finalization instant and
   * not past the allocation horizon; the hook runs before the lease is
   * verified. Witness: a window closed on the clock and still retained, under
   * this store's profile. So a request the store would refuse anyway never
   * reaches the hook, and the hook is never asked about a window the store
   * would not serve.
   *
   * What it is given on the append route, pinned by a test: an unallocated
   * cover append presents 32 zero bytes as `allocationEd25519PublicKey`, and
   * an append under a lease presents that lease's key, so a hook can tell
   * them apart by that field alone.
   *
   * What it should do with the token: compare it in constant time (a token
   * that is a bearer secret must not be found byte by byte from response
   * timing), and expect tokens that are unlinkable per request. A bearer token
   * presented unchanged on every route links one client's allocation, appends
   * and witness offers across windows and network addresses; only a token
   * scheme that hands out a fresh unlinkable token per request avoids that.
   *
   * What it may do: it may have side effects, provided they are idempotent.
   * An exact retry of an admitted request calls it again (and replays its
   * lease only if it admits again), and a side effect can outlive a request
   * the store then refuses or fails to persist — capacity exhausted, a lease
   * that does not verify, a window that closed while the request waited, a
   * failed write. The core commits at most one lease per quota key per
   * ingress window and at most
   * `PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY` new witness records
   * per quota key per window; on append the key only
   * admits. The hook supplies no descriptor-level privacy or unique-person
   * claim.
   */
  readonly allocationAdmission?: {
    authorize(
      request: StoreAdmissionRequestV1,
    ): Uint8Array | null | Promise<Uint8Array | null>;
  };
  /**
   * How many windows back reads, witness offers and stored rows reach, and
   * what the signed descriptor states; see `sweepRetention`. An integer from
   * `PROTOTYPE_STORE_MIN_RETENTION_WINDOWS` (what an honest client reads back)
   * to the profile's `carrierRetentionWindows`; the default is
   * `PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS`, or the profile's value if
   * that is smaller.
   */
  readonly retentionWindows?: number;
}

/** `crypto.getRandomValues` refuses more than this many bytes per call. */
const RANDOM_SLICE_BYTES = 65_536;

/**
 * How far one `finalizeDue` will catch up.
 *
 * Every window costs a full profile's worth of CSPRNG bodies and one signature
 * per chunk, and none of it yields to the event loop — at the pinned profile a
 * window is roughly 1.4 MB and five signatures. A cap of 32 keeps the worst
 * call to tens of megabytes rather than gigabytes, and the server's 250 ms tick
 * means a catch-up of thousands of windows still completes in seconds. Nothing
 * is skipped: the next call resumes at the same window.
 */
const MAX_WINDOWS_FINALIZED_PER_CALL = 32;

/** A route lease is the descriptor's; a route outliving it proves nothing. */
const PROTOTYPE_ROUTE_FAMILY = 1;

/** `storeRouteV1Schema`'s `opaqueLocator` bound. */
const MAX_ROUTE_LOCATOR_BYTES = 2_048;

/** Tolerance for a descriptor signed a moment after the clock was read. */
const DESCRIPTOR_BACKDATE_MS = 60_000n;

const U64_MAX = 0xffffffffffffffffn;

const textEncoder = new TextEncoder();

/** What a caller that presented no admission token is taken to have sent. */
const NO_ADMISSION_TOKEN_BYTES = PROTOTYPE_STORE_ADMISSION_TOKEN_BYTES;

type Admission =
  | { readonly kind: "open" }
  | { readonly kind: "admitted"; readonly quotaKey32: Uint8Array }
  | { readonly kind: "refused" };

/** What the allocation path settled on: a lease, or a status to sign. */
type AllocationDecision =
  | { readonly kind: "lease"; readonly lease: PublicAllocationLeaseV1 }
  | { readonly kind: "status"; readonly status: PublicAllocationStatusKindV1 };

const OPEN_ADMISSION: Admission = { kind: "open" };
const REFUSED_ADMISSION: Admission = { kind: "refused" };

/** The caller's token, copied, or the zero token when none was presented. */
const presentedToken = (token: Uint8Array | undefined): Uint8Array => {
  if (token === undefined) return new Uint8Array(NO_ADMISSION_TOKEN_BYTES);
  if (
    !(token instanceof Uint8Array) ||
    token.length !== NO_ADMISSION_TOKEN_BYTES
  )
    fail("an admission token must be exactly 32 bytes");
  return copyBytes(token);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return false;
  return true;
};

/**
 * Reject coordinates that no signed answer could carry.
 *
 * Every status this store returns names the coordinates it was asked about, so
 * a request the status body cannot encode has no signable refusal — the
 * transport's one constant 400 is the only correct answer. These bounds are
 * the wire widths of the coordinate fields (`bytes32`, `u64`, `u8`); the
 * canonical decoders already enforce them on requests that arrive over HTTP,
 * and these guards are what stop an in-process caller from reaching the
 * encoder and getting a `CanonicalSchemaError` instead.
 */
const requireProfileHash = (value: Uint8Array): void => {
  if (value.length !== 32) fail("a delivery profile hash must be 32 bytes");
};

const requireWindow = (window: bigint): void => {
  if (window < 0n || window > U64_MAX)
    fail("an ingress window must be an unsigned 64-bit integer");
};

const requireChunkIndex = (chunkIndex: bigint): void => {
  if (chunkIndex < 0n || chunkIndex > U64_MAX)
    fail("a chunk index must be an unsigned 64-bit integer");
};

const requireSizeClassId = (sizeClass: number): void => {
  if (!Number.isSafeInteger(sizeClass) || sizeClass < 0 || sizeClass > 0xff)
    fail("a size class id must be an unsigned byte");
};

/**
 * Fill with CSPRNG bytes in slices the WebCrypto cap accepts. Dummy bodies are
 * indistinguishable from real carrier objects by construction — a store that
 * padded with zeros would publish which positions nobody used.
 */
const randomBytes = (length: number): Uint8Array => {
  const output = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += RANDOM_SLICE_BYTES)
    crypto.getRandomValues(
      output.subarray(offset, Math.min(offset + RANDOM_SLICE_BYTES, length)),
    );
  return output;
};

/**
 * The store's own descriptor leaves this process on every checkpoint read, so
 * it leaves as a copy: a reader that mutated what it was handed would rewrite
 * the identity every later answer is signed against.
 */
const copyDescriptor = (descriptor: StoreDescriptorV1): StoreDescriptorV1 => ({
  version: descriptor.version,
  storeIdentityEd25519Key: copyBytes(descriptor.storeIdentityEd25519Key),
  allocationIssuerPublicKeyDer: copyBytes(
    descriptor.allocationIssuerPublicKeyDer,
  ),
  descriptorGeneration: descriptor.descriptorGeneration,
  compatibilityHash: copyBytes(descriptor.compatibilityHash),
  supportedDeliveryProfileHashes:
    descriptor.supportedDeliveryProfileHashes.map(copyBytes),
  checkpointChainStarts: descriptor.checkpointChainStarts.map((start) => ({
    deliveryProfileHash: copyBytes(start.deliveryProfileHash),
    chainStartIngressWindow: start.chainStartIngressWindow,
  })),
  retentionWindows: descriptor.retentionWindows,
  notBeforeUnixMs: descriptor.notBeforeUnixMs,
  notAfterUnixMs: descriptor.notAfterUnixMs,
  descriptorSignature: copyBytes(descriptor.descriptorSignature),
});

const copyRoute = (route: StoreRouteV1): StoreRouteV1 => ({
  version: route.version,
  storeId: copyBytes(route.storeId),
  descriptorHash: copyBytes(route.descriptorHash),
  routeFamily: route.routeFamily,
  opaqueLocator: copyBytes(route.opaqueLocator),
  routePublicParameters: copyBytes(route.routePublicParameters),
  notBeforeUnixMs: route.notBeforeUnixMs,
  notAfterUnixMs: route.notAfterUnixMs,
  routeSignature: copyBytes(route.routeSignature),
});

/** `${sizeClass}:${chunkIndex}:${objectIndexWithinChunk}` */
const slotKey = (
  sizeClass: number,
  chunkIndex: bigint,
  objectIndexWithinChunk: number,
): string =>
  `${String(sizeClass)}:${String(chunkIndex)}:${String(objectIndexWithinChunk)}`;

interface PreparedIdentity {
  readonly secretKey: Uint8Array;
  readonly storeId: Uint8Array;
  readonly profileHash: Uint8Array;
  readonly descriptor: StoreDescriptorV1;
  readonly descriptorHash: Uint8Array;
  readonly routes: readonly StoreRouteV1[];
}

export class PrototypeStoreCore {
  readonly #storeId: Uint8Array;
  readonly #descriptor: StoreDescriptorV1;
  readonly #descriptorHash: Uint8Array;
  readonly #routes: readonly StoreRouteV1[];
  readonly #profileHash: Uint8Array;
  readonly #storePublicKey: Uint8Array;

  readonly #module: LibCrypto;
  readonly #secretKey: Uint8Array;
  readonly #profile: DeliveryProfileV1;
  readonly #geometry: PublicProfileGeometry;
  readonly #clock: StoreClock;
  readonly #persistence: StorePersistencePort;
  readonly #chainStart: bigint;
  readonly #fault: "withhold" | null;
  readonly #allocationAdmission: PrototypeStoreCoreOptions["allocationAdmission"];
  readonly #retentionWindows: number;
  readonly #sizeClasses: readonly DeliverySizeClassV1[];
  readonly #objectBytesByClass: ReadonlyMap<number, number>;

  /** Serializes every mutating entry point; see the file header. */
  #tail: Promise<unknown> = Promise.resolve();

  /** One retention sweep at a time; see `sweepRetention`. */
  #sweeping = false;

  /** Units of work queued or running on `#serialize`. */
  #queueDepth = 0;

  /** The finalization queued or running, which a second caller joins. */
  #finalizing: Promise<readonly bigint[]> | null = null;

  /**
   * This process's record of each window still open for writes: the window's
   * state as last loaded or saved, so refusals, a full cohort, a spent grant
   * and exact replays are answered without loading it, and the queue loads a
   * window once rather than once per request. It only ever holds what
   * persistence holds (filled from a load, replaced after a successful save),
   * and it holds only windows not closed on the clock, so at most
   * `maxFutureIngressWindows + 2` entries; at the pinned profile each is at
   * most 8 allocation records and 40 bound objects, about 1.4 MB.
   */
  readonly #openWindows = new Map<string, StoreWindowState>();

  private constructor(
    options: PrototypeStoreCoreOptions,
    identity: PreparedIdentity,
    objectBytesByClass: ReadonlyMap<number, number>,
    retentionWindows: number,
  ) {
    this.#storeId = identity.storeId;
    this.#descriptor = identity.descriptor;
    this.#descriptorHash = identity.descriptorHash;
    this.#routes = identity.routes;
    this.#profileHash = identity.profileHash;
    this.#storePublicKey = identity.descriptor.storeIdentityEd25519Key;

    this.#module = options.module;
    this.#secretKey = identity.secretKey;
    this.#profile = options.profile;
    this.#geometry = profileGeometry(options.profile);
    this.#clock = options.clock;
    this.#persistence = options.persistence;
    this.#chainStart = options.chainStartIngressWindow;
    this.#fault = options.fault ?? null;
    this.#allocationAdmission = options.allocationAdmission;
    this.#retentionWindows = retentionWindows;
    // Sorted by id once: leaf order and chunk order are both profile order,
    // and rebuilding that order per finalization invites one of them to drift.
    this.#sizeClasses = [...options.profile.sizeClasses].sort(
      (left, right) => left.id - right.id,
    );
    this.#objectBytesByClass = objectBytesByClass;
  }

  /* ---------------------------------------------------------------- *
   * Public identity
   *
   * Getters rather than fields: these are the values every signature this
   * store makes is checked against, and `#append` verifies leases under the
   * descriptor's key. An in-process caller that mutated a handed-out
   * `Uint8Array` would silently repoint that check, so each read is a copy and
   * the originals never leave.
   * ---------------------------------------------------------------- */

  get storeId(): Uint8Array {
    return copyBytes(this.#storeId);
  }

  get descriptor(): StoreDescriptorV1 {
    return copyDescriptor(this.#descriptor);
  }

  get descriptorHash(): Uint8Array {
    return copyBytes(this.#descriptorHash);
  }

  get routes(): readonly StoreRouteV1[] {
    return this.#routes.map(copyRoute);
  }

  get profileHash(): Uint8Array {
    return copyBytes(this.#profileHash);
  }

  /** How many windows back this store serves; see `retentionWindows`. */
  get retentionWindows(): number {
    return this.#retentionWindows;
  }

  /** Units of work queued or running on the mutation queue. */
  get mutationQueueDepth(): number {
    return this.#queueDepth;
  }

  /** True while a request that needs the queue would be refused busy. */
  get mutationQueueSaturated(): boolean {
    return this.#queueDepth >= PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH;
  }

  static async create(
    options: PrototypeStoreCoreOptions,
  ): Promise<PrototypeStoreCore> {
    if (options.seed.length !== 32)
      failConfiguration("the store identity seed must be exactly 32 bytes");
    if (
      options.chainStartIngressWindow < 0n ||
      options.chainStartIngressWindow > U64_MAX
    )
      failConfiguration(
        "chainStartIngressWindow must be an unsigned 64-bit integer",
      );
    if (options.descriptorValidityMs <= 0n)
      failConfiguration("descriptorValidityMs must be positive");
    const opaqueLocator = textEncoder.encode(options.origin);
    if (opaqueLocator.length === 0)
      failConfiguration("origin must not be empty: it is the route's locator");
    if (opaqueLocator.length > MAX_ROUTE_LOCATOR_BYTES)
      failConfiguration(
        `origin must encode to at most ${String(MAX_ROUTE_LOCATOR_BYTES)} UTF-8 bytes`,
      );
    // A profile that has not passed §4.3's inequalities cannot be served:
    // every later offset comparison in this file assumes them.
    validateDeliveryProfileGeometry(options.profile);
    const retentionWindows =
      options.retentionWindows ??
      Math.min(
        PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS,
        options.profile.carrierRetentionWindows,
      );
    // Below the minimum an honest client's catch-up read would meet an
    // expired window; clients refuse such a store at connect anyway.
    if (
      !Number.isSafeInteger(retentionWindows) ||
      retentionWindows < PROTOTYPE_STORE_MIN_RETENTION_WINDOWS ||
      retentionWindows > options.profile.carrierRetentionWindows
    )
      failConfiguration(
        `retentionWindows must be an integer from ${String(PROTOTYPE_STORE_MIN_RETENTION_WINDOWS)}, the furthest an honest client reads back, to the profile's carrierRetentionWindows (${String(options.profile.carrierRetentionWindows)})`,
      );

    const seed = copyBytes(options.seed);
    const keyPair = await keyPairFromSeed(seed, options.module);
    seed.fill(0);

    const profileHash = await deliveryProfileHash(options.profile);
    const storeIdBytes = await computeStoreId(keyPair.publicKey);
    const compatibilityHash =
      await prototypeStoreCompatibilityHash(profileHash);

    const nowMs = options.clock.nowMs();
    // The descriptor must be byte-identical across restarts. Every finalized
    // checkpoint names its `descriptorHash`, and `StructurallyValidCheckpoint`
    // compares that against the descriptor served beside it — so a store that
    // re-dated its descriptor from the instant this process happened to boot
    // would orphan its own chain on the first restart. The validity interval
    // is therefore anchored to the chain start, which persistence fixes once.
    const chainStartMs = ingressWindowStartMs(
      options.chainStartIngressWindow,
      options.profile.deliveryWindowMs,
    );
    const notBeforeUnixMs =
      chainStartMs > DESCRIPTOR_BACKDATE_MS
        ? chainStartMs - DESCRIPTOR_BACKDATE_MS
        : 0n;
    const unsigned: StoreDescriptorV1 = {
      version: 1,
      storeIdentityEd25519Key: keyPair.publicKey,
      // An empty DER SEQUENCE: open allocation has no Privacy Pass issuer, and
      // a zero-length field would not be a well-formed DER value at all.
      allocationIssuerPublicKeyDer: Uint8Array.of(0x30, 0x00),
      descriptorGeneration: 1n,
      compatibilityHash,
      supportedDeliveryProfileHashes: [profileHash],
      checkpointChainStarts: [
        {
          deliveryProfileHash: profileHash,
          chainStartIngressWindow: options.chainStartIngressWindow,
        },
      ],
      retentionWindows,
      notBeforeUnixMs,
      notAfterUnixMs: notBeforeUnixMs + options.descriptorValidityMs,
      descriptorSignature: new Uint8Array(64),
    };
    const descriptor: StoreDescriptorV1 = {
      ...unsigned,
      descriptorSignature: await sign(
        await storeDescriptorSignedMessage(unsigned),
        keyPair.secretKey,
        options.module,
      ),
    };
    const descriptorHashBytes = await computeDescriptorHash(descriptor);

    const unsignedRoute: StoreRouteV1 = {
      version: 1,
      storeId: storeIdBytes,
      descriptorHash: descriptorHashBytes,
      routeFamily: PROTOTYPE_ROUTE_FAMILY,
      opaqueLocator,
      routePublicParameters: new Uint8Array(0),
      notBeforeUnixMs,
      notAfterUnixMs: descriptor.notAfterUnixMs,
      routeSignature: new Uint8Array(64),
    };
    const route: StoreRouteV1 = {
      ...unsignedRoute,
      routeSignature: await sign(
        await storeRouteSignedMessage(unsignedRoute),
        keyPair.secretKey,
        options.module,
      ),
    };

    // Refuse to run rather than serve an identity no client would accept. The
    // reachable failure here is expiry: a chain older than descriptorValidityMs
    // needs a new generation, which needs the per-window descriptor retention
    // this prototype's persistence port does not have.
    const validity = await validateStoreDescriptor(
      descriptor,
      nowMs,
      options.module,
    );
    if (!validity.valid)
      failConfiguration(
        `the store descriptor it just signed is invalid: ${validity.reason}`,
      );
    // The route is checked separately because it binds values the descriptor
    // check never sees — the locator, the family, and its own lease — and a
    // store that published an unusable route would be reachable by nobody.
    const routeValidity = await validateStoreRoute(
      route,
      descriptor,
      nowMs,
      options.module,
    );
    if (!routeValidity.valid)
      failConfiguration(
        `the store route it just signed is invalid: ${routeValidity.reason}`,
      );

    // Refuse to boot on options that contradict the chain already signed.
    //
    // A checkpoint carries both `chainStartIngressWindow` and `descriptorHash`,
    // and neither a chunk nor a checkpoint is ever re-signed. Resuming a chain
    // over windows 100..200 with a chain start of 300 would append checkpoints
    // that `StructurallyValidCheckpoint` rejects forever ("checkpoint precedes
    // the declared chain start"), and a smaller start leaves a hole no later
    // finalization can fill. Both are unrecoverable, so the only safe answer to
    // a mismatch is to not run.
    const lastFinalized = await options.persistence.lastFinalizedWindow();
    if (lastFinalized !== null) {
      const persisted = (await options.persistence.loadWindow(lastFinalized))
        ?.finalized?.checkpoint;
      if (persisted === undefined)
        failConfiguration(
          `persistence reports window ${String(lastFinalized)} finalized but holds no checkpoint for it`,
        );
      if (persisted.chainStartIngressWindow !== options.chainStartIngressWindow)
        failConfiguration(
          `the persisted chain starts at window ${String(persisted.chainStartIngressWindow)}, not the configured ${String(options.chainStartIngressWindow)}`,
        );
      if (!bytesEqual(persisted.descriptorHash, descriptorHashBytes))
        throw new StoreDescriptorChangedError(
          `the persisted chain was signed under a different descriptor than this configuration produces (retention ${String(retentionWindows)} windows): a setting the descriptor states changed, such as the retention or the identity key, or the chain was signed by an earlier prototype version (whose descriptor named another compatibility hash, or stated no retention); restore the setting, or start a new chain with a new database and a new identity key`,
        );
    }

    // One envelope encoding per class, at start: the wire length is fixed by
    // the profile, and recomputing it per append would burn the object length
    // on the request path.
    const objectBytesByClass = new Map<number, number>(
      options.profile.sizeClasses.map((sizeClass) => [
        sizeClass.id,
        carrierObjectWireBytes(options.profile, sizeClass.id, profileHash),
      ]),
    );

    return new PrototypeStoreCore(
      options,
      {
        secretKey: keyPair.secretKey,
        storeId: storeIdBytes,
        profileHash,
        descriptor,
        descriptorHash: descriptorHashBytes,
        routes: [route],
      },
      objectBytesByClass,
      retentionWindows,
    );
  }

  descriptorDocument(): PrototypeStoreDescriptorDocumentV1 {
    return {
      descriptor: copyDescriptor(this.#descriptor),
      routes: this.#routes.map(copyRoute),
    };
  }

  currentWindow(): bigint {
    return ingressWindow(this.#profile.deliveryWindowMs, this.#clock.nowMs());
  }

  /* ---------------------------------------------------------------- *
   * Allocation
   * ---------------------------------------------------------------- */

  /**
   * Open-mode issuance: the store answers every well-formed request with the
   * fixed `issued` shape and 32 zero bytes, and records nothing.
   *
   * Scheme 1 (Blind-RSA Privacy Pass) is not implemented in the prototype, so
   * there is no quota to consume and no replay row to keep — which is exactly
   * why open mode carries no Sybil or fairness claim, only fixed traffic shape.
   */
  async issueToken(
    request: AllocationTokenIssueRequestV1,
  ): Promise<AllocationTokenIssueResultV1> {
    const privateRequest: AllocationTokenIssueRequestV1 = {
      version: request.version,
      storeId: copyBytes(request.storeId),
      deliveryProfileHash: copyBytes(request.deliveryProfileHash),
      ingressWindow: request.ingressWindow,
      privacyPassTokenRequest: copyBytes(request.privacyPassTokenRequest),
    };
    if (privateRequest.version !== 1)
      fail("unsupported allocation token issue request version");

    const body: AllocationTokenIssueResultV1["body"] = {
      kind: "issued",
      version: 1,
      requestHash: await allocationTokenIssueRequestHash(privateRequest),
      privacyPassTokenResponse: new Uint8Array(32),
    };
    return {
      body,
      storeSignature: await sign(
        await allocationTokenIssueResultSignedMessage(body),
        this.#secretKey,
        this.#module,
      ),
    };
  }

  async allocate(
    request: PublicAllocationRequestV1,
  ): Promise<PublicAllocationResultV1> {
    const privateRequest: PublicAllocationRequestV1 = {
      version: request.version,
      deliveryProfileHash: copyBytes(request.deliveryProfileHash),
      ingressWindow: request.ingressWindow,
      allocationEd25519PublicKey: copyBytes(request.allocationEd25519PublicKey),
      privacyPassToken: copyBytes(request.privacyPassToken),
    };
    if (privateRequest.version !== 1)
      fail("unsupported allocation request version");
    if (privateRequest.allocationEd25519PublicKey.length !== 32)
      fail("the allocation public key must be exactly 32 bytes");
    requireProfileHash(privateRequest.deliveryProfileHash);
    requireWindow(privateRequest.ingressWindow);

    const requestHash = await publicAllocationRequestHash(privateRequest);
    const status = (
      kind: PublicAllocationStatusKindV1,
    ): Promise<PublicAllocationResultV1> =>
      this.#allocationStatus(
        privateRequest.deliveryProfileHash,
        privateRequest.ingressWindow,
        requestHash,
        kind,
      );

    // Everything up to the lease is decided off the mutation queue: the clock,
    // the admission hook, and — when this process holds a record of the open
    // window — a replay, a spent grant and a full cohort. None of them loads
    // the window, and none of them waits behind requests that do.
    const refusal = this.#allocationRefusal(privateRequest);
    if (refusal !== null) return status(refusal);
    const admitted = await this.#admit({
      ...privateRequest,
      route: "allocation",
    });
    if (admitted.kind === "refused") return status("invalid-token");

    const known = this.#openWindows.get(String(privateRequest.ingressWindow));
    const early =
      known === undefined
        ? null
        : this.#allocationFromState(known, requestHash, admitted);
    const decided =
      early ??
      (await this.#serialize(() =>
        this.#allocate(privateRequest, requestHash, admitted),
      ));
    return decided.kind === "lease"
      ? { kind: "allocated", lease: copyLease(decided.lease) }
      : status(decided.status);
  }

  /** The refusal the request and the clock alone decide, or `null`. */
  #allocationRefusal(
    request: PublicAllocationRequestV1,
  ): PublicAllocationStatusKindV1 | null {
    // The closed status set has no "unsupported profile" value. `invalid-token`
    // is the honest one: in every allocation scheme the token is bound to the
    // profile, so a request naming another profile cannot carry a token this
    // store would ever accept.
    if (!bytesEqual(request.deliveryProfileHash, this.#profileHash))
      return "invalid-token";

    const target = request.ingressWindow;
    const current = this.currentWindow();
    // Below the chain start no window is ever finalized, so a lease there
    // would promise custody of slots no chunk will carry.
    if (
      target < this.#chainStart ||
      target < current ||
      target > current + BigInt(this.#profile.maxFutureIngressWindows) ||
      this.#closedOnClock(target)
    )
      return "window-closed";
    return null;
  }

  /**
   * What `state` already decides about an admitted allocation: the lease an
   * exact retry replays, or a refusal for a spent grant or a full cohort.
   * `null` means only a new lease can answer, which needs the queue.
   */
  #allocationFromState(
    state: StoreWindowState,
    requestHash: Uint8Array,
    admitted: Admission,
  ): AllocationDecision | null {
    // An exact duplicate replays the byte-identical lease and consumes no
    // second ordinal, on any route and after a restart.
    for (const record of state.allocations.values())
      if (bytesEqual(record.requestHash, requestHash))
        return { kind: "lease", lease: record.lease };

    if (admitted.kind === "admitted")
      for (const record of state.allocations.values())
        if (
          record.admissionQuotaKey32 !== undefined &&
          bytesEqual(record.admissionQuotaKey32, admitted.quotaKey32)
        )
          return { kind: "status", status: "invalid-token" };

    if (state.allocations.size >= this.#profile.cohortAllocationsPerWindow)
      return { kind: "status", status: "capacity-exhausted" };
    return null;
  }

  async #allocate(
    request: PublicAllocationRequestV1,
    requestHash: Uint8Array,
    admitted: Admission,
  ): Promise<AllocationDecision> {
    // Decided again: the window may have closed while this request waited,
    // and a finalized window is always closed on the clock.
    const refusal = this.#allocationRefusal(request);
    if (refusal !== null) return { kind: "status", status: refusal };

    const target = request.ingressWindow;
    const state = await this.#openWindowState(target);
    if (this.#windowIsClosed(state, target))
      return { kind: "status", status: "window-closed" };
    const decided = this.#allocationFromState(state, requestHash, admitted);
    if (decided !== null) return decided;

    let allocationOrdinal = 0;
    while (state.allocations.has(allocationOrdinal)) allocationOrdinal++;

    const leaseBody: PublicAllocationLeaseBodyV1 = {
      version: 1,
      storeId: copyBytes(this.#storeId),
      deliveryProfileHash: copyBytes(this.#profileHash),
      ingressWindow: target,
      requestHash,
      allocationOrdinal,
      allocationEd25519PublicKey: request.allocationEd25519PublicKey,
    };
    const lease: PublicAllocationLeaseV1 = {
      ...leaseBody,
      storeSignature: await sign(
        await publicAllocationLeaseSignedMessage(leaseBody),
        this.#secretKey,
        this.#module,
      ),
    };

    // Do not mutate a window returned by a caching persistence adapter, or
    // held in this process's record, before saveWindow commits. A failed
    // write must not consume an ordinal or grant.
    const nextState = { ...state, allocations: new Map(state.allocations) };
    nextState.allocations.set(allocationOrdinal, {
      leaseBody,
      lease,
      requestHash,
      ...(admitted.kind === "admitted"
        ? { admissionQuotaKey32: admitted.quotaKey32 }
        : {}),
    });
    await this.#persistence.saveWindow(nextState);
    this.#rememberOpenWindow(nextState);
    return { kind: "lease", lease };
  }

  async #allocationStatus(
    profileHashBytes: Uint8Array,
    target: bigint,
    requestHash: Uint8Array,
    status: PublicAllocationStatusKindV1,
  ): Promise<PublicAllocationResultV1> {
    const value: PublicAllocationStatusBodyV1 = {
      version: 1,
      storeId: copyBytes(this.#storeId),
      deliveryProfileHash: copyBytes(profileHashBytes),
      ingressWindow: target,
      requestHash,
      status,
      fixedErrorPadding: new Uint8Array(32),
    };
    return {
      kind: "status",
      value,
      storeSignature: await sign(
        await publicAllocationStatusSignedMessage(value),
        this.#secretKey,
        this.#module,
      ),
    };
  }

  /* ---------------------------------------------------------------- *
   * Append
   * ---------------------------------------------------------------- */

  /**
   * Redeem one admission into one slot, or accept and discard cover.
   *
   * A malformed admission throws `StoreRequestError` (the transport's one
   * constant 400) rather than returning a status: `slot-conflict` is carrier
   * evidence about a slot two clients both claimed, and answering a forged
   * signature with it would manufacture that evidence out of nothing.
   *
   * `admissionToken` is what the caller presented to the admission hook (the
   * transport's bearer header); a hook refusal throws
   * `StoreAdmissionRefusedError`. Everything before the slot binding reads
   * only the request and the clock, and only the binding itself loads the
   * window and takes the mutation queue.
   */
  async append(
    request: PublicAppendRequestV1,
    admissionToken?: Uint8Array,
  ): Promise<PublicAppendResultV1> {
    const admission = request.admission;
    const privateRequest: PublicAppendRequestV1 = {
      version: request.version,
      bucket: copyBucket(request.bucket),
      exactFixedObject: copyBytes(request.exactFixedObject),
      admission:
        admission === null
          ? null
          : {
              version: admission.version,
              lease: copyLease(admission.lease),
              objectOrdinalWithinAllocation:
                admission.objectOrdinalWithinAllocation,
              allocationSignature: copyBytes(admission.allocationSignature),
            },
    };
    const token = presentedToken(admissionToken);
    if (privateRequest.version !== 1)
      fail("unsupported append request version");
    requireProfileHash(privateRequest.bucket.deliveryProfileHash);
    requireWindow(privateRequest.bucket.ingressWindow);
    requireSizeClassId(privateRequest.bucket.sizeClass);

    const { bucket, exactFixedObject } = privateRequest;
    const appendAdmission = privateRequest.admission;
    if (!bytesEqual(bucket.deliveryProfileHash, this.#profileHash))
      fail(
        "the append bucket names a delivery profile this store does not serve",
      );
    const objectBytes = this.#objectBytesByClass.get(bucket.sizeClass);
    if (objectBytes === undefined)
      fail(`no size class with id ${String(bucket.sizeClass)} in this profile`);
    if (exactFixedObject.length !== objectBytes)
      fail("the carrier object is not this size class's exact wire length");

    const requestHash = await publicAppendRequestHash(privateRequest);
    const result = (
      status: PublicAppendStatusV1,
    ): Promise<PublicAppendResultV1> =>
      this.#appendResult(bucket, requestHash, status);

    // Answered from the clock: a finalized window, one closed but not yet
    // finalized, one below the chain start and one already swept are the
    // same request to this line and get the same answer for the same work.
    // Below the chain start no window is ever finalized, so it is closed.
    const window = bucket.ingressWindow;
    if (window < this.#chainStart || this.#closedOnClock(window))
      return result("window-finalized");
    // The status set has no "not open yet". `capacity-exhausted` is the
    // honest one: no lease can exist this far ahead, so the window has no
    // capacity any append to it could use.
    if (
      window >
      this.currentWindow() + BigInt(this.#profile.maxFutureIngressWindows)
    )
      return result("capacity-exhausted");

    const admitted = await this.#admit({
      route: "append",
      version: 1,
      deliveryProfileHash: bucket.deliveryProfileHash,
      ingressWindow: window,
      allocationEd25519PublicKey:
        appendAdmission === null
          ? new Uint8Array(32)
          : appendAdmission.lease.allocationEd25519PublicKey,
      privacyPassToken: token,
    });
    if (admitted.kind === "refused")
      throw new StoreAdmissionRefusedError("append");

    // Degraded cover: the same bounded parse, the one fixed result, no row.
    if (appendAdmission === null) return result("unallocated-cover");

    if (appendAdmission.version !== 1)
      fail("unsupported append admission version");
    const { storeSignature, ...leaseBody } = appendAdmission.lease;
    if (!bytesEqual(leaseBody.storeId, this.#storeId))
      fail("the admission lease names another store");
    if (!bytesEqual(leaseBody.deliveryProfileHash, bucket.deliveryProfileHash))
      fail("the admission lease names another delivery profile");
    if (leaseBody.ingressWindow !== bucket.ingressWindow)
      fail("the admission lease names another ingress window");

    const leaseVerified = await verify(
      await publicAllocationLeaseSignedMessage(leaseBody),
      storeSignature,
      this.#storePublicKey,
      this.#module,
    );
    if (!leaseVerified) fail("the admission lease signature does not verify");

    const sizeClass = this.#sizeClass(bucket.sizeClass);
    const slotsPerAllocation =
      this.#profile.roomSlotsPerClient * sizeClass.appendSchedule.length;
    const ordinal = appendAdmission.objectOrdinalWithinAllocation;
    if (
      !Number.isSafeInteger(ordinal) ||
      ordinal < 0 ||
      ordinal >= slotsPerAllocation
    )
      fail("the object ordinal is outside this allocation's slot count");
    if (
      !Number.isSafeInteger(leaseBody.allocationOrdinal) ||
      leaseBody.allocationOrdinal < 0 ||
      leaseBody.allocationOrdinal >= this.#profile.cohortAllocationsPerWindow
    )
      fail("the lease ordinal is outside the cohort capacity");

    // Binds (storeId, profile, window, sizeClass, allocationOrdinal, ordinal,
    // H(object)) at once, so one admission cannot be replayed into another
    // slot of the same allocation or against different bytes.
    const admissionVerified = await verify(
      await allocationAppendSignedMessage(
        leaseBody,
        bucket.sizeClass,
        ordinal,
        exactFixedObject,
      ),
      appendAdmission.allocationSignature,
      leaseBody.allocationEd25519PublicKey,
      this.#module,
    );
    if (!admissionVerified)
      fail("the allocation append signature does not verify");

    // The fault mode answers as an honest store would and then drops the
    // object, which is what makes the client's cross-store comparison the
    // thing under test rather than the store's own honesty report.
    if (this.#fault === "withhold") return result("stored");

    const coordinates = appendSlotCoordinates(
      this.#geometry,
      bucket.sizeClass,
      leaseBody.allocationOrdinal,
      ordinal,
    );
    const key = slotKey(
      bucket.sizeClass,
      coordinates.chunkIndex,
      coordinates.objectIndexWithinChunk,
    );
    const objectHash = await sha256(exactFixedObject);

    // A replay of a bound slot is answered from this process's record of the
    // open window: it binds nothing, so it neither loads nor queues.
    const bound = this.#openWindows.get(String(window))?.slots.get(key);
    if (bound !== undefined)
      return result(
        bytesEqual(bound.objectHash, objectHash)
          ? "already-present"
          : "slot-conflict",
      );
    return result(
      await this.#serialize(() =>
        this.#bindSlot(window, key, objectHash, exactFixedObject),
      ),
    );
  }

  /** The one part of an append that reads and writes the window. */
  async #bindSlot(
    window: bigint,
    key: string,
    objectHash: Uint8Array,
    object: Uint8Array,
  ): Promise<PublicAppendStatusV1> {
    const state = await this.#openWindowState(window);
    // Decided again: the window may have closed while this waited, and a
    // finalized row is final whatever the clock says.
    if (this.#windowIsClosed(state, window)) return "window-finalized";

    const bound = state.slots.get(key);
    if (bound !== undefined)
      return bytesEqual(bound.objectHash, objectHash)
        ? "already-present"
        : "slot-conflict";

    // Never mutate a window a caching persistence adapter handed back before
    // saveWindow commits: a failed write must not leave the slot bound in a
    // state this process would go on serving and no restart would find.
    const slots = new Map(state.slots);
    slots.set(key, { objectHash, object });
    const nextState = { ...state, slots };
    await this.#persistence.saveWindow(nextState);
    this.#rememberOpenWindow(nextState);
    return "stored";
  }

  async #appendResult(
    bucket: PublicBucketV1,
    requestHash: Uint8Array,
    status: PublicAppendStatusV1,
  ): Promise<PublicAppendResultV1> {
    const body: PublicAppendResultBodyV1 = {
      version: 1,
      storeId: copyBytes(this.#storeId),
      descriptorHash: copyBytes(this.#descriptorHash),
      bucket: copyBucket(bucket),
      requestHash,
      status,
      fixedStatusPadding: new Uint8Array(16),
    };
    return {
      ...body,
      storeSignature: await sign(
        await publicAppendResultSignedMessage(body),
        this.#secretKey,
        this.#module,
      ),
    };
  }

  /* ---------------------------------------------------------------- *
   * Finalization
   * ---------------------------------------------------------------- */

  /**
   * Finalize every window in chain order whose finalization instant has
   * passed, and return the windows this call closed.
   *
   * Chain order is not an optimization: `previousCheckpointHash` must be the
   * exact hash of the immediately preceding window's checkpoint, so a gap can
   * never be filled in later without equivocating.
   */
  async finalizeDue(): Promise<readonly bigint[]> {
    // The store's own work: never shed, and one call queued at a time, so a
    // finalizer tick that lands behind a long queue does not add another.
    if (this.#finalizing !== null) return this.#finalizing;
    const run = this.#serialize(() => this.#finalizeDue(), false);
    this.#finalizing = run;
    try {
      return await run;
    } finally {
      this.#finalizing = null;
    }
  }

  async #finalizeDue(): Promise<readonly bigint[]> {
    const last = await this.#persistence.lastFinalizedWindow();
    let window = last === null ? this.#chainStart : last + 1n;
    if (window < this.#chainStart) window = this.#chainStart;

    const nowMs = this.#clock.nowMs();
    const finalized: bigint[] = [];
    while (finalized.length < MAX_WINDOWS_FINALIZED_PER_CALL) {
      const dueAt =
        ingressWindowStartMs(window, this.#profile.deliveryWindowMs) +
        this.#profile.chunkFinalizationOffsetMs;
      if (dueAt > nowMs) break;
      await this.#finalizeWindow(window);
      finalized.push(window);
      window += 1n;
    }
    return finalized;
  }

  async #finalizeWindow(window: bigint): Promise<void> {
    const state =
      this.#openWindows.get(String(window)) ??
      (await this.#windowState(window));
    // Immutable after signature: re-signing one window is a fault proof.
    if (state.finalized !== null) return;

    const chunks = new Map<number, PublicChunkV1[]>();
    const chunkHashes = new Map<number, Uint8Array[]>();
    for (const sizeClass of this.#sizeClasses) {
      const objectBytes = this.#objectBytesByClass.get(sizeClass.id);
      if (objectBytes === undefined)
        fail(`no size class with id ${String(sizeClass.id)} in this profile`);

      const signedChunks: PublicChunkV1[] = [];
      const hashes: Uint8Array[] = [];
      let previousChunkHash = copyBytes(ZERO32);
      for (
        let chunkIndex = 0;
        chunkIndex < sizeClass.publicChunksPerWindow;
        chunkIndex++
      ) {
        const fixedObjects: Uint8Array[] = [];
        for (
          let objectIndex = 0;
          objectIndex < this.#profile.publicChunkObjectCount;
          objectIndex++
        ) {
          const slot = state.slots.get(
            slotKey(sizeClass.id, BigInt(chunkIndex), objectIndex),
          );
          fixedObjects.push(
            slot === undefined ? randomBytes(objectBytes) : slot.object,
          );
        }

        const body: PublicChunkBodyV1 = {
          version: 1,
          bucket: {
            deliveryProfileHash: copyBytes(this.#profileHash),
            ingressWindow: window,
            sizeClass: sizeClass.id,
          },
          chunkIndex: BigInt(chunkIndex),
          previousChunkHash,
          fixedObjects,
        };
        const chunk: PublicChunkV1 = {
          ...body,
          storeSignature: await sign(
            await publicChunkSigningHash(body),
            this.#secretKey,
            this.#module,
          ),
        };
        signedChunks.push(chunk);
        previousChunkHash = await publicChunkHash(chunk);
        hashes.push(previousChunkHash);
      }
      chunks.set(sizeClass.id, signedChunks);
      chunkHashes.set(sizeClass.id, hashes);
    }

    const finalizedChunkRoot = await rfc9162MerkleTreeHash(
      await checkpointLeafEntries(this.#geometry, chunkHashes),
    );

    let previousCheckpointHash = copyBytes(ZERO32);
    if (window !== this.#chainStart) {
      const previous = await this.#persistence.loadWindow(window - 1n);
      if (previous?.finalized == null)
        fail(
          `window ${String(window)} has no finalized predecessor to chain onto`,
        );
      previousCheckpointHash = await publicStoreCheckpointHash(
        previous.finalized.checkpoint,
      );
    }

    const body: PublicStoreCheckpointBodyV1 = {
      version: 1,
      storeId: copyBytes(this.#storeId),
      descriptorHash: copyBytes(this.#descriptorHash),
      deliveryProfileHash: copyBytes(this.#profileHash),
      ingressWindow: window,
      chainStartIngressWindow: this.#chainStart,
      previousCheckpointHash,
      finalizedChunkCount: profileFinalizedChunkCount(this.#geometry),
      finalizedChunkRoot,
    };
    const checkpoint: PublicStoreCheckpointV1 = {
      ...body,
      storeSignature: await sign(
        await publicStoreCheckpointSigningHash(body),
        this.#secretKey,
        this.#module,
      ),
    };

    // Saved as a new value, for the reason `#bindSlot` gives: a cached row
    // mutated before a failed write would serve a checkpoint no restart finds,
    // and the restart would sign a different one — the store equivocating.
    // The slots go: every bound object is now inside a signed chunk, and a
    // finalized window binds no slot again.
    await this.#persistence.saveWindow({
      window: state.window,
      allocations: state.allocations,
      slots: new Map(),
      finalized: { chunks, checkpoint },
    });
    this.#openWindows.delete(String(window));
    await this.#saveFinalizedResponses(window, chunks, checkpoint);
  }

  /**
   * Precompute what this window will be read back as, strictly after the
   * finalization has committed.
   *
   * The order matters. A crash or a failed write between the two leaves the
   * rows absent, and the reads then answer from the window row. The reverse
   * order would leave rows describing a finalization that never committed,
   * and re-finalizing draws fresh cover for the unoccupied slots, so those
   * rows would be another window's bytes under this window's name. A failure
   * here rejects `finalizeDue` like any failed write, with the window already
   * final; the next call resumes after it.
   *
   * A persistence port that does not offer the rows is not an error: it is
   * how `MemoryStorePersistence` and every test that uses it run.
   */
  async #saveFinalizedResponses(
    window: bigint,
    chunks: ReadonlyMap<number, readonly PublicChunkV1[]>,
    checkpoint: PublicStoreCheckpointV1,
  ): Promise<void> {
    if (this.#persistence.saveFinalizedResponses === undefined) return;
    const bodies: {
      sizeClass: number;
      chunkIndex: bigint;
      body: Uint8Array;
    }[] = [];
    for (const [sizeClass, signed] of chunks)
      signed.forEach((chunk, chunkIndex) => {
        bodies.push({
          sizeClass,
          chunkIndex: BigInt(chunkIndex),
          body: encodePublicChunkReadV1({ kind: "finalized", chunk }),
        });
      });
    await this.#persistence.saveFinalizedResponses({
      window,
      descriptorHash: copyBytes(this.#descriptorHash),
      checkpoint: encodePublicStoreCheckpointReadV1({
        kind: "finalized",
        descriptor: this.#descriptor,
        checkpoint,
      }),
      chunks: bodies,
    });
  }

  /* ---------------------------------------------------------------- *
   * Reads
   *
   * Each read is decided first, from one reading of the clock and nothing
   * stored: a signed status, or "this window is finalized and retained".
   * Only then is anything loaded. The two GET routes take the encoded form:
   * a finalized window's response bytes were fixed when it was signed, so
   * they come from one precomputed row when there is one, and otherwise from
   * the window row, which is the only path a window finalized without rows
   * has. Both forms produce identical bytes; that equality is what the tests
   * assert, because a difference between them would be a difference in what
   * this store's signature covers. A status is never precomputed: it names
   * the store's window at the time of the request.
   * ---------------------------------------------------------------- */

  async readCheckpoint(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
  ): Promise<PublicStoreCheckpointReadV1> {
    const decided = await this.#decideCheckpointRead(
      deliveryProfileHashBytes,
      window,
    );
    if (decided !== null) return decided;
    return {
      kind: "finalized",
      descriptor: copyDescriptor(this.#descriptor),
      checkpoint: copyCheckpoint(await this.#finalizedCheckpoint(window)),
    };
  }

  async readCheckpointEncoded(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
  ): Promise<StoreEncodedRead> {
    const decided = await this.#decideCheckpointRead(
      deliveryProfileHashBytes,
      window,
    );
    if (decided !== null)
      return {
        bytes: encodePublicStoreCheckpointReadV1(decided),
        finalized: false,
      };
    const row = await this.#persistence.loadCheckpointResponse?.(
      window,
      this.#descriptorHash,
    );
    if (row != null) return { bytes: row, finalized: true };
    return {
      bytes: encodePublicStoreCheckpointReadV1({
        kind: "finalized",
        descriptor: this.#descriptor,
        checkpoint: await this.#finalizedCheckpoint(window),
      }),
      finalized: true,
    };
  }

  /**
   * The signed status a checkpoint read gets, or `null` when the window is
   * finalized on the clock and retained, so its checkpoint is the answer.
   */
  async #decideCheckpointRead(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
  ): Promise<PublicStoreCheckpointReadV1 | null> {
    const requested = copyBytes(deliveryProfileHashBytes);
    requireProfileHash(requested);
    requireWindow(window);
    // One reading of the clock decides the answer and is the window it
    // states: two readings could straddle a step of the wall clock and sign a
    // window that contradicts the decision made on the other.
    const nowMs = this.#clock.nowMs();
    const current = ingressWindow(this.#profile.deliveryWindowMs, nowMs);
    const status = (
      kind: PublicStoreCheckpointStatusKindV1,
    ): Promise<PublicStoreCheckpointReadV1> =>
      this.#checkpointStatus(requested, window, current, kind);

    // A profile this store never served has no chain at all, which is a
    // different answer from "that window of my chain is not final yet".
    if (!bytesEqual(requested, this.#profileHash))
      return status("chain-unavailable");
    // Past retention it is out of range whether or not a sweep has deleted
    // the rows yet: the answer follows the clock, not the sweep's progress.
    if (window < this.#chainStart || !this.#readable(window, current))
      return status("out-of-range");
    // Before its finalization instant no window can be final: the clock
    // answers, and an unauthenticated read decodes no row.
    if (!this.#closedOnClock(window, nowMs)) return status("not-final");
    return null;
  }

  /** A window the clock says is final: its checkpoint, or an unsigned 503
   * while the finalizer has not signed it yet. */
  async #finalizedCheckpoint(window: bigint): Promise<PublicStoreCheckpointV1> {
    const state = await this.#persistence.loadWindow(window);
    if (state?.finalized == null)
      throw new StoreFinalizationPendingError(window);
    return state.finalized.checkpoint;
  }

  async #checkpointStatus(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
    storeWindow: bigint,
    status: PublicStoreCheckpointStatusKindV1,
  ): Promise<PublicStoreCheckpointReadV1> {
    const value = {
      version: 1 as const,
      storeId: copyBytes(this.#storeId),
      // The descriptor this answer is given under: judged against any other,
      // the answer does not verify.
      descriptorHash: copyBytes(this.#descriptorHash),
      deliveryProfileHash: deliveryProfileHashBytes,
      ingressWindow: window,
      // Signed so a refusal states when it was given: an `out-of-range` for
      // a window inside the stated retention is then provable from this
      // answer and the descriptor alone, and the same refusal given at two
      // instants is two different statements. It is the reading the answer
      // was decided on.
      storeIngressWindow: storeWindow,
      status,
    };
    return {
      kind: "status",
      value,
      storeSignature: await sign(
        await publicCheckpointStatusSigningHash(value),
        this.#secretKey,
        this.#module,
      ),
    };
  }

  async readChunk(
    bucket: PublicBucketV1,
    chunkIndex: bigint,
  ): Promise<PublicChunkReadV1> {
    const decided = await this.#decideChunkRead(bucket, chunkIndex);
    if (decided.kind === "status") return decided.read;
    return {
      kind: "finalized",
      chunk: copyChunk(
        await this.#finalizedChunk(
          decided.window,
          decided.sizeClass,
          chunkIndex,
        ),
      ),
    };
  }

  async readChunkEncoded(
    bucket: PublicBucketV1,
    chunkIndex: bigint,
  ): Promise<StoreEncodedRead> {
    const decided = await this.#decideChunkRead(bucket, chunkIndex);
    if (decided.kind === "status")
      return { bytes: encodePublicChunkReadV1(decided.read), finalized: false };
    const row = await this.#persistence.loadChunkResponse?.(
      decided.window,
      decided.sizeClass,
      chunkIndex,
    );
    if (row != null) return { bytes: row, finalized: true };
    return {
      bytes: encodePublicChunkReadV1({
        kind: "finalized",
        chunk: await this.#finalizedChunk(
          decided.window,
          decided.sizeClass,
          chunkIndex,
        ),
      }),
      finalized: true,
    };
  }

  /**
   * The signed status a chunk read gets, or the coordinates of a chunk the
   * profile defines in a window that is finalized on the clock and retained.
   */
  async #decideChunkRead(
    bucket: PublicBucketV1,
    chunkIndex: bigint,
  ): Promise<
    | { readonly kind: "status"; readonly read: PublicChunkReadV1 }
    | {
        readonly kind: "finalized";
        readonly window: bigint;
        readonly sizeClass: number;
      }
  > {
    const requested = copyBucket(bucket);
    requireProfileHash(requested.deliveryProfileHash);
    requireWindow(requested.ingressWindow);
    requireSizeClassId(requested.sizeClass);
    requireChunkIndex(chunkIndex);
    // One reading of the clock, as in `#decideCheckpointRead`.
    const nowMs = this.#clock.nowMs();
    const current = ingressWindow(this.#profile.deliveryWindowMs, nowMs);
    const status = async (
      kind: PublicChunkStatusKindV1,
    ): Promise<{
      readonly kind: "status";
      readonly read: PublicChunkReadV1;
    }> => ({
      kind: "status",
      read: await this.#chunkStatus(requested, chunkIndex, current, kind),
    });

    // Coordinates no window of this store can hold, whatever the window:
    // an unserved profile, an unknown class, an index past the class's
    // count. One status for all three, so the reader learns nothing extra
    // from which it was, and never `out-of-range`, which says only that the
    // window is outside what the store keeps.
    if (!bytesEqual(requested.deliveryProfileHash, this.#profileHash))
      return status("no-such-chunk");
    const sizeClass = this.#profile.sizeClasses.find(
      (candidate) => candidate.id === requested.sizeClass,
    );
    if (sizeClass === undefined) return status("no-such-chunk");
    if (chunkIndex >= BigInt(sizeClass.publicChunksPerWindow))
      return status("no-such-chunk");
    if (
      requested.ingressWindow < this.#chainStart ||
      !this.#readable(requested.ingressWindow, current)
    )
      return status("out-of-range");
    if (!this.#closedOnClock(requested.ingressWindow, nowMs))
      return status("not-final");
    return {
      kind: "finalized",
      window: requested.ingressWindow,
      sizeClass: sizeClass.id,
    };
  }

  /** One chunk of a window the clock says is final, or an unsigned 503 while
   * the finalizer has not signed it yet. */
  async #finalizedChunk(
    window: bigint,
    sizeClass: number,
    chunkIndex: bigint,
  ): Promise<PublicChunkV1> {
    const state = await this.#persistence.loadWindow(window);
    if (state?.finalized == null)
      throw new StoreFinalizationPendingError(window);
    const chunk = state.finalized.chunks.get(sizeClass)?.[Number(chunkIndex)];
    // Finalization signs every index of every class, so this is a damaged
    // row: an internal failure, never a signed status.
    if (chunk === undefined)
      throw new Error(
        `storeCore: finalized window ${String(window)} has no chunk ${String(chunkIndex)} of class ${String(sizeClass)}`,
      );
    return chunk;
  }

  async #chunkStatus(
    bucket: PublicBucketV1,
    chunkIndex: bigint,
    storeWindow: bigint,
    status: PublicChunkStatusKindV1,
  ): Promise<PublicChunkReadV1> {
    const value = {
      version: 1 as const,
      descriptorHash: copyBytes(this.#descriptorHash),
      bucket,
      chunkIndex,
      storeIngressWindow: storeWindow,
      status,
    };
    return {
      kind: "status",
      value,
      storeSignature: await sign(
        await publicChunkStatusSigningHash(value),
        this.#secretKey,
        this.#module,
      ),
    };
  }

  /* ---------------------------------------------------------------- *
   * Witness records
   * ---------------------------------------------------------------- */

  /**
   * Record one observation of another store's checkpoint.
   *
   * Bounded and idempotent: a witness log is unauthenticated input from a peer
   * store, so it may not grow without limit, and re-offering an observation
   * must not make it look like two. Only a window closed on this store's clock
   * and still retained is accepted, so nobody can pre-fill a window before
   * its checkpoint can exist, and every row goes with its window at the
   * sweep. Under open admission that still leaves the interval from the
   * window's finalization instant to the honest witness instant, one window
   * later at `chunkFinalizationOffsetMs - maxScheduleSkewMs`, in which anyone
   * can fill the window's bound first.
   *
   * The insert is one atomic persistence call against kept counts: it reads
   * none of the window's records and takes no place on the mutation queue.
   * Under admission each quota key adds at most
   * `PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY` records to a window,
   * so filling the window's `PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW`
   * takes that many admitted grants; under open admission there is no key to
   * charge, and the first callers to reach the per-window bound fill it for
   * everyone.
   */
  async addWitness(
    record: StoreWitnessRecordV1,
    admissionToken?: Uint8Array,
  ): Promise<StoreWitnessOutcomeV1> {
    const privateRecord = copyWitnessRecord(record);
    const token = presentedToken(admissionToken);
    if (privateRecord.version !== 1)
      fail("unsupported store witness record version");
    requireWindow(privateRecord.ingressWindow);
    requireProfileHash(privateRecord.deliveryProfileHash);
    if (
      privateRecord.witnessedStoreId.length !== 32 ||
      privateRecord.checkpointHash.length !== 32
    )
      fail("a witness record names a 32-byte store id and checkpoint hash");

    // A record about another profile answers no read of this one, and a
    // window outside retention can never be read back: neither is worth a
    // row, or a call to the admission hook.
    if (
      !bytesEqual(privateRecord.deliveryProfileHash, this.#profileHash) ||
      !this.#witnessRetained(privateRecord.ingressWindow)
    )
      return "not-recorded";

    const admitted = await this.#admit({
      route: "witness",
      version: 1,
      deliveryProfileHash: privateRecord.deliveryProfileHash,
      ingressWindow: privateRecord.ingressWindow,
      allocationEd25519PublicKey: new Uint8Array(32),
      privacyPassToken: token,
    });
    if (admitted.kind === "refused")
      throw new StoreAdmissionRefusedError("witness");

    const outcome = await this.#persistence.addWitnessRecord(privateRecord, {
      maxRecordsPerWindow: PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW,
      quotaKey32: admitted.kind === "admitted" ? admitted.quotaKey32 : null,
      maxRecordsPerQuotaKey: PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY,
    });
    if (outcome === "added") return "recorded";
    return outcome === "present" ? "already-held" : "not-recorded";
  }

  /** The records held for `window`; none outside retention, unloaded. */
  async witnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]> {
    requireWindow(window);
    if (!this.#witnessRetained(window)) return [];
    return this.#persistence.loadWitnessRecords(window);
  }

  /* ---------------------------------------------------------------- *
   * Retention
   * ---------------------------------------------------------------- */

  /**
   * Delete what retention no longer covers: at most
   * `PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS` window rows and as many witness
   * windows per call, smallest first. The server calls it on a timer.
   *
   * A window stops being served once `current - window > retentionWindows`
   * (`bucketIsReadable`) and is deleted one window after that, so a read that
   * passed its retention check never loads a row this call is removing.
   * Window rows go only below the last finalized window: that one is the chain
   * tip the next checkpoint links to, and anything after it may still owe its
   * slots to a chunk. A deleted row takes its allocation records, their
   * admission quota keys and its precomputed responses with it; a deleted
   * witness window takes its per-key counts.
   *
   * It runs beside requests rather than on the mutation queue: allocation
   * and append name open windows and finalization names the windows after the
   * tip, so nothing that writes touches a row this deletes. A call that
   * overlaps a running one returns at once and deletes nothing.
   */
  async sweepRetention(): Promise<StoreRetentionSweep> {
    if (this.#sweeping) return { windows: 0, witnessWindows: 0 };
    this.#sweeping = true;
    try {
      const floor = this.currentWindow() - BigInt(this.#retentionWindows) - 1n;
      if (floor <= 0n) return { windows: 0, witnessWindows: 0 };
      const tip = await this.#persistence.lastFinalizedWindow();
      const windows =
        tip === null
          ? 0
          : await this.#persistence.deleteWindowsBefore(
              tip < floor ? tip : floor,
              PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS,
            );
      const witnessWindows = await this.#persistence.deleteWitnessRecordsBefore(
        floor,
        PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS,
      );
      return { windows, witnessWindows };
    } finally {
      this.#sweeping = false;
    }
  }

  /* ---------------------------------------------------------------- *
   * Internals
   * ---------------------------------------------------------------- */

  /**
   * Run one unit of mutating work after every unit queued before it.
   *
   * Allocation ordinals and slot bindings are read-modify-write across awaits
   * (signing is async), so two concurrent requests on the HTTP server would
   * otherwise both see the same free ordinal or the same empty slot.
   */
  #serialize<T>(work: () => Promise<T>, shed = true): Promise<T> {
    // Refused before the closure exists: a shed request leaves nothing of
    // itself on the queue.
    if (shed && this.#queueDepth >= PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH)
      return Promise.reject(new StoreBusyError());
    this.#queueDepth += 1;
    const running = this.#tail.then(work, work);
    // The chain must survive a rejected unit of work, or one bad request would
    // wedge every later one.
    const settled = (): void => {
      this.#queueDepth -= 1;
    };
    this.#tail = running.then(settled, settled);
    return running;
  }

  /**
   * Ask the admission hook about one request, or report open admission.
   *
   * The hook gets its own bytes, so accidental mutation cannot change a
   * request already hashed or a key bound afterwards. See
   * `PrototypeStoreCoreOptions.allocationAdmission` for when this is called.
   */
  async #admit(request: StoreAdmissionRequestV1): Promise<Admission> {
    if (this.#allocationAdmission === undefined) return OPEN_ADMISSION;
    try {
      const key = await this.#allocationAdmission.authorize({
        ...request,
        deliveryProfileHash: copyBytes(request.deliveryProfileHash),
        allocationEd25519PublicKey: copyBytes(
          request.allocationEd25519PublicKey,
        ),
        privacyPassToken: copyBytes(request.privacyPassToken),
      });
      if (!(key instanceof Uint8Array) || key.length !== 32)
        return REFUSED_ADMISSION;
      return { kind: "admitted", quotaKey32: copyBytes(key) };
    } catch {
      return REFUSED_ADMISSION;
    }
  }

  /** Served on read: any window not yet past, and retained ones that are. */
  #readable(window: bigint, current: bigint = this.currentWindow()): boolean {
    return (
      window > current ||
      bucketIsReadable(window, current, this.#retentionWindows)
    );
  }

  /**
   * Accepted for witnessing: a window closed on the clock, so its checkpoint
   * can exist, and still retained.
   */
  #witnessRetained(window: bigint): boolean {
    return (
      this.#closedOnClock(window) &&
      bucketIsReadable(window, this.currentWindow(), this.#retentionWindows)
    );
  }

  /**
   * The state of a window a write names: this process's record of it, or a
   * load that then becomes the record while the window is open.
   */
  async #openWindowState(window: bigint): Promise<StoreWindowState> {
    const known = this.#openWindows.get(String(window));
    if (known !== undefined) return known;
    const loaded = await this.#windowState(window);
    this.#rememberOpenWindow(loaded);
    return loaded;
  }

  /**
   * Record a window's committed state while it is open for writes, and drop
   * every window the clock has closed (finalization loads a closed window
   * once). The record never outgrows the windows a write can still name.
   */
  #rememberOpenWindow(state: StoreWindowState): void {
    for (const [key, held] of this.#openWindows)
      if (this.#closedOnClock(held.window)) this.#openWindows.delete(key);
    if (state.finalized !== null || this.#closedOnClock(state.window)) return;
    this.#openWindows.set(String(state.window), state);
    const bound = this.#profile.maxFutureIngressWindows + 2;
    while (this.#openWindows.size > bound) {
      let oldest: bigint | null = null;
      for (const held of this.#openWindows.values())
        if (oldest === null || held.window < oldest) oldest = held.window;
      if (oldest === null) break;
      this.#openWindows.delete(String(oldest));
    }
  }

  async #windowState(window: bigint): Promise<StoreWindowState> {
    return (
      (await this.#persistence.loadWindow(window)) ??
      emptyStoreWindowState(window)
    );
  }

  /**
   * A window is closed once its finalization instant has passed, whether or
   * not `finalizeDue` has run: the close is a property of the clock, not of
   * the finalizer's schedule.
   */
  #windowIsClosed(state: StoreWindowState, window: bigint): boolean {
    return state.finalized !== null || this.#closedOnClock(window);
  }

  /** `IngressWindowStart(window) + chunkFinalizationOffsetMs` has passed. */
  #closedOnClock(window: bigint, nowMs: bigint = this.#clock.nowMs()): boolean {
    const dueAt =
      ingressWindowStartMs(window, this.#profile.deliveryWindowMs) +
      this.#profile.chunkFinalizationOffsetMs;
    return dueAt <= nowMs;
  }

  #sizeClass(id: number): DeliverySizeClassV1 {
    const found = this.#profile.sizeClasses.find(
      (candidate) => candidate.id === id,
    );
    if (found === undefined)
      fail(`no size class with id ${String(id)} in this profile`);
    return found;
  }
}
