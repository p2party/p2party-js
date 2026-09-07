/**
 * The prototype store's window machine: allocation, append, finalization, and
 * the checkpoint chain (design doc §4.3, specification §4.3).
 *
 * Everything this file touches is public geometry — a delivery-profile hash,
 * an ingress window, a size class, an ordinal, and opaque fixed-length bytes.
 * No room, member, peer, invitation or operation value is an input to any
 * method here, and none is derivable from what is stored, which is the whole
 * reason unrelated rooms can share one bucket and cover for each other.
 *
 * Two properties this file is responsible for and that nothing downstream can
 * repair:
 *
 * - A window closes on the clock, not on when `finalizeDue` happened to run.
 *   An append is refused once `IngressWindowStart(w) + chunkFinalizationOffsetMs`
 *   has passed even if the chunks are not signed yet, so a slow finalizer can
 *   never let one client's object into a chunk another client already read a
 *   checkpoint for.
 * - A finalized window is never re-signed. Signing two different chunk bodies
 *   for one index, or two checkpoints for one window, is a permanent fault
 *   proof against the store — so `#finalizeWindow` returns early rather than
 *   recompute, and every mutating entry point is serialized.
 *
 * Transport lives in `storeHttp.ts`; durable rows live behind
 * `StorePersistencePort`. This file knows about neither.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry, and nothing here is a v0.4 release artifact.
 */

import { keyPairFromSeed, sign, verify } from "../../../cryptography/ed25519";
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
} from "../../storeDescriptor";
import {
  carrierObjectWireBytes,
  profileGeometry,
  validateDeliveryProfileGeometry,
} from "../profile";
import { encodeStoreWitnessRecordV1 } from "../storeWire";
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
  override readonly name = "StoreRequestError";

  constructor(message: string) {
    super(`storeCore: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new StoreRequestError(message);
};

export interface StoreClock {
  nowMs(): bigint;
}

/** The one secret a store process holds; the server writes it to a key file. */
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
}

/** `crypto.getRandomValues` refuses more than this many bytes per call. */
const RANDOM_SLICE_BYTES = 65_536;

/**
 * Room for a store to catch up after downtime without letting a corrupt chain
 * start turn one call into an unbounded signing loop. Nothing is skipped: the
 * next `finalizeDue` continues from the same place.
 */
const MAX_WINDOWS_FINALIZED_PER_CALL = 4_096;

/** The witness array's canonical cap (`storeWitnessRecordsV1Schema`). */
const MAX_WITNESS_RECORDS_PER_WINDOW = 4_096;

/** A route lease is the descriptor's; a route outliving it proves nothing. */
const PROTOTYPE_ROUTE_FAMILY = 1;

/** Tolerance for a descriptor signed a moment after the clock was read. */
const DESCRIPTOR_BACKDATE_MS = 60_000n;

const textEncoder = new TextEncoder();

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return false;
  return true;
};

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * Reject coordinates that no signed answer could carry.
 *
 * Every status this store returns names the coordinates it was asked about, so
 * a request the status body cannot encode has no signable refusal — the
 * transport's one constant 400 is the only correct answer. The canonical
 * decoders already enforce these widths on the wire; this is the guard for the
 * in-process callers that do not go through them.
 */
const requireProfileHash = (value: Uint8Array): void => {
  if (value.length !== 32) fail("a delivery profile hash must be 32 bytes");
};

const requireWindow = (window: bigint): void => {
  if (window < 0n) fail("an ingress window must not be negative");
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
  readonly storeId: Uint8Array;
  readonly descriptor: StoreDescriptorV1;
  readonly descriptorHash: Uint8Array;
  readonly routes: readonly StoreRouteV1[];
  readonly profileHash: Uint8Array;

  readonly #module: LibCrypto;
  readonly #secretKey: Uint8Array;
  readonly #profile: DeliveryProfileV1;
  readonly #geometry: PublicProfileGeometry;
  readonly #clock: StoreClock;
  readonly #persistence: StorePersistencePort;
  readonly #chainStart: bigint;
  readonly #fault: "withhold" | null;
  readonly #sizeClasses: readonly DeliverySizeClassV1[];
  readonly #objectBytesByClass: ReadonlyMap<number, number>;

  /** Serializes every mutating entry point; see the file header. */
  #tail: Promise<unknown> = Promise.resolve();

  private constructor(
    options: PrototypeStoreCoreOptions,
    identity: PreparedIdentity,
    objectBytesByClass: ReadonlyMap<number, number>,
  ) {
    this.storeId = identity.storeId;
    this.descriptor = identity.descriptor;
    this.descriptorHash = identity.descriptorHash;
    this.routes = identity.routes;
    this.profileHash = identity.profileHash;

    this.#module = options.module;
    this.#secretKey = identity.secretKey;
    this.#profile = options.profile;
    this.#geometry = profileGeometry(options.profile);
    this.#clock = options.clock;
    this.#persistence = options.persistence;
    this.#chainStart = options.chainStartIngressWindow;
    this.#fault = options.fault ?? null;
    // Sorted by id once: leaf order and chunk order are both profile order,
    // and rebuilding that order per finalization invites one of them to drift.
    this.#sizeClasses = [...options.profile.sizeClasses].sort(
      (left, right) => left.id - right.id,
    );
    this.#objectBytesByClass = objectBytesByClass;
  }

  static async create(
    options: PrototypeStoreCoreOptions,
  ): Promise<PrototypeStoreCore> {
    if (options.seed.length !== 32)
      fail("the store identity seed must be exactly 32 bytes");
    if (options.chainStartIngressWindow < 0n)
      fail("chainStartIngressWindow must not be negative");
    if (options.descriptorValidityMs <= 0n)
      fail("descriptorValidityMs must be positive");
    // A profile that has not passed §4.3's inequalities cannot be served:
    // every later offset comparison in this file assumes them.
    validateDeliveryProfileGeometry(options.profile);

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
      opaqueLocator: textEncoder.encode(options.origin),
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

    // Refuse to run rather than serve a descriptor no client would accept. The
    // reachable failure here is expiry: a chain older than descriptorValidityMs
    // needs a new generation, which needs the per-window descriptor retention
    // this prototype's persistence port does not have.
    const validity = await validateStoreDescriptor(
      descriptor,
      nowMs,
      options.module,
    );
    if (!validity.valid)
      fail(
        `the store descriptor it just signed is invalid: ${validity.reason}`,
      );

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
    );
  }

  descriptorDocument(): PrototypeStoreDescriptorDocumentV1 {
    return {
      descriptor: copyDescriptor(this.descriptor),
      routes: this.routes.map(copyRoute),
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

    return this.#serialize(() => this.#allocate(privateRequest));
  }

  async #allocate(
    request: PublicAllocationRequestV1,
  ): Promise<PublicAllocationResultV1> {
    const requestHash = await publicAllocationRequestHash(request);
    const status = (
      kind: PublicAllocationStatusKindV1,
    ): Promise<PublicAllocationResultV1> =>
      this.#allocationStatus(
        request.deliveryProfileHash,
        request.ingressWindow,
        requestHash,
        kind,
      );

    // The closed status set has no "unsupported profile" value. `invalid-token`
    // is the honest one: in every allocation scheme the token is bound to the
    // profile, so a request naming another profile cannot carry a token this
    // store would ever accept.
    if (!bytesEqual(request.deliveryProfileHash, this.profileHash))
      return status("invalid-token");

    const target = request.ingressWindow;
    const current = this.currentWindow();
    if (
      target < current ||
      target > current + BigInt(this.#profile.maxFutureIngressWindows)
    )
      return status("window-closed");

    const state = await this.#windowState(target);
    if (this.#windowIsClosed(state, target)) return status("window-closed");

    // An exact duplicate replays the byte-identical lease and consumes no
    // second ordinal, on any route and after a restart.
    for (const record of state.allocations.values())
      if (bytesEqual(record.requestHash, requestHash))
        return { kind: "allocated", lease: copyLease(record.lease) };

    if (state.allocations.size >= this.#profile.cohortAllocationsPerWindow)
      return status("capacity-exhausted");

    let allocationOrdinal = 0;
    while (state.allocations.has(allocationOrdinal)) allocationOrdinal++;

    const leaseBody: PublicAllocationLeaseBodyV1 = {
      version: 1,
      storeId: copyBytes(this.storeId),
      deliveryProfileHash: copyBytes(this.profileHash),
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

    state.allocations.set(allocationOrdinal, { leaseBody, lease, requestHash });
    await this.#persistence.saveWindow(state);
    return { kind: "allocated", lease: copyLease(lease) };
  }

  async #allocationStatus(
    profileHashBytes: Uint8Array,
    target: bigint,
    requestHash: Uint8Array,
    status: PublicAllocationStatusKindV1,
  ): Promise<PublicAllocationResultV1> {
    const value: PublicAllocationStatusBodyV1 = {
      version: 1,
      storeId: copyBytes(this.storeId),
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
   */
  async append(request: PublicAppendRequestV1): Promise<PublicAppendResultV1> {
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
    if (privateRequest.version !== 1)
      fail("unsupported append request version");
    requireProfileHash(privateRequest.bucket.deliveryProfileHash);
    requireWindow(privateRequest.bucket.ingressWindow);

    return this.#serialize(() => this.#append(privateRequest));
  }

  async #append(request: PublicAppendRequestV1): Promise<PublicAppendResultV1> {
    const { bucket, exactFixedObject, admission } = request;

    if (!bytesEqual(bucket.deliveryProfileHash, this.profileHash))
      fail(
        "the append bucket names a delivery profile this store does not serve",
      );
    const objectBytes = this.#objectBytesByClass.get(bucket.sizeClass);
    if (objectBytes === undefined)
      fail(`no size class with id ${String(bucket.sizeClass)} in this profile`);
    if (exactFixedObject.length !== objectBytes)
      fail("the carrier object is not this size class's exact wire length");

    const requestHash = await publicAppendRequestHash(request);
    const result = (
      status: PublicAppendStatusV1,
    ): Promise<PublicAppendResultV1> =>
      this.#appendResult(bucket, requestHash, status);

    const state = await this.#windowState(bucket.ingressWindow);
    if (this.#windowIsClosed(state, bucket.ingressWindow))
      return result("window-finalized");

    // Degraded cover: the same bounded parse, the one fixed result, no row.
    if (admission === null) return result("unallocated-cover");

    if (admission.version !== 1) fail("unsupported append admission version");
    const { storeSignature, ...leaseBody } = admission.lease;
    if (!bytesEqual(leaseBody.storeId, this.storeId))
      fail("the admission lease names another store");
    if (!bytesEqual(leaseBody.deliveryProfileHash, bucket.deliveryProfileHash))
      fail("the admission lease names another delivery profile");
    if (leaseBody.ingressWindow !== bucket.ingressWindow)
      fail("the admission lease names another ingress window");

    const leaseVerified = await verify(
      await publicAllocationLeaseSignedMessage(leaseBody),
      storeSignature,
      this.descriptor.storeIdentityEd25519Key,
      this.#module,
    );
    if (!leaseVerified) fail("the admission lease signature does not verify");

    const sizeClass = this.#sizeClass(bucket.sizeClass);
    const slotsPerAllocation =
      this.#profile.roomSlotsPerClient * sizeClass.appendSchedule.length;
    const ordinal = admission.objectOrdinalWithinAllocation;
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
      admission.allocationSignature,
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

    const bound = state.slots.get(key);
    if (bound !== undefined)
      return result(
        bytesEqual(bound.objectHash, objectHash)
          ? "already-present"
          : "slot-conflict",
      );

    state.slots.set(key, { objectHash, object: exactFixedObject });
    await this.#persistence.saveWindow(state);
    return result("stored");
  }

  async #appendResult(
    bucket: PublicBucketV1,
    requestHash: Uint8Array,
    status: PublicAppendStatusV1,
  ): Promise<PublicAppendResultV1> {
    const body: PublicAppendResultBodyV1 = {
      version: 1,
      storeId: copyBytes(this.storeId),
      descriptorHash: copyBytes(this.descriptorHash),
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
    return this.#serialize(() => this.#finalizeDue());
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
    const state = await this.#windowState(window);
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
            deliveryProfileHash: copyBytes(this.profileHash),
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
      storeId: copyBytes(this.storeId),
      descriptorHash: copyBytes(this.descriptorHash),
      deliveryProfileHash: copyBytes(this.profileHash),
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

    state.finalized = { chunks, checkpoint };
    await this.#persistence.saveWindow(state);
  }

  /* ---------------------------------------------------------------- *
   * Reads
   * ---------------------------------------------------------------- */

  async readCheckpoint(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
  ): Promise<PublicStoreCheckpointReadV1> {
    const requested = copyBytes(deliveryProfileHashBytes);
    requireProfileHash(requested);
    requireWindow(window);
    const status = (
      kind: PublicStoreCheckpointStatusKindV1,
    ): Promise<PublicStoreCheckpointReadV1> =>
      this.#checkpointStatus(requested, window, kind);

    // A profile this store never served has no chain at all, which is a
    // different answer from "that window of my chain is not final yet".
    if (!bytesEqual(requested, this.profileHash))
      return status("chain-unavailable");
    if (window < this.#chainStart) return status("out-of-range");

    const state = await this.#persistence.loadWindow(window);
    if (state?.finalized == null) return status("not-final");
    return {
      kind: "finalized",
      descriptor: copyDescriptor(this.descriptor),
      checkpoint: copyCheckpoint(state.finalized.checkpoint),
    };
  }

  async #checkpointStatus(
    deliveryProfileHashBytes: Uint8Array,
    window: bigint,
    status: PublicStoreCheckpointStatusKindV1,
  ): Promise<PublicStoreCheckpointReadV1> {
    const value = {
      version: 1 as const,
      storeId: copyBytes(this.storeId),
      deliveryProfileHash: deliveryProfileHashBytes,
      ingressWindow: window,
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
    const requested = copyBucket(bucket);
    requireProfileHash(requested.deliveryProfileHash);
    requireWindow(requested.ingressWindow);
    if (chunkIndex < 0n) fail("a chunk index must not be negative");
    const status = (
      kind: PublicChunkStatusKindV1,
    ): Promise<PublicChunkReadV1> =>
      this.#chunkStatus(requested, chunkIndex, kind);

    // Chunk reads have only two status values, so an unserved profile, an
    // unknown class and an index past the profile's count all answer with the
    // one out-of-range shape: none of them names a chunk this store can ever
    // hold, and the reader learns nothing extra from which of the three it was.
    if (!bytesEqual(requested.deliveryProfileHash, this.profileHash))
      return status("out-of-range");
    const sizeClass = this.#profile.sizeClasses.find(
      (candidate) => candidate.id === requested.sizeClass,
    );
    if (sizeClass === undefined) return status("out-of-range");
    if (chunkIndex >= BigInt(sizeClass.publicChunksPerWindow))
      return status("out-of-range");
    if (requested.ingressWindow < this.#chainStart)
      return status("out-of-range");

    const state = await this.#persistence.loadWindow(requested.ingressWindow);
    const chunk = state?.finalized?.chunks.get(sizeClass.id)?.[
      Number(chunkIndex)
    ];
    if (chunk === undefined) return status("not-final");
    return { kind: "finalized", chunk: copyChunk(chunk) };
  }

  async #chunkStatus(
    bucket: PublicBucketV1,
    chunkIndex: bigint,
    status: PublicChunkStatusKindV1,
  ): Promise<PublicChunkReadV1> {
    const value = { version: 1 as const, bucket, chunkIndex, status };
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
   * must not make it look like two.
   */
  async addWitness(record: StoreWitnessRecordV1): Promise<void> {
    const privateRecord = copyWitnessRecord(record);
    if (privateRecord.version !== 1)
      fail("unsupported store witness record version");
    if (privateRecord.ingressWindow < 0n)
      fail("a witness record's ingress window must not be negative");

    return this.#serialize(async () => {
      const existing = await this.#persistence.loadWitnessRecords(
        privateRecord.ingressWindow,
      );
      const encoded = hexOf(encodeStoreWitnessRecordV1(privateRecord));
      for (const held of existing)
        if (hexOf(encodeStoreWitnessRecordV1(held)) === encoded) return;
      if (existing.length >= MAX_WITNESS_RECORDS_PER_WINDOW) return;
      await this.#persistence.saveWitnessRecord(privateRecord);
    });
  }

  async witnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]> {
    return this.#persistence.loadWitnessRecords(window);
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
  #serialize<T>(work: () => Promise<T>): Promise<T> {
    const running = this.#tail.then(work, work);
    // The chain must survive a rejected unit of work, or one bad request would
    // wedge every later one.
    this.#tail = running.then(
      () => undefined,
      () => undefined,
    );
    return running;
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
    if (state.finalized !== null) return true;
    const dueAt =
      ingressWindowStartMs(window, this.#profile.deliveryWindowMs) +
      this.#profile.chunkFinalizationOffsetMs;
    return dueAt <= this.#clock.nowMs();
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
