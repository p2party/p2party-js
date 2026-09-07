/**
 * The browser-side client of one prototype store (design doc §4.4, §8).
 *
 * This is the verifying half of the carrier. The store is assumed hostile: it
 * may withhold an object it signed a receipt for, serve one window to this
 * client and another to somebody else, or answer with bytes that decode but
 * commit to nothing. Every claim it makes therefore arrives signed, and this
 * file checks each signature against the key pinned at `connect` before any
 * field of the value is read.
 *
 * Three properties this adapter is responsible for:
 *
 * - **Nothing room-derived leaves.** Every request names a delivery-profile
 *   hash, an ingress window, a size class, two ordinals, an ephemeral
 *   allocation key and opaque fixed-length bytes. There is no room, member,
 *   peer or invitation value in any path or body, which is what lets unrelated
 *   rooms share a bucket and cover for each other.
 * - **A scan never throws.** A store that is unreachable, malformed, or
 *   lying must degrade one event for one store, not abort the caller's whole
 *   window. Faults are recorded and the scan answers `unreachable`.
 * - **Blame is separated from absence.** `chain-fault`, `root-mismatch` and
 *   `custody-breach` mark the store **inert** — its objects are still returned
 *   so the caller can union every observed branch, but it is out of the
 *   availability set. An unreachable route, a gap in the observed chain, and a
 *   window below the chain start are none of those and mark nothing.
 *
 * Browser-safe by construction: it imports no `store/` module (those reach for
 * `node:fs` and `bun:sqlite`) and nothing Node-only. The route strings come
 * from `storeRoutes.ts`, which both halves share.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry, and nothing here is a v0.4 release artifact.
 */

import { sign, verify } from "../../cryptography/ed25519";
import { bytesEqual } from "../canonicalSchema";
import {
  allocationAppendSignedMessage,
  allocationTokenIssueResultSignedMessage,
  prototypeStoreCompatibilityHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
  sha256,
} from "../derivations";
import {
  ZERO32,
  appendSlotCoordinates,
  checkpointLeafEntries,
  ingressWindowStartMs,
  publicChunkHash,
  publicChunkSigningHash,
  publicStoreCheckpointHash,
  rfc9162MerkleTreeHash,
  structurallyValidCheckpoint,
  verifyStoreCheckpointChain,
} from "../publicWindow";
import {
  descriptorChainStart,
  descriptorSupportsProfile,
  publicCarrierContextId,
  storeId as computeStoreId,
  validateStoreDescriptor,
  validateStoreRoute,
} from "../storeDescriptor";
import {
  PROTOTYPE_STORE_PROTOCOL,
  carrierObjectWireBytes,
  profileGeometry,
} from "./profile";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "./storeRoutes";
import {
  decodeAllocationTokenIssueResultV1,
  decodePrototypeStoreDescriptorDocumentV1,
  decodePublicAllocationResultV1,
  decodePublicAppendResultV1,
  decodePublicChunkReadV1,
  decodePublicStoreCheckpointReadV1,
  decodeStoreWitnessRecordsV1,
  encodeAllocationTokenIssueRequestV1,
  encodePublicAllocationRequestV1,
  encodePublicAppendRequestV1,
  encodeStoreWitnessRecordV1,
} from "./storeWire";

import type { LibCrypto } from "../../cryptography/libcrypto";
import type {
  ObservedStoreCheckpoint,
  PublicChunkV1,
  PublicProfileGeometry,
  PublicStoreCheckpointV1,
} from "../publicWindow";
import type { StoreDescriptorV1 } from "../storeDescriptor";
import type { DeliveryProfileV1 } from "./profile";
import type {
  PrototypeStoreDescriptorDocumentV1,
  PublicAllocationLeaseV1,
  PublicAppendAdmissionV1,
  PublicAppendRequestV1,
  PublicAppendResultV1,
  StoreWitnessRecordV1,
} from "./storeWire";

export interface StoreClientOptions {
  readonly origin: string;
  readonly profile: DeliveryProfileV1;
  readonly profileHash: Uint8Array;
  readonly module: LibCrypto;
  /** Injected so a test, a worker or a proxy can supply its own transport. */
  readonly fetch?: typeof fetch;
  readonly nowMs: () => bigint;
}

export type StoreFaultKind =
  | "descriptor-invalid"
  | "signature-invalid"
  | "chain-fault"
  | "root-mismatch"
  | "custody-breach"
  | "checkpoint-split-view-hint";

export interface StoreFaultRecord {
  readonly storeIdHex: string;
  readonly kind: StoreFaultKind;
  readonly window: bigint | null;
  readonly detail: string;
}

export interface WindowScan {
  readonly window: bigint;
  readonly status: "finalized" | "not-final" | "out-of-range" | "unreachable";
  readonly objects: readonly Uint8Array[];
  readonly checkpointHash: Uint8Array | null;
}

/**
 * What this client appended and the store signed for, kept until the window it
 * names is scanned. It is the whole input to the custody check: without the
 * lease's ordinal there is no slot to look in, and without `objectHash` there
 * is nothing to compare the slot's contents against.
 */
export interface AppendReceipt {
  readonly window: bigint;
  readonly sizeClass: number;
  readonly lease: PublicAllocationLeaseV1;
  readonly objectOrdinal: number;
  readonly objectHash: Uint8Array;
  readonly result: PublicAppendResultV1;
}

export class StoreClientError extends Error {
  override readonly name = "StoreClientError";

  constructor(message: string) {
    super(`storeClient: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new StoreClientError(message);
};

/**
 * How many faults one client remembers.
 *
 * The earliest faults are the evidence — every one that matters is acted on
 * (`inert`) the instant it is recorded — so the cap keeps the first ones and
 * drops later repetitions rather than the other way round. A browser tab that
 * scans a store for hours must not accumulate one record per failed fetch.
 */
const MAX_RECORDED_FAULTS = 512;

/**
 * How many checkpoint observations feed the chain verifier.
 *
 * `verifyStoreCheckpointChain` re-verifies every observation on every call, so
 * this bounds both memory and per-scan cost. Dropping the oldest cannot hide a
 * fault: a conflict or a breach is detected by the scan that first observes it
 * and `inert` is permanent from that moment.
 */
const MAX_OBSERVED_CHECKPOINTS = 256;

/** Receipts are consumed by the scan of their window; this bounds the rest. */
const MAX_PENDING_RECEIPTS = 1_024;

const textDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The call signature of `fetch`, without the properties hung off the global.
 *
 * The default is a wrapper rather than the global itself because an unbound
 * `fetch` invoked as a method throws "Illegal invocation" in several engines;
 * this type is what lets the wrapper stand in for one without a cast.
 */
type StoreTransport = (...args: Parameters<typeof fetch>) => Promise<Response>;

const transportOf = (options: StoreClientOptions): StoreTransport =>
  options.fetch ?? ((...args) => globalThis.fetch(...args));

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const copyBytes = (value: Uint8Array): Uint8Array => Uint8Array.from(value);

const copyLease = (
  lease: PublicAllocationLeaseV1,
): PublicAllocationLeaseV1 => ({
  version: lease.version,
  storeId: copyBytes(lease.storeId),
  deliveryProfileHash: copyBytes(lease.deliveryProfileHash),
  ingressWindow: lease.ingressWindow,
  requestHash: copyBytes(lease.requestHash),
  allocationOrdinal: lease.allocationOrdinal,
  allocationEd25519PublicKey: copyBytes(lease.allocationEd25519PublicKey),
  storeSignature: copyBytes(lease.storeSignature),
});

const copyWitnessRecord = (
  record: StoreWitnessRecordV1,
): StoreWitnessRecordV1 => ({
  version: record.version,
  witnessedStoreId: copyBytes(record.witnessedStoreId),
  deliveryProfileHash: copyBytes(record.deliveryProfileHash),
  ingressWindow: record.ingressWindow,
  checkpointHash: copyBytes(record.checkpointHash),
});

/**
 * Sign one admission over the lease this store issued.
 *
 * The transcript binds the store, profile, window, size class, ordinal and the
 * exact object bytes at once, so an admission cannot be replayed into another
 * slot of the same allocation or against different bytes. The secret key is
 * the caller's ephemeral allocation key and is neither copied nor retained
 * here.
 */
export const buildAppendAdmission = async (
  lease: PublicAllocationLeaseV1,
  allocationSecretKey: Uint8Array,
  sizeClass: number,
  objectOrdinal: number,
  exactFixedObject: Uint8Array,
  module: LibCrypto,
): Promise<PublicAppendAdmissionV1> => {
  // Own every caller-controlled byte before the first await: an admission that
  // was signed over one object and shipped with another is unusable evidence.
  const privateLease = copyLease(lease);
  const privateObject = copyBytes(exactFixedObject);
  const { storeSignature: _signature, ...leaseBody } = privateLease;

  return {
    version: 1,
    lease: privateLease,
    objectOrdinalWithinAllocation: objectOrdinal,
    allocationSignature: await sign(
      await allocationAppendSignedMessage(
        leaseBody,
        sizeClass,
        objectOrdinal,
        privateObject,
      ),
      allocationSecretKey,
      module,
    ),
  };
};

export class PrototypeStoreClient {
  /**
   * Public identity, as the design's adapter shape requires it. These are
   * copies: every security decision this file makes uses the private key and
   * hashes below, so a caller that mutates one of them changes what it reads,
   * never what is verified.
   */
  readonly storeId: Uint8Array;
  readonly storeIdHex: string;
  readonly descriptor: StoreDescriptorV1;
  readonly carrierContextId: Uint8Array;
  readonly origin: string;

  readonly #module: LibCrypto;
  readonly #fetch: StoreTransport;
  readonly #profile: DeliveryProfileV1;
  readonly #geometry: PublicProfileGeometry;
  readonly #profileHash: Uint8Array;
  readonly #profileHex: string;
  readonly #storeId: Uint8Array;
  readonly #storeKey: Uint8Array;
  readonly #chainStart: bigint;
  readonly #objectBytesByClass: ReadonlyMap<number, number>;

  #inert = false;
  readonly #faults: StoreFaultRecord[] = [];
  /** Sorted by ingress window; the input to `verifyStoreCheckpointChain`. */
  readonly #observed: ObservedStoreCheckpoint[] = [];
  readonly #checkpointHashes = new Map<string, Uint8Array>();
  #receipts: AppendReceipt[] = [];

  private constructor(
    options: StoreClientOptions,
    pinned: {
      readonly storeId: Uint8Array;
      readonly descriptor: StoreDescriptorV1;
      readonly carrierContextId: Uint8Array;
      readonly chainStart: bigint;
      readonly profileHash: Uint8Array;
      readonly objectBytesByClass: ReadonlyMap<number, number>;
    },
  ) {
    this.storeId = copyBytes(pinned.storeId);
    this.storeIdHex = hexOf(pinned.storeId);
    this.descriptor = pinned.descriptor;
    this.carrierContextId = copyBytes(pinned.carrierContextId);
    this.origin = options.origin;

    this.#module = options.module;
    this.#fetch = transportOf(options);
    this.#profile = options.profile;
    this.#geometry = profileGeometry(options.profile);
    this.#profileHash = pinned.profileHash;
    this.#profileHex = hexOf(pinned.profileHash);
    this.#storeId = pinned.storeId;
    this.#storeKey = copyBytes(pinned.descriptor.storeIdentityEd25519Key);
    this.#chainStart = pinned.chainStart;
    this.#objectBytesByClass = pinned.objectBytesByClass;
  }

  /**
   * Fetch the descriptor, validate it, and pin the identity every later answer
   * is checked against.
   *
   * This is the one place that throws: a client that could not establish whom
   * it is talking to has no store, and returning a half-usable object would
   * push that decision to a caller with less context. Everything after this
   * point degrades instead.
   *
   * `nowMs` is read here and only here. The descriptor and route leases are
   * about now, but every later check is anchored to the instant the window it
   * concerns was finalized — historical evidence must not change meaning
   * because the wall clock moved.
   */
  static async connect(
    options: StoreClientOptions,
  ): Promise<PrototypeStoreClient> {
    if (options.profileHash.length !== 32)
      fail("the delivery profile hash must be exactly 32 bytes");
    const profileHash = copyBytes(options.profileHash);
    const transport = transportOf(options);

    let response: Response;
    try {
      response = await transport(
        `${options.origin}${PROTOTYPE_STORE_ROUTES.descriptor}`,
      );
    } catch (error) {
      return fail(
        `the store descriptor could not be fetched: ${
          error instanceof Error ? error.name : "unknown error"
        }`,
      );
    }
    if (response.status !== 200)
      fail(`the store descriptor route answered ${String(response.status)}`);
    if (response.headers.get("x-p2party-store") !== PROTOTYPE_STORE_PROTOCOL)
      fail("the descriptor answer is not from a prototype-v0 store");

    let served: PrototypeStoreDescriptorDocumentV1;
    try {
      served = decodePrototypeStoreDescriptorDocumentV1(
        new Uint8Array(await response.arrayBuffer()),
      );
    } catch (error) {
      return fail(
        `the store descriptor document is not canonical: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
      );
    }

    const descriptor = served.descriptor;
    if (descriptor.version !== 1) fail("unsupported store descriptor version");

    const nowMs = options.nowMs();
    const validity = await validateStoreDescriptor(
      descriptor,
      nowMs,
      options.module,
    );
    if (!validity.valid)
      fail(`the store descriptor is invalid: ${validity.reason}`);

    // Prototype compatibility is deliberately its own hash: a store that
    // advertises release compatibility bytes is refused rather than
    // half-spoken to.
    if (
      !bytesEqual(
        descriptor.compatibilityHash,
        await prototypeStoreCompatibilityHash(profileHash),
      )
    )
      fail("the store is not compatible with this prototype delivery profile");
    if (!descriptorSupportsProfile(descriptor, profileHash))
      fail("the store does not serve this delivery profile");

    // Exactly one anchor, asserted rather than assumed: the chain start is
    // what every later window is judged against, and `descriptorChainStart`
    // would silently take the first of two. Descriptor validity already makes
    // a second entry impossible; this is the check that says so out loud.
    if (
      descriptor.checkpointChainStarts.filter((start) =>
        bytesEqual(start.deliveryProfileHash, profileHash),
      ).length !== 1
    )
      fail(
        "the store declares no single chain start for this delivery profile",
      );
    const chainStart = descriptorChainStart(descriptor, profileHash);
    if (chainStart === null)
      fail("the store declares no chain start for this delivery profile");

    // The route is checked separately from the descriptor because it binds
    // values the descriptor never sees — the locator this client dialled, the
    // family, and its own lease. A store that signed no route for this origin
    // has not authorized being reached here.
    const route = served.routes.find((candidate) => {
      try {
        return textDecoder.decode(candidate.opaqueLocator) === options.origin;
      } catch {
        return false;
      }
    });
    if (route === undefined)
      fail("the store signed no route whose locator is this origin");
    const routeValidity = await validateStoreRoute(
      route,
      descriptor,
      nowMs,
      options.module,
    );
    if (!routeValidity.valid)
      fail(`the store route is invalid: ${routeValidity.reason}`);

    const storeIdBytes = await computeStoreId(
      descriptor.storeIdentityEd25519Key,
    );

    // One envelope encoding per class, at connect: the wire length is fixed by
    // the profile, and recomputing it per verified object would burn it on the
    // read path.
    const objectBytesByClass = new Map<number, number>(
      options.profile.sizeClasses.map((sizeClass) => [
        sizeClass.id,
        carrierObjectWireBytes(options.profile, sizeClass.id, profileHash),
      ]),
    );

    return new PrototypeStoreClient(options, {
      storeId: storeIdBytes,
      descriptor,
      carrierContextId: await publicCarrierContextId(storeIdBytes, profileHash),
      chainStart,
      profileHash,
      objectBytesByClass,
    });
  }

  /** True once this store has been caught in a fault no absence explains. */
  get inert(): boolean {
    return this.#inert;
  }

  get faults(): readonly StoreFaultRecord[] {
    return this.#faults.map((fault) => ({ ...fault }));
  }

  /* ---------------------------------------------------------------- *
   * Ingress
   * ---------------------------------------------------------------- */

  /**
   * Ask for an allocation token for `targetWindow`.
   *
   * Open mode has no quota to consume, so the answer carries no authority; it
   * is requested and verified anyway because the traffic shape is part of the
   * profile — a client that skipped it would be distinguishable from one that
   * did not.
   */
  async issueToken(targetWindow: bigint): Promise<boolean> {
    const body = encodeAllocationTokenIssueRequestV1({
      version: 1,
      storeId: copyBytes(this.#storeId),
      deliveryProfileHash: copyBytes(this.#profileHash),
      ingressWindow: targetWindow,
      privacyPassTokenRequest: new Uint8Array(32),
    });
    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.token,
      PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
      body,
      targetWindow,
    );
    if (bytes === null) return false;

    const result = this.#decode(
      decodeAllocationTokenIssueResultV1,
      bytes,
      targetWindow,
      "allocation token result",
    );
    if (result === null) return false;
    if (result.body.version !== 1)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "unsupported allocation token result version",
        false,
      );

    const verified = await verify(
      await allocationTokenIssueResultSignedMessage(result.body),
      result.storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the allocation token result signature does not verify",
        false,
      );
    return result.body.kind === "issued";
  }

  /**
   * Redeem a token for a lease over `targetWindow`.
   *
   * Only the public half of `allocationKey` is sent; the secret stays with the
   * caller, which is what makes the lease usable by nobody else.
   */
  async allocate(
    targetWindow: bigint,
    allocationKey: { publicKey: Uint8Array; secretKey: Uint8Array },
  ): Promise<PublicAllocationLeaseV1 | null> {
    const allocationEd25519PublicKey = copyBytes(allocationKey.publicKey);
    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.allocation,
      PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
      encodePublicAllocationRequestV1({
        version: 1,
        deliveryProfileHash: copyBytes(this.#profileHash),
        ingressWindow: targetWindow,
        allocationEd25519PublicKey,
        privacyPassToken: new Uint8Array(32),
      }),
      targetWindow,
    );
    if (bytes === null) return null;

    const result = this.#decode(
      decodePublicAllocationResultV1,
      bytes,
      targetWindow,
      "allocation result",
    );
    if (result === null) return null;

    if (result.kind === "status") {
      if (result.value.version !== 1)
        return this.#reject(
          "signature-invalid",
          targetWindow,
          "unsupported allocation status version",
          null,
        );
      // A refusal is verified for the same reason a lease is: an unsigned one
      // could be forged by the network to push this client onto one store.
      const verified = await verify(
        await publicAllocationStatusSignedMessage(result.value),
        result.storeSignature,
        this.#storeKey,
        this.#module,
      );
      if (!verified)
        return this.#reject(
          "signature-invalid",
          targetWindow,
          "the allocation status signature does not verify",
          null,
        );
      return null;
    }

    const lease = result.lease;
    if (lease.version !== 1)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "unsupported allocation lease version",
        null,
      );
    const { storeSignature, ...leaseBody } = lease;
    const verified = await verify(
      await publicAllocationLeaseSignedMessage(leaseBody),
      storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the allocation lease signature does not verify",
        null,
      );

    // The signature only proves this store wrote the lease; these checks prove
    // it wrote the lease this client asked for. A lease for another window or
    // another key would be admitted by nothing later.
    if (
      !bytesEqual(lease.storeId, this.#storeId) ||
      !bytesEqual(lease.deliveryProfileHash, this.#profileHash) ||
      lease.ingressWindow !== targetWindow ||
      !bytesEqual(lease.allocationEd25519PublicKey, allocationEd25519PublicKey)
    )
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the lease does not bind the allocation this client requested",
        null,
      );

    // The ordinal is the one input to the slot mapping the *store* picks, and
    // the wire carries it as a plain u32. Outside the cohort capacity it names
    // no slot in any window, so a signature over it proves only that the store
    // meant it: `appendSlotCoordinates` would throw on the first use, which is
    // a store choosing when this client crashes. It is refused here instead.
    if (!this.#ordinalWithinCohort(lease.allocationOrdinal))
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the lease names an allocation ordinal outside the cohort capacity",
        null,
      );
    return lease;
  }

  /** `0 <= allocationOrdinal < cohortAllocationsPerWindow`. */
  #ordinalWithinCohort(allocationOrdinal: number): boolean {
    return (
      Number.isSafeInteger(allocationOrdinal) &&
      allocationOrdinal >= 0 &&
      allocationOrdinal < this.#profile.cohortAllocationsPerWindow
    );
  }

  /** `0 <= objectOrdinal < roomSlotsPerClient × appendSchedule.length`. */
  #ordinalWithinAllocation(sizeClass: number, objectOrdinal: number): boolean {
    const found = this.#profile.sizeClasses.find(
      (candidate) => candidate.id === sizeClass,
    );
    if (found === undefined) return false;
    return (
      Number.isSafeInteger(objectOrdinal) &&
      objectOrdinal >= 0 &&
      objectOrdinal <
        this.#profile.roomSlotsPerClient * found.appendSchedule.length
    );
  }

  /**
   * Publish one fixed-size object into `(window, sizeClass)`.
   *
   * `admission === null` is a deliberate unallocated cover append: the store
   * accepts it, answers the one fixed status, and discards it.
   */
  async append(
    window: bigint,
    sizeClass: number,
    exactFixedObject: Uint8Array,
    admission: PublicAppendAdmissionV1 | null,
  ): Promise<PublicAppendResultV1 | null> {
    const request: PublicAppendRequestV1 = {
      version: 1,
      bucket: {
        deliveryProfileHash: copyBytes(this.#profileHash),
        ingressWindow: window,
        sizeClass,
      },
      exactFixedObject: copyBytes(exactFixedObject),
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

    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.append,
      PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
      encodePublicAppendRequestV1(request),
      window,
    );
    if (bytes === null) return null;

    const result = this.#decode(
      decodePublicAppendResultV1,
      bytes,
      window,
      "append result",
    );
    if (result === null) return null;
    if (result.version !== 1)
      return this.#reject(
        "signature-invalid",
        window,
        "unsupported append result version",
        null,
      );

    const { storeSignature, ...body } = result;
    const verified = await verify(
      await publicAppendResultSignedMessage(body),
      storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        window,
        "the append result signature does not verify",
        null,
      );

    // The echoed request hash is what makes this receipt evidence about *this*
    // append rather than some other one the store also answered.
    if (
      !bytesEqual(body.storeId, this.#storeId) ||
      !bytesEqual(body.bucket.deliveryProfileHash, this.#profileHash) ||
      body.bucket.ingressWindow !== window ||
      body.bucket.sizeClass !== sizeClass ||
      !bytesEqual(body.requestHash, await publicAppendRequestHash(request))
    )
      return this.#reject(
        "signature-invalid",
        window,
        "the append result does not answer the request this client sent",
        null,
      );
    return result;
  }

  /**
   * Remember what the store promised, until the window it names is scanned.
   *
   * Validated eagerly, and each coordinate against the half it comes from: the
   * object ordinal is the caller's, so an out-of-range one is a caller bug and
   * says so; the allocation ordinal is the store's, and `allocate` has already
   * refused it if it named no slot — the check here is the belt to that brace,
   * for a lease that reached this client by some other path. Either way the
   * bounds are decided before `appendSlotCoordinates`, which throws, and a
   * throw inside a scan would turn a bad coordinate into a fault report
   * against a store that did nothing wrong.
   */
  recordReceipt(receipt: AppendReceipt): void {
    if (receipt.lease.ingressWindow !== receipt.window)
      fail("the receipt's lease names a different ingress window");
    if (!bytesEqual(receipt.lease.storeId, this.#storeId))
      fail("the receipt's lease names a different store");
    if (!bytesEqual(receipt.lease.deliveryProfileHash, this.#profileHash))
      fail("the receipt's lease names a different delivery profile");
    if (receipt.objectHash.length !== 32)
      fail("the receipt's object hash must be exactly 32 bytes");
    if (!this.#ordinalWithinCohort(receipt.lease.allocationOrdinal))
      fail("the receipt's lease names an ordinal outside the cohort capacity");
    if (
      !this.#ordinalWithinAllocation(receipt.sizeClass, receipt.objectOrdinal)
    )
      fail("the receipt's object ordinal is outside this allocation's slots");

    if (this.#receipts.length >= MAX_PENDING_RECEIPTS) this.#receipts.shift();
    this.#receipts.push({
      window: receipt.window,
      sizeClass: receipt.sizeClass,
      lease: copyLease(receipt.lease),
      objectOrdinal: receipt.objectOrdinal,
      objectHash: copyBytes(receipt.objectHash),
      result: { ...receipt.result },
    });
  }

  /* ---------------------------------------------------------------- *
   * The fixed scan
   * ---------------------------------------------------------------- */

  /**
   * Read one window whole and decide what it proves.
   *
   * The checkpoint and every chunk are issued together and only then awaited:
   * the profile's fixed geometry is the point of the scan, and one round trip
   * per chunk would both leak the reader's pace and miss the window.
   */
  async scanWindow(window: bigint): Promise<WindowScan> {
    const empty = (status: WindowScan["status"]): WindowScan => ({
      window,
      status,
      objects: [],
      checkpointHash: null,
    });

    // Below the chain start there is nothing this store ever promised, so it
    // is out of range rather than missing.
    if (window < this.#chainStart) return empty("out-of-range");

    const classes = [...this.#profile.sizeClasses].sort(
      (left, right) => left.id - right.id,
    );
    const checkpointPromise = this.#get(
      `${PROTOTYPE_STORE_ROUTES.checkpoint}/${this.#profileHex}/${String(window)}`,
      window,
    );
    const chunkPromises = classes.map((sizeClass) =>
      Array.from({ length: sizeClass.publicChunksPerWindow }, (_, index) =>
        this.#get(
          `${PROTOTYPE_STORE_ROUTES.chunk}/${this.#profileHex}/${String(window)}/${String(sizeClass.id)}/${String(index)}`,
          window,
        ),
      ),
    );
    const [checkpointBytes, chunkBytes] = await Promise.all([
      checkpointPromise,
      Promise.all(chunkPromises.map((promises) => Promise.all(promises))),
    ]);

    const checkpointStatus = await this.#readCheckpoint(
      window,
      checkpointBytes,
    );
    if (checkpointStatus.kind !== "finalized")
      return empty(checkpointStatus.status);
    const { checkpoint, descriptor } = checkpointStatus;

    const chunks = await this.#readChunks(window, classes, chunkBytes);
    if (chunks.kind !== "finalized") return empty(chunks.status);

    // The chunks are only *this store's* claim until the checkpoint commits
    // them: recompute the root over the complete profile-fixed sequence and
    // require the committed value.
    const recomputedRoot = await rfc9162MerkleTreeHash(
      await checkpointLeafEntries(this.#geometry, chunks.hashesByClass),
    );
    if (!bytesEqual(recomputedRoot, checkpoint.finalizedChunkRoot))
      return this.#breach(
        "root-mismatch",
        window,
        "the served chunks do not recompute the committed chunk root",
        empty("unreachable"),
      );

    const checkpointHash = await publicStoreCheckpointHash(checkpoint);
    this.#rememberCheckpointHash(window, checkpointHash);

    await this.#verifyChain(window, checkpoint, descriptor);
    await this.#verifyCustody(window, chunks.chunksByClass);

    // Objects in `(sizeClass, chunkIndex, objectIndex)` order: the profile's
    // own order, which is what makes an index into this array meaningful to a
    // caller that never saw the chunks.
    const objects: Uint8Array[] = [];
    for (const sizeClass of classes)
      for (const chunk of chunks.chunksByClass.get(sizeClass.id) ?? [])
        for (const object of chunk.fixedObjects)
          objects.push(copyBytes(object));

    return {
      window,
      status: "finalized",
      objects,
      checkpointHash: copyBytes(checkpointHash),
    };
  }

  /** The verified checkpoint hash for a window this client scanned. */
  checkpointHashFor(window: bigint): Uint8Array | null {
    const held = this.#checkpointHashes.get(String(window));
    return held === undefined ? null : copyBytes(held);
  }

  /**
   * Keep the *first* verified checkpoint hash for a window.
   *
   * This is the value the client witnessed to other stores, so a later branch
   * of an equivocating store must not quietly replace what was gossiped; the
   * branch is not lost either — `#observe` keeps both, which is what turns the
   * pair into a conflict. Bounded like the observation run, and for the same
   * reason: a long-lived tab must not accumulate one entry per window forever.
   */
  #rememberCheckpointHash(window: bigint, checkpointHash: Uint8Array): void {
    const key = String(window);
    if (this.#checkpointHashes.has(key)) return;
    if (this.#checkpointHashes.size >= MAX_OBSERVED_CHECKPOINTS) {
      const oldest = this.#checkpointHashes.keys().next();
      if (!oldest.done) this.#checkpointHashes.delete(oldest.value);
    }
    this.#checkpointHashes.set(key, checkpointHash);
  }

  /* ---------------------------------------------------------------- *
   * Witnessing (design doc §8)
   * ---------------------------------------------------------------- */

  /**
   * Offer this store one observation of another store's checkpoint.
   *
   * Certificate-Transparency-style gossip with the other store as the carrier
   * and no witness network: one fixed POST per other store per window, so the
   * trace stays the profile's fixed shape.
   */
  async postWitness(record: StoreWitnessRecordV1): Promise<boolean> {
    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.witness,
      PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
      encodeStoreWitnessRecordV1(copyWitnessRecord(record)),
      record.ingressWindow,
    );
    return bytes !== null;
  }

  /**
   * Read the observations this store holds for `window`.
   *
   * Witness records are unauthenticated peer input and are returned as data,
   * never as a claim. The one thing this client can decide locally is whether
   * a record about *itself* contradicts the checkpoint it was shown: that is a
   * split-view hint, not a proof — the specification's conflict proof needs
   * two checkpoints signed by the store — so it is logged and does not make
   * the store inert. Comparing records about *other* stores is the carrier
   * runtime's job, since only it holds both stores' verified hashes.
   */
  async readWitnesses(
    window: bigint,
  ): Promise<readonly StoreWitnessRecordV1[]> {
    const bytes = await this.#get(
      `${PROTOTYPE_STORE_ROUTES.witness}/${this.#profileHex}/${String(window)}`,
      window,
    );
    if (bytes === null) return [];
    const records = this.#decode(
      decodeStoreWitnessRecordsV1,
      bytes,
      window,
      "witness records",
    );
    if (records === null) return [];

    const held = this.#checkpointHashes.get(String(window));
    const output: StoreWitnessRecordV1[] = [];
    for (const record of records) {
      if (record.version !== 1) continue;
      if (!bytesEqual(record.deliveryProfileHash, this.#profileHash)) continue;
      if (record.ingressWindow !== window) continue;
      if (
        held !== undefined &&
        bytesEqual(record.witnessedStoreId, this.#storeId) &&
        !bytesEqual(record.checkpointHash, held)
      )
        this.#record(
          "checkpoint-split-view-hint",
          window,
          "a witness record names a different checkpoint than this store showed",
        );
      output.push(copyWitnessRecord(record));
    }
    return output;
  }

  /* ---------------------------------------------------------------- *
   * Internals
   * ---------------------------------------------------------------- */

  /**
   * One GET or POST, reduced to bytes or `null`.
   *
   * A non-200, a missing protocol header and a rejected fetch are one outcome
   * here: this answer is not usable. They are recorded as `signature-invalid`
   * because that is the fault class the design gives an unverifiable answer,
   * and none of them makes the store inert — being unreachable is not evidence
   * of dishonesty.
   */
  async #request(
    path: string,
    window: bigint | null,
    init?: RequestInit,
  ): Promise<Uint8Array | null> {
    let response: Response;
    try {
      response = await this.#fetch(`${this.origin}${path}`, init);
    } catch (error) {
      return this.#reject(
        "signature-invalid",
        window,
        `${path}: the request failed (${
          error instanceof Error ? error.name : "unknown error"
        })`,
        null,
      );
    }
    if (response.status !== 200)
      return this.#reject(
        "signature-invalid",
        window,
        `${path}: answered ${String(response.status)}`,
        null,
      );
    // Every answer of this protocol is attributable to it; one that is not did
    // not come from a store, whatever is in its body.
    if (response.headers.get("x-p2party-store") !== PROTOTYPE_STORE_PROTOCOL)
      return this.#reject(
        "signature-invalid",
        window,
        `${path}: the answer is not from a prototype-v0 store`,
        null,
      );
    try {
      return new Uint8Array(await response.arrayBuffer());
    } catch {
      return this.#reject(
        "signature-invalid",
        window,
        `${path}: the answer body could not be read`,
        null,
      );
    }
  }

  async #get(path: string, window: bigint | null): Promise<Uint8Array | null> {
    return this.#request(path, window);
  }

  async #post(
    path: string,
    mediaType: string,
    body: Uint8Array,
    window: bigint | null,
  ): Promise<Uint8Array | null> {
    // `lib.dom`'s `BodyInit` is narrower than the codecs' `Uint8Array`, and a
    // copy is owed anyway: the request must not be able to change under the
    // transport after the bytes were signed over.
    const buffer = new ArrayBuffer(body.byteLength);
    new Uint8Array(buffer).set(body);
    return this.#request(path, window, {
      method: "POST",
      headers: { "content-type": mediaType },
      body: buffer,
    });
  }

  /**
   * Decode one canonical answer.
   *
   * `decodeCanonicalStrict` re-encodes, so a value that decodes here is the
   * unique encoding of itself — which is what makes a signature over these
   * bytes mean anything.
   */
  #decode<T>(
    decoder: (bytes: Uint8Array) => T,
    bytes: Uint8Array,
    window: bigint | null,
    what: string,
  ): T | null {
    try {
      return decoder(bytes);
    } catch (error) {
      return this.#reject(
        "signature-invalid",
        window,
        `the ${what} is not canonical: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
        null,
      );
    }
  }

  #record(kind: StoreFaultKind, window: bigint | null, detail: string): void {
    if (this.#faults.length >= MAX_RECORDED_FAULTS) return;
    this.#faults.push({
      storeIdHex: this.storeIdHex,
      kind,
      window,
      detail,
    });
  }

  /** Record a fault and answer with the caller's degraded value. */
  #reject<T>(
    kind: StoreFaultKind,
    window: bigint | null,
    detail: string,
    value: T,
  ): T {
    this.#record(kind, window, detail);
    return value;
  }

  /** Record a fault this store cannot blame on absence, and go inert. */
  #breach<T>(
    kind: StoreFaultKind,
    window: bigint,
    detail: string,
    value: T,
  ): T {
    this.#inert = true;
    return this.#reject(kind, window, detail, value);
  }

  /**
   * Verify the checkpoint answer for `window`.
   *
   * The descriptor served beside a checkpoint is what makes the evidence
   * portable, so it — not the pinned copy — is what structural validity is
   * decided against. It must still be the same store identity: accepting a
   * checkpoint under another key would let a store swap identities mid-scan
   * and keep its reputation.
   */
  async #readCheckpoint(
    window: bigint,
    bytes: Uint8Array | null,
  ): Promise<
    | {
        readonly kind: "finalized";
        readonly checkpoint: PublicStoreCheckpointV1;
        readonly descriptor: StoreDescriptorV1;
      }
    | { readonly kind: "status"; readonly status: WindowScan["status"] }
  > {
    const unusable = { kind: "status", status: "unreachable" } as const;
    if (bytes === null) return unusable;

    const read = this.#decode(
      decodePublicStoreCheckpointReadV1,
      bytes,
      window,
      "checkpoint read",
    );
    if (read === null) return unusable;

    if (read.kind === "status") {
      const value = read.value;
      // The version is the only field read before the signature: it is the
      // "is this a shape I can hash at all" question, and the transcript is
      // the canonical encoding of exactly this type. Every other field is
      // read after the signature over the whole body verifies.
      if (value.version !== 1)
        return this.#reject(
          "signature-invalid",
          window,
          "unsupported checkpoint status version",
          unusable,
        );
      const verified = await verify(
        await publicCheckpointStatusSigningHash(value),
        read.storeSignature,
        this.#storeKey,
        this.#module,
      );
      if (!verified)
        return this.#reject(
          "signature-invalid",
          window,
          "the checkpoint status signature does not verify",
          unusable,
        );
      if (
        !bytesEqual(value.storeId, this.#storeId) ||
        !bytesEqual(value.deliveryProfileHash, this.#profileHash) ||
        value.ingressWindow !== window
      )
        return this.#reject(
          "signature-invalid",
          window,
          "the checkpoint status does not name this store, profile and window",
          unusable,
        );
      if (value.status === "not-final")
        return { kind: "status", status: "not-final" };
      if (value.status === "out-of-range")
        return { kind: "status", status: "out-of-range" };
      // `chain-unavailable` contradicts the descriptor this client pinned,
      // which named this profile and a chain start for it.
      return this.#reject(
        "signature-invalid",
        window,
        "the store denies a profile chain its own descriptor declares",
        unusable,
      );
    }

    const { descriptor, checkpoint } = read;
    // Which key may sign at all is the one question that has to precede
    // verification: a signature checked under a key the same answer carried
    // proves nothing about the store this client pinned.
    if (!bytesEqual(descriptor.storeIdentityEd25519Key, this.#storeKey))
      return this.#reject(
        "descriptor-invalid",
        window,
        "the checkpoint was served under a different store identity",
        unusable,
      );

    // This is where the checkpoint signature is checked, so nothing below
    // reads a field of an unverified body. The descriptor must have been
    // valid when this window was finalized, not now: historical evidence must
    // not depend on today's clock.
    const validity = await structurallyValidCheckpoint(
      descriptor,
      checkpoint,
      this.#geometry,
      this.#finalizationInstantMs(window),
      this.#module,
    );
    if (!validity.valid)
      return this.#reject(
        "signature-invalid",
        window,
        `the checkpoint is not structurally valid: ${validity.reason}`,
        unusable,
      );

    if (checkpoint.version !== 1)
      return this.#reject(
        "signature-invalid",
        window,
        "unsupported checkpoint version",
        unusable,
      );
    if (
      checkpoint.ingressWindow !== window ||
      !bytesEqual(checkpoint.deliveryProfileHash, this.#profileHash)
    )
      return this.#reject(
        "signature-invalid",
        window,
        "the checkpoint names another window or delivery profile",
        unusable,
      );
    // `structurallyValidCheckpoint` judges the chain start against the
    // descriptor served beside the checkpoint, which is what keeps the
    // evidence portable. This client also pinned one, and a checkpoint
    // anchored elsewhere under the same key is a store restarting its chain —
    // which, unobserved beside a second window, nothing downstream would see.
    if (checkpoint.chainStartIngressWindow !== this.#chainStart)
      return this.#reject(
        "descriptor-invalid",
        window,
        "the checkpoint is anchored to a chain start this store did not pin",
        unusable,
      );
    return { kind: "finalized", checkpoint, descriptor };
  }

  /**
   * Verify every chunk of every class for `window`.
   *
   * A chunk is only usable once it is this store's signature over these exact
   * coordinates, this exact object count, this class's exact object length,
   * and the hash of the chunk before it. Everything a store could otherwise
   * do — relocate an object between classes or windows, shorten a chunk,
   * reorder the sequence — is one of those checks.
   *
   * The signature is checked first and the rest after, in both branches. The
   * conjunction would be fail-closed either way, but a reader should not have
   * to prove that: nothing here reads a field of a body whose signature has
   * not verified.
   */
  async #readChunks(
    window: bigint,
    classes: readonly {
      readonly id: number;
      readonly publicChunksPerWindow: number;
    }[],
    chunkBytes: readonly (readonly (Uint8Array | null)[])[],
  ): Promise<
    | {
        readonly kind: "finalized";
        readonly chunksByClass: ReadonlyMap<number, readonly PublicChunkV1[]>;
        readonly hashesByClass: ReadonlyMap<number, readonly Uint8Array[]>;
      }
    | { readonly kind: "status"; readonly status: WindowScan["status"] }
  > {
    const unusable = { kind: "status", status: "unreachable" } as const;
    const chunksByClass = new Map<number, PublicChunkV1[]>();
    const hashesByClass = new Map<number, Uint8Array[]>();

    for (let classIndex = 0; classIndex < classes.length; classIndex++) {
      const sizeClass = classes[classIndex];
      const objectBytes = this.#objectBytesByClass.get(sizeClass.id);
      if (objectBytes === undefined)
        return this.#reject(
          "signature-invalid",
          window,
          `no size class with id ${String(sizeClass.id)} in this profile`,
          unusable,
        );

      const verifiedChunks: PublicChunkV1[] = [];
      const hashes: Uint8Array[] = [];
      let previousChunkHash = ZERO32;

      for (let index = 0; index < sizeClass.publicChunksPerWindow; index++) {
        const bytes = chunkBytes[classIndex][index];
        if (bytes === null) return unusable;
        const read = this.#decode(
          decodePublicChunkReadV1,
          bytes,
          window,
          "chunk read",
        );
        if (read === null) return unusable;

        if (read.kind === "status") {
          const value = read.value;
          // Version first and then the signature, for the same reason as the
          // checkpoint status: the transcript is the canonical encoding of
          // this exact type, and every other field is read after it verifies.
          if (value.version !== 1)
            return this.#reject(
              "signature-invalid",
              window,
              "unsupported chunk status version",
              unusable,
            );
          const verified = await verify(
            await publicChunkStatusSigningHash(value),
            read.storeSignature,
            this.#storeKey,
            this.#module,
          );
          if (!verified)
            return this.#reject(
              "signature-invalid",
              window,
              "the chunk status signature does not verify",
              unusable,
            );
          if (
            !bytesEqual(value.bucket.deliveryProfileHash, this.#profileHash) ||
            value.bucket.ingressWindow !== window ||
            value.bucket.sizeClass !== sizeClass.id ||
            value.chunkIndex !== BigInt(index)
          )
            return this.#reject(
              "signature-invalid",
              window,
              "the chunk status does not name the chunk that was requested",
              unusable,
            );
          // A store that signed a checkpoint for this window and then refuses
          // one of the chunks it committed contradicts itself.
          return this.#reject(
            "signature-invalid",
            window,
            `the store withholds chunk ${String(index)} of class ${String(sizeClass.id)} from a window it finalized`,
            unusable,
          );
        }

        const chunk = read.chunk;
        if (chunk.version !== 1)
          return this.#reject(
            "signature-invalid",
            window,
            "unsupported chunk version",
            unusable,
          );
        // The signature comes before every other question about this chunk:
        // its coordinates, its object count, its object lengths and its link
        // to the chunk before it are all claims, and an unsigned claim is not
        // one this client should be reasoning about at all.
        const { storeSignature, ...body } = chunk;
        const verified = await verify(
          await publicChunkSigningHash(body),
          storeSignature,
          this.#storeKey,
          this.#module,
        );
        if (!verified)
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk signature does not verify",
            unusable,
          );

        if (
          !bytesEqual(chunk.bucket.deliveryProfileHash, this.#profileHash) ||
          chunk.bucket.ingressWindow !== window ||
          chunk.bucket.sizeClass !== sizeClass.id ||
          chunk.chunkIndex !== BigInt(index)
        )
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk does not name the coordinates that were requested",
            unusable,
          );
        if (chunk.fixedObjects.length !== this.#profile.publicChunkObjectCount)
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk does not hold the profile's fixed object count",
            unusable,
          );
        for (const object of chunk.fixedObjects)
          if (object.length !== objectBytes)
            return this.#reject(
              "signature-invalid",
              window,
              "a carrier object is not this size class's exact wire length",
              unusable,
            );
        if (!bytesEqual(chunk.previousChunkHash, previousChunkHash))
          return this.#reject(
            "signature-invalid",
            window,
            `chunk ${String(index)} of class ${String(sizeClass.id)} does not link to its predecessor`,
            unusable,
          );

        previousChunkHash = await publicChunkHash(chunk);
        verifiedChunks.push(chunk);
        hashes.push(previousChunkHash);
      }

      chunksByClass.set(sizeClass.id, verifiedChunks);
      hashesByClass.set(sizeClass.id, hashes);
    }

    return { kind: "finalized", chunksByClass, hashesByClass };
  }

  /**
   * Add this observation to the run and re-decide the whole chain.
   *
   * The verifier is given the run rather than the pair because blame outranks
   * absence: a conflict or a broken predecessor anywhere in what this client
   * holds must be reported even when a later window is missing.
   */
  async #verifyChain(
    window: bigint,
    checkpoint: PublicStoreCheckpointV1,
    descriptor: StoreDescriptorV1,
  ): Promise<void> {
    const observation: ObservedStoreCheckpoint = {
      checkpoint,
      descriptor,
      finalizationInstantUnixMs: this.#finalizationInstantMs(window),
    };
    this.#observe(observation);

    const verdict = await verifyStoreCheckpointChain(
      this.#observed,
      this.#geometry,
      this.#module,
    );
    // A gap is the one blame-free outcome besides success: it says this client
    // did not observe enough, which no proof can attribute to the store.
    if (
      verdict.outcome === "chain-verified" ||
      verdict.outcome === "unverified-chain-gap"
    )
      return;
    this.#breach(
      "chain-fault",
      window,
      `${verdict.outcome}: ${verdict.reason}`,
      undefined,
    );
  }

  /**
   * Keep the run sorted by ingress window, and keep both sides of a same-window
   * disagreement: dropping the second one would erase the equivocation.
   */
  #observe(observation: ObservedStoreCheckpoint): void {
    const window = observation.checkpoint.ingressWindow;
    for (const held of this.#observed)
      if (
        held.checkpoint.ingressWindow === window &&
        bytesEqual(
          held.checkpoint.storeSignature,
          observation.checkpoint.storeSignature,
        )
      )
        return;

    let position = this.#observed.length;
    while (
      position > 0 &&
      this.#observed[position - 1].checkpoint.ingressWindow > window
    )
      position--;
    this.#observed.splice(position, 0, observation);
    if (this.#observed.length > MAX_OBSERVED_CHECKPOINTS)
      this.#observed.shift();
  }

  /**
   * Compare every receipt for this window against the slot the geometry says
   * it must occupy.
   *
   * This is exactly the specification's custody-breach contradiction: the
   * store signed that it stored these bytes at coordinates derived only from
   * public values, and the window it finalized says otherwise.
   */
  async #verifyCustody(
    window: bigint,
    chunksByClass: ReadonlyMap<number, readonly PublicChunkV1[]>,
  ): Promise<void> {
    const remaining: AppendReceipt[] = [];
    for (const receipt of this.#receipts) {
      if (receipt.window !== window) {
        remaining.push(receipt);
        continue;
      }
      // Only a promise of custody can be breached: a refused or cover append
      // committed the store to nothing.
      if (
        receipt.result.status !== "stored" &&
        receipt.result.status !== "already-present"
      )
        continue;

      const coordinates = appendSlotCoordinates(
        this.#geometry,
        receipt.sizeClass,
        receipt.lease.allocationOrdinal,
        receipt.objectOrdinal,
      );
      const chunk = chunksByClass.get(receipt.sizeClass)?.[
        Number(coordinates.chunkIndex)
      ];
      if (chunk === undefined) {
        this.#breach(
          "custody-breach",
          window,
          "the window holds no chunk for a slot this store signed a receipt for",
          undefined,
        );
        continue;
      }
      const held = await sha256(
        chunk.fixedObjects[coordinates.objectIndexWithinChunk],
      );
      if (!bytesEqual(held, receipt.objectHash))
        this.#breach(
          "custody-breach",
          window,
          `the object at class ${String(receipt.sizeClass)} chunk ${String(coordinates.chunkIndex)} slot ${String(coordinates.objectIndexWithinChunk)} is not the one this store received`,
          undefined,
        );
    }
    this.#receipts = remaining;
  }

  /** `IngressWindowStart(w) + chunkFinalizationOffsetMs`. */
  #finalizationInstantMs(window: bigint): bigint {
    return (
      ingressWindowStartMs(window, this.#profile.deliveryWindowMs) +
      this.#profile.chunkFinalizationOffsetMs
    );
  }
}
