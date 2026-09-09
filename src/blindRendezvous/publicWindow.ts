/**
 * Public windows, buckets, immutable chunks, and checkpoints (Section 4.3).
 *
 * The store's whole view is public geometry: a delivery profile, an ingress
 * window, a size class, a chunk index, and opaque fixed-size objects. Nothing
 * here takes a room-derived input, which is what lets every room in a profile
 * share one bucket and makes unrelated rooms cover for each other rather than
 * members of anything.
 *
 * Two clocks meet in this file and must never be substituted for one another:
 * `IngressWindow` is carrier geometry, and `RoomLogicalWindow` is operation
 * validity under immutable room policy. Profiles with different cadences carry
 * the same operation without changing its validity or the reducer's result.
 *
 * Scope: geometry, hashing, the append slot mapping, RFC 9162 inclusion
 * verification, and the descriptor-bound checkpoint predicates. The remaining
 * Section 4.3 fault proofs are assembled from these parts by a caller that also
 * holds the raw evidence: `checkpointsConflict` and `chainLinksSuccessor` are
 * the descriptor-free halves, and `structurallyValidCheckpoint` supplies the
 * descriptor join each proof requires of both of its checkpoints.
 */

import { verify } from "../cryptography/ed25519";
import { encodeCanonical } from "./canonicalSchema";
import { concatBytes, domain, sha256 } from "./derivations";
import {
  chainStartConflict,
  descriptorChainStart,
  descriptorHash,
  descriptorSupportsProfile,
  storeId,
  validateStoreDescriptor,
} from "./storeDescriptor";
import {
  publicBucketV1Schema,
  publicCheckpointChunkLeafV1Schema,
  publicChunkBodyV1Schema,
  publicChunkV1Schema,
  publicStoreCheckpointBodyV1Schema,
  publicStoreCheckpointV1Schema,
} from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { StoreDescriptorV1 } from "./storeDescriptor";

export interface PublicBucketV1 {
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  sizeClass: number;
}

export interface PublicChunkBodyV1 {
  version: 1;
  bucket: PublicBucketV1;
  chunkIndex: bigint;
  previousChunkHash: Uint8Array;
  fixedObjects: readonly Uint8Array[];
}

export type PublicChunkV1 = PublicChunkBodyV1 & { storeSignature: Uint8Array };

export interface PublicStoreCheckpointBodyV1 {
  version: 1;
  storeId: Uint8Array;
  descriptorHash: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  chainStartIngressWindow: bigint;
  previousCheckpointHash: Uint8Array;
  finalizedChunkCount: number;
  finalizedChunkRoot: Uint8Array;
}

export type PublicStoreCheckpointV1 = PublicStoreCheckpointBodyV1 & {
  storeSignature: Uint8Array;
};

export interface PublicCheckpointChunkLeafV1 {
  sizeClass: number;
  chunkIndex: bigint;
  publicChunkHash: Uint8Array;
}

export interface PublicCheckpointChunkInclusionProofV1 {
  version: 1;
  checkpointHash: Uint8Array;
  leaf: PublicCheckpointChunkLeafV1;
  leafIndex: number;
  siblingHashes: readonly Uint8Array[];
}

/** The size-class geometry a profile fixes; the subset this module needs. */
export interface PublicProfileGeometry {
  readonly publicChunkObjectCount: number;
  readonly cohortAllocationsPerWindow: number;
  readonly roomSlotsPerClient: number;
  readonly sizeClasses: readonly {
    readonly id: number;
    readonly appendScheduleLength: number;
    readonly publicChunksPerWindow: number;
  }[];
}

export class PublicWindowError extends Error {
  override readonly name = "PublicWindowError";

  constructor(message: string) {
    super(`publicWindow: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PublicWindowError(message);
};

export const ZERO32: Uint8Array = new Uint8Array(32);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return false;
  return true;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++)
    if (left[index] !== right[index]) return left[index] - right[index];
  return left.length - right.length;
};

const checkedMultiply = (left: number, right: number): number => {
  const product = left * right;
  if (!Number.isSafeInteger(product)) fail("checked multiplication overflowed");
  return product;
};

const checkedAdd = (left: number, right: number): number => {
  const sum = left + right;
  if (!Number.isSafeInteger(sum)) fail("checked addition overflowed");
  return sum;
};

/* ------------------------------------------------------------------ *
 * Windows
 * ------------------------------------------------------------------ */

/** `IngressWindow(profile, now) = floor(now / profile.deliveryWindowMs)` */
export const ingressWindow = (
  deliveryWindowMs: bigint,
  nowMs: bigint,
): bigint => {
  if (deliveryWindowMs <= 0n) fail("deliveryWindowMs must be positive");
  if (nowMs < 0n) fail("now must not be negative");
  return nowMs / deliveryWindowMs;
};

/**
 * `RoomLogicalWindow(roomPolicy, now) = floor(now / logicalWindowMs)`
 *
 * Deliberately a separate function from `ingressWindow` despite the identical
 * shape: substituting one for the other would let carrier geometry decide
 * operation validity.
 */
export const roomLogicalWindow = (
  logicalWindowMs: bigint,
  nowMs: bigint,
): bigint => {
  if (logicalWindowMs <= 0n) fail("logicalWindowMs must be positive");
  if (nowMs < 0n) fail("now must not be negative");
  return nowMs / logicalWindowMs;
};

/** `IngressWindowStart(w) = checkedMultiply(w, deliveryWindowMs)` */
export const ingressWindowStartMs = (
  window: bigint,
  deliveryWindowMs: bigint,
): bigint => {
  if (window < 0n) fail("ingress window must not be negative");
  return window * deliveryWindowMs;
};

/**
 * Retention is inclusive and has one wire meaning: a bucket finalized in
 * window `w` stays readable through the END of `w + carrierRetentionWindows`,
 * and may be deleted only at or after the start of the window after that.
 */
export const bucketIsReadable = (
  bucketWindow: bigint,
  currentWindow: bigint,
  carrierRetentionWindows: number,
): boolean =>
  bucketWindow <= currentWindow &&
  currentWindow <= bucketWindow + BigInt(carrierRetentionWindows);

/* ------------------------------------------------------------------ *
 * Identifiers
 * ------------------------------------------------------------------ */

export const publicBucketId = async (
  bucket: PublicBucketV1,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-bucket/v1"),
      encodeCanonical(publicBucketV1Schema, bucket),
    ),
  );

/** The transcript a store signs; the body only, never the signed form. */
export const publicChunkSigningHash = async (
  body: PublicChunkBodyV1,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-chunk/signing/v1"),
      encodeCanonical(publicChunkBodyV1Schema, body),
    ),
  );

/** The identity of a signed chunk, which is what a checkpoint leaf commits. */
export const publicChunkHash = async (
  chunk: PublicChunkV1,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-chunk/signed/v1"),
      encodeCanonical(publicChunkV1Schema, chunk),
    ),
  );

export const publicStoreCheckpointSigningHash = async (
  body: PublicStoreCheckpointBodyV1,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-store-checkpoint/signing/v1"),
      encodeCanonical(publicStoreCheckpointBodyV1Schema, body),
    ),
  );

export const publicStoreCheckpointHash = async (
  checkpoint: PublicStoreCheckpointV1,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-store-checkpoint/signed/v1"),
      encodeCanonical(publicStoreCheckpointV1Schema, checkpoint),
    ),
  );

/** The leaf preimage a checkpoint's Merkle tree is built over. */
export const publicCheckpointChunkLeafInput = (
  leaf: PublicCheckpointChunkLeafV1,
): Uint8Array =>
  concatBytes(
    domain("p2party/public-checkpoint-chunk-leaf/v1"),
    encodeCanonical(publicCheckpointChunkLeafV1Schema, leaf),
  );

/* ------------------------------------------------------------------ *
 * Append slot mapping (Section 4.3.13)
 * ------------------------------------------------------------------ */

export interface AppendSlotCoordinates {
  readonly chunkIndex: bigint;
  readonly objectIndexWithinChunk: number;
  readonly globalObjectOrdinal: number;
  readonly roomSlotOrdinal: number;
  readonly objectOrdinalWithinRoomSlot: number;
}

/**
 * Where one admitted append lands, derived only from the signed lease ordinal
 * and public profile geometry.
 *
 * This is the mapping a custody promise commits to, so it is a total function
 * of public values: a store cannot move an object by claiming a different
 * position, and a client can check the promise without asking anyone.
 */
export const appendSlotCoordinates = (
  geometry: PublicProfileGeometry,
  sizeClassId: number,
  allocationOrdinal: number,
  objectOrdinalWithinAllocation: number,
): AppendSlotCoordinates => {
  const sizeClass = geometry.sizeClasses.find(
    (entry) => entry.id === sizeClassId,
  );
  if (sizeClass === undefined)
    fail(`unknown size class ${String(sizeClassId)}`);

  const perAllocation = checkedMultiply(
    geometry.roomSlotsPerClient,
    sizeClass.appendScheduleLength,
  );
  if (
    !Number.isSafeInteger(allocationOrdinal) ||
    allocationOrdinal < 0 ||
    allocationOrdinal >= geometry.cohortAllocationsPerWindow
  )
    fail("allocation ordinal is outside the cohort capacity");
  if (
    !Number.isSafeInteger(objectOrdinalWithinAllocation) ||
    objectOrdinalWithinAllocation < 0 ||
    objectOrdinalWithinAllocation >= perAllocation
  )
    fail("object ordinal is outside this allocation's slot count");

  const globalObjectOrdinal = checkedAdd(
    checkedMultiply(allocationOrdinal, perAllocation),
    objectOrdinalWithinAllocation,
  );

  return {
    globalObjectOrdinal,
    chunkIndex: BigInt(
      Math.floor(globalObjectOrdinal / geometry.publicChunkObjectCount),
    ),
    objectIndexWithinChunk:
      globalObjectOrdinal % geometry.publicChunkObjectCount,
    roomSlotOrdinal: Math.floor(
      objectOrdinalWithinAllocation / sizeClass.appendScheduleLength,
    ),
    objectOrdinalWithinRoomSlot:
      objectOrdinalWithinAllocation % sizeClass.appendScheduleLength,
  };
};

/**
 * The checkpoint leaf index of one chunk: the profile-fixed sequence sorted by
 * `(sizeClass, chunkIndex)`.
 */
export const profileChunkOrdinal = (
  geometry: PublicProfileGeometry,
  sizeClassId: number,
  chunkIndex: bigint,
): number => {
  const ordered = [...geometry.sizeClasses].sort((a, b) => a.id - b.id);
  let ordinal = 0;
  for (const sizeClass of ordered) {
    if (sizeClass.id === sizeClassId) {
      if (
        chunkIndex < 0n ||
        chunkIndex >= BigInt(sizeClass.publicChunksPerWindow)
      )
        fail("chunk index is outside this size class's per-window count");
      return checkedAdd(ordinal, Number(chunkIndex));
    }
    ordinal = checkedAdd(ordinal, sizeClass.publicChunksPerWindow);
  }
  return fail(`unknown size class ${String(sizeClassId)}`);
};

/** `checkedSum(profile.sizeClasses[].publicChunksPerWindow)` */
export const profileFinalizedChunkCount = (
  geometry: PublicProfileGeometry,
): number =>
  geometry.sizeClasses.reduce(
    (total, sizeClass) => checkedAdd(total, sizeClass.publicChunksPerWindow),
    0,
  );

/* ------------------------------------------------------------------ *
 * RFC 9162 Merkle tree (Section 4.3.17)
 * ------------------------------------------------------------------ */

/**
 * RFC 9162 Section 2.1.1 leaf hash: `HASH(0x00 || entry)`.
 *
 * The prefix bytes are the whole point — without them a leaf and an interior
 * node could collide, which is the classic second-preimage attack on
 * unprefixed Merkle trees.
 */
export const rfc9162LeafHash = async (entry: Uint8Array): Promise<Uint8Array> =>
  sha256(concatBytes(Uint8Array.of(0x00), entry));

/** RFC 9162 Section 2.1.1 interior node: `HASH(0x01 || left || right)`. */
export const rfc9162NodeHash = async (
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> => sha256(concatBytes(Uint8Array.of(0x01), left, right));

/** The largest power of two strictly less than `n`, as RFC 9162 defines. */
const largestPowerOfTwoBelow = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/**
 * RFC 9162 Merkle Tree Hash over a nonempty entry sequence.
 *
 * The empty case is rejected rather than returning `HASH()`: a checkpoint
 * always commits the profile's complete fixed chunk sequence, so an empty
 * input means the caller built the wrong sequence.
 */
export const rfc9162MerkleTreeHash = async (
  entries: readonly Uint8Array[],
): Promise<Uint8Array> => {
  if (entries.length === 0)
    fail("a checkpoint commits a nonempty chunk sequence");
  if (entries.length === 1) return rfc9162LeafHash(entries[0]);

  const split = largestPowerOfTwoBelow(entries.length);
  const [left, right] = await Promise.all([
    rfc9162MerkleTreeHash(entries.slice(0, split)),
    rfc9162MerkleTreeHash(entries.slice(split)),
  ]);
  return rfc9162NodeHash(left, right);
};

/**
 * The RFC 9162 audit path for one leaf: the sibling hashes from the leaf up.
 *
 * Exposed so a verifier can assert the received path has exactly this length —
 * a missing or extra sibling is invalid, not merely unhelpful.
 */
export const rfc9162AuditPath = async (
  entries: readonly Uint8Array[],
  leafIndex: number,
): Promise<Uint8Array[]> => {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0)
    fail("leaf index must be a non-negative safe integer");
  if (leafIndex >= entries.length) fail("leaf index is outside the tree");
  if (entries.length === 1) return [];

  const split = largestPowerOfTwoBelow(entries.length);
  if (leafIndex < split) {
    const path = await rfc9162AuditPath(entries.slice(0, split), leafIndex);
    path.push(await rfc9162MerkleTreeHash(entries.slice(split)));
    return path;
  }
  const path = await rfc9162AuditPath(entries.slice(split), leafIndex - split);
  path.push(await rfc9162MerkleTreeHash(entries.slice(0, split)));
  return path;
};

/** The exact number of siblings an RFC 9162 audit path has for `(index, n)`. */
export const rfc9162AuditPathLength = (
  leafIndex: number,
  treeSize: number,
): number => {
  if (treeSize <= 1) return 0;
  const split = largestPowerOfTwoBelow(treeSize);
  return leafIndex < split
    ? checkedAdd(rfc9162AuditPathLength(leafIndex, split), 1)
    : checkedAdd(
        rfc9162AuditPathLength(leafIndex - split, treeSize - split),
        1,
      );
};

/** Recompute a root from a leaf and its audit path (RFC 9162 Section 2.1.3). */
export const rfc9162RootFromAuditPath = async (
  leafEntry: Uint8Array,
  leafIndex: number,
  treeSize: number,
  siblingHashes: readonly Uint8Array[],
): Promise<Uint8Array> => {
  if (!Number.isSafeInteger(treeSize) || treeSize <= 0)
    fail("tree size must be a positive safe integer");
  if (
    !Number.isSafeInteger(leafIndex) ||
    leafIndex < 0 ||
    leafIndex >= treeSize
  )
    fail("leaf index is outside the tree");
  if (siblingHashes.length !== rfc9162AuditPathLength(leafIndex, treeSize))
    fail("audit path does not have the exact RFC 9162 sibling count");

  // RFC 9162 Section 2.1.3.2, verbatim. The audit path is ordered from the
  // leaf upward, so it is consumed in that direction: walking down from the
  // root instead silently recomputes a different root for any tree whose size
  // is not a power of two.
  let fn = leafIndex;
  let sn = treeSize - 1;
  let hash = await rfc9162LeafHash(leafEntry);

  for (const sibling of siblingHashes) {
    if (sn === 0) fail("audit path is longer than the tree is deep");
    if ((fn & 1) === 1 || fn === sn) {
      hash = await rfc9162NodeHash(sibling, hash);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>>= 1;
          sn >>>= 1;
        }
      }
    } else {
      hash = await rfc9162NodeHash(hash, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }

  if (sn !== 0) fail("audit path is shorter than the tree is deep");
  return hash;
};

/* ------------------------------------------------------------------ *
 * Checkpoint construction and inclusion verification
 * ------------------------------------------------------------------ */

/**
 * The complete leaf sequence a checkpoint commits: every chunk of every size
 * class, sorted by `(sizeClass, chunkIndex)`, including all-dummy windows.
 */
export const checkpointLeafEntries = async (
  geometry: PublicProfileGeometry,
  chunkHashBySizeClass: ReadonlyMap<number, readonly Uint8Array[]>,
): Promise<Uint8Array[]> => {
  const entries: Uint8Array[] = [];
  for (const sizeClass of [...geometry.sizeClasses].sort(
    (a, b) => a.id - b.id,
  )) {
    const hashes = chunkHashBySizeClass.get(sizeClass.id);
    if (
      hashes === undefined ||
      hashes.length !== sizeClass.publicChunksPerWindow
    )
      fail(
        `size class ${String(sizeClass.id)} must supply exactly ${String(sizeClass.publicChunksPerWindow)} chunk hashes`,
      );
    for (let chunkIndex = 0; chunkIndex < hashes.length; chunkIndex++)
      entries.push(
        publicCheckpointChunkLeafInput({
          sizeClass: sizeClass.id,
          chunkIndex: BigInt(chunkIndex),
          publicChunkHash: hashes[chunkIndex],
        }),
      );
  }
  return entries;
};

export type InclusionVerdict =
  { readonly valid: true } | { readonly valid: false; readonly reason: string };

const invalid = (reason: string): InclusionVerdict => ({
  valid: false,
  reason,
});

/**
 * Verify that a signed chunk occupies its committed position in a checkpoint.
 *
 * The signature check is the caller's: it needs the store descriptor from
 * Section 4.2 to know which key to trust. Everything that can be decided from
 * the geometry and the hashes is decided here, and every cross-coordinate
 * relocation is rejected — a store must not be able to move an object between
 * classes, chunks, or windows and still produce a passing proof.
 */
export const verifyCheckpointChunkInclusion = async (
  geometry: PublicProfileGeometry,
  checkpoint: PublicStoreCheckpointV1,
  chunk: PublicChunkV1,
  proof: PublicCheckpointChunkInclusionProofV1,
): Promise<InclusionVerdict> => {
  if (proof.version !== 1)
    return invalid("unsupported inclusion proof version");

  if (
    !bytesEqual(
      chunk.bucket.deliveryProfileHash,
      checkpoint.deliveryProfileHash,
    )
  )
    return invalid("chunk and checkpoint name different delivery profiles");
  if (chunk.bucket.ingressWindow !== checkpoint.ingressWindow)
    return invalid("chunk and checkpoint name different ingress windows");
  if (chunk.bucket.sizeClass !== proof.leaf.sizeClass)
    return invalid("chunk and proof leaf name different size classes");
  if (chunk.chunkIndex !== proof.leaf.chunkIndex)
    return invalid("chunk and proof leaf name different chunk indexes");

  if (!bytesEqual(proof.leaf.publicChunkHash, await publicChunkHash(chunk)))
    return invalid("proof leaf does not commit this exact signed chunk");

  if (
    !bytesEqual(
      proof.checkpointHash,
      await publicStoreCheckpointHash(checkpoint),
    )
  )
    return invalid("proof does not bind this exact checkpoint");

  const expectedCount = profileFinalizedChunkCount(geometry);
  if (checkpoint.finalizedChunkCount !== expectedCount)
    return invalid("checkpoint count is not the profile-fixed chunk count");

  let expectedIndex: number;
  try {
    expectedIndex = profileChunkOrdinal(
      geometry,
      chunk.bucket.sizeClass,
      chunk.chunkIndex,
    );
  } catch {
    return invalid("chunk coordinates are outside the profile geometry");
  }
  if (proof.leafIndex !== expectedIndex)
    return invalid(
      "leaf index is not the profile-order position of this chunk",
    );
  if (proof.leafIndex < 0 || proof.leafIndex >= checkpoint.finalizedChunkCount)
    return invalid("leaf index is outside the committed tree");

  let recomputed: Uint8Array;
  try {
    recomputed = await rfc9162RootFromAuditPath(
      publicCheckpointChunkLeafInput(proof.leaf),
      proof.leafIndex,
      checkpoint.finalizedChunkCount,
      proof.siblingHashes,
    );
  } catch (error) {
    return invalid(
      error instanceof Error ? error.message : "audit path is malformed",
    );
  }
  if (!bytesEqual(recomputed, checkpoint.finalizedChunkRoot))
    return invalid("audit path does not recompute the committed root");

  return { valid: true };
};

/**
 * Two checkpoints for one store/profile/window that are not the same object.
 *
 * This is the descriptor-free half of `PublicCheckpointConflictProofV1`; a
 * complete proof additionally joins each embedded descriptor. Canonical order
 * is bytewise-lower checkpoint hash first, so one fault has one proof rather
 * than two mirror images.
 */
export const checkpointsConflict = async (
  first: PublicStoreCheckpointV1,
  second: PublicStoreCheckpointV1,
): Promise<
  | { readonly conflicting: false }
  | {
      readonly conflicting: true;
      readonly canonicalOrder: readonly [
        PublicStoreCheckpointV1,
        PublicStoreCheckpointV1,
      ];
    }
> => {
  if (
    !bytesEqual(first.storeId, second.storeId) ||
    !bytesEqual(first.deliveryProfileHash, second.deliveryProfileHash) ||
    first.ingressWindow !== second.ingressWindow
  )
    return { conflicting: false };

  const [firstHash, secondHash] = await Promise.all([
    publicStoreCheckpointHash(first),
    publicStoreCheckpointHash(second),
  ]);
  const order = compareBytes(firstHash, secondHash);
  if (order === 0) return { conflicting: false };

  return {
    conflicting: true,
    canonicalOrder: order < 0 ? [first, second] : [second, first],
  };
};

/**
 * The hash-linkage half of `ChainValidSuccessor`.
 *
 * Structural validity under each embedded descriptor is a separate Section 4.2
 * check, and the specification is explicit that structural validity alone does
 * not assert predecessor continuity — which is exactly what this decides.
 */
export const chainLinksSuccessor = async (
  previous: PublicStoreCheckpointV1,
  next: PublicStoreCheckpointV1,
): Promise<boolean> =>
  bytesEqual(previous.storeId, next.storeId) &&
  bytesEqual(previous.deliveryProfileHash, next.deliveryProfileHash) &&
  previous.chainStartIngressWindow === next.chainStartIngressWindow &&
  next.ingressWindow === previous.ingressWindow + 1n &&
  bytesEqual(
    next.previousCheckpointHash,
    await publicStoreCheckpointHash(previous),
  );

/** At the chain start the predecessor hash is exactly `ZERO32`. */
export const isChainStart = (checkpoint: PublicStoreCheckpointV1): boolean =>
  checkpoint.ingressWindow === checkpoint.chainStartIngressWindow &&
  bytesEqual(checkpoint.previousCheckpointHash, ZERO32);

/**
 * `StructurallyValidCheckpoint(descriptor, checkpoint, profile)`.
 *
 * Deliberately portable: it uses the descriptor embedded in the read or proof,
 * and takes no input from local carrier authorization, catalog arrival order,
 * or which descriptor the verifier considers "latest". Whether the frontend may
 * *contact* that store is a separate local decision — conflating the two would
 * make historical evidence depend on present-day policy, so a store could
 * escape a proof by being removed from a catalog.
 *
 * `finalizationInstantUnixMs` is the instant the checkpoint was finalized, and
 * the descriptor must have been valid then — not now.
 *
 * Of the specification's "profile-fixed count/root checks", only the count half
 * is decided here. Recomputing `finalizedChunkRoot` needs the window's chunk
 * hashes, which this predicate is never given; that is
 * `verifyCheckpointChunkInclusion`, and nothing composes the two, so no single
 * call asserts both halves. A checkpoint accepted here may still carry a root
 * no chunk sequence produces.
 *
 * TODO(spec): the condition list in Section 4.3 does not name a version check,
 * so `checkpoint.version` is not checked here, while `StoreDescriptorAuthentic`
 * does name one and `validateStoreDescriptor` enforces it. Whether the version
 * byte belongs to structural validity is a question for the specification, not
 * one to settle by tightening this predicate; the current behaviour is pinned
 * in tests/blindRendezvous/storeHonesty.test.ts.
 */
export const structurallyValidCheckpoint = async (
  descriptor: StoreDescriptorV1,
  checkpoint: PublicStoreCheckpointV1,
  geometry: PublicProfileGeometry,
  finalizationInstantUnixMs: bigint,
  module?: LibCrypto,
): Promise<InclusionVerdict> => {
  const descriptorValid = await validateStoreDescriptor(
    descriptor,
    finalizationInstantUnixMs,
    module,
  );
  if (!descriptorValid.valid) return invalid(descriptorValid.reason);

  if (!bytesEqual(checkpoint.descriptorHash, await descriptorHash(descriptor)))
    return invalid("checkpoint does not name this descriptor");
  if (
    !bytesEqual(
      checkpoint.storeId,
      await storeId(descriptor.storeIdentityEd25519Key),
    )
  )
    return invalid("checkpoint does not name this descriptor's store");

  if (!descriptorSupportsProfile(descriptor, checkpoint.deliveryProfileHash))
    return invalid("descriptor does not support this delivery profile");

  const chainStart = descriptorChainStart(
    descriptor,
    checkpoint.deliveryProfileHash,
  );
  if (chainStart === null)
    return invalid("descriptor declares no chain start for this profile");
  if (chainStart !== checkpoint.chainStartIngressWindow)
    return invalid(
      "checkpoint names a different chain start than the descriptor",
    );
  if (checkpoint.ingressWindow < chainStart)
    return invalid("checkpoint precedes the declared chain start");

  if (checkpoint.finalizedChunkCount !== profileFinalizedChunkCount(geometry))
    return invalid("checkpoint count is not the profile-fixed chunk count");

  // Only the chain start may carry a zero predecessor; a later window with
  // ZERO32 would silently restart the chain.
  if (
    checkpoint.ingressWindow === chainStart &&
    !bytesEqual(checkpoint.previousCheckpointHash, ZERO32)
  )
    return invalid("chain start must have a zero predecessor hash");
  if (
    checkpoint.ingressWindow !== chainStart &&
    bytesEqual(checkpoint.previousCheckpointHash, ZERO32)
  )
    return invalid("only the chain start may have a zero predecessor hash");

  // Section 4.3 defines PublicStoreCheckpointSigningHash as the signing hash
  // itself; unlike the append receipt there is no further signature-message
  // domain prefix, so the signature is over that hash exactly.
  const { storeSignature, ...body } = checkpoint;
  const verified = await verify(
    await publicStoreCheckpointSigningHash(body),
    storeSignature,
    descriptor.storeIdentityEd25519Key,
    module,
  );
  if (!verified) return invalid("checkpoint signature does not verify");

  return { valid: true };
};

/**
 * `ChainValidSuccessor(previous, next)`: both structurally valid under their
 * embedded descriptors, and linked.
 *
 * Structural validity alone deliberately does not assert continuity — that is
 * what makes a missing predecessor detectable rather than assumed.
 */
export const chainValidSuccessor = async (
  previous: PublicStoreCheckpointV1,
  previousDescriptor: StoreDescriptorV1,
  previousFinalizationUnixMs: bigint,
  next: PublicStoreCheckpointV1,
  nextDescriptor: StoreDescriptorV1,
  nextFinalizationUnixMs: bigint,
  geometry: PublicProfileGeometry,
  module?: LibCrypto,
): Promise<InclusionVerdict> => {
  const previousValid = await structurallyValidCheckpoint(
    previousDescriptor,
    previous,
    geometry,
    previousFinalizationUnixMs,
    module,
  );
  if (!previousValid.valid)
    return invalid(`predecessor: ${previousValid.reason}`);

  const nextValid = await structurallyValidCheckpoint(
    nextDescriptor,
    next,
    geometry,
    nextFinalizationUnixMs,
    module,
  );
  if (!nextValid.valid) return invalid(`successor: ${nextValid.reason}`);

  if (!(await chainLinksSuccessor(previous, next)))
    return invalid("successor does not link to this exact predecessor");

  return { valid: true };
};

/* ------------------------------------------------------------------ *
 * Sequence-level store honesty
 * ------------------------------------------------------------------ */

/**
 * One checkpoint exactly as a client observed it: the read itself, the
 * descriptor embedded beside it, and the instant that window was finalized.
 *
 * Deliberately not a `...V1` name: this is an in-memory bundle of three
 * already-frozen objects, not a wire shape the specification has registered.
 */
export interface ObservedStoreCheckpoint {
  readonly checkpoint: PublicStoreCheckpointV1;
  readonly descriptor: StoreDescriptorV1;
  readonly finalizationInstantUnixMs: bigint;
}

/**
 * What `verifyStoreCheckpointChain` detected. Exactly one outcome is blame-free
 * besides success: `unverified-chain-gap` says the client did not observe
 * enough, which the specification is explicit is not a fault.
 */
export type StoreCheckpointChainVerdict =
  | {
      readonly outcome: "chain-verified";
      readonly storeId: Uint8Array;
      readonly deliveryProfileHash: Uint8Array;
      readonly chainStartIngressWindow: bigint;
      readonly firstIngressWindow: bigint;
      readonly headIngressWindow: bigint;
      readonly headCheckpointHash: Uint8Array;
      readonly startsAtChainStart: boolean;
    }
  | {
      readonly outcome: "structurally-invalid-checkpoint";
      readonly reason: string;
      readonly index: number;
    }
  | {
      readonly outcome: "not-one-store-profile-chain";
      readonly reason: string;
      readonly index: number;
    }
  | {
      readonly outcome: "chain-start-conflict";
      readonly reason: string;
      readonly canonicalOrder: readonly [StoreDescriptorV1, StoreDescriptorV1];
    }
  | {
      readonly outcome: "checkpoint-conflict";
      readonly reason: string;
      readonly canonicalOrder: readonly [
        PublicStoreCheckpointV1,
        PublicStoreCheckpointV1,
      ];
    }
  | {
      readonly outcome: "chain-breach";
      readonly reason: string;
      readonly previous: PublicStoreCheckpointV1;
      readonly next: PublicStoreCheckpointV1;
    }
  | {
      readonly outcome: "unverified-chain-gap";
      readonly reason: string;
      readonly afterIngressWindow: bigint;
      readonly beforeIngressWindow: bigint;
    };

/**
 * The sequence form of the Section 4.3 checkpoint checks: one entry point a
 * store client can call over the run of checkpoints it actually holds.
 *
 * `chainValidSuccessor` remains the specified predicate for a single pair; this
 * verifies each checkpoint's structure exactly once and then decides the
 * pairwise questions, so a long run costs one signature verification per
 * checkpoint rather than two.
 *
 * Blame is reported before absence. A store must not be able to bury an
 * equivocation behind a hole in what the client happened to retain, so a
 * conflict, chain-start conflict, or broken predecessor anywhere in the run
 * outranks a missing window; only when no fault exists does a gap become the
 * verdict.
 *
 * What a `chain-verified` verdict is not: it says the observed run is
 * internally consistent and signed, over exactly the windows supplied. It is
 * not a completeness, availability, or non-equivocation claim — a store that
 * showed this client one branch and another client a different one is caught
 * only when the two observations meet. Nor does it assert `finalizedChunkRoot`:
 * `structurallyValidCheckpoint` cannot, and this composes that, not inclusion.
 *
 * A `chain-verified` verdict copies the bytes it reports, so it stays true
 * after the buffers a store's reply was decoded into are reused. The conflict
 * and breach verdicts deliberately do not: they carry the caller's own
 * checkpoint and descriptor objects, because those are the exact halves the
 * specification's proofs are built from, and copying them here would only
 * hide that they must be retained unmutated to stay usable as evidence.
 *
 * Ordering the run is the caller's job: observations must arrive sorted by
 * ingress window. A store cannot cause a violation of that, so it throws
 * rather than returning a verdict that would read as a detected fault.
 */
export const verifyStoreCheckpointChain = async (
  observations: readonly ObservedStoreCheckpoint[],
  geometry: PublicProfileGeometry,
  module?: LibCrypto,
): Promise<StoreCheckpointChainVerdict> => {
  if (observations.length === 0)
    fail("a checkpoint chain observation must be nonempty");
  for (let index = 1; index < observations.length; index++)
    if (
      observations[index].checkpoint.ingressWindow <
      observations[index - 1].checkpoint.ingressWindow
    )
      fail("observations must be ordered by ingress window");

  // Structure first: a conflict or a breach between checkpoints that are not
  // themselves valid is junk rather than evidence, and every proof the
  // specification defines requires both of its halves to be structurally valid.
  for (let index = 0; index < observations.length; index++) {
    const observation = observations[index];
    const valid = await structurallyValidCheckpoint(
      observation.descriptor,
      observation.checkpoint,
      geometry,
      observation.finalizationInstantUnixMs,
      module,
    );
    if (!valid.valid)
      return {
        outcome: "structurally-invalid-checkpoint",
        reason: valid.reason,
        index,
      };
  }

  const first = observations[0].checkpoint;
  for (let index = 1; index < observations.length; index++) {
    const { checkpoint } = observations[index];
    if (
      !bytesEqual(checkpoint.storeId, first.storeId) ||
      !bytesEqual(checkpoint.deliveryProfileHash, first.deliveryProfileHash)
    )
      return {
        outcome: "not-one-store-profile-chain",
        reason: "observations name more than one store or delivery profile",
        index,
      };
  }

  // A disagreement about the chain start is signed equivocation about where
  // accountability begins, and it is permanent for that store and profile.
  for (let index = 1; index < observations.length; index++) {
    const observation = observations[index];
    if (
      observation.checkpoint.chainStartIngressWindow ===
      first.chainStartIngressWindow
    )
      continue;
    const conflict = await chainStartConflict(
      observations[0].descriptor,
      observation.descriptor,
      first.deliveryProfileHash,
      module,
    );
    if (conflict.conflicting)
      return {
        outcome: "chain-start-conflict",
        reason: "two valid descriptors name different chain starts",
        canonicalOrder: conflict.canonicalOrder,
      };
    // Unreachable behind the checks above, and kept as defence in depth: both
    // descriptors are already known valid, structural validity ties each one to
    // its checkpoint's store and profile, and the pass above has forced those
    // equal — so differing chain starts are always a conflict.
    return {
      outcome: "not-one-store-profile-chain",
      reason: "observations do not share one chain start",
      index,
    };
  }

  // Two checkpoints for one window: either the same object seen twice, or
  // signed same-window equivocation.
  const distinct: PublicStoreCheckpointV1[] = [first];
  for (let index = 1; index < observations.length; index++) {
    const { checkpoint } = observations[index];
    const previous = distinct[distinct.length - 1];
    if (checkpoint.ingressWindow !== previous.ingressWindow) {
      distinct.push(checkpoint);
      continue;
    }
    const conflict = await checkpointsConflict(previous, checkpoint);
    if (conflict.conflicting)
      return {
        outcome: "checkpoint-conflict",
        reason:
          "two distinct signed checkpoints for one store, profile, window",
        canonicalOrder: conflict.canonicalOrder,
      };
  }

  // A broken predecessor is blame; a missing window is not, so every adjacent
  // pair is checked before any gap is reported.
  for (let index = 1; index < distinct.length; index++) {
    const previous = distinct[index - 1];
    const next = distinct[index];
    if (next.ingressWindow !== previous.ingressWindow + 1n) continue;
    if (!(await chainLinksSuccessor(previous, next)))
      return {
        outcome: "chain-breach",
        reason: "successor does not link to this exact predecessor",
        previous,
        next,
      };
  }

  for (let index = 1; index < distinct.length; index++) {
    const previous = distinct[index - 1];
    const next = distinct[index];
    if (next.ingressWindow === previous.ingressWindow + 1n) continue;
    return {
      outcome: "unverified-chain-gap",
      reason: "the run skips a window, which no proof can attribute",
      afterIngressWindow: previous.ingressWindow,
      beforeIngressWindow: next.ingressWindow,
    };
  }

  const head = distinct[distinct.length - 1];
  return {
    outcome: "chain-verified",
    storeId: Uint8Array.from(first.storeId),
    deliveryProfileHash: Uint8Array.from(first.deliveryProfileHash),
    chainStartIngressWindow: first.chainStartIngressWindow,
    firstIngressWindow: first.ingressWindow,
    headIngressWindow: head.ingressWindow,
    headCheckpointHash: await publicStoreCheckpointHash(head),
    startsAtChainStart: isChainStart(first),
  };
};
