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
 * Scope: this implements the geometry, the hashing, the append slot mapping,
 * and RFC 9162 inclusion verification. The descriptor-bound predicates —
 * `StructurallyValidCheckpoint`, `ChainValidSuccessor`, and the three fault
 * proofs — additionally need `StoreDescriptorV1` from Section 4.2, which is not
 * implemented yet; `checkpointsConflict` below is deliberately named for the
 * one part that needs no descriptor.
 */

import { encodeCanonical } from "./canonicalSchema";
import { concatBytes, domain, sha256 } from "./derivations";
import {
  publicBucketV1Schema,
  publicCheckpointChunkLeafV1Schema,
  publicChunkBodyV1Schema,
  publicChunkV1Schema,
  publicStoreCheckpointBodyV1Schema,
  publicStoreCheckpointV1Schema,
} from "./schemas";

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
