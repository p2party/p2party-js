import { describe, expect, test } from "bun:test";

import { sha256 } from "../../src/blindRendezvous/derivations";
import {
  ZERO32,
  appendSlotCoordinates,
  bucketIsReadable,
  chainLinksSuccessor,
  checkpointLeafEntries,
  checkpointsConflict,
  ingressWindow,
  ingressWindowStartMs,
  isChainStart,
  profileChunkOrdinal,
  profileFinalizedChunkCount,
  publicBucketId,
  publicChunkHash,
  publicChunkSigningHash,
  publicStoreCheckpointHash,
  rfc9162AuditPath,
  rfc9162AuditPathLength,
  rfc9162LeafHash,
  rfc9162MerkleTreeHash,
  rfc9162RootFromAuditPath,
  roomLogicalWindow,
  verifyCheckpointChunkInclusion,
} from "../../src/blindRendezvous/publicWindow";

import type {
  PublicCheckpointChunkInclusionProofV1,
  PublicChunkV1,
  PublicProfileGeometry,
  PublicStoreCheckpointV1,
} from "../../src/blindRendezvous/publicWindow";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

/**
 * An independent RFC 9162 implementation, written from the RFC's recursive
 * definition rather than by reusing the module under test. Comparing two
 * separately derived results is the point: a shared helper would make the
 * comparison vacuous.
 */
const referenceMth = async (
  entries: readonly Uint8Array[],
): Promise<Uint8Array> => {
  const cat = (...parts: Uint8Array[]): Uint8Array => {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const output = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  };
  if (entries.length === 1) return sha256(cat(Uint8Array.of(0), entries[0]));
  // k = largest power of two strictly less than n
  let k = 1;
  while (k * 2 < entries.length) k *= 2;
  return sha256(
    cat(
      Uint8Array.of(1),
      await referenceMth(entries.slice(0, k)),
      await referenceMth(entries.slice(k)),
    ),
  );
};

const geometry: PublicProfileGeometry = {
  publicChunkObjectCount: 4,
  cohortAllocationsPerWindow: 6,
  roomSlotsPerClient: 2,
  sizeClasses: [
    { id: 0, appendScheduleLength: 3, publicChunksPerWindow: 9 },
    { id: 1, appendScheduleLength: 1, publicChunksPerWindow: 3 },
  ],
};

describe("carrier and room clocks stay separate", () => {
  test("each divides by its own cadence", () => {
    expect(ingressWindow(60_000n, 180_500n)).toBe(3n);
    expect(roomLogicalWindow(15_000n, 180_500n)).toBe(12n);
    expect(ingressWindowStartMs(3n, 60_000n)).toBe(180_000n);
  });

  test("non-positive cadence and negative time are refused", () => {
    expect(() => ingressWindow(0n, 1n)).toThrow("must be positive");
    expect(() => roomLogicalWindow(-1n, 1n)).toThrow("must be positive");
    expect(() => ingressWindow(60_000n, -1n)).toThrow("must not be negative");
  });

  test("retention is inclusive of the last readable window", () => {
    // Readable through the END of w + carrierRetentionWindows.
    expect(bucketIsReadable(10n, 10n, 3)).toBe(true);
    expect(bucketIsReadable(10n, 13n, 3)).toBe(true);
    expect(bucketIsReadable(10n, 14n, 3)).toBe(false);
    expect(bucketIsReadable(10n, 9n, 3)).toBe(false);
  });
});

describe("append slot mapping is a total function of public geometry", () => {
  test("maps ordinals to the specified chunk and index", () => {
    // q_c = roomSlotsPerClient * appendSchedule.length = 2 * 3 = 6
    const first = appendSlotCoordinates(geometry, 0, 0, 0);
    expect(first.globalObjectOrdinal).toBe(0);
    expect(first.chunkIndex).toBe(0n);
    expect(first.objectIndexWithinChunk).toBe(0);
    expect(first.roomSlotOrdinal).toBe(0);
    expect(first.objectOrdinalWithinRoomSlot).toBe(0);

    const later = appendSlotCoordinates(geometry, 0, 2, 5);
    expect(later.globalObjectOrdinal).toBe(2 * 6 + 5);
    expect(later.chunkIndex).toBe(BigInt(Math.floor(17 / 4)));
    expect(later.objectIndexWithinChunk).toBe(17 % 4);
    expect(later.roomSlotOrdinal).toBe(Math.floor(5 / 3));
    expect(later.objectOrdinalWithinRoomSlot).toBe(5 % 3);
  });

  test("every ordinal pair lands in a distinct global position", () => {
    const seen = new Set<number>();
    for (let allocation = 0; allocation < 6; allocation++) {
      for (let object = 0; object < 6; object++) {
        const slot = appendSlotCoordinates(geometry, 0, allocation, object);
        expect(seen.has(slot.globalObjectOrdinal)).toBe(false);
        seen.add(slot.globalObjectOrdinal);
        expect(
          Number(slot.chunkIndex) * geometry.publicChunkObjectCount +
            slot.objectIndexWithinChunk,
        ).toBe(slot.globalObjectOrdinal);
      }
    }
    expect(seen.size).toBe(36);
  });

  test("out-of-range ordinals and unknown classes are refused", () => {
    expect(() => appendSlotCoordinates(geometry, 0, 6, 0)).toThrow(
      "outside the cohort capacity",
    );
    expect(() => appendSlotCoordinates(geometry, 0, 0, 6)).toThrow(
      "outside this allocation's slot count",
    );
    expect(() => appendSlotCoordinates(geometry, 9, 0, 0)).toThrow(
      "unknown size class",
    );
  });

  test("checkpoint leaf ordinals run size class then chunk index", () => {
    expect(profileChunkOrdinal(geometry, 0, 0n)).toBe(0);
    expect(profileChunkOrdinal(geometry, 0, 8n)).toBe(8);
    expect(profileChunkOrdinal(geometry, 1, 0n)).toBe(9);
    expect(profileChunkOrdinal(geometry, 1, 2n)).toBe(11);
    expect(profileFinalizedChunkCount(geometry)).toBe(12);
    expect(() => profileChunkOrdinal(geometry, 1, 3n)).toThrow(
      "outside this size class",
    );
  });
});

describe("RFC 9162 tree matches an independent implementation", () => {
  const entries = (count: number): Uint8Array[] =>
    Array.from({ length: count }, (_, index) =>
      Uint8Array.of(index, index + 1, index + 2),
    );

  test("leaf and node hashes carry the specified prefixes", async () => {
    const entry = Uint8Array.of(1, 2, 3);
    expect(hex(await rfc9162LeafHash(entry))).toBe(
      hex(await sha256(Uint8Array.of(0, 1, 2, 3))),
    );
    // The prefixes are what stop a leaf from colliding with an interior node.
    expect(hex(await rfc9162LeafHash(entry))).not.toBe(
      hex(await sha256(entry)),
    );
  });

  test("tree hash agrees for every size from 1 to 33", async () => {
    for (let size = 1; size <= 33; size++) {
      const data = entries(size);
      expect(hex(await rfc9162MerkleTreeHash(data))).toBe(
        hex(await referenceMth(data)),
      );
    }
  });

  test("an empty sequence is refused rather than hashed to HASH()", async () => {
    await expect(rfc9162MerkleTreeHash([])).rejects.toThrow("nonempty");
  });

  test("every audit path recomputes the root, for every leaf of every size", async () => {
    for (let size = 1; size <= 17; size++) {
      const data = entries(size);
      const root = await rfc9162MerkleTreeHash(data);
      for (let index = 0; index < size; index++) {
        const path = await rfc9162AuditPath(data, index);
        expect(path.length).toBe(rfc9162AuditPathLength(index, size));
        expect(
          hex(await rfc9162RootFromAuditPath(data[index], index, size, path)),
        ).toBe(hex(root));
      }
    }
  });

  test("a path with a missing, extra, or altered sibling fails", async () => {
    const data = entries(12);
    const root = await rfc9162MerkleTreeHash(data);
    const path = await rfc9162AuditPath(data, 5);

    await expect(
      rfc9162RootFromAuditPath(data[5], 5, 12, path.slice(0, -1)),
    ).rejects.toThrow("exact RFC 9162 sibling count");
    await expect(
      rfc9162RootFromAuditPath(data[5], 5, 12, [...path, bytes(9)]),
    ).rejects.toThrow("exact RFC 9162 sibling count");

    const altered = [...path];
    altered[0] = bytes(0xee);
    expect(
      hex(await rfc9162RootFromAuditPath(data[5], 5, 12, altered)),
    ).not.toBe(hex(root));
  });

  test("a leaf's own path does not verify at another index", async () => {
    const data = entries(8);
    const root = await rfc9162MerkleTreeHash(data);
    const path = await rfc9162AuditPath(data, 3);
    expect(hex(await rfc9162RootFromAuditPath(data[3], 4, 8, path))).not.toBe(
      hex(root),
    );
  });
});

describe("checkpoint inclusion verification", () => {
  const bucketFor = (sizeClass: number) => ({
    deliveryProfileHash: bytes(0xa1),
    ingressWindow: 42n,
    sizeClass,
  });

  const chunkFor = (sizeClass: number, chunkIndex: number): PublicChunkV1 => ({
    version: 1,
    bucket: bucketFor(sizeClass),
    chunkIndex: BigInt(chunkIndex),
    previousChunkHash: chunkIndex === 0 ? ZERO32 : bytes(chunkIndex),
    fixedObjects: [Uint8Array.of(sizeClass, chunkIndex, 7)],
    storeSignature: new Uint8Array(64).fill(sizeClass + chunkIndex),
  });

  const buildWindow = async () => {
    const chunks = new Map<number, PublicChunkV1[]>();
    const hashes = new Map<number, Uint8Array[]>();
    for (const sizeClass of geometry.sizeClasses) {
      const classChunks: PublicChunkV1[] = [];
      const classHashes: Uint8Array[] = [];
      for (let index = 0; index < sizeClass.publicChunksPerWindow; index++) {
        const chunk = chunkFor(sizeClass.id, index);
        classChunks.push(chunk);
        classHashes.push(await publicChunkHash(chunk));
      }
      chunks.set(sizeClass.id, classChunks);
      hashes.set(sizeClass.id, classHashes);
    }

    const leaves = await checkpointLeafEntries(geometry, hashes);
    const checkpoint: PublicStoreCheckpointV1 = {
      version: 1,
      storeId: bytes(0xb2),
      descriptorHash: bytes(0xb3),
      deliveryProfileHash: bytes(0xa1),
      ingressWindow: 42n,
      chainStartIngressWindow: 40n,
      previousCheckpointHash: bytes(0xc4),
      finalizedChunkCount: leaves.length,
      finalizedChunkRoot: await rfc9162MerkleTreeHash(leaves),
      storeSignature: new Uint8Array(64).fill(0xd5),
    };
    return { chunks, hashes, leaves, checkpoint };
  };

  const proofFor = async (
    leaves: readonly Uint8Array[],
    checkpoint: PublicStoreCheckpointV1,
    sizeClass: number,
    chunkIndex: number,
    chunkHash: Uint8Array,
  ): Promise<PublicCheckpointChunkInclusionProofV1> => {
    const leafIndex = profileChunkOrdinal(
      geometry,
      sizeClass,
      BigInt(chunkIndex),
    );
    return {
      version: 1,
      checkpointHash: await publicStoreCheckpointHash(checkpoint),
      leaf: {
        sizeClass,
        chunkIndex: BigInt(chunkIndex),
        publicChunkHash: chunkHash,
      },
      leafIndex,
      siblingHashes: await rfc9162AuditPath(leaves, leafIndex),
    };
  };

  test("accepts every chunk of a finalized window at its own position", async () => {
    const { chunks, hashes, leaves, checkpoint } = await buildWindow();
    expect(checkpoint.finalizedChunkCount).toBe(12);

    for (const sizeClass of geometry.sizeClasses) {
      for (let index = 0; index < sizeClass.publicChunksPerWindow; index++) {
        const verdict = await verifyCheckpointChunkInclusion(
          geometry,
          checkpoint,
          chunks.get(sizeClass.id)![index],
          await proofFor(
            leaves,
            checkpoint,
            sizeClass.id,
            index,
            hashes.get(sizeClass.id)![index],
          ),
        );
        expect(verdict.valid).toBe(true);
      }
    }
  });

  test("rejects every cross-coordinate relocation", async () => {
    const { chunks, hashes, leaves, checkpoint } = await buildWindow();
    const chunk = chunks.get(0)![2];
    const good = await proofFor(leaves, checkpoint, 0, 2, hashes.get(0)![2]);

    const cases: [string, () => Promise<unknown>][] = [
      [
        "different profile",
        () =>
          verifyCheckpointChunkInclusion(
            geometry,
            checkpoint,
            {
              ...chunk,
              bucket: { ...chunk.bucket, deliveryProfileHash: bytes(0x99) },
            },
            good,
          ),
      ],
      [
        "different window",
        () =>
          verifyCheckpointChunkInclusion(
            geometry,
            checkpoint,
            { ...chunk, bucket: { ...chunk.bucket, ingressWindow: 43n } },
            good,
          ),
      ],
      [
        "different size class",
        () =>
          verifyCheckpointChunkInclusion(
            geometry,
            checkpoint,
            { ...chunk, bucket: { ...chunk.bucket, sizeClass: 1 } },
            good,
          ),
      ],
      [
        "different chunk index",
        () =>
          verifyCheckpointChunkInclusion(
            geometry,
            checkpoint,
            { ...chunk, chunkIndex: 3n },
            good,
          ),
      ],
      [
        "another chunk's leaf index",
        async () =>
          verifyCheckpointChunkInclusion(geometry, checkpoint, chunk, {
            ...good,
            leafIndex: 5,
          }),
      ],
      [
        "another checkpoint's hash",
        async () =>
          verifyCheckpointChunkInclusion(geometry, checkpoint, chunk, {
            ...good,
            checkpointHash: bytes(0x11),
          }),
      ],
    ];

    for (const [name, run] of cases) {
      const verdict = (await run()) as { valid: boolean };
      expect(`${name}:${String(verdict.valid)}`).toBe(`${name}:false`);
    }
  });

  test("rejects a chunk whose bytes changed after signing", async () => {
    const { chunks, hashes, leaves, checkpoint } = await buildWindow();
    const chunk = chunks.get(0)![1];
    const proof = await proofFor(leaves, checkpoint, 0, 1, hashes.get(0)![1]);
    const mutated: PublicChunkV1 = {
      ...chunk,
      fixedObjects: [Uint8Array.of(9, 9, 9)],
    };
    const verdict = await verifyCheckpointChunkInclusion(
      geometry,
      checkpoint,
      mutated,
      proof,
    );
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("exact signed chunk");
  });

  test("rejects a checkpoint whose count is not the profile's", async () => {
    const { chunks, hashes, leaves, checkpoint } = await buildWindow();
    const wrongCount = { ...checkpoint, finalizedChunkCount: 11 };
    const verdict = await verifyCheckpointChunkInclusion(
      geometry,
      wrongCount,
      chunks.get(0)![0],
      await proofFor(leaves, wrongCount, 0, 0, hashes.get(0)![0]),
    );
    expect(verdict.valid).toBe(false);
  });

  test("the leaf sequence must be complete for every size class", async () => {
    await expect(
      checkpointLeafEntries(geometry, new Map([[0, [bytes(1)]]])),
    ).rejects.toThrow("must supply exactly 9 chunk hashes");
  });

  test("the signing transcript is the body, distinct from the signed hash", async () => {
    const chunk = chunkFor(0, 0);
    const { storeSignature: _signature, ...body } = chunk;
    expect(hex(await publicChunkSigningHash(body))).not.toBe(
      hex(await publicChunkHash(chunk)),
    );
  });

  test("a bucket id carries no room-derived input", async () => {
    const first = await publicBucketId(bucketFor(0));
    const second = await publicBucketId(bucketFor(0));
    expect(hex(first)).toBe(hex(second));
    expect(hex(await publicBucketId(bucketFor(1)))).not.toBe(hex(first));
  });
});

describe("checkpoint chain and conflict", () => {
  const base: PublicStoreCheckpointV1 = {
    version: 1,
    storeId: bytes(0xb2),
    descriptorHash: bytes(0xb3),
    deliveryProfileHash: bytes(0xa1),
    ingressWindow: 40n,
    chainStartIngressWindow: 40n,
    previousCheckpointHash: ZERO32,
    finalizedChunkCount: 12,
    finalizedChunkRoot: bytes(0x77),
    storeSignature: new Uint8Array(64).fill(0xd5),
  };

  test("the chain start has a zero predecessor hash", () => {
    expect(isChainStart(base)).toBe(true);
    expect(isChainStart({ ...base, previousCheckpointHash: bytes(1) })).toBe(
      false,
    );
    expect(isChainStart({ ...base, ingressWindow: 41n })).toBe(false);
  });

  test("a successor links to the exact predecessor hash", async () => {
    const next: PublicStoreCheckpointV1 = {
      ...base,
      ingressWindow: 41n,
      previousCheckpointHash: await publicStoreCheckpointHash(base),
      finalizedChunkRoot: bytes(0x78),
    };
    expect(await chainLinksSuccessor(base, next)).toBe(true);

    // A skipped window, a different chain start, or a wrong predecessor hash
    // all break linkage; none of them creates a preferred branch.
    expect(
      await chainLinksSuccessor(base, { ...next, ingressWindow: 42n }),
    ).toBe(false);
    expect(
      await chainLinksSuccessor(base, {
        ...next,
        chainStartIngressWindow: 39n,
      }),
    ).toBe(false);
    expect(
      await chainLinksSuccessor(base, {
        ...next,
        previousCheckpointHash: bytes(0x55),
      }),
    ).toBe(false);
  });

  test("two distinct checkpoints for one window conflict, in canonical order", async () => {
    const other = { ...base, finalizedChunkRoot: bytes(0x88) };
    const result = await checkpointsConflict(base, other);
    expect(result.conflicting).toBe(true);
    if (!result.conflicting) throw new Error("unreachable");

    // Canonical order is bytewise-lower checkpoint hash first, so presenting
    // the pair in either order yields one proof rather than two mirror images.
    const reversed = await checkpointsConflict(other, base);
    if (!reversed.conflicting) throw new Error("unreachable");
    expect(hex(await publicStoreCheckpointHash(result.canonicalOrder[0]))).toBe(
      hex(await publicStoreCheckpointHash(reversed.canonicalOrder[0])),
    );

    const [lower, higher] = await Promise.all([
      publicStoreCheckpointHash(result.canonicalOrder[0]),
      publicStoreCheckpointHash(result.canonicalOrder[1]),
    ]);
    expect(hex(lower) < hex(higher)).toBe(true);
  });

  test("identical checkpoints and different coordinates do not conflict", async () => {
    expect((await checkpointsConflict(base, { ...base })).conflicting).toBe(
      false,
    );
    expect(
      (
        await checkpointsConflict(base, {
          ...base,
          ingressWindow: 41n,
          finalizedChunkRoot: bytes(0x88),
        })
      ).conflicting,
    ).toBe(false);
    expect(
      (
        await checkpointsConflict(base, {
          ...base,
          storeId: bytes(0xcc),
          finalizedChunkRoot: bytes(0x88),
        })
      ).conflicting,
    ).toBe(false);
  });
});
