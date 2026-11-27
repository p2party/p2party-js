import { beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  getMerkleProof,
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import provenance from "../../src/cryptography/libcrypto.provenance.json";
import { loadTestModule } from "../../src/cryptography/testModule";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";

// A reproducible stream for synthetic data. Each case owns its own state.
const seededWords = (seed: number) => () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
};

// Independent SHA-512 oracle for the protocol's domain separation and its
// rule that an unpaired node moves to the next level unchanged.
const referenceRoot = (chunks: Uint8Array[]) => {
  let level = chunks.map((chunk) =>
    createHash("sha512").update(Uint8Array.of(0)).update(chunk).digest(),
  );
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1];
      next.push(
        right
          ? createHash("sha512")
              .update(Uint8Array.of(1))
              .update(left)
              .update(right)
              .digest()
          : left,
      );
    }
    level = next;
  }
  return new Uint8Array(level[0]);
};

const seed = 0x50325035;
const sizes = [1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65];
const nextSize = seededWords(seed);
const trees = [
  ...sizes,
  ...Array.from({ length: 17 }, () => 1 + (nextSize() % 65)),
];
const boundaryLengths = [
  0, 1, 63, 64, 110, 111, 112, 126, 127, 128, 129, 255, 256, 511, 512,
];

describe("compiled WASM Merkle properties", () => {
  let wasm: LibCrypto;
  beforeAll(async () => {
    const bytes = readFileSync(
      new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
    );
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      provenance.artifact.sha256,
    );
    wasm = await loadTestModule();
  });

  for (const [caseIndex, leafCount] of trees.entries()) {
    test(`case ${caseIndex}, ${leafCount} leaves`, async () => {
      const next = seededWords(seed + caseIndex + 1);
      const chunks = Array.from({ length: leafCount }, (_, index) => {
        const boundary =
          boundaryLengths[(caseIndex + index) % boundaryLengths.length];
        const length = index % 2 === 0 ? boundary : next() % 513;
        return Uint8Array.from({ length }, () => next() & 255);
      });
      const hashes = chunks.map((chunk) => hashMerkleLeafWasm(chunk, wasm));
      const leaves = Buffer.concat(hashes);
      const root = await getMerkleRoot(leaves, wasm);
      expect(root).toEqual(referenceRoot(chunks));

      for (const index of new Set([0, leafCount - 1, next() % leafCount])) {
        const chunk = chunks[index];
        const proof = await getMerkleProof(leaves, hashes[index], wasm);
        expect(await verifyMerkleProof(chunk, root, proof, wasm)).toBe(true);

        const changedChunk = chunk.length ? chunk.slice() : Uint8Array.of(0);
        changedChunk[next() % changedChunk.length] ^= 1;
        expect(await verifyMerkleProof(changedChunk, root, proof, wasm)).toBe(
          false,
        );

        const changedRoot = Uint8Array.from(root);
        changedRoot[next() % changedRoot.length] ^= 1;
        expect(await verifyMerkleProof(chunk, changedRoot, proof, wasm)).toBe(
          false,
        );

        // A singleton root already authenticates its leaf. Larger trees
        // authenticate it through at least one sibling hash in the proof.
        if (leafCount > 1) {
          const changedProof = proof.slice();
          changedProof[next() % 64] ^= 1;
          expect(await verifyMerkleProof(chunk, root, changedProof, wasm)).toBe(
            false,
          );
        }
      }
    });
  }
});
