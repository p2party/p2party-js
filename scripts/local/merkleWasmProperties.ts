import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  getMerkleProof,
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
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

const requestedSeed = process.argv[2] ?? "0x50325035";
const seed = Number(requestedSeed);
if (
  process.argv.length > 3 ||
  !/^(?:0x[\da-f]+|\d+)$/i.test(requestedSeed) ||
  !Number.isInteger(seed) ||
  seed < 1 ||
  seed > 0xffffffff
) {
  throw new Error(
    "Expected a nonzero 32-bit seed, written in decimal or hexadecimal.",
  );
}
const sizes = [1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65];
const nextSize = seededWords(seed);
const trees = [
  ...sizes,
  ...Array.from({ length: 17 }, () => 1 + (nextSize() % 65)),
];
const boundaryLengths = [
  0, 1, 63, 64, 110, 111, 112, 126, 127, 128, 129, 255, 256, 511, 512,
];

const wasmBytes = readFileSync(
  new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
);
assert.equal(
  createHash("sha256").update(wasmBytes).digest("hex"),
  provenance.artifact.sha256,
  "WASM provenance digest",
);
const wasm = await loadTestModule();
const seedLabel = `0x${seed.toString(16)}`;
for (const [caseIndex, leafCount] of trees.entries()) {
  const context = `seed ${seedLabel}, case ${caseIndex}, ${leafCount} leaves`;
  const next = seededWords((seed + caseIndex + 1) >>> 0 || 1);
  const chunks = Array.from({ length: leafCount }, (_, index) => {
    const boundary =
      boundaryLengths[(caseIndex + index) % boundaryLengths.length];
    const length = index % 2 === 0 ? boundary : next() % 513;
    return Uint8Array.from({ length }, () => next() & 255);
  });
  const hashes = chunks.map((chunk) => hashMerkleLeafWasm(chunk, wasm));
  const leaves = Buffer.concat(hashes);
  const root = await getMerkleRoot(leaves, wasm);
  assert.deepEqual(
    Uint8Array.from(root),
    referenceRoot(chunks),
    `${context}: root`,
  );
  for (const index of new Set([0, leafCount - 1, next() % leafCount])) {
    const label = `${context}, leaf ${index}`;
    const chunk = chunks[index];
    const proof = await getMerkleProof(leaves, hashes[index], wasm);
    assert.equal(
      await verifyMerkleProof(chunk, root, proof, wasm),
      true,
      `${label}: valid proof`,
    );
    const changedChunk = chunk.length ? chunk.slice() : Uint8Array.of(0);
    changedChunk[next() % changedChunk.length] ^= 1;
    assert.equal(
      await verifyMerkleProof(changedChunk, root, proof, wasm),
      false,
      `${label}: changed payload`,
    );
    const changedRoot = Uint8Array.from(root);
    changedRoot[next() % changedRoot.length] ^= 1;
    assert.equal(
      await verifyMerkleProof(chunk, changedRoot, proof, wasm),
      false,
      `${label}: changed root`,
    );
    // A singleton root already authenticates its leaf. Larger trees
    // authenticate it through at least one sibling hash in the proof.
    if (leafCount > 1) {
      const changedProof = proof.slice();
      changedProof[next() % 64] ^= 1;
      assert.equal(
        await verifyMerkleProof(chunk, root, changedProof, wasm),
        false,
        `${label}: changed sibling hash`,
      );
    }
  }
}
console.log(
  `Verified ${trees.length} Merkle trees with seed ${seedLabel} and WASM ${provenance.artifact.sha256}.`,
);
