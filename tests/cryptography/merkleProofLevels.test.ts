import { beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  buildMerkleProofLevels,
  getMerkleProof,
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { PROOF_LEN } from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

/** Distinct random chunks and their domain-separated leaf hashes. */
const makeTree = (
  leafCount: number,
): { items: Uint8Array[]; leaves: Uint8Array } => {
  const items: Uint8Array[] = [];
  const leaves = new Uint8Array(leafCount * crypto_hash_sha512_BYTES);
  for (let i = 0; i < leafCount; i++) {
    const item = crypto.getRandomValues(new Uint8Array(48));
    new DataView(item.buffer).setUint32(0, i);
    items.push(item);
    leaves.set(hashMerkleLeafWasm(item, module), i * crypto_hash_sha512_BYTES);
  }
  return { items, leaves };
};

const leafAt = (leaves: Uint8Array, index: number): Uint8Array =>
  leaves.subarray(
    index * crypto_hash_sha512_BYTES,
    (index + 1) * crypto_hash_sha512_BYTES,
  );

/** The module, with its SHA-512 inits and WASM proof builds counted. */
const countingModule = (
  target: LibCrypto,
): { module: LibCrypto; counts: { sha512Init: number; wasmProof: number } } => {
  const counts = { sha512Init: 0, wasmProof: 0 };
  const counted = new Proxy(target, {
    get(object, property, receiver) {
      if (property === "_sha512_init")
        return (state: number) => {
          counts.sha512Init++;
          return object._sha512_init(state);
        };
      if (property === "_get_merkle_proof")
        return (...args: Parameters<LibCrypto["_get_merkle_proof"]>) => {
          counts.wasmProof++;
          return object._get_merkle_proof(...args);
        };
      return Reflect.get(object, property, receiver) as unknown;
    },
  });
  return { module: counted, counts };
};

const LEAF_COUNTS = [1, 2, 3, 4, 5, 7, 8, 9, 1000, 1001];

describe("Merkle proof levels", () => {
  test("cached-level proofs equal getMerkleProof for all indices", async () => {
    for (const leafCount of LEAF_COUNTS) {
      const { items, leaves } = makeTree(leafCount);
      const root = await getMerkleRoot(leaves, module);
      const levels = buildMerkleProofLevels(leaves, module);
      expect(levels.leafCount).toBe(leafCount);
      expect(levels.root()).toEqual(root);

      for (let index = 0; index < leafCount; index++) {
        const leaf = leafAt(leaves, index);
        const expected = await getMerkleProof(leaves, leaf, module);
        const proof = levels.proof(index, leaf);
        expect(proof).toEqual(expected);
        expect(await verifyMerkleProof(items[index], root, proof, module)).toBe(
          true,
        );

        // The fixed-length framing the sender puts on the wire, as
        // getMerkleProof frames it: u32 BE length ‖ proof ‖ fresh padding.
        const framed = levels.proof(index, leaf, PROOF_LEN);
        expect(framed.length).toBe(PROOF_LEN);
        expect(new DataView(framed.buffer).getUint32(0, false)).toBe(
          expected.length,
        );
        expect(framed.subarray(4, 4 + expected.length)).toEqual(expected);
      }
      levels.release();
    }
    // getMerkleProof's own framing of the same proof, for one index per tree.
    const { leaves } = makeTree(9);
    const levels = buildMerkleProofLevels(leaves, module);
    const wasmFramed = await getMerkleProof(
      leaves,
      leafAt(leaves, 6),
      module,
      PROOF_LEN,
    );
    const length = new DataView(wasmFramed.buffer).getUint32(0, false);
    expect(
      levels.proof(6, leafAt(leaves, 6), PROOF_LEN).subarray(0, 4 + length),
    ).toEqual(wasmFramed.subarray(0, 4 + length));
    levels.release();
  }, 60_000);

  test("the tree is hashed once: N − 1 node hashes, no per-proof rebuild", () => {
    for (const leafCount of LEAF_COUNTS) {
      const { leaves } = makeTree(leafCount);
      const { module: counted, counts } = countingModule(module);
      const levels = buildMerkleProofLevels(leaves, counted);
      expect(counts.sha512Init).toBe(leafCount - 1);
      for (let index = 0; index < leafCount; index++)
        levels.proof(index, leafAt(leaves, index), PROOF_LEN);
      expect(counts.sha512Init).toBe(leafCount - 1);
      expect(counts.wasmProof).toBe(0);
      levels.release();
    }
  });

  test("holds about N × 64 bytes above the leaves and nothing once released", () => {
    // 19,270 leaves is a 1 GiB file at the default 0.9 fill.
    const leafCount = 19_270;
    const leaves = new Uint8Array(leafCount * crypto_hash_sha512_BYTES);
    for (let i = 0; i < leafCount; i++)
      new DataView(leaves.buffer).setUint32(i * crypto_hash_sha512_BYTES, i);
    const levels = buildMerkleProofLevels(leaves, module);
    // Levels 1..top hold 9,635 + 4,818 + ... + 1 = 19,277 nodes.
    expect(levels.byteLength).toBe(19_277 * crypto_hash_sha512_BYTES);
    levels.release();
    expect(levels.byteLength).toBe(0);
    expect(() => levels.proof(0, leafAt(leaves, 0))).toThrow("released");
    expect(() => levels.root()).toThrow("released");
  });

  test("a leaf that is not the one at its index, or an index outside the tree, is refused", () => {
    const { leaves } = makeTree(5);
    const levels = buildMerkleProofLevels(leaves, module);
    expect(() => levels.proof(1, leafAt(leaves, 2))).toThrow(
      "not the leaf at this index",
    );
    expect(() => levels.proof(5, leafAt(leaves, 0))).toThrow(RangeError);
    expect(() => levels.proof(-1, leafAt(leaves, 0))).toThrow(RangeError);
    expect(() => levels.proof(0.5, leafAt(leaves, 0))).toThrow(RangeError);
    levels.release();
  });

  test("with duplicate leaves each index gets its own path, and every path verifies", async () => {
    // getMerkleProof proves the FIRST equal leaf; the levels prove the one at
    // the index asked for. Both reach the same root.
    const item = crypto.getRandomValues(new Uint8Array(48));
    const leaf = hashMerkleLeafWasm(item, module);
    const leaves = new Uint8Array(5 * crypto_hash_sha512_BYTES);
    for (let i = 0; i < 5; i++) leaves.set(leaf, i * crypto_hash_sha512_BYTES);
    const root = await getMerkleRoot(leaves, module);
    const levels = buildMerkleProofLevels(leaves, module);
    const first = await getMerkleProof(leaves, leaf, module);
    expect(levels.proof(0, leaf)).toEqual(first);
    for (let index = 0; index < 5; index++)
      expect(
        await verifyMerkleProof(item, root, levels.proof(index, leaf), module),
      ).toBe(true);
    levels.release();
  });
});
