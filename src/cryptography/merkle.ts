import cryptoMemory from "./memory";

// import libcrypto from "./libcrypto";
import { wasmLoader } from "./wasmLoader";

import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
} from "./interfaces";
import { hashMerkleLeaf, hashMerkleLeafWasm } from "../utils/leafHash";

import type { LibCrypto } from "./libcrypto";

/**
 * @function
 * Returns the Merkle root of a tree.
 *
 * @param treeHashes: The tree, hashed.
 * @returns Promise<Uint8Array>
 */
export const getMerkleRoot = async (
  treeHashes: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> => {
  if (treeHashes.length % crypto_hash_sha512_BYTES !== 0) {
    throw new Error("Hashes were not passed");
  }

  const treeLen = treeHashes.length / crypto_hash_sha512_BYTES; // tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle root of tree with no leaves.");
  } else if (treeLen === 1) {
    return treeHashes;
  }

  const wasmMemory =
    module?.wasmMemory ?? cryptoMemory.getMerkleRootMemory(treeLen);
  const cryptoModule = module ?? (await wasmLoader(wasmMemory));
  // (await libcrypto({
  //   wasmMemory,
  // }));

  const ptr1 = cryptoModule._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );
  leavesHashed.set(treeHashes);

  const ptr2 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const rootWasm = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );

  const result = cryptoModule._get_merkle_root(
    treeLen,
    leavesHashed.byteOffset,
    rootWasm.byteOffset,
  );

  cryptoModule._free(ptr1);

  switch (result) {
    case 0: {
      const root = Uint8Array.from([...rootWasm]);
      cryptoModule._free(ptr2);

      return root;
    }

    case -1: {
      cryptoModule._free(ptr2);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -2: {
      cryptoModule._free(ptr2);

      throw new Error("Could not calculate hash.");
    }

    default: {
      cryptoModule._free(ptr2);

      throw new Error("Unexpected error occured.");
    }
  }
};

/**
 * @function
 * getMerkleProof
 *
 * @description
 * Returns the Merkle proof of an element of a tree.
 * Can be used as a receipt of a transaction etc.
 *
 * @param {Uint8Array[]} treeHashes: The tree.
 * @param {Uint8Array} elementHash: The element.
 *
 * @returns {Promise<Uint8Array>}: The Merkle proof.
 */
export const getMerkleProof = async (
  treeHashes: Uint8Array,
  elementHash: Uint8Array,
  module?: LibCrypto,
  proofFixedLen?: number,
): Promise<Uint8Array> => {
  if (treeHashes.length % crypto_hash_sha512_BYTES !== 0) {
    throw new Error("Hashes were not passed");
  }

  const treeLen = treeHashes.length / crypto_hash_sha512_BYTES; // tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  } else if (treeLen === 1) {
    // "No point in calculating proof of a tree with single leaf.",
    const proof = new Uint8Array(crypto_hash_sha512_BYTES + 1);
    proof.set(elementHash);

    if (proofFixedLen) {
      const result = crypto_hash_sha512_BYTES + 1;
      const proofArray = globalThis.crypto.getRandomValues(
        new Uint8Array(proofFixedLen),
      );

      let offset = 0;
      const proofLenBytes = 4;
      const proofLenView = new DataView(
        proofArray.buffer,
        offset,
        proofLenBytes,
      );
      proofLenView.setUint32(0, result, false); // Big-endian
      offset += proofLenBytes;

      proofArray.set(proof, offset);

      return proofArray;
    } else {
      return proof;
    }
  }

  const wasmMemory =
    module?.wasmMemory ?? cryptoMemory.getMerkleProofMemory(treeLen);
  const cryptoModule = module ?? (await wasmLoader(wasmMemory));
  // (await libcrypto({
  //   wasmMemory,
  // }));

  const ptr1 = cryptoModule._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );
  leavesHashed.set(treeHashes);

  const ptr2 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const element = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  // const digest = await window.crypto.subtle.digest("SHA-512", element);
  // hash = await sha512(element);
  // elementHash.set(new Uint8Array(digest));
  element.set(elementHash);

  const proofLen = treeLen * (crypto_hash_sha512_BYTES + 1);
  // Math.ceil(Math.log2(treeLen)) * (crypto_hash_sha512_BYTES + 1);
  const ptr3 = cryptoModule._malloc(proofLen);
  const proof = new Uint8Array(wasmMemory.buffer, ptr3, proofLen);

  const result = cryptoModule._get_merkle_proof(
    treeLen,
    // proofLen,
    leavesHashed.byteOffset,
    element.byteOffset,
    proof.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);

  switch (result) {
    case -1: {
      cryptoModule._free(ptr3);

      throw new Error("Element not in tree.");
    }

    case -2: {
      cryptoModule._free(ptr3);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -3: {
      cryptoModule._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      if (result > 0) {
        if (proofFixedLen && proofFixedLen >= result) {
          const proofArray = globalThis.crypto.getRandomValues(
            new Uint8Array(proofFixedLen),
          );

          let offset = 0;
          const proofLenBytes = 4;
          const proofLenView = new DataView(
            proofArray.buffer,
            offset,
            proofLenBytes,
          );
          proofLenView.setUint32(0, result, false); // Big-endian
          offset += proofLenBytes;

          proofArray.set(proof.slice(0, result), offset);
          cryptoModule._free(ptr3);

          return proofArray;
        } else {
          const proofArray = Uint8Array.from([...proof.slice(0, result)]);
          cryptoModule._free(ptr3);

          return proofArray;
        }
      } else {
        cryptoModule._free(ptr3);

        throw new Error("An unexpected error occured");
      }
    }
  }
};

// merkle.c's internal-node hash: SHA-512(0x01 ‖ left ‖ right).
const MERKLE_NODE_DOMAIN = 0x01;
const MERKLE_NODE_INPUT_BYTES = 1 + 2 * crypto_hash_sha512_BYTES;
const MERKLE_PROOF_ARTIFACT_BYTES = crypto_hash_sha512_BYTES + 1;

/** getMerkleProof's fixed-length framing: u32 BE length ‖ proof ‖ random. */
const frameMerkleProof = (
  proof: Uint8Array,
  proofFixedLen: number,
): Uint8Array => {
  const framed = globalThis.crypto.getRandomValues(
    new Uint8Array(proofFixedLen),
  );
  new DataView(framed.buffer, 0, 4).setUint32(0, proof.length, false);
  framed.set(proof, 4);
  return framed;
};

/**
 * Every level of one Merkle tree, built once, so the proof of any leaf is a
 * walk of at most ⌈log2 N⌉ sibling copies. `getMerkleProof` rebuilds the
 * whole tree in WASM for every call, which a sender pays once per chunk.
 */
export interface MerkleProofLevels {
  readonly leafCount: number;
  /**
   * Bytes held above the caller's leaves: about N × 64 for N leaves. Zero once
   * released.
   */
  readonly byteLength: number;
  /**
   * The proof of the leaf at `index`, framed exactly as `getMerkleProof`
   * frames it (with `proofFixedLen`: u32 BE length ‖ proof ‖ random padding).
   * For a tree of distinct leaves the bytes equal `getMerkleProof(tree,
   * leafHash)`. With duplicate leaves `getMerkleProof` proves the FIRST equal
   * leaf, and this proves the one at `index`; both verify against the root.
   * Throws when `leafHash` is not the leaf at `index`.
   */
  proof(
    index: number,
    leafHash: Uint8Array,
    proofFixedLen?: number,
  ): Uint8Array;
  /** A copy of the root, equal to `getMerkleRoot` over the same leaves. */
  root(): Uint8Array;
  /** Drop every level. Idempotent; a later `proof` or `root` throws. */
  release(): void;
}

/**
 * Build every level of the tree over `treeHashes` (the domain-separated leaf
 * hashes) with merkle.c's rules: an internal node is SHA-512(0x01 ‖ left ‖
 * right), computed by the module's libsodium SHA-512, and a lone odd node is
 * promoted unchanged. That is N − 1 node hashes, once.
 *
 * Level 0 is `treeHashes` itself, not a copy: the caller must not modify it
 * while the levels are live.
 */
export const buildMerkleProofLevels = (
  treeHashes: Uint8Array,
  module: LibCrypto,
): MerkleProofLevels => {
  if (treeHashes.length % crypto_hash_sha512_BYTES !== 0) {
    throw new Error("Hashes were not passed");
  }
  const leafCount = treeHashes.length / crypto_hash_sha512_BYTES;
  if (leafCount === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  }

  let levels: Uint8Array[] = [treeHashes];
  if (leafCount > 1) {
    const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
    const inputPtr = module._malloc(MERKLE_NODE_INPUT_BYTES);
    const outputPtr = module._malloc(crypto_hash_sha512_BYTES);
    try {
      if (!statePtr || !inputPtr || !outputPtr)
        throw new Error(
          "Could not allocate memory for hash concatenation helper array.",
        );
      // ALLOW_MEMORY_GROWTH=0: the heap never moves, so these views stay valid.
      const input = new Uint8Array(
        module.wasmMemory.buffer,
        inputPtr,
        MERKLE_NODE_INPUT_BYTES,
      );
      const output = new Uint8Array(
        module.wasmMemory.buffer,
        outputPtr,
        crypto_hash_sha512_BYTES,
      );
      input[0] = MERKLE_NODE_DOMAIN;
      let below = treeHashes;
      let nodes = leafCount;
      while (nodes > 1) {
        const parents = Math.ceil(nodes / 2);
        const level = new Uint8Array(parents * crypto_hash_sha512_BYTES);
        for (let j = 0; j < parents; j++) {
          const left = 2 * j * crypto_hash_sha512_BYTES;
          if (2 * j + 1 === nodes) {
            level.set(
              below.subarray(left, left + crypto_hash_sha512_BYTES),
              j * crypto_hash_sha512_BYTES,
            );
            continue;
          }
          input.set(
            below.subarray(left, left + 2 * crypto_hash_sha512_BYTES),
            1,
          );
          if (
            module._sha512_init(statePtr) !== 0 ||
            module._sha512_update(
              statePtr,
              inputPtr,
              MERKLE_NODE_INPUT_BYTES,
            ) !== 0 ||
            module._sha512_final(statePtr, outputPtr) !== 0
          )
            throw new Error("Could not calculate hash.");
          level.set(output, j * crypto_hash_sha512_BYTES);
        }
        levels.push(level);
        below = level;
        nodes = parents;
      }
    } finally {
      module._free(statePtr);
      module._free(inputPtr);
      module._free(outputPtr);
    }
  }

  let released = false;
  return {
    leafCount,
    get byteLength(): number {
      let bytes = 0;
      for (let l = 1; l < levels.length; l++) bytes += levels[l].length;
      return bytes;
    },
    proof(
      index: number,
      leafHash: Uint8Array,
      proofFixedLen?: number,
    ): Uint8Array {
      if (released) throw new Error("Merkle proof levels were released.");
      if (!Number.isSafeInteger(index) || index < 0 || index >= leafCount)
        throw new RangeError("Merkle leaf index is out of range.");
      const leafStart = index * crypto_hash_sha512_BYTES;
      if (
        leafHash.length !== crypto_hash_sha512_BYTES ||
        leafHash.some((byte, i) => byte !== levels[0][leafStart + i])
      )
        throw new Error("Element is not the leaf at this index.");

      if (leafCount === 1) {
        const proof = new Uint8Array(MERKLE_PROOF_ARTIFACT_BYTES);
        proof.set(leafHash);
        return proofFixedLen ? frameMerkleProof(proof, proofFixedLen) : proof;
      }

      const artifacts = new Uint8Array(
        (levels.length - 1) * MERKLE_PROOF_ARTIFACT_BYTES,
      );
      let emitted = 0;
      let position = index;
      for (let l = 0; l < levels.length - 1; l++) {
        const level = levels[l];
        const nodes = level.length / crypto_hash_sha512_BYTES;
        // A lone odd node is promoted, so it contributes no artifact.
        if (nodes % 2 === 1 && position === nodes - 1) {
          position >>>= 1;
          continue;
        }
        const siblingIsRight = position % 2 === 0;
        const sibling =
          (siblingIsRight ? position + 1 : position - 1) *
          crypto_hash_sha512_BYTES;
        const at = emitted * MERKLE_PROOF_ARTIFACT_BYTES;
        artifacts.set(
          level.subarray(sibling, sibling + crypto_hash_sha512_BYTES),
          at,
        );
        artifacts[at + crypto_hash_sha512_BYTES] = siblingIsRight ? 1 : 0;
        emitted++;
        position >>>= 1;
      }
      const proof = artifacts.slice(0, emitted * MERKLE_PROOF_ARTIFACT_BYTES);
      return proofFixedLen && proofFixedLen >= proof.length
        ? frameMerkleProof(proof, proofFixedLen)
        : proof;
    },
    root(): Uint8Array {
      if (released) throw new Error("Merkle proof levels were released.");
      return levels[levels.length - 1].slice(0, crypto_hash_sha512_BYTES);
    },
    release(): void {
      released = true;
      levels = [];
    },
  };
};

/**
 * @function
 * Calculates the Merkle root from the element hash and its Merkle proof.
 *
 * @param hash: The hash of the base element in question.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 *
 * @returns The Merkle root
 */
export const getMerkleRootFromProof = async (
  item: Uint8Array,
  proof: Uint8Array,
): Promise<Uint8Array> => {
  const proofLen = proof.length;
  if (proofLen % (crypto_hash_sha512_BYTES + 1) !== 0)
    throw new Error("Proof length not multiple of hash length + 1.");
  const proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  const wasmMemory = cryptoMemory.verifyMerkleProofMemory(proofLen);
  const cryptoModule = await wasmLoader(wasmMemory);
  // const cryptoModule = await libcrypto({
  //   wasmMemory,
  // });

  const ptr1 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  elementHash.set(await hashMerkleLeaf(item));

  const ptr2 = cryptoModule._malloc(proofLen);
  const proofArray = new Uint8Array(wasmMemory.buffer, ptr2, proofLen);
  proofArray.set(proof);

  const ptr3 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const rootArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_hash_sha512_BYTES,
  );

  const result = cryptoModule._get_merkle_root_from_proof(
    proofArtifactsLen,
    elementHash.byteOffset,
    proofArray.byteOffset,
    rootArray.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);

  switch (result) {
    case 0: {
      const proof = Uint8Array.from([...rootArray]);
      cryptoModule._free(ptr3);

      return proof;
    }

    case -1: {
      cryptoModule._free(ptr3);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -2: {
      cryptoModule._free(ptr3);

      throw new Error("Proof artifact position is neither left nor right.");
    }

    case -3: {
      cryptoModule._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      cryptoModule._free(ptr3);

      throw new Error("Unexpected error occured.");
    }
  }
};

/**
 * Verifies that the hash was indeed included in the calculation of the Merkle root.
 * @param hash: The hash of the base element in question.
 * @param root: The Merkle root.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 */
export const verifyMerkleProof = async (
  item: Uint8Array,
  root: Uint8Array,
  proof: Uint8Array,
  module?: LibCrypto,
): Promise<boolean> => {
  const proofLen = proof.length;
  if (proofLen % (crypto_hash_sha512_BYTES + 1) !== 0)
    throw new Error("Proof length not multiple of hash length + 1.");

  const proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  const wasmMemory =
    module?.wasmMemory ?? cryptoMemory.verifyMerkleProofMemory(proofLen);
  const cryptoModule = module ?? (await wasmLoader(wasmMemory));
  // (await libcrypto({
  //   wasmMemory,
  // }));

  const ptr1 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  // Receive-side leaf hash in libsodium (C), not browser crypto.
  elementHash.set(hashMerkleLeafWasm(item, cryptoModule));

  const ptr2 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const rootArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  rootArray.set(root);

  const ptr3 = cryptoModule._malloc(proofLen);
  const proofArray = new Uint8Array(wasmMemory.buffer, ptr3, proofLen);
  proofArray.set(proof);

  const result = cryptoModule._verify_merkle_proof(
    proofArtifactsLen,
    elementHash.byteOffset,
    rootArray.byteOffset,
    proofArray.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);

  switch (result) {
    case 0:
      return true;

    case 1:
      return false;

    case -1:
      throw new Error("If 1 artifact then proof is its hash");

    case -2:
      throw new Error("Could not allocate memory for hashes helper array.");

    case -3:
      throw new Error("Proof artifact position is neither left nor right.");

    case -4:
      throw new Error("Could not calculate hash.");

    default:
      throw new Error("Unexpected error occured.");
  }
};
