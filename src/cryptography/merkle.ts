import cryptoMemory from "./memory";

import libcrypto from "./libcrypto";

import { crypto_hash_sha512_BYTES } from "./interfaces";

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
  const cryptoModule =
    module ??
    (await libcrypto({
      wasmMemory,
    }));

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
 * @param {Uint8Array} element: The element.
 *
 * @returns {Promise<Uint8Array>}: The Merkle proof.
 */
export const getMerkleProof = async (
  treeHashes: Uint8Array,
  element: Uint8Array,
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
    return new Uint8Array(crypto_hash_sha512_BYTES + 1).fill(1);
  }

  const wasmMemory =
    module?.wasmMemory ?? cryptoMemory.getMerkleProofMemory(treeLen);
  const cryptoModule =
    module ??
    (await libcrypto({
      wasmMemory,
    }));

  const ptr1 = cryptoModule._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );
  leavesHashed.set(treeHashes);

  const ptr2 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  const digest = await window.crypto.subtle.digest("SHA-512", element);
  // hash = await sha512(element);
  elementHash.set(new Uint8Array(digest));

  const proofLen = treeLen * (crypto_hash_sha512_BYTES + 1);
  // Math.ceil(Math.log2(treeLen)) * (crypto_hash_sha512_BYTES + 1);
  const ptr3 = cryptoModule._malloc(proofLen);
  const proof = new Uint8Array(wasmMemory.buffer, ptr3, proofLen);

  const result = cryptoModule._get_merkle_proof(
    treeLen,
    // proofLen,
    leavesHashed.byteOffset,
    elementHash.byteOffset,
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
          const proofArray = window.crypto.getRandomValues(
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
  const cryptoModule = await libcrypto({
    wasmMemory,
  });

  const ptr1 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  const hash = await window.crypto.subtle.digest("SHA-512", item);
  elementHash.set(new Uint8Array(hash));

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
  // const wasmMemory = cryptoMemory.verifyMerkleProofMemory(proofLen);
  const cryptoModule =
    module ??
    (await libcrypto({
      wasmMemory,
    }));

  const ptr1 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  const hash = await window.crypto.subtle.digest("SHA-512", item);
  elementHash.set(new Uint8Array(hash));

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
