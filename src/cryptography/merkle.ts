import cryptoMemory from "./memory";

// import libcrypto from "./libcrypto";
import { wasmLoader } from "./wasmLoader";

import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
} from "./interfaces";
import { hashMerkleLeaf, hashMerkleLeafWasm } from "../utils/leafHash";
import {
  MERKLE_NODE_DOMAIN,
  PROOF_LEVEL_BUILD_SLICE_MS,
} from "../utils/constants";

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

/** How a proof-level build shares the thread it runs on. */
export interface MerkleProofLevelsBuildOptions {
  /**
   * The longest one slice of the build may hold the thread, in ms of `now`.
   * Defaults to PROOF_LEVEL_BUILD_SLICE_MS.
   */
  readonly sliceMs?: number;
  /** The clock slices are timed on. Defaults to `performance.now`. */
  readonly now?: () => number;
  /**
   * Hands the thread back between slices, until the event loop has run what
   * was queued meanwhile. Defaults to a message to the build's own
   * MessageChannel: a task, never throttled as a hidden page's timers are, and
   * queued behind a timer worker's message that arrived during the slice.
   */
  readonly yieldToEventLoop?: () => Promise<void>;
  /** Stops the build at its next slice; it then rejects with the reason. */
  readonly signal?: AbortSignal;
}

/** A proof-level build that is running, or has ended. */
export interface MerkleProofLevelsBuild {
  /** The levels, or the build's error, or the stop signal's reason. */
  readonly done: Promise<MerkleProofLevels>;
  /**
   * Bytes the levels built so far hold above the leaves. Zero once the build
   * has ended: when it succeeds the levels it settles with hold them; when it
   * fails or is stopped they are dropped, at the slice it stops in.
   */
  readonly byteLength: number;
}

/**
 * Build every level of the tree over `treeHashes` (the domain-separated leaf
 * hashes) with merkle.c's rules: an internal node is SHA-512(0x01 ‖ left ‖
 * right), computed by the module's libsodium SHA-512, and a lone odd node is
 * promoted unchanged. That is N − 1 node hashes, once.
 *
 * The build runs in slices. A slice stops before the hash that would take it
 * past `sliceMs` at the slice's own rate so far, then the thread is handed
 * back (`yieldToEventLoop`) before the next one: so on a page, a timer or a
 * message that falls due during the build waits at most one slice, not the
 * whole build (Chromium, 1,600,000 leaves: 3.9 s in one call; see
 * docs/e2e/cover-timers/). A slice hashes at least one node, so a hash that
 * alone takes longer than `sliceMs` (which no measured one did) overruns it.
 *
 * Level 0 is `treeHashes` itself, not a copy: the caller must not modify it
 * while the levels are live.
 */
export const startMerkleProofLevelsBuild = (
  treeHashes: Uint8Array,
  module: LibCrypto,
  options: MerkleProofLevelsBuildOptions = {},
): MerkleProofLevelsBuild => {
  let built: Uint8Array[] = [];
  const done = runMerkleProofLevelsBuild(treeHashes, module, options, (level) =>
    built.push(level),
  ).finally(() => {
    built = [];
  });
  return {
    done,
    get byteLength(): number {
      let bytes = 0;
      for (const level of built) bytes += level.length;
      return bytes;
    },
  };
};

/** `startMerkleProofLevelsBuild`, for a caller that only needs the levels. */
export const buildMerkleProofLevels = (
  treeHashes: Uint8Array,
  module: LibCrypto,
  options: MerkleProofLevelsBuildOptions = {},
): Promise<MerkleProofLevels> =>
  startMerkleProofLevelsBuild(treeHashes, module, options).done;

const runMerkleProofLevelsBuild = async (
  treeHashes: Uint8Array,
  module: LibCrypto,
  options: MerkleProofLevelsBuildOptions,
  onLevel: (level: Uint8Array) => void,
): Promise<MerkleProofLevels> => {
  if (treeHashes.length % crypto_hash_sha512_BYTES !== 0) {
    throw new Error("Hashes were not passed");
  }
  const leafCount = treeHashes.length / crypto_hash_sha512_BYTES;
  if (leafCount === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  }
  const sliceMs = options.sliceMs ?? PROOF_LEVEL_BUILD_SLICE_MS;
  if (!Number.isFinite(sliceMs) || sliceMs <= 0)
    throw new RangeError("Proof-level build slice must be a positive time.");
  const now = options.now ?? (() => performance.now());
  const signal = options.signal;
  signal?.throwIfAborted();

  let levels: Uint8Array[] = [treeHashes];
  if (leafCount > 1) {
    let channel: MessageChannel | undefined;
    const yieldToEventLoop =
      options.yieldToEventLoop ??
      (() =>
        new Promise<void>((resolve) => {
          channel ??= new MessageChannel();
          channel.port1.onmessage = () => {
            resolve();
          };
          channel.port2.postMessage(null);
        }));
    const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
    const inputPtr = module._malloc(MERKLE_NODE_INPUT_BYTES);
    const outputPtr = module._malloc(crypto_hash_sha512_BYTES);
    try {
      if (!statePtr || !inputPtr || !outputPtr)
        throw new Error(
          "Could not allocate memory for hash concatenation helper array.",
        );
      // ALLOW_MEMORY_GROWTH=0: the heap never moves, so these views stay
      // valid across slices, whatever else uses the module between them.
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
      let parents = Math.ceil(nodes / 2);
      let level = new Uint8Array(parents * crypto_hash_sha512_BYTES);
      onLevel(level);
      let j = 0;
      for (;;) {
        // One slice, synchronous: the thread is held from here to its end.
        const sliceStart = now();
        let hashed = 0;
        while (nodes > 1) {
          if (j === parents) {
            levels.push(level);
            below = level;
            nodes = parents;
            if (nodes === 1) break;
            parents = Math.ceil(nodes / 2);
            level = new Uint8Array(parents * crypto_hash_sha512_BYTES);
            onLevel(level);
            j = 0;
          }
          const left = 2 * j * crypto_hash_sha512_BYTES;
          if (2 * j + 1 === nodes) {
            level.set(
              below.subarray(left, left + crypto_hash_sha512_BYTES),
              j * crypto_hash_sha512_BYTES,
            );
            j++;
            continue;
          }
          if (hashed > 0) {
            const held = now() - sliceStart;
            if (held + held / hashed > sliceMs) break;
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
          hashed++;
          j++;
        }
        if (nodes === 1) break;
        await yieldToEventLoop();
        signal?.throwIfAborted();
      }
    } finally {
      module._free(statePtr);
      module._free(inputPtr);
      module._free(outputPtr);
      channel?.port1.close();
      channel?.port2.close();
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
