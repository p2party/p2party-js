import { beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import * as merkle from "../../src/cryptography/merkle";
import {
  buildMerkleProofLevels,
  getMerkleProof,
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import {
  PROOF_LEN,
  PROOF_LEVEL_BUILD_SLICE_MS,
  PROOF_LEVEL_MAX_HASHES_PER_SLICE,
} from "../../src/utils/constants";
import { uint8ArrayToHex } from "../../src/utils/uint8array";

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
      const levels = await buildMerkleProofLevels(leaves, module);
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
    const levels = await buildMerkleProofLevels(leaves, module);
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

  test("every proofFixedLen is framed, left raw or refused exactly as getMerkleProof does", async () => {
    // getMerkleProof frames a single-leaf proof whenever proofFixedLen is set
    // and a larger tree's only when proofFixedLen >= its length; a length
    // that leaves no room for the 4-byte prefix is refused by both.
    const outcome = async (
      prove: () => Promise<Uint8Array> | Uint8Array,
    ): Promise<string> => {
      try {
        const proof = await prove();
        return `${String(proof.length)}:${uint8ArrayToHex(proof.subarray(0, 4))}`;
      } catch (error) {
        return `throws ${(error as Error).name}`;
      }
    };
    for (const leafCount of [1, 2, 3, 5]) {
      const { leaves } = makeTree(leafCount);
      const levels = await buildMerkleProofLevels(leaves, module);
      for (let index = 0; index < leafCount; index++) {
        const leaf = leafAt(leaves, index);
        const raw = await getMerkleProof(leaves, leaf, module);
        for (let fixed = 1; fixed <= raw.length + 8; fixed++) {
          const expected = await outcome(() =>
            getMerkleProof(leaves, leaf, module, fixed),
          );
          expect(await outcome(() => levels.proof(index, leaf, fixed))).toBe(
            expected,
          );
        }
      }
      levels.release();
    }
  });

  test("the tree is hashed once: N − 1 node hashes, no per-proof rebuild", async () => {
    for (const leafCount of LEAF_COUNTS) {
      const { leaves } = makeTree(leafCount);
      const { module: counted, counts } = countingModule(module);
      const levels = await buildMerkleProofLevels(leaves, counted);
      expect(counts.sha512Init).toBe(leafCount - 1);
      for (let index = 0; index < leafCount; index++)
        levels.proof(index, leafAt(leaves, index), PROOF_LEN);
      expect(counts.sha512Init).toBe(leafCount - 1);
      expect(counts.wasmProof).toBe(0);
      levels.release();
    }
  });

  test("holds about N × 64 bytes above the leaves and nothing once released", async () => {
    // 19,270 leaves is a 1 GiB file at the default 0.9 fill.
    const leafCount = 19_270;
    const leaves = new Uint8Array(leafCount * crypto_hash_sha512_BYTES);
    for (let i = 0; i < leafCount; i++)
      new DataView(leaves.buffer).setUint32(i * crypto_hash_sha512_BYTES, i);
    const levels = await buildMerkleProofLevels(leaves, module);
    // Levels 1..top hold 9,635 + 4,818 + ... + 1 = 19,277 nodes.
    expect(levels.byteLength).toBe(19_277 * crypto_hash_sha512_BYTES);
    levels.release();
    expect(levels.byteLength).toBe(0);
    expect(() => levels.proof(0, leafAt(leaves, 0))).toThrow("released");
    expect(() => levels.root()).toThrow("released");
  });

  test("a leaf that is not the one at its index, or an index outside the tree, is refused", async () => {
    const { leaves } = makeTree(5);
    const levels = await buildMerkleProofLevels(leaves, module);
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
    const levels = await buildMerkleProofLevels(leaves, module);
    const first = await getMerkleProof(leaves, leaf, module);
    expect(levels.proof(0, leaf)).toEqual(first);
    for (let index = 0; index < 5; index++)
      expect(
        await verifyMerkleProof(item, root, levels.proof(index, leaf), module),
      ).toBe(true);
    levels.release();
  });
});

/**
 * A clock that only the build's own hashes move: each SHA-512 init costs
 * `costMs`. What a slice held is the clock's advance between two hand-backs.
 */
const countingClock = (target: LibCrypto, costMs: number) => {
  const state = { now: 0, hashes: 0 };
  const counted = new Proxy(target, {
    get(object, property, receiver) {
      if (property === "_sha512_init")
        return (statePtr: number) => {
          state.hashes++;
          state.now += costMs;
          return object._sha512_init(statePtr);
        };
      return Reflect.get(object, property, receiver) as unknown;
    },
  });
  return { module: counted, state, now: () => state.now };
};

describe("the proof-level build shares the thread", () => {
  test("the proof-level build yields within its slice budget", async () => {
    // A hash costs 0.3 of a slice, so a slice fits three of them and not a
    // fourth: a check made only after a hash would let a slice hold 1.2.
    const leafCount = 1_001;
    const { items, leaves } = makeTree(leafCount);
    const clock = countingClock(module, 0.3 * PROOF_LEVEL_BUILD_SLICE_MS);
    const held: number[] = [];
    let resumedAt = 0;
    const levels = await buildMerkleProofLevels(leaves, clock.module, {
      now: clock.now,
      yieldToEventLoop: async () => {
        held.push(clock.now() - resumedAt);
        await Promise.resolve();
        resumedAt = clock.now();
      },
    });
    held.push(clock.now() - resumedAt);

    expect(clock.state.hashes).toBe(leafCount - 1);
    // ⌈1,000 / 3⌉ slices: every one but the last holds three hashes, none
    // more than the budget.
    expect(held).toHaveLength(Math.ceil((leafCount - 1) / 3));
    for (const slice of held)
      expect(slice).toBeLessThanOrEqual(PROOF_LEVEL_BUILD_SLICE_MS);
    // Built across 334 slices, the tree is the one the WASM builds in one.
    const root = await getMerkleRoot(leaves, module);
    expect(levels.root()).toEqual(root);
    for (const index of [0, 1, 499, 999, 1_000])
      expect(
        await verifyMerkleProof(
          items[index],
          root,
          levels.proof(index, leafAt(leaves, index)),
          module,
        ),
      ).toBe(true);
    levels.release();
  });

  test.each(["frozen", "100 ms steps"])(
    "each slice bounds its hash count with a %s clock",
    async (resolution) => {
      const leafCount = 2 * PROOF_LEVEL_MAX_HASHES_PER_SLICE + 3;
      const { leaves } = makeTree(leafCount);
      const clock = countingClock(module, 0.3);
      const sliceHashes: number[] = [];
      let previous = 0;
      const record = () => {
        sliceHashes.push(clock.state.hashes - previous);
        previous = clock.state.hashes;
      };
      const levels = await buildMerkleProofLevels(leaves, clock.module, {
        now: () =>
          resolution === "frozen" ? 0 : Math.floor(clock.now() / 100) * 100,
        yieldToEventLoop: async () => {
          record();
          await Promise.resolve();
        },
      });
      record();
      expect(Math.max(...sliceHashes)).toBe(PROOF_LEVEL_MAX_HASHES_PER_SLICE);
      expect(clock.state.hashes).toBe(leafCount - 1);
      expect(levels.root()).toEqual(await getMerkleRoot(leaves, module));
      levels.release();
    },
  );

  test("concurrent trees share one runnable slice per task", async () => {
    const { leaves } = makeTree(2 * PROOF_LEVEL_MAX_HASHES_PER_SLICE + 1);
    const clock = countingClock(module, 0);
    const wake = new MessageChannel();
    const wakeCount = new Promise<number>((resolve) => {
      wake.port1.onmessage = () => resolve(clock.state.hashes);
    });
    const probe = new Proxy(clock.module, {
      get(target, prop, receiver) {
        if (prop === "_sha512_init")
          return (ptr: number) => {
            if (!clock.state.hashes) wake.port2.postMessage(null);
            return target._sha512_init(ptr);
          };
        return Reflect.get(target, prop, receiver) as unknown;
      },
    });
    try {
      const builds = Array.from({ length: 6 }, () =>
        buildMerkleProofLevels(leaves, probe, { now: clock.now }),
      );
      expect(clock.state.hashes).toBe(0);
      const levels = await Promise.all(builds);
      expect(await wakeCount).toBe(PROOF_LEVEL_MAX_HASHES_PER_SLICE);
      const expectedRoot = await getMerkleRoot(leaves, module);
      for (const tree of levels) {
        expect(tree.root()).toEqual(expectedRoot);
        tree.release();
      }
    } finally {
      wake.port1.close();
      wake.port2.close();
    }
  });

  test("between slices a task queued during one runs before the next", async () => {
    // The default hand-back is a task: a message that arrives while a slice
    // runs (as a timer worker's wake-up does) is handled before the next
    // slice, not after the whole build.
    const leafCount = 41;
    const { leaves } = makeTree(leafCount);
    const clock = countingClock(module, PROOF_LEVEL_BUILD_SLICE_MS / 2);
    const wakeUp = new MessageChannel();
    let hashesWhenWoken = -1;
    wakeUp.port1.onmessage = () => {
      hashesWhenWoken = clock.state.hashes;
    };
    try {
      const counted = new Proxy(clock.module, {
        get(object, property, receiver) {
          if (property === "_sha512_init")
            return (statePtr: number) => {
              // The wake-up arrives during the first slice's first hash.
              if (clock.state.hashes === 0) wakeUp.port2.postMessage(null);
              return object._sha512_init(statePtr);
            };
          return Reflect.get(object, property, receiver) as unknown;
        },
      });
      const levels = await buildMerkleProofLevels(leaves, counted, {
        now: clock.now,
      });
      expect(clock.state.hashes).toBe(leafCount - 1);
      // Two hashes fit a slice: it was handled after the first slice.
      expect(hashesWhenWoken).toBe(2);
      levels.release();
    } finally {
      wakeUp.port1.close();
      wakeUp.port2.close();
    }
  });

  test("a stopped build does no more work after its slice and drops what it built", async () => {
    const leafCount = 101;
    const { leaves } = makeTree(leafCount);
    const clock = countingClock(module, PROOF_LEVEL_BUILD_SLICE_MS / 2);
    const stop = new AbortController();
    const reason = new Error("stopped");
    let handBacks = 0;
    const build = merkle.startMerkleProofLevelsBuild(leaves, clock.module, {
      now: clock.now,
      signal: stop.signal,
      yieldToEventLoop: async () => {
        handBacks++;
        // Stopped while the third slice's hand-back is pending.
        if (handBacks === 3) {
          expect(build.byteLength).toBeGreaterThan(0);
          stop.abort(reason);
        }
        await Promise.resolve();
      },
    });
    await expect(build.done).rejects.toBe(reason);
    expect(clock.state.hashes).toBe(6);
    expect(handBacks).toBe(3);
    expect(build.byteLength).toBe(0);
  });
});
