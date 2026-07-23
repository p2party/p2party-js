import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import libcrypto from "./libcrypto";
import cryptoMemory from "./memory";
import { getMerkleProof, getMerkleRoot } from "./merkle";
import { crypto_hash_sha512_BYTES } from "./interfaces";

const wasmFile = readFileSync(
  new URL("./libcrypto.wasm", import.meta.url),
);
const wasmBinary = wasmFile.buffer.slice(
  wasmFile.byteOffset,
  wasmFile.byteOffset + wasmFile.byteLength,
) as ArrayBuffer;

describe("operation-sized WASM memory", () => {
  test("a Merkle module sized for the send plan handles more than 16k leaves", async () => {
    const leavesLen = 16_385;
    const leaves = new Uint8Array(leavesLen * crypto_hash_sha512_BYTES);
    const view = new DataView(leaves.buffer);
    for (let index = 0; index < leavesLen; index++)
      view.setUint32(index * crypto_hash_sha512_BYTES, index, false);

    const wasmMemory = cryptoMemory.getMerkleProofMemory(leavesLen);
    const module = await libcrypto({ wasmBinary, wasmMemory });
    const root = await getMerkleRoot(leaves, module);
    const proof = await getMerkleProof(
      leaves,
      leaves.slice(0, crypto_hash_sha512_BYTES),
      module,
    );

    expect(root).toHaveLength(crypto_hash_sha512_BYTES);
    expect(proof.length).toBeGreaterThan(0);
  });
});
