import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
} from "../cryptography/interfaces";

import type { LibCrypto } from "../cryptography/libcrypto";

// Merkle leaf domain byte (0x00). Internal nodes use 0x01 (in merkle.c), so an
// internal-node hash can never be reinterpreted as a leaf (CVE-2012-2459 class).
// Receipts do NOT expose this leaf directly: receiptToken.ts binds it to the
// message root and chunk index before the receiver sends a 64-byte token.
export const MERKLE_LEAF_DOMAIN = 0x00;

/**
 * Domain-separated Merkle leaf hash computed in **libsodium (C)**:
 * `SHA-512(0x00 ‖ chunk)`, byte-identical to the WebCrypto `hashMerkleLeaf`
 * above and to the C `receive_message_with_key` leaf (pake_ratchet.c:155-164).
 * Synchronous — the WASM SHA-512 runs inline (init → update(0x00 ‖ chunk) →
 * final). Used on the RECEIVE path (Merkle verification + the receipt token) so
 * every leaf hash there is libsodium rather than browser crypto. `module` must
 * expose `_sha512_init/update/final` + `_malloc/_free` (the main crypto module).
 */
export const hashMerkleLeafWasm = (
  chunk: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const bufPtr = module._malloc(1 + chunk.length);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  try {
    // ALLOW_MEMORY_GROWTH=0 → the heap never grows, so this view stays valid.
    const buf = new Uint8Array(module.wasmMemory.buffer, bufPtr, 1 + chunk.length);
    buf[0] = MERKLE_LEAF_DOMAIN;
    buf.set(chunk, 1);

    if (module._sha512_init(statePtr) !== 0)
      throw new Error("hashMerkleLeafWasm: sha512_init failed");
    if (module._sha512_update(statePtr, bufPtr, 1 + chunk.length) !== 0)
      throw new Error("hashMerkleLeafWasm: sha512_update failed");
    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("hashMerkleLeafWasm: sha512_final failed");

    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outPtr, crypto_hash_sha512_BYTES),
    );
  } finally {
    module._free(statePtr);
    module._free(bufPtr);
    module._free(outPtr);
  }
};

export const hashMerkleLeaf = async (
  chunk: Uint8Array,
): Promise<Uint8Array> => {
  const buf = new Uint8Array(1 + chunk.length);
  buf[0] = MERKLE_LEAF_DOMAIN;
  buf.set(chunk, 1);
  const digest = await window.crypto.subtle.digest(
    "SHA-512",
    buf as Uint8Array<ArrayBuffer>,
  );

  return new Uint8Array(digest);
};
