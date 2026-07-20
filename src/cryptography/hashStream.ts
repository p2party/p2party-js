import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
} from "./interfaces";

import { HASH_WINDOW_BYTES, HASH_WASM_CHUNK_BYTES } from "../utils/constants";

import type { LibCrypto } from "./libcrypto";

/**
 * Compute the plain SHA-512 of a File incrementally: read it one
 * HASH_WINDOW_BYTES slice at a time (O(1) memory — the whole file is never
 * resident) and feed each slice to the WASM streaming hash in
 * HASH_WASM_CHUNK_BYTES sub-chunks (the WASM heap buffer is tiny and fixed,
 * since the merkle module's memory cannot grow). The result is byte-identical
 * to `crypto.subtle.digest("SHA-512", <whole file>)` (plain SHA-512, no domain
 * separation), so it drops in for the previous whole-file-in-RAM digest.
 *
 * @param file - the File to hash (disk-backed; slices load lazily).
 * @param module - a LibCrypto exposing _sha512_init/update/final + _malloc/_free.
 * @returns the 64-byte SHA-512 digest.
 */
export const hashFileStreaming = async (
  file: File,
  module: LibCrypto,
): Promise<Uint8Array> => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const bufPtr = module._malloc(HASH_WASM_CHUNK_BYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);

  try {
    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");

    // ALLOW_MEMORY_GROWTH=0, so the heap never grows and this view stays valid
    // for the whole loop (the backing ArrayBuffer is never detached).
    const bufView = new Uint8Array(
      module.wasmMemory.buffer,
      bufPtr,
      HASH_WASM_CHUNK_BYTES,
    );

    for (let offset = 0; offset < file.size; offset += HASH_WINDOW_BYTES) {
      const end = Math.min(offset + HASH_WINDOW_BYTES, file.size);
      const window = new Uint8Array(await file.slice(offset, end).arrayBuffer());

      for (let s = 0; s < window.length; s += HASH_WASM_CHUNK_BYTES) {
        const n = Math.min(HASH_WASM_CHUNK_BYTES, window.length - s);
        bufView.set(window.subarray(s, s + n), 0);
        if (module._sha512_update(statePtr, bufPtr, n) !== 0)
          throw new Error("sha512_update failed");
      }
    }

    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("sha512_final failed");

    // Copy the digest out of the WASM heap before freeing.
    return Uint8Array.from(
      new Uint8Array(
        module.wasmMemory.buffer,
        outPtr,
        crypto_hash_sha512_BYTES,
      ),
    );
  } finally {
    module._free(statePtr);
    module._free(bufPtr);
    module._free(outPtr);
  }
};
