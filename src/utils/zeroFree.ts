import type { LibCrypto } from "../cryptography/libcrypto";

/**
 * Wipe a secret-bearing WASM buffer before returning it to the allocator.
 *
 * WASM `_malloc`/`_free` does not zero memory, and the encryption/receive heaps
 * are long-lived and reused, so freed secret key material would otherwise linger
 * in the ArrayBuffer. This mirrors the `sodium_free` discipline used on the C
 * side. Pass the live view over the buffer; its `byteOffset` is the pointer.
 */
export const zeroFree = (module: LibCrypto, view: Uint8Array): void => {
  view.fill(0);
  module._free(view.byteOffset);
};
