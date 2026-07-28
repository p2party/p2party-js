import {
  maxAeadPlaintextBytes,
  openWasmAead,
  sealWasmAead,
  WASM_AEAD_MAX_BYTES,
  type WasmAeadSuite,
} from "./aeadWasm";
import {
  crypto_aead_xchacha20poly1305_ietf_ABYTES,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";

import type { LibCrypto } from "./libcrypto";

const XCHACHA20POLY1305_SUITE = Object.freeze({
  name: "xchacha20poly1305",
  keyBytes: crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  nonceBytes: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  tagBytes: crypto_aead_xchacha20poly1305_ietf_ABYTES,
  encrypt: (
    module,
    output,
    input,
    inputLength,
    key,
    nonce,
    associatedData,
    associatedDataLength,
  ) =>
    module._carrier_aead_xchacha20poly1305_encrypt(
      output,
      input,
      inputLength,
      key,
      nonce,
      associatedData,
      associatedDataLength,
    ),
  decrypt: (
    module,
    output,
    input,
    inputLength,
    key,
    nonce,
    associatedData,
    associatedDataLength,
  ) =>
    module._carrier_aead_xchacha20poly1305_decrypt(
      output,
      input,
      inputLength,
      key,
      nonce,
      associatedData,
      associatedDataLength,
    ),
} satisfies WasmAeadSuite);

export const XCHACHA20POLY1305_MAX_WASM_BYTES = WASM_AEAD_MAX_BYTES;
export const XCHACHA20POLY1305_MAX_PLAINTEXT_BYTES = maxAeadPlaintextBytes(
  XCHACHA20POLY1305_SUITE,
);

/** Seal to XChaCha20-Poly1305 `ciphertext || 16-byte tag`. */
export const xchacha20Poly1305Seal = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array =>
  sealWasmAead(
    XCHACHA20POLY1305_SUITE,
    module,
    key,
    nonce,
    plaintext,
    associatedData,
  );

/** Open `ciphertext || tag`, returning null on authentication failure. */
export const xchacha20Poly1305Open = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array | null =>
  openWasmAead(
    XCHACHA20POLY1305_SUITE,
    module,
    key,
    nonce,
    ciphertextAndTag,
    associatedData,
  );
