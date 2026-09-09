import {
  maxAeadPlaintextBytes,
  openWasmAead,
  sealWasmAead,
  WASM_AEAD_MAX_BYTES,
  type WasmAeadSuite,
} from "./aeadWasm";
import {
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";

import type { LibCrypto } from "./libcrypto";

const CHACHA20POLY1305_SUITE = Object.freeze({
  name: "chacha20poly1305",
  keyBytes: crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  nonceBytes: crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  tagBytes: crypto_aead_chacha20poly1305_ietf_ABYTES,
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
    module._encrypt_chachapoly_symmetric(
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
    module._decrypt_chachapoly_symmetric(
      output,
      input,
      inputLength,
      key,
      nonce,
      associatedData,
      associatedDataLength,
    ),
} satisfies WasmAeadSuite);

export const CHACHA20POLY1305_MAX_WASM_BYTES = WASM_AEAD_MAX_BYTES;
export const CHACHA20POLY1305_MAX_PLAINTEXT_BYTES = maxAeadPlaintextBytes(
  CHACHA20POLY1305_SUITE,
);

/** Seal to RFC 8439 `ciphertext || 16-byte Poly1305 tag`. */
export const chacha20Poly1305Seal = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array =>
  sealWasmAead(
    CHACHA20POLY1305_SUITE,
    module,
    key,
    nonce,
    plaintext,
    associatedData,
  );

/** Open RFC 8439 `ciphertext || tag`, returning null on authentication failure. */
export const chacha20Poly1305Open = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array | null =>
  openWasmAead(
    CHACHA20POLY1305_SUITE,
    module,
    key,
    nonce,
    ciphertextAndTag,
    associatedData,
  );
