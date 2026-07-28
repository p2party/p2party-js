import {
  crypto_aead_xchacha20poly1305_ietf_ABYTES,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

/**
 * XChaCha20-Poly1305 as required by the blind-rendezvous delivery profile's
 * `carrierAeadSuite = 1` (`draft-irtf-cfrg-xchacha-03`).
 *
 * The construction comes from the pinned libsodium build; this file only moves
 * bytes across the WASM boundary and zeroizes the key and plaintext staging
 * buffers afterwards. It implements no cryptography, which is what SEC-002 and
 * SEC-019 require of application code.
 */

export class CarrierAeadError extends Error {
  override readonly name = "CarrierAeadError";

  constructor(message: string) {
    super(`carrierAead: ${message}`);
  }
}

const requireLength = (
  name: string,
  value: Uint8Array,
  expected: number,
): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== expected)
    throw new CarrierAeadError(
      `${name} must be exactly ${String(expected)} bytes`,
    );
  return value;
};

export const xchacha20poly1305Seal = (
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  requireLength("key", key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  requireLength("nonce", nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  const outputLength =
    plaintext.length + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  // A zero-length malloc is undefined; allocate one byte for an empty AAD.
  const aadAllocLength = Math.max(associatedData.length, 1);
  const plaintextAllocLength = Math.max(plaintext.length, 1);

  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const aadPtr = module._malloc(aadAllocLength);
  const plaintextPtr = module._malloc(plaintextAllocLength);
  const outputPtr = module._malloc(outputLength);

  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, associatedData.length).set(
      associatedData,
    );
    new Uint8Array(
      module.wasmMemory.buffer,
      plaintextPtr,
      plaintext.length,
    ).set(plaintext);

    const result = module._carrier_aead_xchacha20poly1305_encrypt(
      outputPtr,
      plaintextPtr,
      plaintext.length,
      keyPtr,
      noncePtr,
      aadPtr,
      associatedData.length,
    );
    if (result !== 0)
      throw new CarrierAeadError("XChaCha20-Poly1305 encryption failed");

    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    module._free(aadPtr);
    zeroFree(
      module,
      new Uint8Array(
        module.wasmMemory.buffer,
        plaintextPtr,
        plaintextAllocLength,
      ),
    );
    module._free(outputPtr);
  }
};

/**
 * Returns null on authentication failure.
 *
 * libsodium verifies the tag in constant time and writes no plaintext when it
 * fails, so a caller can treat null as "not for this room" — which is exactly
 * how a dummy object reads — without having to scrub a partial buffer.
 */
export const xchacha20poly1305Open = (
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  ciphertextAndTag: Uint8Array,
  module: LibCrypto,
): Uint8Array | null => {
  requireLength("key", key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  requireLength("nonce", nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  if (ciphertextAndTag.length < crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return null;

  const outputLength =
    ciphertextAndTag.length - crypto_aead_xchacha20poly1305_ietf_ABYTES;
  const aadAllocLength = Math.max(associatedData.length, 1);
  const outputAllocLength = Math.max(outputLength, 1);

  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const aadPtr = module._malloc(aadAllocLength);
  const ciphertextPtr = module._malloc(ciphertextAndTag.length);
  const outputPtr = module._malloc(outputAllocLength);

  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, associatedData.length).set(
      associatedData,
    );
    new Uint8Array(
      module.wasmMemory.buffer,
      ciphertextPtr,
      ciphertextAndTag.length,
    ).set(ciphertextAndTag);

    const result = module._carrier_aead_xchacha20poly1305_decrypt(
      outputPtr,
      ciphertextPtr,
      ciphertextAndTag.length,
      keyPtr,
      noncePtr,
      aadPtr,
      associatedData.length,
    );
    if (result !== 0) return null;

    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    module._free(aadPtr);
    module._free(ciphertextPtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputAllocLength),
    );
  }
};
