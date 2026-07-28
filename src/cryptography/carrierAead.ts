import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";
import {
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
} from "./xchacha20poly1305";
import { snapshotByteInput } from "./byteInput";
import { WasmAeadError } from "./aeadWasm";

import type { LibCrypto } from "./libcrypto";

/**
 * XChaCha20-Poly1305 as required by the blind-rendezvous delivery profile's
 * `carrierAeadSuite = 1` (`draft-irtf-cfrg-xchacha-03`).
 *
 * The construction comes from the pinned libsodium build. The reusable
 * XChaCha adapter owns the hardened WASM boundary; this compatibility wrapper
 * preserves the established carrier call shape and errors. Application code
 * implements no cryptography, which is what SEC-002 and SEC-019 require.
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
  let snapshot: Uint8Array | undefined;
  try {
    snapshot = snapshotByteInput(value, `carrierAead: ${name}`, {
      exactLength: expected,
    });
  } catch {
    throw new CarrierAeadError(
      `${name} must be exactly ${String(expected)} bytes`,
    );
  } finally {
    snapshot?.fill(0);
  }
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

  try {
    return xchacha20Poly1305Seal(module, key, nonce, plaintext, associatedData);
  } catch (cause) {
    // Key/nonce validation above preserves the existing CarrierAeadError
    // contract. Keep new caller-input type/range failures precise, while
    // translating allocation or primitive failures to the legacy message.
    if (cause instanceof WasmAeadError)
      throw new CarrierAeadError("XChaCha20-Poly1305 encryption failed");
    throw cause;
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

  return xchacha20Poly1305Open(
    module,
    key,
    nonce,
    ciphertextAndTag,
    associatedData,
  );
};
