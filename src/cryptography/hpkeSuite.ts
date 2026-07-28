import {
  MLKEM768_X25519_CIPHERTEXT_BYTES,
  MLKEM768_X25519_PUBLIC_KEY_BYTES,
  MLKEM768_X25519_SECRET_KEY_BYTES,
  MLKEM768_X25519_SHARED_SECRET_BYTES,
} from "./hybridKemSuite";

/**
 * Constants-only SSOT for the fixed pair-bootstrap HPKE suite.
 *
 * Keeping this separate from the executable HPKE adapter lets schemas and the
 * blind-rendezvous suite registry consume the exact wire geometry without
 * importing WASM-backed cryptographic code.
 */
export const HPKE_MLKEM768_X25519_KEM_ID = 0x647a;
export const HPKE_HKDF_SHA256_KDF_ID = 0x0001;
export const HPKE_CHACHA20POLY1305_AEAD_ID = 0x0003;
export const HPKE_MODE_BASE = 0x00;
export const HPKE_MODE_PSK = 0x01;
export const HPKE_HASH_BYTES = 32;
export const HPKE_KEY_BYTES = 32;
export const HPKE_NONCE_BYTES = 12;
export const HPKE_TAG_BYTES = 16;
export const HPKE_PAIR_PSK_BYTES = 32;
export const HPKE_PAIR_PSK_ID_BYTES = 32;
export const HPKE_MAX_EXPORT_BYTES = 255 * HPKE_HASH_BYTES;
export const HPKE_MAX_APPLICATION_CONTEXT_BYTES = 65_535;

export const HPKE_MLKEM768_X25519_SUITE = Object.freeze({
  specification: Object.freeze({
    kem: "draft-ietf-hpke-pq-05",
    kemKeyDerivation: "draft-ietf-hpke-hpke-03",
    keySchedule: "RFC 9180",
  }),
  kemId: HPKE_MLKEM768_X25519_KEM_ID,
  kdfId: HPKE_HKDF_SHA256_KDF_ID,
  aeadId: HPKE_CHACHA20POLY1305_AEAD_ID,
  publicKeyBytes: MLKEM768_X25519_PUBLIC_KEY_BYTES,
  secretKeyBytes: MLKEM768_X25519_SECRET_KEY_BYTES,
  encapsulatedKeyBytes: MLKEM768_X25519_CIPHERTEXT_BYTES,
  sharedSecretBytes: MLKEM768_X25519_SHARED_SECRET_BYTES,
  keyBytes: HPKE_KEY_BYTES,
  nonceBytes: HPKE_NONCE_BYTES,
  tagBytes: HPKE_TAG_BYTES,
  pskBytes: HPKE_PAIR_PSK_BYTES,
  pskIdBytes: HPKE_PAIR_PSK_ID_BYTES,
} as const);
