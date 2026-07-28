/**
 * Frozen wire geometry for the pair-bootstrap KEM.
 *
 * This constants-only module is the SSOT shared by the crypto implementation
 * and blind-rendezvous schemas. Changing any value requires a new suite ID.
 */
export const MLKEM768_X25519_SEED_BYTES = 32;
export const MLKEM768_X25519_PUBLIC_KEY_BYTES = 1_216;
export const MLKEM768_X25519_SECRET_KEY_BYTES = 32;
export const MLKEM768_X25519_CIPHERTEXT_BYTES = 1_120;
export const MLKEM768_X25519_SHARED_SECRET_BYTES = 32;
export const MLKEM768_X25519_RANDOM_BYTES = 64;

export const MLKEM768_X25519_SUITE = Object.freeze({
  standardName: "MLKEM768-X25519",
  specification: "draft-irtf-cfrg-concrete-hybrid-kems-04",
  seedBytes: MLKEM768_X25519_SEED_BYTES,
  publicKeyBytes: MLKEM768_X25519_PUBLIC_KEY_BYTES,
  secretKeyBytes: MLKEM768_X25519_SECRET_KEY_BYTES,
  ciphertextBytes: MLKEM768_X25519_CIPHERTEXT_BYTES,
  sharedSecretBytes: MLKEM768_X25519_SHARED_SECRET_BYTES,
  randomnessBytes: MLKEM768_X25519_RANDOM_BYTES,
} as const);
