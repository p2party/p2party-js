#include "pake_ratchet.h"

/* ---------------- CPace over Ristretto255 ---------------- */

void
cpace_ristretto255_from_hash(
    uint8_t out[crypto_core_ristretto255_BYTES],
    const uint8_t hash[crypto_core_ristretto255_HASHBYTES])
{
  crypto_core_ristretto255_from_hash(out, hash);
}

int
cpace_ristretto255_scalarmult(
    uint8_t out[crypto_core_ristretto255_BYTES],
    const uint8_t scalar[crypto_core_ristretto255_SCALARBYTES],
    const uint8_t point[crypto_core_ristretto255_BYTES])
{
  /* q = scalar * point; returns -1 if the result is the identity. */
  return crypto_scalarmult_ristretto255(out, scalar, point);
}

void
cpace_ristretto255_scalar_random(
    uint8_t out[crypto_core_ristretto255_SCALARBYTES])
{
  crypto_core_ristretto255_scalar_random(out);
}

/* ---------------- X25519 DH ratchet ---------------- */

int
x25519_keypair(uint8_t pk[crypto_scalarmult_curve25519_BYTES],
               uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES])
{
  randombytes_buf(sk, crypto_scalarmult_curve25519_SCALARBYTES);
  /* crypto_scalarmult_curve25519_base clamps sk internally. */
  return crypto_scalarmult_curve25519_base(pk, sk);
}

int
x25519_dh(uint8_t shared[crypto_scalarmult_curve25519_BYTES],
          const uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES],
          const uint8_t pk[crypto_scalarmult_curve25519_BYTES])
{
  return crypto_scalarmult_curve25519(shared, sk, pk);
}

/* ---------------- HKDF-SHA512 (RFC 5869) via libsodium ----------------
 * Thin wrappers over libsodium's native crypto_kdf_hkdf_sha512_{extract,expand}
 * (crypto_kdf_hkdf_sha512_KEYBYTES == crypto_auth_hmacsha512_BYTES == 64).
 * Export names/signatures are unchanged so src/cryptography/hkdf.ts and all
 * consumers (cpace/x3dh/ratchet) stay untouched. Both return 0 on success. */

int
hkdf_sha512_extract(uint8_t prk[crypto_auth_hmacsha512_BYTES],
                    const uint8_t *salt, const unsigned int salt_len,
                    const uint8_t *ikm, const unsigned int ikm_len)
{
  return crypto_kdf_hkdf_sha512_extract(prk, salt, (size_t)salt_len, ikm,
                                        (size_t)ikm_len);
}

int
hkdf_sha512_expand(uint8_t *out, const unsigned int out_len,
                   const uint8_t prk[crypto_auth_hmacsha512_BYTES],
                   const uint8_t *info, const unsigned int info_len)
{
  /* libsodium's expand takes ctx (= our info) then the prk LAST. */
  return crypto_kdf_hkdf_sha512_expand(out, (size_t)out_len,
                                       (const char *)info, (size_t)info_len,
                                       prk);
}

/* ---------------- Symmetric AEAD (message-key path) ---------------- */

/* out = ciphertext || Poly1305 tag  (out_len == data_len + ABYTES).
 * No nonce is prepended (unlike encrypt_chachapoly_asymmetric): the v3 send
 * path derives the nonce from the chunk index, so it is not on the wire. */
int
encrypt_chachapoly_symmetric(
    uint8_t *out, const uint8_t *data, const unsigned int data_len,
    const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len)
{
  unsigned long long clen = 0;
  int res = crypto_aead_chacha20poly1305_ietf_encrypt(
      out, &clen, data, data_len, aad, aad_len, NULL, nonce, key);
  if (res != 0) return -1;
  return 0;
}

/* ---------------- v3 receive path (no signature) ----------------
 * Frame: [type(1) | DH_pub(32) | N(8) | PN(8) | PQ_EPOCH(1) | nonce(12) | ciphertext||tag]
 * Symmetric-decrypt under message_key with AAD = merkle_root || N || PN, then
 * run the merkle-proof / leaf-hash / receipt logic VERBATIM from
 * receive_message (utils.c:146-181). Return codes mirror receive_message
 * minus the -1 "signature wrong" case. */
int
receive_message_with_key(
    uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
    const uint8_t merkle_root[crypto_hash_sha512_BYTES],
    const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES])
{
  const uint8_t *n_ptr = message + FRAME_TYPE_LEN + RATCHET_DHPUB_LEN;
  const uint8_t *pn_ptr = n_ptr + RATCHET_N_LEN;

  uint8_t aad[crypto_hash_sha512_BYTES + RATCHET_N_LEN + RATCHET_PN_LEN];
  memcpy(aad, merkle_root, crypto_hash_sha512_BYTES);
  memcpy(aad + crypto_hash_sha512_BYTES, n_ptr, RATCHET_N_LEN);
  memcpy(aad + crypto_hash_sha512_BYTES + RATCHET_N_LEN, pn_ptr,
         RATCHET_PN_LEN);

  /* Nonce = the fresh, random 12-byte per-chunk nonce carried in the CLEARTEXT
   * frame header (right after PQ_EPOCH, before the ciphertext). Receiver-derivable
   * because it is literally on the wire, metadata-safe because it is random (not an
   * index), and birthday-safe within a per-message key. NPUBBYTES == RATCHET_NONCE_LEN
   * (both 12). */
  const uint8_t *nonce = pn_ptr + RATCHET_PN_LEN + PQ_EPOCH_LEN;

  unsigned long long DATA_LEN = DECRYPTED_LEN;
  int d = crypto_aead_chacha20poly1305_ietf_decrypt(
      decrypted, &DATA_LEN, NULL, message + MESSAGE_START,
      (unsigned long long)(DECRYPTED_LEN
                           + crypto_aead_chacha20poly1305_ietf_ABYTES),
      aad, sizeof aad, nonce, message_key);
  if (d != 0) return -2;

  /* ---- VERBATIM from receive_message (utils.c:146-181) ---- */
  uint32_t proofLen = ((uint32_t)decrypted[METADATA_LEN] << 24)
                      | ((uint32_t)decrypted[METADATA_LEN + 1] << 16)
                      | ((uint32_t)decrypted[METADATA_LEN + 2] << 8)
                      | (uint32_t)decrypted[METADATA_LEN + 3];
  if (proofLen % (crypto_hash_sha512_BYTES + 1) != 0 || proofLen > PROOF_LEN)
    return -3;
  size_t proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  uint8_t leaf[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state leaf_state;
  const uint8_t leaf_domain = 0x00;
  int h = crypto_hash_sha512_init(&leaf_state);
  if (h == 0) h = crypto_hash_sha512_update(&leaf_state, &leaf_domain, 1);
  if (h == 0)
    h = crypto_hash_sha512_update(&leaf_state,
                                  &decrypted[METADATA_LEN + PROOF_LEN],
                                  DECRYPTED_LEN - METADATA_LEN - PROOF_LEN);
  if (h == 0) h = crypto_hash_sha512_final(&leaf_state, leaf);
  if (h != 0) return -5;

  uint8_t fold[crypto_hash_sha512_BYTES];
  memcpy(fold, leaf, crypto_hash_sha512_BYTES);
  int vmp = verify_merkle_proof(proofArtifactsLen, fold, merkle_root,
                                &decrypted[METADATA_LEN + 4]);
  if (vmp != 0) return -6;

  memcpy(&decrypted[METADATA_LEN], leaf, crypto_hash_sha512_BYTES);
  return 0;
}
