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

/* ---------------- HKDF-SHA512 (RFC 5869) on HMAC-SHA512 ---------------- */

int
hkdf_sha512_extract(uint8_t prk[crypto_auth_hmacsha512_BYTES],
                    const uint8_t *salt, const unsigned int salt_len,
                    const uint8_t *ikm, const unsigned int ikm_len)
{
  crypto_auth_hmacsha512_state st;
  uint8_t zero_salt[crypto_auth_hmacsha512_BYTES];
  const uint8_t *k = salt;
  size_t klen = salt_len;
  if (salt == NULL || salt_len == 0)
  {
    memset(zero_salt, 0, sizeof zero_salt); /* RFC 5869: HashLen zeros */
    k = zero_salt;
    klen = sizeof zero_salt;
  }
  if (crypto_auth_hmacsha512_init(&st, k, klen) != 0) return -1;
  if (crypto_auth_hmacsha512_update(&st, ikm, ikm_len) != 0) return -2;
  if (crypto_auth_hmacsha512_final(&st, prk) != 0) return -3;
  return 0;
}

int
hkdf_sha512_expand(uint8_t *out, const unsigned int out_len,
                   const uint8_t prk[crypto_auth_hmacsha512_BYTES],
                   const uint8_t *info, const unsigned int info_len)
{
  const unsigned int HASH_LEN = crypto_auth_hmacsha512_BYTES; /* 64 */
  if (out_len > 255U * HASH_LEN) return -1;

  uint8_t t[crypto_auth_hmacsha512_BYTES];
  unsigned int t_len = 0;
  unsigned int done = 0;
  uint8_t counter = 0;

  while (done < out_len)
  {
    counter++;
    crypto_auth_hmacsha512_state st;
    if (crypto_auth_hmacsha512_init(&st, prk, HASH_LEN) != 0) return -2;
    if (t_len > 0)
    {
      if (crypto_auth_hmacsha512_update(&st, t, t_len) != 0) return -3;
    }
    if (info_len > 0 && info != NULL)
    {
      if (crypto_auth_hmacsha512_update(&st, info, info_len) != 0) return -4;
    }
    if (crypto_auth_hmacsha512_update(&st, &counter, 1) != 0) return -5;
    if (crypto_auth_hmacsha512_final(&st, t) != 0) return -6;
    t_len = HASH_LEN;

    unsigned int n = out_len - done;
    if (n > HASH_LEN) n = HASH_LEN;
    memcpy(out + done, t, n);
    done += n;
  }
  return 0;
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
 * Frame: [type(1) | DH_pub(32) | N(8) | PN(8) | PQ_EPOCH(1) | ciphertext||tag]
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

  /* Nonce = 12-byte big-endian message counter N. Stage 5 refines this to the
   * true per-chunk chunkIndex when the frame remap lands; unique per
   * (message-key, chunk) either way. */
  uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
  memset(nonce, 0, sizeof nonce);
  memcpy(nonce + (crypto_aead_chacha20poly1305_ietf_NPUBBYTES - RATCHET_N_LEN),
         n_ptr, RATCHET_N_LEN);

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
