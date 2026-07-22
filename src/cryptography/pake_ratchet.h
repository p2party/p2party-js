#ifndef pake_ratchet_H
#define pake_ratchet_H

#include <stdint.h>
#include <string.h>

#include "utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_core_ristretto255.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_ristretto255.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_kdf_hkdf_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/randombytes.h"

/* ---- v3 frame-layout constants (byte-matched to src/utils/constants.ts) ----
 * SSOT NOTE: Stage 5 relocates these to utils.h alongside the MESSAGE_START
 * remap and adds the C<->TS constant-agreement unit test. They live here now
 * only so receive_message_with_key compiles in isolation this stage. */
#define FRAME_TYPE_LEN 1U
#define RATCHET_DHPUB_LEN 32U
#define RATCHET_N_LEN 8U
#define RATCHET_PN_LEN 8U
#define PQ_EPOCH_LEN 1U
#define CHUNK_HEADER_LEN                                                     \
  (RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN + PQ_EPOCH_LEN) /* 49 */
#define MESSAGE_START (FRAME_TYPE_LEN + CHUNK_HEADER_LEN) /* 50 */

void cpace_ristretto255_from_hash(
    uint8_t out[crypto_core_ristretto255_BYTES],
    const uint8_t hash[crypto_core_ristretto255_HASHBYTES]);
int cpace_ristretto255_scalarmult(
    uint8_t out[crypto_core_ristretto255_BYTES],
    const uint8_t scalar[crypto_core_ristretto255_SCALARBYTES],
    const uint8_t point[crypto_core_ristretto255_BYTES]);
void cpace_ristretto255_scalar_random(
    uint8_t out[crypto_core_ristretto255_SCALARBYTES]);

int x25519_keypair(uint8_t pk[crypto_scalarmult_curve25519_BYTES],
                   uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES]);
int x25519_dh(uint8_t shared[crypto_scalarmult_curve25519_BYTES],
              const uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES],
              const uint8_t pk[crypto_scalarmult_curve25519_BYTES]);

int hkdf_sha512_extract(uint8_t prk[crypto_auth_hmacsha512_BYTES],
                        const uint8_t *salt, const unsigned int salt_len,
                        const uint8_t *ikm, const unsigned int ikm_len);
int hkdf_sha512_expand(uint8_t *out, const unsigned int out_len,
                       const uint8_t prk[crypto_auth_hmacsha512_BYTES],
                       const uint8_t *info, const unsigned int info_len);

int encrypt_chachapoly_symmetric(
    uint8_t *out, const uint8_t *data, const unsigned int data_len,
    const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len);

int receive_message_with_key(
    uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
    const uint8_t merkle_root[crypto_hash_sha512_BYTES],
    const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES]);

#endif
