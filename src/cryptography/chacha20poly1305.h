#ifndef chacha20poly1305_H
#define chacha20poly1305_H

#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int encrypt_chachapoly_asymmetric(
    const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t receiver_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t sender_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES]);

int decrypt_chachapoly_asymmetric(
    const unsigned int ENCRYPTED_LEN,
    const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t sender_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES]);

#endif
