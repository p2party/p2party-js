#ifndef ed25519_H
#define ed25519_H

#include <stdbool.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int random_bytes(const unsigned int SIZE, uint8_t array[SIZE]);

int random_number_in_range(const int MIN, const int MAX);

int sha512(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
           uint8_t hash[crypto_hash_sha512_BYTES]);

int argon2(const unsigned int MNEMONIC_LEN,
           uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
           const char mnemonic[MNEMONIC_LEN],
           const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES]);

void
calculate_nonce(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]);

int keypair(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
            uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

int keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                      uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                      const uint8_t seed[crypto_sign_ed25519_SEEDBYTES]);

int keypair_from_secret_key(
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

int sign(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
         const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
         uint8_t signature[crypto_sign_ed25519_BYTES]);

int verify(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
           const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
           const uint8_t signature[crypto_sign_ed25519_BYTES]);

#endif
