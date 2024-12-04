#ifndef merkle_H
#define merkle_H

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

int
get_merkle_root(const unsigned int LEAVES_LEN,
                uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
                uint8_t root[crypto_hash_sha512_BYTES]);

int
get_merkle_proof(const unsigned int LEAVES_LEN,
                 uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
                 const uint8_t element_hash[crypto_hash_sha512_BYTES],
                 uint8_t proof[LEAVES_LEN * (crypto_hash_sha512_BYTES + 1)]);

int get_merkle_root_from_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)],
    uint8_t root[crypto_hash_sha512_BYTES]);

int verify_merkle_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t root[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)]);

#endif
