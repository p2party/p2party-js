#ifndef P2PARTY_MLKEM768_H
#define P2PARTY_MLKEM768_H

#include <stdint.h>

#define P2PARTY_MLKEM768_PUBLICKEYBYTES 1184
#define P2PARTY_MLKEM768_SECRETKEYBYTES 2400
#define P2PARTY_MLKEM768_CIPHERTEXTBYTES 1088
#define P2PARTY_MLKEM768_BYTES 32
#define P2PARTY_MLKEM768_KEYPAIRCOINBYTES 64
#define P2PARTY_MLKEM768_ENCAPSCOINBYTES 32
#define P2PARTY_FIPS202_SHA3_256_BYTES 32
#define P2PARTY_FIPS202_MAX_BUFFER_BYTES (SIZE_MAX >> 12)

/*
 * Deterministic ML-KEM-768 boundary. The caller must supply cryptographically
 * secure, uniformly random coins. Return values are mlkem-native status codes:
 * zero is success and a negative value is failure.
 */
int mlkem768_keypair(uint8_t pk[P2PARTY_MLKEM768_PUBLICKEYBYTES],
                     uint8_t sk[P2PARTY_MLKEM768_SECRETKEYBYTES],
                     const uint8_t coins[P2PARTY_MLKEM768_KEYPAIRCOINBYTES]);

int mlkem768_encaps(uint8_t ct[P2PARTY_MLKEM768_CIPHERTEXTBYTES],
                    uint8_t ss[P2PARTY_MLKEM768_BYTES],
                    const uint8_t pk[P2PARTY_MLKEM768_PUBLICKEYBYTES],
                    const uint8_t coins[P2PARTY_MLKEM768_ENCAPSCOINBYTES]);

int mlkem768_decaps(uint8_t ss[P2PARTY_MLKEM768_BYTES],
                    const uint8_t ct[P2PARTY_MLKEM768_CIPHERTEXTBYTES],
                    const uint8_t sk[P2PARTY_MLKEM768_SECRETKEYBYTES]);

/*
 * P2Party-owned one-shot FIPS 202 boundary backed by the SHAKE/SHA3
 * implementation already compiled into the shared ML-KEM-768 unit.
 *
 * Inputs and outputs must be non-NULL and non-overlapping. Lengths must be
 * non-negative and no greater than P2PARTY_FIPS202_MAX_BUFFER_BYTES, which
 * mirrors the vendored implementation's proof bound. Zero is success and -1
 * is invalid input.
 */
int fips202_shake256(uint8_t *out, int out_len, const uint8_t *input,
                     int input_len);
int fips202_sha3_256(uint8_t out[P2PARTY_FIPS202_SHA3_256_BYTES],
                     const uint8_t *input, int input_len);

#endif /* P2PARTY_MLKEM768_H */
