#ifndef P2PARTY_MLKEM768_H
#define P2PARTY_MLKEM768_H

#include <stdint.h>

#define P2PARTY_MLKEM768_PUBLICKEYBYTES 1184
#define P2PARTY_MLKEM768_SECRETKEYBYTES 2400
#define P2PARTY_MLKEM768_CIPHERTEXTBYTES 1088
#define P2PARTY_MLKEM768_BYTES 32
#define P2PARTY_MLKEM768_KEYPAIRCOINBYTES 64
#define P2PARTY_MLKEM768_ENCAPSCOINBYTES 32

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

#endif /* P2PARTY_MLKEM768_H */
