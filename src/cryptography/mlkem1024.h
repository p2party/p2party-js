#ifndef P2PARTY_MLKEM1024_H
#define P2PARTY_MLKEM1024_H

#include <stdint.h>

#define P2PARTY_MLKEM1024_PUBLICKEYBYTES 1568
#define P2PARTY_MLKEM1024_SECRETKEYBYTES 3168
#define P2PARTY_MLKEM1024_CIPHERTEXTBYTES 1568
#define P2PARTY_MLKEM1024_BYTES 32
#define P2PARTY_MLKEM1024_KEYPAIRCOINBYTES 64
#define P2PARTY_MLKEM1024_ENCAPSCOINBYTES 32

/*
 * Deterministic ML-KEM-1024 boundary. The caller must supply cryptographically
 * secure, uniformly random coins. Return values are mlkem-native status codes:
 * zero is success and a negative value is failure.
 */
int mlkem1024_keypair(uint8_t pk[P2PARTY_MLKEM1024_PUBLICKEYBYTES],
                      uint8_t sk[P2PARTY_MLKEM1024_SECRETKEYBYTES],
                      const uint8_t coins[P2PARTY_MLKEM1024_KEYPAIRCOINBYTES]);

int mlkem1024_encaps(uint8_t ct[P2PARTY_MLKEM1024_CIPHERTEXTBYTES],
                     uint8_t ss[P2PARTY_MLKEM1024_BYTES],
                     const uint8_t pk[P2PARTY_MLKEM1024_PUBLICKEYBYTES],
                     const uint8_t coins[P2PARTY_MLKEM1024_ENCAPSCOINBYTES]);

int mlkem1024_decaps(uint8_t ss[P2PARTY_MLKEM1024_BYTES],
                     const uint8_t ct[P2PARTY_MLKEM1024_CIPHERTEXTBYTES],
                     const uint8_t sk[P2PARTY_MLKEM1024_SECRETKEYBYTES]);

#endif /* P2PARTY_MLKEM1024_H */
