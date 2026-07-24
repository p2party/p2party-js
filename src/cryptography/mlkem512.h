#ifndef P2PARTY_MLKEM512_H
#define P2PARTY_MLKEM512_H

#include <stdint.h>

#define P2PARTY_MLKEM512_PUBLICKEYBYTES 800
#define P2PARTY_MLKEM512_SECRETKEYBYTES 1632
#define P2PARTY_MLKEM512_CIPHERTEXTBYTES 768
#define P2PARTY_MLKEM512_BYTES 32
#define P2PARTY_MLKEM512_KEYPAIRCOINBYTES 64
#define P2PARTY_MLKEM512_ENCAPSCOINBYTES 32

/*
 * Deterministic ML-KEM-512 boundary. The caller must supply cryptographically
 * secure, uniformly random coins. Return values are mlkem-native status codes:
 * zero is success and a negative value is failure.
 */
int mlkem512_keypair(uint8_t pk[P2PARTY_MLKEM512_PUBLICKEYBYTES],
                     uint8_t sk[P2PARTY_MLKEM512_SECRETKEYBYTES],
                     const uint8_t coins[P2PARTY_MLKEM512_KEYPAIRCOINBYTES]);

int mlkem512_encaps(uint8_t ct[P2PARTY_MLKEM512_CIPHERTEXTBYTES],
                    uint8_t ss[P2PARTY_MLKEM512_BYTES],
                    const uint8_t pk[P2PARTY_MLKEM512_PUBLICKEYBYTES],
                    const uint8_t coins[P2PARTY_MLKEM512_ENCAPSCOINBYTES]);

int mlkem512_decaps(uint8_t ss[P2PARTY_MLKEM512_BYTES],
                    const uint8_t ct[P2PARTY_MLKEM512_CIPHERTEXTBYTES],
                    const uint8_t sk[P2PARTY_MLKEM512_SECRETKEYBYTES]);

#endif /* P2PARTY_MLKEM512_H */
