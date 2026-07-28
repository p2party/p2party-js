#ifndef P2PARTY_CARRIER_AEAD_H
#define P2PARTY_CARRIER_AEAD_H

#include <sodium.h>
#include <stdint.h>

/* XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) as required by the
 * blind-rendezvous delivery profile's carrierAeadSuite=1: 32-byte key,
 * 24-byte nonce, 16-byte tag.
 *
 * These are thin wrappers over libsodium's IETF construction. They exist
 * because the specification pins this exact construction and the 24-byte
 * nonce it needs, which the ChaCha20-Poly1305 IETF export cannot provide. No
 * cryptographic logic lives here. */

int carrier_aead_xchacha20poly1305_encrypt(
    uint8_t *out, const uint8_t *data, const unsigned int data_len,
    const uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len);

int carrier_aead_xchacha20poly1305_decrypt(
    uint8_t *out, const uint8_t *in, const unsigned int in_len,
    const uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len);

#endif /* P2PARTY_CARRIER_AEAD_H */
