#include "./carrierAead.h"

/* out = ciphertext || Poly1305 tag (out_len == data_len + ABYTES).
 * Returns 0 on success, -1 otherwise. */
int
carrier_aead_xchacha20poly1305_encrypt(
    uint8_t *out, const uint8_t *data, const unsigned int data_len,
    const uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len)
{
  unsigned long long clen = 0;
  int res = crypto_aead_xchacha20poly1305_ietf_encrypt(
      out, &clen, data, data_len, aad, aad_len, NULL, nonce, key);
  if (res != 0) return -1;
  return 0;
}

/* Inverse of the above: in = ciphertext || tag (in_len == out_len + ABYTES).
 * libsodium verifies the tag in constant time and writes NO plaintext on
 * authentication failure, which is what lets a caller treat -1 as "not for
 * this room" rather than having to scrub a partial buffer. Returns 0 on
 * success, -1 on authentication failure. */
int
carrier_aead_xchacha20poly1305_decrypt(
    uint8_t *out, const uint8_t *in, const unsigned int in_len,
    const uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
    const uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
    const uint8_t *aad, const unsigned int aad_len)
{
  unsigned long long mlen = 0;
  int res = crypto_aead_xchacha20poly1305_ietf_decrypt(
      out, &mlen, NULL, in, in_len, aad, aad_len, nonce, key);
  if (res != 0) return -1;
  return 0;
}
