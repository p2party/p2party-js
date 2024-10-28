#include "ed25519.h"

int
keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                  uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                  const uint8_t seed[crypto_sign_ed25519_SEEDBYTES])
{
  return crypto_sign_ed25519_seed_keypair(public_key, secret_key, seed);
}

int
keypair_from_secret_key(
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  memcpy(public_key, secret_key + crypto_sign_ed25519_SEEDBYTES,
         crypto_sign_ed25519_PUBLICKEYBYTES);

  return 0;
}

int
sign(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
     const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
     uint8_t signature[crypto_sign_ed25519_BYTES])
{
  unsigned long long SIGNATURE_LEN = crypto_sign_ed25519_BYTES;

  return crypto_sign_ed25519_detached(signature, &SIGNATURE_LEN, data, DATA_LEN,
                                      secret_key);
}

int
verify(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
       const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
       const uint8_t signature[crypto_sign_ed25519_BYTES])
{
  return crypto_sign_ed25519_verify_detached(signature, data, DATA_LEN,
                                             public_key);
}
