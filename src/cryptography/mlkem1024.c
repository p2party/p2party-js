#include "./mlkem1024.h"

#include <stddef.h>
#include <stdint.h>

/*
 * mlkem-native v1.2.0, pinned in vendor/mlkem-native/UPSTREAM.md.
 *
 * This is one member of a three-parameter-set build. Every member enables
 * MLK_CONFIG_MULTILEVEL_BUILD. ML-KEM-768 owns the shared implementation;
 * this compilation unit emits only ML-KEM-1024-specific code.
 *
 * WebCrypto supplies entropy to the caller-facing TypeScript layer. Keep the
 * randomized upstream API out of the binary and select portable C for WASM.
 */
#define MLK_CONFIG_PARAMETER_SET 1024
#define MLK_CONFIG_NAMESPACE_PREFIX p2party_mlkem
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_SUPERCOP
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_ZEROIZE

static void
mlk_zeroize(void *ptr, size_t len)
{
  volatile uint8_t *cursor = (volatile uint8_t *)ptr;

  while (len != 0)
  {
    *cursor++ = 0;
    len--;
  }
}

#include "./vendor/mlkem-native/mlkem/mlkem_native.h"
_Static_assert(MLKEM1024_PUBLICKEYBYTES == P2PARTY_MLKEM1024_PUBLICKEYBYTES,
               "ML-KEM-1024 public-key size mismatch");
_Static_assert(MLKEM1024_SECRETKEYBYTES == P2PARTY_MLKEM1024_SECRETKEYBYTES,
               "ML-KEM-1024 secret-key size mismatch");
_Static_assert(MLKEM1024_CIPHERTEXTBYTES ==
                 P2PARTY_MLKEM1024_CIPHERTEXTBYTES,
               "ML-KEM-1024 ciphertext size mismatch");
_Static_assert(MLKEM_BYTES == P2PARTY_MLKEM1024_BYTES,
               "ML-KEM shared-secret size mismatch");

#include "./vendor/mlkem-native/mlkem/mlkem_native.c"

int
mlkem1024_keypair(uint8_t pk[P2PARTY_MLKEM1024_PUBLICKEYBYTES],
                  uint8_t sk[P2PARTY_MLKEM1024_SECRETKEYBYTES],
                  const uint8_t coins[P2PARTY_MLKEM1024_KEYPAIRCOINBYTES])
{
  return p2party_mlkem1024_keypair_derand(pk, sk, coins);
}

int
mlkem1024_encaps(uint8_t ct[P2PARTY_MLKEM1024_CIPHERTEXTBYTES],
                 uint8_t ss[P2PARTY_MLKEM1024_BYTES],
                 const uint8_t pk[P2PARTY_MLKEM1024_PUBLICKEYBYTES],
                 const uint8_t coins[P2PARTY_MLKEM1024_ENCAPSCOINBYTES])
{
  return p2party_mlkem1024_enc_derand(ct, ss, pk, coins);
}

int
mlkem1024_decaps(uint8_t ss[P2PARTY_MLKEM1024_BYTES],
                 const uint8_t ct[P2PARTY_MLKEM1024_CIPHERTEXTBYTES],
                 const uint8_t sk[P2PARTY_MLKEM1024_SECRETKEYBYTES])
{
  return p2party_mlkem1024_dec(ss, ct, sk);
}
