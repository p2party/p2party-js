#include "./mlkem768.h"

#include <stddef.h>
#include <stdint.h>

/*
 * mlkem-native v1.2.0, pinned in vendor/mlkem-native/UPSTREAM.md.
 *
 * This is one member of a three-parameter-set build. Every member enables
 * MLK_CONFIG_MULTILEVEL_BUILD. This compilation unit owns the one shared
 * implementation; the ML-KEM-512 and ML-KEM-1024 units use NO_SHARED.
 *
 * WebCrypto supplies the entropy to the caller-facing TypeScript layer. Keep
 * the randomized upstream API out of the binary so there is no second RNG
 * path, and select the portable C backend because the target is WebAssembly.
 */
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX p2party_mlkem
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_SUPERCOP
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_ZEROIZE

/*
 * MLK_CONFIG_NO_ASM requires a consumer-provided secure erase. Volatile byte
 * stores prevent the compiler from proving that these writes are dead.
 */
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
_Static_assert(MLKEM768_PUBLICKEYBYTES == P2PARTY_MLKEM768_PUBLICKEYBYTES,
               "ML-KEM-768 public-key size mismatch");
_Static_assert(MLKEM768_SECRETKEYBYTES == P2PARTY_MLKEM768_SECRETKEYBYTES,
               "ML-KEM-768 secret-key size mismatch");
_Static_assert(MLKEM768_CIPHERTEXTBYTES == P2PARTY_MLKEM768_CIPHERTEXTBYTES,
               "ML-KEM-768 ciphertext size mismatch");
_Static_assert(MLKEM_BYTES == P2PARTY_MLKEM768_BYTES,
               "ML-KEM shared-secret size mismatch");

#include "./vendor/mlkem-native/mlkem/mlkem_native.c"

int
mlkem768_keypair(uint8_t pk[P2PARTY_MLKEM768_PUBLICKEYBYTES],
                 uint8_t sk[P2PARTY_MLKEM768_SECRETKEYBYTES],
                 const uint8_t coins[P2PARTY_MLKEM768_KEYPAIRCOINBYTES])
{
  return p2party_mlkem768_keypair_derand(pk, sk, coins);
}

int
mlkem768_encaps(uint8_t ct[P2PARTY_MLKEM768_CIPHERTEXTBYTES],
                uint8_t ss[P2PARTY_MLKEM768_BYTES],
                const uint8_t pk[P2PARTY_MLKEM768_PUBLICKEYBYTES],
                const uint8_t coins[P2PARTY_MLKEM768_ENCAPSCOINBYTES])
{
  return p2party_mlkem768_enc_derand(ct, ss, pk, coins);
}

int
mlkem768_decaps(uint8_t ss[P2PARTY_MLKEM768_BYTES],
                const uint8_t ct[P2PARTY_MLKEM768_CIPHERTEXTBYTES],
                const uint8_t sk[P2PARTY_MLKEM768_SECRETKEYBYTES])
{
  return p2party_mlkem768_dec(ss, ct, sk);
}
