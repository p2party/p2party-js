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

/*
 * Include the internal FIPS 202 declarations while the shared ML-KEM
 * namespace is configured. The single-compilation-unit source below undefines
 * those macros after emitting their implementation, so these public wrappers
 * must be defined first.
 */
#include "./vendor/mlkem-native/mlkem/src/fips202/fips202.h"
_Static_assert(SHA3_256_HASHBYTES == P2PARTY_FIPS202_SHA3_256_BYTES,
               "SHA3-256 output size mismatch");
#ifdef MLK_MAX_BUFFER_SIZE
_Static_assert(MLK_MAX_BUFFER_SIZE == P2PARTY_FIPS202_MAX_BUFFER_BYTES,
               "FIPS 202 proof-bound mismatch");
#endif

static int
p2party_regions_overlap(const uint8_t *left, size_t left_len,
                        const uint8_t *right, size_t right_len)
{
  uintptr_t left_address;
  uintptr_t right_address;

  if (left_len == 0 || right_len == 0) return 0;
  left_address = (uintptr_t)left;
  right_address = (uintptr_t)right;
  if (left_address <= right_address)
    return right_address - left_address < left_len;
  return left_address - right_address < right_len;
}

int
fips202_shake256(uint8_t *out, int out_len, const uint8_t *input, int input_len)
{
  size_t output_length;
  size_t input_length;

  if (out == NULL || input == NULL) return -1;
  if (out_len < 0 || input_len < 0) return -1;
  output_length = (size_t)out_len;
  input_length = (size_t)input_len;
  if (output_length > P2PARTY_FIPS202_MAX_BUFFER_BYTES
      || input_length > P2PARTY_FIPS202_MAX_BUFFER_BYTES)
    return -1;
  if (p2party_regions_overlap(out, output_length, input, input_length))
    return -1;

  mlk_shake256(out, output_length, input, input_length);
  return 0;
}

int
fips202_sha3_256(uint8_t out[P2PARTY_FIPS202_SHA3_256_BYTES],
                 const uint8_t *input, int input_len)
{
  size_t input_length;

  if (out == NULL || input == NULL) return -1;
  if (input_len < 0) return -1;
  input_length = (size_t)input_len;
  if (input_length > P2PARTY_FIPS202_MAX_BUFFER_BYTES) return -1;
  if (p2party_regions_overlap(out, P2PARTY_FIPS202_SHA3_256_BYTES, input,
                              input_length))
    return -1;

  mlk_sha3_256(out, input, input_length);
  return 0;
}

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
