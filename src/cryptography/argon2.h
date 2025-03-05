#ifndef argon2_H
#define argon2_H

#include "string.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../libsodium/src/libsodium/include/sodium/private/quirks.h"
#include "../../libsodium/src/libsodium/include/sodium/utils.h"

#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

#define ARGON2_MIN_OUTLEN UINT32_C(16)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

#define ARGON2_DEFAULT_FLAGS (UINT32_C(0))

typedef struct Argon2_Context
{
  uint8_t *out;    /* output array */
  uint32_t outlen; /* digest length */

  uint8_t *pwd;    /* password array */
  uint32_t pwdlen; /* password length */

  uint8_t *salt;    /* salt array */
  uint32_t saltlen; /* salt length */

  uint8_t *secret;    /* key array */
  uint32_t secretlen; /* key length */

  uint8_t *ad;    /* associated data array */
  uint32_t adlen; /* associated data length */

  uint32_t t_cost;  /* number of passes */
  uint32_t m_cost;  /* amount of memory requested (KB) */
  uint32_t lanes;   /* number of lanes */
  uint32_t threads; /* maximum number of threads */

  uint32_t flags; /* array of bool options */
} argon2_context;

/* Argon2 primitive type */
typedef enum Argon2_type
{
  Argon2_i = 1,
  Argon2_id = 2
} argon2_type;

/*
 * Function that performs memory-hard hashing with certain degree of parallelism
 * @param  context  Pointer to the Argon2 internal structure
 * @return Error code if smth is wrong, ARGON2_OK otherwise
 */
int argon2_ctx(argon2_context *context, argon2_type type);

int argon2(const unsigned int MNEMONIC_LEN,
           uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
           const char mnemonic[MNEMONIC_LEN],
           const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES]);

#endif
