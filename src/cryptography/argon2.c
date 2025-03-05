#include "argon2.h"

int
argon2(const unsigned int MNEMONIC_LEN,
       uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
       const char mnemonic[MNEMONIC_LEN],
       const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES])
{
  // memset(seed, 0, crypto_sign_ed25519_SEEDBYTES);
  if (MNEMONIC_LEN > crypto_pwhash_argon2id_PASSWD_MAX)
  {
    // errno = EFBIG;
    return -1;
  }
  if (MNEMONIC_LEN < crypto_pwhash_argon2id_PASSWD_MIN)
  {
    // errno = EINVAL;
    return -2;
  }
  if ((const void *)seed == (const void *)mnemonic)
  {
    // errno = EINVAL;
    return -3;
  }

  // int
  // argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
  //             const uint32_t parallelism, const void *pwd, const size_t
  //             pwdlen, const void *salt, const size_t saltlen, void *hash,
  //             const size_t hashlen, char *encoded, const size_t encodedlen,
  //             argon2_type type)
  // int
  // argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
  //                  const uint32_t parallelism, const void *pwd,
  //                  const size_t pwdlen, const void *salt, const size_t
  //                  saltlen, void *hash, const size_t hashlen)
  // {
  //     return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt,
  //     saltlen,
  //                        hash, hashlen, NULL, 0, Argon2_i);
  // }
  // crypto_pwhash_argon2id(unsigned char *const out, unsigned long long outlen,
  //                      const char *const passwd, unsigned long long
  //                      passwdlen, const unsigned char *const salt, unsigned
  //                      long long opslimit, size_t memlimit, int alg)
  //
  // return crypto_pwhash_argon2id(seed, crypto_sign_ed25519_SEEDBYTES,
  // mnemonic,
  //                               MNEMONIC_LEN, salt,
  //                               crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
  //                               crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
  //                               crypto_pwhash_argon2id_ALG_ARGON2ID13);
  // seed = out, hash
  // crypto_sign_ed25519_SEEDBYTES = outlen, hashlen
  // mnemonic = passwd, pwd
  // MNEMONIC_LEN = passwdlen, pwdlen
  // salt = salt
  // crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = opslimit, t_cost
  // crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = memlimit, m_cost = (uint32_t)
  // (memlimit/1024U) (uint32_t) 1U = parallelism
  // crypto_pwhash_argon2id_ALG_ARGON2ID13 = alg

  // if (argon2id_hash_raw((uint32_t) opslimit, (uint32_t) (memlimit / 1024U),
  //                       (uint32_t) 1U, passwd, (size_t) passwdlen, salt,
  //                       (size_t) crypto_pwhash_argon2id_SALTBYTES, out,
  //                       (size_t) outlen) != ARGON2_OK) {
  //     return -1; /* LCOV_EXCL_LINE */
  // }

  argon2_context context;
  int result;
  uint8_t *out;

  if (MNEMONIC_LEN > ARGON2_MAX_PWD_LENGTH)
  {
    return -4; // ARGON2_PWD_TOO_LONG;
  }

  if (crypto_sign_ed25519_SEEDBYTES > ARGON2_MAX_OUTLEN)
  {
    return -5; // ARGON2_OUTPUT_TOO_LONG;
  }

  if (crypto_pwhash_argon2id_SALTBYTES > ARGON2_MAX_SALT_LENGTH)
  {
    return -6; // ARGON2_SALT_TOO_LONG;
  }

  out = (uint8_t *)malloc(crypto_sign_ed25519_SEEDBYTES);
  if (!out)
  {
    return -7; // ARGON2_MEMORY_ALLOCATION_ERROR;
  }

  context.out = (uint8_t *)out;
  context.outlen = (uint32_t)crypto_sign_ed25519_SEEDBYTES;
  context.pwd = (uint8_t *)mnemonic;
  context.pwdlen = (uint32_t)MNEMONIC_LEN;
  context.salt = (uint8_t *)salt;
  context.saltlen = (uint32_t)crypto_pwhash_argon2id_SALTBYTES;
  context.secret = NULL;
  context.secretlen = 0;
  context.ad = NULL;
  context.adlen = 0;
  context.t_cost = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
  context.m_cost
      = (uint32_t)(crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE / 1024U);
  context.lanes = (uint32_t)1U;
  context.threads = (uint32_t)1U;
  context.flags = ARGON2_DEFAULT_FLAGS;

  result = argon2_ctx(&context, Argon2_id);

  if (result != 0)
  {
    sodium_memzero(out, crypto_sign_ed25519_SEEDBYTES);
    free(out);

    return result;
  }

  /* if raw hash requested, write it */
  if (seed)
  {
    memcpy(seed, out, crypto_sign_ed25519_SEEDBYTES);
  }

  sodium_memzero(out, crypto_sign_ed25519_SEEDBYTES);
  free(out);

  return 0;
}
