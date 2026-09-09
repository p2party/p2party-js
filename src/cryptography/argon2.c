#include "argon2.h"

int
argon2(const unsigned int MNEMONIC_LEN,
       uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
       const char mnemonic[MNEMONIC_LEN],
       const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES])
{
  return crypto_pwhash_argon2id(seed, crypto_sign_ed25519_SEEDBYTES, mnemonic,
                                (unsigned long long)MNEMONIC_LEN, salt,
                                crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
                                crypto_pwhash_argon2id_ALG_ARGON2ID13);
}
