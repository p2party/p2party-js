#ifndef p2party_argon2_H
#define p2party_argon2_H

#include <sodium.h>

int argon2(const unsigned int MNEMONIC_LEN,
           uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
           const char mnemonic[MNEMONIC_LEN],
           const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES]);

#endif
