#include <sodium.h>
#include <stdlib.h>

int
crypto_init(void)
{
  return sodium_init() < 0 ? -1 : 0;
}

__attribute__((constructor)) static void
crypto_init_or_abort(void)
{
  if (crypto_init() != 0) abort();
}

#include "./argon2.c"
#include "./ed25519.c"
#include "./merkle.c"
#include "./pake_ratchet.c"
#include "./utils.c"
