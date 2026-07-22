/* Minimal randombytes_buf for the emscripten build. libsodium's own
 * randombytes.c is not compiled (all other entropy is generated in JS and
 * passed in as seeds), but crypto_core_ristretto255_scalar_random and
 * x25519_keypair need randombytes_buf. Back it with emscripten's getentropy,
 * which maps to crypto.getRandomValues in web/worker. getentropy caps at 256
 * bytes per call. */
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

void
randombytes_buf(void *const buf, const size_t size)
{
  uint8_t *p = (uint8_t *)buf;
  size_t off = 0;
  while (off < size)
  {
    size_t n = size - off;
    if (n > 256) n = 256;
    (void)getentropy(p + off, n);
    off += n;
  }
}
