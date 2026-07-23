#include "utils.h"

/* Streaming SHA-512 exposed to JS so the send side can hash an arbitrarily large
 * file incrementally (window-by-window) instead of loading the whole file into
 * memory for crypto.subtle.digest. Thin wrappers over the already-linked
 * libsodium multipart API; PLAIN SHA-512 (no domain prefix) so the result is
 * byte-identical to crypto.subtle.digest("SHA-512", ...). The JS side allocates
 * the 208-byte crypto_hash_sha512_state on the heap and passes its pointer. */
int
sha512_init(crypto_hash_sha512_state *state)
{
  if (!state) return -1;
  return crypto_hash_sha512_init(state);
}

int
sha512_update(crypto_hash_sha512_state *state, const uint8_t *in,
              const unsigned int in_len)
{
  if (!state || !in) return -1;
  return crypto_hash_sha512_update(state, in, (unsigned long long)in_len);
}

int
sha512_final(crypto_hash_sha512_state *state,
             uint8_t out[crypto_hash_sha512_BYTES])
{
  if (!state || !out) return -1;
  return crypto_hash_sha512_final(state, out);
}

int
serialize_metadata(uint8_t out[METADATA_LEN], uint64_t schemaVersion,
                   uint8_t messageType,
                   const uint8_t hash[crypto_hash_sha512_BYTES],
                   uint64_t totalSize, int64_t date_ms, const char *name,
                   uint64_t chunkStartIndex, uint64_t chunkEndIndex,
                   uint64_t chunkIndex)
{
  if (!out || !hash) return -1;
  unsigned int off = 0;

  be_put_u64(out + off, schemaVersion);
  off += 8;
  out[off++] = messageType;

  memcpy(out + off, hash, crypto_hash_sha512_BYTES);
  off += crypto_hash_sha512_BYTES;

  be_put_u64(out + off, totalSize);
  off += 8;
  be_put_u64(out + off, (uint64_t)date_ms);
  off += 8;

  memset(out + off, 0, NAME_LEN);
  if (name)
  {
    size_t n = strnlen(name, NAME_LEN);
    memcpy(out + off, name, n);
  }
  off += NAME_LEN;

  be_put_u64(out + off, chunkStartIndex);
  off += 8;
  be_put_u64(out + off, chunkEndIndex);
  off += 8;
  be_put_u64(out + off, chunkIndex);
  off += 8;

  return (int)off; // == METADATA_LEN
}

/* ---- Deserialize: buffer -> struct (expects exactly METADATA_LEN) ---- */
Metadata
deserialize_metadata(const uint8_t in[METADATA_LEN])
{
  Metadata m;
  unsigned int off = 0;

  m.schemaVersion = be_get_u64(in + off);
  off += 8;
  m.messageType = in[off++];

  memcpy(m.hash, in + off, crypto_hash_sha512_BYTES);
  off += crypto_hash_sha512_BYTES;

  m.totalSize = be_get_u64(in + off);
  off += 8;
  m.date_ms = (int64_t)be_get_u64(in + off);
  off += 8;

  memcpy(m.name, in + off, NAME_LEN);
  m.name[NAME_LEN] = '\0';
  /* Trim trailing zeros to a clean C string (optional) */
  for (int i = NAME_LEN - 1; i >= 0; --i)
  {
    if (m.name[i] != '\0')
    {
      m.name[i + 1] = '\0';
      break;
    }
    if (i == 0) m.name[0] = '\0';
  }
  off += NAME_LEN;

  m.chunkStartIndex = be_get_u64(in + off);
  off += 8;
  m.chunkEndIndex = be_get_u64(in + off);
  off += 8;
  m.chunkIndex = be_get_u64(in + off); /* off += 8; */

  return m;
}
