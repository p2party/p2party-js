#ifndef utils_H
#define utils_H

#include "merkle.h"
#include <sodium.h>

const unsigned int MESSAGE_LEN = 64 * 1024;
const unsigned int NAME_LEN = 256;
const unsigned int METADATA_LEN = 8 +                        // schemaVersion
                                  1 +                        // messageType
                                  crypto_hash_sha512_BYTES + // hash
                                  8 +                        // totalSize
                                  8 +                        // date
                                  NAME_LEN +                 // name
                                  8 +                        // chunkStartIndex
                                  8 +                        // chunkEndIndex
                                  8;                         // chunkIndex
const unsigned int PROOF_LEN
    = 4 + // length of the proof
      48
          * (crypto_hash_sha512_BYTES
             + 1); // ceil(log2(tree)) <= 48 * (hash + position)
/* Protocol-v4 authenticated-plaintext profile. The u64 PQ epoch adds seven
 * clear-header bytes relative to v3; padding pays for them so the complete
 * wire cell remains exactly 65,490 bytes. Byte-matched to constants.ts. */
#define CHUNK_PLAINTEXT_LEN 65405U
const unsigned int DECRYPTED_LEN = CHUNK_PLAINTEXT_LEN;
const unsigned int CHUNK_LEN = DECRYPTED_LEN - METADATA_LEN - PROOF_LEN;

/* Protocol-v4 wire framing, byte-matched to src/utils/constants.ts. */
#define PROTOCOL_VERSION 4U
#define FRAME_TYPE_LEN 1U
#define FRAME_TYPE_HANDSHAKE 1U
#define FRAME_TYPE_CHUNK 2U
#define FRAME_TYPE_RECEIPT 3U
#define FRAME_TYPE_COVER 4U
#define FRAME_TYPE_PQ_CONTROL 5U
#define PQ_TAG_LEN 1U

/* v4 large-cell clear header:
 * type(1) | dh-or-control-id(32) | N(8) | PN(8) | pqEpoch(8) | nonce(12).
 * CHUNK_AAD_HEADER_LEN excludes the nonce and is authenticated byte-for-byte.
 */
#define RATCHET_DHPUB_LEN 32U
#define RATCHET_N_LEN 8U
#define RATCHET_PN_LEN 8U
#define PQ_EPOCH_LEN 8U
#define RATCHET_NONCE_LEN 12U
#define CHUNK_AAD_HEADER_LEN                                                   \
  (FRAME_TYPE_LEN + RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN         \
   + PQ_EPOCH_LEN) /* 57 */
#define CHUNK_HEADER_LEN                                                       \
  (RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN + PQ_EPOCH_LEN           \
   + RATCHET_NONCE_LEN)                                   /* 68 */
#define MESSAGE_START (FRAME_TYPE_LEN + CHUNK_HEADER_LEN) /* 69 */
#define WIRE_CHUNK_FRAME_LEN 65490U
_Static_assert(
    MESSAGE_START + CHUNK_PLAINTEXT_LEN
            + crypto_aead_chacha20poly1305_ietf_ABYTES
        == WIRE_CHUNK_FRAME_LEN,
    "protocol-v4 chunk cell geometry must remain exactly 65,490 bytes");

typedef struct
{
  uint64_t schemaVersion;                 // 8
  uint8_t messageType;                    // 1
  uint8_t hash[crypto_hash_sha512_BYTES]; // 64
  uint64_t totalSize;                     // 8
  int64_t date_ms;                        // 8 (Unix ms)
  char *name;               // stored as 256 bytes; +1 for C NUL on read
  uint64_t chunkStartIndex; // 8
  uint64_t chunkEndIndex;   // 8
  uint64_t chunkIndex;      // 8
} Metadata;

static inline void
be_put_u64(uint8_t *p, uint64_t v)
{
  p[0] = (uint8_t)(v >> 56);
  p[1] = (uint8_t)(v >> 48);
  p[2] = (uint8_t)(v >> 40);
  p[3] = (uint8_t)(v >> 32);
  p[4] = (uint8_t)(v >> 24);
  p[5] = (uint8_t)(v >> 16);
  p[6] = (uint8_t)(v >> 8);
  p[7] = (uint8_t)(v);
}

static inline uint64_t
be_get_u64(const uint8_t *p)
{
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

int serialize_metadata(uint8_t out[METADATA_LEN], uint64_t schemaVersion,
                       uint8_t messageType,
                       const uint8_t hash[crypto_hash_sha512_BYTES],
                       uint64_t totalSize, int64_t date_ms, const char *name,
                       uint64_t chunkStartIndex, uint64_t chunkEndIndex,
                       uint64_t chunkIndex);

Metadata deserialize_metadata(const uint8_t in[METADATA_LEN]);

/* Streaming SHA-512 (see utils.c) — the state is a heap
 * crypto_hash_sha512_state (208 bytes) allocated by JS. Plain SHA-512, no
 * domain separation. */
int sha512_init(crypto_hash_sha512_state *state);
int sha512_update(crypto_hash_sha512_state *state, const uint8_t *in,
                  const unsigned int in_len);
int sha512_final(crypto_hash_sha512_state *state,
                 uint8_t out[crypto_hash_sha512_BYTES]);

#endif
