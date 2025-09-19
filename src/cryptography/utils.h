#ifndef utils_H
#define utils_H

#include "chacha20poly1305.h"
#include "ed25519.h"
#include "merkle.h"

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
const unsigned int IMPORTANT_DATA_LEN
    = crypto_sign_ed25519_PUBLICKEYBYTES + // ephemeral pk
      crypto_sign_ed25519_BYTES +          // pk signed with identity sk
      METADATA_LEN +                       // fixed
      PROOF_LEN +                          // Merkle proof max len of 3kb
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES + // Encrypted message nonce
      crypto_aead_chacha20poly1305_ietf_ABYTES; // Encrypted message auth tag
const unsigned int CHUNK_LEN = MESSAGE_LEN - IMPORTANT_DATA_LEN;
const unsigned int DECRYPTED_LEN = METADATA_LEN + PROOF_LEN + CHUNK_LEN;
const unsigned int ENCRYPTED_LEN
    = DECRYPTED_LEN + crypto_aead_chacha20poly1305_ietf_NPUBBYTES
      +                                         // Encrypted message nonce
      crypto_aead_chacha20poly1305_ietf_ABYTES; // Encrypted message auth tag
// const unsigned int ENCRYPTED_LEN = MESSAGE_LEN
//                                    - crypto_sign_ed25519_PUBLICKEYBYTES
//                                    - crypto_sign_ed25519_BYTES;
// const unsigned int DECRYPTED_LEN = ENCRYPTED_LEN
//                                    -
//                                    crypto_aead_chacha20poly1305_ietf_NPUBBYTES
//                                    -
//                                    crypto_aead_chacha20poly1305_ietf_ABYTES;

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

int receive_message(
    uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
    const uint8_t merkle_root[crypto_hash_sha512_BYTES],
    const uint8_t sender_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

#endif
