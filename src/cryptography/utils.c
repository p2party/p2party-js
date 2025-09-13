#include "utils.h"

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

int
receive_message(
    uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
    const uint8_t merkle_root[crypto_hash_sha512_BYTES],
    const uint8_t sender_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  int v = verify(crypto_sign_ed25519_PUBLICKEYBYTES, message, sender_public_key,
                 &message[crypto_sign_ed25519_PUBLICKEYBYTES]);

  if (v != 0) return -1;

  int d = decrypt_chachapoly_asymmetric(
      ENCRYPTED_LEN,
      &message[crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES],
      message, receiver_secret_key, crypto_hash_sha512_BYTES, merkle_root,
      decrypted);

  if (d != 0) return -2;

  /* First 4 bytes = proof length (big-endian) */
  uint32_t proofLen = ((uint32_t)decrypted[METADATA_LEN] << 24)
                      | ((uint32_t)decrypted[METADATA_LEN + 1] << 16)
                      | ((uint32_t)decrypted[METADATA_LEN + 2] << 8)
                      | (uint32_t)decrypted[METADATA_LEN + 3];
  if (proofLen % (crypto_hash_sha512_BYTES + 1) != 0 || proofLen > PROOF_LEN)
    return -3;
  size_t proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  uint8_t *element_hash = malloc(sizeof(uint8_t) * crypto_hash_sha512_BYTES);
  if (element_hash == NULL) return -4;

  int h = crypto_hash_sha512(element_hash, &decrypted[METADATA_LEN + PROOF_LEN],
                             DECRYPTED_LEN - METADATA_LEN - PROOF_LEN);
  if (h != 0)
  {
    free(element_hash);

    return -5;
  }

  int vmp = verify_merkle_proof(proofArtifactsLen, element_hash, merkle_root,
                                &decrypted[METADATA_LEN + 4]);
  free(element_hash);
  if (vmp != 0) return -6;

  return 0;
}
