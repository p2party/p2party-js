#include "merkle.h"

/* Domain separation (CVE-2012-2459 class): leaves are hashed with a 0x00 prefix
 * at the call sites (splitToChunks / receive_message), internal nodes with a
 * 0x01 prefix here, so an internal-node hash can never be reinterpreted as a
 * leaf. Lone odd nodes are PROMOTED unchanged to the next level instead of being
 * hashed with themselves (H(x||x)), which otherwise lets distinct leaf multisets
 * collide to the same root. */
#define MERKLE_NODE_DOMAIN 0x01

static int
hash_node(uint8_t out[crypto_hash_sha512_BYTES],
          const uint8_t left[crypto_hash_sha512_BYTES],
          const uint8_t right[crypto_hash_sha512_BYTES])
{
  uint8_t buf[1 + 2 * crypto_hash_sha512_BYTES];
  buf[0] = MERKLE_NODE_DOMAIN;
  memcpy(buf + 1, left, crypto_hash_sha512_BYTES);
  memcpy(buf + 1 + crypto_hash_sha512_BYTES, right, crypto_hash_sha512_BYTES);

  return crypto_hash_sha512(out, buf, sizeof(buf));
}

int
get_merkle_root(const unsigned int LEAVES_LEN,
                uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
                uint8_t root[crypto_hash_sha512_BYTES])
{
  size_t i, j;
  int res;
  unsigned int leaves = LEAVES_LEN;

  // For every branch level.
  while (leaves > 1)
  {
    bool odd_leaves = leaves % 2 != 0;

    // For every two leaves (writing the parent in place at index j <= i).
    for (i = 0, j = 0; i < leaves; i += 2, j++)
    {
      if (odd_leaves && i + 1 == leaves)
      {
        // Lone odd node: promote unchanged (no self-hash).
        memcpy(&leaves_hashed[j * crypto_hash_sha512_BYTES],
               &leaves_hashed[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
      }
      else
      {
        res = hash_node(&leaves_hashed[j * crypto_hash_sha512_BYTES],
                        &leaves_hashed[i * crypto_hash_sha512_BYTES],
                        &leaves_hashed[(i + 1) * crypto_hash_sha512_BYTES]);
        if (res != 0) return -2;
      }
    }

    leaves = (leaves + 1) / 2; // ceil
  }

  memcpy(root, leaves_hashed, crypto_hash_sha512_BYTES);

  return 0;
}

// The result is the proof length in bytes.
int
get_merkle_proof(const unsigned int LEAVES_LEN,
                 uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
                 const uint8_t element_hash[crypto_hash_sha512_BYTES],
                 uint8_t proof[LEAVES_LEN * (crypto_hash_sha512_BYTES + 1)])
{
  int res, index = -1;
  size_t i, j, k;

  for (i = 0; i < LEAVES_LEN; i++)
  {
    res = memcmp(&leaves_hashed[i * crypto_hash_sha512_BYTES], element_hash,
                 crypto_hash_sha512_BYTES);
    if (res != 0) continue;

    index = i;
    break;
  }

  if (index == -1) return -1;

  unsigned int element_of_interest = index;
  unsigned int leaves = LEAVES_LEN;

  // Counts the number of proof artifacts emitted.
  k = 0;

  while (leaves > 1)
  {
    bool odd_leaves = leaves % 2 != 0;

    for (i = 0, j = 0; i < leaves; i += 2, j++)
    {
      if (odd_leaves && i + 1 == leaves)
      {
        // Lone odd node: promoted unchanged, so it contributes no artifact.
        if (i == element_of_interest) element_of_interest = j;

        memcpy(&leaves_hashed[j * crypto_hash_sha512_BYTES],
               &leaves_hashed[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
      }
      else
      {
        if (i == element_of_interest)
        {
          // Sibling is on the right.
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)],
                 &leaves_hashed[(i + 1) * crypto_hash_sha512_BYTES],
                 crypto_hash_sha512_BYTES);
          proof[k * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
              = 1;

          k++;
          element_of_interest = j;
        }
        else if (i + 1 == element_of_interest)
        {
          // Sibling is on the left.
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)],
                 &leaves_hashed[i * crypto_hash_sha512_BYTES],
                 crypto_hash_sha512_BYTES);
          proof[k * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
              = 0;

          k++;
          element_of_interest = j;
        }

        res = hash_node(&leaves_hashed[j * crypto_hash_sha512_BYTES],
                        &leaves_hashed[i * crypto_hash_sha512_BYTES],
                        &leaves_hashed[(i + 1) * crypto_hash_sha512_BYTES]);
        if (res != 0) return -3;
      }
    }

    leaves = (leaves + 1) / 2; // ceil
  }

  return k * (crypto_hash_sha512_BYTES + 1);
}

int
get_merkle_root_from_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)],
    uint8_t root[crypto_hash_sha512_BYTES])
{
  memcpy(root, element_hash, crypto_hash_sha512_BYTES);

  size_t i;
  unsigned int position;
  int res;

  // Single-leaf tree: the proof is (a copy of) the element hash, which is the
  // root. Distinguished from a 2-leaf proof by root == element.
  if (PROOF_ARTIFACTS_LEN == 1
      && memcmp(proof, element_hash, crypto_hash_sha512_BYTES) == 0)
  {
    return 0;
  }

  for (i = 0; i < PROOF_ARTIFACTS_LEN; i++)
  {
    position
        = proof[i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES];

    if (position == 0)
    {
      // Proof artifact is the left sibling.
      res = hash_node(root, &proof[i * (crypto_hash_sha512_BYTES + 1)], root);
    }
    else if (position == 1)
    {
      // Proof artifact is the right sibling.
      res = hash_node(root, root, &proof[i * (crypto_hash_sha512_BYTES + 1)]);
    }
    else
    {
      return -2;
    }

    if (res != 0) return -3;
  }

  return 0;
}

int
verify_merkle_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t root[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)])
{
  int res;
  size_t i, position;

  // Single-leaf tree: root == element (proof carries the element hash).
  if (PROOF_ARTIFACTS_LEN == 1
      && memcmp(root, element_hash, crypto_hash_sha512_BYTES) == 0)
  {
    return 0;
  }

  for (i = 0; i < PROOF_ARTIFACTS_LEN; i++)
  {
    position
        = proof[i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES];
    if (position != 0 && position != 1) return -3;

    if (position == 0)
    {
      // Proof artifact is the left sibling.
      res = hash_node(element_hash, &proof[i * (crypto_hash_sha512_BYTES + 1)],
                      element_hash);
    }
    else
    {
      // Proof artifact is the right sibling.
      res = hash_node(element_hash, element_hash,
                      &proof[i * (crypto_hash_sha512_BYTES + 1)]);
    }

    if (res != 0) return -4;
  }

  res = memcmp(element_hash, root, crypto_hash_sha512_BYTES);

  if (res != 0) return 1;

  return 0;
}
