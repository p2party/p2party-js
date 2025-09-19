import {
  getEncryptedLen,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

export const MESSAGE_LEN = 64 * 1024;
export const MAX_BUFFERED_AMOUNT = 2 * MESSAGE_LEN;
export const PROOF_LEN =
  4 + // length of the proof
  48 * (crypto_hash_sha512_BYTES + 1); // ceil(log2(tree)) <= 48 * (hash + position)
export const NAME_LEN = 256;
export const METADATA_LEN =
  8 + // schemaVersion (8 bytes)
  1 + // messageType (1 byte)
  crypto_hash_sha512_BYTES + // hash
  8 + // totalSize (8 bytes)
  8 + // date (8 bytes)
  NAME_LEN + // name (256 bytes)
  8 + // chunkStartIndex (8 bytes)
  8 + // chunkEndIndex (8 bytes)
  8; // chunkIndex (8 bytes)
export const IMPORTANT_DATA_LEN =
  crypto_sign_ed25519_PUBLICKEYBYTES + // ephemeral pk
  crypto_sign_ed25519_BYTES + // pk signed with identity sk
  METADATA_LEN + // fixed
  PROOF_LEN + // Merkle proof max len of 3kb
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES + // Encrypted message nonce
  crypto_box_poly1305_AUTHTAGBYTES; // Encrypted message auth tag
export const CHUNK_LEN =
  MESSAGE_LEN - // 64kb max message size on RTCDataChannel
  // crypto_hash_sha512_BYTES - // merkle root of message
  IMPORTANT_DATA_LEN;
export const DECRYPTED_LEN = METADATA_LEN + PROOF_LEN + CHUNK_LEN;
export const ENCRYPTED_LEN = getEncryptedLen(DECRYPTED_LEN);
