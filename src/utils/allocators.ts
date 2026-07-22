import {
  ENCRYPTED_LEN,
  DECRYPTED_LEN,
  CHUNK_AUTH_TRANSCRIPT_LEN,
} from "./constants";

import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../cryptography/interfaces";

import type { LibCrypto } from "../cryptography/libcrypto";

export const allocateSendMessage = (encryptionModule: LibCrypto) => {
  const ptr1 = encryptionModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const senderEphemeralPublicKey = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = encryptionModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const senderEphemeralSecretKey = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr3 = encryptionModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seedBytes = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SEEDBYTES,
  );

  const ptr5 = encryptionModule._malloc(crypto_sign_ed25519_BYTES);
  const senderEphemeralSignature = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr5,
    crypto_sign_ed25519_BYTES,
  );

  const ptr6 = encryptionModule._malloc(DECRYPTED_LEN);
  const chunkArray = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr6,
    DECRYPTED_LEN,
  );

  const ptr7 = encryptionModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const receiverPublicKeyArray = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr7,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr9 = encryptionModule._malloc(
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  );
  const nonceArray = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr9,
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  );

  const ptr10 = encryptionModule._malloc(ENCRYPTED_LEN);
  const encryptedArray = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptr10,
    ENCRYPTED_LEN,
  );

  // Buffer for the per-chunk sender-auth transcript
  // (DOMAIN || merkle_root || ephemeral_pk), signed instead of the bare pk.
  const ptrTranscript = encryptionModule._malloc(CHUNK_AUTH_TRANSCRIPT_LEN);
  const authTranscript = new Uint8Array(
    encryptionModule.wasmMemory.buffer,
    ptrTranscript,
    CHUNK_AUTH_TRANSCRIPT_LEN,
  );

  return {
    ptr1,
    ptr2,
    ptr3,
    ptr5,
    ptr6,
    ptr7,
    ptr9,
    ptr10,
    ptrTranscript,
    senderEphemeralPublicKey,
    senderEphemeralSecretKey,
    seedBytes,
    senderEphemeralSignature,
    chunkArray,
    receiverPublicKeyArray,
    nonceArray,
    encryptedArray,
    authTranscript,
  };
};
