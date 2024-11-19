import cryptoMemory from "./memory";

import libcrypto from "./libcrypto";

import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  getEncryptedLen,
  getDecryptedLen,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";

import type { LibCrypto } from "./libcrypto";

/**
 * Encrypts a message with additional data using
 * the crypto_aead_chacha20poly1305_ietf_encrypt operation from
 * libsodium and computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 secret key and the receiver's Ed25519 public key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_server_session_keys.
 * The nonce is calculated by taking the first half of the
 * sha512 hash of a Uint8Array(3 * 32) array with 32 random bytes, the X25519 public key
 * and the X25519 secret key.
 * The auth tag is generated using Poly1305.
 *
 * If you need to perform bulk encryptions with predictable message
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.encryptMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all messages and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * ```ts
 * import dcrypto from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const aliceKeyPair = await dcrypto.keyPair();
 * const bobKeyPair = await dcrypto.keyPair();
 *
 * const box = await dcrypto.encrypt(
 *    message,
 *    bobKeyPair.publicKey,
 *    aliceKeyPair.secretKey,
 *    additionalData
 * );
 * ```
 *
 * @param message - the message to encrypt
 * @param receiverPublicKey - the receiver's Ed25519 public key
 * @param senderSecretKey - the sender's Ed25519 secret key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk encryptions
 *
 * @returns Encrypted box [nonce 16 || encrypted_data || auth tag 12]
 */
export const encryptAsymmetric = async (
  message: Uint8Array,
  receiverPublicKey: Uint8Array,
  senderSecretKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory =
    module?.wasmMemory ??
    cryptoMemory.encryptAsymmetricMemory(len, additionalLen);

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pk.set(receiverPublicKey);

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(senderSecretKey);

  const ptr4 = cryptoModule._malloc(
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  );
  const nonceArray = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  );
  const nonce = window.crypto.getRandomValues(
    new Uint8Array(crypto_aead_chacha20poly1305_ietf_NPUBBYTES),
  );
  nonceArray.set(nonce);

  const ptr5 = cryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const sealedBoxLen = getEncryptedLen(len);

  const ptr6 = cryptoModule._malloc(
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const encrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr6,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = cryptoModule._encrypt_chachapoly_asymmetric(
    len,
    dataArray.byteOffset,
    pk.byteOffset,
    sk.byteOffset,
    nonceArray.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);
  cryptoModule._free(ptr4);
  cryptoModule._free(ptr5);

  switch (result) {
    case 0: {
      const enc = Uint8Array.from(encrypted);
      cryptoModule._free(ptr6);

      return enc;
    }

    case -1: {
      cryptoModule._free(ptr6);

      throw new Error("Could not allocate memory for the ciphertext array.");
    }

    case -2: {
      cryptoModule._free(ptr6);

      throw new Error(
        "Could not allocate memory for the ephemeral x25519 public key array.",
      );
    }

    case -3: {
      cryptoModule._free(ptr6);

      throw new Error(
        "Could not allocate memory for the ephemeral x25519 secret key array.",
      );
    }

    case -4: {
      cryptoModule._free(ptr6);

      throw new Error(
        "Could not allocate memory for the receiver's ed25519 converted to x25519 public key array.",
      );
    }

    case -5: {
      cryptoModule._free(ptr6);

      throw new Error("Could not convert Ed25519 public key to X25519.");
    }

    case -6: {
      cryptoModule._free(ptr6);

      throw new Error("Could not allocate memory for the shared secret array.");
    }

    case -7: {
      cryptoModule._free(ptr6);

      throw new Error("Could not create a shared secret.");
    }

    case -8: {
      cryptoModule._free(ptr6);

      throw new Error("Could not allocate memory for the nonce helper array.");
    }

    default: {
      cryptoModule._free(ptr6);

      throw new Error("An unexpected error occured.");
    }
  }
};

/**
 * Decrypts a box with additional data using the
 * crypto_aead_chacha20poly1305_ietf_decrypt function from libsodium and
 * computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 public key and the receiver's Ed25519 secret key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_client_session_keys.
 * The encrypted box is a Uint8Array[nonce 16 || encrypted_data || auth tag 12].
 *
 * If you need to perform bulk decryptions with predictable box
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.decryptMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all boxes and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * @example
 * ```ts
 * import dcrypto from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const aliceKeyPair = await dcrypto.keyPair();
 * const bobKeyPair = await dcrypto.keyPair();
 *
 * const box = await dcrypto.encrypt(
 *    message,
 *    bobKeyPair.publicKey,
 *    aliceKeyPair.secretKey,
 *    additionalData
 * );
 *
 * const decrypted = await dcrypto.decrypt(
 *    box,
 *    bobKeyPair.secretKey,
 *    additionalData
 * );
 *
 * \/\/ message should be equal to decrypted.
 * ```
 *
 * @param encrypted - The encrypted box including sender public key, nonce and auth tag
 * @param receiverSecretKey - The receiver secret key
 * @param additionalData - The additional data for aead
 * @param module - The wasm module in case of bulk decryptions
 * @returns The decrypted message
 */
export const decryptAsymmetric = async (
  encrypted: Uint8Array,
  publicKey: Uint8Array,
  secretKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;

  const wasmMemory =
    module?.wasmMemory ??
    cryptoMemory.decryptAsymmetricMemory(len, additionalLen);

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const decryptedLen = getDecryptedLen(len);

  const ptr1 = cryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const encryptedArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set(encrypted);

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pub = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pub.set(publicKey);

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sec = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sec.set(secretKey);

  const ptr4 = cryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const ptr5 = cryptoModule._malloc(
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const decrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = cryptoModule._decrypt_chachapoly_asymmetric(
    len,
    encryptedArray.byteOffset,
    pub.byteOffset,
    sec.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const decr = Uint8Array.from(decrypted);
      cryptoModule._free(ptr4);

      return decr;
    }

    case -1: {
      cryptoModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ed25519 converted to x25519 public key array.",
      );
    }

    case -2: {
      cryptoModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ed25519 converted to x25519 secret key array.",
      );
    }

    case -3: {
      cryptoModule._free(ptr4);

      throw new Error(
        "Could not convert receiver ed25519 secret key to x25519.",
      );
    }

    case -4: {
      cryptoModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ed25519 converted to x25519 sender public key array.",
      );
    }

    case -5: {
      cryptoModule._free(ptr4);

      throw new Error("Could not convert sender ed25519 public key to x25519.");
    }

    case -6: {
      cryptoModule._free(ptr4);

      throw new Error("Could not allocate memory for the shared secret array.");
    }

    case -7: {
      cryptoModule._free(ptr4);

      throw new Error("Could not successfully generate a shared secret.");
    }

    case -8: {
      cryptoModule._free(ptr4);

      throw new Error("Could not allocate memory for the ciphertext array.");
    }

    default: {
      cryptoModule._free(ptr4);

      throw new Error("Unsuccessful decryption attempt");
    }
  }
};
