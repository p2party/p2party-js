import memory from "./memory";

import libcrypto from "./libcrypto";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_BYTES,
} from "./interfaces";

import type { SignKeyPair } from "./interfaces";
import type { LibCrypto } from "./libcrypto";

export const newKeyPair = async (module?: LibCrypto): Promise<SignKeyPair> => {
  const wasmMemory = module?.wasmMemory ?? memory.newKeyPairMemory();

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seedBytes = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SEEDBYTES,
  );
  window.crypto.getRandomValues(seedBytes);

  const result = cryptoModule._keypair_from_seed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  );

  cryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(publicKey),
        secretKey: Uint8Array.from(secretKey),
      };

      cryptoModule._free(ptr1);
      cryptoModule._free(ptr2);

      return keyPair;
    }

    default: {
      cryptoModule._free(ptr1);
      cryptoModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

export const keyPairFromSeed = async (
  seed: Uint8Array,
  module?: LibCrypto,
): Promise<SignKeyPair> => {
  const wasmMemory = module?.wasmMemory ?? memory.keyPairFromSeedMemory();

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seedBytes = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SEEDBYTES,
  );
  seedBytes.set(seed);

  const result = cryptoModule._keypair_from_seed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  );

  cryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(publicKey),
        secretKey: Uint8Array.from(secretKey),
      };

      cryptoModule._free(ptr1);
      cryptoModule._free(ptr2);

      return keyPair;
    }

    default: {
      cryptoModule._free(ptr1);
      cryptoModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

export const keyPairFromSecretKey = async (
  secretKey: Uint8Array,
  module?: LibCrypto,
): Promise<SignKeyPair> => {
  const wasmMemory = module?.wasmMemory ?? memory.keyPairFromSecretKeyMemory();

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(secretKey);

  const result = cryptoModule._keypair_from_secret_key(
    pk.byteOffset,
    sk.byteOffset,
  );

  cryptoModule._free(ptr2);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(pk),
        secretKey,
      };

      cryptoModule._free(ptr1);

      return keyPair;
    }

    default: {
      cryptoModule._free(ptr1);

      throw new Error("An unexpected error occured.");
    }
  }
};

/**
 * @function
 * Returns the signature of the data provided.
 */
export const sign = async (
  message: Uint8Array,
  secretKey: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> => {
  const messageLen = message.length;

  const wasmMemory = module ? module.wasmMemory : memory.signMemory(messageLen);

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(messageLen * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    messageLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_BYTES);
  const signature = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_BYTES,
  );

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(secretKey);

  cryptoModule._sign(
    messageLen,
    dataArray.byteOffset,
    sk.byteOffset,
    signature.byteOffset,
  );

  const sig = Uint8Array.from([...signature]);

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);

  return sig;
};

export const verify = async (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  module?: LibCrypto,
): Promise<boolean> => {
  const len = message.length;

  const wasmMemory = module ? module.wasmMemory : memory.verifyMemory(len);

  const cryptoModule = module ?? (await libcrypto({ wasmMemory }));

  const ptr1 = cryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = cryptoModule._malloc(crypto_sign_ed25519_BYTES);
  const sig = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_BYTES,
  );
  sig.set(signature);

  const ptr3 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const key = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  key.set(publicKey);

  const result = cryptoModule._verify(
    len,
    dataArray.byteOffset,
    key.byteOffset,
    sig.byteOffset,
  );

  cryptoModule._free(ptr1);
  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);

  return result === 0;
};
