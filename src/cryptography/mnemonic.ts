import { keyPairFromSeed } from "./ed25519";
import memory from "./memory";

// import libcrypto from "./libcrypto";
import { wasmLoader } from "./wasmLoader";

import wordlist from "../utils/wordlist.json";

import {
  crypto_pwhash_argon2id_SALTBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "./interfaces";

import type { LibCrypto } from "./libcrypto";

const normalize = (str: string) => {
  return str.normalize("NFKD");
};

export const argon2 = async (
  mnemonic: string,
  salt?: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> => {
  const mnemonicNormalized = normalize(mnemonic);
  const encoder = new TextEncoder();
  const mnemonicBuffer = encoder.encode(mnemonicNormalized).buffer;
  const mnemonicInt8Array = new Int8Array(mnemonicBuffer);
  const mnemonicArrayLen = mnemonicInt8Array.length;

  salt =
    salt ??
    window.crypto.getRandomValues(
      new Uint8Array(crypto_pwhash_argon2id_SALTBYTES),
    );

  const wasmMemory =
    module?.wasmMemory ?? memory.argon2Memory(mnemonicArrayLen);

  // module = module ?? (await libcrypto({ wasmMemory }));
  module = module ?? (await wasmLoader(wasmMemory));

  const ptr1 = module._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_SEEDBYTES,
  );
  const randomData = window.crypto.getRandomValues(
    new Uint8Array(crypto_sign_ed25519_SEEDBYTES),
  );
  seed.set(randomData);

  const ptr2 = module._malloc(mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT);
  const mnmnc = new Int8Array(
    wasmMemory.buffer,
    ptr2,
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  mnmnc.set(mnemonicInt8Array);

  const ptr3 = module._malloc(crypto_pwhash_argon2id_SALTBYTES);
  const saltArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_pwhash_argon2id_SALTBYTES,
  );
  saltArray.set(salt);

  const result = module._argon2(
    mnemonicArrayLen,
    seed.byteOffset,
    mnmnc.byteOffset,
    saltArray.byteOffset,
  );

  const s = Uint8Array.from(seed);

  module._free(ptr1);
  module._free(ptr2);
  module._free(ptr3);

  if (result === 0) {
    return s;
  } else {
    throw new Error("Could not generate argon2id for mnemonic.");
  }
};

/**
 * Generates a sequence of words chosen from a prespecified wordlist
 * that represents a random seed that
 * can be translated later into a cryptographic keypair.
 * With a strength of 128 bits of entropy you get 12 words.
 * In every additional step you get 3 more words. The maximum is
 * set to 512 bits of entropy, or 48 words!
 *
 * @param strength - Entropy bits
 * @returns The mnemonic from the wordlist.
 *
 */
export const generateMnemonic = async (
  strength:
    | 128
    | 160
    | 192
    | 224
    | 256
    | 288
    | 320
    | 352
    | 384
    | 416
    | 448
    | 480
    | 512 = 128,
): Promise<string> => {
  if (!wordlist) throw new Error("English wordlist could not be loaded.");

  if (strength % 32 !== 0)
    throw new TypeError("Mnemonic strength needs to be multiple of 32.");

  if (
    ![128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 480, 512].includes(
      strength,
    )
  )
    throw new Error("Wrong mnemonic strength");

  // Between 16 and 64 and multiple of 4
  const entropy = window.crypto.getRandomValues(new Uint8Array(strength / 8));
  const entropyBits = entropy.reduce(
    (str, byte) => str + byte.toString(2).padStart(8, "0"),
    "",
  );

  const CS = strength / 32;
  const entropyArray = Uint8Array.from(entropy);
  const entropyHash = await window.crypto.subtle.digest(
    "SHA-512",
    entropyArray,
  );
  const checksumBits = new Uint8Array(entropyHash)
    .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
    .slice(0, CS);

  const bits = entropyBits + checksumBits;

  // eslint-disable-next-line @typescript-eslint/non-nullable-type-assertion-style
  const chunks = bits.match(/(.{1,11})/g) as RegExpMatchArray;

  // if (!chunks)
  //   throw new Error("Did not find enough 1s and 11s in binary format.");

  const words = chunks.map((binary: string): string => {
    const index = parseInt(binary, 2);
    return wordlist[index];
  });

  return words.join(" ");
};

export const mnemonicToEntropy = async (mnemonic: string): Promise<boolean> => {
  // if (!wordlist) throw new Error("Could not load english wordlist");

  const words = normalize(mnemonic).split(" ");
  if (words.length % 3 !== 0)
    throw new Error("Number of words in mnemonic must be multiple of three.");

  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word: string): string => {
      const index = wordlist.indexOf(word);
      if (index === -1) {
        throw new Error("Could not find word in wordlist.");
      }

      return index.toString(2).padStart(11, "0");
      // return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // convert bits to entropy
  // eslint-disable-next-line @typescript-eslint/non-nullable-type-assertion-style
  const entropyBitsMatched = entropyBits.match(/(.{1,8})/g) as RegExpMatchArray;

  // if (!entropyBitsMatched) throw new Error("Invalid entropy bits.");

  // calculate the checksum and compare
  const entropy = entropyBitsMatched.map((bin: string) => parseInt(bin, 2));

  if (entropy.length < 16)
    throw new Error("Entropy length too small (less than 128 bits).");

  if (entropy.length > 64)
    throw new Error("Entropy length too large (more than 512 bits).");

  // Can never happen because of :45 always divisible by 4
  // if (entropy.length % 4 !== 0)
  //   throw new Error("Entropy length must be a multiple of 4.");

  const CS = entropy.length / 4;
  const entropyArray = Uint8Array.from(entropy);
  const entropyHash = await window.crypto.subtle.digest(
    "SHA-512",
    entropyArray,
  );
  const newChecksum = new Uint8Array(entropyHash)
    .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
    .slice(0, CS);

  if (newChecksum !== checksumBits) throw new Error("Invalid checksum.");

  return true;
};

export const validateMnemonic = async (mnemonic: string): Promise<boolean> => {
  try {
    return await mnemonicToEntropy(mnemonic);
  } catch {
    return false;
  }
};

/**
 * Generates an Ed25519 key pair from the provided mnemonic.
 * Optionally, you can strenthen the generation with a password.
 * The mnemonic is converted into a seed through the use of argon2id.
 * The password is used as a salt for argon2id.
 * From the generated seed we extract the key pair.
 *
 * @param mnemonic - Sequence of words from the predefined wordlist
 * @param password - Optional salt for the seed derivation
 * @returns An Ed25519 key pair
 */
export const keyPairFromMnemonic = async (
  mnemonic: string,
  password?: string,
) => {
  const isValid = await validateMnemonic(mnemonic);
  if (!isValid) throw new Error("Invalid mnemonic.");

  // const defaultSalt = Uint8Array.from(Buffer.from("password12345678", "utf8"));
  const defaultSalt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);
  const encoder = new TextEncoder();
  encoder.encodeInto("password12345678", defaultSalt);
  const salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);

  if (password) {
    const pwdBuffer = encoder.encode(password);
    const pwdHash = await window.crypto.subtle.digest("SHA-512", pwdBuffer);

    salt.set(
      new Uint8Array(pwdHash).slice(
        crypto_hash_sha512_BYTES - crypto_pwhash_argon2id_SALTBYTES,
        crypto_hash_sha512_BYTES,
      ),
    );
  } else {
    salt.set(defaultSalt);
  }

  const seed = await argon2(mnemonic, salt);

  return await keyPairFromSeed(seed);
};
