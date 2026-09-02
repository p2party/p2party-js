import { keyPairFromSeed } from "./ed25519";
import memory from "./memory";
import { fillRandomBytesInto } from "./random";
import { zeroFree } from "../utils/zeroFree";

// import libcrypto from "./libcrypto";
import { wasmLoader } from "./wasmLoader";

import wordlist from "../utils/wordlist.json";

import {
  crypto_pwhash_argon2id_SALTBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "./interfaces";

import type { LibCrypto } from "./libcrypto";

/** 128 bits of entropy plus its checksum. */
const MIN_MNEMONIC_WORDS = 12;
/** 512 bits of entropy plus its checksum. */
const MAX_MNEMONIC_WORDS = 48;

/** Constant-time-irrelevant lookup of a public wordlist, but O(1) per word. */
const wordIndices = new Map<string, number>(
  wordlist.map((word, index) => [word, index]),
);

/**
 * The result of a mnemonic check, shaped for a form field: `reason` is a
 * displayable sentence naming the first problem found, and is absent when the
 * phrase is usable.
 */
export interface MnemonicValidation {
  ok: boolean;
  reason?: string;
}

const normalize = (str: string) => {
  return str.normalize("NFKD");
};

/**
 * The canonical form of a recovery phrase, and part of the derivation
 * contract: NFKD, then any run of whitespace collapsed to a single space,
 * trimmed, lowercased.
 *
 * A phrase is transcribed by a human from paper, a password manager or a
 * screenshot, so it arrives with a trailing newline, a double space, a soft
 * wrap, or a capital first letter from a keyboard's autocapitalisation. All of
 * those used to be rejected outright by the wordlist lookup. Normalising them
 * away here means `"  Adapt  patrol "` and `"adapt patrol"` are the same
 * phrase everywhere: for validation, and for the argon2id input that produces
 * the seed. Every phrase that derived a key before this normalisation existed
 * was already in canonical form, so no backup changes what it restores.
 */
export const normalizeMnemonic = (mnemonic: string): string =>
  normalize(mnemonic).replace(/\s+/g, " ").trim().toLowerCase();

/**
 * SHA-512 over the Web Crypto boundary that browsers, workers, Node 20+ and
 * Bun all share. `globalThis` rather than `window`: this module is imported by
 * the session API, which runs outside a document.
 */
const sha512 = async (data: Uint8Array): Promise<Uint8Array> => {
  const subtle = globalThis.crypto?.subtle;
  if (typeof subtle?.digest !== "function")
    throw new Error("Web Crypto SHA-512 is unavailable");

  // A copy, so a caller may hand us a view into WebAssembly.Memory: Chromium
  // rejects BufferSource inputs backed by resizable buffers.
  return new Uint8Array(await subtle.digest("SHA-512", data.slice()));
};

const toBits = (bytes: Uint8Array): string =>
  bytes.reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "");

const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  fillRandomBytesInto(bytes);

  return bytes;
};

/**
 * Derive an argon2id seed from a passphrase.
 *
 * This is the low-level KDF: it applies NFKD only, because an arbitrary
 * passphrase is not a mnemonic and must not be lowercased. Callers that hash a
 * recovery phrase pass it through `normalizeMnemonic` first, as
 * `keyPairFromMnemonic` does.
 *
 * @param mnemonic - Passphrase to stretch
 * @param salt - Optional salt; a random one is generated when omitted
 * @param module - Optional preloaded WASM module, otherwise one is loaded
 * @returns The argon2id seed. The caller owns it and should wipe it.
 */
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

  salt = salt ?? randomBytes(crypto_pwhash_argon2id_SALTBYTES);

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

  const ptr2 = module._malloc(mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT);
  const mnmnc = new Int8Array(
    wasmMemory.buffer,
    ptr2,
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const ptr3 = module._malloc(crypto_pwhash_argon2id_SALTBYTES);
  const saltArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_pwhash_argon2id_SALTBYTES,
  );
  try {
    fillRandomBytesInto(seed);
    mnmnc.set(mnemonicInt8Array);
    saltArray.set(salt);

    const result = module._argon2(
      mnemonicArrayLen,
      seed.byteOffset,
      mnmnc.byteOffset,
      saltArray.byteOffset,
    );
    if (result !== 0)
      throw new Error("Could not generate argon2id for mnemonic.");
    return Uint8Array.from(seed);
  } finally {
    zeroFree(module, seed);
    zeroFree(
      module,
      new Uint8Array(
        wasmMemory.buffer,
        ptr2,
        mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
      ),
    );
    module._free(ptr3);
    mnemonicInt8Array.fill(0);
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
  if (strength % 32 !== 0)
    throw new TypeError("Mnemonic strength needs to be multiple of 32.");

  if (
    ![128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 480, 512].includes(
      strength,
    )
  )
    throw new Error("Wrong mnemonic strength");

  // Between 16 and 64 and multiple of 4
  const entropy = randomBytes(strength / 8);
  const entropyBits = toBits(entropy);

  const CS = strength / 32;
  const entropyHash = await sha512(entropy);
  const checksumBits = toBits(entropyHash).slice(0, CS);

  const bits = entropyBits + checksumBits;

  const chunks = bits.match(/(.{1,11})/g) as RegExpMatchArray;

  // if (!chunks)
  //   throw new Error("Did not find enough 1s and 11s in binary format.");

  const words = chunks.map((binary: string): string => {
    const index = parseInt(binary, 2);
    return wordlist[index];
  });

  entropy.fill(0);
  entropyHash.fill(0);

  return words.join(" ");
};

export const mnemonicToEntropy = async (mnemonic: string): Promise<boolean> => {
  // if (!wordlist) throw new Error("Could not load english wordlist");

  const words = normalizeMnemonic(mnemonic).split(" ");
  if (words.length % 3 !== 0)
    throw new Error("Number of words in mnemonic must be multiple of three.");

  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word: string): string => {
      const index = wordIndices.get(word);
      if (index === undefined) {
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
  const entropyHash = await sha512(entropyArray);
  const newChecksum = toBits(entropyHash).slice(0, CS);

  entropyArray.fill(0);
  entropyHash.fill(0);

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
 * Everything about a recovery phrase that can be checked without hashing:
 * word count and membership of the wordlist. Synchronous, so a form can call
 * it on every keystroke and tell the user which word they mistyped.
 *
 * The checksum is deliberately not checked here — SHA-512 is only available
 * asynchronously through Web Crypto. Use `validateMnemonicPhrase` (or
 * `validateMnemonic`) once the phrase is structurally complete.
 *
 * @param words - The phrase as typed; normalisation is applied for you
 * @returns `{ ok }`, plus a displayable `reason` for the first problem found
 */
export const validateMnemonicWords = (words: string): MnemonicValidation => {
  const mnemonic = normalizeMnemonic(words);
  if (mnemonic.length === 0)
    return { ok: false, reason: "The recovery phrase is empty." };

  const list = mnemonic.split(" ");
  if (list.length < MIN_MNEMONIC_WORDS || list.length > MAX_MNEMONIC_WORDS)
    return {
      ok: false,
      reason: `A recovery phrase has between ${String(MIN_MNEMONIC_WORDS)} and ${String(MAX_MNEMONIC_WORDS)} words, not ${String(list.length)}.`,
    };

  if (list.length % 3 !== 0)
    return {
      ok: false,
      reason: `The number of words must be a multiple of three, not ${String(list.length)}.`,
    };

  for (let i = 0; i < list.length; i++) {
    if (!wordIndices.has(list[i]))
      return {
        ok: false,
        reason: `Word ${String(i + 1)}, "${list[i]}", is not in the wordlist.`,
      };
  }

  return { ok: true };
};

/**
 * The full check: `validateMnemonicWords` plus the checksum, reported in the
 * same shape so a form can show one message wherever the phrase went wrong.
 *
 * @param words - The phrase as typed; normalisation is applied for you
 * @returns `{ ok }`, plus a displayable `reason` when the phrase is unusable
 */
export const validateMnemonicPhrase = async (
  words: string,
): Promise<MnemonicValidation> => {
  const structure = validateMnemonicWords(words);
  if (!structure.ok) return structure;

  try {
    await mnemonicToEntropy(words);

    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof Error
          ? error.message
          : "The recovery phrase is invalid.",
    };
  }
};

/**
 * Generates an Ed25519 key pair from the provided mnemonic.
 * Optionally, you can strenthen the generation with a password.
 * The mnemonic is converted into a seed through the use of argon2id.
 * The password is used as a salt for argon2id.
 * From the generated seed we extract the key pair.
 *
 * The phrase is normalised first (see `normalizeMnemonic`), so how it was
 * typed does not change the identity it restores. Nothing here is persisted:
 * the seed, the salt and the encoded password are wiped before returning, and
 * the phrase itself stays the caller's to forget.
 *
 * @param mnemonic - Sequence of words from the predefined wordlist
 * @param password - Optional salt for the seed derivation
 * @param module - Optional preloaded WASM module, otherwise one is loaded
 * @returns An Ed25519 key pair
 */
export const keyPairFromMnemonic = async (
  mnemonic: string,
  password?: string,
  module?: LibCrypto,
) => {
  const normalized = normalizeMnemonic(mnemonic);
  const isValid = await validateMnemonic(normalized);
  if (!isValid) throw new Error("Invalid mnemonic.");

  // const defaultSalt = Uint8Array.from(Buffer.from("password12345678", "utf8"));
  const encoder = new TextEncoder();
  const salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);

  if (password) {
    const pwdBuffer = encoder.encode(password);
    let pwdHash: Uint8Array | undefined;
    try {
      pwdHash = await sha512(pwdBuffer);
      salt.set(
        pwdHash.subarray(
          crypto_hash_sha512_BYTES - crypto_pwhash_argon2id_SALTBYTES,
          crypto_hash_sha512_BYTES,
        ),
      );
    } finally {
      pwdBuffer.fill(0);
      pwdHash?.fill(0);
    }
  } else {
    encoder.encodeInto("password12345678", salt);
  }

  const seed = await argon2(normalized, salt, module);

  try {
    return await keyPairFromSeed(seed, module);
  } finally {
    seed.fill(0);
    salt.fill(0);
  }
};
