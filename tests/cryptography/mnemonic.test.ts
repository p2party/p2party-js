import { readFileSync } from "node:fs";

import { describe, expect, test } from "bun:test";

import libcrypto from "../../src/cryptography/libcrypto";
import memory from "../../src/cryptography/memory";
import {
  generateMnemonic,
  keyPairFromMnemonic,
  validateMnemonic,
  validateMnemonicPhrase,
  validateMnemonicWords,
} from "../../src/cryptography/mnemonic";
import { secureRandomUint32 } from "../../src/cryptography/random";

import wordlist from "../../src/utils/wordlist.json";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

/**
 * Known-answer vector. The phrase encodes the fixed entropy bytes
 * `i * 17 + 3` for i in 0..15 plus this library's SHA-512 checksum nibble, and
 * the public key is what `keyPairFromMnemonic` derived before this module was
 * made runtime-agnostic. Argon2id parameters, the salt scheme and the
 * normalisation contract are all pinned by this constant: if a change to the
 * derivation makes an existing backup phrase restore a different identity,
 * this test fails.
 */
const KAT_MNEMONIC =
  "adapt patrol eternal modify make run common noble salute lecture detail air";
const KAT_PUBLIC_KEY_HEX =
  "83a316bebc4b4a3ddbc490b48c2cab7269c21b82d9ca5d5d49d91933b1c43203";

/**
 * The same entropy with the final word replaced. The 12-word checksum is only
 * four bits wide, so the replacement is a fixed vector that was checked to
 * actually break the checksum rather than a random other word.
 */
const KAT_MNEMONIC_CORRUPTED =
  "adapt patrol eternal modify make run common noble salute lecture detail zoo";

/**
 * Argon2id over a 75 MiB heap costs ~0.4 s per derivation here, including
 * instantiating the WASM module, so this file keeps to five derivations in
 * total and still allows a wide margin on slower machines.
 */
const DERIVATION_TIMEOUT_MS = 60_000;

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

/**
 * A module big enough for argon2id, so the preloaded-module path can be
 * exercised (`loadTestModule` deliberately caps its heap at 2 MiB).
 */
const loadArgon2Module = async (): Promise<LibCrypto> => {
  const fileBytes = readFileSync(
    new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
  );
  const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
  new Uint8Array(wasmBinary).set(fileBytes);

  return (await libcrypto({
    wasmBinary,
    wasmMemory: memory.argon2Memory(KAT_MNEMONIC.length),
    getRandomValue: secureRandomUint32,
  })) as LibCrypto;
};

describe("mnemonic generation", () => {
  test("128 bits of entropy give twelve wordlist words that validate", async () => {
    const mnemonic = await generateMnemonic(128);
    const words = mnemonic.split(" ");

    expect(words).toHaveLength(12);
    for (const word of words) expect(wordlist).toContain(word);
    expect(await validateMnemonic(mnemonic)).toBe(true);
    expect(validateMnemonicWords(mnemonic).ok).toBe(true);
  });

  test("256 bits of entropy give twenty-four words", async () => {
    const mnemonic = await generateMnemonic(256);

    expect(mnemonic.split(" ")).toHaveLength(24);
    expect(await validateMnemonic(mnemonic)).toBe(true);
  });
});

describe("mnemonic validation", () => {
  test("a corrupted last word fails the checksum", async () => {
    expect(await validateMnemonic(KAT_MNEMONIC)).toBe(true);
    expect(await validateMnemonic(KAT_MNEMONIC_CORRUPTED)).toBe(false);

    // The words themselves are all real, so only the async check can tell.
    expect(validateMnemonicWords(KAT_MNEMONIC_CORRUPTED).ok).toBe(true);

    const checked = await validateMnemonicPhrase(KAT_MNEMONIC_CORRUPTED);
    expect(checked.ok).toBe(false);
    expect(checked.reason).toContain("checksum");
  });

  test("validateMnemonicWords reports a wrong word count", () => {
    const short = validateMnemonicWords("adapt patrol eternal");
    expect(short.ok).toBe(false);
    expect(short.reason).toContain("12");

    const words = KAT_MNEMONIC.split(" ");
    const notAMultipleOfThree = validateMnemonicWords(
      [...words, "adapt"].join(" "),
    );
    expect(notAMultipleOfThree.ok).toBe(false);
    expect(notAMultipleOfThree.reason).toContain("three");

    expect(validateMnemonicWords("   ").ok).toBe(false);
  });

  test("validateMnemonicWords names an unknown word", () => {
    const words = KAT_MNEMONIC.split(" ");
    words[3] = "notaword";

    const result = validateMnemonicWords(words.join(" "));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("notaword");
    expect(result.reason).toContain("4");
  });

  test("validation normalises whitespace and case", async () => {
    const messy = `  Adapt\tPATROL   eternal Modify make run
      common noble salute lecture detail AIR  `;

    expect(validateMnemonicWords(messy).ok).toBe(true);
    expect(await validateMnemonic(messy)).toBe(true);
    expect((await validateMnemonicPhrase(messy)).ok).toBe(true);
  });
});

describe("key derivation", () => {
  test(
    "the same phrase always derives the same key pair",
    async () => {
      const first = await keyPairFromMnemonic(KAT_MNEMONIC);
      const second = await keyPairFromMnemonic(KAT_MNEMONIC);

      expect(toHex(first.publicKey)).toBe(KAT_PUBLIC_KEY_HEX);
      expect(toHex(second.publicKey)).toBe(KAT_PUBLIC_KEY_HEX);
      expect(toHex(second.secretKey)).toBe(toHex(first.secretKey));

      first.secretKey.fill(0);
      second.secretKey.fill(0);
    },
    DERIVATION_TIMEOUT_MS,
  );

  test(
    "a password changes the derived key",
    async () => {
      const withPassword = await keyPairFromMnemonic(
        KAT_MNEMONIC,
        "correct horse battery staple",
      );

      expect(toHex(withPassword.publicKey)).not.toBe(KAT_PUBLIC_KEY_HEX);

      withPassword.secretKey.fill(0);
    },
    DERIVATION_TIMEOUT_MS,
  );

  test(
    "whitespace and case normalisation is part of the derivation contract",
    async () => {
      const keyPair = await keyPairFromMnemonic(
        "  Adapt  patrol\tETERNAL modify make run common noble salute lecture detail air\n",
      );

      expect(toHex(keyPair.publicKey)).toBe(KAT_PUBLIC_KEY_HEX);

      keyPair.secretKey.fill(0);
    },
    DERIVATION_TIMEOUT_MS,
  );

  test(
    "a preloaded module is reused instead of loading another one",
    async () => {
      const module = await loadArgon2Module();
      const keyPair = await keyPairFromMnemonic(
        KAT_MNEMONIC,
        undefined,
        module,
      );

      expect(toHex(keyPair.publicKey)).toBe(KAT_PUBLIC_KEY_HEX);

      keyPair.secretKey.fill(0);
    },
    DERIVATION_TIMEOUT_MS,
  );

  test("an invalid phrase never reaches the key derivation", async () => {
    await expect(keyPairFromMnemonic(KAT_MNEMONIC_CORRUPTED)).rejects.toThrow(
      "Invalid mnemonic",
    );
  });
});
