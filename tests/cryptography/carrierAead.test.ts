import { describe, expect, test } from "bun:test";

import {
  CarrierAeadError,
  xchacha20poly1305Open,
  xchacha20poly1305Seal,
} from "../../src/cryptography/carrierAead";
import { readFileSync } from "node:fs";

import libcrypto from "../../src/cryptography/libcrypto";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.replace(/\s+/gu, "").match(/../gu) ?? [], (pair) =>
    parseInt(pair, 16),
  );

// The emscripten factory types wasmBinary as ArrayBuffer while readFileSync
// returns a Buffer, so the bytes are copied into a fresh ArrayBuffer.
const fileBytes = readFileSync(
  new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
new Uint8Array(wasmBinary).set(fileBytes);

const PAGES = 1024;
const module = (await libcrypto({
  wasmBinary,
  wasmMemory: new WebAssembly.Memory({ initial: PAGES, maximum: PAGES }),
})) as unknown as LibCrypto;

describe("XChaCha20-Poly1305 matches the draft-irtf-cfrg-xchacha-03 vector", () => {
  // Appendix A.3.1 of draft-irtf-cfrg-xchacha-03: AEAD_XCHACHA20_POLY1305.
  const plaintext = fromHex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
      "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069742e",
  );
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const key = fromHex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  );
  const nonce = fromHex("404142434445464748494a4b4c4d4e4f5051525354555657");
  const expectedCiphertext = fromHex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
      "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
      "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
      "21f9664c97637da9768812f615c68b13b52e",
  );
  const expectedTag = fromHex("c0875924c1c7987947deafd8780acf49");

  test("seals to the exact published ciphertext and tag", () => {
    const sealed = xchacha20poly1305Seal(key, nonce, aad, plaintext, module);
    expect(sealed.length).toBe(plaintext.length + 16);
    expect(hex(sealed.subarray(0, plaintext.length))).toBe(
      hex(expectedCiphertext),
    );
    expect(hex(sealed.subarray(plaintext.length))).toBe(hex(expectedTag));
  });

  test("opens the published ciphertext back to the exact plaintext", () => {
    const sealed = new Uint8Array(
      expectedCiphertext.length + expectedTag.length,
    );
    sealed.set(expectedCiphertext);
    sealed.set(expectedTag, expectedCiphertext.length);
    const opened = xchacha20poly1305Open(key, nonce, aad, sealed, module);
    expect(opened).not.toBeNull();
    expect(hex(opened!)).toBe(hex(plaintext));
  });

  test("round-trips an empty plaintext and empty associated data", () => {
    const sealed = xchacha20poly1305Seal(
      key,
      nonce,
      new Uint8Array(0),
      new Uint8Array(0),
      module,
    );
    expect(sealed.length).toBe(16);
    const opened = xchacha20poly1305Open(
      key,
      nonce,
      new Uint8Array(0),
      sealed,
      module,
    );
    expect(opened).not.toBeNull();
    expect(opened!.length).toBe(0);
  });
});

describe("authentication failures return null, never a plaintext", () => {
  const key = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(24).fill(9);
  const aad = Uint8Array.of(1, 2, 3);
  const plaintext = Uint8Array.of(10, 11, 12, 13);

  test("a flipped ciphertext bit, wrong key, nonce, or AAD all fail closed", () => {
    const sealed = xchacha20poly1305Seal(key, nonce, aad, plaintext, module);

    const tampered = Uint8Array.from(sealed);
    tampered[0] ^= 0xff;
    expect(xchacha20poly1305Open(key, nonce, aad, tampered, module)).toBeNull();

    const flippedTag = Uint8Array.from(sealed);
    flippedTag[flippedTag.length - 1] ^= 0x01;
    expect(
      xchacha20poly1305Open(key, nonce, aad, flippedTag, module),
    ).toBeNull();

    expect(
      xchacha20poly1305Open(
        new Uint8Array(32).fill(8),
        nonce,
        aad,
        sealed,
        module,
      ),
    ).toBeNull();
    expect(
      xchacha20poly1305Open(
        key,
        new Uint8Array(24).fill(10),
        aad,
        sealed,
        module,
      ),
    ).toBeNull();
    expect(
      xchacha20poly1305Open(key, nonce, Uint8Array.of(1, 2, 4), sealed, module),
    ).toBeNull();

    // The honest path still succeeds after all of the above.
    expect(hex(xchacha20poly1305Open(key, nonce, aad, sealed, module)!)).toBe(
      hex(plaintext),
    );
  });

  test("a ciphertext shorter than the tag is refused, not indexed into", () => {
    expect(
      xchacha20poly1305Open(key, nonce, aad, new Uint8Array(15), module),
    ).toBeNull();
  });

  test("wrong key or nonce lengths throw rather than silently truncating", () => {
    expect(() =>
      xchacha20poly1305Seal(new Uint8Array(31), nonce, aad, plaintext, module),
    ).toThrow(CarrierAeadError);
    expect(() =>
      xchacha20poly1305Seal(key, new Uint8Array(12), aad, plaintext, module),
    ).toThrow("nonce must be exactly 24 bytes");
  });

  test("legacy validation rejects proxies and ignores shadowed typed-array surfaces", () => {
    const proxiedKey = new Proxy(new Uint8Array(32), {
      getPrototypeOf(): never {
        throw new Error("hostile getPrototypeOf must not run");
      },
    });
    expect(() =>
      xchacha20poly1305Seal(proxiedKey, nonce, aad, plaintext, module),
    ).toThrow(CarrierAeadError);

    const shortKey = new Uint8Array(31);
    Object.defineProperty(shortKey, "length", { value: 32 });
    expect(() =>
      xchacha20poly1305Seal(shortKey, nonce, aad, plaintext, module),
    ).toThrow(CarrierAeadError);

    const shadow = (value: Uint8Array): Uint8Array => {
      Object.defineProperty(value, "length", { value: 0 });
      Object.defineProperty(value, Symbol.iterator, {
        value: (): never => {
          throw new Error("hostile iterator must not run");
        },
      });
      return value;
    };
    const shadowedKey = shadow(Uint8Array.from(key));
    const shadowedNonce = shadow(Uint8Array.from(nonce));
    const sealed = xchacha20poly1305Seal(
      shadowedKey,
      shadowedNonce,
      aad,
      plaintext,
      module,
    );
    const opened = xchacha20poly1305Open(
      shadowedKey,
      shadowedNonce,
      aad,
      shadow(Uint8Array.from(sealed)),
      module,
    );
    expect(opened).not.toBeNull();
    expect(hex(opened!)).toBe(hex(plaintext));
  });

  test("a distinct nonce under one key yields distinct ciphertext", () => {
    const first = xchacha20poly1305Seal(key, nonce, aad, plaintext, module);
    const second = xchacha20poly1305Seal(
      key,
      new Uint8Array(24).fill(11),
      aad,
      plaintext,
      module,
    );
    expect(hex(first)).not.toBe(hex(second));
  });
});
