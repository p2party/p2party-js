import { describe, expect, test } from "bun:test";

import {
  hmacSha256,
  hkdfSha256Expand,
  hkdfSha256Extract,
  sha256,
} from "../../src/cryptography/webCryptoSha256";

const bytes = (value: number, length: number): Uint8Array =>
  new Uint8Array(length).fill(value);

const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("WebCrypto SHA-256 input ownership", () => {
  test("SHA-256 and HMAC-SHA-256 match independent standard vectors", async () => {
    expect(hex(await sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223" + "b00361a396177a9cb410ff61f20015ad",
    );
    expect(
      hex(
        await hmacSha256(bytes(0x0b, 20), new TextEncoder().encode("Hi There")),
      ),
    ).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b" + "881dc200c9833da726e9376c2e32cff7",
    );
  });

  test("SHA-256 and HMAC snapshot caller bytes before their first await", async () => {
    const hashInput = bytes(0x11, 47);
    const originalHashInput = Uint8Array.from(hashInput);
    const pendingHash = sha256(hashInput);
    hashInput.fill(0xff);
    expect(await pendingHash).toEqual(await sha256(originalHashInput));

    const key = bytes(0x22, 32);
    const message = bytes(0x33, 61);
    const originalKey = Uint8Array.from(key);
    const originalMessage = Uint8Array.from(message);
    const pendingMac = hmacSha256(key, message);
    key.fill(0xee);
    message.fill(0xdd);
    expect(await pendingMac).toEqual(
      await hmacSha256(originalKey, originalMessage),
    );
  });

  test("HKDF Extract and Expand snapshot every caller byte input", async () => {
    const salt = bytes(0x44, 13);
    const ikm = bytes(0x55, 37);
    const originalSalt = Uint8Array.from(salt);
    const originalIkm = Uint8Array.from(ikm);
    const pendingExtract = hkdfSha256Extract(salt, ikm);
    salt.fill(0xcc);
    ikm.fill(0xbb);
    expect(await pendingExtract).toEqual(
      await hkdfSha256Extract(originalSalt, originalIkm),
    );

    const prk = bytes(0x66, 32);
    const info = bytes(0x77, 29);
    const originalPrk = Uint8Array.from(prk);
    const originalInfo = Uint8Array.from(info);
    const pendingExpand = hkdfSha256Expand(prk, info, 96);
    prk.fill(0xaa);
    info.fill(0x99);
    expect(await pendingExpand).toEqual(
      await hkdfSha256Expand(originalPrk, originalInfo, 96),
    );
  });

  test("HKDF Expand enforces its nonempty RFC-bounded output and minimum PRK", async () => {
    const prk = bytes(0x88, 32);
    expect((await hkdfSha256Expand(prk, new Uint8Array(0), 1)).length).toBe(1);
    expect((await hkdfSha256Expand(prk, new Uint8Array(0), 8_160)).length).toBe(
      8_160,
    );
    await expect(hkdfSha256Expand(prk, new Uint8Array(0), 0)).rejects.toThrow(
      RangeError,
    );
    await expect(
      hkdfSha256Expand(prk, new Uint8Array(0), 8_161),
    ).rejects.toThrow(RangeError);
    await expect(
      hkdfSha256Expand(bytes(0x88, 31), new Uint8Array(0), 32),
    ).rejects.toThrow("must be at least 32 bytes");
  });

  test("rejects non-byte inputs instead of coercing them", async () => {
    await expect(sha256([1, 2, 3] as unknown as Uint8Array)).rejects.toThrow(
      TypeError,
    );
    await expect(
      hmacSha256(new Uint8Array(32), [1, 2, 3] as unknown as Uint8Array),
    ).rejects.toThrow(TypeError);
    await expect(
      hkdfSha256Extract([1, 2, 3] as unknown as Uint8Array, new Uint8Array(32)),
    ).rejects.toThrow(TypeError);
    await expect(
      hkdfSha256Expand(
        new Uint8Array(32),
        [1, 2, 3] as unknown as Uint8Array,
        32,
      ),
    ).rejects.toThrow(TypeError);
  });
});
