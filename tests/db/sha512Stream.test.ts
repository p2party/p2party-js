import { describe, expect, test } from "bun:test";

import { Sha512Stream } from "../../src/db/sha512Stream";

const hex = (bytes: Uint8Array | ArrayBuffer): string =>
  Buffer.from(
    bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
  ).toString("hex");

const webCrypto = async (data: Uint8Array): Promise<string> =>
  hex(await crypto.subtle.digest("SHA-512", data as Uint8Array<ArrayBuffer>));

// Deterministic PRNG so a failure reproduces.
const prng = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const bytes = (length: number, random: () => number): Uint8Array =>
  Uint8Array.from({ length }, () => Math.floor(random() * 256));

describe("worker streaming SHA-512", () => {
  test("matches the FIPS 180-4 test vectors", () => {
    expect(hex(new Sha512Stream().digest())).toBe(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );
    expect(
      hex(new Sha512Stream().update(new TextEncoder().encode("abc")).digest()),
    ).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
  });

  test("matches WebCrypto for every length across the padding boundaries, fed in random pieces", async () => {
    const random = prng(0x5a);
    for (let length = 0; length <= 520; length++) {
      const data = bytes(length, random);
      const hasher = new Sha512Stream();
      for (let offset = 0; offset < length;) {
        const take = 1 + Math.floor(random() * 150);
        hasher.update(data.subarray(offset, offset + take));
        offset += take;
      }
      expect(hex(hasher.digest())).toBe(await webCrypto(data));
    }
  });

  test("matches WebCrypto on a multi-megabyte input fed in chunk-sized pieces", async () => {
    const data = bytes(3 * 1024 * 1024 + 17, prng(0xa5));
    const hasher = new Sha512Stream();
    for (let offset = 0; offset < data.length; offset += 61_912)
      hasher.update(data.subarray(offset, offset + 61_912));
    expect(hex(hasher.digest())).toBe(await webCrypto(data));
  });

  test("refuses use after the digest is taken", () => {
    const hasher = new Sha512Stream();
    hasher.digest();
    expect(() => hasher.update(new Uint8Array(1))).toThrow();
    expect(() => hasher.digest()).toThrow();
  });
});
