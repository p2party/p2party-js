import { describe, expect, test } from "bun:test";

// hashMerkleLeaf uses window.crypto; under Bun the Web Crypto API is a global
// but `window` is not, so alias it.
(globalThis as unknown as { window: typeof globalThis }).window = globalThis;

import { hashMerkleLeaf } from "./leafHash";

const sha512 = async (b: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-512", b as Uint8Array<ArrayBuffer>),
  );

describe("hashMerkleLeaf", () => {
  test("prepends the 0x00 leaf domain (differs from a bare SHA-512)", async () => {
    const chunk = new Uint8Array([1, 2, 3, 4, 5]);
    const leaf = await hashMerkleLeaf(chunk);
    const bare = await sha512(chunk);
    // Domain separation must actually change the digest.
    expect(Buffer.from(leaf).equals(Buffer.from(bare))).toBe(false);
  });

  test("equals SHA-512(0x00 || chunk)", async () => {
    const chunk = new Uint8Array([9, 8, 7]);
    const prefixed = new Uint8Array(1 + chunk.length);
    prefixed[0] = 0x00;
    prefixed.set(chunk, 1);
    const expected = await sha512(prefixed);
    const leaf = await hashMerkleLeaf(chunk);
    expect(Buffer.from(leaf).equals(Buffer.from(expected))).toBe(true);
  });
});
