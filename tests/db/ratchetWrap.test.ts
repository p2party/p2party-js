import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "bun:test";
import { getWrapKey, wrapSecret, unwrapSecret } from "../../src/db/ratchetWrap";

beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
  Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

describe("wrapSecret / unwrapSecret", () => {
  test("round-trips the original bytes", async () => {
    const key = await getWrapKey();
    const bytes = rnd(32);
    const blob = await wrapSecret(key, bytes);
    expect(eq(blob, bytes)).toBe(false); // stored as ciphertext
    expect(blob.byteLength).toBe(12 + 32 + 16); // IV + ciphertext + GCM tag
    const back = await unwrapSecret(key, blob);
    expect(eq(back, bytes)).toBe(true);
  });

  test("tampered ciphertext fails AEAD auth", async () => {
    const key = await getWrapKey();
    const blob = await wrapSecret(key, rnd(16));
    const v = new Uint8Array(blob);
    v[20] ^= 0xff; // flip a ciphertext byte
    await expect(unwrapSecret(key, v.buffer)).rejects.toBeDefined();
  });

  test("truncated generic secret envelopes fail before WebCrypto", async () => {
    const key = await getWrapKey();
    await expect(unwrapSecret(key, new Uint8Array(27).buffer)).rejects.toThrow(
      "Malformed wrapped secret",
    );
  });

  test("two wraps of the same plaintext produce different ciphertext (fresh IV per call)", async () => {
    const key = await getWrapKey();
    const bytes = rnd(32);
    const blobA = await wrapSecret(key, bytes);
    const blobB = await wrapSecret(key, bytes);
    // Ciphertexts (and hence full blobs, since the IV is prepended) must
    // differ because each call draws a fresh random 12-byte IV.
    expect(eq(blobA, blobB)).toBe(false);
    const ivA = blobA.slice(0, 12);
    const ivB = blobB.slice(0, 12);
    expect(eq(ivA, ivB)).toBe(false);
    // Both still decrypt back to the same original plaintext.
    expect(eq(await unwrapSecret(key, blobA), bytes)).toBe(true);
    expect(eq(await unwrapSecret(key, blobB), bytes)).toBe(true);
  });
});

describe("getWrapKey persistence", () => {
  test("is non-extractable and survives a simulated reload", async () => {
    const k1 = await getWrapKey();
    expect(k1.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", k1)).rejects.toBeDefined();

    const bytes = rnd(32);
    const blob = await wrapSecret(k1, bytes);
    // Simulate reload: do NOT reset the factory; a fresh getWrapKey must read
    // the SAME persisted CryptoKey back from the meta store and unwrap.
    const k2 = await getWrapKey();
    const back = await unwrapSecret(k2, blob);
    expect(eq(back, bytes)).toBe(true);
  });

  test("is get-or-create: two calls in the same session return the identical key (not regenerated)", async () => {
    const k1 = await getWrapKey();
    const bytes = rnd(24);
    const blob = await wrapSecret(k1, bytes);

    const k2 = await getWrapKey();
    // If k2 were a freshly-generated (different) key, this would throw
    // (OperationError) rather than returning the original bytes.
    const back = await unwrapSecret(k2, blob);
    expect(eq(back, bytes)).toBe(true);
  });
});
