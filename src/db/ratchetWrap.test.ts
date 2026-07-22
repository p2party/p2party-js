// Stage 3 / Task 3 — non-extractable AES-GCM at-rest wrap for ratchet secrets.
//
// Exercised against fake-indexeddb so it runs under `bun test` without a real
// browser. NOTE: confirmed (see task report) that this fake-indexeddb version
// DOES structured-clone a real non-extractable CryptoKey and the round-tripped
// key remains usable via WebCrypto, so the "survives a simulated reload" test
// below exercises the real getWrapKey() persistence path, not a stub.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "bun:test";

import {
  getWrapKey,
  wrapSecret,
  unwrapSecret,
  wrapRatchetSession,
  unwrapRatchetSession,
} from "./ratchetWrap";
import { getDB } from "./src/getDB";

import type { RatchetSession } from "./types";

// Each test gets a pristine IndexedDB (clears BOTH the ratchetSessions store
// and the persisted wrap key), so "reload persistence" is tested explicitly by
// NOT resetting within a single test.
beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
  Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

const sampleSession = (): RatchetSession => ({
  roomId: "room-1",
  peerPublicKey: "aa".repeat(32),
  peerId: "peer-abc-123",
  rootKey: rnd(32),
  sendingChainKey: rnd(32),
  receivingChainKey: null,
  dhSelfPub: rnd(32),
  dhSelfSec: rnd(32),
  dhRemotePub: rnd(32),
  Ns: 3,
  Nr: 1,
  PN: 2,
  skippedMessageKeys: [{ dhPub: rnd(32), n: 0, messageKey: rnd(32) }],
  updatedAt: 111,
});

describe("wrapSecret / unwrapSecret", () => {
  test("round-trips the original bytes", async () => {
    const key = await getWrapKey();
    const bytes = rnd(32);
    const blob = await wrapSecret(key, bytes);
    expect(eq(blob, bytes)).toBe(false); // stored as ciphertext
    expect(blob.byteLength).toBe(12 + 32 + 16); // iv + ct + poly1305 tag
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

describe("wrap / unwrap RatchetSession", () => {
  test("round-trips secrets, leaves public + null fields intact", async () => {
    const key = await getWrapKey();
    const s = sampleSession();
    const w = await wrapRatchetSession(s, key);
    expect(eq(w.rootKey, s.rootKey)).toBe(false); // secret wrapped
    expect(eq(w.dhSelfSec, s.dhSelfSec)).toBe(false); // secret wrapped
    expect(eq(w.dhSelfPub, s.dhSelfPub)).toBe(true); // public untouched
    expect(eq(w.dhRemotePub as ArrayBuffer, s.dhRemotePub as ArrayBuffer)).toBe(
      true,
    ); // public untouched
    expect(w.receivingChainKey).toBe(null); // null preserved
    expect(w.Ns).toBe(3);
    expect(w.Nr).toBe(1);
    expect(w.PN).toBe(2);
    expect(w.roomId).toBe("room-1");
    expect(w.peerPublicKey).toBe("aa".repeat(32));
    expect(w.updatedAt).toBe(111);
    expect(w.skippedMessageKeys[0].n).toBe(0);
    expect(
      eq(w.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true); // skipped dhPub untouched
    expect(
      eq(w.skippedMessageKeys[0].messageKey, s.skippedMessageKeys[0].messageKey),
    ).toBe(false); // skipped messageKey wrapped

    const u = await unwrapRatchetSession(w, key);
    expect(eq(u.rootKey, s.rootKey)).toBe(true);
    expect(eq(u.dhSelfSec, s.dhSelfSec)).toBe(true);
    expect(
      u.sendingChainKey != null && eq(u.sendingChainKey, s.sendingChainKey!),
    ).toBe(true);
    expect(u.receivingChainKey).toBe(null);
    expect(
      eq(u.skippedMessageKeys[0].messageKey, s.skippedMessageKeys[0].messageKey),
    ).toBe(true);
    expect(u.skippedMessageKeys[0].n).toBe(0);
    expect(u.peerId).toBe("peer-abc-123");
  });
});

describe("ratchetSessions store round-trip (at-rest wrapped)", () => {
  test("put wrapped -> on-disk secret is ciphertext -> get+unwrap == plaintext", async () => {
    const key = await getWrapKey();
    const s = sampleSession();
    const db = await getDB();
    await db.put("ratchetSessions", await wrapRatchetSession(s, key));
    const onDisk = (await db.get("ratchetSessions", [
      s.roomId,
      s.peerPublicKey,
    ])) as RatchetSession;
    db.close();
    expect(eq(onDisk.rootKey, s.rootKey)).toBe(false); // proves at-rest wrap
    const u = await unwrapRatchetSession(onDisk, key);
    expect(eq(u.rootKey, s.rootKey)).toBe(true);
    expect(u.Ns).toBe(3);
  });
});
