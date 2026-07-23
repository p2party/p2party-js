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
  RATCHET_WRAP_VERSION,
  RatchetRollbackGuard,
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
  rootSuite: "hybrid-3dh-mlkem768-cpace21-v3",
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

describe("wrap / unwrap RatchetSession", () => {
  test("rejects an untagged pre-hybrid session", async () => {
    const key = await getWrapKey();
    const untagged = sampleSession() as Partial<RatchetSession>;
    delete untagged.rootSuite;
    await expect(
      wrapRatchetSession(untagged as RatchetSession, key),
    ).rejects.toThrow("Unsupported ratchet root suite");
  });

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
    expect(w.rootSuite).toBe("hybrid-3dh-mlkem768-cpace21-v3");
    expect(w.peerPublicKey).toBe("aa".repeat(32));
    expect(w.updatedAt).toBe(111);
    expect(w.skippedMessageKeys[0].n).toBe(0);
    expect(
      eq(w.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true); // skipped dhPub untouched
    expect(
      eq(
        w.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(false); // skipped messageKey wrapped

    const u = await unwrapRatchetSession(w, key);
    expect(eq(u.rootKey, s.rootKey)).toBe(true);
    expect(eq(u.dhSelfSec, s.dhSelfSec)).toBe(true);
    expect(
      u.sendingChainKey != null && eq(u.sendingChainKey, s.sendingChainKey!),
    ).toBe(true);
    expect(u.receivingChainKey).toBe(null);
    expect(
      eq(
        u.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(true);
    expect(u.skippedMessageKeys[0].n).toBe(0);
    expect(u.peerId).toBe("peer-abc-123");
  });

  test("uses an explicit versioned ratchet envelope", async () => {
    const key = await getWrapKey();
    const wrapped = await wrapRatchetSession(sampleSession(), key);
    const rootEnvelope = new Uint8Array(wrapped.rootKey);
    expect(Array.from(rootEnvelope.subarray(0, 4))).toEqual([
      0x50, 0x32, 0x52, 0x57,
    ]);
    expect(rootEnvelope[4]).toBe(RATCHET_WRAP_VERSION);
    // magic + version + per-write ID + IV + ciphertext + GCM tag
    expect(rootEnvelope.byteLength).toBe(4 + 1 + 16 + 12 + 32 + 16);
  });

  test("authenticates all public session metadata and nullability", async () => {
    const key = await getWrapKey();
    const wrapped = await wrapRatchetSession(sampleSession(), key);
    const mutations: RatchetSession[] = [
      { ...wrapped, roomId: "room-2" },
      { ...wrapped, peerPublicKey: "bb".repeat(32) },
      { ...wrapped, peerId: "peer-rebound-456" },
      { ...wrapped, Ns: wrapped.Ns + 1 },
      { ...wrapped, Nr: wrapped.Nr + 1 },
      { ...wrapped, PN: wrapped.PN + 1 },
      { ...wrapped, updatedAt: wrapped.updatedAt + 1 },
      {
        ...wrapped,
        dhSelfPub: Uint8Array.from(
          new Uint8Array(wrapped.dhSelfPub),
          (byte, index) => byte ^ (index === 0 ? 1 : 0),
        ).buffer,
      },
      {
        ...wrapped,
        dhRemotePub: Uint8Array.from(
          new Uint8Array(wrapped.dhRemotePub as ArrayBuffer),
          (byte, index) => byte ^ (index === 0 ? 1 : 0),
        ).buffer,
      },
      {
        ...wrapped,
        skippedMessageKeys: wrapped.skippedMessageKeys.map((entry, index) => ({
          ...entry,
          n: entry.n + (index === 0 ? 1 : 0),
        })),
      },
      { ...wrapped, sendingChainKey: null },
    ];

    for (const mutation of mutations)
      await expect(unwrapRatchetSession(mutation, key)).rejects.toBeDefined();
  });

  test("rejects ciphertext transplanted between secret fields or sessions", async () => {
    const key = await getWrapKey();
    const firstPlain = sampleSession();
    const first = await wrapRatchetSession(firstPlain, key);
    const sameMetadataRewrap = await wrapRatchetSession(firstPlain, key);
    const secondPlain = {
      ...sampleSession(),
      roomId: "room-2",
      peerPublicKey: "bb".repeat(32),
    };
    const second = await wrapRatchetSession(secondPlain, key);

    await expect(
      unwrapRatchetSession(
        {
          ...first,
          rootKey: first.dhSelfSec,
          dhSelfSec: first.rootKey,
        },
        key,
      ),
    ).rejects.toBeDefined();
    await expect(
      unwrapRatchetSession({ ...second, rootKey: first.rootKey }, key),
    ).rejects.toBeDefined();
    // Even identical public metadata and the same millisecond cannot make
    // fields from two independently wrapped generations composable.
    expect(
      eq(first.rootKey.slice(5, 21), sameMetadataRewrap.rootKey.slice(5, 21)),
    ).toBe(false);
    await expect(
      unwrapRatchetSession(
        { ...sameMetadataRewrap, rootKey: first.rootKey },
        key,
      ),
    ).rejects.toThrow("record ID mismatch");
  });

  test("fails closed on envelope downgrade, truncation, and wrong key", async () => {
    const key = await getWrapKey();
    const wrapped = await wrapRatchetSession(sampleSession(), key);
    const downgradedRoot = wrapped.rootKey.slice(0);
    new Uint8Array(downgradedRoot)[4] = 0;
    await expect(
      unwrapRatchetSession({ ...wrapped, rootKey: downgradedRoot }, key),
    ).rejects.toThrow("Unsupported or malformed ratchet wrap envelope");

    await expect(
      unwrapRatchetSession(
        { ...wrapped, rootKey: wrapped.rootKey.slice(0, 16) },
        key,
      ),
    ).rejects.toThrow("Unsupported or malformed ratchet wrap envelope");

    const wrongKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    await expect(unwrapRatchetSession(wrapped, wrongKey)).rejects.toBeDefined();
  });

  test("rejects non-canonical metadata and malformed plaintext secrets", async () => {
    const key = await getWrapKey();
    await expect(
      wrapRatchetSession({ ...sampleSession(), peerId: "peer-\ud800" }, key),
    ).rejects.toThrow("not canonical Unicode");
    await expect(
      wrapRatchetSession(
        { ...sampleSession(), peerPublicKey: "AA".repeat(32) },
        key,
      ),
    ).rejects.toThrow("lowercase hex");
    await expect(
      wrapRatchetSession({ ...sampleSession(), rootKey: rnd(31) }, key),
    ).rejects.toThrow("rootKey must be 32 bytes");
  });
});

describe("RatchetRollbackGuard", () => {
  test("rememberTrustedWrite advances the watermark only from a valid local envelope", async () => {
    const key = await getWrapKey();
    const guard = new RatchetRollbackGuard();
    const current = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 300 },
      key,
    );
    await guard.rememberTrustedWrite(current);

    const older = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 299 },
      key,
    );
    await expect(unwrapRatchetSession(older, key, guard)).rejects.toThrow(
      "rollback detected",
    );

    const malformed = {
      ...current,
      dhSelfSec: current.dhSelfSec.slice(0, 20),
      updatedAt: 301,
    };
    await expect(guard.rememberTrustedWrite(malformed)).rejects.toThrow(
      "Unsupported or malformed",
    );
  });

  test("accepts exact replay/newer state and rejects rollback or same-time equivocation", async () => {
    const key = await getWrapKey();
    const guard = new RatchetRollbackGuard();
    const currentPlain = { ...sampleSession(), updatedAt: 200 };
    const current = await wrapRatchetSession(currentPlain, key);

    await expect(
      unwrapRatchetSession(current, key, guard),
    ).resolves.toBeDefined();
    // An idempotent reread of the exact stored envelope is safe.
    await expect(
      unwrapRatchetSession(current, key, guard),
    ).resolves.toBeDefined();

    const older = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 199 },
      key,
    );
    await expect(unwrapRatchetSession(older, key, guard)).rejects.toThrow(
      "rollback detected",
    );

    const equivocatedPlain = {
      ...sampleSession(),
      updatedAt: 200,
      Ns: 4,
    };
    const equivocated = await wrapRatchetSession(equivocatedPlain, key);
    await expect(unwrapRatchetSession(equivocated, key, guard)).rejects.toThrow(
      "equivocation detected",
    );

    const newer = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 201, Ns: 4 },
      key,
    );
    await expect(
      unwrapRatchetSession(newer, key, guard),
    ).resolves.toBeDefined();
  });

  test("forget explicitly resets one edge's in-memory high-water mark", async () => {
    const key = await getWrapKey();
    const guard = new RatchetRollbackGuard();
    const current = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 200 },
      key,
    );
    const older = await wrapRatchetSession(
      { ...sampleSession(), updatedAt: 199 },
      key,
    );
    await unwrapRatchetSession(current, key, guard);
    guard.forget("room-1", "aa".repeat(32));
    await expect(
      unwrapRatchetSession(older, key, guard),
    ).resolves.toBeDefined();
    guard.clear();
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
