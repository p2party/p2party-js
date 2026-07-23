import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../cryptography/testModule";
import { initRatchet, ratchetEncrypt } from "../cryptography/ratchet";
import { parseChunkFrameHeader } from "./chunkFrame";
import {
  encryptMessageChunks,
  decryptMessageChunk,
  sealChunk,
  messageCacheKey,
} from "./messageChunkCrypto";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

const rand = (n: number): Uint8Array => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

// A 64-byte "merkle root" — the per-message value the AAD (root ‖ N ‖ PN) binds
// to, matching the C `receive_message_with_key`.
const root = () => rand(crypto_hash_sha512_BYTES);

// Bob is the responder (initRatchet false, remote null); Alice the initiator,
// consuming Bob's initial ratchet pub. Same setup as ratchet.test.ts.
const pair = async () => {
  const module = await loadTestModule();
  const seed = rand(32);
  const bob = initRatchet(seed, false, null, module);
  const alice = initRatchet(Uint8Array.from(seed), true, bob.dhSelfPub, module);
  return { module, alice, bob };
};

describe("messageChunkCrypto", () => {
  test("round-trip: a 3-chunk message encrypts to 3 frames, all decrypt byte-exact", async () => {
    const { module, alice, bob } = await pair();
    const r = root();
    const chunks = [rand(1000), rand(777), rand(1234)];

    const frames = encryptMessageChunks(alice, chunks, r, module);
    expect(frames.length).toBe(3);

    // Every frame carries the SAME per-message ratchet header (one ratchet step
    // for the whole message) but a DISTINCT random nonce per chunk.
    const h0 = parseChunkFrameHeader(frames[0]);
    const h1 = parseChunkFrameHeader(frames[1]);
    const h2 = parseChunkFrameHeader(frames[2]);
    expect(Buffer.from(h1.header.dhPub)).toEqual(Buffer.from(h0.header.dhPub));
    expect(h1.header.N).toBe(h0.header.N);
    expect(h2.header.N).toBe(h0.header.N);
    expect(Buffer.from(h1.nonce)).not.toEqual(Buffer.from(h0.nonce));
    expect(Buffer.from(h2.nonce)).not.toEqual(Buffer.from(h0.nonce));

    const cache = new Map<string, Uint8Array>();
    const d0 = decryptMessageChunk(bob, frames[0], cache, r, module);
    const d1 = decryptMessageChunk(bob, frames[1], cache, r, module);
    const d2 = decryptMessageChunk(bob, frames[2], cache, r, module);

    // Chunk 0 is the ONLY one that advanced the ratchet; 1 & 2 reused the
    // per-message cached key (ratchetDecrypt is NOT called per chunk — if it
    // were, chunk 1 would throw "message key already consumed").
    expect(d0.stateAdvanced).toBe(true);
    expect(d1.stateAdvanced).toBe(false);
    expect(d2.stateAdvanced).toBe(false);
    expect(bob.Nr).toBe(1); // exactly one receiving-chain step for the message
    expect(cache.size).toBe(1); // one cache entry keyed by (dhPub, N)

    expect(Buffer.from(d0.plaintext)).toEqual(Buffer.from(chunks[0]));
    expect(Buffer.from(d1.plaintext)).toEqual(Buffer.from(chunks[1]));
    expect(Buffer.from(d2.plaintext)).toEqual(Buffer.from(chunks[2]));
  });

  test("cache correctness: chunks decrypt in any order; a 2nd message advances the ratchet with its own entry", async () => {
    const { module, alice, bob } = await pair();
    const rA = root();
    const chunksA = [rand(900), rand(900), rand(900)];
    const framesA = encryptMessageChunks(alice, chunksA, rA, module);

    // Out-of-order: decrypt 2, then 0, then 1. The first-arriving chunk derives
    // and caches the per-message key; the rest are served from the cache
    // regardless of order (the key is per (dhPub, N), not per chunk).
    const cache = new Map<string, Uint8Array>();
    const a2 = decryptMessageChunk(bob, framesA[2], cache, rA, module);
    const a0 = decryptMessageChunk(bob, framesA[0], cache, rA, module);
    const a1 = decryptMessageChunk(bob, framesA[1], cache, rA, module);
    expect(a2.stateAdvanced).toBe(true);
    expect(a0.stateAdvanced).toBe(false);
    expect(a1.stateAdvanced).toBe(false);
    expect(Buffer.from(a0.plaintext)).toEqual(Buffer.from(chunksA[0]));
    expect(Buffer.from(a1.plaintext)).toEqual(Buffer.from(chunksA[1]));
    expect(Buffer.from(a2.plaintext)).toEqual(Buffer.from(chunksA[2]));

    // A 2nd distinct message advances the ratchet (new header N) and gets its
    // own cache entry (distinct (dhPub, N) key).
    const keyA = messageCacheKey(
      parseChunkFrameHeader(framesA[0]).header.dhPub,
      parseChunkFrameHeader(framesA[0]).header.N,
    );

    const rB = root();
    const chunksB = [rand(500), rand(650)];
    const framesB = encryptMessageChunks(alice, chunksB, rB, module);
    const keyB = messageCacheKey(
      parseChunkFrameHeader(framesB[0]).header.dhPub,
      parseChunkFrameHeader(framesB[0]).header.N,
    );
    expect(keyB).not.toBe(keyA); // different N -> different cache entry

    const b0 = decryptMessageChunk(bob, framesB[0], cache, rB, module);
    const b1 = decryptMessageChunk(bob, framesB[1], cache, rB, module);
    expect(b0.stateAdvanced).toBe(true); // 2nd message stepped the ratchet again
    expect(b1.stateAdvanced).toBe(false);
    expect(bob.Nr).toBe(2); // two messages -> two receiving-chain steps
    expect(cache.size).toBe(2); // one entry per message
    expect(cache.has(keyA)).toBe(true);
    expect(cache.has(keyB)).toBe(true);
    expect(Buffer.from(b0.plaintext)).toEqual(Buffer.from(chunksB[0]));
    expect(Buffer.from(b1.plaintext)).toEqual(Buffer.from(chunksB[1]));
  });

  test("sealChunk (streaming send primitive): step once, seal per chunk, decrypt byte-exact; a reconcile re-seal (same key/header, fresh nonce) rides the cache", async () => {
    const { module, alice, bob } = await pair();
    const r = root();
    const chunks = [rand(1100), rand(950)];

    // The live send path: ONE ratchet step for the whole message (handleSendMessage /
    // sendWithReconcile), then sealChunk per chunk as they stream out of IndexedDB —
    // NOT encryptMessageChunks (which would buffer every chunk in RAM, regressing
    // big-file transfers). The messageKey outlives the loop (retransmit rounds reuse
    // it) and is wiped by the caller afterward.
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = chunks.map((c) => sealChunk(messageKey, header, c, r, module));

    // Same per-message header on every frame, distinct random nonce per chunk —
    // byte-identical to encryptMessageChunks' framing.
    const h0 = parseChunkFrameHeader(frames[0]);
    const h1 = parseChunkFrameHeader(frames[1]);
    expect(Buffer.from(h1.header.dhPub)).toEqual(Buffer.from(h0.header.dhPub));
    expect(h1.header.N).toBe(h0.header.N);
    expect(Buffer.from(h1.nonce)).not.toEqual(Buffer.from(h0.nonce));

    const cache = new Map<string, Uint8Array>();
    const d0 = decryptMessageChunk(bob, frames[0], cache, r, module);
    const d1 = decryptMessageChunk(bob, frames[1], cache, r, module);
    expect(d0.stateAdvanced).toBe(true);
    expect(d1.stateAdvanced).toBe(false); // per-message cache, not per-chunk
    expect(Buffer.from(d0.plaintext)).toEqual(Buffer.from(chunks[0]));
    expect(Buffer.from(d1.plaintext)).toEqual(Buffer.from(chunks[1]));

    // Reconcile / selective-retransmit: re-seal an un-acked chunk under the SAME
    // (still-live) messageKey + header with a FRESH nonce. It is a distinct frame
    // on the wire, yet the receiver's cached per-(dhPub, N) key opens it (cache
    // HIT, no ratchet step) to the same plaintext — the streaming-safe alternative
    // to caching every ciphertext frame.
    const resend0 = sealChunk(messageKey, header, chunks[0], r, module);
    expect(Buffer.from(resend0)).not.toEqual(Buffer.from(frames[0])); // fresh nonce
    const re0 = decryptMessageChunk(bob, resend0, cache, r, module);
    expect(re0.stateAdvanced).toBe(false);
    expect(Buffer.from(re0.plaintext)).toEqual(Buffer.from(chunks[0]));

    messageKey.fill(0);
  });

  test("clone-rollback: a corrupted chunk fails to authenticate and leaves the ratchet unadvanced", async () => {
    const { module, alice, bob } = await pair();
    const r = root();
    const chunks = [rand(1500), rand(1500)];
    const frames = encryptMessageChunks(alice, chunks, r, module);

    // Snapshot the receiver's pre-attempt state. Bob is the responder and has
    // not yet stepped: no receiving chain, root == the seed, Nr == 0.
    const rootBefore = Uint8Array.from(bob.rootKey);
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);

    // Corrupt one ciphertext byte of the first chunk's frame (past the 62-byte
    // cleartext header) and attempt to decrypt it as the first-arriving chunk.
    const bad = Uint8Array.from(frames[0]);
    bad[80] ^= 0xff;

    const cache = new Map<string, Uint8Array>();
    expect(() => decryptMessageChunk(bob, bad, cache, r, module)).toThrow(
      /authenticate/,
    );

    // ratchetDecrypt mutates before the AEAD authenticates, so the derivation
    // ran on a CLONE; the auth failure discarded it. The live state is byte-for-
    // byte unadvanced: same root, still no DH step, Nr still 0, nothing cached.
    expect(Buffer.from(bob.rootKey)).toEqual(Buffer.from(rootBefore));
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);
    expect(cache.size).toBe(0);

    // A subsequent GOOD frame of the same message still decrypts (proof the
    // rollback left the ratchet in a usable state).
    const good = decryptMessageChunk(bob, frames[0], cache, r, module);
    expect(good.stateAdvanced).toBe(true);
    expect(Buffer.from(good.plaintext)).toEqual(Buffer.from(chunks[0]));
    // ...and the remaining chunk of that message rides the now-cached key.
    const good1 = decryptMessageChunk(bob, frames[1], cache, r, module);
    expect(good1.stateAdvanced).toBe(false);
    expect(Buffer.from(good1.plaintext)).toEqual(Buffer.from(chunks[1]));
  });
});
