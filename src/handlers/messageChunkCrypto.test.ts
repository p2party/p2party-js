import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../cryptography/testModule";
import { initRatchet, ratchetEncrypt } from "../cryptography/ratchet";
import { getMerkleRoot, getMerkleProof } from "../cryptography/merkle";
import { hashMerkleLeafWasm } from "../utils/leafHash";
import { parseChunkFrameHeader } from "./chunkFrame";
import { sealChunk, decryptMessageChunk } from "./messageChunkCrypto";
import {
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";
import {
  METADATA_LEN,
  PROOF_LEN,
  CHUNK_LEN,
  DECRYPTED_LEN,
} from "../utils/constants";

import type { LibCrypto } from "../cryptography/libcrypto";

const rand = (n: number): Uint8Array => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

// Bob is the responder (initRatchet false, remote null); Alice the initiator,
// consuming Bob's initial ratchet pub. Same setup as ratchet.test.ts.
const pair = async () => {
  const module = await loadTestModule();
  const seed = rand(32);
  const bob = initRatchet(seed, false, null, module);
  const alice = initRatchet(Uint8Array.from(seed), true, bob.dhSelfPub, module);
  return { module, alice, bob };
};

// Build K *real* chunk plaintexts (`metadata ‖ merkle-proof ‖ chunk`) sharing one
// Merkle root — exactly the DECRYPTED_LEN layout the send path assembles, so the C
// `_receive_message_with_key` decrypts AND verifies. The metadata region is opaque
// to the receive crypto (the C only reads the proof + chunk), so it is left zero.
const buildMessage = async (module: LibCrypto, K: number) => {
  const datas = Array.from({ length: K }, () => rand(CHUNK_LEN));
  const leaves = new Uint8Array(K * crypto_hash_sha512_BYTES);
  datas.forEach((d, i) =>
    leaves.set(hashMerkleLeafWasm(d, module), i * crypto_hash_sha512_BYTES),
  );
  const root = await getMerkleRoot(leaves, module);

  const plaintexts: Uint8Array[] = [];
  for (let i = 0; i < K; i++) {
    const proof = await getMerkleProof(
      leaves,
      hashMerkleLeafWasm(datas[i], module),
      module,
      PROOF_LEN,
    );
    const pt = new Uint8Array(DECRYPTED_LEN);
    pt.set(proof, METADATA_LEN);
    pt.set(datas[i], METADATA_LEN + PROOF_LEN);
    plaintexts.push(pt);
  }
  return { root, datas, plaintexts };
};

const chunkOf = (decrypted: Uint8Array): Uint8Array =>
  decrypted.slice(METADATA_LEN + PROOF_LEN);
const receiptOf = (decrypted: Uint8Array): Uint8Array =>
  decrypted.slice(METADATA_LEN, METADATA_LEN + crypto_hash_sha512_BYTES);

describe("messageChunkCrypto (single-call C receive)", () => {
  test("round-trip: a real 2-chunk message decrypts byte-exact through the C receive; chunk 0 steps the ratchet, chunk 1 rides the per-message cache", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);

    // ONE ratchet step for the whole message; seal each chunk with a fresh nonce.
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((pt) =>
      sealChunk(messageKey, header, pt, root, module),
    );
    messageKey.fill(0);

    // Same per-message header on every frame, distinct random nonce per chunk.
    const h0 = parseChunkFrameHeader(frames[0]);
    const h1 = parseChunkFrameHeader(frames[1]);
    expect(Buffer.from(h1.header.dhPub)).toEqual(Buffer.from(h0.header.dhPub));
    expect(h1.header.N).toBe(h0.header.N);
    expect(Buffer.from(h1.nonce)).not.toEqual(Buffer.from(h0.nonce));

    const cache = new Map<string, Uint8Array>();
    const d0 = decryptMessageChunk(bob, frames[0], cache, root, module);
    const d1 = decryptMessageChunk(bob, frames[1], cache, root, module);

    expect(d0.ok).toBe(true);
    expect(d1.ok).toBe(true);
    expect(d0.stateAdvanced).toBe(true); // first chunk stepped the ratchet
    expect(d1.stateAdvanced).toBe(false); // second rode the cached key
    expect(bob.Nr).toBe(1); // exactly one receiving-chain step for the message
    expect(cache.size).toBe(1);

    // The chunk region round-trips byte-exact.
    expect(Buffer.from(chunkOf(d0.decrypted!))).toEqual(Buffer.from(datas[0]));
    expect(Buffer.from(chunkOf(d1.decrypted!))).toEqual(Buffer.from(datas[1]));

    // The C wrote the receipt leaf SHA-512(0x00 ‖ chunk) over the proof region.
    expect(Buffer.from(receiptOf(d0.decrypted!))).toEqual(
      Buffer.from(hashMerkleLeafWasm(datas[0], module)),
    );
  });

  test("clone-rollback: a corrupted ciphertext byte fails the AEAD (C code -2), so the ratchet is left byte-for-byte unadvanced; a good frame then decrypts", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((pt) =>
      sealChunk(messageKey, header, pt, root, module),
    );
    messageKey.fill(0);

    // Bob is the responder and has not stepped: no receiving chain, root == seed.
    const rootBefore = Uint8Array.from(bob.rootKey);
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);

    // Corrupt one ciphertext byte (past the 62-byte cleartext header).
    const bad = Uint8Array.from(frames[0]);
    bad[80] ^= 0xff;

    const cache = new Map<string, Uint8Array>();
    const r = decryptMessageChunk(bob, bad, cache, root, module);
    expect(r.ok).toBe(false);
    expect(r.stateAdvanced).toBe(false);
    expect(r.decrypted).toBeNull();

    // The clone was discarded; the live state never advanced.
    expect(Buffer.from(bob.rootKey)).toEqual(Buffer.from(rootBefore));
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);
    expect(cache.size).toBe(0);

    // The GOOD frame of that message still decrypts (rollback left it usable).
    const good = decryptMessageChunk(bob, frames[0], cache, root, module);
    expect(good.ok).toBe(true);
    expect(good.stateAdvanced).toBe(true);
    expect(Buffer.from(chunkOf(good.decrypted!))).toEqual(Buffer.from(datas[0]));
  });

  test("AEAD-authentic but bad Merkle proof: C returns != -2, so the ratchet COMMITS (stateAdvanced) even though the chunk is dropped (ok false)", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 2);

    // Tamper a proof-artifact byte INSIDE the plaintext, then seal it: the AEAD is
    // valid (we seal the tampered bytes) but the proof no longer folds to the root.
    const tampered = Uint8Array.from(plaintexts[0]);
    tampered[METADATA_LEN + 8] ^= 0xff;
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, tampered, root, module);
    messageKey.fill(0);

    const cache = new Map<string, Uint8Array>();
    const r = decryptMessageChunk(bob, frame, cache, root, module);
    expect(r.ok).toBe(false); // Merkle verification failed inside the C call
    expect(r.decrypted).toBeNull();
    expect(r.stateAdvanced).toBe(true); // but the AEAD authenticated → ratchet stepped
    expect(bob.Nr).toBe(1);
    expect(cache.size).toBe(1); // key cached so the message's other chunks can arrive
  });

  test("reconcile re-seal: same key/header, fresh nonce → a distinct frame that rides the cached per-message key", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, plaintexts[0], root, module);

    const cache = new Map<string, Uint8Array>();
    const d = decryptMessageChunk(bob, frame, cache, root, module);
    expect(d.ok).toBe(true);
    expect(d.stateAdvanced).toBe(true);

    // Selective-retransmit: re-seal the SAME plaintext under the still-live key
    // with a FRESH nonce. Distinct frame on the wire, opened by the cached key.
    const resend = sealChunk(messageKey, header, plaintexts[0], root, module);
    messageKey.fill(0);
    expect(Buffer.from(resend)).not.toEqual(Buffer.from(frame)); // fresh nonce
    const re = decryptMessageChunk(bob, resend, cache, root, module);
    expect(re.ok).toBe(true);
    expect(re.stateAdvanced).toBe(false); // cache HIT, no ratchet step
    expect(Buffer.from(chunkOf(re.decrypted!))).toEqual(Buffer.from(datas[0]));
  });
});
