import {
  adoptRatchet,
  cloneRatchet,
  ratchetDecrypt,
  wipeRatchet,
} from "../cryptography/ratchet";
import { packChunkFrameHeader, parseChunkFrameHeader } from "./chunkFrame";
import { zeroFree } from "../utils/zeroFree";
import {
  RATCHET_N_LEN,
  RATCHET_PN_LEN,
  MESSAGE_LEN,
  DECRYPTED_LEN,
} from "../utils/constants";
import {
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";

import type { RatchetState, RatchetHeader } from "../cryptography/ratchet";
import type { LibCrypto } from "../cryptography/libcrypto";

// ── Stage-5 task 3: per-message-ratchet + per-chunk-AEAD message-chunk crypto ────
//
// THE key subtlety (design §"per-MESSAGE, not per-chunk"): `ratchetEncrypt` /
// `ratchetDecrypt` MUTATE and advance the ratchet ONCE per call. A logical
// message is many chunks. So the ratchet is stepped ONCE per message and the
// resulting `messageKey` is reused (from a caller-owned cache on receive) for
// every chunk of that message. Each chunk gets a fresh random 12-byte nonce.
//
// AEAD: symmetric ChaCha20-Poly1305-IETF under the message key. AAD = the
// per-message `merkleRoot(64) ‖ N(8 BE) ‖ PN(8 BE)`. N/PN come from the ratchet
// header, so the AAD is the same for every chunk of a message.
//
// SEND builds the AAD + seals in TS (`buildAad`/`aeadSeal`/`sealChunk`). RECEIVE
// is done ENTIRELY in one C call: `decryptMessageChunk` derives the per-message
// key off the ratchet (the only state C needs, passed in as an arg) and hands the
// raw frame + key + expected root to `_receive_message_with_key`, which
// AEAD-decrypts, hashes the leaf, verifies the Merkle proof, and writes the
// receipt — all in libsodium, in place, no TS↔WASM back-and-forth (DRY/KISS: the
// C receive path is the SSOT for receive crypto).

const AEAD_KEY_LEN = crypto_aead_chacha20poly1305_ietf_KEYBYTES; // 32
const AEAD_NONCE_LEN = crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12
const AEAD_TAG_LEN = crypto_aead_chacha20poly1305_ietf_ABYTES; // 16
const AAD_LEN = crypto_hash_sha512_BYTES + RATCHET_N_LEN + RATCHET_PN_LEN; // 80

const toHex = (u8: Uint8Array): string =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Per-message key-cache key. Keyed by `(dhPub, N)` — the pair that uniquely
 * identifies a ratchet message; every chunk of that message shares it. Exported
 * so the caller can evict a completed message's key deterministically.
 */
export const messageCacheKey = (dhPub: Uint8Array, N: number): string =>
  `${toHex(dhPub)}:${N}`;

// AAD = merkleRoot(64) ‖ N(8 BE) ‖ PN(8 BE). Big-endian to match the on-wire
// header bytes the C `receive_message_with_key` memcpy's straight into its AAD.
const buildAad = (
  merkleRoot: Uint8Array,
  N: number,
  PN: number,
): Uint8Array => {
  const aad = new Uint8Array(AAD_LEN);
  aad.set(merkleRoot, 0);
  const dv = new DataView(aad.buffer);
  dv.setBigUint64(crypto_hash_sha512_BYTES, BigInt(N), false);
  dv.setBigUint64(crypto_hash_sha512_BYTES + RATCHET_N_LEN, BigInt(PN), false);
  return aad;
};

const randomNonce = (): Uint8Array => {
  const nonce = new Uint8Array(AEAD_NONCE_LEN);
  crypto.getRandomValues(nonce);
  return nonce;
};

/**
 * AEAD seal: `out = ChaCha20(key,nonce) XOR data ‖ Poly1305(aad, ciphertext)`,
 * length `data.length + 16`. Thin wrapper over the exported
 * `_encrypt_chachapoly_symmetric`; secret scratch (key, data, out) is zeroed
 * before free.
 */
const aeadSeal = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array => {
  const dataAlloc = Math.max(data.length, 1);
  const aadAlloc = Math.max(aad.length, 1);
  const outLen = data.length + AEAD_TAG_LEN;

  const keyPtr = module._malloc(AEAD_KEY_LEN);
  const noncePtr = module._malloc(AEAD_NONCE_LEN);
  const dataPtr = module._malloc(dataAlloc);
  const aadPtr = module._malloc(aadAlloc);
  const outPtr = module._malloc(outLen);

  new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN).set(key);
  new Uint8Array(module.wasmMemory.buffer, noncePtr, AEAD_NONCE_LEN).set(nonce);
  if (data.length)
    new Uint8Array(module.wasmMemory.buffer, dataPtr, data.length).set(data);
  if (aad.length)
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);

  const r = module._encrypt_chachapoly_symmetric(
    outPtr,
    dataPtr,
    data.length,
    keyPtr,
    noncePtr,
    aadPtr,
    aad.length,
  );

  const out =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(module.wasmMemory.buffer, outPtr, outLen),
        )
      : null;

  // key, data (plaintext) and out (holds plaintext on the decrypt path) are
  // secret — zero them before returning the heap to the allocator.
  zeroFree(
    module,
    new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN),
  );
  module._free(noncePtr);
  zeroFree(
    module,
    new Uint8Array(module.wasmMemory.buffer, dataPtr, dataAlloc),
  );
  module._free(aadPtr);
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, outPtr, outLen));

  if (!out) throw new Error("messageChunkCrypto: AEAD encrypt failed");
  return out;
};

/**
 * RECEIVE one chunk frame ENTIRELY in libsodium. Hand the raw wire `frame`, the
 * ratchet-derived per-message `key` (the only state C needs — passed as an arg),
 * and the expected `merkleRoot` to the C `_receive_message_with_key`, which:
 * AEAD-decrypts `frame + MESSAGE_START` (AAD = root ‖ N ‖ PN read from the
 * cleartext header, nonce from the header), hashes the domain-separated leaf,
 * verifies the Merkle proof, and writes the receipt leaf over the proof region —
 * all in one call, in place, no TS↔WASM back-and-forth.
 *
 * Returns the C status + the DECRYPTED_LEN plaintext (`metadata ‖ receiptLeaf ‖
 * chunk`), meaningful only when `code === 0`:
 *   code  0  → decrypt + Merkle both passed
 *   code -2  → AEAD auth failed (forgery/replay) → caller ROLLS the ratchet back
 *   code <0  → AEAD passed but Merkle/proof bad → caller COMMITS the ratchet, drops
 */
const receiveWithKey = (
  module: LibCrypto,
  frame: Uint8Array,
  merkleRoot: Uint8Array,
  key: Uint8Array,
): { code: number; decrypted: Uint8Array | null } => {
  const msgPtr = module._malloc(MESSAGE_LEN);
  const decPtr = module._malloc(DECRYPTED_LEN);
  const rootPtr = module._malloc(crypto_hash_sha512_BYTES);
  const keyPtr = module._malloc(AEAD_KEY_LEN);

  // The C signature reads a full MESSAGE_LEN buffer; the wire frame is shorter
  // (WIRE_CHUNK_FRAME_LEN) so zero the tail, then copy the frame in.
  const msg = new Uint8Array(module.wasmMemory.buffer, msgPtr, MESSAGE_LEN);
  const dec = new Uint8Array(
    module.wasmMemory.buffer,
    decPtr,
    DECRYPTED_LEN,
  );
  msg.fill(0);
  // malloc may return a region containing a previous plaintext. Initialize the
  // output before C runs, then copy it into JS only after full AEAD + Merkle
  // success. Failed receives never expose stale heap contents.
  dec.fill(0);
  msg.set(frame.subarray(0, MESSAGE_LEN), 0);
  new Uint8Array(
    module.wasmMemory.buffer,
    rootPtr,
    crypto_hash_sha512_BYTES,
  ).set(merkleRoot);
  new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN).set(key);

  const code = module._receive_message_with_key(
    decPtr,
    msgPtr,
    rootPtr,
    keyPtr,
  );

  const decrypted = code === 0 ? Uint8Array.from(dec) : null;

  // key + decrypted (holds the plaintext) are secret — wipe before free.
  module._free(msgPtr);
  module._free(rootPtr);
  zeroFree(
    module,
    new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN),
  );
  zeroFree(module, dec);

  return { code, decrypted };
};

/**
 * Seal ONE chunk under an already-derived per-message `messageKey` + `header`:
 * fresh random nonce, AEAD over `merkleRoot ‖ N ‖ PN`, framed as
 * `packChunkFrameHeader(header, nonce) ‖ ciphertext`. Does NOT touch the ratchet
 * (the caller stepped it ONCE via `ratchetEncrypt` for the whole message) and
 * does NOT wipe `messageKey` (the caller owns its lifecycle — it must stay live
 * across a big-file's streamed chunks AND across selective-retransmit rounds).
 *
 * This is the streaming/reconcile-friendly primitive the live send path uses: it
 * seals chunks one-at-a-time as they are read from IndexedDB, so a multi-GB
 * message is never materialised in RAM. A retransmit re-seals the same plaintext
 * under the SAME `messageKey` with a FRESH random nonce — cryptographically safe
 * (distinct 96-bit random nonces under one key) and decryptable by the receiver's
 * cached per-message key (a HIT on `(dhPub, N)`), so no frame-cache is needed.
 */
export const sealChunk = (
  messageKey: Uint8Array,
  header: RatchetHeader,
  chunk: Uint8Array,
  merkleRoot: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("messageChunkCrypto: merkleRoot must be 64 bytes");
  const aad = buildAad(merkleRoot, header.N, header.PN);
  const nonce = randomNonce(); // fresh + random per chunk
  const ciphertext = aeadSeal(module, messageKey, nonce, chunk, aad);
  const frameHeader = packChunkFrameHeader(header, nonce);
  const frame = new Uint8Array(frameHeader.length + ciphertext.length);
  frame.set(frameHeader, 0);
  frame.set(ciphertext, frameHeader.length);
  return frame;
};

export interface DecryptedChunk {
  /** The DECRYPTED_LEN plaintext `metadata ‖ receiptLeaf ‖ chunk` written by the C
   *  receive, or `null` when the chunk was dropped (AEAD or Merkle failure). */
  decrypted: Uint8Array | null;
  /** True iff C returned 0 — AEAD **and** Merkle both passed. When false the caller
   *  drops the chunk (but still persists the ratchet if `stateAdvanced`). */
  ok: boolean;
  /** True iff this chunk stepped the ratchet (first-arriving chunk of a message
   *  whose AEAD authenticated). The caller persists `state` when true — even if
   *  `ok` is false, since the DH step is real once the AEAD authenticates. */
  stateAdvanced: boolean;
}

/**
 * RECEIVE one chunk frame: derive the per-message key off the ratchet (in TS —
 * the ratchet state is a TS object), then do ALL the crypto in ONE C call
 * (`receiveWithKey` → `_receive_message_with_key`: decrypt + leaf-hash + Merkle +
 * receipt, in place).
 *
 * The `cache` (caller-owned, keyed by `messageCacheKey(dhPub, N)`) holds the
 * per-message key. On a HIT — chunk 2..n, out-of-order, or a duplicate — the key
 * is reused WITHOUT touching the ratchet. On a MISS the key is derived under the
 * clone-rollback contract and cached.
 *
 * Clone-rollback (MANDATORY — `ratchetDecrypt` mutates BEFORE the AEAD
 * authenticates, so a replayed/old-chain header could otherwise fire a spurious
 * DH-step and desync the session):
 *   1. `clone = deserializeRatchet(serializeRatchet(state))`.
 *   2. `messageKey = ratchetDecrypt(clone, header)` — mutates the CLONE only.
 *   3. C decrypts+verifies. COMMIT (adopt the clone, cache the key) iff the AEAD
 *      authenticated (`code !== -2`); on `-2` DISCARD the clone — the live `state`
 *      is byte-for-byte untouched. `ok` (store-vs-drop) then follows `code === 0`.
 *
 * Cache lifecycle: the caller evicts a message's key (via `messageCacheKey`) when
 * the message completes (all leaves present) or on a TTL, so a peer can't pin keys
 * with never-completing messages.
 */
export const decryptMessageChunk = (
  state: RatchetState,
  frame: Uint8Array,
  cache: Map<string, Uint8Array>,
  merkleRoot: Uint8Array,
  module: LibCrypto,
): DecryptedChunk => {
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("messageChunkCrypto: merkleRoot must be 64 bytes");

  const { header } = parseChunkFrameHeader(frame); // ratchet header + cache key
  const cacheK = messageCacheKey(header.dhPub, header.N);

  // HIT — reuse the per-message key; the ratchet is NOT touched.
  const cached = cache.get(cacheK);
  if (cached) {
    const { code, decrypted } = receiveWithKey(
      module,
      frame,
      merkleRoot,
      cached,
    );
    return {
      decrypted: code === 0 ? decrypted : null,
      ok: code === 0,
      stateAdvanced: false,
    };
  }

  // MISS — derive the message key on a CLONE.
  const clone = cloneRatchet(state);
  let messageKey: Uint8Array;
  try {
    messageKey = deriveOnClone(clone, header, module);
  } catch {
    // ratchetDecrypt rejected the header (e.g. a stale-chain replay) — drop; the
    // live state is untouched (deriveOnClone already wiped the clone).
    return { decrypted: null, ok: false, stateAdvanced: false };
  }

  const { code, decrypted } = receiveWithKey(
    module,
    frame,
    merkleRoot,
    messageKey,
  );

  if (code === -2) {
    // AEAD auth failed → ROLLBACK: discard the clone + key, live state unadvanced.
    messageKey.fill(0);
    wipeRatchet(clone);
    return { decrypted: null, ok: false, stateAdvanced: false };
  }

  // AEAD authenticated → COMMIT the ratchet step + cache the key for the rest of
  // the message. `ok` still depends on the Merkle result (`code === 0`).
  adoptRatchet(state, clone);
  cache.set(cacheK, messageKey);
  return {
    decrypted: code === 0 ? decrypted : null,
    ok: code === 0,
    stateAdvanced: true,
  };
};

// Derive the message key on a clone. Isolated so a `ratchetDecrypt` throw (e.g.
// an already-consumed same-chain replay, `header.N < Nr`) never leaves a
// half-mutated live state — the clone is thrown away with the exception.
const deriveOnClone = (
  clone: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): Uint8Array => {
  try {
    return ratchetDecrypt(clone, header, module);
  } catch (e) {
    wipeRatchet(clone);
    throw e;
  }
};
