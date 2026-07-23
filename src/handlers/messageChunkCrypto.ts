import {
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchet,
  deserializeRatchet,
} from "../cryptography/ratchet";
import {
  packChunkFrameHeader,
  parseChunkFrameHeader,
} from "./chunkFrame";
import { zeroFree } from "../utils/zeroFree";
import { RATCHET_N_LEN, RATCHET_PN_LEN } from "../utils/constants";
import {
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
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
// per-message `merkleRoot(64) ‖ N(8 BE) ‖ PN(8 BE)`, byte-identical to the C
// `receive_message_with_key` (pake_ratchet.c) so this crypto interoperates with
// the C receive path once it is wired in (Stage-7). N/PN come from the ratchet
// header, so the AAD is the same for every chunk of a message.
//
// SCOPE: this is the self-contained, unit-tested crypto CORE. It does NOT touch
// the handlers, the merkle/proof path, or the C. The receive-side AEAD open is
// merkle-free on purpose (see `aeadOpen`).

const AEAD_KEY_LEN = crypto_aead_chacha20poly1305_ietf_KEYBYTES; // 32
const AEAD_NONCE_LEN = crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12
const AEAD_TAG_LEN = crypto_box_poly1305_AUTHTAGBYTES; // 16
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
      ? Uint8Array.from(new Uint8Array(module.wasmMemory.buffer, outPtr, outLen))
      : null;

  // key, data (plaintext) and out (holds plaintext on the decrypt path) are
  // secret — zero them before returning the heap to the allocator.
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN));
  module._free(noncePtr);
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, dataPtr, dataAlloc));
  module._free(aadPtr);
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, outPtr, outLen));

  if (!out) throw new Error("messageChunkCrypto: AEAD encrypt failed");
  return out;
};

/**
 * AEAD open of `ciphertext = body ‖ tag(16)` under `key`/`nonce` via libsodium's
 * exported `_decrypt_chachapoly_symmetric` (crypto_aead_chacha20poly1305_ietf_decrypt):
 * the Poly1305 tag is verified in constant time inside libsodium and NO plaintext
 * is written on authentication failure. Returns the plaintext, or `null` if the
 * tag does not verify. AAD must be byte-identical to the seal's.
 */
const aeadOpen = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null => {
  if (ciphertext.length < AEAD_TAG_LEN) return null;
  const outLen = ciphertext.length - AEAD_TAG_LEN;
  const outAlloc = Math.max(outLen, 1);
  const aadAlloc = Math.max(aad.length, 1);

  const keyPtr = module._malloc(AEAD_KEY_LEN);
  const noncePtr = module._malloc(AEAD_NONCE_LEN);
  const inPtr = module._malloc(ciphertext.length);
  const aadPtr = module._malloc(aadAlloc);
  const outPtr = module._malloc(outAlloc);

  new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN).set(key);
  new Uint8Array(module.wasmMemory.buffer, noncePtr, AEAD_NONCE_LEN).set(nonce);
  new Uint8Array(module.wasmMemory.buffer, inPtr, ciphertext.length).set(
    ciphertext,
  );
  if (aad.length)
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);

  const r = module._decrypt_chachapoly_symmetric(
    outPtr,
    inPtr,
    ciphertext.length,
    keyPtr,
    noncePtr,
    aadPtr,
    aad.length,
  );

  const out =
    r === 0
      ? Uint8Array.from(new Uint8Array(module.wasmMemory.buffer, outPtr, outLen))
      : null;

  // key + out (holds the plaintext on success) are secret — wipe before free.
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, keyPtr, AEAD_KEY_LEN));
  module._free(noncePtr);
  module._free(inPtr);
  module._free(aadPtr);
  zeroFree(module, new Uint8Array(module.wasmMemory.buffer, outPtr, outAlloc));

  return out;
};

// Wipe the secret-bearing fields of a ratchet state (used to discard a rolled-
// back clone, and to retire superseded live secrets on commit).
const wipeRatchetSecrets = (s: RatchetState): void => {
  s.rootKey.fill(0);
  s.sendingChainKey?.fill(0);
  s.receivingChainKey?.fill(0);
  s.dhSelfSec.fill(0);
  for (const mk of s.skipped.values()) mk.fill(0);
};

// Commit an authenticated clone into the live state in place: retire the live
// state's superseded secrets, then adopt every field of `next` (the clone owns
// independent buffers — no aliasing with the retired ones).
const adoptRatchetState = (live: RatchetState, next: RatchetState): void => {
  wipeRatchetSecrets(live);
  live.rootKey = next.rootKey;
  live.sendingChainKey = next.sendingChainKey;
  live.receivingChainKey = next.receivingChainKey;
  live.dhSelfPub = next.dhSelfPub;
  live.dhSelfSec = next.dhSelfSec;
  live.dhRemotePub = next.dhRemotePub;
  live.Ns = next.Ns;
  live.Nr = next.Nr;
  live.PN = next.PN;
  live.skipped = next.skipped;
};

/**
 * SEND: step the ratchet ONCE for the whole message, then AEAD-encrypt every
 * chunk under the single message key with a fresh random per-chunk nonce, and
 * frame each as `packChunkFrameHeader(header, nonce) ‖ ciphertext`.
 *
 * `state` is advanced in place (the sending chain steps). The CALLER persists it
 * (`serializeRatchet` / `setRatchetSession`) — this function does NOT persist.
 * The message key is wiped after the last chunk.
 *
 * `merkleRoot` is the message's 64-byte root; it (plus the header's N/PN) forms
 * the per-chunk AAD, matching the C receive path.
 */
export const encryptMessageChunks = (
  state: RatchetState,
  chunks: Uint8Array[],
  merkleRoot: Uint8Array,
  module: LibCrypto,
): Uint8Array[] => {
  if (chunks.length === 0)
    throw new Error("messageChunkCrypto: a message needs at least one chunk");
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("messageChunkCrypto: merkleRoot must be 64 bytes");

  const { messageKey, header } = ratchetEncrypt(state, module); // ONCE per message
  try {
    const aad = buildAad(merkleRoot, header.N, header.PN);
    return chunks.map((chunk) => {
      const nonce = randomNonce(); // fresh + random per chunk
      const ciphertext = aeadSeal(module, messageKey, nonce, chunk, aad);
      const frameHeader = packChunkFrameHeader(header, nonce);
      const frame = new Uint8Array(frameHeader.length + ciphertext.length);
      frame.set(frameHeader, 0);
      frame.set(ciphertext, frameHeader.length);
      return frame;
    });
  } finally {
    messageKey.fill(0);
  }
};

export interface DecryptedChunk {
  plaintext: Uint8Array;
  /** True iff this chunk stepped the ratchet (the first chunk of a message that
   *  was not already in the cache). The caller persists `state` when true. */
  stateAdvanced: boolean;
}

/**
 * RECEIVE one chunk frame.
 *
 * The `cache` (caller-owned, keyed by `messageCacheKey(dhPub, N)`) holds the
 * per-message key. On a HIT — chunk 2..n of a message, an out-of-order chunk, or
 * a duplicate — the key is reused WITHOUT touching the ratchet (per-message
 * reuse + dedup in one). On a MISS the key is derived via the clone-rollback
 * contract and cached.
 *
 * Clone-rollback (MANDATORY — `ratchetDecrypt` mutates BEFORE the AEAD
 * authenticates, so a replayed/old-chain header could otherwise fire a spurious
 * DH-step and desync the session):
 *   1. `clone = deserializeRatchet(serializeRatchet(state))`.
 *   2. `messageKey = ratchetDecrypt(clone, header)` — mutates the CLONE only.
 *   3. AEAD-open the chunk. COMMIT (adopt the clone as live, cache the key) ONLY
 *      if it authenticates; otherwise DISCARD the clone — the live `state` is
 *      byte-for-byte untouched — and throw.
 *
 * Cache lifecycle: the caller evicts a message's key (via `messageCacheKey`)
 * when the message completes (all leaves present) or on a TTL, so a peer can't
 * pin keys with never-completing messages.
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

  const { header, nonce, ciphertext } = parseChunkFrameHeader(frame);
  const aad = buildAad(merkleRoot, header.N, header.PN);
  const key = messageCacheKey(header.dhPub, header.N);

  // HIT — reuse the per-message key; the ratchet is NOT advanced.
  const cached = cache.get(key);
  if (cached) {
    const plaintext = aeadOpen(module, cached, nonce, ciphertext, aad);
    if (!plaintext)
      throw new Error("messageChunkCrypto: chunk failed to authenticate");
    return { plaintext, stateAdvanced: false };
  }

  // MISS — derive on a CLONE; commit only after the AEAD authenticates.
  const clone = deserializeRatchet(serializeRatchet(state));
  const messageKey = deriveOnClone(clone, header, module);
  const plaintext = aeadOpen(module, messageKey, nonce, ciphertext, aad);
  if (!plaintext) {
    // ROLLBACK — discard the clone; the live `state` never advanced.
    messageKey.fill(0);
    wipeRatchetSecrets(clone);
    throw new Error("messageChunkCrypto: chunk failed to authenticate");
  }
  // COMMIT — adopt the advanced clone, cache the key for the message's rest.
  adoptRatchetState(state, clone);
  cache.set(key, messageKey);
  return { plaintext, stateAdvanced: true };
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
    wipeRatchetSecrets(clone);
    throw e;
  }
};
