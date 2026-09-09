import {
  adoptRatchet,
  cloneRatchet,
  ratchetDecrypt,
  wipeRatchet,
} from "../cryptography/ratchet";
import { packChunkFrameHeader, parseChunkFrameHeader } from "./chunkFrame";
import { zeroFree } from "../utils/zeroFree";
import {
  CHUNK_AAD_HEADER_LEN,
  MESSAGE_LEN,
  DECRYPTED_LEN,
} from "../utils/constants";
import {
  combinePqMessageKey,
  PQ_MESSAGE_KEY_BINDING_BYTES,
  PQ_MESSAGE_KEY_ROOT_BYTES,
} from "../cryptography/pqMessageKey";
import {
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";

import type { RatchetState, RatchetHeader } from "../cryptography/ratchet";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";

// ── v4 per-message ratchet + PQ key combiner + per-chunk AEAD ────────────────
//
// THE key subtlety (design §"per-MESSAGE, not per-chunk"): `ratchetEncrypt` /
// `ratchetDecrypt` MUTATE and advance the ratchet ONCE per call. A logical
// message is many chunks. So the ratchet is stepped ONCE per message and the
// resulting `messageKey` is reused (from a caller-owned cache on receive) for
// every chunk of that message. Each chunk gets a fresh random 12-byte nonce.
//
// AEAD: symmetric ChaCha20-Poly1305-IETF under the combined message key. AAD =
// `merkleRoot(64) ‖ type(1) ‖ dhPub(32) ‖ N(8) ‖ PN(8) ‖ pqEpoch(8)`.
// The complete clear header excluding the fresh random nonce is authenticated.
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
const AAD_LEN = crypto_hash_sha512_BYTES + CHUNK_AAD_HEADER_LEN; // 121
const MAX_U64 = (1n << 64n) - 1n;

const toHex = (u8: Uint8Array): string =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Per-message key-cache key. Production passes the parsed epoch explicitly and
 * gets an epoch-bound `(dhPub,N,epoch)` identity. Omitting the epoch preserves
 * the legacy low-level `dhPub:N` identity for raw/bootstrap tests only; this is
 * needed while those tests still round-trip keys through RatchetState.skipped,
 * whose historical serializer understands exactly that two-field shape.
 */
export const messageCacheKey = (
  dhPub: Uint8Array,
  N: number,
  pqEpoch?: bigint,
): string => {
  const prefix = `${toHex(dhPub)}:${N}`;
  if (pqEpoch === undefined) return prefix;
  if (typeof pqEpoch !== "bigint" || pqEpoch < 0n || pqEpoch > MAX_U64)
    throw new Error("messageChunkCrypto: PQ epoch out of u64 range");
  return `${prefix}:${pqEpoch.toString(10)}`;
};

// AAD = merkleRoot || the exact on-wire clear header excluding its nonce.
// Copying the serialized bytes (rather than re-encoding fields) makes TS/C
// parity structural: C memcpy's the same prefix from the received frame.
const buildAad = (
  merkleRoot: Uint8Array,
  frameHeader: Uint8Array,
): Uint8Array => {
  if (frameHeader.length < CHUNK_AAD_HEADER_LEN)
    throw new Error("messageChunkCrypto: incomplete chunk frame header");
  const aad = new Uint8Array(AAD_LEN);
  aad.set(merkleRoot, 0);
  aad.set(
    frameHeader.subarray(0, CHUNK_AAD_HEADER_LEN),
    crypto_hash_sha512_BYTES,
  );
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
  const dec = new Uint8Array(module.wasmMemory.buffer, decPtr, DECRYPTED_LEN);
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
 * Seal ONE chunk under an already-derived classical `messageKey` + `header`.
 * With a PQ context, an owned copy of the classical key is consumed by the v4
 * combiner and the resulting key is wiped after this one AEAD operation. The
 * caller's classical key remains live across streamed chunks/retransmit rounds.
 * The low-level context-free default emits bootstrap epoch zero and uses the
 * raw classical key for backwards-compatible tests only.
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
  pqContext?: PqMessageKeyContext,
): Uint8Array => {
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("messageChunkCrypto: merkleRoot must be 64 bytes");
  const nonce = randomNonce(); // fresh + random per chunk
  const frameHeader = packChunkFrameHeader(
    header,
    nonce,
    pqContext?.epoch ?? 0n,
  );
  const aad = buildAad(merkleRoot, frameHeader);
  let combinedKey: Uint8Array | null = null;
  try {
    const aeadKey = pqContext
      ? (combinedKey = combinePqMessageKey(
          Uint8Array.from(messageKey),
          pqContext,
          header,
          module,
        ))
      : messageKey;
    const ciphertext = aeadSeal(module, aeadKey, nonce, chunk, aad);
    const frame = new Uint8Array(frameHeader.length + ciphertext.length);
    frame.set(frameHeader, 0);
    frame.set(ciphertext, frameHeader.length);
    return frame;
  } finally {
    combinedKey?.fill(0);
  }
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
 * Resolve an authenticated, currently acceptable PQ epoch. Returning null
 * rejects unknown/stale/future epochs before a Double-Ratchet clone is touched.
 */
export type PqMessageKeyContextResolver = (
  epoch: bigint,
) => PqMessageKeyContext | null;

const resolvedContextMatches = (
  context: PqMessageKeyContext,
  epoch: bigint,
  rootSuite: RatchetState["rootSuite"],
): boolean =>
  context.epoch === epoch &&
  context.rootSuite === rootSuite &&
  context.rootKey instanceof Uint8Array &&
  context.rootKey.length === PQ_MESSAGE_KEY_ROOT_BYTES &&
  context.binding instanceof Uint8Array &&
  context.binding.length === PQ_MESSAGE_KEY_BINDING_BYTES;

/**
 * RECEIVE one chunk frame: derive the per-message key off the ratchet (in TS —
 * the ratchet state is a TS object), then do ALL the crypto in ONE C call
 * (`receiveWithKey` → `_receive_message_with_key`: decrypt + leaf-hash + Merkle +
 * receipt, in place).
 *
 * The production `cache` is caller-owned and keyed by
 * `messageCacheKey(dhPub,N,pqEpoch)`. It stores already-combined active receive
 * keys separately from classical skipped keys. On a HIT the key is reused
 * without touching the ratchet. On a MISS, the resolver must authorize the
 * epoch before the classical key is derived on a clone and combined.
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
  pqContextResolver?: PqMessageKeyContextResolver,
): DecryptedChunk => {
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("messageChunkCrypto: merkleRoot must be 64 bytes");

  const { header, pqEpoch } = parseChunkFrameHeader(frame);

  let pqContext: PqMessageKeyContext | null = null;
  if (pqContextResolver) {
    try {
      pqContext = pqContextResolver(pqEpoch);
    } catch {
      return { decrypted: null, ok: false, stateAdvanced: false };
    }
    if (
      !pqContext ||
      !resolvedContextMatches(pqContext, pqEpoch, state.rootSuite)
    )
      return { decrypted: null, ok: false, stateAdvanced: false };
  } else if (pqEpoch !== 0n) {
    // Context-free operation is a bootstrap-only low-level compatibility path.
    // Never interpret a nonzero wire epoch as a raw classical key.
    return { decrypted: null, ok: false, stateAdvanced: false };
  }

  const cacheK = messageCacheKey(
    header.dhPub,
    header.N,
    pqContextResolver ? pqEpoch : undefined,
  );

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
    if (pqContext)
      messageKey = combinePqMessageKey(messageKey, pqContext, header, module);
  } catch {
    // Header rejection or combiner/context failure only touched the clone.
    // combinePqMessageKey consumes its classical input even when it throws.
    wipeRatchet(clone);
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
