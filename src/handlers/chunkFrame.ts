import {
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_LEN,
  RATCHET_DHPUB_LEN,
  RATCHET_N_LEN,
  RATCHET_PN_LEN,
  PQ_EPOCH_LEN,
  RATCHET_NONCE_LEN,
  CHUNK_HEADER_LEN,
} from "../utils/constants";

import type { RatchetHeader } from "../cryptography/ratchet";

// ── v3 CHUNK frame codec (Stage-5 task 1) ────────────────────────────────────────
// Layout: FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8 BE) ‖ PN(8 BE) ‖ PQ_EPOCH(1) ‖ nonce(12) ‖ ciphertext
// The ratchet header (dhPub,N,PN) is shared by every chunk of a message; the nonce is
// fresh + random per chunk. Pure functions — no wasm, no state — so they are trivially
// unit-testable. The send/receive paths that USE them are Stage-5 task 3.

const DHPUB_OFF = FRAME_TYPE_LEN; // 1
const N_OFF = DHPUB_OFF + RATCHET_DHPUB_LEN; // 33
const PN_OFF = N_OFF + RATCHET_N_LEN; // 41
const PQ_EPOCH_OFF = PN_OFF + RATCHET_PN_LEN; // 49
const NONCE_OFF = PQ_EPOCH_OFF + PQ_EPOCH_LEN; // 50

/** Total cleartext header length; ciphertext begins here. = 62 (the v3 MESSAGE_START). */
export const CHUNK_FRAME_HEADER_LEN = FRAME_TYPE_LEN + CHUNK_HEADER_LEN;

// The ratchet counters (N, PN) are JS numbers but need a fixed 8-byte wire width. They
// are serialized big-endian and guarded to the safe-integer range (a peer sending a
// counter > 2^53-1 is rejected rather than silently truncated).
const writeU64BE = (out: Uint8Array, offset: number, value: number): void => {
  if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER)
    throw new Error("chunkFrame: ratchet counter out of safe-integer range");
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(
    offset,
    BigInt(value),
    false,
  );
};

const readU64BE = (buf: Uint8Array, offset: number): number => {
  const v = new DataView(
    buf.buffer,
    buf.byteOffset,
    buf.byteLength,
  ).getBigUint64(offset, false);
  if (v > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error("chunkFrame: ratchet counter exceeds safe-integer range");
  return Number(v);
};

/** Build the 62-byte cleartext chunk-frame header (ciphertext is appended by the caller). */
export const packChunkFrameHeader = (
  header: RatchetHeader,
  nonce: Uint8Array,
): Uint8Array => {
  if (header.dhPub.length !== RATCHET_DHPUB_LEN)
    throw new Error("chunkFrame: dhPub must be 32 bytes");
  if (nonce.length !== RATCHET_NONCE_LEN)
    throw new Error("chunkFrame: nonce must be 12 bytes");
  const out = new Uint8Array(CHUNK_FRAME_HEADER_LEN);
  out[0] = FRAME_TYPE_CHUNK;
  out.set(header.dhPub, DHPUB_OFF);
  writeU64BE(out, N_OFF, header.N);
  writeU64BE(out, PN_OFF, header.PN);
  // Epoch zero is the mandatory ML-KEM bootstrap root. Periodic/sparse KEM
  // epoch advancement is intentionally not part of the current v3 ratchet.
  out[PQ_EPOCH_OFF] = 0;
  out.set(nonce, NONCE_OFF);
  return out;
};

export interface ParsedChunkFrame {
  header: RatchetHeader; // dhPub is a zero-copy view into `frame`
  nonce: Uint8Array; // zero-copy view
  ciphertext: Uint8Array; // zero-copy view
}

/** Parse a v3 CHUNK frame into its ratchet header, nonce, and ciphertext (zero-copy views). */
export const parseChunkFrameHeader = (frame: Uint8Array): ParsedChunkFrame => {
  if (frame.length < CHUNK_FRAME_HEADER_LEN)
    throw new Error("chunkFrame: frame shorter than the header");
  if (frame[0] !== FRAME_TYPE_CHUNK)
    throw new Error("chunkFrame: leading byte is not FRAME_TYPE_CHUNK");
  if (frame[PQ_EPOCH_OFF] !== 0)
    throw new Error("chunkFrame: unsupported PQ epoch");
  return {
    header: {
      dhPub: frame.subarray(DHPUB_OFF, DHPUB_OFF + RATCHET_DHPUB_LEN),
      N: readU64BE(frame, N_OFF),
      PN: readU64BE(frame, PN_OFF),
    },
    nonce: frame.subarray(NONCE_OFF, NONCE_OFF + RATCHET_NONCE_LEN),
    ciphertext: frame.subarray(CHUNK_FRAME_HEADER_LEN),
  };
};
