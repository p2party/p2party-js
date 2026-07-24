import { hkdfExpand, hkdfExtract } from "./hkdf";
import {
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_hash_sha512_BYTES,
} from "./interfaces";
import {
  FRAME_TYPE_COVER,
  FRAME_TYPE_LEN,
  PQ_EPOCH_LEN,
  RATCHET_DHPUB_LEN,
  RATCHET_N_LEN,
  RATCHET_NONCE_LEN,
  RATCHET_PN_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
  RATCHET_ROOT_SUITE_MLKEM768,
  RATCHET_ROOT_SUITE_MLKEM1024,
  WIRE_CHUNK_FRAME_LEN,
  type RatchetRootSuite,
} from "../utils/constants";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

// ── protocol-v4 authenticated cover cells ────────────────────────────────────
//
// Scheduled cover lanes never send unauthenticated random bytes. Every cover
// slot carries one exact 65,490-byte cell in the uniform v4 geometry:
//
//   type(1) | edge-binding(32) | counter(8) | reserved(8) | keyEpoch(8)
//   | nonce(12) | encrypted(subtype(1) | payloadLen(4) | payload | zero pad)
//   | tag(16)
//
// The complete 69-byte clear header, including the nonce, is AEAD AAD. The
// key is derived from the CURRENT epoch's PQ message root, domain-separated
// by the authenticated room suite, the edge binding, the direction, and the
// epoch — so a cell from another lane, edge, room, direction, or epoch fails
// authentication outright. The subtype (dummy, CANCEL, terminal receipt) is
// inside the ciphertext: a receiver can distinguish them ONLY after
// authentication, and CANCEL/receipt payloads carry the 64-byte transfer
// Merkle root so a cell can never terminate another transfer's work.

const BINDING_OFFSET = FRAME_TYPE_LEN;
const COUNTER_OFFSET = BINDING_OFFSET + RATCHET_DHPUB_LEN;
const RESERVED_OFFSET = COUNTER_OFFSET + RATCHET_N_LEN;
const EPOCH_OFFSET = RESERVED_OFFSET + RATCHET_PN_LEN;
const NONCE_OFFSET = EPOCH_OFFSET + PQ_EPOCH_LEN;

export const COVER_CELL_HEADER_BYTES =
  FRAME_TYPE_LEN +
  RATCHET_DHPUB_LEN +
  RATCHET_N_LEN +
  RATCHET_PN_LEN +
  PQ_EPOCH_LEN +
  RATCHET_NONCE_LEN;
export const COVER_CELL_PLAINTEXT_BYTES =
  WIRE_CHUNK_FRAME_LEN -
  COVER_CELL_HEADER_BYTES -
  crypto_aead_chacha20poly1305_ietf_ABYTES;
export const COVER_CELL_BINDING_BYTES = RATCHET_DHPUB_LEN;
export const COVER_CELL_ROOT_BYTES = 32;
export const COVER_CELL_TOKEN_BYTES = crypto_hash_sha512_BYTES;

const SUBTYPE_BYTES = 1;
const PAYLOAD_LENGTH_BYTES = 4;
export const COVER_CELL_MAX_PAYLOAD_BYTES =
  COVER_CELL_PLAINTEXT_BYTES - SUBTYPE_BYTES - PAYLOAD_LENGTH_BYTES;

const MAX_U64 = (1n << 64n) - 1n;
const KEY_DOMAIN = new TextEncoder().encode(
  "p2party/cover-cell/key/v1\u0000",
);

export type CoverCellDirection =
  | "initiator-to-responder"
  | "responder-to-initiator";

export type CoverCellContent =
  | { readonly subtype: "dummy" }
  | {
      /** Explicit encrypted CANCEL for exactly one admitted transfer. */
      readonly subtype: "cancel";
      readonly merkleRoot: Uint8Array;
    }
  | {
      /**
       * Scheduled receipt (per-cell ack or terminal completion token), scoped
       * to its transfer root. Never the 65-byte immediate receipt frame.
       */
      readonly subtype: "receipt";
      readonly merkleRoot: Uint8Array;
      readonly token: Uint8Array;
    };

export type CoverCellErrorCode =
  | "authentication-failed"
  | "binding-mismatch"
  | "epoch-mismatch"
  | "invalid-cell"
  | "invalid-direction"
  | "invalid-padding"
  | "replayed-counter";

export class CoverCellError extends Error {
  readonly code: CoverCellErrorCode;

  constructor(code: CoverCellErrorCode, message: string) {
    super(`coverCell: ${message}`);
    this.name = "CoverCellError";
    this.code = code;
  }
}

const fail = (code: CoverCellErrorCode, message: string): never => {
  throw new CoverCellError(code, message);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= left[index] ^ right[index];
  return difference === 0;
};

const requireBytes = (
  value: unknown,
  name: string,
  length?: number,
): Uint8Array => {
  if (!(value instanceof Uint8Array))
    return fail("invalid-cell", `${name} must be a Uint8Array`);
  if (length !== undefined && value.length !== length)
    fail("invalid-cell", `${name} must be exactly ${String(length)} bytes`);
  return value;
};

const requireU64 = (value: unknown, name: string): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    return fail("invalid-cell", `${name} must be an unsigned 64-bit bigint`);
  return value;
};

const suiteTag = (rootSuite: RatchetRootSuite): number => {
  if (rootSuite === RATCHET_ROOT_SUITE_MLKEM768) return 1;
  if (rootSuite === RATCHET_ROOT_SUITE_MLKEM512) return 2;
  if (rootSuite === RATCHET_ROOT_SUITE_MLKEM1024) return 3;
  return fail("invalid-cell", "authenticated room suite is unsupported");
};

const directionTag = (direction: unknown): number => {
  if (direction === "initiator-to-responder") return 1;
  if (direction === "responder-to-initiator") return 2;
  return fail("invalid-direction", "cover-cell direction is unknown");
};

const subtypeTag = (subtype: CoverCellContent["subtype"]): number => {
  if (subtype === "dummy") return 1;
  if (subtype === "cancel") return 2;
  if (subtype === "receipt") return 3;
  return fail("invalid-cell", "cover-cell subtype is unknown");
};

const deriveCellKey = (
  module: LibCrypto,
  rootSuite: RatchetRootSuite,
  rootKey: Uint8Array,
  binding: Uint8Array,
  direction: CoverCellDirection,
  keyEpoch: bigint,
): Uint8Array => {
  requireBytes(rootKey, "PQ message root", COVER_CELL_ROOT_BYTES);
  requireBytes(binding, "edge binding", COVER_CELL_BINDING_BYTES);
  const epochBytes = new Uint8Array(8);
  new DataView(epochBytes.buffer).setBigUint64(
    0,
    requireU64(keyEpoch, "keyEpoch"),
    false,
  );
  const info = new Uint8Array(
    KEY_DOMAIN.length + 1 + 1 + binding.length + epochBytes.length,
  );
  info.set(KEY_DOMAIN, 0);
  info[KEY_DOMAIN.length] = suiteTag(rootSuite);
  info[KEY_DOMAIN.length + 1] = directionTag(direction);
  info.set(binding, KEY_DOMAIN.length + 2);
  info.set(epochBytes, KEY_DOMAIN.length + 2 + binding.length);

  const prk = hkdfExtract(rootKey, binding, module);
  try {
    return hkdfExpand(
      prk,
      info,
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
      module,
    );
  } finally {
    prk.fill(0);
    epochBytes.fill(0);
  }
};

const encodeContent = (content: CoverCellContent): Uint8Array => {
  if (content.subtype === "dummy") return new Uint8Array(0);
  if (content.subtype === "cancel")
    return Uint8Array.from(
      requireBytes(
        content.merkleRoot,
        "cancel transfer root",
        COVER_CELL_TOKEN_BYTES,
      ),
    );
  const merkleRoot = requireBytes(
    content.merkleRoot,
    "receipt transfer root",
    COVER_CELL_TOKEN_BYTES,
  );
  const token = requireBytes(
    content.token,
    "receipt token",
    COVER_CELL_TOKEN_BYTES,
  );
  const payload = new Uint8Array(merkleRoot.length + token.length);
  payload.set(merkleRoot, 0);
  payload.set(token, merkleRoot.length);
  return payload;
};

const decodeContent = (
  subtype: number,
  payload: Uint8Array,
): CoverCellContent => {
  if (subtype === 1) {
    if (payload.length !== 0)
      fail("invalid-cell", "dummy cover cells carry no payload");
    return { subtype: "dummy" };
  }
  if (subtype === 2) {
    if (payload.length !== COVER_CELL_TOKEN_BYTES)
      fail("invalid-cell", "CANCEL payload must be one 64-byte transfer root");
    return { subtype: "cancel", merkleRoot: Uint8Array.from(payload) };
  }
  if (subtype === 3) {
    if (payload.length !== COVER_CELL_TOKEN_BYTES * 2)
      fail("invalid-cell", "receipt payload must be root ‖ token");
    return {
      subtype: "receipt",
      merkleRoot: payload.slice(0, COVER_CELL_TOKEN_BYTES),
      token: payload.slice(COVER_CELL_TOKEN_BYTES),
    };
  }
  return fail("invalid-cell", "cover-cell subtype is unknown");
};

const randomNonce = (): Uint8Array => {
  const nonce = new Uint8Array(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  crypto.getRandomValues(nonce);
  return nonce;
};

const aeadSeal = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array => {
  const outputLength =
    plaintext.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const plaintextPtr = module._malloc(plaintext.length);
  const aadPtr = module._malloc(aad.length);
  const outputPtr = module._malloc(outputLength);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(
      module.wasmMemory.buffer,
      plaintextPtr,
      plaintext.length,
    ).set(plaintext);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);
    const result = module._encrypt_chachapoly_symmetric(
      outputPtr,
      plaintextPtr,
      plaintext.length,
      keyPtr,
      noncePtr,
      aadPtr,
      aad.length,
    );
    if (result !== 0)
      return fail("invalid-cell", "cover-cell AEAD encryption failed");
    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, plaintextPtr, plaintext.length),
    );
    module._free(aadPtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  }
};

const aeadOpen = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array => {
  const plaintextLength =
    ciphertext.length - crypto_aead_chacha20poly1305_ietf_ABYTES;
  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const ciphertextPtr = module._malloc(ciphertext.length);
  const aadPtr = module._malloc(aad.length);
  const plaintextPtr = module._malloc(plaintextLength);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(
      module.wasmMemory.buffer,
      ciphertextPtr,
      ciphertext.length,
    ).set(ciphertext);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);
    const plaintextHeap = new Uint8Array(
      module.wasmMemory.buffer,
      plaintextPtr,
      plaintextLength,
    );
    plaintextHeap.fill(0);
    const result = module._decrypt_chachapoly_symmetric(
      plaintextPtr,
      ciphertextPtr,
      ciphertext.length,
      keyPtr,
      noncePtr,
      aadPtr,
      aad.length,
    );
    if (result !== 0)
      return fail("authentication-failed", "cover-cell authentication failed");
    return Uint8Array.from(plaintextHeap);
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    module._free(ciphertextPtr);
    module._free(aadPtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, plaintextPtr, plaintextLength),
    );
  }
};

export interface SealCoverCellOptions {
  readonly module: LibCrypto;
  readonly rootSuite: RatchetRootSuite;
  /** Current epoch's PQ message root (borrowed; never wiped here). */
  readonly rootKey: Uint8Array;
  readonly binding: Uint8Array;
  readonly direction: CoverCellDirection;
  readonly keyEpoch: bigint;
  /** Strictly increasing per-direction cover counter (replay ordering). */
  readonly counter: bigint;
  readonly content: CoverCellContent;
}

export interface OpenCoverCellOptions {
  readonly module: LibCrypto;
  readonly rootSuite: RatchetRootSuite;
  readonly rootKey: Uint8Array;
  readonly binding: Uint8Array;
  /** Expected inbound direction; the opposite direction derives another key. */
  readonly direction: CoverCellDirection;
  readonly keyEpoch: bigint;
  /** Highest already-accepted counter; the cell must be strictly newer. */
  readonly counterAbove?: bigint;
  readonly frame: Uint8Array;
}

export interface OpenedCoverCell {
  readonly content: CoverCellContent;
  readonly counter: bigint;
}

/** Seal one authenticated fixed-size cover cell (dummy, CANCEL, or receipt). */
export const sealCoverCell = (options: SealCoverCellOptions): Uint8Array => {
  const binding = requireBytes(
    options.binding,
    "edge binding",
    COVER_CELL_BINDING_BYTES,
  );
  const keyEpoch = requireU64(options.keyEpoch, "keyEpoch");
  const counter = requireU64(options.counter, "counter");
  const payload = encodeContent(options.content);
  if (payload.length > COVER_CELL_MAX_PAYLOAD_BYTES)
    fail("invalid-cell", "cover payload does not fit the uniform cell");

  const nonce = randomNonce();
  const header = new Uint8Array(COVER_CELL_HEADER_BYTES);
  header[0] = FRAME_TYPE_COVER;
  header.set(binding, BINDING_OFFSET);
  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  );
  view.setBigUint64(COUNTER_OFFSET, counter, false);
  // RESERVED_OFFSET remains canonical zero.
  view.setBigUint64(EPOCH_OFFSET, keyEpoch, false);
  header.set(nonce, NONCE_OFFSET);

  const plaintext = new Uint8Array(COVER_CELL_PLAINTEXT_BYTES);
  plaintext[0] = subtypeTag(options.content.subtype);
  new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  ).setUint32(SUBTYPE_BYTES, payload.length, false);
  plaintext.set(payload, SUBTYPE_BYTES + PAYLOAD_LENGTH_BYTES);

  const key = deriveCellKey(
    options.module,
    options.rootSuite,
    options.rootKey,
    binding,
    options.direction,
    keyEpoch,
  );
  try {
    const ciphertext = aeadSeal(options.module, key, nonce, plaintext, header);
    const frame = new Uint8Array(WIRE_CHUNK_FRAME_LEN);
    frame.set(header, 0);
    frame.set(ciphertext, COVER_CELL_HEADER_BYTES);
    return frame;
  } finally {
    key.fill(0);
    plaintext.fill(0);
    payload.fill(0);
  }
};

/**
 * Authenticate one fixed-size cover cell and return its content. The subtype
 * is knowable only after this authentication succeeds; an unauthentic cell
 * reveals nothing and terminates nothing.
 */
export const openCoverCell = (
  options: OpenCoverCellOptions,
): OpenedCoverCell => {
  const frame = requireBytes(
    options.frame,
    "cover cell",
    WIRE_CHUNK_FRAME_LEN,
  );
  const binding = requireBytes(
    options.binding,
    "edge binding",
    COVER_CELL_BINDING_BYTES,
  );
  const keyEpoch = requireU64(options.keyEpoch, "keyEpoch");
  if (frame[0] !== FRAME_TYPE_COVER)
    fail("invalid-cell", "frame type is not a cover cell");
  if (
    !bytesEqual(
      frame.subarray(BINDING_OFFSET, BINDING_OFFSET + RATCHET_DHPUB_LEN),
      binding,
    )
  )
    fail("binding-mismatch", "cover cell belongs to another edge");

  const header = frame.subarray(0, COVER_CELL_HEADER_BYTES);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const counter = view.getBigUint64(COUNTER_OFFSET, false);
  if (view.getBigUint64(RESERVED_OFFSET, false) !== 0n)
    fail("invalid-cell", "cover-cell reserved header must be zero");
  if (view.getBigUint64(EPOCH_OFFSET, false) !== keyEpoch)
    fail("epoch-mismatch", "cover-cell epoch is not the expected epoch");
  if (options.counterAbove !== undefined) {
    requireU64(options.counterAbove, "counterAbove");
    if (counter <= options.counterAbove)
      fail("replayed-counter", "cover-cell counter is not strictly newer");
  }

  const nonce = frame.subarray(NONCE_OFFSET, NONCE_OFFSET + RATCHET_NONCE_LEN);
  const ciphertext = frame.subarray(COVER_CELL_HEADER_BYTES);
  const key = deriveCellKey(
    options.module,
    options.rootSuite,
    options.rootKey,
    binding,
    options.direction,
    keyEpoch,
  );
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = aeadOpen(options.module, key, nonce, ciphertext, header);
    const payloadLength = new DataView(
      plaintext.buffer,
      plaintext.byteOffset,
      plaintext.byteLength,
    ).getUint32(SUBTYPE_BYTES, false);
    if (payloadLength > COVER_CELL_MAX_PAYLOAD_BYTES)
      fail("invalid-padding", "encrypted cover payload length is invalid");
    const payloadOffset = SUBTYPE_BYTES + PAYLOAD_LENGTH_BYTES;
    const paddingOffset = payloadOffset + payloadLength;
    let nonzeroPadding = 0;
    for (let index = paddingOffset; index < plaintext.length; index += 1)
      nonzeroPadding |= plaintext[index];
    if (nonzeroPadding !== 0)
      fail("invalid-padding", "encrypted cover padding must be all zero");

    const content = decodeContent(
      plaintext[0],
      plaintext.subarray(payloadOffset, paddingOffset),
    );
    return { content, counter };
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
};
