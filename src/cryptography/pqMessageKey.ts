import { hkdfExpand, hkdfExtract } from "./hkdf";
import {
  FRAME_TYPE_CHUNK,
  isRatchetRootSuite,
  RATCHET_DHPUB_LEN,
} from "../utils/constants";
import { crypto_aead_chacha20poly1305_ietf_KEYBYTES } from "./interfaces";

import type { LibCrypto } from "./libcrypto";
import type { RatchetHeader } from "./ratchet";
import type { RatchetRootSuite } from "../utils/constants";

/**
 * Context authenticated by the hybrid bootstrap and advanced by sparse PQ
 * healing. `rootKey` is reusable epoch state: this module copies it and never
 * wipes the caller's live buffer.
 */
export interface PqMessageKeyContext {
  readonly rootKey: Uint8Array;
  readonly binding: Uint8Array;
  readonly rootSuite: RatchetRootSuite;
  readonly epoch: bigint;
}

export const PQ_MESSAGE_KEY_BYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
export const PQ_MESSAGE_KEY_ROOT_BYTES = 32;
export const PQ_MESSAGE_KEY_BINDING_BYTES = 32;

const MAX_U64 = (1n << 64n) - 1n;
const DOMAIN = new TextEncoder().encode("p2party/pq-message-key/v1\u0000");

const requireBytes = (
  value: Uint8Array,
  name: string,
  length: number,
): void => {
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new Error(`pqMessageKey: ${name} must be ${String(length)} bytes`);
};

const requireCounter = (value: number, name: string): void => {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error(`pqMessageKey: ${name} is outside the safe u64 range`);
};

const requireEpoch = (value: bigint): void => {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    throw new Error("pqMessageKey: epoch is outside the u64 range");
};

const viewsOverlap = (a: Uint8Array, b: Uint8Array): boolean =>
  a.buffer === b.buffer &&
  a.byteOffset < b.byteOffset + b.byteLength &&
  b.byteOffset < a.byteOffset + a.byteLength;

/**
 * Canonical public HKDF info:
 *
 * domain || suiteLen(u16 BE) || suite(UTF-8) || binding(32) ||
 * epoch(u64 BE) || FRAME_TYPE_CHUNK(1) || dhPub(32) || N(u64 BE) ||
 * PN(u64 BE)
 *
 * The explicit type prevents cross-use outside application chunk cells. Every
 * integer uses the same big-endian encoding as the wire header.
 */
const encodeInfo = (
  context: PqMessageKeyContext,
  header: RatchetHeader,
): Uint8Array => {
  if (!isRatchetRootSuite(context.rootSuite))
    throw new Error("pqMessageKey: unsupported root suite");
  requireBytes(context.rootKey, "rootKey", PQ_MESSAGE_KEY_ROOT_BYTES);
  requireBytes(context.binding, "binding", PQ_MESSAGE_KEY_BINDING_BYTES);
  requireEpoch(context.epoch);
  requireBytes(header.dhPub, "header.dhPub", RATCHET_DHPUB_LEN);
  requireCounter(header.N, "header.N");
  requireCounter(header.PN, "header.PN");

  const suite = new TextEncoder().encode(context.rootSuite);
  if (suite.length > 0xffff)
    throw new Error("pqMessageKey: root suite identifier is too long");
  const length =
    DOMAIN.length +
    2 +
    suite.length +
    PQ_MESSAGE_KEY_BINDING_BYTES +
    8 +
    1 +
    RATCHET_DHPUB_LEN +
    8 +
    8;
  const info = new Uint8Array(length);
  let offset = 0;
  info.set(DOMAIN, offset);
  offset += DOMAIN.length;
  const view = new DataView(info.buffer);
  view.setUint16(offset, suite.length, false);
  offset += 2;
  info.set(suite, offset);
  offset += suite.length;
  info.set(context.binding, offset);
  offset += PQ_MESSAGE_KEY_BINDING_BYTES;
  view.setBigUint64(offset, context.epoch, false);
  offset += 8;
  info[offset++] = FRAME_TYPE_CHUNK;
  info.set(header.dhPub, offset);
  offset += RATCHET_DHPUB_LEN;
  view.setBigUint64(offset, BigInt(header.N), false);
  offset += 8;
  view.setBigUint64(offset, BigInt(header.PN), false);
  return info;
};

/**
 * Combine one classical Double-Ratchet message key with the current PQ epoch
 * root:
 *
 *   PRK = HKDF-Extract-SHA512(salt = pqRoot, IKM = classicalMessageKey)
 *   key = HKDF-Expand-SHA512(PRK, canonicalContext, 32)
 *
 * Ownership is deliberate: `classicalMessageKey` is consumed and zeroed on
 * every success/failure path. The live `context.rootKey` remains reusable; only
 * an owned copy and the transient PRK are wiped. Callers that need the
 * classical key for multiple chunks must pass an owned copy on each call.
 */
export const combinePqMessageKey = (
  classicalMessageKey: Uint8Array,
  context: PqMessageKeyContext,
  header: RatchetHeader,
  module: LibCrypto,
): Uint8Array => {
  if (!(classicalMessageKey instanceof Uint8Array))
    throw new Error("pqMessageKey: classicalMessageKey must be a Uint8Array");
  // Consuming an alias would necessarily destroy the reusable live root. Make
  // that invalid ownership relationship explicit rather than violating either
  // side of the contract.
  if (
    context?.rootKey instanceof Uint8Array &&
    viewsOverlap(classicalMessageKey, context.rootKey)
  )
    throw new Error(
      "pqMessageKey: classicalMessageKey must not alias context.rootKey",
    );

  let rootCopy: Uint8Array | null = null;
  let prk: Uint8Array | null = null;
  try {
    requireBytes(
      classicalMessageKey,
      "classicalMessageKey",
      PQ_MESSAGE_KEY_BYTES,
    );
    const info = encodeInfo(context, header);
    rootCopy = Uint8Array.from(context.rootKey);
    prk = hkdfExtract(rootCopy, classicalMessageKey, module);
    return hkdfExpand(prk, info, PQ_MESSAGE_KEY_BYTES, module);
  } finally {
    classicalMessageKey.fill(0);
    rootCopy?.fill(0);
    prk?.fill(0);
  }
};
