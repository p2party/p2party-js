import { x25519Keypair, x25519Dh } from "./x25519";
import { hkdfExtract, hkdfExpand } from "./hkdf";
import {
  KDF_RK_LABEL,
  KDF_CK_LABEL,
  KDF_MK_LABEL,
  MAX_SKIP,
} from "../utils/constants";

import type { LibCrypto } from "./libcrypto";

// HKDF `info` strings for the two ratchet chains (SSOT labels, constants.ts).
const RK_INFO = new TextEncoder().encode(KDF_RK_LABEL);
const CK_INFO = new TextEncoder().encode(KDF_CK_LABEL);
const MK_INFO = new TextEncoder().encode(KDF_MK_LABEL);

/**
 * Live Double Ratchet state for one `(roomId, peerPublicKey)` edge. Every key
 * field is a plain-JS `Uint8Array` secret (the WASM heap holds no ratchet state
 * — see design §9): `rootKey`, both chain keys, `dhSelfSec`, and each value in
 * `skipped`. Stage 3 wraps these at rest; here they are live plaintext.
 *
 * The ratchet advances **per logical message**, never per chunk. `Ns`/`Nr` are
 * the send/receive message counters in the current chains; `PN` is the length
 * of the previous sending chain (folded into inbound headers so the peer can
 * skip the tail of a superseded chain).
 */
export interface RatchetState {
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  dhSelfPub: Uint8Array;
  dhSelfSec: Uint8Array;
  dhRemotePub: Uint8Array | null;
  Ns: number;
  Nr: number;
  PN: number;
  skipped: Map<string, Uint8Array>;
}

/**
 * Cleartext per-message ratchet header. Rides the frame so the receiver can
 * derive the message key before decrypting: `dhPub` drives the DH ratchet, `N`
 * is this message's index in the sender's current chain, `PN` is the length of
 * the sender's previous chain (for skip-on-DH-step).
 */
export interface RatchetHeader {
  dhPub: Uint8Array;
  N: number;
  PN: number;
}

/**
 * Serializable projection of a `RatchetState` — maps 1:1 onto the wrapped
 * secret fields of the `RatchetSession` IndexedDB row (Stage 3). All buffers
 * are owned copies; the skipped map is flattened to an array keyed by
 * `(dhPub, n)`.
 */
export interface RatchetSessionSecrets {
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer | null;
  receivingChainKey: ArrayBuffer | null;
  dhSelfPub: ArrayBuffer;
  dhSelfSec: ArrayBuffer;
  dhRemotePub: ArrayBuffer | null;
  Ns: number;
  Nr: number;
  PN: number;
  skippedMessageKeys: Array<{
    dhPub: ArrayBuffer;
    n: number;
    messageKey: ArrayBuffer;
  }>;
}

const toHex = (u8: Uint8Array): string =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

const fromHex = (hex: string): Uint8Array => {
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++)
    u[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return u;
};

// Constant-time equality for the (public) DH-pub comparison that triggers a step.
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

// KDF_RK: (rootKey, dhOut) -> (newRootKey, chainKey). HKDF-Extract salted with
// the current root over the DH output, then Expand to 64 bytes split 32/32.
// prk/okm are transient secrets and are wiped before this returns.
const kdfRk = (
  rootKey: Uint8Array,
  dhOut: Uint8Array,
  module: LibCrypto,
): { rootKey: Uint8Array; chainKey: Uint8Array } => {
  const prk = hkdfExtract(rootKey, dhOut, module);
  const okm = hkdfExpand(prk, RK_INFO, 64, module);
  prk.fill(0);
  const newRoot = okm.slice(0, 32);
  const chainKey = okm.slice(32, 64);
  okm.fill(0);
  return { rootKey: newRoot, chainKey };
};

// KDF_CK: chainKey -> (nextChainKey, messageKey) via two domain-separated
// HMAC-SHA512s (HKDF-Extract keyed by the chain key over the CK/MK labels),
// each truncated to 32 bytes. The two full HMAC outputs are wiped here; the
// caller owns the returned 32-byte halves.
const kdfCk = (
  chainKey: Uint8Array,
  module: LibCrypto,
): { chainKey: Uint8Array; messageKey: Uint8Array } => {
  const mkFull = hkdfExtract(chainKey, MK_INFO, module);
  const ckFull = hkdfExtract(chainKey, CK_INFO, module);
  const messageKey = mkFull.slice(0, 32);
  const nextChainKey = ckFull.slice(0, 32);
  mkFull.fill(0);
  ckFull.fill(0);
  return { chainKey: nextChainKey, messageKey };
};

/**
 * Seed a ratchet from a 32-byte root secret (CPace `K` or X3DH secret).
 *
 * Initiator/responder asymmetry (must match so the two sides interoperate):
 *  - The **responder** (`amInitiator=false`, `remoteDhPub=null`) generates its
 *    DH keypair and stops: both chains stay `null`. It publishes `dhSelfPub`;
 *    the first inbound message triggers its first DH-ratchet step, which builds
 *    the receiving chain (and, in the same step, its sending chain).
 *  - The **initiator** (`amInitiator=true`) is handed the responder's
 *    `dhSelfPub` as `remoteDhPub`, runs one `kdf_rk` over `DH(selfSec, remote)`
 *    to advance the root and open its **sending** chain immediately, so it can
 *    send message 0 before ever hearing back. Its receiving chain opens on the
 *    responder's first reply (a DH step against the responder's fresh pub).
 */
export const initRatchet = (
  rootSeed: Uint8Array,
  amInitiator: boolean,
  remoteDhPub: Uint8Array | null,
  module: LibCrypto,
): RatchetState => {
  const kp = x25519Keypair(module);
  const state: RatchetState = {
    rootKey: Uint8Array.from(rootSeed),
    sendingChainKey: null,
    receivingChainKey: null,
    dhSelfPub: kp.publicKey,
    dhSelfSec: kp.secretKey,
    dhRemotePub: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: new Map(),
  };

  if (amInitiator) {
    if (!remoteDhPub) throw new Error("ratchet: initiator requires remoteDhPub");
    state.dhRemotePub = Uint8Array.from(remoteDhPub);
    const dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
    const rk = kdfRk(state.rootKey, dhOut, module);
    dhOut.fill(0);
    state.rootKey.fill(0); // wipe the seed copy now superseded by the first root
    state.rootKey = rk.rootKey;
    state.sendingChainKey = rk.chainKey;
  }
  // Responder: chains stay null; the first inbound header triggers the DH step.

  return state;
};

/**
 * Advance the sending chain by one message. Returns the message key (caller's to
 * consume/wipe) and the cleartext header to put on the wire. The consumed chain
 * key is wiped once its successor is derived.
 */
export const ratchetEncrypt = (
  state: RatchetState,
  module: LibCrypto,
): { messageKey: Uint8Array; header: RatchetHeader } => {
  if (!state.sendingChainKey) throw new Error("ratchet: no sending chain");
  const { chainKey, messageKey } = kdfCk(state.sendingChainKey, module);
  const header: RatchetHeader = {
    dhPub: Uint8Array.from(state.dhSelfPub),
    N: state.Ns,
    PN: state.PN,
  };
  state.sendingChainKey.fill(0);
  state.sendingChainKey = chainKey;
  state.Ns += 1;
  return { messageKey, header };
};

// Pop a previously-stored key for an out-of-order/replayed message, keyed by
// (header.dhPub, header.N). Consumed keys are removed so they can't be reused.
const trySkipped = (
  state: RatchetState,
  header: RatchetHeader,
): Uint8Array | null => {
  const key = `${toHex(header.dhPub)}:${header.N}`;
  const mk = state.skipped.get(key);
  if (mk) {
    state.skipped.delete(key);
    return mk;
  }
  return null;
};

// Derive-and-stash the message keys for indices [Nr, until) of the current
// receiving chain so later out-of-order deliveries can be served. Anti-DoS:
// skipping more than MAX_SKIP keys in one call throws rather than looping.
const skipMessageKeys = (
  state: RatchetState,
  until: number,
  module: LibCrypto,
): void => {
  if (state.Nr + MAX_SKIP < until)
    throw new Error("ratchet: MAX_SKIP exceeded");
  if (!state.receivingChainKey) return;
  while (state.Nr < until) {
    const { chainKey, messageKey } = kdfCk(state.receivingChainKey, module);
    state.receivingChainKey.fill(0);
    state.receivingChainKey = chainKey;
    state.skipped.set(`${toHex(state.dhRemotePub!)}:${state.Nr}`, messageKey);
    state.Nr += 1;
  }
};

// A DH-ratchet step: the peer moved to a new DH pub. Finish nothing here (the
// caller skips the previous chain's tail first), then (1) derive the new
// receiving chain from DH(oldSelfSec, newRemotePub), (2) rotate our own DH key,
// (3) derive the new sending chain from DH(newSelfSec, newRemotePub). Retired
// roots, chain keys and the retired DH secret are wiped.
const dhRatchet = (
  state: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): void => {
  state.PN = state.Ns;
  state.Ns = 0;
  state.Nr = 0;
  state.dhRemotePub = Uint8Array.from(header.dhPub);

  let dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
  let rk = kdfRk(state.rootKey, dhOut, module);
  dhOut.fill(0);
  state.rootKey.fill(0);
  state.rootKey = rk.rootKey;
  state.receivingChainKey?.fill(0);
  state.receivingChainKey = rk.chainKey;

  const oldSelfSec = state.dhSelfSec;
  const kp = x25519Keypair(module);
  state.dhSelfPub = kp.publicKey;
  state.dhSelfSec = kp.secretKey;
  oldSelfSec.fill(0);

  dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
  rk = kdfRk(state.rootKey, dhOut, module);
  dhOut.fill(0);
  state.rootKey.fill(0);
  state.rootKey = rk.rootKey;
  state.sendingChainKey?.fill(0);
  state.sendingChainKey = rk.chainKey;
};

/**
 * Advance the receiving side for an inbound header and return its message key.
 * Handles three cases: (a) a stored skipped key (replay/out-of-order within a
 * seen chain), (b) a new peer DH pub — skip the old chain's tail, then DH-step,
 * (c) a forward message in the current chain — skip any gap, then derive.
 * The consumed chain key is wiped once its successor is derived.
 */
export const ratchetDecrypt = (
  state: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): Uint8Array => {
  const skipped = trySkipped(state, header);
  if (skipped) return skipped;

  const isNewDh =
    !state.dhRemotePub || !bytesEqual(header.dhPub, state.dhRemotePub);
  if (isNewDh) {
    skipMessageKeys(state, header.PN, module); // finish the previous chain
    dhRatchet(state, header, module);
  }

  if (header.N < state.Nr)
    throw new Error("ratchet: message key already consumed");

  skipMessageKeys(state, header.N, module);
  const { chainKey, messageKey } = kdfCk(state.receivingChainKey!, module);
  state.receivingChainKey!.fill(0);
  state.receivingChainKey = chainKey;
  state.Nr += 1;
  return messageKey;
};

const toBuf = (u8: Uint8Array): ArrayBuffer => u8.slice().buffer;
const toBufN = (u8: Uint8Array | null): ArrayBuffer | null =>
  u8 ? u8.slice().buffer : null;

/**
 * Snapshot all live state (including the skipped map + DH keys) to owned
 * buffers for at-rest persistence. Does NOT wipe the source state — the caller
 * keeps using it.
 */
export const serializeRatchet = (
  state: RatchetState,
): RatchetSessionSecrets => ({
  rootKey: toBuf(state.rootKey),
  sendingChainKey: toBufN(state.sendingChainKey),
  receivingChainKey: toBufN(state.receivingChainKey),
  dhSelfPub: toBuf(state.dhSelfPub),
  dhSelfSec: toBuf(state.dhSelfSec),
  dhRemotePub: toBufN(state.dhRemotePub),
  Ns: state.Ns,
  Nr: state.Nr,
  PN: state.PN,
  skippedMessageKeys: Array.from(state.skipped.entries()).map(([k, mk]) => {
    const idx = k.lastIndexOf(":");
    return {
      dhPub: fromHex(k.slice(0, idx)).slice().buffer,
      n: Number(k.slice(idx + 1)),
      messageKey: mk.slice().buffer,
    };
  }),
});

/** Rebuild a live `RatchetState` from a persisted snapshot. */
export const deserializeRatchet = (s: RatchetSessionSecrets): RatchetState => {
  const skipped = new Map<string, Uint8Array>();
  for (const e of s.skippedMessageKeys) {
    const dh = new Uint8Array(e.dhPub);
    skipped.set(`${toHex(dh)}:${e.n}`, new Uint8Array(e.messageKey));
  }
  return {
    rootKey: new Uint8Array(s.rootKey),
    sendingChainKey: s.sendingChainKey
      ? new Uint8Array(s.sendingChainKey)
      : null,
    receivingChainKey: s.receivingChainKey
      ? new Uint8Array(s.receivingChainKey)
      : null,
    dhSelfPub: new Uint8Array(s.dhSelfPub),
    dhSelfSec: new Uint8Array(s.dhSelfSec),
    dhRemotePub: s.dhRemotePub ? new Uint8Array(s.dhRemotePub) : null,
    Ns: s.Ns,
    Nr: s.Nr,
    PN: s.PN,
    skipped,
  };
};
