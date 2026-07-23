import { x25519Keypair, x25519Dh } from "./x25519";
import { hkdfExtract, hkdfExpand } from "./hkdf";
import {
  KDF_RK_LABEL,
  KDF_CK_LABEL,
  KDF_MK_LABEL,
  MAX_SKIP,
  MAX_SKIP_SESSION,
  RATCHET_DHPUB_LEN,
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
 * Seed a ratchet from the handshake's 32-byte, transcript-bound hybrid root.
 *
 * Initiator/responder asymmetry (must match so the two sides interoperate):
 *  - The **responder** (`amInitiator=false`, `remoteDhPub=null`) generates its
 *    DH keypair and stops: both chains stay `null`. After the initiator's
 *    initial DH pub is authenticated, `primeResponderRatchet` performs the
 *    receive-side DH step without consuming a message key and opens both
 *    chains. A lower-level caller that does not prime retains the legacy
 *    first-inbound-message behavior.
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
    if (!remoteDhPub)
      throw new Error("ratchet: initiator requires remoteDhPub");
    state.dhRemotePub = Uint8Array.from(remoteDhPub);
    const dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
    const rk = kdfRk(state.rootKey, dhOut, module);
    dhOut.fill(0);
    state.rootKey.fill(0); // wipe the seed copy now superseded by the first root
    state.rootKey = rk.rootKey;
    state.sendingChainKey = rk.chainKey;
  }
  // Responder: chains stay null until primeResponderRatchet or first inbound.

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

  // Anti-DoS: MAX_SKIP above only bounds derivations within THIS call; bound
  // the CUMULATIVE size of `state.skipped` across the whole session too, else
  // a peer that repeatedly forces DH-steps (or gaps) can grow it — and the
  // persisted IndexedDB row — without ceiling. Evict the OLDEST entries first
  // (a `Map` preserves insertion order) rather than throwing, so availability
  // for recent/legitimate reordering is preserved.
  if (state.skipped.size > MAX_SKIP_SESSION) {
    for (const k of state.skipped.keys()) {
      if (state.skipped.size <= MAX_SKIP_SESSION) break;
      state.skipped.get(k)?.fill(0);
      state.skipped.delete(k);
    }
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
 * Complete the responder's handshake-time ratchet bootstrap after the
 * initiator's initial DH public key has been authenticated by key confirmation.
 *
 * This is the receive-side DH step that an unprimed responder would otherwise
 * perform on the initiator's first message, deliberately stopped before
 * `kdfCk`: it opens the receiving chain from
 * `DH(initialResponder, initialInitiator)`, rotates the responder DH keypair,
 * and opens the sending chain from `DH(rotatedResponder, initialInitiator)`.
 * Consequently both peers can send message 0 immediately after the handshake,
 * including simultaneously, without consuming or skipping a message key.
 */
export const primeResponderRatchet = (
  state: RatchetState,
  initiatorDhPub: Uint8Array,
  module: LibCrypto,
): void => {
  if (initiatorDhPub.length !== RATCHET_DHPUB_LEN)
    throw new Error("ratchet: invalid initiator DH public key");
  if (
    state.sendingChainKey ||
    state.receivingChainKey ||
    state.dhRemotePub ||
    state.Ns !== 0 ||
    state.Nr !== 0 ||
    state.PN !== 0 ||
    state.skipped.size !== 0
  )
    throw new Error("ratchet: responder bootstrap requires pristine state");

  dhRatchet(
    state,
    {
      dhPub: initiatorDhPub,
      N: 0,
      PN: 0,
    },
    module,
  );
};

/**
 * Advance the receiving side for an inbound header and return its message key.
 *
 * CAUTION — this function is UNAUTHENTICATED: it mutates `state` (and may fire
 * a DH-ratchet step) from the cleartext header alone, before the AEAD tag is
 * ever checked (authentication happens later, in Stage 5). A duplicate or
 * replayed message that is NOT a stored skipped key — e.g. a retransmit of a
 * message from a chain the session has since stepped past — is NOT detected
 * here: it falls through to the "new peer DH pub" case below and can fire a
 * spurious backward DH-step, permanently desyncing the session. This is
 * reachable by our own retransmit/reconcile layer, so callers MUST:
 *   1. Dedup already-seen `(header.dhPub, header.N)` pairs BEFORE calling this
 *      function — never invoke it a second time for a message already
 *      processed.
 *   2. Call `ratchetDecrypt` on a CLONE of `state` (via
 *      `deserializeRatchet(serializeRatchet(state))`) and commit that clone as
 *      the live state ONLY after the returned message key successfully
 *      authenticates the AEAD ciphertext. If authentication fails, discard the
 *      clone and leave the live state untouched.
 * `ratchetDecrypt` itself performs neither dedup nor authentication — the safe
 * integration of both rules is wired in Stage 4/5, not here.
 *
 * Against that (untrusted) header, handles three cases: (a) a stored skipped
 * key — out-of-order delivery within an already-seen chain, (b) a new peer DH
 * pub — skip the old chain's tail, then DH-step, (c) a forward message in the
 * current chain — skip any gap, then derive. The consumed chain key is wiped
 * once its successor is derived.
 */
export const ratchetDecrypt = (
  state: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): Uint8Array => {
  if (
    !Number.isInteger(header.N) ||
    header.N < 0 ||
    !Number.isInteger(header.PN) ||
    header.PN < 0
  )
    throw new Error("invalid ratchet header");

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

/** Deep-clone a live ratchet state into independently owned key buffers. */
export const cloneRatchet = (state: RatchetState): RatchetState =>
  deserializeRatchet(serializeRatchet(state));

/** Wipe every secret-bearing buffer owned by a ratchet state. */
export const wipeRatchet = (state: RatchetState): void => {
  state.rootKey.fill(0);
  state.sendingChainKey?.fill(0);
  state.receivingChainKey?.fill(0);
  state.dhSelfSec.fill(0);
  for (const messageKey of state.skipped.values()) messageKey.fill(0);
};

/**
 * Replace a live state with an independently owned authenticated successor.
 * The superseded live secrets are wiped before ownership moves from `next`.
 */
export const adoptRatchet = (live: RatchetState, next: RatchetState): void => {
  wipeRatchet(live);
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
