import { deriveGenerator, cpaceStart, cpaceShared } from "../cryptography/cpace";
import { x3dhDeriveSecret } from "../cryptography/x3dh";
import { x25519Keypair } from "../cryptography/x25519";
import { initRatchet, serializeRatchet } from "../cryptography/ratchet";
import { verifyIdentityCrossSig } from "../cryptography/identityCrossSig";
import { setRatchetSession, getIdentityX25519 } from "../db/api";
import { store } from "../store";
import { openRatchetGate, rejectRatchetGate } from "./ratchetGate";
import { zeroFree } from "../utils/zeroFree";
import { FRAME_TYPE_HANDSHAKE, PQ_TAG } from "../utils/constants";
import {
  concatUint8Arrays,
  hexToUint8Array,
  uint8ArrayToHex,
  uint8ArraysAreEqual,
} from "../utils/uint8array";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { RatchetState } from "../cryptography/ratchet";
import type { RatchetSession } from "../db/types";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";

export interface ChannelInputParams {
  channelId: Uint8Array;
  ikInitiator: Uint8Array;
  ikResponder: Uint8Array;
  fpInitiator: Uint8Array;
  fpResponder: Uint8Array;
}

/**
 * CPace channel-input transcript (spec §5): CI = channel-id ‖ IK_a ‖ IK_b ‖
 * fp_a ‖ fp_b ‖ PQ_TAG, with a = initiator, b = responder. Both peers build a
 * byte-identical CI because they agree on the initiator role (Task 4). Binding
 * both identity keys + both DTLS fingerprints is what makes a swapped-cert
 * MITM fail the key-confirmation MAC.
 *
 * Deliberately synchronous (unlike the project's async concatUint8Arrays
 * helper in utils/uint8array.ts, which yields to the microtask queue for
 * parity with other WASM-backed helpers): CI construction is pure
 * byte-copying with no WASM/IndexedDB involved, and callers build it inline
 * while assembling the CPace transcript.
 */
export const buildChannelInput = (p: ChannelInputParams): Uint8Array => {
  const parts = [
    p.channelId,
    p.ikInitiator,
    p.ikResponder,
    p.fpInitiator,
    p.fpResponder,
    PQ_TAG,
  ];

  let len = 0;
  for (const part of parts) len += part.length;

  const ci = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    ci.set(part, offset);
    offset += part.length;
  }

  return ci;
};

const FINGERPRINT_RE = /a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/;

/**
 * Raw bytes of the `a=fingerprint:sha-256 XX:XX:...` line in an SDP blob.
 * Throws if no sha-256 fingerprint attribute is present, or if the one found
 * doesn't decode to exactly 32 bytes.
 */
export const parseFingerprintFromSdp = (sdp: string): Uint8Array => {
  const match = FINGERPRINT_RE.exec(sdp);
  if (!match) throw new Error("No sha-256 DTLS fingerprint found in SDP");

  const bytes = match[1].split(":").map((byte) => parseInt(byte, 16));
  if (bytes.length !== 32 || bytes.some((b) => Number.isNaN(b)))
    throw new Error("Malformed sha-256 DTLS fingerprint in SDP");

  return Uint8Array.from(bytes);
};

const normalizeFingerprintHex = (fp: string): string =>
  fp.replace(/:/g, "").toLowerCase();

// Shape of the entries RTCStatsReport.forEach hands back that this helper
// reads. RTCStatsReport's own DOM typing declares its forEach value as `any`
// (there is no per-type stats union in lib.dom.d.ts), so this local interface
// is what keeps the body of verifyDtlsFingerprints free of `any`.
interface RTCStatEntry {
  type: string;
  id?: string;
  localCertificateId?: string;
  remoteCertificateId?: string;
  fingerprint?: string;
}

/**
 * Post-connect DTLS binding check (spec §5): the fingerprint declared in the
 * SDP (and bound into the CPace channel-input via buildChannelInput) must
 * equal the live certificate reported by getStats(). A disagreement means the
 * DTLS transport terminates on a different certificate than the one that was
 * authenticated by the handshake — i.e. a signaling server (or any on-path
 * attacker) swapped the SDP fingerprint/cert after the CPace transcript was
 * bound. This is the actual MITM tripwire, so it THROWS (never returns a
 * boolean, never logs-and-continues) — the caller must abort the channel.
 */
export const verifyDtlsFingerprints = async (
  epc: IRTCPeerConnection,
): Promise<void> => {
  const localSdp = epc.localDescription?.sdp ?? "";
  const remoteSdp = epc.remoteDescription?.sdp ?? "";

  const localSdpFp = normalizeFingerprintHex(
    uint8ArrayToHex(parseFingerprintFromSdp(localSdp)),
  );
  const remoteSdpFp = normalizeFingerprintHex(
    uint8ArrayToHex(parseFingerprintFromSdp(remoteSdp)),
  );

  const stats = await epc.getStats();

  // RTCStatsReport only exposes forEach (no .get in the DOM typings), and per
  // the webrtc-stats spec the Map key IS each report's own id — report.id
  // itself is not guaranteed to be echoed back on every implementation — so
  // matching is done against the forEach key, falling back to report.id.
  let localCertId: string | undefined;
  let remoteCertId: string | undefined;
  stats.forEach((report: RTCStatEntry) => {
    if (report.type === "transport") {
      localCertId = report.localCertificateId ?? localCertId;
      remoteCertId = report.remoteCertificateId ?? remoteCertId;
    }
  });

  const certificateFingerprint = (id: string | undefined): string | null => {
    if (!id) return null;
    let found: string | null = null;
    stats.forEach((report: RTCStatEntry, key: string) => {
      if (
        report.type === "certificate" &&
        (key === id || report.id === id) &&
        report.fingerprint
      ) {
        found = normalizeFingerprintHex(report.fingerprint);
      }
    });
    return found;
  };

  const liveLocalFp = certificateFingerprint(localCertId);
  const liveRemoteFp = certificateFingerprint(remoteCertId);

  // Fail closed: a tripwire that cannot confirm a fingerprint must abort, not
  // pass. If the live certificate can't be located in the stats report (e.g.
  // a missing/attacker-truncated report), that is treated the same as an
  // outright mismatch — never as "unable to verify, so allow".
  if (liveLocalFp === null || liveLocalFp !== localSdpFp)
    throw new Error(
      "DTLS fingerprint mismatch: local certificate not found or does not match local SDP fingerprint",
    );
  if (liveRemoteFp === null || liveRemoteFp !== remoteSdpFp)
    throw new Error(
      "DTLS fingerprint mismatch: remote certificate not found or does not match remote SDP fingerprint (possible MITM)",
    );
};

// ── protocol-v3 handshake core (spec §5) ─────────────────────────────────────

// Internal handshake sub-frame tags (inside the FRAME_TYPE_HANDSHAKE payload).
const HS_STEP_HELLO = 0x01;
const HS_STEP_CONFIRM = 0x02;
// Key-confirmation domain separator (local to the handshake; only ever hashed
// into the MAC input, never on the wire outside it).
const HS_KC_DOMAIN = new TextEncoder().encode("p2party-hs-v1");
// Role separators appended to the transcript so the responder's and the
// initiator's key-confirmation MACs are over distinct messages and can never be
// reflected/replayed for one another.
const HS_MAC_TAG_RESPONDER = new Uint8Array([HS_STEP_CONFIRM]);
const HS_MAC_TAG_INITIATOR = new Uint8Array([HS_STEP_HELLO]);
// CPace generator session-id (D1). The generator G = deriveGenerator(pin, sid,
// CI) must be byte-identical on both legs, so both must feed the SAME sid. We
// bind the INITIATOR's sid: it is the one value both legs can agree on without a
// prior round, which forces an initiator-first ordering — the initiator knows
// its own sid upfront and derives G before sending HELLO, while the responder
// must RECEIVE the initiator's HELLO first, take the initiator's sid from it,
// and only then derive its matching G and reply. (Binding both sids is
// impossible: neither leg knows the peer's before it must publish its CPace Y.)
// Freshness comes from the channel-input (CI = channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖
// fp_b ‖ PQ_TAG, whose per-connection DTLS fingerprints are session-unique) plus
// the initiator's random sid folded into G; BOTH sids are additionally bound
// into the key-confirmation transcript below. See task report.

const DH_LEN = 32;
const SID_LEN = 32;
const EK_LEN = 32;
const Y_LEN = 32;
const MAC_LEN = 64;
// In-band X25519 identity carried by each HELLO: the dedicated X25519 identity
// pub plus its Ed25519 cross-signature (verified against the pinned peer Ed25519
// identity before any DH). IDENTITY_SIG_LEN stays distinct from MAC_LEN (both
// happen to be 64) so the two 64-byte roles never get conflated.
const X25519_ID_PUB_LEN = 32;
const IDENTITY_SIG_LEN = 64;

const HELLO_LEN =
  1 + SID_LEN + EK_LEN + Y_LEN + X25519_ID_PUB_LEN + IDENTITY_SIG_LEN;
const CONFIRM_LEN = 1 + DH_LEN + MAC_LEN;

export interface HandshakeTransport {
  send(bytes: Uint8Array): void;
  recv(): Promise<Uint8Array>;
}

export interface HandshakeCoreParams {
  mode: "pin" | "nopin";
  pin: Uint8Array | null;
  channelInput: Uint8Array;
  amInitiator: boolean;
  idSelfSec: Uint8Array;
  selfIdentityX25519Pub: Uint8Array;
  selfIdentityCrossSignature: Uint8Array;
  peerIdentityEd25519Pub: Uint8Array;
}

// HMAC-SHA512(key, msg) via the Stage-1 export (HKDF-Extract == HMAC with the
// salt as key). Small fixed buffers, freed immediately. The key is the derived
// root secret, so its wasm-heap staging copy is zeroFree'd (Stage-1/2
// convention), never plain-freed.
const hmacSha512 = (
  key: Uint8Array,
  msg: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const keyPtr = module._malloc(key.length);
  const msgPtr = module._malloc(msg.length);
  const outPtr = module._malloc(MAC_LEN);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, msgPtr, msg.length).set(msg);
    const r = module._hkdf_sha512_extract(
      outPtr,
      keyPtr,
      key.length,
      msgPtr,
      msg.length,
    );
    if (r !== 0) throw new Error("handshake hmac_sha512 failed");
    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outPtr, MAC_LEN),
    );
  } finally {
    // key is secret material: wipe its staging buffer, don't merely free it.
    zeroFree(module, new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length));
    module._free(msgPtr);
    module._free(outPtr);
  }
};

// HELLO   = [HS_STEP_HELLO ‖ sid(32) ‖ EK(32) ‖ Y(32) ‖ X25519_id_pub(32) ‖ crossSig(64)]
//           (Y = zeros in no-PIN; X25519_id_pub + crossSig carry the in-band identity)
// CONFIRM = [HS_STEP_CONFIRM ‖ dhPub(32) ‖ mac(64)]       (dhPub = zeros from initiator)
// Both fixed size, one FRAME_TYPE_HANDSHAKE frame each.
const packHello = (
  sid: Uint8Array,
  ek: Uint8Array,
  y: Uint8Array,
  x25519Pub: Uint8Array,
  crossSig: Uint8Array,
): Uint8Array => {
  const out = new Uint8Array(HELLO_LEN);
  out[0] = HS_STEP_HELLO;
  out.set(sid, 1);
  out.set(ek, 1 + SID_LEN);
  out.set(y, 1 + SID_LEN + EK_LEN);
  out.set(x25519Pub, 1 + SID_LEN + EK_LEN + Y_LEN);
  out.set(crossSig, 1 + SID_LEN + EK_LEN + Y_LEN + X25519_ID_PUB_LEN);
  return out;
};

const packConfirm = (dhPub: Uint8Array, mac: Uint8Array): Uint8Array => {
  const out = new Uint8Array(CONFIRM_LEN);
  out[0] = HS_STEP_CONFIRM;
  out.set(dhPub, 1);
  out.set(mac, 1 + DH_LEN);
  return out;
};

/**
 * Two-round handshake core (spec §5), decoupled from RTCDataChannel so it is
 * unit-testable with two linked in-memory transports:
 *   R1  both send HELLO {sid, EK, Y}; derive the 32-byte secret (X3DH-DH or CPace).
 *   R2  responder initRatchet(false,null) → dhPubR, sends CONFIRM{dhPubR, mac_R};
 *       initiator recvs CONFIRM, sends its own CONFIRM{0, mac_I}, verifies mac_R,
 *       then seeds initRatchet(true, dhPubR); responder verifies mac_I.
 *
 * The MAC is HMAC(secret, transcript ‖ role) over the full ordered transcript T;
 * a swapped cert/key (or a wrong PIN) makes the two legs' secret disagree while
 * T stays byte-identical, so the key-confirmation MAC fails on both sides →
 * throw. Persistence + gate-open happen ONLY in runHandshake, after this
 * resolves, so a throw here leaves nothing persisted.
 *
 * NOTE on the R2 ordering: the initiator publishes its mac_I BEFORE verifying
 * mac_R. That send does not depend on the ratchet state (T is fully known once
 * dhPubR arrives), and it guarantees the responder's recv() is always satisfied
 * — otherwise a wrong-PIN initiator would abort before sending and deadlock the
 * responder's recv(). The initiator still seeds its ratchet only AFTER mac_R
 * verifies, so a bad handshake never yields a usable initiator state.
 */
export const performHandshakeCore = async (
  transport: HandshakeTransport,
  params: HandshakeCoreParams,
  module: LibCrypto,
): Promise<{ state: RatchetState; secret: Uint8Array }> => {
  const {
    mode,
    pin,
    channelInput,
    amInitiator,
    idSelfSec,
    selfIdentityX25519Pub,
    selfIdentityCrossSignature,
    peerIdentityEd25519Pub,
  } = params;

  // R1: build our HELLO. Ephemeral X25519 EK is always generated (its pub is in
  // the transcript for both modes); its secret is only DH'd in no-PIN mode.
  const sidSelf = crypto.getRandomValues(new Uint8Array(SID_LEN));
  const ek = x25519Keypair(module);
  let cpaceY: Uint8Array = new Uint8Array(Y_LEN); // zeros in no-PIN
  let cpaceScalar: Uint8Array | null = null; // our secret CPace scalar y
  let secret: Uint8Array | undefined;

  // D1: CPace generator over the INITIATOR's sid. Returns null in no-PIN mode
  // (there is no CPace generator there); the initiator-first ordering below is
  // applied uniformly in both modes for simplicity. The scalar/Y are assigned in
  // the caller's direct control flow (not inside this closure) so the finally's
  // cpaceScalar wipe sees the correct `Uint8Array | null` type.
  const startCpace = (
    sidForG: Uint8Array,
  ): { y: Uint8Array; Y: Uint8Array } | null => {
    if (mode !== "pin") return null;
    if (!pin) throw new Error("PIN mode requires a PIN");
    const G = deriveGenerator(pin, sidForG, channelInput, module);
    const started = cpaceStart(G, module);
    G.fill(0); // public point, but no reason to keep it around
    return started;
  };

  const buildHello = (): Uint8Array =>
    packHello(
      sidSelf,
      ek.publicKey,
      cpaceY,
      selfIdentityX25519Pub,
      selfIdentityCrossSignature,
    );

  try {
    // R1 — initiator-first exchange (D1). The initiator knows its own sid
    // upfront, so it derives G, starts CPace, and sends HELLO before receiving.
    // The responder must receive the initiator's HELLO FIRST to learn the
    // initiator's sid, then derive its matching G and reply.
    let peerHello: Uint8Array;
    if (amInitiator) {
      // generator binds MY sid (I am the initiator)
      const started = startCpace(sidSelf);
      if (started) {
        cpaceScalar = started.y;
        cpaceY = started.Y;
      }
      transport.send(buildHello());
      peerHello = await transport.recv();
    } else {
      peerHello = await transport.recv();
    }

    // Parse peer HELLO. Fail closed on any malformed/short/mis-tagged frame.
    if (peerHello.length !== HELLO_LEN || peerHello[0] !== HS_STEP_HELLO)
      throw new Error("Malformed handshake HELLO");
    const sidPeer = peerHello.subarray(1, 1 + SID_LEN);
    const ekPeer = peerHello.subarray(1 + SID_LEN, 1 + SID_LEN + EK_LEN);
    const yPeer = peerHello.subarray(
      1 + SID_LEN + EK_LEN,
      1 + SID_LEN + EK_LEN + Y_LEN,
    );
    const peerX25519Pub = peerHello.subarray(
      1 + SID_LEN + EK_LEN + Y_LEN,
      1 + SID_LEN + EK_LEN + Y_LEN + X25519_ID_PUB_LEN,
    );
    const peerCrossSig = peerHello.subarray(
      1 + SID_LEN + EK_LEN + Y_LEN + X25519_ID_PUB_LEN,
      HELLO_LEN,
    );

    // T5: verify-before-DH, fail-closed. The peer's X25519 identity pub must be
    // cross-signed by the pinned peer Ed25519 identity; otherwise abort BEFORE
    // computing any shared secret. The finally-block below wipes ek.secretKey /
    // cpaceScalar and the catch wipes `secret`, so a throw here is free of leaks.
    if (
      !(await verifyIdentityCrossSig(
        peerX25519Pub,
        peerCrossSig,
        peerIdentityEd25519Pub,
        module,
      ))
    )
      throw new Error("Handshake peer X25519 identity cross-signature invalid");

    // Responder: now that the initiator's sid is known, derive the matching G
    // and send our HELLO in reply.
    if (!amInitiator) {
      // generator binds the INITIATOR's (peer's) sid
      const started = startCpace(sidPeer);
      if (started) {
        cpaceScalar = started.y;
        cpaceY = started.Y;
      }
      transport.send(buildHello());
    }

    // Derive the shared 32-byte secret. Both modes fold CI: no-PIN via
    // x3dh(idKeys, EKs) over the VERIFIED peer X25519 pub from the HELLO; PIN via
    // G = deriveGenerator(pin, sid, CI) so CI is already bound into K.
    if (mode === "pin") {
      secret = cpaceShared(cpaceScalar!, yPeer, module);
    } else {
      secret = x3dhDeriveSecret(
        idSelfSec,
        peerX25519Pub,
        ek.secretKey,
        ekPeer,
        amInitiator,
        module,
      );
    }

    // Ordered transcript T (I = initiator, R = responder). Both legs build the
    // byte-identical value regardless of which side computed each field.
    const sidI = amInitiator ? sidSelf : sidPeer;
    const sidR = amInitiator ? sidPeer : sidSelf;
    const ekI = amInitiator ? ek.publicKey : ekPeer;
    const ekR = amInitiator ? ekPeer : ek.publicKey;
    const yI = amInitiator ? cpaceY : yPeer;
    const yR = amInitiator ? yPeer : cpaceY;
    const buildTranscript = (dhPubR: Uint8Array): Promise<Uint8Array> =>
      concatUint8Arrays([
        HS_KC_DOMAIN,
        sidI,
        sidR,
        ekI,
        ekR,
        yI,
        yR,
        dhPubR,
        channelInput,
      ]);

    // R2 — DH-ratchet exchange + bidirectional key confirmation.
    let state: RatchetState;
    if (!amInitiator) {
      // Responder: seed the ratchet, publish its DH pub, MAC the transcript.
      state = initRatchet(secret, false, null, module);
      const dhPubR = state.dhSelfPub;
      const T = await buildTranscript(dhPubR);
      const macR = hmacSha512(
        secret,
        await concatUint8Arrays([T, HS_MAC_TAG_RESPONDER]),
        module,
      );
      transport.send(packConfirm(dhPubR, macR));

      const peerConfirm = await transport.recv();
      if (peerConfirm.length !== CONFIRM_LEN || peerConfirm[0] !== HS_STEP_CONFIRM)
        throw new Error("Malformed handshake CONFIRM");
      const macI = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
      const expectI = hmacSha512(
        secret,
        await concatUint8Arrays([T, HS_MAC_TAG_INITIATOR]),
        module,
      );
      if (!(await uint8ArraysAreEqual(macI, expectI)))
        throw new Error("Handshake key-confirmation failed");
    } else {
      // Initiator: wait for the responder's DH pub, publish our mac_I (does not
      // need the ratchet state), verify mac_R, THEN seed against dhPubR.
      const peerConfirm = await transport.recv();
      if (peerConfirm.length !== CONFIRM_LEN || peerConfirm[0] !== HS_STEP_CONFIRM)
        throw new Error("Malformed handshake CONFIRM");
      const dhPubR = Uint8Array.from(peerConfirm.subarray(1, 1 + DH_LEN));
      const macR = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
      const T = await buildTranscript(dhPubR);
      const macI = hmacSha512(
        secret,
        await concatUint8Arrays([T, HS_MAC_TAG_INITIATOR]),
        module,
      );
      transport.send(packConfirm(new Uint8Array(DH_LEN), macI));
      const expectR = hmacSha512(
        secret,
        await concatUint8Arrays([T, HS_MAC_TAG_RESPONDER]),
        module,
      );
      if (!(await uint8ArraysAreEqual(macR, expectR)))
        throw new Error("Handshake key-confirmation failed");
      state = initRatchet(secret, true, dhPubR, module);
    }

    return { state, secret };
  } catch (err) {
    // Fail closed: wipe the root secret on any failure so nothing usable lingers.
    secret?.fill(0);
    throw err;
  } finally {
    // Ephemeral scalar secrets are never needed past derivation; wipe on every
    // exit (success or throw). The returned root `secret` is intentionally left
    // intact for the caller and wiped by runHandshake after it is persisted.
    ek.secretKey.fill(0);
    cpaceScalar?.fill(0);
  }
};

// ── handshake inbox / channel registry + runHandshake wiring seam ─────────────

// Per-peer handshake inbox: the main channel's onmessage (Task 5) routes
// FRAME_TYPE_HANDSHAKE payloads here (tag stripped); runHandshake's
// transport.recv() awaits them, buffering any that arrive before a recv.
interface Inbox {
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void };
  queue: Uint8Array[];
  waiters: ((v: Uint8Array) => void)[];
}
const inboxes = new Map<string, Inbox>();

export const setHandshakeChannel = (
  peerId: string,
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void },
): void => {
  inboxes.set(peerId, { channel, queue: [], waiters: [] });
};

export const deliverHandshakeFrame = (
  peerId: string,
  payload: Uint8Array,
): void => {
  const inbox = inboxes.get(peerId);
  if (!inbox) return;
  const next = inbox.waiters.shift();
  if (next) next(payload);
  else inbox.queue.push(payload);
};

const transportForPeer = (peerId: string): HandshakeTransport => {
  const inbox = inboxes.get(peerId);
  if (!inbox) throw new Error(`No handshake channel registered for ${peerId}`);
  return {
    send: (bytes: Uint8Array): void => {
      // Prefix the FRAME_TYPE_HANDSHAKE tag on the wire; the peer's onmessage
      // strips it before deliverHandshakeFrame.
      const framed = new Uint8Array(1 + bytes.length);
      framed[0] = FRAME_TYPE_HANDSHAKE;
      framed.set(bytes, 1);
      // framed owns its whole buffer (offset 0, full length), so sending the
      // ArrayBuffer is byte-equivalent to the view and satisfies both arms of
      // the channel union's send() signature.
      inbox.channel.send(framed.buffer as ArrayBuffer);
    },
    recv: (): Promise<Uint8Array> =>
      inbox.queue.length > 0
        ? Promise.resolve(inbox.queue.shift()!)
        : new Promise((res) => inbox.waiters.push(res)),
  };
};

/**
 * Orchestrates the handshake on the persistent `main` channel (spec §5): verifies
 * the DTLS fingerprints (getStats vs SDP), runs the two-round core, then — ONLY
 * on success — seeds + persists the (wrapped) ratchet, sets epc.ratchetState /
 * epc.session, and opens the per-peer gate. Any failure (fingerprint mismatch,
 * CPace/X3DH error, key-confirmation mismatch, a bad/short frame, a transport or
 * persistence error) rejects the gate and re-throws, having persisted NOTHING —
 * the caller (Task 5) tears the channel down.
 */
export const runHandshake = async (
  epc: IRTCPeerConnection,
  mode: "pin" | "nopin",
  pin: Uint8Array | null,
  channelInput: Uint8Array,
  module: LibCrypto,
): Promise<void> => {
  try {
    await verifyDtlsFingerprints(epc);

    // Tie-break role on the STABLE Ed25519 identity edge (unchanged). The
    // handshake's DH/verify now uses the dedicated X25519 identity: unwrap its
    // secret + pub + cross-sig from IndexedDB, and pin the peer's Ed25519 pub as
    // the anchor the in-band peer X25519 pub must be cross-signed by (T5/T6).
    const { publicKey } = store.getState().keyPair;
    const amInitiator = publicKey < epc.withPeerPublicKey; // deterministic tie-break
    const identity = await getIdentityX25519();
    if (!identity) throw new Error("X25519 identity not provisioned");
    const idSelfSec = new Uint8Array(identity.secret);
    const selfIdentityX25519Pub = new Uint8Array(identity.pub);
    const selfIdentityCrossSignature = new Uint8Array(identity.crossSig);
    const peerIdentityEd25519Pub = hexToUint8Array(epc.withPeerPublicKey);

    const transport = transportForPeer(epc.withPeerId);
    const { state, secret } = await performHandshakeCore(
      transport,
      {
        mode,
        pin,
        channelInput,
        amInitiator,
        idSelfSec,
        selfIdentityX25519Pub,
        selfIdentityCrossSignature,
        peerIdentityEd25519Pub,
      },
      module,
    );

    // Persist keyed to the STABLE identity edge. roomId comes from the
    // registered main channel (falling back to the peer's first room).
    // Build the session from the PLAINTEXT serializeRatchet output: the worker's
    // fnSetRatchetSession wraps the secret fields exactly once. (Wrapping here
    // too would double-wrap them into an unreadable session — the T6 fix.)
    const inbox = inboxes.get(epc.withPeerId);
    const roomId =
      (inbox?.channel as IRTCDataChannel).roomIds?.[0] ??
      epc.rooms[0]?.roomId ??
      "";
    const s = serializeRatchet(state);
    const session: RatchetSession = {
      roomId,
      peerPublicKey: epc.withPeerPublicKey,
      peerId: epc.withPeerId,
      rootKey: s.rootKey,
      sendingChainKey: s.sendingChainKey,
      receivingChainKey: s.receivingChainKey,
      dhSelfPub: s.dhSelfPub,
      dhSelfSec: s.dhSelfSec,
      dhRemotePub: s.dhRemotePub,
      Ns: s.Ns,
      Nr: s.Nr,
      PN: s.PN,
      skippedMessageKeys: [],
      updatedAt: Date.now(),
    };
    await setRatchetSession(session);

    // The returned root secret is now folded into the (persisted) ratchet; wipe
    // the loose copy AND the unwrapped X25519 identity secret.
    secret.fill(0);
    idSelfSec.fill(0);

    epc.ratchetState = state;
    epc.session = session;
    openRatchetGate(epc.withPeerId);
  } catch (err) {
    rejectRatchetGate(epc.withPeerId, err);
    throw err;
  }
};
