// Store-free protocol-v3 handshake primitives for standalone and WebRTC callers.
import {
  deriveGenerator,
  cpaceStart,
  cpaceShared,
} from "../cryptography/cpace";
import { x3dhDeriveSecret } from "../cryptography/x3dh";
import { x25519Keypair } from "../cryptography/x25519";
import { initRatchet } from "../cryptography/ratchet";
import { verifyIdentityCrossSig } from "../cryptography/identityCrossSig";
import { zeroFree } from "../utils/zeroFree";
import { PQ_TAG } from "../utils/constants";
import { concatUint8Arrays, uint8ArraysAreEqual } from "../utils/uint8array";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { RatchetState } from "../cryptography/ratchet";

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
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
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
      if (
        peerConfirm.length !== CONFIRM_LEN ||
        peerConfirm[0] !== HS_STEP_CONFIRM
      )
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
      if (
        peerConfirm.length !== CONFIRM_LEN ||
        peerConfirm[0] !== HS_STEP_CONFIRM
      )
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
