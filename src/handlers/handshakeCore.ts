// Store-free protocol-v3 handshake primitives for standalone and WebRTC callers.
import {
  deriveGenerator,
  cpaceStart,
  cpaceFinish,
} from "../cryptography/cpace";
import { deriveInteractive3dhSecret } from "../cryptography/x3dh";
import { x25519Keypair } from "../cryptography/x25519";
import {
  initRatchet,
  primeResponderRatchet,
  wipeRatchet,
} from "../cryptography/ratchet";
import { verifyIdentityCrossSig } from "../cryptography/identityCrossSig";
import { hkdfExpand, hkdfExtract } from "../cryptography/hkdf";
import {
  createMlKem768Backend,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  type MlKem768Decapsulation,
  type MlKem768Encapsulation,
  type MlKem768KeyPair,
} from "../cryptography/mlkem";
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
const HS_KC_DOMAIN = new TextEncoder().encode(
  "p2party-v3-hs-kc-transcript-v3",
);
// The two confirmation flights intentionally authenticate different fixed
// inputs. The responder must send before it can know the initiator's ratchet
// public key, while the initiator's confirmation binds both initial ratchet
// keys. Explicit role/domain labels prevent reflection despite that asymmetry.
const HS_KC_RESPONDER_DOMAIN = new TextEncoder().encode(
  "p2party-v3-hs-kc-responder-v3",
);
const HS_KC_INITIATOR_DOMAIN = new TextEncoder().encode(
  "p2party-v3-hs-kc-initiator-ratchet-dh-v3",
);
// Both authentication modes prove possession of the cross-signed X25519
// identity through interactive triple-DH. PIN mode ADDS CPace; it must never
// substitute CPace for identity possession, because a static X25519 pub +
// Ed25519 cross-signature is a replayable certificate. Distinct v3 suite
// domains make the two fixed-order combiners unambiguous:
//   no-PIN: 3DH || ML-KEM
//   PIN:    CPace-ISK || 3DH || ML-KEM
const HS_HYBRID_KDF_NOPIN_DOMAIN = new TextEncoder().encode(
  "p2party-v3-hybrid-root-3dh-ml-kem-768-v3",
);
const HS_HYBRID_KDF_PIN_DOMAIN = new TextEncoder().encode(
  "p2party-v3-hybrid-root-cpace21-3dh-ml-kem-768-v3",
);
const HS_HYBRID_KDF_SALT = new Uint8Array(64);
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

const HELLO_SID_OFF = 1;
const HELLO_EK_OFF = HELLO_SID_OFF + SID_LEN;
const HELLO_Y_OFF = HELLO_EK_OFF + EK_LEN;
const HELLO_X25519_ID_PUB_OFF = HELLO_Y_OFF + Y_LEN;
const HELLO_IDENTITY_SIG_OFF = HELLO_X25519_ID_PUB_OFF + X25519_ID_PUB_LEN;
const HELLO_ML_KEM_PUBLIC_KEY_OFF = HELLO_IDENTITY_SIG_OFF + IDENTITY_SIG_LEN;
const HELLO_ML_KEM_CIPHERTEXT_OFF =
  HELLO_ML_KEM_PUBLIC_KEY_OFF + ML_KEM_768_PUBLIC_KEY_BYTES;
const HELLO_LEN = HELLO_ML_KEM_CIPHERTEXT_OFF + ML_KEM_768_CIPHERTEXT_BYTES;
const CONFIRM_LEN = 1 + DH_LEN + MAC_LEN;

export type HandshakeStep = 1 | 2;

/**
 * Fail-closed pre-auth framing check used before a payload enters the handshake
 * inbox. This keeps attacker-controlled frames bounded before the crypto core
 * consumes them; the core repeats the same checks when parsing.
 */
export const isHandshakePayloadForStep = (
  payload: Uint8Array,
  step: HandshakeStep,
): boolean =>
  step === HS_STEP_HELLO
    ? payload.length === HELLO_LEN && payload[0] === HS_STEP_HELLO
    : payload.length === CONFIRM_LEN && payload[0] === HS_STEP_CONFIRM;

export interface HandshakeTransport {
  send(bytes: Uint8Array): void | Promise<void>;
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

// HELLO   = [HS_STEP_HELLO ‖ sid(32) ‖ EK(32) ‖ Y(32) ‖
//            X25519_id_pub(32) ‖ crossSig(64) ‖
//            mlKemPublicKey(1184) ‖ mlKemCiphertext(1088)]
// Initiator: public key is fresh and ciphertext is all zero.
// Responder: public key is all zero and ciphertext encapsulates to the
// initiator's key. The unused fixed-width field MUST be canonical all-zero.
// CONFIRM = [HS_STEP_CONFIRM ‖ dhPub(32) ‖ mac(64)]
// Both roles publish their actual initial ratchet DH public key.
// Both fixed size, one FRAME_TYPE_HANDSHAKE frame each.
const packHello = (
  sid: Uint8Array,
  ek: Uint8Array,
  y: Uint8Array,
  x25519Pub: Uint8Array,
  crossSig: Uint8Array,
  mlKemPublicKey: Uint8Array,
  mlKemCiphertext: Uint8Array,
): Uint8Array => {
  const out = new Uint8Array(HELLO_LEN);
  out[0] = HS_STEP_HELLO;
  out.set(sid, HELLO_SID_OFF);
  out.set(ek, HELLO_EK_OFF);
  out.set(y, HELLO_Y_OFF);
  out.set(x25519Pub, HELLO_X25519_ID_PUB_OFF);
  out.set(crossSig, HELLO_IDENTITY_SIG_OFF);
  out.set(mlKemPublicKey, HELLO_ML_KEM_PUBLIC_KEY_OFF);
  out.set(mlKemCiphertext, HELLO_ML_KEM_CIPHERTEXT_OFF);
  return out;
};

const allZero = (bytes: Uint8Array): boolean => {
  let aggregate = 0;
  for (const byte of bytes) aggregate |= byte;
  return aggregate === 0;
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
 *   R1  initiator sends HELLO {sid, EK, Y, ML-KEM pk}; responder encapsulates,
 *       replies with HELLO {sid, EK, Y, ML-KEM ct}; both derive the 32-byte
 *       hybrid root from interactive-3DH || ML-KEM (no-PIN) or
 *       CPace-ISK || interactive-3DH || ML-KEM (PIN).
 *   R2  responder initRatchet(false,null) → dhPubR and sends
 *       CONFIRM{dhPubR, mac_R}; initiator seeds against dhPubR and sends
 *       CONFIRM{dhPubI, mac_I}. After verifying mac_I, responder performs the
 *       receive-side DH step without consuming a message key, opening both its
 *       receiving and sending chains before return.
 *
 * ML-KEM-768 is mandatory: this function constructs its backend itself and
 * fails before sending if the WASM exports are missing. There is deliberately
 * no classical fallback or negotiation bit. Both MACs cover the full ordered
 * HELLO transcript and dhPubR under distinct role domains; mac_I additionally
 * covers dhPubI. A swapped cert/key, altered KEM field, ratchet-key tamper, or
 * wrong PIN makes key confirmation fail (or is rejected as malformed).
 * Persistence + gate-open happen ONLY in runHandshake, after this resolves, so
 * a throw here leaves nothing persisted.
 *
 * NOTE on the R2 ordering: the initiator publishes its mac_I BEFORE verifying
 * mac_R. The provisional initiator ratchet is needed to publish dhPubI and is
 * wiped if mac_R fails. Sending first guarantees the responder's recv() is
 * always satisfied — otherwise a wrong-PIN initiator would abort before sending
 * and deadlock the responder's recv().
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

  // Mandatory suite construction is deliberately first. A module built without
  // ML-KEM cannot enter or emit any v3 handshake traffic.
  const mlKem = createMlKem768Backend(module);

  // R1: build our HELLO. Ephemeral X25519 EK is always generated and always
    // enters interactive 3DH, including PIN rooms: CPace proves PIN knowledge
    // while 3DH independently proves possession of the presented cross-signed
    // identity.
  const sidSelf = crypto.getRandomValues(new Uint8Array(SID_LEN));
  const ek = x25519Keypair(module);
  let cpaceY: Uint8Array = new Uint8Array(Y_LEN); // zeros in no-PIN
  let cpaceScalar: Uint8Array | null = null; // our secret CPace scalar y
  const mlKemPublicKeySelf = new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES);
  const mlKemCiphertextSelf = new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES);
  let mlKemKeyPair: MlKem768KeyPair | null = null;
  let mlKemShared: MlKem768Encapsulation | MlKem768Decapsulation | null = null;
  let identitySecret: Uint8Array | undefined;
  let pakeSecret: Uint8Array | undefined;
  let hybridIkm: Uint8Array | undefined;
  let hybridPrk: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  // Owned here until the success return transfers it to the caller. In
  // particular, the responder must create its DH ratchet before it can publish
  // dhPubR, so a bad/missing initiator confirmation must explicitly erase that
  // provisional state rather than leave its root/DH secrets to garbage
  // collection.
  let ratchetState: RatchetState | null = null;

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
      mlKemPublicKeySelf,
      mlKemCiphertextSelf,
    );

  try {
    // R1 — initiator-first exchange (D1). The initiator knows its own sid
    // upfront, so it derives G, starts CPace, and sends HELLO before receiving.
    // The responder must receive the initiator's HELLO FIRST to learn the
    // initiator's sid, then derive its matching G and reply.
    let peerHello: Uint8Array;
    if (amInitiator) {
      mlKemKeyPair = await mlKem.generateKeyPair();
      mlKemPublicKeySelf.set(mlKemKeyPair.publicKey);

      // generator binds MY sid (I am the initiator)
      const started = startCpace(sidSelf);
      if (started) {
        cpaceScalar = started.y;
        cpaceY = started.Y;
      }
      await transport.send(buildHello());
      peerHello = await transport.recv();
    } else {
      peerHello = await transport.recv();
    }

    // Parse peer HELLO. Fail closed on any malformed/short/mis-tagged frame.
    if (peerHello.length !== HELLO_LEN || peerHello[0] !== HS_STEP_HELLO)
      throw new Error("Malformed handshake HELLO");
    const sidPeer = peerHello.subarray(HELLO_SID_OFF, HELLO_SID_OFF + SID_LEN);
    const ekPeer = peerHello.subarray(HELLO_EK_OFF, HELLO_EK_OFF + EK_LEN);
    const yPeer = peerHello.subarray(HELLO_Y_OFF, HELLO_Y_OFF + Y_LEN);
    const peerX25519Pub = peerHello.subarray(
      HELLO_X25519_ID_PUB_OFF,
      HELLO_X25519_ID_PUB_OFF + X25519_ID_PUB_LEN,
    );
    const peerCrossSig = peerHello.subarray(
      HELLO_IDENTITY_SIG_OFF,
      HELLO_IDENTITY_SIG_OFF + IDENTITY_SIG_LEN,
    );
    const mlKemPublicKeyPeer = peerHello.subarray(
      HELLO_ML_KEM_PUBLIC_KEY_OFF,
      HELLO_ML_KEM_PUBLIC_KEY_OFF + ML_KEM_768_PUBLIC_KEY_BYTES,
    );
    const mlKemCiphertextPeer = peerHello.subarray(
      HELLO_ML_KEM_CIPHERTEXT_OFF,
      HELLO_ML_KEM_CIPHERTEXT_OFF + ML_KEM_768_CIPHERTEXT_BYTES,
    );

    // Canonical fixed fields make the role and mandatory suite unambiguous.
    // Reject before identity verification/KEM work; never interpret an absent
    // used field as a request to fall back to the classical secret.
    if (amInitiator) {
      if (!allZero(mlKemPublicKeyPeer))
        throw new Error(
          "Malformed handshake HELLO: responder ML-KEM public-key field must be zero",
        );
      if (allZero(mlKemCiphertextPeer))
        throw new Error(
          "Malformed handshake HELLO: responder ML-KEM ciphertext is required",
        );
    } else {
      if (allZero(mlKemPublicKeyPeer))
        throw new Error(
          "Malformed handshake HELLO: initiator ML-KEM public key is required",
        );
      if (!allZero(mlKemCiphertextPeer))
        throw new Error(
          "Malformed handshake HELLO: initiator ML-KEM ciphertext field must be zero",
        );
    }

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

    // Responder encapsulates directly to the initiator's key; it never creates
    // an unnecessary KEM keypair/private key. Initiator decapsulates only after
    // the responder's X25519 identity cross-signature verifies.
    if (!amInitiator) {
      const encapsulation = await mlKem.encapsulate(mlKemPublicKeyPeer);
      mlKemShared = encapsulation;
      mlKemCiphertextSelf.set(encapsulation.ciphertext);

      // generator binds the INITIATOR's (peer's) sid
      const started = startCpace(sidPeer);
      if (started) {
        cpaceScalar = started.y;
        cpaceY = started.Y;
      }
      await transport.send(buildHello());
    } else {
      if (!mlKemKeyPair)
        throw new Error("Handshake ML-KEM initiator keypair is unavailable");
      const decapsulation = await mlKem.decapsulate(
        mlKemCiphertextPeer,
        mlKemKeyPair.secretKey,
      );
      mlKemShared = decapsulation;
      // The decapsulation is complete; minimize the lifetime of the 2400-byte
      // KEM private key. destroy() is idempotent and also runs in finally.
      mlKemKeyPair.destroy();
    }

    // Identity possession is mandatory in BOTH modes. Merely verifying the
    // static cross-signature is insufficient: an attacker could replay a
    // victim's public X25519 credential without owning its secret. Interactive
    // 3DH makes the root depend on both presented identity secrets and both
    // fresh ephemeral secrets.
    identitySecret = deriveInteractive3dhSecret(
      idSelfSec,
      peerX25519Pub,
      ek.secretKey,
      ekPeer,
      amInitiator,
      module,
    );

    // Ordered fields (I = initiator, R = responder). Both legs build the
    // byte-identical values regardless of which side computed each field. All
    // four fixed PQ fields, including canonical zero fields, enter key
    // confirmation so their exact bytes cannot be rewritten in transit.
    const sidI = amInitiator ? sidSelf : sidPeer;
    const sidR = amInitiator ? sidPeer : sidSelf;
    const ekI = amInitiator ? ek.publicKey : ekPeer;
    const ekR = amInitiator ? ekPeer : ek.publicKey;
    const yI = amInitiator ? cpaceY : yPeer;
    const yR = amInitiator ? yPeer : cpaceY;
    const x25519IdentityPubI = amInitiator
      ? selfIdentityX25519Pub
      : peerX25519Pub;
    const x25519IdentityCrossSigI = amInitiator
      ? selfIdentityCrossSignature
      : peerCrossSig;
    const x25519IdentityPubR = amInitiator
      ? peerX25519Pub
      : selfIdentityX25519Pub;
    const x25519IdentityCrossSigR = amInitiator
      ? peerCrossSig
      : selfIdentityCrossSignature;
    const mlKemPublicKeyI = amInitiator
      ? mlKemPublicKeySelf
      : mlKemPublicKeyPeer;
    const mlKemCiphertextI = amInitiator
      ? mlKemCiphertextSelf
      : mlKemCiphertextPeer;
    const mlKemPublicKeyR = amInitiator
      ? mlKemPublicKeyPeer
      : mlKemPublicKeySelf;
    const mlKemCiphertextR = amInitiator
      ? mlKemCiphertextPeer
      : mlKemCiphertextSelf;

    // PIN mode additionally proves room-secret knowledge with draft-21 CPace.
    // CI already binds identities/roles, so ADa/ADb are empty. Only CPace's
    // transcript-bound ISK leaves cpaceFinish; its raw shared point K never
    // enters JavaScript or the hybrid combiner.
    if (mode === "pin") {
      if (!cpaceScalar)
        throw new Error("Handshake CPace scalar is unavailable");
      pakeSecret = cpaceFinish(
        {
          y: cpaceScalar,
          peerShare: yPeer,
          sid: sidI,
          initiatorShare: yI,
          responderShare: yR,
        },
        module,
      );
    }

    // Fixed-order, transcript-bound application-handshake combiner. PIN mode
    // adds (rather than replaces) CPace-ISK || 3DH || ML-KEM; no-PIN remains
    // 3DH || ML-KEM. This is deliberately NOT labelled X-Wing: X-Wing is a
    // specific CFRG-draft KEM combiner, while this interactive handshake also
    // binds identity possession, CPace policy, DTLS, and key confirmation.
    // Separate mode/version domains prevent the variable-length IKM layouts
    // from ever being interpreted as one another.
    const hybridDomain =
      mode === "pin"
        ? HS_HYBRID_KDF_PIN_DOMAIN
        : HS_HYBRID_KDF_NOPIN_DOMAIN;
    hybridIkm = await concatUint8Arrays(
      mode === "pin"
        ? [pakeSecret!, identitySecret, mlKemShared.sharedSecret]
        : [identitySecret, mlKemShared.sharedSecret],
    );
    hybridPrk = hkdfExtract(HS_HYBRID_KDF_SALT, hybridIkm, module);
    const hybridInfo = await concatUint8Arrays([
      hybridDomain,
      channelInput,
      x25519IdentityPubI,
      x25519IdentityCrossSigI,
      x25519IdentityPubR,
      x25519IdentityCrossSigR,
      mlKemPublicKeyI,
      mlKemCiphertextR,
    ]);
    secret = hkdfExpand(hybridPrk, hybridInfo, 32, module);

    // Wipe the component secrets immediately after the hybrid root exists.
    identitySecret.fill(0);
    pakeSecret?.fill(0);
    hybridIkm.fill(0);
    hybridPrk.fill(0);
    mlKemShared.destroy();

    const buildConfirmationInput = (
      roleDomain: Uint8Array,
      dhPubR: Uint8Array,
      dhPubI?: Uint8Array,
    ): Promise<Uint8Array> =>
      concatUint8Arrays([
        HS_KC_DOMAIN,
        roleDomain,
        sidI,
        sidR,
        ekI,
        ekR,
        yI,
        yR,
        x25519IdentityPubI,
        x25519IdentityCrossSigI,
        x25519IdentityPubR,
        x25519IdentityCrossSigR,
        mlKemPublicKeyI,
        mlKemCiphertextI,
        mlKemPublicKeyR,
        mlKemCiphertextR,
        dhPubR,
        ...(dhPubI ? [dhPubI] : []),
        channelInput,
      ]);

    // R2 — DH-ratchet exchange + bidirectional key confirmation.
    if (!amInitiator) {
      // Responder: seed the ratchet, publish its DH pub, MAC the transcript.
      ratchetState = initRatchet(secret, false, null, module);
      const dhPubR = ratchetState.dhSelfPub;
      const confirmationInputR = await buildConfirmationInput(
        HS_KC_RESPONDER_DOMAIN,
        dhPubR,
      );
      const macR = hmacSha512(secret, confirmationInputR, module);
      await transport.send(packConfirm(dhPubR, macR));
      macR.fill(0);

      const peerConfirm = await transport.recv();
      if (
        peerConfirm.length !== CONFIRM_LEN ||
        peerConfirm[0] !== HS_STEP_CONFIRM
      )
        throw new Error("Malformed handshake CONFIRM");
      const dhPubI = Uint8Array.from(peerConfirm.subarray(1, 1 + DH_LEN));
      const macI = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
      const confirmationInputI = await buildConfirmationInput(
        HS_KC_INITIATOR_DOMAIN,
        dhPubR,
        dhPubI,
      );
      const expectI = hmacSha512(secret, confirmationInputI, module);
      const initiatorConfirmed = await uint8ArraysAreEqual(macI, expectI);
      expectI.fill(0);
      if (!initiatorConfirmed)
        throw new Error("Handshake key-confirmation failed");
      primeResponderRatchet(ratchetState, dhPubI, module);
    } else {
      // Initiator: wait for dhPubR, provisionally seed so its actual dhPubI can
      // be authenticated in mac_I, send it, then verify mac_R. A failure wipes
      // the provisional ratchet in the outer finally.
      const peerConfirm = await transport.recv();
      if (
        peerConfirm.length !== CONFIRM_LEN ||
        peerConfirm[0] !== HS_STEP_CONFIRM
      )
        throw new Error("Malformed handshake CONFIRM");
      const dhPubR = Uint8Array.from(peerConfirm.subarray(1, 1 + DH_LEN));
      const macR = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
      ratchetState = initRatchet(secret, true, dhPubR, module);
      const dhPubI = ratchetState.dhSelfPub;
      const confirmationInputI = await buildConfirmationInput(
        HS_KC_INITIATOR_DOMAIN,
        dhPubR,
        dhPubI,
      );
      const macI = hmacSha512(secret, confirmationInputI, module);
      await transport.send(packConfirm(dhPubI, macI));
      macI.fill(0);
      const confirmationInputR = await buildConfirmationInput(
        HS_KC_RESPONDER_DOMAIN,
        dhPubR,
      );
      const expectR = hmacSha512(secret, confirmationInputR, module);
      const responderConfirmed = await uint8ArraysAreEqual(macR, expectR);
      expectR.fill(0);
      if (!responderConfirmed)
        throw new Error("Handshake key-confirmation failed");
    }

    if (!ratchetState)
      throw new Error("Handshake ratchet initialization failed");
    const establishedState = ratchetState;
    ratchetState = null; // ownership transfers to the successful caller
    return { state: establishedState, secret };
  } catch (err) {
    // Fail closed: wipe the root secret on any failure so nothing usable lingers.
    secret?.fill(0);
    throw err;
  } finally {
    // Ephemeral/component secrets are never needed past derivation; wipe on
    // every exit (success or throw). The returned hybrid root `secret` is
    // intentionally left intact on success for the caller, which wipes it after
    // persistence/session construction.
    ek.secretKey.fill(0);
    cpaceScalar?.fill(0);
    identitySecret?.fill(0);
    pakeSecret?.fill(0);
    hybridIkm?.fill(0);
    hybridPrk?.fill(0);
    mlKemShared?.destroy();
    mlKemKeyPair?.destroy();
    if (ratchetState) wipeRatchet(ratchetState);
  }
};
