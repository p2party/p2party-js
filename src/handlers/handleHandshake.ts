import { wipeRatchet } from "../cryptography/ratchet";
import { getIdentityX25519, recordAuthenticatedPeer } from "../db/api";
import { store } from "../store";
import {
  isCurrentRatchetGateLease,
  openRatchetGate,
  rejectRatchetGate,
} from "./ratchetGate";
import {
  assertCurrentRatchetGeneration,
  claimRatchetGeneration,
} from "./ratchetPersist";
import { SparsePqHealingState } from "./pqHealingRuntime";
import { HandshakeFailure } from "./handshakeFailure";
import { FRAME_TYPE_HANDSHAKE } from "../utils/constants";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { isIdentityInitiator } from "../utils/identityRole";
import { parseFingerprintFromSdp } from "../utils/sdpFingerprint";
import {
  isHandshakePayloadForStep,
  performHandshakeCore,
  type HandshakeStep,
  type HandshakeTransport,
  type PqHealingBootstrap,
} from "./handshakeCore";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { RatchetRootSuite } from "../utils/constants";
import type { RatchetState } from "../cryptography/ratchet";
import type { RatchetGateLease } from "./ratchetGate";
import type { RoomPqMode } from "../roomPolicy";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";

// The fingerprint parser lives in the store-free utils module so the signaling
// path can detect a remote certificate change without importing this file;
// it stays exported here for the handshake transcript and existing callers.
export { parseFingerprintFromSdp };

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

/** Session-scoped: whether this engine reports certificate stats cannot change
 * while the page is loaded, so the notice below is emitted at most once. */
let certificateStatsUnsupportedReported = false;

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
  let reportsCertificates = false;
  stats.forEach((report: RTCStatEntry) => {
    if (report.type === "transport") {
      localCertId = report.localCertificateId ?? localCertId;
      remoteCertId = report.remoteCertificateId ?? remoteCertId;
    }
    if (report.type === "certificate") reportsCertificates = true;
  });

  // Firefox implements neither the `transport` stat nor `certificate` rows, so
  // this check cannot run there at all. Treating that as a mismatch failed
  // every handshake and made the library unusable in Firefox, which is not a
  // security win: it is the difference between "this browser cannot answer"
  // and "this browser gave the wrong answer".
  //
  // What survives without it: both SDP fingerprints are already authenticated
  // inside the handshake transcript, so an attacker who rewrites SDP still
  // produces a transcript both peers reject. What is lost is the narrower
  // tripwire below — catching a DTLS transport that terminates on a different
  // certificate than the SDP advertised. Where the browser can answer, a
  // disagreement is still fatal.
  if (!reportsCertificates && localCertId === undefined) {
    // Whether an engine implements `certificate` stats is a property of the
    // engine, not of this peer or this handshake, so it is reported once per
    // session. Logging per handshake meant a busy room repeated the same
    // unactionable notice for every peer and every reconnect, which buries the
    // errors a user actually needs to see.
    if (!certificateStatsUnsupportedReported) {
      certificateStatsUnsupportedReported = true;
      console.warn(
        "p2party: this browser does not report WebRTC certificate statistics, " +
          "so the post-connect DTLS certificate check cannot run. The SDP " +
          "fingerprints remain bound into the authenticated handshake transcript.",
      );
    }
    return;
  }

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

// Per-peer handshake inbox: the main channel's onmessage routes
// FRAME_TYPE_HANDSHAKE payloads here (tag stripped); runHandshake's
// transport.recv() awaits them, buffering any that arrive before a recv.
interface Inbox {
  lease: HandshakeLease;
  pqMode: RoomPqMode;
  /** Only the initiator receives the responder's third FINISH flight. */
  expectFinish: boolean;
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void };
  queue: Uint8Array[];
  nextStep: HandshakeStep | null;
  waiters: Array<{
    resolve: (value: Uint8Array) => void;
    reject: (error: Error) => void;
  }>;
}

/** Opaque owner of one concrete main-channel handshake attempt. */
export interface HandshakeLease {
  readonly token: symbol;
}

const inboxes = new Map<string, Inbox>();
const HANDSHAKE_STEP_TIMEOUT_MS = 30_000;

const inboxKey = (roomId: string, peerId: string): string =>
  `${roomId}\u0000${peerId}`;

export const setHandshakeChannel = (
  roomId: string,
  peerId: string,
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void },
  pqMode: RoomPqMode = "hybrid-mlkem768",
  expectFinish = false,
): HandshakeLease => {
  const key = inboxKey(roomId, peerId);
  const previous = inboxes.get(key);
  if (previous) {
    const error = new Error("Handshake channel replaced");
    for (const waiter of previous.waiters) waiter.reject(error);
  }
  const lease: HandshakeLease = { token: Symbol("handshake-inbox") };
  inboxes.set(key, {
    lease,
    pqMode,
    expectFinish,
    channel,
    queue: [],
    nextStep: 1,
    waiters: [],
  });
  return lease;
};

export const clearHandshakeChannel = (
  roomId: string,
  peerId: string,
  reason = new Error("Handshake channel closed"),
  lease?: HandshakeLease,
): boolean => {
  const key = inboxKey(roomId, peerId);
  const inbox = inboxes.get(key);
  if (!inbox || (lease && inbox.lease !== lease)) return false;
  inboxes.delete(key);
  for (const waiter of inbox.waiters) waiter.reject(reason);
  return true;
};

export const deliverHandshakeFrame = (
  roomId: string,
  peerId: string,
  payload: Uint8Array,
  lease: HandshakeLease,
): boolean => {
  const inbox = inboxes.get(inboxKey(roomId, peerId));
  if (!inbox || inbox.lease !== lease) return false;
  if (
    inbox.nextStep === null ||
    !isHandshakePayloadForStep(payload, inbox.nextStep, inbox.pqMode)
  ) {
    clearHandshakeChannel(
      roomId,
      peerId,
      new HandshakeFailure(
        "Malformed, surplus, or out-of-order handshake frame",
        // A frame that does not match the expected step for this pq mode is a
        // policy/suite disagreement between two immutable room policies, not a
        // transport fault: it fails identically on every fresh transport.
        "policy",
      ),
      lease,
    );
    return false;
  }
  inbox.nextStep =
    inbox.nextStep === 1
      ? 2
      : inbox.nextStep === 2 && inbox.expectFinish
        ? 3
        : null;
  const next = inbox.waiters.shift();
  if (next) next.resolve(payload);
  else inbox.queue.push(payload);
  return true;
};

/**
 * The send/recv pair runHandshake drives the inbox with. Exported so the frame
 * bounds — including the framing rejection's typed failure, which is only ever
 * observable through a parked recv — can be exercised without a full handshake.
 */
export const transportForPeer = (
  roomId: string,
  peerId: string,
  lease: HandshakeLease,
): HandshakeTransport => {
  const key = inboxKey(roomId, peerId);
  const inbox = inboxes.get(key);
  if (!inbox || inbox.lease !== lease)
    throw new Error(`No owned handshake channel registered for ${peerId}`);
  const assertOwnership = (): void => {
    if (inboxes.get(key) !== inbox || inbox.lease !== lease)
      throw new Error("Handshake channel lease is stale");
  };
  return {
    send: (bytes: Uint8Array): void => {
      assertOwnership();
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
    recv: (): Promise<Uint8Array> => {
      try {
        assertOwnership();
      } catch (error) {
        return Promise.reject(error);
      }
      if (inbox.queue.length > 0) return Promise.resolve(inbox.queue.shift()!);
      return new Promise((resolve, reject) => {
        const waiter = {
          resolve: (value: Uint8Array): void => {
            clearTimeout(timer);
            resolve(value);
          },
          reject: (error: Error): void => {
            clearTimeout(timer);
            reject(error);
          },
        };
        const timer = setTimeout(() => {
          const index = inbox.waiters.indexOf(waiter);
          if (index > -1) inbox.waiters.splice(index, 1);
          reject(new Error("Handshake step timed out"));
        }, HANDSHAKE_STEP_TIMEOUT_MS);
        inbox.waiters.push(waiter);
      });
    },
  };
};

/**
 * Consume the handshake's PQ-healing bootstrap into a live store-free runtime.
 * The constructor copies the root/binding, so the caller-owned bootstrap
 * buffers are wiped on every exit — including a failed construction — leaving
 * the returned runtime as the only holder of the derived PQ root.
 */
export const createHandshakePqRuntime = (
  module: LibCrypto,
  pqMode: RoomPqMode,
  rootSuite: RatchetRootSuite,
  amInitiator: boolean,
  bootstrap: PqHealingBootstrap,
): SparsePqHealingState => {
  try {
    return new SparsePqHealingState({
      module,
      pqMode,
      rootSuite,
      binding: bootstrap.binding,
      rootKey: bootstrap.rootKey,
      nextOfferer: bootstrap.nextOfferer,
      amInitiator,
    });
  } finally {
    bootstrap.rootKey.fill(0);
    bootstrap.binding.fill(0);
  }
};

export interface EdgeCryptoCandidate {
  readonly state: RatchetState;
  readonly pqRuntime: SparsePqHealingState;
}

/** Install both freshly authenticated ratchets in RAM under the current gate lease. */
export const activateEdgeCrypto = (
  epc: IRTCPeerConnection,
  roomId: string,
  candidate: EdgeCryptoCandidate,
  beforeInstall: () => void,
): void => {
  assertCurrentRatchetGeneration(epc, roomId);
  // Resolving the gate queues its waiters. Install both handles synchronously
  // before any waiting channel can resume.
  beforeInstall();
  if (epc.ratchetState) wipeRatchet(epc.ratchetState);
  epc.pqHealingState?.destroy();
  epc.ratchetState = candidate.state;
  epc.pqHealingState = candidate.pqRuntime;
  epc.messageKeyCache = candidate.pqRuntime.activeReceiveKeys;
};

/**
 * Orchestrates the handshake on the persistent `main` channel (spec §5): verifies
 * the DTLS fingerprints (getStats vs SDP), runs the triple-confirmation core,
 * then installs both ratchets on the authenticated connection and opens its gate.
 * A rejected handshake discards both candidates.
 */
export const runHandshake = async (
  epc: IRTCPeerConnection,
  roomId: string,
  mode: "pin" | "nopin",
  pqMode: RoomPqMode,
  pin: Uint8Array | null,
  channelInput: Uint8Array,
  module: LibCrypto,
  handshakeLease: HandshakeLease,
  gateLease: RatchetGateLease,
): Promise<void> => {
  // Hoisted so the finally wipes them on EVERY exit (success or throw), not just
  // the success path — idSelfSec is the long-term X25519 identity secret.
  let idSelfSec: Uint8Array | null = null;
  let secret: Uint8Array | null = null;
  let state: RatchetState | null = null;
  let pqRuntime: SparsePqHealingState | null = null;
  try {
    await verifyDtlsFingerprints(epc);

    // Tie-break role on the STABLE Ed25519 identity edge (unchanged). The
    // handshake's DH/verify now uses the dedicated X25519 identity: unwrap its
    // secret + pub + cross-sig from IndexedDB, and pin the peer's Ed25519 pub as
    // the anchor the in-band peer X25519 pub must be cross-signed by.
    const { publicKey } = store.getState().keyPair;
    const amInitiator = isIdentityInitiator(publicKey, epc.withPeerPublicKey);
    const identity = await getIdentityX25519();
    if (!identity) throw new Error("X25519 identity not provisioned");
    idSelfSec = new Uint8Array(identity.secret);
    const selfIdentityX25519Pub = new Uint8Array(identity.pub);
    const selfIdentityCrossSignature = new Uint8Array(identity.crossSig);
    const peerIdentityEd25519Pub = hexToUint8Array(epc.withPeerPublicKey);

    const transport = transportForPeer(roomId, epc.withPeerId, handshakeLease);
    const result = await performHandshakeCore(
      transport,
      {
        mode,
        pqMode,
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
    state = result.state;
    secret = result.secret;
    // Consume the PQ bootstrap immediately: after this line the runtime is the
    // only holder of the healing root, and the outer finally owns its fate.
    pqRuntime = createHandshakePqRuntime(
      module,
      pqMode,
      state.rootSuite,
      amInitiator,
      result.pqHealing,
    );

    // performHandshakeCore verified the remote cross-signature under this
    // Ed25519 key. Consult the durable policy before persisting or opening
    // any edge for it, including when the block changed during the handshake.
    const membership = await recordAuthenticatedPeer(
      epc.withPeerId,
      epc.withPeerPublicKey,
    );
    const room = store.getState().rooms.find((entry) => entry.id === roomId);
    if (
      !room ||
      membership.blocked ||
      (room.onlyConnectWithKnownAddresses && !membership.known)
    )
      throw new HandshakeFailure(
        "Authenticated identity is refused by this room",
        "policy",
      );

    if (!isCurrentRatchetGateLease(roomId, epc.withPeerId, gateLease))
      throw new Error("Handshake transport lease is stale");

    // Invalidate queued mutations from any replaced PC before writing this new
    // handshake seed. The stable-edge persistence lock makes this seed land
    // after any old write already in flight.
    claimRatchetGeneration(epc, roomId);
    activateEdgeCrypto(epc, roomId, { state, pqRuntime }, () => {
      if (!isCurrentRatchetGateLease(roomId, epc.withPeerId, gateLease))
        throw new Error(
          "Handshake transport lease was replaced during persistence",
        );
      if (!openRatchetGate(roomId, epc.withPeerId, gateLease))
        throw new Error("Handshake transport gate is already settled");
    });
    // Ownership of both candidates transferred to the live connection.
    state = null;
    pqRuntime = null;
  } catch (err) {
    rejectRatchetGate(roomId, epc.withPeerId, err, gateLease);
    throw err;
  } finally {
    // Wipe the loose root-secret copy and unwrapped long-term X25519 identity
    // secret on every exit; destroy an untransferred PQ runtime with them.
    secret?.fill(0);
    idSelfSec?.fill(0);
    if (state) wipeRatchet(state);
    pqRuntime?.destroy();
    clearHandshakeChannel(
      roomId,
      epc.withPeerId,
      new Error("Handshake attempt finished"),
      handshakeLease,
    );
  }
};
