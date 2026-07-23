import { serializeRatchet } from "../cryptography/ratchet";
import { setRatchetSession, getIdentityX25519 } from "../db/api";
import { store } from "../store";
import { openRatchetGate, rejectRatchetGate } from "./ratchetGate";
import { FRAME_TYPE_HANDSHAKE } from "../utils/constants";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { performHandshakeCore, type HandshakeTransport } from "./handshakeCore";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { RatchetSession } from "../db/types";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";

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

// Per-peer handshake inbox: the main channel's onmessage routes
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
 * the caller tears the channel down.
 */
export const runHandshake = async (
  epc: IRTCPeerConnection,
  mode: "pin" | "nopin",
  pin: Uint8Array | null,
  channelInput: Uint8Array,
  module: LibCrypto,
): Promise<void> => {
  // Hoisted so the finally wipes them on EVERY exit (success or throw), not just
  // the success path — idSelfSec is the long-term X25519 identity secret.
  let idSelfSec: Uint8Array | null = null;
  let secret: Uint8Array | null = null;
  try {
    await verifyDtlsFingerprints(epc);

    // Tie-break role on the STABLE Ed25519 identity edge (unchanged). The
    // handshake's DH/verify now uses the dedicated X25519 identity: unwrap its
    // secret + pub + cross-sig from IndexedDB, and pin the peer's Ed25519 pub as
    // the anchor the in-band peer X25519 pub must be cross-signed by.
    const { publicKey } = store.getState().keyPair;
    const amInitiator = publicKey < epc.withPeerPublicKey;
    const identity = await getIdentityX25519();
    if (!identity) throw new Error("X25519 identity not provisioned");
    idSelfSec = new Uint8Array(identity.secret);
    const selfIdentityX25519Pub = new Uint8Array(identity.pub);
    const selfIdentityCrossSignature = new Uint8Array(identity.crossSig);
    const peerIdentityEd25519Pub = hexToUint8Array(epc.withPeerPublicKey);

    const transport = transportForPeer(epc.withPeerId);
    const { state, secret: coreSecret } = await performHandshakeCore(
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
    secret = coreSecret;

    // Build the session from the PLAINTEXT serializeRatchet output: the worker's
    // fnSetRatchetSession wraps the secret fields exactly once.
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

    epc.ratchetState = state;
    epc.session = session;
    openRatchetGate(epc.withPeerId);
  } catch (err) {
    rejectRatchetGate(epc.withPeerId, err);
    throw err;
  } finally {
    // Wipe the loose root-secret copy and unwrapped long-term X25519 identity
    // secret on every exit.
    secret?.fill(0);
    idSelfSec?.fill(0);
  }
};
