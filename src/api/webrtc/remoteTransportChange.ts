import { wipeRatchet } from "../../cryptography/ratchet";
import { clearHandshakeChannel } from "../../handlers/handleHandshake";
import { destroyPqHealingOrchestrator } from "../../handlers/pqHealingOrchestrator";
import { releaseScheduledReceipts } from "../../handlers/coverTransfer";
import { teardownCoverEdge } from "../../handlers/coverEdge";
import { isRatchetGateOpen, resetRatchetGate } from "../../handlers/ratchetGate";
import { setPeerHandshakeStatus } from "../../reducers/roomSlice";
import { parseFingerprintFromSdp } from "../../utils/sdpFingerprint";
import { debugLog } from "../../utils/debug";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCPeerConnection } from "./interfaces";

/**
 * True iff both SDPs declare a sha-256 DTLS fingerprint and the two differ.
 *
 * A remote description whose fingerprint differs from the one already applied
 * on this RTCPeerConnection means the peer built a NEW RTCPeerConnection (a
 * fresh DTLS certificate is minted per PC) while this side kept its old one.
 * The browser accepts the change and re-runs DTLS on the same PC, but every
 * piece of edge authentication this side holds — handshake transcript (which
 * binds both fingerprints), ratchet, PQ runtime, message keys — was proven
 * against the OLD certificate and must not survive onto the new transport.
 *
 * Missing or malformed fingerprints on either side are not a change: there is
 * nothing to compare, and the handshake itself rejects such SDPs later.
 */
export const detectRemoteTransportChange = (
  previousSdp: string | undefined,
  nextSdp: string,
): boolean => {
  if (previousSdp === undefined) return false;
  let previous: Uint8Array;
  let next: Uint8Array;
  try {
    previous = parseFingerprintFromSdp(previousSdp);
    next = parseFingerprintFromSdp(nextSdp);
  } catch {
    return false;
  }
  if (previous.length !== next.length) return true;
  for (let i = 0; i < previous.length; i++)
    if (previous[i] !== next[i]) return true;
  return false;
};

/**
 * True iff this room/peer edge has been authenticated on THIS
 * RTCPeerConnection: a live ratchet, a ratchet gate opened under this
 * transport's own lease, or an open `main` (a handshake in flight over a live
 * SCTP association). A transport that only ever negotiated (main still
 * connecting, gate pending) has proven nothing yet.
 */
export const isEdgeAuthenticatedOnTransport = (
  epc: Pick<
    IRTCPeerConnection,
    "ratchetState" | "ratchetGateLease" | "mainChannel"
  >,
  roomId: string,
  peerId: string,
): boolean =>
  epc.ratchetState !== undefined ||
  isRatchetGateOpen(roomId, peerId, epc.ratchetGateLease) ||
  epc.mainChannel?.readyState === "open";

export type RemoteTransportChangeResponse = "reset-in-place" | "replace";

export interface RemoteTransportChangeDecisionParams {
  epc: Pick<
    IRTCPeerConnection,
    "ratchetState" | "ratchetGateLease" | "mainChannel"
  >;
  roomId: string;
  peerId: string;
  descriptionType: RTCSdpType;
  /** Whether this side is the identity initiator (the side that opens main). */
  isInitiator: boolean;
}

/**
 * What to do with an existing RTCPeerConnection whose remote DTLS fingerprint
 * is about to change.
 *
 * A never-authenticated transport is simply re-bound in place: nothing proven
 * against the old certificate exists, and the browser renegotiates DTLS on
 * the same PC (the T1 path, `resetEdgeAuthenticationForNewRemoteTransport`).
 *
 * An AUTHENTICATED transport whose peer shows up with a new certificate is
 * the stale side of the edge: its SCTP association is dead on the far side
 * while it is still writable locally. Whether it can be re-bound in place
 * depends on who has to open the next `main` on it:
 *
 * - The peer's fresh transport OFFERS: it carries the peer's channels, so a
 *   fresh PC of our own answers it cleanly whatever our role. Replace.
 * - We are the identity initiator and receive an ANSWER: re-binding in place
 *   would make us create the replacement `main` on the OLD, still-writable
 *   SCTP association, whose onopen fires before DTLS re-runs against the new
 *   certificate; the handshake then reads the old remote certificate from
 *   getStats and fails as a fingerprint mismatch. Replace the PC and re-dial.
 * - We are the responder and receive an ANSWER: we open no channel on the
 *   reset PC. The peer's fresh transport (the initiator) already holds the
 *   next `main`, which opens only once the browser has re-run DTLS and SCTP
 *   against the new certificate, so the in-place re-bind completes with a
 *   clean handshake. Replacing here would instead leave the peer's fresh PC
 *   bound to our closed one with nothing to re-offer to our channel-less
 *   replacement (a never-connected transport does not re-dial on failure).
 */
export const decideRemoteTransportChangeResponse = ({
  epc,
  roomId,
  peerId,
  descriptionType,
  isInitiator,
}: RemoteTransportChangeDecisionParams): RemoteTransportChangeResponse => {
  if (!isEdgeAuthenticatedOnTransport(epc, roomId, peerId))
    return "reset-in-place";
  if (descriptionType === "offer") return "replace";
  return isInitiator ? "replace" : "reset-in-place";
};

export interface ResetEdgeAuthenticationParams {
  epc: IRTCPeerConnection;
  roomId: string;
  peerId: string;
  api: Pick<BaseQueryApi, "dispatch">;
  reason: Error;
}

/**
 * Drop everything that authenticated this room/peer edge against the previous
 * remote DTLS certificate, WITHOUT tearing the RTCPeerConnection down.
 *
 * This is the "reset-in-place" response of decideRemoteTransportChangeResponse:
 * a transport that never authenticated, or the responder's transport when the
 * initiator answers from a fresh one. The PC itself survives: the browser
 * renegotiates DTLS on it against the new remote certificate, and the next
 * `main` (created by the identity initiator on a never-authenticated PC, or
 * arriving from the initiator's fresh transport on the responder's) opens
 * only over the re-run DTLS/SCTP, so the new handshake binds the new
 * fingerprint pair. The old `main` is closed here; its onclose handler
 * observes a stale gate lease (replaced below) and returns early, so closing
 * it never cascades into a disconnectFromPeer of the edge we are keeping.
 * Per-message channels are left alone: they are gated on the ratchet lease
 * and drain/close on their own once their transfer settles or the lease
 * check fails.
 */
export const resetEdgeAuthenticationForNewRemoteTransport = ({
  epc,
  roomId,
  peerId,
  api,
  reason,
}: ResetEdgeAuthenticationParams): void => {
  // Reject any in-flight handshake step on the old transcript first, then
  // replace the gate so every awaiter of the old authenticated state (sends,
  // receipt replay, message channels) fails over to the new attempt.
  clearHandshakeChannel(roomId, peerId, reason);
  epc.ratchetGateLease = resetRatchetGate(roomId, peerId, reason);

  // Same wipe order as disconnectFromPeerQuery: orchestrator timers die
  // before the PQ runtime, then the ratchet, then the derived caches.
  destroyPqHealingOrchestrator(epc);
  if (epc.pqHealingState) {
    epc.pqHealingState.destroy();
    epc.pqHealingState = undefined;
  }
  if (epc.ratchetState) {
    wipeRatchet(epc.ratchetState);
    epc.ratchetState = undefined;
  }
  if (epc.messageKeyCache) {
    for (const messageKey of epc.messageKeyCache.values()) messageKey.fill(0);
    epc.messageKeyCache.clear();
    epc.messageKeyCache = undefined;
  }
  epc.messageKeyByMerkleRoot?.clear();
  epc.messageKeyByMerkleRoot = undefined;
  epc.serializeEdgeCryptoState = undefined;
  teardownCoverEdge(epc);
  releaseScheduledReceipts(epc);

  const previousMain = epc.mainChannel;
  epc.mainChannel = undefined;
  if (previousMain && previousMain.readyState !== "closed")
    previousMain.close();

  api.dispatch(
    setPeerHandshakeStatus({ roomId, peerId, status: "authenticating" }),
  );
  debugLog(
    `Remote DTLS certificate changed for ${peerId} in ${roomId}; edge authentication reset`,
  );
};
