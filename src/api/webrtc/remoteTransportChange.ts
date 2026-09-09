import { wipeRatchet } from "../../cryptography/ratchet";
import { clearHandshakeChannel } from "../../handlers/handleHandshake";
import { destroyPqHealingOrchestrator } from "../../handlers/pqHealingOrchestrator";
import { releaseScheduledReceipts } from "../../handlers/coverTransfer";
import { teardownCoverEdge } from "../../handlers/coverEdge";
import { isRatchetGateOpen, resetRatchetGate } from "../../handlers/ratchetGate";
import { setPeerHandshakeStatus } from "../../reducers/roomSlice";
import { parseFingerprintFromSdp } from "../../utils/sdpFingerprint";
import { debugLog } from "../../utils/debug";
import { armRebindAuthenticationDeadline } from "./rebindDeadline";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { RebindDeadlineScheduler } from "./rebindDeadline";
import type {
  DisconnectPeerTransport,
  IRTCDataChannel,
  IRTCPeerConnection,
} from "./interfaces";

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

/**
 * True iff this transport COMPLETED an edge authentication: a live ratchet, or
 * the per-peer gate open under its own lease.
 *
 * Deliberately narrower than `isEdgeAuthenticatedOnTransport`, which also
 * counts an open `main` — a handshake merely in flight. The re-bind budget
 * below has to distinguish "this transport proved something" from "this
 * transport is trying again", and an open `main` is the latter.
 */
const hasProvenEdgeAuthentication = (
  epc: Pick<IRTCPeerConnection, "ratchetState" | "ratchetGateLease">,
  roomId: string,
  peerId: string,
): boolean =>
  epc.ratchetState !== undefined ||
  isRatchetGateOpen(roomId, peerId, epc.ratchetGateLease);

export type RemoteTransportChangeResponse = "reset-in-place" | "replace";

export interface RemoteTransportChangeDecisionParams {
  epc: Pick<
    IRTCPeerConnection,
    | "ratchetState"
    | "ratchetGateLease"
    | "mainChannel"
    | "remoteTransportRebinds"
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
 *
 * All of that is bounded by one invariant: AT MOST ONE in-place re-bind per
 * unauthenticated transport. An in-place re-bind changes only the REMOTE
 * certificate — ours is minted with the RTCPeerConnection and lives as long as
 * it does. A PC whose ICE stays connected never fails, so neither the
 * ICE-failure re-dial nor the grace-timer teardown ever replaces it, and it
 * keeps answering with a certificate the peer may already have retired (T9)
 * while the peer keeps offering from ever newer ones: a livelock in which both
 * sides negotiate forever and no `main` ever opens. Requiring the first
 * re-bind to have actually authenticated before granting a second one caps the
 * loop at one round — the second fingerprint change replaces the transport,
 * which mints a new local certificate the peer has never retired, and the edge
 * converges.
 */
export const decideRemoteTransportChangeResponse = ({
  epc,
  roomId,
  peerId,
  descriptionType,
  isInitiator,
}: RemoteTransportChangeDecisionParams): RemoteTransportChangeResponse => {
  if (
    epc.remoteTransportRebinds > 0 &&
    !hasProvenEdgeAuthentication(epc, roomId, peerId)
  )
    return "replace";
  if (!isEdgeAuthenticatedOnTransport(epc, roomId, peerId))
    return "reset-in-place";
  if (descriptionType === "offer") return "replace";
  return isInitiator ? "replace" : "reset-in-place";
};

export interface ResetEdgeAuthenticationParams {
  epc: IRTCPeerConnection;
  roomId: string;
  peerId: string;
  api: Pick<BaseQueryApi, "dispatch" | "getState">;
  /**
   * The shared open-channel registry. Passed in explicitly (the caller already
   * holds it) so this helper stays store-free and unit-testable: it owns the
   * retirement of the generation's channels, which live in BOTH this array and
   * `epc.messageChannels`.
   */
  dataChannels: IRTCDataChannel[];
  /**
   * Tears this room/peer transport down through the transport-failure path.
   * Injected exactly as setDescriptionQuery's own teardown is, so the deadline
   * armed below needs no import of the API that registers it.
   */
  disconnectPeer: DisconnectPeerTransport;
  /** Test seams for the re-bind deadline; production takes the defaults. */
  deadlineMs?: number;
  schedule?: RebindDeadlineScheduler;
  reason: Error;
}

/** Drop exactly this channel object from the shared open-channel registry. */
const unregisterDataChannel = (
  channel: IRTCDataChannel,
  dataChannels: IRTCDataChannel[],
): void => {
  for (let index = dataChannels.length - 1; index >= 0; index--)
    if (dataChannels[index] === channel) dataChannels.splice(index, 1);
};

/**
 * Retire one non-main channel of the generation being dropped: release its
 * protocol accounting, detach every handler, close it, and unregister it from
 * both the edge's set and the shared array. Same operation, same order, as
 * disconnectFromPeerQuery's channel sweep — an already-closed channel is
 * released and unregistered but never re-closed.
 */
const releaseRetiredChannel = (
  channel: IRTCDataChannel,
  epc: IRTCPeerConnection,
  dataChannels: IRTCDataChannel[],
): void => {
  channel.releaseProtocolResources?.();
  channel.onopen = null;
  channel.onclose = null;
  channel.onerror = null;
  channel.onclosing = null;
  channel.onmessage = null;
  channel.onbufferedamountlow = null;
  if (channel.readyState !== "closed") channel.close();
  epc.messageChannels?.delete(channel);
  unregisterDataChannel(channel, dataChannels);
};

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
 *
 * EVERY other channel of the retired generation goes with it. A per-message
 * channel belongs to the ratchet generation that opened it: it captured that
 * generation's gate lease, so once the lease is replaced here its next inbound
 * frame can only be rejected as application data before peer authentication —
 * and that rejection closes the channel, which on a live transfer cascades
 * into closing `main` and tearing down the very edge this re-bind exists to
 * keep. (Observed on the process-freeze harness: an 8 MiB transfer in flight
 * across the freeze left its data channel OPEN on the surviving PC, and the
 * first frame after the re-bind killed the edge.) A send in flight over such a
 * channel loses nothing: the gate lease replaced here is exactly what tells
 * handleSendMessage that the close was OURS, so the transfer resumes on the
 * re-authenticated generation (re-opening its channel, re-stepping the ratchet)
 * instead of being read as a cancel by the peer. Cover lanes are NOT swept
 * here — `teardownCoverEdge` above closes each one, and the close listener
 * `registerCoverChannelUntilClose` installed unregisters it from both
 * `epc.coverChannels` and the shared array.
 *
 * Detaching those handlers also skips the receive-side bookkeeping a normal
 * close would have run — `forgetCompletedReceiveMessageKey`. That is
 * deliberate: retiring a key durably is asynchronous I/O and this reset is a
 * synchronous step on the description path. Every key is wiped from RAM below
 * (message-key cache filled with zeros, ratchet wiped, PQ runtime destroyed),
 * and the durable edge checkpoint is keyed by (roomId, peerPublicKey) and
 * rewritten whole by the next handshake's persist, so a completed transfer's
 * key survives only until this edge re-authenticates.
 */
export const resetEdgeAuthenticationForNewRemoteTransport = ({
  epc,
  roomId,
  peerId,
  api,
  dataChannels,
  disconnectPeer,
  deadlineMs,
  schedule,
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
  // Cover lanes are owned by teardownCoverEdge, which closes every one of
  // them; the close listener registerCoverChannelUntilClose installed then
  // unregisters the lane from `epc.coverChannels` AND from the shared array.
  // That listener fires on the close EVENT, so a lane can still be in the
  // array a moment later — capture the set first and let its own teardown
  // finish the job rather than racing it with a blunter release.
  const coverLanes = new Set<IRTCDataChannel>(epc.coverChannels);
  teardownCoverEdge(epc);
  releaseScheduledReceipts(epc);

  const previousMain = epc.mainChannel;
  epc.mainChannel = undefined;

  // The generation's channels: everything this edge tracks as a message
  // channel, plus anything of this room/peer still registered in the shared
  // array (a channel whose own accounting already released it, or one this
  // edge never tracked). `main` is retired separately, below.
  const retired = new Set<IRTCDataChannel>(epc.messageChannels);
  for (const channel of dataChannels)
    if (
      channel !== previousMain &&
      !coverLanes.has(channel) &&
      channel.withPeerId === peerId &&
      channel.roomIds.includes(roomId)
    )
      retired.add(channel);
  for (const channel of retired)
    releaseRetiredChannel(channel, epc, dataChannels);

  // `main` keeps the treatment it has always had — closed once, detached from
  // the connection, its own onclose left to observe the stale lease and return
  // — and is dropped from the shared array, which nothing else does for it on
  // this path.
  if (previousMain) {
    unregisterDataChannel(previousMain, dataChannels);
    if (previousMain.readyState !== "closed") previousMain.close();
  }

  // One more in-place re-bind on the record for this transport. The handshake
  // success path clears it, so decideRemoteTransportChangeResponse's budget
  // only ever counts re-binds that authenticated nothing.
  epc.remoteTransportRebinds = (epc.remoteTransportRebinds ?? 0) + 1;

  // A re-bind that never completes must not cost the peer's 30 s handshake
  // step timeout: the surviving SCTP association can accept our own new
  // streams while never delivering the peer's `main`, and nothing else on a
  // still-ICE-connected transport ever notices. Armed AFTER the gate above is
  // replaced, so the deadline owns this attempt's lease.
  armRebindAuthenticationDeadline({
    epc,
    roomId,
    peerId,
    api,
    disconnectPeer,
    deadlineMs,
    schedule,
  });

  api.dispatch(
    setPeerHandshakeStatus({
      roomId,
      peerId,
      peerPublicKey: epc.withPeerPublicKey,
      status: "authenticating",
    }),
  );
  debugLog(
    `Remote DTLS certificate changed for ${peerId} in ${roomId}; edge authentication reset`,
  );
};
