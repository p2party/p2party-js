import type { IRTCPeerConnection } from "./interfaces";

/**
 * How long a fresh transport may hold its first offer without any remote
 * description before the transport is given up on and the room re-dialed.
 *
 * Must outlive the signaling server's dark-socket drop (one missed 10 s ping
 * plus its 5 s pong window): an offer sent to a peer that was still on the
 * roster but whose socket had already gone dark is lost when the server
 * closes that socket, and by the time this fires the roster no longer lists
 * the peer, so the re-dial builds nothing for it until it is really back.
 */
export const PENDING_OFFER_TIMEOUT_MS = 15_000;

/**
 * True iff this transport holds a local offer that no remote description has
 * ever answered, i.e. its FIRST offer is still pending.
 *
 * An ICE-restart offer on a negotiated transport is excluded: there the
 * remote description of the previous round is still applied, and the ICE
 * repair paths own that timeout. Only the identity initiator ever offers on
 * a fresh transport (the responder creates no channel there), so a pending
 * first offer belongs to exactly one side of an edge.
 *
 * Such a transport never fails on its own: without a remote description no
 * ICE checks run, so connectionState stays "new" and nothing tears it down.
 * A peer that later re-dials with a `connection` frame (its old transport
 * died while its socket was dark, so it never saw the offer) finds this PC
 * reused by ensureConnection, which would leave the edge half-built forever.
 */
export const hasUnansweredFirstOffer = (
  epc: Pick<IRTCPeerConnection, "signalingState" | "remoteDescription">,
): boolean =>
  epc.signalingState === "have-local-offer" && epc.remoteDescription == null;

/**
 * True iff this transport has negotiated nothing at all: no local offer was
 * ever made and no remote description ever arrived. Only a protocol RESPONDER
 * reaches this state on a healthy edge — it creates no channel, so
 * onnegotiationneeded never fires — and it is exactly the state a second
 * session for one identity is stranded in (C1).
 *
 * Disjoint from hasUnansweredFirstOffer by construction: that one requires a
 * local offer, this one requires the absence of every description. No
 * transport can be watched by both watchdogs at once.
 */
export const hasNoNegotiatedDescription = (
  epc: Pick<
    IRTCPeerConnection,
    "signalingState" | "localDescription" | "remoteDescription"
  >,
): boolean =>
  epc.signalingState === "stable" &&
  epc.localDescription == null &&
  epc.remoteDescription == null;
