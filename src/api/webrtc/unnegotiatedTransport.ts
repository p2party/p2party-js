/**
 * Bounded rebuild budget for a transport that never negotiated.
 *
 * A protocol responder creates no data channel on a fresh transport, so if the
 * peer never dials it the transport sits in `new` with no description of any
 * kind and nothing watches it: the offer watchdog needs `have-local-offer`,
 * the rebind deadline needs a description, and ICE never runs. Tearing it down
 * and re-dialling makes the failure visible and lets a generation-aware peer
 * (see peerSocketGeneration) rebuild against the live session.
 *
 * Against a PRE-generation server the peer will not rebuild, so an uncapped
 * watchdog would churn every PENDING_OFFER_TIMEOUT_MS forever. This cap turns
 * that into three attempts and then a quiet, visibly-failed edge.
 */
export const MAX_UNNEGOTIATED_TRANSPORT_REBUILDS = 3;

const rebuilds = new Map<string, number>();

const key = (roomId: string, peerId: string): string => `${roomId}|${peerId}`;

export const recordUnnegotiatedTransportRebuild = (
  roomId: string,
  peerId: string,
): number => {
  const next = (rebuilds.get(key(roomId, peerId)) ?? 0) + 1;
  rebuilds.set(key(roomId, peerId), next);
  return next;
};

export const unnegotiatedTransportRebuilds = (
  roomId: string,
  peerId: string,
): number => rebuilds.get(key(roomId, peerId)) ?? 0;

export const clearUnnegotiatedTransportRebuilds = (
  roomId: string,
  peerId: string,
): void => {
  rebuilds.delete(key(roomId, peerId));
};

export const mayRebuildUnnegotiatedTransport = (
  roomId: string,
  peerId: string,
): boolean =>
  unnegotiatedTransportRebuilds(roomId, peerId) <
  MAX_UNNEGOTIATED_TRANSPORT_REBUILDS;
