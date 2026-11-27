import { setConnectingToPeers } from "../reducers/roomSlice";

import type { SignalingState } from "../reducers/signalingServerSlice";

export interface EdgeTeardownFollowUpApi {
  getState: () => unknown;
  dispatch: (action: ReturnType<typeof setConnectingToPeers>) => unknown;
}

/**
 * Re-dials a room after one of its peer edges was torn down on a path that
 * has no re-dial of its own.
 *
 * disconnectFromPeer nulls every handler on the RTCPeerConnection and on its
 * data channels before closing them, so the main-channel onclose that would
 * normally re-request the roster never runs for a grace-timer or a
 * failed/closed teardown. The peer usually still holds its side of the edge
 * at that point (its ICE consent has not expired while it was frozen), so it
 * will not offer either, and the edge stays down until an unrelated event
 * happens to trigger a roster request.
 *
 * The room listener queues the intent while the socket is unavailable and
 * flushes it once that socket proves the identity. A left room or reset identity
 * must never inherit a deferred repair.
 *
 * The request goes through setConnectingToPeers, whose listener debounces it
 * under the dedicated "redial" key: a teardown that happens to land inside
 * the "join" window of a fresh room join must still be able to re-dial.
 *
 * Callers decide WHEN a teardown deserves a re-dial; this helper has no
 * backoff of its own. handleConnectToPeer re-dials after an ICE failure or
 * grace-timer teardown only for an edge that had reached "connected" at least
 * once (a transport that never connected would otherwise rebuild and fail
 * again on every ICE failure interval), and after a fresh transport's first
 * offer went unanswered for PENDING_OFFER_TIMEOUT_MS (by then the signaling
 * server has dropped a dark peer from the roster, so a re-dial to a peer that
 * is really gone builds nothing).
 */
export const requestPeersAfterEdgeTeardown = (
  api: EdgeTeardownFollowUpApi,
  roomId: string,
  peerId?: string,
): boolean => {
  const { signalingServer } = api.getState() as {
    signalingServer: SignalingState;
  };
  if (signalingServer.refusal) return false;

  api.dispatch(
    setConnectingToPeers({
      roomId,
      connectingToPeers: true,
      reason: "redial",
      ...(peerId ? { peerId } : {}),
    }),
  );

  return signalingServer.isConnected && signalingServer.isVerified;
};
