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
 * Only a connected and verified socket can carry a peers request. Without one
 * the signaling reconnect path re-requests the roster on its own once the new
 * socket proves identity, so there is nothing to do here.
 *
 * The request goes through setConnectingToPeers, whose listener debounces it
 * under the dedicated "redial" key: a teardown that happens to land inside
 * the "join" window of a fresh room join must still be able to re-dial.
 */
export const requestPeersAfterEdgeTeardown = (
  api: EdgeTeardownFollowUpApi,
  roomId: string,
): boolean => {
  const { signalingServer } = api.getState() as {
    signalingServer: SignalingState;
  };
  if (!signalingServer.isConnected || !signalingServer.isVerified) return false;

  api.dispatch(
    setConnectingToPeers({ roomId, connectingToPeers: true, reason: "redial" }),
  );

  return true;
};
