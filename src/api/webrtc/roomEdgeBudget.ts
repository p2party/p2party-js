import { MAX_SIGNALING_ROOM_PEERS } from "../../utils/signalingBounds";

import type { Peer } from "../../reducers/roomSlice";
import type { IRTCPeerConnection } from "./interfaces";

/**
 * Enforce one cumulative edge budget across Redux roster state and concrete
 * transports, including PCs inserted while their WASM initialization awaits.
 *
 * Callers run this under the stable room-configuration mutex immediately
 * before registry insertion, making concurrent identities observe each other.
 */
export const assertRoomEdgeBudget = (
  roomId: string,
  peers: readonly Peer[],
  peerConnections: readonly IRTCPeerConnection[],
  candidatePublicKey: string,
): void => {
  const identities = new Set(peers.map((peer) => peer.peerPublicKey));
  for (const connection of peerConnections) {
    if (connection.roomId === roomId)
      identities.add(connection.withPeerPublicKey);
  }
  identities.add(candidatePublicKey);

  if (identities.size > MAX_SIGNALING_ROOM_PEERS)
    throw new Error("WebRTC room edge budget is exhausted");
};
