import type { RTCPeerConnectionParams } from "../api/webrtc/interfaces";
import type { WebSocketMessagePeerConnectionResponse } from "../utils/interfaces";

export interface ConnectionSignalEffects {
  recordPeer: (peer: {
    roomId: string;
    peerId: string;
    peerPublicKey: string;
  }) => void;
  recordChannel: (channel: {
    roomId: string;
    peerId: string;
    label: string;
  }) => void;
  ensureConnection: (params: RTCPeerConnectionParams) => Promise<void>;
}

/**
 * Reconcile the server's accepted `connection` signal into both room metadata
 * and a local WebRTC transport.
 *
 * A `connection` signal is asymmetric: it proves that the remote side created
 * (or reused) its half of the edge, but an SDP offer may not follow when the
 * remote identity is the protocol responder. Ensuring the local half here lets
 * the deterministic identity initiator open `main` regardless of which peer
 * happened to join the room last.
 */
export const establishSignaledConnection = async (
  message: WebSocketMessagePeerConnectionResponse,
  rtcConfig: RTCConfiguration,
  effects: ConnectionSignalEffects,
): Promise<void> => {
  effects.recordPeer({
    roomId: message.roomId,
    peerId: message.fromPeerId,
    peerPublicKey: message.fromPeerPublicKey,
  });

  for (const label of message.labels)
    effects.recordChannel({
      roomId: message.roomId,
      peerId: message.fromPeerId,
      label,
    });

  await effects.ensureConnection({
    roomId: message.roomId,
    peerId: message.fromPeerId,
    peerPublicKey: message.fromPeerPublicKey,
    rtcConfig,
  });
};
