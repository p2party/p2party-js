import type { IRTCPeerConnection } from "./interfaces";

export const isRoomPeerConnection = (
  connection: IRTCPeerConnection,
  roomId: string,
  peerId: string,
): boolean =>
  connection.roomId === roomId && connection.withPeerId === peerId;

export const findRoomPeerConnectionIndex = (
  connections: IRTCPeerConnection[],
  roomId: string,
  peerId: string,
): number =>
  connections.findIndex((connection) =>
    isRoomPeerConnection(connection, roomId, peerId),
  );

export const findRoomPeerConnection = (
  connections: IRTCPeerConnection[],
  roomId: string,
  peerId: string,
): IRTCPeerConnection | undefined => {
  const index = findRoomPeerConnectionIndex(connections, roomId, peerId);
  return index < 0 ? undefined : connections[index];
};

/**
 * A peerId is a transient signaling handle; the Ed25519 public key is the
 * stable cryptographic identity. Return transports in this room which claim
 * the same stable identity under a different peerId so callers can replace
 * them before a second live ratchet owner is created.
 */
export const findRoomIdentityAliases = (
  connections: IRTCPeerConnection[],
  roomId: string,
  peerId: string,
  peerPublicKey: string,
): IRTCPeerConnection[] =>
  connections.filter(
    (connection) =>
      connection.roomId === roomId &&
      connection.withPeerPublicKey === peerPublicKey &&
      connection.withPeerId !== peerId,
  );
