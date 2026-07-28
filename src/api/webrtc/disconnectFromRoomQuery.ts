import { deleteMessageStateOnly, deletePeer } from "../../reducers/roomSlice";
import { deleteRoomDataTerminal } from "./deleteRoomData";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromRoomParams,
  DisconnectPeerTransport,
} from "./interfaces";

export interface RTCDisconnectFromRoomParamsExtension extends RTCDisconnectFromRoomParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  disconnectPeer: DisconnectPeerTransport;
}

const webrtcDisconnectRoomQuery: BaseQueryFn<
  RTCDisconnectFromRoomParamsExtension,
  undefined
> = async (
  { roomId, deleteMessages, peerConnections, dataChannels, disconnectPeer },
  api,
) => {
  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    if (!channel.roomIds.includes(roomId)) continue;

    channel.releaseProtocolResources?.();
    channel.onopen = null;
    channel.onclose = null;
    channel.onerror = null;
    channel.onclosing = null;
    channel.onmessage = null;
    channel.onbufferedamountlow = null;
    if (channel.readyState !== "closed") channel.close();
    dataChannels.splice(i, 1);
  }

  const roomPeers = peerConnections
    .filter((connection) => connection.roomId === roomId)
    .map((connection) => connection.withPeerId);
  for (const peerId of roomPeers) {
    await disconnectPeer({ peerId, roomId });
    api.dispatch(deletePeer({ peerId, roomId }));
  }

  if (deleteMessages)
    await deleteRoomDataTerminal(roomId, (merkleRootHex) => {
      // Durable deletion was explicitly awaited before this reducer-only twin.
      // No listener-owned DB task survives the terminal API boundary.
      api.dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
    });

  return { data: undefined };
};

export default webrtcDisconnectRoomQuery;
