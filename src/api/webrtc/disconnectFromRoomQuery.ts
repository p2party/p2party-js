import { deleteMessage, deletePeer } from "../../reducers/roomSlice";
import {
  deleteDBUniqueRoom,
  getAllDBUniqueRooms,
  getDBRoomMessageData,
} from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromRoomParams,
} from "./interfaces";
import webrtcApi from ".";

export interface RTCDisconnectFromRoomParamsExtension extends RTCDisconnectFromRoomParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectRoomQuery: BaseQueryFn<
  RTCDisconnectFromRoomParamsExtension,
  undefined
> = async ({ roomId, deleteMessages, peerConnections, dataChannels }, api) => {
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
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId, roomId }),
    );
    api.dispatch(deletePeer({ peerId, roomId }));
  }

  if (deleteMessages) {
    const rooms = await getAllDBUniqueRooms();
    const roomIndex = rooms.findIndex((r) => r.roomId === roomId);

    if (roomIndex > -1) {
      await deleteDBUniqueRoom(roomId);
      const messages = await getDBRoomMessageData(roomId);
      const messagesLen = messages.length;
      for (let j = 0; j < messagesLen; j++) {
        api.dispatch(
          deleteMessage({
            roomId,
            merkleRootHex: messages[j].merkleRoot,
          }),
        );
      }
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectRoomQuery;
