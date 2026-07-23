import webrtcApi from ".";

import { deleteMessage, deletePeer } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromAllRoomsParams,
} from "./interfaces";

import type { State } from "../../store";

export interface RTCDisconnectFromAllRoomsParamsExtension extends RTCDisconnectFromAllRoomsParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectAllRoomsQuery: BaseQueryFn<
  RTCDisconnectFromAllRoomsParamsExtension,
  undefined
> = async (
  { deleteMessages, exceptionRoomIds, peerConnections, dataChannels },
  api,
) => {
  const exceptions = new Set(exceptionRoomIds ?? []);

  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    if (channel.roomIds.some((roomId) => exceptions.has(roomId))) continue;

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

  const targets = peerConnections
    .filter((connection) => !exceptions.has(connection.roomId))
    .map((connection) => ({
      roomId: connection.roomId,
      peerId: connection.withPeerId,
    }));
  for (const target of targets) {
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate(target),
    );
    api.dispatch(deletePeer(target));
  }

  if (deleteMessages) {
    const { rooms } = api.getState() as State;
    const roomsLen = rooms.length;

    for (let i = 0; i < roomsLen; i++) {
      if (exceptionRoomIds?.includes(rooms[i].id)) continue;

      const messagesLen = rooms[i].messages.length;
      for (let messageIndex = 0; messageIndex < messagesLen; messageIndex++) {
        api.dispatch(
          deleteMessage({
            roomId: rooms[i].id,
            merkleRootHex: rooms[i].messages[messageIndex].merkleRootHex,
          }),
        );
      }
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectAllRoomsQuery;
