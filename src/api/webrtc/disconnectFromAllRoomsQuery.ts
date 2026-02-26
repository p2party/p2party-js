import webrtcApi from ".";

import { deleteMessage } from "../../reducers/roomSlice";

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
  const CHANNELS_LEN = dataChannels.length;
  for (let i = 0; i < CHANNELS_LEN; i++) {
    if (dataChannels[i]?.readyState !== "open") continue;

    if (exceptionRoomIds && exceptionRoomIds.length > 0) {
      const ROOM_IDS_LEN = dataChannels[i].roomIds.length;
      const indexesToSplice: number[] = [];
      for (let roomIndex = 0; roomIndex < ROOM_IDS_LEN; roomIndex++) {
        if (!exceptionRoomIds.includes(dataChannels[i].roomIds[roomIndex]))
          indexesToSplice.push(roomIndex);
      }

      const INDEXES_TO_SPLICE_LEN = indexesToSplice.length;
      for (
        let spliceIndex = 0;
        spliceIndex < INDEXES_TO_SPLICE_LEN;
        spliceIndex++
      ) {
        dataChannels[i].roomIds.splice(indexesToSplice[spliceIndex], 1);
      }

      if (dataChannels[i].roomIds.length === 0) dataChannels[i].close();
    } else {
      dataChannels[i].close();
    }
  }

  const PEERS_LEN = peerConnections.length;
  for (let i = 0; i < PEERS_LEN; i++) {
    if (peerConnections[i]?.connectionState !== "connected") continue;

    if (exceptionRoomIds && exceptionRoomIds.length > 0) {
      const PEER_ROOMS_LEN = peerConnections[i].rooms.length;
      const indexesToSplice: number[] = [];
      for (let roomIndex = 0; roomIndex < PEER_ROOMS_LEN; roomIndex++) {
        if (
          !exceptionRoomIds.includes(peerConnections[i].rooms[roomIndex].roomId)
        )
          indexesToSplice.push(roomIndex);
      }

      const INDEXES_TO_SPLICE_LEN = indexesToSplice.length;
      for (
        let spliceIndex = 0;
        spliceIndex < INDEXES_TO_SPLICE_LEN;
        spliceIndex++
      ) {
        peerConnections[i].rooms.splice(indexesToSplice[spliceIndex], 1);
      }

      if (peerConnections[i].rooms.length === 0)
        await api.dispatch(
          webrtcApi.endpoints.disconnectFromPeer.initiate({
            peerId: peerConnections[i].withPeerId,
          }),
        );
    } else {
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({
          peerId: peerConnections[i].withPeerId,
        }),
      );
    }
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
            merkleRootHex: rooms[i].messages[messageIndex].merkleRootHex,
          }),
        );
      }
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectAllRoomsQuery;
