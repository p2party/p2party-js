import { deletePeer, deleteMessage } from "../../reducers/roomSlice";
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

export interface RTCDisconnectFromRoomParamsExtension
  extends RTCDisconnectFromRoomParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectRoomQuery: BaseQueryFn<
  RTCDisconnectFromRoomParamsExtension,
  void,
  unknown
> = async ({ roomId, deleteMessages, peerConnections, dataChannels }, api) => {
  try {
    const CHANNELS_LEN = dataChannels.length;
    for (let i = 0; i < CHANNELS_LEN; i++) {
      if (
        !dataChannels[i] ||
        !dataChannels[i].roomIds.includes(roomId) ||
        dataChannels[i].readyState !== "open"
      )
        continue;

      const roomIndex = dataChannels[i].roomIds.findIndex((r) => r === roomId);
      if (roomIndex > -1) {
        dataChannels[i].roomIds.splice(roomIndex, 1);

        if (dataChannels[i].roomIds.length === 0) dataChannels[i].close();
      }
    }

    const PEERS_LEN = peerConnections.length;
    for (let i = 0; i < PEERS_LEN; i++) {
      if (
        !peerConnections[i] ||
        !peerConnections[i].roomIds.includes(roomId) ||
        peerConnections[i].connectionState !== "connected"
      )
        continue;

      const peerIndex = peerConnections[i].roomIds.findIndex(
        (p) => p === roomId,
      );
      if (peerIndex > -1) {
        peerConnections[i].roomIds.splice(peerIndex, 1);

        if (peerConnections[i].roomIds.length === 0) {
          peerConnections[i].ontrack = null;
          peerConnections[i].ondatachannel = null;
          peerConnections[i].onicecandidate = null;
          peerConnections[i].onicecandidateerror = null;
          peerConnections[i].onnegotiationneeded = null;
          peerConnections[i].onsignalingstatechange = null;
          peerConnections[i].onconnectionstatechange = null;
          peerConnections[i].onicegatheringstatechange = null;
          peerConnections[i].oniceconnectionstatechange = null;
          peerConnections[i].close();

          api.dispatch(deletePeer({ peerId: peerConnections[i].withPeerId }));

          delete peerConnections[i];
          peerConnections.splice(i, 1);
        }
      }
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
              merkleRootHex: messages[j].merkleRoot,
            }),
          );
        }
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcDisconnectRoomQuery;
