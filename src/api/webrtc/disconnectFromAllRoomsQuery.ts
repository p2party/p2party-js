import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromAllRoomsParams,
} from "./interfaces";
import { deletePeer, deleteMessage } from "../../reducers/roomSlice";

import type { State } from "../../store";

export interface RTCDisconnectFromAllRoomsParamsExtension
  extends RTCDisconnectFromAllRoomsParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectAllRoomsQuery: BaseQueryFn<
  RTCDisconnectFromAllRoomsParamsExtension,
  void,
  unknown
> = async (
  { deleteMessages, exceptionRoomIds, peerConnections, dataChannels },
  api,
) => {
  return new Promise((resolve, reject) => {
    try {
      let i,
        j = 0;
      const CHANNELS_LEN = dataChannels.length;
      for (i = 0; i < CHANNELS_LEN; i++) {
        if (!dataChannels[i] || dataChannels[i].readyState !== "open") continue;

        if (exceptionRoomIds && exceptionRoomIds.length > 0) {
          const ROOM_IDS_LEN = dataChannels[i].roomIds.length;
          const indexesToSplice: number[] = [];
          for (j = 0; j < ROOM_IDS_LEN; j++) {
            if (!exceptionRoomIds.includes(dataChannels[i].roomIds[j]))
              indexesToSplice.push(j);
          }

          const INDEXES_TO_SPLICE_LEN = indexesToSplice.length;
          for (j = 0; j < INDEXES_TO_SPLICE_LEN; j++) {
            dataChannels[i].roomIds.splice(indexesToSplice[j], 1);
          }

          if (dataChannels[i].roomIds.length === 0) dataChannels[i].close();
        } else {
          dataChannels[i].close();
        }
      }

      const PEERS_LEN = peerConnections.length;
      for (i = 0; i < PEERS_LEN; i++) {
        if (
          !peerConnections[i] ||
          peerConnections[i].connectionState !== "connected"
        )
          continue;

        if (exceptionRoomIds && exceptionRoomIds.length > 0) {
          const PEER_ROOMS_LEN = peerConnections[i].roomIds.length;
          const indexesToSplice: number[] = [];
          for (j = 0; j < PEER_ROOMS_LEN; j++) {
            if (!exceptionRoomIds.includes(peerConnections[i].roomIds[j]))
              indexesToSplice.push(j);
          }

          const INDEXES_TO_SPLICE_LEN = indexesToSplice.length;
          for (j = 0; j < INDEXES_TO_SPLICE_LEN; j++) {
            peerConnections[i].roomIds.splice(indexesToSplice[j], 1);
          }

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
        } else {
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

      if (deleteMessages) {
        const { rooms } = api.getState() as State;
        const roomsLen = rooms.length;

        for (i = 0; i < roomsLen; i++) {
          if (exceptionRoomIds && exceptionRoomIds.includes(rooms[i].id))
            continue;

          const messagesLen = rooms[i].messages.length;
          for (j = 0; j < messagesLen; j++) {
            api.dispatch(
              deleteMessage({
                merkleRootHex: rooms[i].messages[j].merkleRootHex,
              }),
            );
          }
        }
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectAllRoomsQuery;
