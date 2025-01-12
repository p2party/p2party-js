import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromRoomParams,
} from "./interfaces";
import { deletePeer } from "../../reducers/roomSlice";

export interface RTCDisconnectFromRoomParamsExtension
  extends RTCDisconnectFromRoomParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectRoomQuery: BaseQueryFn<
  RTCDisconnectFromRoomParamsExtension,
  void,
  unknown
> = async ({ roomId, peerConnections, dataChannels }, api) => {
  return new Promise((resolve, reject) => {
    try {
      const CHANNELS_LEN = dataChannels.length;
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (
          dataChannels[i].roomId !== roomId ||
          dataChannels[i].readyState !== "open"
        )
          continue;

        dataChannels[i].close();
      }

      const PEERS_LEN = peerConnections.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        if (
          peerConnections[i].roomId !== roomId ||
          peerConnections[i].connectionState !== "connected"
        )
          continue;

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

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectRoomQuery;
