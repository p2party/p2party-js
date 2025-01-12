import { deletePeer } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
} from "./interfaces";
// import { deleteDBSendQueue } from "../../db/api";

export interface RTCDisconnectFromPeerParamsExtension
  extends RTCDisconnectFromPeerParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectPeerQuery: BaseQueryFn<
  RTCDisconnectFromPeerParamsExtension,
  void,
  unknown
> = async ({ peerId, peerConnections, dataChannels }, api) => {
  try {
    api.dispatch(deletePeer({ peerId }));

    const peerIndex = peerConnections.findIndex(
      (peer) => peer.withPeerId === peerId,
    );

    if (peerIndex > -1) {
      peerConnections[peerIndex].ontrack = null;
      peerConnections[peerIndex].ondatachannel = null;
      peerConnections[peerIndex].onicecandidate = null;
      peerConnections[peerIndex].onicecandidateerror = null;
      peerConnections[peerIndex].onnegotiationneeded = null;
      peerConnections[peerIndex].onsignalingstatechange = null;
      peerConnections[peerIndex].onconnectionstatechange = null;
      peerConnections[peerIndex].onicegatheringstatechange = null;
      peerConnections[peerIndex].oniceconnectionstatechange = null;

      if (peerConnections[peerIndex].connectionState !== "closed")
        peerConnections[peerIndex].close();

      delete peerConnections[peerIndex];
      peerConnections.splice(peerIndex, 1);
    }

    const CHANNELS_LEN = dataChannels.length;
    for (let i = 0; i < CHANNELS_LEN; i++) {
      if (dataChannels[i].withPeerId !== peerId) continue;
      if (dataChannels[i].readyState === "open") {
        dataChannels[i].close();
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcDisconnectPeerQuery;
