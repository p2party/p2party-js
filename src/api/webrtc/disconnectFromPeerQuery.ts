import { deleteChannel, deletePeer } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
} from "./interfaces";

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
  return new Promise((resolve, reject) => {
    try {
      const peerIndex = peerConnections.findIndex(
        (peer) => peer.withPeerId === peerId,
      );

      if (peerIndex > -1) {
        if (
          peerConnections[peerIndex].connectionState === "connected" ||
          peerConnections[peerIndex].connectionState === "failed"
        ) {
          peerConnections[peerIndex].ontrack = null;
          peerConnections[peerIndex].ondatachannel = null;
          peerConnections[peerIndex].onicecandidate = null;
          peerConnections[peerIndex].onicecandidateerror = null;
          peerConnections[peerIndex].onnegotiationneeded = null;
          peerConnections[peerIndex].onsignalingstatechange = null;
          peerConnections[peerIndex].onconnectionstatechange = null;
          peerConnections[peerIndex].onicegatheringstatechange = null;
          peerConnections[peerIndex].oniceconnectionstatechange = null;
          peerConnections[peerIndex].close();
        }

        api.dispatch(deletePeer({ peerId }));

        peerConnections.splice(peerIndex, 1);
      }

      const CHANNELS_LEN = dataChannels.length;
      const channelsClosedIndexes: number[] = [];

      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (dataChannels[i].withPeerId !== peerId) continue;
        if (dataChannels[i].readyState === "open") {
          dataChannels[i].onopen = null;
          dataChannels[i].onclose = null;
          dataChannels[i].onerror = null;
          dataChannels[i].onclosing = null;
          dataChannels[i].onmessage = null;
          dataChannels[i].onbufferedamountlow = null;
          dataChannels[i].close();
        }

        channelsClosedIndexes.push(i);

        api.dispatch(deleteChannel({ peerId, label: dataChannels[i].label }));
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        dataChannels.splice(channelsClosedIndexes[i], 1);
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectPeerQuery;
