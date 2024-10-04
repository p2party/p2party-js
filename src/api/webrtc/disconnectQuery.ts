import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { IRTCDataChannel, IRTCPeerConnection } from "./interfaces";

export interface RTCDisconnectParamsExtension {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectQuery: BaseQueryFn<
  RTCDisconnectParamsExtension,
  void,
  unknown
> = async ({ peerConnections, dataChannels }) => {
  return new Promise((resolve, reject) => {
    try {
      const CHANNELS_LEN = dataChannels.length;
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (dataChannels[i].readyState !== "open") continue;

        dataChannels[i].onopen = null;
        dataChannels[i].onclose = null;
        dataChannels[i].onerror = null;
        dataChannels[i].onclosing = null;
        dataChannels[i].onmessage = null;
        dataChannels[i].onbufferedamountlow = null;
        dataChannels[i].close();
        dataChannels.splice(i, 1);
      }

      const PEERS_LEN = peerConnections.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        if (peerConnections[i].connectionState !== "connected") continue;

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
        peerConnections.splice(i, 1);
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectQuery;
