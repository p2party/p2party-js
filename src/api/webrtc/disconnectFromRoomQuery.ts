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
> = async ({ roomId, peerConnections, dataChannels }) => {
  return new Promise((resolve, reject) => {
    try {
      const peersIncluded: number[] = [];

      const CHANNELS_LEN = dataChannels.length;
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (
          dataChannels[i].roomId !== roomId ||
          dataChannels[i].readyState !== "open"
        )
          continue;

        const peerIndex = peerConnections.findIndex((p) => {
          p.withPeerId === dataChannels[i].withPeerId;
        });
        if (!peersIncluded.includes(peerIndex)) peersIncluded.push(peerIndex);

        dataChannels[i].onopen = null;
        dataChannels[i].onclose = null;
        dataChannels[i].onerror = null;
        dataChannels[i].onclosing = null;
        dataChannels[i].onmessage = null;
        dataChannels[i].onbufferedamountlow = null;
        dataChannels[i].close();
        dataChannels.splice(i, 1);
      }

      const PEERS_LEN = peersIncluded.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        const peerConnection = peerConnections[peersIncluded[i]];
        if (peerConnection.connectionState !== "connected") continue;

        const channelIndex = dataChannels.findIndex((c) => {
          c.withPeerId === peerConnection.withPeerId;
        });

        if (channelIndex !== -1) continue;

        peerConnection.ontrack = null;
        peerConnection.ondatachannel = null;
        peerConnection.onicecandidate = null;
        peerConnection.onicecandidateerror = null;
        peerConnection.onnegotiationneeded = null;
        peerConnection.onsignalingstatechange = null;
        peerConnection.onconnectionstatechange = null;
        peerConnection.onicegatheringstatechange = null;
        peerConnection.oniceconnectionstatechange = null;
        peerConnection.close();

        peerConnections.splice(peersIncluded[i], 1);
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectRoomQuery;
