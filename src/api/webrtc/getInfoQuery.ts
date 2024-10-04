import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCMessage,
  IRTCPeerConnection,
} from "./interfaces";
import type { RTCRoomInfoParams, RoomData } from "./interfaces";

export interface RTCRoomInfoParamsExtension extends RTCRoomInfoParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  messages: IRTCMessage[];
}

const webrtcGetInfoQuery: BaseQueryFn<
  RTCRoomInfoParamsExtension,
  RoomData,
  unknown
> = async ({ roomId, peerConnections, dataChannels, messages }) => {
  return new Promise((resolve, reject) => {
    try {
      const cs = dataChannels.filter((c) => c.roomId === roomId);
      const channelsLen = cs.length;
      const peersLen = peerConnections.length;

      const channelsIncluded: number[] = [];
      const messagesIncluded: number[] = [];

      let ps: RoomData = {
        roomId,
        peers: [],
        channels: [],
        messages: [],
      };

      for (let i = 0; i < peersLen; i++) {
        for (let j = 0; j < channelsLen; j++) {
          if (channelsIncluded.includes(j)) continue;

          if (cs[j].withPeerId === peerConnections[i].withPeerId) {
            channelsIncluded.push(j);

            const peerIndex = ps.peers.findIndex(
              (p) => p.peerId === cs[j].withPeerId,
            );

            if (peerIndex === -1) {
              ps.peers.push({
                peerId: peerConnections[i].withPeerId,
                peerPublicKey: peerConnections[i].withPeerPublicKey,
              });
            }

            const channelIndex = ps.channels.findIndex(
              (c) => c.label === cs[j].label,
            );

            if (channelIndex === -1) {
              ps.channels.push({
                label: cs[j].label,
                peerId: cs[j].withPeerId,
              });
            }

            const messagesLen = messages.length;
            for (let k = 0; k < messagesLen; k++) {
              if (messagesIncluded.includes(k)) continue;

              if (
                messages[k].fromPeerId === cs[j].withPeerId ||
                messages[k].toPeerId === cs[j].withPeerId
              ) {
                ps.messages.push({
                  ...messages[k],
                  channel: cs[j].label,
                });
              }
            }
          }
        }
      }

      resolve({ data: ps });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcGetInfoQuery;
