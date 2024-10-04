import openChannelHelper from "../../utils/openChannelHelper";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCOpenChannelParams,
  IRTCDataChannel,
  IRTCPeerConnection,
} from "./interfaces";

export interface RTCOpenChannelParamsExtention extends RTCOpenChannelParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcOpenChannelQuery: BaseQueryFn<
  RTCOpenChannelParamsExtention,
  void,
  unknown
> = async ({ channel, withPeers, peerConnections, dataChannels }, api) => {
  try {
    const { keyPair } = api.getState() as State;

    if (withPeers && withPeers.length > 0) {
      const PEERS_LEN = withPeers.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        if (keyPair.peerId === withPeers[i].peerId) continue;

        const peerIndex = peerConnections.findIndex(
          (p) => p.withPeerId === withPeers[i].peerId,
        );

        if (peerIndex > -1) {
          const epc = peerConnections[peerIndex];
          await openChannelHelper({ channel, epc, dataChannels }, api);
        }
      }
    } else {
      const PEERS_LEN = peerConnections.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        const epc = peerConnections[i];
        await openChannelHelper({ channel, epc, dataChannels }, api);
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcOpenChannelQuery;
