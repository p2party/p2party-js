import signalingServerApi from "../signalingServerApi";

import openChannelHelper from "../../utils/openChannelHelper";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCOpenChannelParams,
  IRTCDataChannel,
  IRTCPeerConnection,
  IRTCMessage,
} from "./interfaces";
import type { WebSocketMessagePeersRequest } from "../../utils/interfaces";

export interface RTCOpenChannelParamsExtention extends RTCOpenChannelParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  messages: IRTCMessage[];
}

const webrtcOpenChannelQuery: BaseQueryFn<
  RTCOpenChannelParamsExtention,
  void,
  unknown
> = async (
  { channel, roomId, withPeers, peerConnections, dataChannels, messages },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;

    if (withPeers && withPeers.length > 0) {
      const PEERS_LEN = withPeers.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        const peerIndex = peerConnections.findIndex((p) => {
          p.withPeerId === withPeers[i].peerId;
        });

        if (peerIndex > -1) {
          const epc = peerConnections[peerIndex];
          await openChannelHelper(
            { channel, epc, dataChannels, messages },
            api,
          );
        }
      }
    } else {
      // TODO
      api.dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "peers",
            fromPeerId: keyPair.peerId,
            roomId,
          } as WebSocketMessagePeersRequest,
        }),
      );
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcOpenChannelQuery;
