import connectToPeerHelper from "../../utils/connectToPeerHelper";
import openChannelHelper from "../../utils/openChannelHelper";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  RTCPeerConnectionParams,
  IRTCPeerConnection,
  IRTCDataChannel,
} from "./interfaces";
import type { State } from "../../store";

export interface RTCPeerConnectionParamsExtend extends RTCPeerConnectionParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcBaseQuery: BaseQueryFn<
  RTCPeerConnectionParamsExtend,
  void,
  unknown
> = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    initiator,
    rtcConfig,
    peerConnections,
    dataChannels,
  },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");

    const connectionIndex = peerConnections.findIndex(
      (pc) => pc.withPeerId === peerId,
    );
    if (connectionIndex === -1) {
      const epc = await connectToPeerHelper(
        { peerId, peerPublicKey, roomId, initiator, rtcConfig },
        api,
      );

      epc.ondatachannel = async (e: RTCDataChannelEvent) => {
        await openChannelHelper({ channel: e.channel, epc, dataChannels }, api);
      };

      peerConnections.push(epc);

      if (initiator) {
        await openChannelHelper(
          { channel: "signaling", epc, dataChannels },
          api,
        );
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcBaseQuery;
