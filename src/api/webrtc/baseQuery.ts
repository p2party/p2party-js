import connectToPeerHelper from "../../utils/connectToPeerHelper";
import openChannelHelper from "../../utils/openChannelHelper";
import libcrypto from "../../cryptography/libcrypto";

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
  encryptionWasmMemory: WebAssembly.Memory;
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
    encryptionWasmMemory,
  },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");

    const encryptionModule = await libcrypto({
      wasmMemory: encryptionWasmMemory,
    });

    const connectionIndex = peerConnections.findIndex(
      (pc) => pc.withPeerId === peerId,
    );

    if (connectionIndex === -1) {
      const epc = await connectToPeerHelper(
        { peerId, peerPublicKey, roomId, initiator, rtcConfig },
        api,
      );

      epc.ondatachannel = async (e: RTCDataChannelEvent) => {
        await openChannelHelper(
          { channel: e.channel, epc, dataChannels, encryptionModule },
          api,
        );
      };

      peerConnections.push(epc);

      if (initiator) {
        await openChannelHelper(
          { channel: "signaling", epc, dataChannels, encryptionModule },
          api,
        );

        await openChannelHelper(
          { channel: "main", epc, dataChannels, encryptionModule },
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
