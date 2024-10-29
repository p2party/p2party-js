import openChannelHelper from "../../utils/openChannelHelper";
import libcrypto from "../../cryptography/libcrypto";

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
  encryptionWasmMemory: WebAssembly.Memory;
}

const webrtcOpenChannelQuery: BaseQueryFn<
  RTCOpenChannelParamsExtention,
  void,
  unknown
> = async (
  { channel, withPeers, peerConnections, dataChannels, encryptionWasmMemory },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;

    const encryptionModule = await libcrypto({
      wasmMemory: encryptionWasmMemory,
    });

    if (withPeers && withPeers.length > 0) {
      const PEERS_LEN = withPeers.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        if (keyPair.peerId === withPeers[i].peerId) continue;

        const peerIndex = peerConnections.findIndex(
          (p) => p.withPeerId === withPeers[i].peerId,
        );

        if (peerIndex > -1) {
          const epc = peerConnections[peerIndex];
          await openChannelHelper(
            { channel, epc, dataChannels, encryptionModule },
            api,
          );
        }
      }
    } else {
      const PEERS_LEN = peerConnections.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        const epc = peerConnections[i];
        await openChannelHelper(
          { channel, epc, dataChannels, encryptionModule },
          api,
        );
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcOpenChannelQuery;
