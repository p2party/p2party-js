import { handleOpenChannel } from "../../handlers/handleOpenChannel";

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
  decryptionWasmMemory: WebAssembly.Memory;
  merkleWasmMemory: WebAssembly.Memory;
}

const webrtcOpenChannelQuery: BaseQueryFn<
  RTCOpenChannelParamsExtention,
  void,
  unknown
> = async (
  {
    roomId,
    channel,
    withPeers,
    peerConnections,
    dataChannels,
    decryptionWasmMemory,
    merkleWasmMemory,
  },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;

    const decryptionModule = await libcrypto({
      wasmMemory: decryptionWasmMemory,
    });

    const merkleModule = await libcrypto({
      wasmMemory: merkleWasmMemory,
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
          await handleOpenChannel(
            {
              channel,
              epc,
              roomId,
              dataChannels,
              decryptionModule,
              merkleModule,
            },
            api,
          );
        }
      }
    } else {
      const PEERS_LEN = peerConnections.length;
      for (let i = 0; i < PEERS_LEN; i++) {
        const epc = peerConnections[i];
        await handleOpenChannel(
          {
            channel,
            epc,
            roomId,
            dataChannels,
            decryptionModule,
            merkleModule,
          },
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
