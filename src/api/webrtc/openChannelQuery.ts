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
  receiveMessageWasmMemory: WebAssembly.Memory;
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
    receiveMessageWasmMemory,
  },
  api,
) => {
  const { keyPair } = api.getState() as State;

  const receiveMessageModule = await libcrypto({
    wasmMemory: receiveMessageWasmMemory,
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
            receiveMessageModule,
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
          receiveMessageModule,
        },
        api,
      );
    }
  }

  return { data: undefined };
};

export default webrtcOpenChannelQuery;
