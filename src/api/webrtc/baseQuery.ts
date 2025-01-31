import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";

import { setChannel, setPeer } from "../../reducers/roomSlice";

import { getDBPeerIsBlacklisted } from "../../db/api";

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
  decryptionWasmMemory: WebAssembly.Memory;
  merkleWasmMemory: WebAssembly.Memory;
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
    decryptionWasmMemory,
    merkleWasmMemory,
  },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");

    const decryptionModule = await libcrypto({
      wasmMemory: decryptionWasmMemory,
    });

    const merkleModule = await libcrypto({
      wasmMemory: merkleWasmMemory,
    });

    const blacklisted = await getDBPeerIsBlacklisted(peerId);
    if (blacklisted) return { data: undefined };

    const connectionIndex = peerConnections.findIndex(
      (pc) => pc.withPeerId === peerId,
    );

    if (connectionIndex === -1) {
      const epc = await handleConnectToPeer(
        { peerId, peerPublicKey, roomId, initiator, rtcConfig },
        api,
      );

      epc.ondatachannel = async (e: RTCDataChannelEvent) => {
        await handleOpenChannel(
          {
            channel: e.channel,
            epc,
            roomId,
            dataChannels,
            decryptionModule,
            merkleModule,
          },
          api,
        );
      };

      peerConnections.push(epc);

      if (initiator) {
        await handleOpenChannel(
          {
            channel: "main",
            epc,
            roomId,
            dataChannels,
            decryptionModule,
            merkleModule,
          },
          api,
        );
      }
    } else {
      const epc = peerConnections[connectionIndex];
      if (epc.connectionState === "connected") {
        epc.roomIds.push(roomId);
        api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));

        const dataChannelsLen = dataChannels.length;
        for (let i = 0; i < dataChannelsLen; i++) {
          if (dataChannels[i].withPeerId === peerId) {
            dataChannels[i].roomIds.push(roomId);
          }
        }

        const { rooms } = api.getState() as State;
        const roomsLen = rooms.length;
        for (let i = 0; i < roomsLen; i++) {
          const channelIndex = rooms[i].channels.findIndex((c) =>
            c.peerIds.includes(peerId),
          );
          if (channelIndex > -1) {
            api.dispatch(
              setChannel({
                roomId,
                label: rooms[i].channels[channelIndex].label,
                peerId,
              }),
            );
          }
        }
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcBaseQuery;
