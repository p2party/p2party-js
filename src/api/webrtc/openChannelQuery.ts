import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { findRoomPeerConnection } from "./roomPeer";
import { isIdentityInitiator } from "../../utils/identityRole";

// import cryptoMemory from "../../cryptography/memory";
// import libcrypto from "../../cryptography/libcrypto";

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
  // receiveMessageWasmMemory: WebAssembly.Memory;
  // decryptionWasmMemory: WebAssembly.Memory;
  // merkleWasmMemory: WebAssembly.Memory;
}

const webrtcOpenChannelQuery: BaseQueryFn<
  RTCOpenChannelParamsExtention,
  undefined
> = async (
  {
    roomId,
    channel,
    withPeers,
    peerConnections,
    dataChannels,
    // receiveMessageWasmMemory,
    // decryptionWasmMemory,
    // merkleWasmMemory,
  },
  api,
) => {
  const { keyPair } = api.getState() as State;

  const openOnRoomPeer = async (
    epc: IRTCPeerConnection,
  ): Promise<void> => {
    if (typeof channel !== "string") {
      const opened = await handleOpenChannel(
        { channel, epc, roomId: epc.roomId, dataChannels },
        api,
      );
      if (opened.label === "main") epc.mainChannel = opened;
      return;
    }

    const existing = dataChannels.find(
      (dataChannel) =>
        dataChannel.withPeerId === epc.withPeerId &&
        dataChannel.roomIds.includes(epc.roomId) &&
        dataChannel.label === channel &&
        dataChannel.readyState !== "closing" &&
        dataChannel.readyState !== "closed",
    );
    if (existing) return;
    if (
      channel === "main" &&
      !isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey)
    )
      return;

    const rtcChannel = epc.createDataChannel(channel, {
      ordered: channel === "main",
      protocol: "raw",
    });
    const opened = await handleOpenChannel(
      { channel: rtcChannel, epc, roomId: epc.roomId, dataChannels },
      api,
    );
    if (opened.label === "main") epc.mainChannel = opened;
  };

  // const decryptionModule = await libcrypto({
  //   wasmMemory: decryptionWasmMemory,
  // });
  //
  // const merkleModule = await libcrypto({
  //   wasmMemory: merkleWasmMemory,
  // });

  if (withPeers && withPeers.length > 0) {
    const PEERS_LEN = withPeers.length;
    for (let i = 0; i < PEERS_LEN; i++) {
      if (keyPair.peerId === withPeers[i].peerId) continue;

      const epc = findRoomPeerConnection(
        peerConnections,
        roomId,
        withPeers[i].peerId,
      );

      if (epc) {

        await openOnRoomPeer(epc);
      }
    }
  } else {
    const roomPeerConnections = peerConnections.filter(
      (connection) => connection.roomId === roomId,
    );
    const PEERS_LEN = roomPeerConnections.length;
    for (let i = 0; i < PEERS_LEN; i++) {
      const epc = roomPeerConnections[i];


      await openOnRoomPeer(epc);
    }
  }

  return { data: undefined };
};

export default webrtcOpenChannelQuery;
