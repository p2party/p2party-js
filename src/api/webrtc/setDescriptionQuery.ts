import signalingServerApi from "../signalingServerApi";

import libcrypto from "../../cryptography/libcrypto";

import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";
import { handleOpenChannel } from "../../handlers/handleOpenChannel";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCSetDescriptionParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
} from "./interfaces";
import type { WebSocketMessageDescriptionSend } from "../../utils/interfaces";

export interface RTCSetDescriptionParamsExtension
  extends RTCSetDescriptionParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
  dataChannels: IRTCDataChannel[];
  decryptionWasmMemory: WebAssembly.Memory;
  merkleWasmMemory: WebAssembly.Memory;
}

const webrtcSetDescriptionQuery: BaseQueryFn<
  RTCSetDescriptionParamsExtension,
  void,
  unknown
> = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    description,
    rtcConfig,
    peerConnections,
    iceCandidates,
    dataChannels,
    decryptionWasmMemory,
    merkleWasmMemory,
  },
  api,
) => {
  const { keyPair } = api.getState() as State;

  const decryptionModule = await libcrypto({
    wasmMemory: decryptionWasmMemory,
  });

  const merkleModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  const connectionIndex = peerConnections.findIndex(
    (peer) => peer.withPeerId === peerId,
  );

  const epc =
    connectionIndex > -1
      ? peerConnections[connectionIndex]
      : await handleConnectToPeer(
          {
            peerId,
            peerPublicKey,
            roomId,
            peerConnections,
            rtcConfig,
          },
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

  const ICE_CANDIDATES_LEN = iceCandidates.length;
  const purgeCandidates: number[] = [];
  for (let i = 0; i < ICE_CANDIDATES_LEN; i++) {
    if (iceCandidates[i].withPeerId !== peerId) continue;

    purgeCandidates.push(i);
    epc.iceCandidates.push(iceCandidates[i]);
  }
  const PURGE_CANDIDATES_LEN = purgeCandidates.length;
  for (let i = 0; i < PURGE_CANDIDATES_LEN; i++) {
    iceCandidates.splice(purgeCandidates[i], 1);
  }

  if (connectionIndex === -1) peerConnections.push(epc);

  const offerCollision =
    description.type === "offer" &&
    (epc.makingOffer || epc.signalingState !== "stable");
  const isPolite = keyPair.peerId < epc.withPeerId;
  console.log("Is polite is " + isPolite);
  const ignoreOffer = !isPolite && offerCollision;
  if (ignoreOffer) return { data: undefined };

  await epc.setRemoteDescription(description);
  if (description.type === "offer") {
    await epc.setLocalDescription();
    const answer = epc.localDescription;
    if (answer) {
      await api.dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "description",
            description: answer,
            fromPeerId: keyPair.peerId,
            fromPeerPublicKey: keyPair.publicKey,
            toPeerId: peerId,
            roomId,
          } as WebSocketMessageDescriptionSend,
        }),
      );
    }
  }
  // else {
  //   if (
  //     epc.signalingState !== "stable" &&
  //     (epc.signalingState === "have-local-offer" ||
  //       epc.signalingState === "have-remote-offer")
  //   ) {
  //     await epc.setRemoteDescription(description);
  //   } else {
  //     await handleQueuedIceCandidates(epc);
  //   }
  // }

  if (epc.connectionState === "connected" && connectionIndex > -1) {
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

  return { data: undefined };
};

export default webrtcSetDescriptionQuery;
