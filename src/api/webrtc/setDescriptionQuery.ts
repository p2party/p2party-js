import signalingServerApi from "../signalingServerApi";

import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";
import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { handleQueuedIceCandidates } from "../../handlers/handleQueuedIceCandidates";

import { setMakingOffer } from "../../reducers/makingOfferSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCSetDescriptionParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
} from "./interfaces";
import type { WebSocketMessageDescriptionSend } from "../../utils/interfaces";
import libcrypto from "../../cryptography/libcrypto";

export interface RTCSetDescriptionParamsExtension
  extends RTCSetDescriptionParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
  dataChannels: IRTCDataChannel[];
  encryptionWasmMemory: WebAssembly.Memory;
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
    encryptionWasmMemory,
  },
  api,
) => {
  try {
    const { keyPair } = api.getState() as State;
    const encryptionModule = await libcrypto({
      wasmMemory: encryptionWasmMemory,
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
              initiator: false,
              rtcConfig,
            },
            api,
          );

    epc.ondatachannel = async (e: RTCDataChannelEvent) => {
      await handleOpenChannel(
        { channel: e.channel, epc, dataChannels, encryptionModule },
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

    let offering = false;
    const { makingOffer } = api.getState() as State;
    const offerIndex = makingOffer.findIndex(
      (o) => o.withPeerId === epc.withPeerId,
    );
    if (offerIndex > -1) offering = makingOffer[offerIndex].makingOffer;

    const offerCollision = description.type === "offer" && offering;
    if (offerCollision && connectionIndex > -1) return { data: undefined };

    if (offerCollision) {
      api.dispatch(
        setMakingOffer({ withPeerId: epc.withPeerId, makingOffer: false }),
      );
      await epc.setLocalDescription({ type: "rollback" });
      await epc.setRemoteDescription(description);
      await epc.setLocalDescription();
      const answer = epc.localDescription;

      if (answer) {
        api.dispatch(
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
    } else if (description.type === "offer") {
      await epc.setRemoteDescription(description);
      await epc.setLocalDescription();
      const answer = epc.localDescription;

      if (answer) {
        api.dispatch(
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
    } else if (description.type === "answer") {
      if (
        epc.signalingState === "have-local-offer" ||
        epc.signalingState === "have-remote-offer"
      ) {
        await epc.setRemoteDescription(description);
      } else {
        await handleQueuedIceCandidates(epc);
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcSetDescriptionQuery;
