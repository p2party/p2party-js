import signalingServerApi from "../signalingServerApi";

import { getPeerMutex } from "./negotiationLock";

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

export interface RTCSetDescriptionParamsExtension extends RTCSetDescriptionParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
  dataChannels: IRTCDataChannel[];
}

const webrtcSetDescriptionQuery: BaseQueryFn<
  RTCSetDescriptionParamsExtension,
  undefined
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
  },
  api,
) => {
  return getPeerMutex(peerId).runExclusive(async () => {
    const { keyPair } = api.getState() as State;

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

    if (
      connectionIndex === -1 ||
      peerConnections[connectionIndex].ondatachannel == undefined
    ) {
      epc.ondatachannel = async (e: RTCDataChannelEvent) => {
        await handleOpenChannel(
          {
            channel: e.channel,
            epc,
            roomId,
            dataChannels,
          },
          api,
        );
      };
    }

    const offerCollision =
      description.type === "offer" &&
      (epc.makingOffer || epc.signalingState !== "stable");
    // Polite peer has the lexicographically smaller peerId
    const isPolite = keyPair.peerId < epc.withPeerId;
    const ignoreOffer = !isPolite && offerCollision;
    epc.ignoreOffer = ignoreOffer;

    if (ignoreOffer) {
      for (let i = iceCandidates.length - 1; i >= 0; i--) {
        if (iceCandidates[i].withPeerId === peerId) iceCandidates.splice(i, 1);
      }
      return { data: undefined };
    }

    // Polite peer must rollback its local description before accepting remote offer
    if (offerCollision && isPolite) {
      try {
        await epc.setLocalDescription({ type: "rollback" });
        console.log(`Polite peer rolled back local description for ${peerId}`);
      } catch (e) {
        console.error(`Failed to rollback for ${peerId}:`, e);
      }
    }

    const ICE_CANDIDATES_LEN = iceCandidates.length;
    const purgeCandidates: number[] = [];
    for (let i = 0; i < ICE_CANDIDATES_LEN; i++) {
      if (iceCandidates[i].withPeerId !== peerId) continue;

      purgeCandidates.push(i);
      epc.iceCandidates.push(iceCandidates[i]);
    }
    const PURGE_CANDIDATES_LEN = purgeCandidates.length;
    for (let i = PURGE_CANDIDATES_LEN - 1; i >= 0; i--) {
      iceCandidates.splice(purgeCandidates[i], 1);
    }

    if (connectionIndex === -1) peerConnections.push(epc);

    if (epc.signalingState === "closed") {
      return { data: undefined };
    }

    if (
      description.type === "answer" &&
      epc.signalingState !== "have-local-offer"
    ) {
      console.warn(
        `Ignoring stale answer from ${peerId} in signaling state ${epc.signalingState}`,
      );
      return { data: undefined };
    }

    {
      try {
        await epc.setRemoteDescription(description);
      } catch (e: unknown) {
        // Handle ICE restart mismatch - if we receive an offer with new ICE credentials
        // but didn't request a restart, we need to accept the restart gracefully
        const error = e as { message?: string };
        if (
          description.type === "answer" &&
          error.message?.includes("Called in wrong state")
        ) {
          console.warn(`Ignoring late answer from ${peerId}: ${error.message}`);
          return { data: undefined };
        }

        if (error.message?.includes("ICE restart")) {
          console.warn(
            `ICE restart mismatch with ${peerId}, accepting remote restart`,
          );
          try {
            // Rollback and accept the restart
            if (epc.signalingState !== "stable") {
              await epc.setLocalDescription({ type: "rollback" });
            }
            await epc.setRemoteDescription(description);
          } catch (retryError) {
            console.error(
              `Failed to handle ICE restart for ${peerId}:`,
              retryError,
            );
            return { data: undefined };
          }
        } else {
          console.error(`setRemoteDescription failed for ${peerId}:`, e);
          return { data: undefined };
        }
      }
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
    }

    if (epc.connectionState === "connected" && connectionIndex > -1) {
      await handleOpenChannel(
        {
          channel: "main",
          epc,
          roomId,
          dataChannels,
        },
        api,
      );
    }

    return { data: undefined };
  });
};

export default webrtcSetDescriptionQuery;
