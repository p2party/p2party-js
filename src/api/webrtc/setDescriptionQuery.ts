import { debugLog } from "../../utils/debug";
import signalingServerApi from "../signalingServerApi";

import { getRoomPeerMutex } from "./negotiationLock";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import {
  discardIceCandidatesForAttempt,
  takePendingIceCandidates,
} from "./pendingIceCandidates";
import { isIdentityInitiator } from "../../utils/identityRole";
import { PROTOCOL_VERSION } from "../../utils/constants";

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
  return getRoomPeerMutex(roomId, peerId).runExclusive(async () => {
    const { keyPair } = api.getState() as State;

    const connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
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
        try {
          const channel = await handleOpenChannel(
            {
              channel: e.channel,
              epc,
              roomId: epc.roomId,
              dataChannels,
              incoming: true,
            },
            api,
          );
          if (channel.label === "main") epc.mainChannel = channel;
        } catch (error) {
          console.error("Rejected incoming DataChannel:", error);
        }
      };
    }

    const offerCollision =
      description.type === "offer" &&
      (epc.makingOffer || epc.signalingState !== "stable");
    // Polite peer has the lexicographically smaller peerId
    const isPolite = keyPair.peerId < epc.withPeerId;
    const ignoreOffer = !isPolite && offerCollision;
    epc.ignoreOffer = ignoreOffer;

    const discardIceForAttempt = (): void => {
      discardIceCandidatesForAttempt(
        epc.iceCandidates,
        iceCandidates,
        roomId,
        peerId,
      );
    };

    if (ignoreOffer) {
      discardIceForAttempt();
      return { data: undefined };
    }

    // Polite peer must rollback its local description before accepting remote offer
    if (offerCollision && isPolite) {
      try {
        await epc.setLocalDescription({ type: "rollback" });
        debugLog(`Polite peer rolled back local description for ${peerId}`);
      } catch (e) {
        console.error(`Failed to rollback for ${peerId}:`, e);
      }
    }

    epc.iceCandidates.push(
      ...takePendingIceCandidates(iceCandidates, roomId, peerId),
    );

    if (findRoomPeerConnectionIndex(peerConnections, roomId, peerId) === -1)
      peerConnections.push(epc);

    if (epc.signalingState === "closed") {
      discardIceForAttempt();
      return { data: undefined };
    }

    if (
      description.type === "answer" &&
      epc.signalingState !== "have-local-offer"
    ) {
      console.warn(
        `Ignoring stale answer from ${peerId} in signaling state ${epc.signalingState}`,
      );
      discardIceForAttempt();
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
          discardIceForAttempt();
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
            discardIceForAttempt();
            return { data: undefined };
          }
        } else {
          console.error(`setRemoteDescription failed for ${peerId}:`, e);
          discardIceForAttempt();
          return { data: undefined };
        }
      }
      if (description.type === "offer") {
        try {
          await epc.setLocalDescription();
        } catch (error) {
          console.error(`setLocalDescription failed for ${peerId}:`, error);
          discardIceForAttempt();
          return { data: undefined };
        }
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
                protocolVersion: PROTOCOL_VERSION,
              } as WebSocketMessageDescriptionSend,
            }),
          );
        }
      }
    }

    if (
      epc.connectionState === "connected" &&
      connectionIndex > -1 &&
      isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey) &&
      (!epc.mainChannel ||
        epc.mainChannel.readyState === "closing" ||
        epc.mainChannel.readyState === "closed")
    ) {
      const channel = epc.createDataChannel("main", {
        // Handshake HELLO/CONFIRM frames are a strict transcript sequence.
        ordered: true,
        protocol: "raw",
      });
      epc.mainChannel = await handleOpenChannel(
        { channel, epc, roomId: epc.roomId, dataChannels },
        api,
      );
    }

    return { data: undefined };
  });
};

export default webrtcSetDescriptionQuery;
