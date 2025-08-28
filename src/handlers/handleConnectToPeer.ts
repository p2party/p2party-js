import { isUUID } from "class-validator";

import { handleQueuedIceCandidates } from "./handleQueuedIceCandidates";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { defaultRTCConfig, setPeer } from "../reducers/roomSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  RTCPeerConnectionParams,
} from "../api/webrtc/interfaces";
import type {
  WebSocketMessageDescriptionSend,
  WebSocketMessageCandidateSend,
} from "../utils/interfaces";

export interface IRTCPeerConnectionParams extends RTCPeerConnectionParams {
  peerConnections: IRTCPeerConnection[];
}

export const handleConnectToPeer = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    peerConnections,
    rtcConfig,
  }: IRTCPeerConnectionParams,
  api: BaseQueryApi,
): Promise<IRTCPeerConnection> => {
  return new Promise((resolve, reject) => {
    try {
      const { keyPair } = api.getState() as State;

      rtcConfig ??= defaultRTCConfig;

      if (!isUUID(peerId)) reject(new Error("PeerId is not a valid uuidv4"));
      if (peerPublicKey.length !== 64)
        reject(new Error("Peer public key is not a valid length"));

      const peerIndex = peerConnections.findIndex(
        (p) => p.withPeerId === peerId,
      );
      if (peerIndex > -1) {
        const roomIndex = peerConnections[peerIndex].roomIds.findIndex(
          (r) => r === roomId,
        );
        if (roomIndex === -1) peerConnections[peerIndex].roomIds.push(roomId);

        resolve(peerConnections[peerIndex]);
      }

      const pc = new RTCPeerConnection(rtcConfig);
      const epc = pc as IRTCPeerConnection;
      epc.withPeerId = peerId;
      epc.withPeerPublicKey = peerPublicKey;
      epc.makingOffer = false;
      epc.roomIds = [roomId];
      epc.iceCandidates = [] as RTCIceCandidate[];

      epc.onnegotiationneeded = async () => {
        try {
          epc.makingOffer = true;
          await epc.setLocalDescription();

          if (epc.localDescription) {
            await api.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "description",
                  description: epc.localDescription,
                  fromPeerId: keyPair.peerId,
                  fromPeerPublicKey: keyPair.publicKey,
                  toPeerId: peerId,
                  roomId,
                } as WebSocketMessageDescriptionSend,
              }),
            );

            console.log(
              `Negotiation was needed with ${peerId} and you sent a description ${epc.localDescription.type}.`,
            );
          }
        } catch (error) {
          console.error(error);
        } finally {
          epc.makingOffer = false;
        }
      };

      epc.onicecandidate = async ({ candidate }) => {
        if (candidate && candidate.candidate !== "") {
          await api.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "candidate",
                candidate,
                fromPeerId: keyPair.peerId,
                toPeerId: peerId,
                roomId,
              } as WebSocketMessageCandidateSend,
            }),
          );
        }
      };

      epc.onicecandidateerror = (e) => {
        // epc.restartIce();
        console.error(e);
      };

      epc.oniceconnectionstatechange = async () => {
        if (epc.iceConnectionState === "failed") {
          const { signalingServer } = api.getState() as State;
          if (
            !signalingServer.isConnected &&
            !signalingServer.isEstablishingConnection &&
            signalingServer.serverUrl.length > 0
          ) {
            await api.dispatch(
              signalingServerApi.endpoints.connectWebSocket.initiate(
                signalingServer.serverUrl,
              ),
            );
          }

          epc.restartIce();
        }

        console.log(
          `ICE candidate connection state with ${peerId} is ${epc.iceConnectionState}.`,
        );
      };

      epc.onicegatheringstatechange = () => {
        console.log(
          `ICE gathering state with ${peerId} is ${epc.iceGatheringState}.`,
        );
      };

      epc.onsignalingstatechange = async () => {
        console.log(`Signaling state with ${peerId} is ${epc.signalingState}.`);

        if (epc.signalingState === "stable" && epc.remoteDescription)
          await handleQueuedIceCandidates(epc);
      };

      epc.onconnectionstatechange = async () => {
        if (
          epc.connectionState === "closed" ||
          epc.connectionState === "failed" ||
          epc.connectionState === "disconnected"
        ) {
          await api.dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }),
          );

          console.error(
            `Connection with peer ${peerId} has ${epc.connectionState}.`,
          );
        } else {
          if (epc.connectionState === "connected") {
            api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));

            console.log(
              `Connection status with peer ${peerId} is ${epc.connectionState}.`,
            );

            // if (!initiator) {
            //   const { signalingServer } = api.getState() as State;
            //   if (signalingServer.isConnected) {
            //     api.dispatch(
            //       signalingServerApi.endpoints.sendMessage.initiate({
            //         content: {
            //           type: "peers",
            //           fromPeerId: keyPair.peerId,
            //           roomId,
            //         } as WebSocketMessagePeersRequest,
            //       }),
            //     );
            //   }
            // }
          }
        }
      };

      resolve(epc);
    } catch (error) {
      reject(error as Error);
    }
  });
};
