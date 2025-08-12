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
  // WebSocketMessagePeersRequest,
} from "../utils/interfaces";

export const handleConnectToPeer = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    initiator,
    rtcConfig,
  }: RTCPeerConnectionParams,
  api: BaseQueryApi,
): Promise<IRTCPeerConnection> => {
  return new Promise((resolve, reject) => {
    try {
      const { keyPair } = api.getState() as State;

      if (!initiator) initiator = true;
      if (!rtcConfig) rtcConfig = defaultRTCConfig;
      console.log(rtcConfig);
      if (initiator)
        console.log(`You are initiating a peer connection with ${peerId}.`);

      if (!isUUID(peerId)) reject(new Error("PeerId is not a valid uuidv4"));
      if (peerPublicKey.length !== 64)
        reject(new Error("Peer public key is not a valid length"));

      const pc = new RTCPeerConnection(rtcConfig);
      const epc = pc as IRTCPeerConnection;
      epc.withPeerId = peerId;
      epc.withPeerPublicKey = peerPublicKey;
      epc.roomIds = [roomId];
      epc.iceCandidates = [] as RTCIceCandidate[];

      // let makingOffer = false;

      epc.onnegotiationneeded = async () => {
        if (epc.signalingState === "stable") {
          // if (initiator) {
          try {
            // makingOffer = true;
            await epc.setLocalDescription();

            if (epc.localDescription) {
              api.dispatch(
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
            // makingOffer = false;
          }
          // }
        }
      };

      epc.onicecandidate = ({ candidate }) => {
        if (candidate && candidate.candidate !== "") {
          api.dispatch(
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

      epc.oniceconnectionstatechange = () => {
        if (epc.iceConnectionState === "failed") {
          const { signalingServer } = api.getState() as State;
          if (
            !signalingServer.isConnected &&
            !signalingServer.isEstablishingConnection &&
            signalingServer.serverUrl.length > 0
          ) {
            api.dispatch(
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
          console.error(
            `Connection with peer ${peerId} has ${epc.connectionState}.`,
          );

          await api.dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }),
          );
        } else {
          console.log(
            `Connection status with peer ${peerId} is ${epc.connectionState}.`,
          );

          if (epc.connectionState === "connected") {
            api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));

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
      reject(error);
    }
  });
};
