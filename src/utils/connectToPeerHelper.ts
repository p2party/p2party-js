import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { setMakingOffer } from "../reducers/makingOfferSlice";
import { setPeerRoom } from "../reducers/peerRoomsSlice";

import { handleQueuedIceCandidates } from "../handlers/handleQueuedIceCandidates";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  RTCPeerConnectionParams,
} from "../api/webrtc/interfaces";
import type {
  WebSocketMessageDescriptionSend,
  WebSocketMessageCandidateSend,
  WebSocketMessagePeersRequest,
} from "../utils/interfaces";

const connectToPeerHelper = async (
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
      if (!rtcConfig)
        rtcConfig = {
          iceServers: [
            {
              urls: [
                "stun:stun.l.google.com:19302",
                "stun:stun1.l.google.com:19302",
              ],
            },
          ],
        };

      if (initiator)
        console.log(`You have initiated a peer connection with ${peerId}.`);

      const pc = new RTCPeerConnection(rtcConfig);
      const epc = pc as IRTCPeerConnection;
      epc.withPeerId = peerId;
      epc.withPeerPublicKey = peerPublicKey;
      // epc.polite = !initiator; // TODO send this to signaling for random number challenge
      epc.iceCandidates = [] as RTCIceCandidate[];

      api.dispatch(setMakingOffer({ withPeerId: peerId, makingOffer: false }));
      api.dispatch(setPeerRoom({ withPeerId: peerId, roomId }));

      epc.onnegotiationneeded = async () => {
        try {
          const { makingOffer } = api.getState() as State;
          const offerIndex = makingOffer.findIndex(
            (o) => o.withPeerId === epc.withPeerId,
          );
          const offering =
            offerIndex > -1 ? makingOffer[offerIndex].makingOffer : false;
          if (epc.signalingState !== "stable" || offering) return; // Don't initiate renegotiation if already negotiating or not stable

          if (initiator) {
            try {
              api.dispatch(
                setMakingOffer({ withPeerId: peerId, makingOffer: true }),
              );

              // const offer = await epc.createOffer();
              await epc.setLocalDescription(); // offer);
              const offer = epc.localDescription;
              if (offer) {
                api.dispatch(
                  signalingServerApi.endpoints.sendMessage.initiate({
                    content: {
                      type: "description",
                      description: offer,
                      fromPeerId: keyPair.peerId,
                      fromPeerPublicKey: keyPair.publicKey,
                      toPeerId: peerId,
                      roomId,
                    } as WebSocketMessageDescriptionSend,
                  }),
                );

                console.log(
                  `Negotiation was needed with ${peerId} and you sent a description ${offer.type}.`,
                );
              }
            } catch (error) {
              console.error(error);
              api.dispatch(
                setMakingOffer({ withPeerId: peerId, makingOffer: false }),
              );
            } finally {
              api.dispatch(
                setMakingOffer({ withPeerId: peerId, makingOffer: false }),
              );
            }
          }
        } catch (err) {
          console.error(err);
        }
      };

      epc.onicecandidate = ({ candidate }) => {
        if (candidate && candidate.candidate !== "") {
          console.log(`ICE candidate was sent to ${peerId}.`);

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
        console.error(`ICE candidate error with ${peerId}`);
        console.error(e);

        // api.dispatch(
        //   webrtcApi.endpoints.disconnectFromPeer.initiate({
        //     peerId: epc.withPeerId,
        //   }),
        // );
        // epc.restartIce();
      };

      epc.oniceconnectionstatechange = () => {
        console.log(
          `ICE candidate connection state with ${peerId} is ${epc.iceConnectionState}.`,
        );
        // if (epc.iceConnectionState === "failed") {
        //   epc.restartIce();
        // }
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

      epc.onconnectionstatechange = () => {
        if (
          epc.connectionState === "closed" ||
          epc.connectionState === "failed" ||
          epc.connectionState === "disconnected"
        ) {
          api.dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }),
          );
          console.error(
            `Connection with peer ${peerId} has ${epc.connectionState}.`,
          );
        } else {
          console.log(
            `Connection status with peer ${peerId} is ${epc.connectionState}.`,
          );

          if (epc.connectionState === "connected" && !initiator) {
            const { signalingServer } = api.getState() as State;
            if (signalingServer.isConnected) {
              api.dispatch(
                signalingServerApi.endpoints.sendMessage.initiate({
                  content: {
                    type: "peers",
                    fromPeerId: keyPair.peerId,
                    roomId,
                  } as WebSocketMessagePeersRequest,
                }),
              );
            }
          }
        }
      };

      // epc.ondatachannel = (e: RTCDataChannelEvent) => {
      //   console.log(e);
      //   api.dispatch(
      //     webrtcApi.endpoints.openChannel.initiate({
      //       channel: e.channel,
      //       roomId,
      //       withPeers: [
      //         { peerId: epc.withPeerId, peerPublicKey: epc.withPeerPublicKey },
      //       ],
      //     }),
      //   );
      // };

      resolve(epc);
    } catch (error) {
      reject(error);
    }
  });
};

export default connectToPeerHelper;
