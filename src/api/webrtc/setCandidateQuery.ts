import webrtcApi from ".";
// import signalingServerApi from "../signalingServerApi";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  RTCSetCandidateParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
} from "./interfaces";
import type { State } from "../../store";
// import { isUUID } from "class-validator";

export interface RTCSetCandidateParamsExtention extends RTCSetCandidateParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
}

const webrtcSetIceCandidateQuery: BaseQueryFn<
  RTCSetCandidateParamsExtention,
  void,
  unknown
> = async ({ peerId, candidate, peerConnections, iceCandidates }, api) => {
  const { keyPair } = api.getState() as State;

  const connectionIndex = peerConnections.findIndex(
    (peer) => peer.withPeerId === peerId,
  );

  if (connectionIndex > -1) {
    const epc = peerConnections[connectionIndex];
    const cand = new RTCIceCandidate(candidate);
    if (!epc.remoteDescription || epc.signalingState !== "stable") {
      epc.iceCandidates.push(cand);
    } else {
      try {
        await epc.addIceCandidate(cand);
      } catch (error) {
        const offerCollision =
          epc.makingOffer || epc.signalingState !== "stable";
        const isPolite = keyPair.peerId < epc.withPeerId;
        const ignoreOffer = !isPolite && offerCollision;
        // if (!ignoreOffer) throw error;

        if (!ignoreOffer) {
          // console.error(error);
          await api.dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate({
              peerId: epc.withPeerId,
            }),
          );

          epc.restartIce();
        }
      }
    }

    // if (cand.usernameFragment === candidate.usernameFragment) {
    //   await api.dispatch(
    //     webrtcApi.endpoints.disconnectFromPeer.initiate({
    //       peerId: epc.withPeerId,
    //     }),
    //   );
    //
    //   const { commonState, keyPair } = api.getState() as State;
    //   if (isUUID(keyPair.peerId) && commonState.currentRoomUrl.length === 64) {
    //     await api.dispatch(
    //       signalingServerApi.endpoints.sendMessage.initiate({
    //         content: {
    //           type: "room",
    //           fromPeerId: keyPair.peerId,
    //           roomUrl: commonState.currentRoomUrl,
    //         },
    //       }),
    //     );
    //   }
    //
    //   return { data: undefined };
    // }

    // if (!epc.remoteDescription || epc.signalingState !== "stable") {
    //   // const receivers = epc.getReceivers();
    //   //
    //   // for (const receiver of receivers) {
    //   //   // const parameters = receiver.getParameters();
    //   //   const parameters = receiver.transport?.iceTransport.getRemoteParameters();
    //   //
    //   //   if (parameters.usernameFragment === candidate.usernameFragment) {
    //   //     return { data: undefined };
    //   //   }
    //   // }
    //
    //   epc.iceCandidates.push(cand);
    // } else {
    //   await epc.addIceCandidate(cand);
    // }
  } else {
    iceCandidates.push({
      ...candidate,
      withPeerId: peerId,
    });
  }

  return { data: undefined };
};

export default webrtcSetIceCandidateQuery;
