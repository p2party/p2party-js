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

const normalizeCandidate = (
  candidate: RTCIceCandidateInit | RTCIceCandidate,
): RTCIceCandidateInit => {
  if (typeof (candidate as RTCIceCandidate).toJSON === "function") {
    return (candidate as RTCIceCandidate).toJSON();
  }

  const candidateInit = candidate as RTCIceCandidateInit;
  return {
    candidate: candidateInit.candidate,
    sdpMid: candidateInit.sdpMid,
    sdpMLineIndex: candidateInit.sdpMLineIndex,
    usernameFragment: candidateInit.usernameFragment,
  };
};

const webrtcSetIceCandidateQuery: BaseQueryFn<
  RTCSetCandidateParamsExtention,
  undefined
> = async ({ peerId, candidate, peerConnections, iceCandidates }, api) => {
  const { keyPair } = api.getState() as State;
  const candidateInit = normalizeCandidate(candidate);

  const connectionIndex = peerConnections.findIndex(
    (peer) => peer.withPeerId === peerId,
  );

  if (connectionIndex > -1) {
    const epc = peerConnections[connectionIndex];
    if (epc.ignoreOffer) return { data: undefined };

    if (!epc.remoteDescription || epc.signalingState !== "stable") {
      epc.iceCandidates.push(candidateInit);
    } else {
      try {
        await epc.addIceCandidate(candidateInit);
      } catch {
        const offerCollision =
          epc.makingOffer || (epc.signalingState as string) !== "stable";
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
      ...candidateInit,
      withPeerId: peerId,
    } as IRTCIceCandidate);
  }

  return { data: undefined };
};

export default webrtcSetIceCandidateQuery;
