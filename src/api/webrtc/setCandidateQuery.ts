import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  RTCSetCandidateParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
} from "./interfaces";

export interface RTCSetCandidateParamsExtention extends RTCSetCandidateParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
}

const webrtcSetIceCandidateQuery: BaseQueryFn<
  RTCSetCandidateParamsExtention,
  void,
  unknown
> = async ({ peerId, candidate, peerConnections, iceCandidates }) => {
  try {
    const connectionIndex = peerConnections.findIndex(
      (peer) => peer.withPeerId === peerId,
    );

    if (connectionIndex > -1) {
      const epc = peerConnections[connectionIndex];
      if (!epc.remoteDescription || epc.signalingState !== "stable") {
        epc.iceCandidates.push(candidate);
      } else {
        try {
          await epc.addIceCandidate(candidate);
        } catch (error) {
          throw error;
        }
      }
    } else {
      iceCandidates.push({
        ...candidate,
        withPeerId: peerId,
      });
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcSetIceCandidateQuery;
