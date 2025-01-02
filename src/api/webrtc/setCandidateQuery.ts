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
      const cand = new RTCIceCandidate(candidate);

      if (!epc.remoteDescription || epc.signalingState !== "stable") {
        // if (cand.usernameFragment !== candidate.usernameFragment)
        epc.iceCandidates.push(cand);
      } else {
        try {
          // if (cand.usernameFragment !== candidate.usernameFragment)
          await epc.addIceCandidate(cand);
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
