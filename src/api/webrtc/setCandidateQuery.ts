import webrtcApi from ".";
// import signalingServerApi from "../signalingServerApi";

import { getRoomPeerMutex } from "./negotiationLock";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import {
  enqueueConnectionIceCandidate,
  enqueuePendingIceCandidate,
  normalizeIceCandidate,
} from "./pendingIceCandidates";
import { candidateMatchesRemoteIceGeneration } from "./iceGeneration";
import { repairIceTransportAfterCandidateFailure } from "./iceRepair";

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
  undefined
> = async (
  { peerId, roomId, candidate, peerConnections, iceCandidates },
  api,
) => {
  return getRoomPeerMutex(roomId, peerId).runExclusive(async () => {
    const { keyPair } = api.getState() as State;
    const candidateInit = normalizeIceCandidate(candidate);

    const connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    if (connectionIndex > -1) {
      const epc = peerConnections[connectionIndex];
      if (epc.ignoreOffer) return { data: undefined };

      if (!epc.remoteDescription || epc.signalingState !== "stable") {
        enqueueConnectionIceCandidate(epc.iceCandidates, candidateInit);
      } else if (
        candidateMatchesRemoteIceGeneration(
          candidateInit,
          epc.remoteDescription,
        )
      ) {
        try {
          await epc.addIceCandidate(candidateInit);
        } catch {
          const offerCollision =
            epc.makingOffer || (epc.signalingState as string) !== "stable";
          const isPolite = keyPair.peerId < epc.withPeerId;
          const ignoreOffer = !isPolite && offerCollision;
          // if (!ignoreOffer) throw error;

          if (!ignoreOffer) {
            await repairIceTransportAfterCandidateFailure(epc, async () => {
              // A later room peer update creates a fresh transport. This
              // callback runs only when in-place restart is impossible, never
              // before restartIce().
              epc.iceCandidates.length = 0;
              await api.dispatch(
                webrtcApi.endpoints.disconnectFromPeer.initiate({
                  peerId: epc.withPeerId,
                  roomId: epc.roomId,
                }),
              );
            });
          }
        }
      }

      // An explicit ufrag absent from the active remote SDP belongs to an
      // abandoned offer/answer or pre-restart generation and is dropped.
    } else {
      enqueuePendingIceCandidate(iceCandidates, roomId, peerId, candidateInit);
    }

    return { data: undefined };
  });
};

export default webrtcSetIceCandidateQuery;
