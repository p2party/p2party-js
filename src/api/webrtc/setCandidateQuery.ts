import webrtcApi from ".";
// import signalingServerApi from "../signalingServerApi";

import { runRoomPeerExclusive } from "./negotiationLock";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import {
  discardIceCandidatesForAttempt,
  enqueueConnectionIceCandidate,
  enqueuePendingIceCandidate,
  normalizeIceCandidate,
} from "./pendingIceCandidates";
import { candidateMatchesRemoteIceGeneration } from "./iceGeneration";
import { repairIceTransportAfterCandidateFailure } from "./iceRepair";
import { awaitPcOperation } from "./settleOnClose";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  RTCSetCandidateParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
} from "./interfaces";
import type { State } from "../../store";

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
  return runRoomPeerExclusive(roomId, peerId, async () => {
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
        // The add is awaited through awaitPcOperation: close() aborts an
        // in-flight addIceCandidate without ever settling its promise, and a
        // plain await on that would hold this room/peer mutex — and, through
        // the socket's serial ingress queue, every later signaling frame —
        // forever.
        let addFailed: boolean;
        try {
          const outcome = await awaitPcOperation(
            epc,
            epc.addIceCandidate(candidateInit),
            { name: `addIceCandidate(${roomId}, ${peerId})` },
          );
          if (outcome === "closed") {
            // The transport is gone and its own close path owns the follow-up.
            // Everything buffered for this attempt died with it; another
            // room's candidates for the same peer are untouched.
            discardIceCandidatesForAttempt(
              epc.iceCandidates,
              iceCandidates,
              roomId,
              peerId,
            );
            return { data: undefined };
          }
          // A live transport that never answered is a failed add.
          addFailed = outcome === "timeout";
        } catch {
          addFailed = true;
        }

        if (addFailed) {
          const offerCollision =
            epc.makingOffer || (epc.signalingState as string) !== "stable";
          const isPolite = keyPair.peerId < epc.withPeerId;
          const ignoreOffer = !isPolite && offerCollision;
          // if (!ignoreOffer) throw error;

          if (!ignoreOffer) {
            // A correlated credential response is delivered by this same
            // serial ingress queue. Release it before waiting for that response.
            if (epc.iceConnectionState === "failed")
              void repairIceTransportAfterCandidateFailure(epc, async () => {
                if (!peerConnections.includes(epc)) return;
                epc.iceCandidates.length = 0;
                await api.dispatch(
                  webrtcApi.endpoints.disconnectFromPeer.initiate(
                    {
                      peerId: epc.withPeerId,
                      roomId: epc.roomId,
                    },
                    { track: false },
                  ),
                );
              }).catch((error: unknown) =>
                console.warn("p2party: candidate repair failed", error),
              );
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
