import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import { candidateMatchesRemoteIceGeneration } from "../api/webrtc/iceGeneration";

export const handleQueuedIceCandidates = async (epc: IRTCPeerConnection) => {
  while (
    epc.iceCandidates.length > 0 &&
    epc.signalingState === "stable" &&
    epc.remoteDescription
  ) {
    const candidate = epc.iceCandidates.shift();
    if (
      candidate &&
      candidateMatchesRemoteIceGeneration(candidate, epc.remoteDescription)
    ) {
      try {
        await epc.addIceCandidate(candidate);
      } catch (error) {
        // One malformed/unusable candidate must not strand the rest of the
        // active ICE generation. The candidate has already been removed from
        // the queue, so drop only that item and continue draining.
        console.warn("Could not add queued ICE candidate:", error);
      }
    }
  }
};
