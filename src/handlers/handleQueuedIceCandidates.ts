import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

export const handleQueuedIceCandidates = async (epc: IRTCPeerConnection) => {
  try {
    while (
      epc.iceCandidates.length > 0 &&
      epc.signalingState === "stable" &&
      epc.remoteDescription
    ) {
      const candidate = epc.iceCandidates.shift();
      if (candidate) await epc.addIceCandidate(candidate);
    }
  } catch (error) {
    throw error;
  }
};
