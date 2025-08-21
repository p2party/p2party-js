import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

export const handleQueuedIceCandidates = async (epc: IRTCPeerConnection) => {
  while (
    epc.iceCandidates.length > 0 &&
    epc.signalingState === "stable" &&
    epc.remoteDescription
  ) {
    const candidate = epc.iceCandidates.shift();
    if (candidate) {
      const cand = new RTCIceCandidate(candidate);
      if (cand.usernameFragment !== candidate.usernameFragment)
        await epc.addIceCandidate(cand);
    }
  }
};
