import type { IRTCIceCandidate } from "./interfaces";

/** Bounds unauthenticated signaling state held before an SDP creates an edge. */
export const MAX_PENDING_ICE_PER_EDGE = 64;
export const MAX_PENDING_ICE_TOTAL = 1024;

export const normalizeIceCandidate = (
  candidate: RTCIceCandidateInit | RTCIceCandidate,
): RTCIceCandidateInit => {
  if (typeof (candidate as RTCIceCandidate).toJSON === "function")
    return (candidate as RTCIceCandidate).toJSON();

  const candidateInit = candidate as RTCIceCandidateInit;
  return {
    candidate: candidateInit.candidate,
    sdpMid: candidateInit.sdpMid,
    sdpMLineIndex: candidateInit.sdpMLineIndex,
    usernameFragment: candidateInit.usernameFragment,
  };
};

export const enqueuePendingIceCandidate = (
  queue: IRTCIceCandidate[],
  roomId: string,
  peerId: string,
  candidate: RTCIceCandidateInit,
): void => {
  let edgeCount = 0;
  for (let i = queue.length - 1; i >= 0; i--) {
    if (queue[i].roomId !== roomId || queue[i].withPeerId !== peerId) continue;
    edgeCount += 1;
    if (edgeCount >= MAX_PENDING_ICE_PER_EDGE) {
      queue.splice(i, 1);
      break;
    }
  }
  while (queue.length >= MAX_PENDING_ICE_TOTAL) queue.shift();
  queue.push({ ...candidate, roomId, withPeerId: peerId });
};

export const enqueueConnectionIceCandidate = (
  queue: RTCIceCandidateInit[],
  candidate: RTCIceCandidateInit,
): void => {
  while (queue.length >= MAX_PENDING_ICE_PER_EDGE) queue.shift();
  queue.push(candidate);
};

export const takePendingIceCandidates = (
  queue: IRTCIceCandidate[],
  roomId: string,
  peerId: string,
): RTCIceCandidateInit[] => {
  const selected: RTCIceCandidateInit[] = [];
  for (let i = queue.length - 1; i >= 0; i--) {
    const candidate = queue[i];
    if (candidate.roomId !== roomId || candidate.withPeerId !== peerId)
      continue;

    selected.unshift(candidate);
    queue.splice(i, 1);
  }
  return selected;
};

export const discardPendingIceCandidates = (
  queue: IRTCIceCandidate[],
  roomId: string,
  peerId: string,
): void => {
  for (let i = queue.length - 1; i >= 0; i--) {
    if (queue[i].roomId === roomId && queue[i].withPeerId === peerId)
      queue.splice(i, 1);
  }
};

/**
 * Abandon one room/peer SDP attempt without disturbing the same peer's ICE
 * candidates in another room.
 */
export const discardIceCandidatesForAttempt = (
  connectionQueue: RTCIceCandidateInit[],
  pendingQueue: IRTCIceCandidate[],
  roomId: string,
  peerId: string,
): void => {
  connectionQueue.length = 0;
  discardPendingIceCandidates(pendingQueue, roomId, peerId);
};
