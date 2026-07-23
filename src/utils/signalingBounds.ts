export const MAX_SIGNALING_MESSAGE_CHARS = 512 * 1024;
export const MAX_SDP_CHARS = 256 * 1024;
export const MAX_ICE_CANDIDATE_CHARS = 4096;
export const MAX_ICE_FIELD_CHARS = 256;
export const MAX_SIGNALING_LABELS = 64;
export const MAX_DATA_CHANNEL_LABEL_CHARS = 193;

export const isBoundedDescription = (
  description: RTCSessionDescription | RTCSessionDescriptionInit,
): boolean =>
  (description.type === "offer" ||
    description.type === "answer" ||
    description.type === "pranswer" ||
    description.type === "rollback") &&
  typeof description.sdp === "string" &&
  description.sdp.length <= MAX_SDP_CHARS;

export const isBoundedIceCandidate = (
  candidate: RTCIceCandidateInit | RTCIceCandidate,
): boolean => {
  const value = candidate as RTCIceCandidateInit;
  return (
    typeof value.candidate === "string" &&
    value.candidate.length <= MAX_ICE_CANDIDATE_CHARS &&
    (value.sdpMid == null ||
      (typeof value.sdpMid === "string" &&
        value.sdpMid.length <= MAX_ICE_FIELD_CHARS)) &&
    (value.usernameFragment == null ||
      (typeof value.usernameFragment === "string" &&
        value.usernameFragment.length <= MAX_ICE_FIELD_CHARS))
  );
};

export const areBoundedDataChannelLabels = (labels: unknown): labels is string[] =>
  Array.isArray(labels) &&
  labels.length <= MAX_SIGNALING_LABELS &&
  labels.every(
    (label) =>
      typeof label === "string" &&
      label.length > 0 &&
      label.length <= MAX_DATA_CHANNEL_LABEL_CHARS,
  );
