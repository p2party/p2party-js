const SDP_ICE_UFRAG = /(?:^|\r?\n)a=ice-ufrag:([^\r\n]+)/g;
const CANDIDATE_ICE_UFRAG = /(?:^|\s)ufrag\s+([^\s]+)/i;

/**
 * Return every ICE username fragment advertised by the active remote SDP.
 * Multiple values are legitimate when media sections are not bundled.
 */
export const remoteIceUsernameFragments = (
  description: RTCSessionDescription | RTCSessionDescriptionInit | null,
): Set<string> => {
  const fragments = new Set<string>();
  const sdp = description?.sdp;
  if (!sdp) return fragments;

  for (const match of sdp.matchAll(SDP_ICE_UFRAG)) {
    const fragment = match[1].trim();
    if (fragment) fragments.add(fragment);
  }
  return fragments;
};

/**
 * Prefer the structured usernameFragment, but recover the optional `ufrag`
 * candidate extension when signaling supplied only a candidate string.
 */
export const candidateIceUsernameFragment = (
  candidate: RTCIceCandidateInit,
): string | null => {
  const structured = candidate.usernameFragment?.trim();
  if (structured) return structured;

  const fromCandidate = candidate.candidate?.match(CANDIDATE_ICE_UFRAG)?.[1];
  return fromCandidate?.trim() || null;
};

/**
 * Reject a candidate that explicitly names an ICE generation absent from the
 * active remote description. Candidates without a ufrag remain acceptable:
 * older signaling payloads omit it and the browser can still route them by
 * sdpMid/sdpMLineIndex.
 */
export const candidateMatchesRemoteIceGeneration = (
  candidate: RTCIceCandidateInit,
  remoteDescription: RTCSessionDescription | RTCSessionDescriptionInit | null,
): boolean => {
  const activeFragments = remoteIceUsernameFragments(remoteDescription);
  if (activeFragments.size === 0) return true;

  const candidateFragment = candidateIceUsernameFragment(candidate);
  return candidateFragment === null || activeFragments.has(candidateFragment);
};
