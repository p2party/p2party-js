// Pure SDP DTLS-fingerprint parsing. Kept store-free so both the handshake
// transcript (handleHandshake) and the signaling path (remote-transport change
// detection) can share one definition of "the certificate this SDP declares".
const FINGERPRINT_RE = /a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/;

/**
 * Raw bytes of the `a=fingerprint:sha-256 XX:XX:...` line in an SDP blob.
 * Throws if no sha-256 fingerprint attribute is present, or if the one found
 * doesn't decode to exactly 32 bytes.
 */
export const parseFingerprintFromSdp = (sdp: string): Uint8Array => {
  const match = FINGERPRINT_RE.exec(sdp);
  if (!match) throw new Error("No sha-256 DTLS fingerprint found in SDP");

  const bytes = match[1].split(":").map((byte) => parseInt(byte, 16));
  if (bytes.length !== 32 || bytes.some((b) => Number.isNaN(b)))
    throw new Error("Malformed sha-256 DTLS fingerprint in SDP");

  return Uint8Array.from(bytes);
};
