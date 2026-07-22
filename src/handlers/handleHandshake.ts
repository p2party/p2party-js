import { PQ_TAG } from "../utils/constants";
import { uint8ArrayToHex } from "../utils/uint8array";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

export interface ChannelInputParams {
  channelId: Uint8Array;
  ikInitiator: Uint8Array;
  ikResponder: Uint8Array;
  fpInitiator: Uint8Array;
  fpResponder: Uint8Array;
}

/**
 * CPace channel-input transcript (spec §5): CI = channel-id ‖ IK_a ‖ IK_b ‖
 * fp_a ‖ fp_b ‖ PQ_TAG, with a = initiator, b = responder. Both peers build a
 * byte-identical CI because they agree on the initiator role (Task 4). Binding
 * both identity keys + both DTLS fingerprints is what makes a swapped-cert
 * MITM fail the key-confirmation MAC.
 *
 * Deliberately synchronous (unlike the project's async concatUint8Arrays
 * helper in utils/uint8array.ts, which yields to the microtask queue for
 * parity with other WASM-backed helpers): CI construction is pure
 * byte-copying with no WASM/IndexedDB involved, and callers build it inline
 * while assembling the CPace transcript.
 */
export const buildChannelInput = (p: ChannelInputParams): Uint8Array => {
  const parts = [
    p.channelId,
    p.ikInitiator,
    p.ikResponder,
    p.fpInitiator,
    p.fpResponder,
    PQ_TAG,
  ];

  let len = 0;
  for (const part of parts) len += part.length;

  const ci = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    ci.set(part, offset);
    offset += part.length;
  }

  return ci;
};

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

const normalizeFingerprintHex = (fp: string): string =>
  fp.replace(/:/g, "").toLowerCase();

// Shape of the entries RTCStatsReport.forEach hands back that this helper
// reads. RTCStatsReport's own DOM typing declares its forEach value as `any`
// (there is no per-type stats union in lib.dom.d.ts), so this local interface
// is what keeps the body of verifyDtlsFingerprints free of `any`.
interface RTCStatEntry {
  type: string;
  id?: string;
  localCertificateId?: string;
  remoteCertificateId?: string;
  fingerprint?: string;
}

/**
 * Post-connect DTLS binding check (spec §5): the fingerprint declared in the
 * SDP (and bound into the CPace channel-input via buildChannelInput) must
 * equal the live certificate reported by getStats(). A disagreement means the
 * DTLS transport terminates on a different certificate than the one that was
 * authenticated by the handshake — i.e. a signaling server (or any on-path
 * attacker) swapped the SDP fingerprint/cert after the CPace transcript was
 * bound. This is the actual MITM tripwire, so it THROWS (never returns a
 * boolean, never logs-and-continues) — the caller must abort the channel.
 */
export const verifyDtlsFingerprints = async (
  epc: IRTCPeerConnection,
): Promise<void> => {
  const localSdp = epc.localDescription?.sdp ?? "";
  const remoteSdp = epc.remoteDescription?.sdp ?? "";

  const localSdpFp = normalizeFingerprintHex(
    uint8ArrayToHex(parseFingerprintFromSdp(localSdp)),
  );
  const remoteSdpFp = normalizeFingerprintHex(
    uint8ArrayToHex(parseFingerprintFromSdp(remoteSdp)),
  );

  const stats = await epc.getStats();

  // RTCStatsReport only exposes forEach (no .get in the DOM typings), and per
  // the webrtc-stats spec the Map key IS each report's own id — report.id
  // itself is not guaranteed to be echoed back on every implementation — so
  // matching is done against the forEach key, falling back to report.id.
  let localCertId: string | undefined;
  let remoteCertId: string | undefined;
  stats.forEach((report: RTCStatEntry) => {
    if (report.type === "transport") {
      localCertId = report.localCertificateId ?? localCertId;
      remoteCertId = report.remoteCertificateId ?? remoteCertId;
    }
  });

  const certificateFingerprint = (id: string | undefined): string | null => {
    if (!id) return null;
    let found: string | null = null;
    stats.forEach((report: RTCStatEntry, key: string) => {
      if (
        report.type === "certificate" &&
        (key === id || report.id === id) &&
        report.fingerprint
      ) {
        found = normalizeFingerprintHex(report.fingerprint);
      }
    });
    return found;
  };

  const liveLocalFp = certificateFingerprint(localCertId);
  const liveRemoteFp = certificateFingerprint(remoteCertId);

  // Fail closed: a tripwire that cannot confirm a fingerprint must abort, not
  // pass. If the live certificate can't be located in the stats report (e.g.
  // a missing/attacker-truncated report), that is treated the same as an
  // outright mismatch — never as "unable to verify, so allow".
  if (liveLocalFp === null || liveLocalFp !== localSdpFp)
    throw new Error(
      "DTLS fingerprint mismatch: local certificate not found or does not match local SDP fingerprint",
    );
  if (liveRemoteFp === null || liveRemoteFp !== remoteSdpFp)
    throw new Error(
      "DTLS fingerprint mismatch: remote certificate not found or does not match remote SDP fingerprint (possible MITM)",
    );
};
