import { parseFingerprintFromSdp } from "../../utils/sdpFingerprint";

/**
 * Remote DTLS certificates this side has stopped believing in, per
 * (roomId, peerId) edge.
 *
 * A description is only ever meaningful for the transport pair it belongs to,
 * but nothing on the wire correlates an answer with the offer it answers (the
 * SDK cannot add signaling fields without a server change). So a description
 * that a peer produced on a transport we already retired can land on a
 * transport of ours that has no remote description yet — where the
 * fingerprint-change detection of `remoteTransportChange` returns false BY
 * CONSTRUCTION, because there is nothing to compare against — and bind our
 * fresh RTCPeerConnection to a certificate that is already dead.
 *
 * That is exactly how a frozen phone whose signaling socket stayed open
 * deadlocks an edge: the peer's queued ICE-restart offer is answered from its
 * old, still-authenticated transport after the thaw; the answer arrives at
 * our brand-new PC, is accepted, and the correct answer that follows it is
 * then dropped as "stale" because the PC is already `stable`. Neither side's
 * transport ever connects, so no failure path re-dials either.
 *
 * Remembering the fingerprint of every transport we retire closes that hole:
 * an ANSWER carrying one is discarded before it is applied (setDescriptionQuery
 * explains why an offer is instead accepted, and un-retires the transport it
 * binds through `forgetRetiredRemoteTransport`).
 *
 * The set is bounded twice, because it is keyed by a peer-supplied identifier
 * and must never grow without limit nor lock a peer out forever:
 *
 * - at most MAX_RETIRED_REMOTE_TRANSPORTS_PER_EDGE fingerprints per edge, the
 *   oldest evicted first;
 * - each entry expires RETIRED_REMOTE_TRANSPORT_TTL_MS after it was retired.
 *
 * Chromium mints a fresh certificate for every RTCPeerConnection and this
 * codebase never passes `RTCConfiguration.certificates` for its own
 * connections (roomSlice only CLONES a caller-supplied configuration), so a
 * rebuilt peer transport always presents a fingerprint we have never retired.
 * If a caller DOES pin a certificate, its peer's replacement transport
 * presents the very fingerprint we retired and its descriptions are discarded
 * until the TTL expires; the edge then heals on the next re-dial, one TTL
 * later, instead of immediately.
 */
export const MAX_RETIRED_REMOTE_TRANSPORTS_PER_EDGE = 4;
export const RETIRED_REMOTE_TRANSPORT_TTL_MS = 120_000;

interface RetiredRemoteTransport {
  fingerprint: Uint8Array;
  retiredAt: number;
}

const retiredByEdge = new Map<string, RetiredRemoteTransport[]>();

/**
 * Length-prefixed, as in negotiationLock: without it ("ab", "c") and
 * ("a", "bc") would share one entry.
 */
const edgeKey = (roomId: string, peerId: string): string =>
  `${String(roomId.length)}:${roomId}${peerId}`;

const fingerprintsAreEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return false;
  return true;
};

const parseFingerprint = (
  transport: string | Uint8Array | null | undefined,
): Uint8Array | undefined => {
  if (transport == undefined) return undefined;
  if (typeof transport !== "string") return transport;
  try {
    return parseFingerprintFromSdp(transport);
  } catch {
    // An SDP with no (or a malformed) sha-256 fingerprint identifies no
    // certificate. There is nothing to remember and nothing to match; the
    // handshake rejects such an SDP later on its own.
    return undefined;
  }
};

/**
 * Drop expired entries, and the edge itself once it holds none. Pruning on
 * access is enough to bound the registry in practice: an edge is only ever
 * created by retiring a transport on it, and every later lookup or retirement
 * for that edge prunes it. `forgetRetiredRemoteTransports` covers the edge
 * that is never touched again because its room was left.
 */
const pruneEdge = (
  key: string,
  entries: RetiredRemoteTransport[],
  now: number,
): RetiredRemoteTransport[] => {
  const live = entries.filter(
    (entry) => now - entry.retiredAt < RETIRED_REMOTE_TRANSPORT_TTL_MS,
  );
  if (live.length === 0) retiredByEdge.delete(key);
  else if (live.length !== entries.length) retiredByEdge.set(key, live);
  return live;
};

/**
 * Remember that this side has stopped believing in the remote transport that
 * presented `transport` (an SDP blob or its raw sha-256 fingerprint) on the
 * (roomId, peerId) edge. Returns whether a fingerprint was actually recorded.
 */
export const retireRemoteTransport = (
  roomId: string,
  peerId: string,
  transport: string | Uint8Array | null | undefined,
  now: number = Date.now(),
): boolean => {
  const fingerprint = parseFingerprint(transport);
  if (!fingerprint) return false;

  const key = edgeKey(roomId, peerId);
  const entries = pruneEdge(key, retiredByEdge.get(key) ?? [], now);
  // Re-retiring a fingerprint refreshes it instead of consuming a slot: the
  // same dead certificate can be retired again by a later teardown path.
  const kept = entries.filter(
    (entry) => !fingerprintsAreEqual(entry.fingerprint, fingerprint),
  );
  kept.push({ fingerprint, retiredAt: now });
  while (kept.length > MAX_RETIRED_REMOTE_TRANSPORTS_PER_EDGE) kept.shift();
  retiredByEdge.set(key, kept);

  return true;
};

/**
 * True iff `sdp` declares the certificate of a remote transport already
 * retired for this edge, i.e. the description must not be applied.
 */
export const isRetiredRemoteTransport = (
  roomId: string,
  peerId: string,
  sdp: string | null | undefined,
  now: number = Date.now(),
): boolean => {
  const key = edgeKey(roomId, peerId);
  const entries = retiredByEdge.get(key);
  if (!entries) return false;

  const live = pruneEdge(key, entries, now);
  if (live.length === 0) return false;

  const fingerprint = parseFingerprint(sdp);
  if (!fingerprint) return false;

  return live.some((entry) =>
    fingerprintsAreEqual(entry.fingerprint, fingerprint),
  );
};

/**
 * Un-retire one transport of an edge: this side is bound to it again.
 *
 * A retired fingerprint means "we are not bound to this remote certificate",
 * so the moment a description from it IS applied — the peer offered on the
 * transport we had given up on, proving it negotiates there — the retirement
 * is void. Without this, the answer to our own next ICE restart on that very
 * binding would be discarded as retired.
 */
export const forgetRetiredRemoteTransport = (
  roomId: string,
  peerId: string,
  transport: string | Uint8Array | null | undefined,
): void => {
  const fingerprint = parseFingerprint(transport);
  if (!fingerprint) return;

  const key = edgeKey(roomId, peerId);
  const entries = retiredByEdge.get(key);
  if (!entries) return;

  const kept = entries.filter(
    (entry) => !fingerprintsAreEqual(entry.fingerprint, fingerprint),
  );
  if (kept.length === entries.length) return;
  if (kept.length === 0) retiredByEdge.delete(key);
  else retiredByEdge.set(key, kept);
};

/**
 * Forget every retired transport of one edge. Called when the edge itself is
 * terminal — its room was left or purged — so a room the user rejoins later
 * starts with a clean slate.
 */
export const forgetRetiredRemoteTransports = (
  roomId: string,
  peerId: string,
): void => {
  retiredByEdge.delete(edgeKey(roomId, peerId));
};
