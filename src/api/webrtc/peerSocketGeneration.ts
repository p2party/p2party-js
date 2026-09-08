import { isUUID } from "class-validator";

/**
 * Whether a peerId still names the same signaling session.
 *
 * The server binds one stable peerId to an identity public key, so a second
 * tab or a phrase-restored second device reconnects as the SAME peerId and
 * evicts its predecessor. Without a per-socket generation the edge stayed
 * bound to the evicted socket: the transport never failed (no SDP, no ICE
 * event), so nothing rebuilt it, and a responder on the new session creates no
 * channel and can never offer — the split was permanent (C1).
 *
 * "unknown" is the fail-safe verdict: an absent or malformed generation (a
 * pre-generation server, or a fresh transport that has not recorded one yet)
 * must behave exactly as 0.14.7 does, never as a teardown trigger. The server
 * leaves the field empty until a socket has proved ownership of its key and
 * empties it again whenever a fresh challenge is issued, so "" and undefined
 * are the same statement: no information.
 */
export type PeerSocketGenerationVerdict = "unknown" | "unchanged" | "changed";

/**
 * Which inbound frame carried a generation, and therefore how much authority
 * it has.
 *
 * - "connection": the peer's own `connection` frame. It is emitted from one
 *   place only (handleConnectToPeer's connectWithPeer), and that place is
 *   reachable only after a FRESH transport has been built — both baseQuery and
 *   handleConnectToPeer early-return on a live one. A changed generation there
 *   always means a genuinely new remote transport.
 * - "roster": a `peers` introduction. The roster is re-requested on join, on
 *   re-dial AND on reconcile, and a signaling socket now reconnects on its
 *   own, so a benign reconnect of a healthy session routinely delivers a
 *   changed generation for an edge that is working perfectly. Acting on that
 *   is a regression of cluster C4, so it is record-only while the local
 *   transport is connected.
 */
export type PeerSocketGenerationSource = "connection" | "roster";

export const isCanonicalSocketGeneration = (value: unknown): value is string =>
  typeof value === "string" && isUUID(value, 4);

export const comparePeerSocketGeneration = (
  recorded: string | undefined,
  observed: unknown,
): PeerSocketGenerationVerdict => {
  if (!isCanonicalSocketGeneration(observed)) return "unknown";
  if (!isCanonicalSocketGeneration(recorded)) return "unknown";
  return recorded === observed ? "unchanged" : "changed";
};

/**
 * Generations this side has already torn an edge down for.
 *
 * A generation is a UUIDv4: it carries no ordering, so "different" can never
 * be read as "newer". Two things make a bare `recorded !== observed` unsafe.
 * handlePeerConnection can deliver one introduction twice — directly and again
 * through pub/sub — and signaling frames can cross on the wire, so a frame
 * naming the generation we just retired can arrive AFTER the replacement is
 * built. Comparing against the replacement's own generation would then call
 * the dead socket "changed" and tear the good edge down, oscillating forever.
 * Remembering what was retired makes the decision monotone.
 */
const retired = new Map<string, Set<string>>();

/** How many retired generations one edge remembers. */
const MAX_RETIRED_GENERATIONS_PER_EDGE = 8;

const edgeKey = (roomId: string, peerId: string): string =>
  `${roomId}|${peerId}`;

export const markPeerSocketGenerationRetired = (
  roomId: string,
  peerId: string,
  generation: unknown,
): void => {
  if (!isCanonicalSocketGeneration(generation)) return;
  const key = edgeKey(roomId, peerId);
  const seen = retired.get(key) ?? new Set<string>();
  seen.delete(generation);
  seen.add(generation);
  // Insertion-ordered, so the oldest retired generation is the first key.
  while (seen.size > MAX_RETIRED_GENERATIONS_PER_EDGE) {
    const oldest = seen.values().next();
    if (oldest.done) break;
    seen.delete(oldest.value);
  }
  retired.set(key, seen);
};

export const isPeerSocketGenerationRetired = (
  roomId: string,
  peerId: string,
  generation: unknown,
): boolean =>
  isCanonicalSocketGeneration(generation) &&
  (retired.get(edgeKey(roomId, peerId))?.has(generation) ?? false);

export const clearRetiredPeerSocketGenerations = (
  roomId: string,
  peerId: string,
): void => {
  retired.delete(edgeKey(roomId, peerId));
};

export interface PeerSocketGenerationObservation {
  roomId: string;
  peerId: string;
  /** The generation the local transport was built against, if any. */
  recorded: string | undefined;
  /** The generation this frame names for the peer. */
  observed: unknown;
  /** Which inbound frame carried it; an unattributed frame is advisory. */
  source: PeerSocketGenerationSource | undefined;
  /** The local transport's current state. */
  connectionState: RTCPeerConnectionState;
}

/**
 * Whether an observed generation is reason enough to retire the local
 * transport for this edge and rebuild it against the peer's live session.
 *
 * Deliberately conservative in two directions. A roster introduction is acted
 * on only when the local transport is demonstrably not working — a healthy
 * edge must survive an ordinary signaling reconnect (C4). And a generation
 * this edge has already retired never triggers a second teardown, however it
 * arrives.
 *
 * "not working" excludes "disconnected". handleConnectToPeer answers that state
 * with an ICE restart and only tears the edge down if it is still disconnected
 * 8 s later, and the restart usually succeeds — so a roster frame arriving in
 * that window would replace a transport that was about to heal itself.
 */
export const shouldRetireTransportForSocketGeneration = ({
  roomId,
  peerId,
  recorded,
  observed,
  source,
  connectionState,
}: PeerSocketGenerationObservation): boolean => {
  if (comparePeerSocketGeneration(recorded, observed) !== "changed")
    return false;
  if (isPeerSocketGenerationRetired(roomId, peerId, observed)) return false;
  if (source === "connection") return true;
  return connectionState !== "connected" && connectionState !== "disconnected";
};
