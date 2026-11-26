import { isUUID } from "../utils/formatValidation";

import { isCanonicalEd25519Identity } from "../utils/identityRole";
import { isProtocolVersionCompatible } from "../utils/protocolVersion";
import { MAX_SIGNALING_ROOM_PEERS } from "../utils/signalingBounds";

import type { Peer, PeerSignalingPresence } from "../reducers/roomSlice";
import type {
  PeerDepartureReason,
  RoomPeer,
  WebSocketMessagePeerLeft,
} from "../utils/interfaces";

export interface SelfPeerIdentity {
  peerId: string;
  publicKey: string;
}

/** Validate the whole snapshot before replacing prior membership. */
export const parsePeerRosterSnapshot = (
  peers: readonly RoomPeer[],
  self: SelfPeerIdentity,
): Peer[] => {
  if (peers.length > MAX_SIGNALING_ROOM_PEERS)
    throw new Error("Signaling peer roster exceeds the room edge cap");
  const ids = new Set<string>(),
    keys = new Set<string>();
  for (const peer of peers) {
    if (
      !peer ||
      !isUUID(peer.id) ||
      !isCanonicalEd25519Identity(peer.publicKey) ||
      ids.has(peer.id) ||
      keys.has(peer.publicKey)
    )
      throw new Error("Malformed membership snapshot");
    ids.add(peer.id);
    keys.add(peer.publicKey);
  }
  return mergePeerRosterDelta([], peers, self);
};

/**
 * Server `peers` messages are accepted-peer deltas, not room snapshots.
 * Preserve prior members and upsert only canonical, non-conflicting additions.
 * Peer removal belongs to transport teardown and to a `peerLeft` report for a
 * member this client holds no connected edge to (planPeerDeparture).
 */
export const mergePeerRosterDelta = (
  current: readonly Peer[],
  delta: readonly RoomPeer[],
  self: SelfPeerIdentity,
): Peer[] => {
  if (
    current.length > MAX_SIGNALING_ROOM_PEERS ||
    delta.length > MAX_SIGNALING_ROOM_PEERS
  )
    throw new Error("Signaling peer roster exceeds the room edge cap");

  const merged = current.map((peer) => ({ ...peer }));
  const byPeerId = new Map(merged.map((peer) => [peer.peerId, peer]));
  const byPublicKey = new Map(merged.map((peer) => [peer.peerPublicKey, peer]));

  for (const candidate of delta) {
    if (
      !isUUID(candidate.id) ||
      !isCanonicalEd25519Identity(candidate.publicKey) ||
      candidate.id === self.peerId ||
      candidate.publicKey === self.publicKey
    )
      continue;

    if (byPeerId.has(candidate.id)) continue;

    const existingIdentity = byPublicKey.get(candidate.publicKey);
    if (existingIdentity) continue;
    if (merged.length >= MAX_SIGNALING_ROOM_PEERS)
      throw new Error("Signaling peer roster exceeds the room edge cap");

    const peer = {
      peerId: candidate.id,
      peerPublicKey: candidate.publicKey,
    };
    merged.push(peer);
    byPeerId.set(peer.peerId, peer);
    byPublicKey.set(peer.peerPublicKey, peer);
  }

  return merged;
};

/** A `peerLeft` frame's fields, once each one is well formed. */
export interface PeerDepartureReport {
  roomId: string;
  peerId: string;
  reason: PeerDepartureReason;
  /** The departed socket's generation, a UUIDv4. */
  socketGeneration: string;
}

/** Validate a server `peerLeft` frame; undefined for anything malformed. */
export const parsePeerLeft = (
  message: unknown,
): PeerDepartureReport | undefined => {
  if (typeof message !== "object" || message === null) return undefined;
  const frame = message as Partial<
    Record<keyof WebSocketMessagePeerLeft, unknown>
  >;
  if (
    !isProtocolVersionCompatible(frame.protocolVersion as number | undefined) ||
    !isUUID(frame.roomId) ||
    !isUUID(frame.peerId) ||
    (frame.reason !== "left" && frame.reason !== "offline") ||
    !isUUID(frame.socketGeneration, 4)
  )
    return undefined;
  return {
    roomId: frame.roomId as string,
    peerId: frame.peerId as string,
    reason: frame.reason,
    socketGeneration: frame.socketGeneration as string,
  };
};

/** The parts of a room the presence rules read; a superset of the reducer's. */
export interface PresenceRoom {
  readonly peers: readonly { readonly peerId: string }[];
  readonly knownPeers?: readonly { readonly peerId: string }[];
  readonly peerPresence?: Readonly<
    Record<string, PeerSignalingPresence | undefined>
  >;
}

/** A member this client tracks: on the roster or in the last snapshot. */
export const isRoomMember = (room: PresenceRoom, peerId: string): boolean =>
  room.peers.some((peer) => peer.peerId === peerId) ||
  (room.knownPeers?.some((peer) => peer.peerId === peerId) ?? false);

/**
 * What a `peerLeft` report may change.
 *
 * The signaling server is not trusted and cannot authenticate this report to
 * the members' WebRTC edges, so it is a hint and never closes a connected
 * edge:
 *
 * - "ignore": the report names this client, a peer this client does not
 *   track, or a socket generation other than the one the server last named
 *   for that peer (a report about an earlier session, delivered after the
 *   peer came back on a new socket).
 * - "remove": "left" with no connected edge. The member is dropped, which
 *   ends its reconcile retries; the caller cancels any negotiation still in
 *   progress.
 * - "mark": "left" with a connected edge, or "offline". The edge and
 *   everything on it stay. The mark keeps the member out of reconcile
 *   retries; a "left" member is dropped when that edge closes (deletePeer).
 */
export type PeerDepartureVerdict = "ignore" | "remove" | "mark";

export const planPeerDeparture = (
  room: PresenceRoom,
  report: Pick<PeerDepartureReport, "peerId" | "reason" | "socketGeneration">,
  selfPeerId: string,
  edgeConnected: boolean,
): PeerDepartureVerdict => {
  if (report.peerId === selfPeerId || !isRoomMember(room, report.peerId))
    return "ignore";
  const named = room.peerPresence?.[report.peerId]?.socketGeneration;
  if (named !== undefined && named !== report.socketGeneration) return "ignore";
  return report.reason === "left" && !edgeConnected ? "remove" : "mark";
};

/**
 * How much a server frame naming a member says about its presence.
 *
 * - "session": the frame comes from the member's live socket — a `peers`
 *   delta (it accepted an introduction), a `peerConnection` introduction (it
 *   asked for peers), or a `connection` (it is dialling).
 * - "membership": a `peers` snapshot entry. A snapshot lists offline members
 *   too, so it says the peer is a member, not that it is online.
 */
export type PeerPresenceEvidence = "session" | "membership";

/**
 * The presence a server frame naming a member leaves behind.
 *
 * Any frame naming the member withdraws a "left" report: it is a member
 * again. An "offline" report is withdrawn by a frame naming another socket
 * generation, or by a session frame that names none; a frame naming the
 * generation that went offline is older than the report and changes nothing,
 * and a snapshot entry without a generation is no evidence the member is
 * online. A canonical generation the frame names is recorded either way.
 */
export const notedPeerPresence = (
  current: PeerSignalingPresence | undefined,
  socketGeneration: unknown,
  evidence: PeerPresenceEvidence,
): PeerSignalingPresence => {
  const generation = isUUID(socketGeneration, 4)
    ? (socketGeneration as string)
    : undefined;
  let departure = current?.departure;
  if (departure === "left") departure = undefined;
  else if (departure === "offline") {
    const departedSession =
      generation !== undefined && generation === current?.socketGeneration;
    if (
      evidence === "session"
        ? !departedSession
        : generation !== undefined && !departedSession
    )
      departure = undefined;
  }
  const next: PeerSignalingPresence = {};
  const recorded = generation ?? current?.socketGeneration;
  if (recorded !== undefined) next.socketGeneration = recorded;
  if (departure !== undefined) next.departure = departure;
  return next;
};
