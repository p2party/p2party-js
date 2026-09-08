import { isUUID } from "class-validator";

import { isCanonicalEd25519Identity } from "../utils/identityRole";
import { MAX_SIGNALING_ROOM_PEERS } from "../utils/signalingBounds";

import type { Peer } from "../reducers/roomSlice";
import type { RoomPeer } from "../utils/interfaces";

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
 * Peer removal belongs to explicit transport teardown/disconnect handling.
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
