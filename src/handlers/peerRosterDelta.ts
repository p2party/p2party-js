import { isUUID } from "class-validator";

import { isCanonicalEd25519Identity } from "../utils/identityRole";

import type { Peer } from "../reducers/roomSlice";
import type { RoomPeer } from "../utils/interfaces";

export interface SelfPeerIdentity {
  peerId: string;
  publicKey: string;
}

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
