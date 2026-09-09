import { getDBMessageData } from "../db/api";
import { hasQueuedEdgeReceiveWork } from "./handleMessageQueueing";
import { sweepTransferStorageDetails } from "./outbox";
import {
  captureReceiveMessageKey,
  forgetExpiredReceiveMessageKey,
} from "./receiveMessageKeyLifetime";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { Message, Room } from "../reducers/roomSlice";

export interface ExpiredReceiveProjectionDependencies {
  getRooms: () => readonly Pick<Room, "id" | "messages">[];
  getPeers: () => readonly IRTCPeerConnection[];
  dropMessage: (roomId: string, merkleRootHex: string) => void;
  sweep?: typeof sweepTransferStorageDetails;
  readProgress?: typeof getDBMessageData;
  forgetKey?: typeof forgetExpiredReceiveMessageKey;
}

const incompleteReceive = (message: Message): boolean =>
  message.transferId === undefined &&
  message.totalSize > 0 &&
  message.savedSize >= 0 &&
  message.savedSize < message.totalSize;

/** Project only committed expiry deletions, never a scan's stale candidates. */
export const sweepExpiredReceiveState = async ({
  getRooms,
  getPeers,
  dropMessage,
  sweep = sweepTransferStorageDetails,
  readProgress = getDBMessageData,
  forgetKey = forgetExpiredReceiveMessageKey,
}: ExpiredReceiveProjectionDependencies): Promise<void> => {
  // Redux rows are immutable: reference equality distinguishes a later chunk,
  // completion, reload, or same-root replacement while the worker is busy.
  const canSweep = () =>
    !getPeers().some((peer) =>
      hasQueuedEdgeReceiveWork(peer.roomId, peer.withPeerId),
    );
  // Decrypted frames may await receipt-token work before submitting storage.
  // Such frames have no worker write lease yet; their queue owns the partial.
  if (!canSweep()) return;
  const rooms = getRooms();
  const keys = getPeers().flatMap((peer) =>
    [...(peer.messageKeyByMerkleRoot?.keys() ?? [])].flatMap((root) => {
      const snapshot = captureReceiveMessageKey(peer, root);
      return snapshot ? [snapshot] : [];
    }),
  );
  const deleted = await sweep(canSweep);
  for (const { merkleRoot, roomId, fromPeerId } of deleted) {
    const before = rooms
      .find((room) => room.id === roomId)
      ?.messages.find((message) => message.merkleRootHex === merkleRoot);
    if (
      before &&
      (!incompleteReceive(before) || before.fromPeerId !== fromPeerId)
    )
      continue;
    const current = () =>
      getRooms()
        .find((room) => room.id === roomId)
        ?.messages.find((message) => message.merkleRootHex === merkleRoot);
    const stillAbsent = async () =>
      !(await readProgress(merkleRoot)) &&
      current() === before &&
      !hasQueuedEdgeReceiveWork(roomId, fromPeerId);

    if (!(await stillAbsent())) continue;
    for (const snapshot of keys) {
      if (
        snapshot.roomId !== roomId ||
        snapshot.peerId !== fromPeerId ||
        snapshot.merkleRootHex !== merkleRoot
      )
        continue;
      try {
        await forgetKey(snapshot, stillAbsent);
      } catch (error) {
        // A failed durable retirement retains its usable key. Storage expiry
        // still removes the stale view; ordinary cache limits bound RAM keys.
        console.error("Could not retire expired receive key", error);
      }
    }
    if (
      before &&
      incompleteReceive(before) &&
      before.fromPeerId === fromPeerId &&
      (await stillAbsent())
    )
      dropMessage(roomId, merkleRoot);
  }
};

/** Metadata polling shares one lazy maintenance pass at most every 30 seconds. */
export const createExpiredReceiveMaintenance = (
  dependencies: ExpiredReceiveProjectionDependencies,
  now: () => number = Date.now,
): (() => Promise<void>) => {
  let nextRunAt = -Infinity;
  let running: Promise<void> | undefined;
  return () => {
    if (running) return running;
    if (now() < nextRunAt) return Promise.resolve();
    nextRunAt = now() + 30_000;
    running = sweepExpiredReceiveState(dependencies).finally(() => {
      running = undefined;
    });
    return running;
  };
};
