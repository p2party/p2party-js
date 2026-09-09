import { deleteReceiveTransfer, getDBMessageData } from "../db/api";
import { deleteMessageStateOnly } from "../reducers/roomSlice";
import { forgetMappedReceiveMessageKey } from "./receiveMessageKeyLifetime";
import { waitForEdgeReceiveQuiescence } from "./handleMessageQueueing";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { MessageData, ReceiveDeleteGuard } from "../db/types";

// ── the receiving half of a scheduled CANCEL ─────────────────────────────────
//
// `abortTransfer` reads `activeByRoom`, which only `beginTransfer`
// (src/index.ts, the public send boundary) ever writes: it is the OUTBOUND
// registry. An authenticated remote CANCEL therefore aborted our own send of
// that root and swept nothing on the side that was RECEIVING it, so a
// cancelled inbound transfer kept its partial file, its pre-sized OPFS
// storage and its state row forever — and no re-send could ever fill them,
// because a fresh send has fresh decoys and a different Merkle root.

const MERKLE_ROOT_HEX_SHAPE = /^[0-9a-f]{128}$/;

export type InboundReceiveProgress = Pick<
  MessageData,
  "transferId" | "fromPeerId" | "savedSize" | "totalSize"
>;

/**
 * Whether a remote CANCEL from `fromPeerId` may destroy this stored row.
 *
 * Deletion is irreversible, so every clause here is a refusal:
 *
 * - `transferId` is written only on rows this device SENT (db.worker), so it
 *   marks the sender's own self-copy. A CANCEL must never delete that: the
 *   peer is telling us about its receive, not about our library.
 * - a row owned by a different peer is not this edge's to cancel.
 * - a COMPLETED message is a delivered file. A late or replayed CANCEL, or a
 *   sender whose delivery bound expired after the last cell landed, must not
 *   take it away.
 */
export const shouldSweepCancelledInboundTransfer = (
  progress: InboundReceiveProgress | undefined,
  fromPeerId: string,
): boolean =>
  progress !== undefined &&
  progress.transferId === undefined &&
  progress.fromPeerId === fromPeerId &&
  Number.isFinite(progress.totalSize) &&
  Number.isFinite(progress.savedSize) &&
  progress.totalSize > 0 &&
  progress.savedSize >= 0 &&
  progress.savedSize < progress.totalSize;

/**
 * Storage seam. Defaults to the production Worker-backed functions; a caller
 * (and a test, for which the Worker is not available) may substitute them —
 * the same convention `forgetMappedReceiveMessageKey` already uses for its own
 * durable retirement.
 */
export interface InboundTransferSweepDeps {
  readonly waitForReceiveIdle: typeof waitForEdgeReceiveQuiescence;
  readonly readProgress: typeof getDBMessageData;
  readonly forgetKey: typeof forgetMappedReceiveMessageKey;
  readonly deleteReceive: (
    root: string,
    guard: ReceiveDeleteGuard,
  ) => Promise<boolean>;
  /**
   * Drop the message from the LIVE room state. `deleteReceive` is the durable
   * half only — chunks, the messageData row and the pre-sized OPFS file — and
   * both immediate-mode cancels do this second half too
   * (disconnectFromPeerChannelLabelQuery, disconnectFromChannelLabelQuery both
   * dispatch deleteMessage). Without it the user is left looking at a partial
   * whose bytes no longer exist and which no re-send can ever fill.
   */
  readonly dropStateRow: (
    roomId: string,
    merkleRootHex: string,
  ) => void | Promise<void>;
}

/**
 * The store is reached through a lazy import, never a module-level one: this
 * module is pulled in by installCoverEdge, and store.ts initializes the browser
 * identity slice from localStorage at import time. `deleteMessageStateOnly` is
 * the reducer-only twin, which is exactly right here — the durable deletion has
 * already been awaited by the time this runs.
 */
const dispatchStateRowDeletion = async (
  roomId: string,
  merkleRootHex: string,
): Promise<void> => {
  const { dispatch } = await import("../store");
  dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
};

export const productionInboundTransferSweepDeps: InboundTransferSweepDeps = {
  waitForReceiveIdle: waitForEdgeReceiveQuiescence,
  readProgress: getDBMessageData,
  forgetKey: forgetMappedReceiveMessageKey,
  deleteReceive: deleteReceiveTransfer,
  dropStateRow: dispatchStateRowDeletion,
};

/**
 * Drop the partial WE are receiving for one cancelled transfer root.
 *
 * The immediate-mode cancel is TWO deletions, and this is both of them:
 * `cancelReceiveTransfer` in the Worker (chunks, the messageData row, the
 * pre-sized OPFS file), and then `deleteMessage` on the room state — which is
 * what `disconnectFromPeerChannelLabelQuery` and `disconnectFromChannelLabelQuery`
 * each dispatch alongside it. Doing only the durable half leaves the user
 * looking at an N/M partial whose bytes are already gone.
 *
 * Order matters and is the same as immediate mode's: retire the mapped receive
 * key first (so no key outlives the data it opens), then the durable data, and
 * the state row last — it is the only remaining evidence the partial exists, so
 * it must not go while anything a reconnect could still resume is on disk.
 *
 * Never throws: it runs from a cover-cell handler on the fixed schedule, and
 * an observer must not be able to perturb that. Storage uncertainty leaves the
 * partial in place, which a reconnect can still resume — the safe direction.
 */
export const sweepCancelledInboundTransfer = async (
  epc: IRTCPeerConnection,
  roomId: string,
  merkleRootHex: string,
  deps: InboundTransferSweepDeps = productionInboundTransferSweepDeps,
): Promise<boolean> => {
  if (!MERKLE_ROOT_HEX_SHAPE.test(merkleRootHex)) return false;
  try {
    // Cover control cells bypass the chunk queue. Let already queued frames
    // finish first, including a final chunk that turns this into a delivered
    // file. The completion predicate must see their durable result.
    await deps.waitForReceiveIdle(roomId, epc.withPeerId);
    const progress = await deps.readProgress(merkleRootHex);
    if (
      progress?.roomId !== roomId ||
      !shouldSweepCancelledInboundTransfer(progress, epc.withPeerId)
    )
      return false;

    await deps.forgetKey(epc, roomId, merkleRootHex);
    const removed = await deps.deleteReceive(merkleRootHex, {
      roomId,
      fromPeerId: epc.withPeerId,
      incompleteOnly: true,
    });
    if (!removed) return false;
    await deps.dropStateRow(roomId, merkleRootHex);

    return true;
  } catch (error) {
    console.error(
      "p2party: could not sweep a cancelled inbound transfer",
      error,
    );

    return false;
  }
};
