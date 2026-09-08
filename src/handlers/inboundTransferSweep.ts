import { deleteReceiveTransfer, getDBMessageData } from "../db/api";
import { forgetMappedReceiveMessageKey } from "./receiveMessageKeyLifetime";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { MessageData } from "../db/types";

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
  readonly readProgress: typeof getDBMessageData;
  readonly forgetKey: typeof forgetMappedReceiveMessageKey;
  readonly deleteReceive: typeof deleteReceiveTransfer;
}

export const productionInboundTransferSweepDeps: InboundTransferSweepDeps = {
  readProgress: getDBMessageData,
  forgetKey: forgetMappedReceiveMessageKey,
  deleteReceive: deleteReceiveTransfer,
};

/**
 * Drop the partial WE are receiving for one cancelled transfer root.
 *
 * Mirrors `handleOpenChannel`'s immediate-mode `cancelReceiveTransfer`: retire
 * the mapped receive key first (so no key outlives the data it opens), then
 * delete the receive transfer, which is what owns the chunks, the messageData
 * row and the pre-sized OPFS file.
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
    const progress = await deps.readProgress(merkleRootHex);
    if (!shouldSweepCancelledInboundTransfer(progress, epc.withPeerId))
      return false;

    await deps.forgetKey(epc, roomId, merkleRootHex);
    await deps.deleteReceive(merkleRootHex);

    return true;
  } catch (error) {
    console.error(
      "p2party: could not sweep a cancelled inbound transfer",
      error,
    );

    return false;
  }
};
