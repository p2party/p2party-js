import { compileChannelMessageLabel } from "../utils/channelLabel";
import { WIRE_CHUNK_FRAME_LEN } from "../utils/constants";

import type { CoverJob, CoverJobSlot } from "./coverScheduler";
import type { CoverRuntime } from "./coverRuntime";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

// ── protocol-v4 scheduled-transfer integration helpers ───────────────────────
//
// In a scheduled room, receipts and cancellation substitute into already-
// scheduled cover slots instead of riding immediate frames. This module owns
// the per-edge pending-receipt queue and its lazy drain job: receipts
// accumulate here and one `control` job per cycle drains them one slot at a
// time, returning null (dummy substitution) whenever the queue is empty. The
// receiving side of a transfer therefore acknowledges through the SAME fixed
// observable schedule it already emits, at zero marginal scheduled cells.

interface PendingScheduledReceipt {
  readonly merkleRoot: Uint8Array;
  readonly token: Uint8Array;
}

interface ScheduledReceiptState {
  readonly pending: PendingScheduledReceipt[];
  drainJobActive: boolean;
  jobSequence: number;
}

const receiptStates = new WeakMap<IRTCPeerConnection, ScheduledReceiptState>();

const MAX_PENDING_SCHEDULED_RECEIPTS = 4_096;

const receiptState = (epc: IRTCPeerConnection): ScheduledReceiptState => {
  let state = receiptStates.get(epc);
  if (!state) {
    state = { pending: [], drainJobActive: false, jobSequence: 0 };
    receiptStates.set(epc, state);
  }
  return state;
};

/**
 * Queue one scheduled receipt (per-cell ack or terminal completion token) for
 * the next available reverse control slots. Returns false when the edge has no
 * cover runtime (immediate mode) so the caller falls back to immediate
 * receipts, and drops oldest-first beyond the flood bound.
 */
export const queueScheduledReceipt = (
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  token: Uint8Array,
): boolean => {
  const runtime = epc.coverRuntime;
  if (!runtime) return false;
  if (merkleRoot.length !== 64 || token.length !== 64) return false;
  const state = receiptState(epc);
  state.pending.push({
    merkleRoot: Uint8Array.from(merkleRoot),
    token: Uint8Array.from(token),
  });
  while (state.pending.length > MAX_PENDING_SCHEDULED_RECEIPTS)
    state.pending.shift();
  ensureReceiptDrainJob(epc, runtime, state);
  return true;
};

const ensureReceiptDrainJob = (
  epc: IRTCPeerConnection,
  runtime: CoverRuntime,
  state: ScheduledReceiptState,
): void => {
  if (state.drainJobActive || state.pending.length === 0) return;
  const capacity = runtime.cellsPerLanePerCycle();
  const declared = Math.min(state.pending.length, capacity);
  if (declared <= 0) return;
  state.drainJobActive = true;
  state.jobSequence += 1;
  const job: CoverJob = {
    // A control lane must advertise the same constant label shape as every
    // other lane; the id IS the lane label.
    id: runtime.randomLaneLabel(),
    kind: "control",
    declaredCellCount: declared,
    nextCell: () => {
      const next = state.pending.shift();
      if (!next) return null; // dummy substitution for an empty slot
      try {
        return runtime.sealCoverContent({
          subtype: "receipt",
          merkleRoot: next.merkleRoot,
          token: next.token,
        });
      } finally {
        next.merkleRoot.fill(0);
        next.token.fill(0);
      }
    },
  };
  try {
    runtime.enqueue(job);
  } catch (error) {
    state.drainJobActive = false;
    console.error("coverTransfer: could not enqueue receipt drain job", error);
    return;
  }
  // Re-arm on settlement so a long receipt backlog drains across cycles.
  runtime.onJobSettled(job.id, () => {
    state.drainJobActive = false;
    ensureReceiptDrainJob(epc, runtime, state);
  });
};

/** Wipe and drop every queued scheduled receipt (edge teardown). */
export const releaseScheduledReceipts = (epc: IRTCPeerConnection): void => {
  const state = receiptStates.get(epc);
  if (!state) return;
  for (const entry of state.pending) {
    entry.merkleRoot.fill(0);
    entry.token.fill(0);
  }
  state.pending.length = 0;
  state.drainJobActive = false;
  receiptStates.delete(epc);
};

/**
 * A synthetic constant-shape label for receipt routing: handleReadReceipt only
 * consumes the Merkle-root element, so the name element is canonical zeros.
 */
export const syntheticScheduledLabel = (merkleRootHex: string): string =>
  `${"00".repeat(32)}~${merkleRootHex}`;

/** Seal exactly one already-staged chunk into its uniform 65,490-byte cell. */
export type SealTransferSlotCell = (
  chunkIndex: number,
) => Promise<Uint8Array | null> | Uint8Array | null;

export interface ScheduledSendJobOptions {
  readonly runtime: CoverRuntime;
  /** The compiled per-message channel label; it is the job/lane id. */
  readonly channelMessageLabel: string;
  readonly totalChunks: number;
  /** Seal the sender's cell for one chunk index (real bytes). */
  readonly sealSlotCell: SealTransferSlotCell;
  /** Set of already-acked real chunk indices for reconcile skipping. */
  readonly getAckedChunks?: () => ReadonlySet<number>;
  /** Real chunk indices only (decoys never resend); default is all indices. */
  readonly realChunkIndices?: readonly number[];
}

/**
 * Build the lazy scheduled-send job for one message on one edge. It seals at
 * most ONE chunk per scheduled slot (never a burst), returns null (dummy
 * substitution) once every not-yet-acked real chunk has been offered this
 * pass, and refuses admission if the declared cell count cannot fit the
 * authenticated `F × D` capacity class. Reconcile is scheduled, not burst: an
 * un-acked chunk is re-offered on the next pass through the job's cells.
 */
export const buildScheduledSendJob = (
  options: ScheduledSendJobOptions,
): CoverJob => {
  const capacity = options.runtime.cellsPerLanePerCycle();
  if (options.totalChunks > capacity)
    throw new Error(
      `coverTransfer: message of ${String(options.totalChunks)} cells exceeds the room F×D capacity of ${String(capacity)}`,
    );
  const realIndices =
    options.realChunkIndices ??
    Array.from({ length: options.totalChunks }, (_, index) => index);

  // A single job-run makes ONE pass over the real indices, offering each
  // chunk that is not already acked exactly once and then dummy-substituting
  // for the tail. Reconcile (re-offering the still-missing reals) is a fresh
  // job on a later cycle — never a burst inside this one.
  let cursor = 0;
  const nextRealIndex = (): number | null => {
    const acked = options.getAckedChunks?.() ?? EMPTY_ACK_SET;
    while (cursor < realIndices.length) {
      const index = realIndices[cursor];
      cursor += 1;
      if (!acked.has(index)) return index;
    }
    return null;
  };

  return {
    id: options.channelMessageLabel,
    kind: "real",
    declaredCellCount: options.totalChunks,
    nextCell: async (_slot: CoverJobSlot): Promise<Uint8Array | null> => {
      const index = nextRealIndex();
      if (index === null) return null; // dummy substitution: nothing left to send
      const cell = await options.sealSlotCell(index);
      if (cell === null) return null;
      if (cell.length !== WIRE_CHUNK_FRAME_LEN)
        throw new Error(
          "coverTransfer: sealed transfer cell is not the uniform length",
        );
      return cell;
    },
  };
};

const EMPTY_ACK_SET: ReadonlySet<number> = new Set<number>();

/**
 * The scheduled-mode wire CANCEL for one transfer on one edge: scheduler
 * cancellation emits the encrypted CANCEL cell in the job's next slot and
 * leaves a dummy tail through the fixed boundary. Never a channel close.
 */
export const cancelScheduledTransfer = async (
  epc: IRTCPeerConnection,
  channelLabel: string,
  merkleRootHex: string,
): Promise<boolean> => {
  const runtime = epc.coverRuntime;
  if (!runtime) return false;
  const label = await compileChannelMessageLabel(channelLabel, merkleRootHex);
  const result = runtime.cancel(label);
  return result !== "not-found";
};
