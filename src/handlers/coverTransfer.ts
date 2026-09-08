import { compileChannelMessageLabel } from "../utils/channelLabel";
import { hexToUint8Array } from "../utils/uint8array";
import {
  SCHEDULED_DELIVERY_MARGIN_MS,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";
import { coverSlotSpacingMs } from "./coverScheduler";

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

/**
 * One reverse control cell waiting for a scheduled slot: a receipt when it
 * carries a completion token, the wire CANCEL for that transfer when it does
 * not. Both are the same shape on the wire and both cost zero marginal
 * scheduled cells, so they share one queue and one drain job.
 */
interface PendingScheduledControlCell {
  readonly merkleRoot: Uint8Array;
  readonly token?: Uint8Array;
}

interface ScheduledReceiptState {
  readonly pending: PendingScheduledControlCell[];
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
        return next.token
          ? runtime.sealCoverContent({
              subtype: "receipt",
              merkleRoot: next.merkleRoot,
              token: next.token,
            })
          : runtime.sealCoverContent({
              subtype: "cancel",
              merkleRoot: next.merkleRoot,
            });
      } finally {
        next.merkleRoot.fill(0);
        next.token?.fill(0);
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
    entry.token?.fill(0);
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

const COMPILED_LABEL_SHAPE = /^[0-9a-f]{64}~[0-9a-f]{128}$/;

/**
 * The transfer root carried by a compiled channel-message label (which is also
 * the scheduled-send job id). Null for anything that is not one — the
 * synchronous counterpart of decompileChannelMessageLabel, used where a cancel
 * cannot await.
 */
export const scheduledTransferRootFromLabel = (
  channelMessageLabel: string,
): Uint8Array | null =>
  COMPILED_LABEL_SHAPE.test(channelMessageLabel)
    ? hexToUint8Array(channelMessageLabel.slice(65))
    : null;

/**
 * Queue this transfer's wire CANCEL as a standalone reverse control cell.
 *
 * A send job carries its own `cancelCell`, but only while the scheduler still
 * holds it. By the time a delivery bound expires the job has usually emitted
 * every declared cell and settled "completed", so `CoverScheduler.cancel`
 * answers "not-found" and nothing would ever reach the receiver — which is the
 * state that strands it: an unfillable N/M partial that a re-send cannot fill,
 * because decoy chunks are fresh randomness and the Merkle root differs (C3).
 * This is the same substitution a receipt uses, so it costs no extra cells and
 * changes nothing observable about the schedule.
 */
export const queueScheduledCancel = (
  epc: IRTCPeerConnection,
  channelMessageLabel: string,
): boolean => {
  const runtime = epc.coverRuntime;
  if (!runtime) return false;
  const merkleRoot = scheduledTransferRootFromLabel(channelMessageLabel);
  if (!merkleRoot) return false;
  const state = receiptState(epc);
  state.pending.push({ merkleRoot });
  while (state.pending.length > MAX_PENDING_SCHEDULED_RECEIPTS)
    state.pending.shift();
  ensureReceiptDrainJob(epc, runtime, state);
  return true;
};

export interface ScheduledDeliveryScheduleShape {
  readonly coverCadenceMs: number;
  readonly coverLanes: number;
  readonly coverFramesPerCell: number;
  readonly coverDurationEpochs: number;
}

const assertPositive = (name: string, unit: string, value: number): void => {
  if (!Number.isFinite(value) || value <= 0)
    throw new Error(`coverTransfer: ${name} must be a positive ${unit}`);
};

/**
 * The earliest a terminal scheduled receipt can possibly exist, plus head-room.
 *
 * A job is admitted only at a cycle open, so a send enqueued at t first emits
 * at the next boundary; the receiver's terminal receipt is itself a job
 * admitted at the boundary after that. Two cycles is therefore the arithmetic
 * floor. The shipped "5 min cycles" preset needs 301.2 s of it — against the
 * fixed 120 s bound this replaces, every send in such a room failed (C3).
 *
 * The third term is the wait inside the receipt's own cycle: one slot spacing,
 * except that a room stripes its lanes across the cycle, so a control job
 * dequeued onto the LAST lane emits (lanes - 0.5) spacings in, not one. That
 * term is what the margin sits on top of, so the margin stays head-room for
 * every lane count instead of being silently spent covering the stripe — a
 * bound under the floor is C3 again with a different number.
 */
export const scheduledDeliveryTimeoutMs = (
  schedule: ScheduledDeliveryScheduleShape,
): number => {
  assertPositive("cover cadence", "duration", schedule.coverCadenceMs);
  assertPositive("cover lanes", "count", schedule.coverLanes);
  assertPositive("cover frames per cell", "count", schedule.coverFramesPerCell);
  assertPositive(
    "cover duration epochs",
    "count",
    schedule.coverDurationEpochs,
  );

  const cycleMs = schedule.coverCadenceMs * schedule.coverDurationEpochs;
  const spacingMs = Math.ceil(
    coverSlotSpacingMs({ ...schedule, phaseOffsetMs: 0 }),
  );
  // coverScheduler.slotAt for ordinal `coverLanes - 1` of epoch 0: the first
  // slot the last lane of a cycle ever gets.
  const lastLaneFirstSlotMs = Math.ceil(
    ((2 * schedule.coverLanes - 1) * schedule.coverCadenceMs) /
      (2 * schedule.coverLanes * schedule.coverFramesPerCell),
  );
  return (
    2 * cycleMs +
    Math.max(spacingMs, lastLaneFirstSlotMs) +
    SCHEDULED_DELIVERY_MARGIN_MS
  );
};

/** Seal exactly one already-staged chunk into its uniform 65,490-byte cell. */
export type SealTransferSlotCell = (
  chunkIndex: number,
) => Promise<Uint8Array | null> | Uint8Array | null;

export interface ScheduledSendJobOptions {
  readonly runtime: CoverRuntime;
  /** The compiled per-message channel label; it is the job/lane id. */
  readonly channelMessageLabel: string;
  readonly totalChunks: number;
  /** This transfer's 64-byte Merkle root; the wire CANCEL is scoped to it. */
  readonly merkleRoot: Uint8Array;
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
    cancelCell: async (_slot: CoverJobSlot): Promise<Uint8Array> => {
      // The scheduled-mode wire CANCEL: an encrypted cover cell in this job's
      // next slot, sealed against the LIVE context, with a dummy tail through
      // the fixed boundary. Never a channel close — a cover lane closes at
      // every boundary regardless of transfer state. Before C3 the job defined
      // none, so CoverScheduler.cancel threw for anything already admitted.
      const cell = options.runtime.sealCoverContent({
        subtype: "cancel",
        merkleRoot: options.merkleRoot,
      });
      if (cell.length !== WIRE_CHUNK_FRAME_LEN)
        throw new Error(
          "coverTransfer: sealed cancel cell is not the uniform length",
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
