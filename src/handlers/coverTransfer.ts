import { compileChannelMessageLabel } from "../utils/channelLabel";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { MAX_COVER_CHUNK_RECEIPTS } from "../cryptography/coverCell";
import {
  SCHEDULED_DELIVERY_MARGIN_MS,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";
import { coverSlotSpacingMs } from "./coverScheduler";

import type {
  CoverJob,
  CoverJobProgress,
  CoverJobSlot,
  CoverSchedulerStatus,
} from "./coverScheduler";
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
  readonly tokens?: Uint8Array[];
  readonly tokenKeys?: Set<string>;
}

interface ScheduledReceiptState {
  readonly pending: PendingScheduledControlCell[];
  drainJobActive: boolean;
  jobSequence: number;
  released: boolean;
  queuedTokens: number;
  readonly latestBatchByRoot: Map<string, PendingScheduledControlCell>;
}

const receiptStates = new WeakMap<IRTCPeerConnection, ScheduledReceiptState>();

const MAX_PENDING_SCHEDULED_RECEIPTS = 4_096;

const receiptState = (epc: IRTCPeerConnection): ScheduledReceiptState => {
  let state = receiptStates.get(epc);
  if (!state) {
    state = {
      pending: [],
      drainJobActive: false,
      jobSequence: 0,
      released: false,
      queuedTokens: 0,
      latestBatchByRoot: new Map(),
    };
    receiptStates.set(epc, state);
  }
  return state;
};

const removePendingControl = (
  state: ScheduledReceiptState,
): PendingScheduledControlCell | undefined => {
  const next = state.pending.shift();
  if (!next) return;
  state.queuedTokens -= next.tokens?.length ?? 1;
  const root = uint8ArrayToHex(next.merkleRoot);
  if (state.latestBatchByRoot.get(root) === next)
    state.latestBatchByRoot.delete(root);
  return next;
};

const wipeControl = (entry: PendingScheduledControlCell): void => {
  entry.merkleRoot.fill(0);
  entry.token?.fill(0);
  for (const token of entry.tokens ?? []) token.fill(0);
  entry.tokenKeys?.clear();
};

const boundScheduledControls = (state: ScheduledReceiptState): void => {
  while (state.queuedTokens > MAX_PENDING_SCHEDULED_RECEIPTS) {
    const dropped = removePendingControl(state);
    if (!dropped) break;
    wipeControl(dropped);
  }
};

/** Authenticated per-chunk tokens, batched only within the same transfer root. */
export const queueScheduledChunkReceipt = (
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  token: Uint8Array,
): boolean => {
  const runtime = epc.coverRuntime;
  if (!runtime || merkleRoot.length !== 64 || token.length !== 64) return false;
  const state = receiptState(epc);
  const rootKey = uint8ArrayToHex(merkleRoot),
    tokenKey = uint8ArrayToHex(token);
  let batch = state.latestBatchByRoot.get(rootKey);
  if (batch?.tokenKeys?.has(tokenKey)) return true;
  if (
    !batch ||
    !batch.tokens ||
    batch.tokens.length >= MAX_COVER_CHUNK_RECEIPTS
  ) {
    batch = {
      merkleRoot: Uint8Array.from(merkleRoot),
      tokens: [],
      tokenKeys: new Set(),
    };
    state.pending.push(batch);
    state.latestBatchByRoot.set(rootKey, batch);
  }
  batch.tokens!.push(Uint8Array.from(token));
  batch.tokenKeys!.add(tokenKey);
  state.queuedTokens++;
  boundScheduledControls(state);
  ensureReceiptDrainJob(epc, runtime, state);
  return true;
};

/**
 * Queue one legacy scheduled terminal receipt (token equals transfer root) for
 * the next available reverse control slots. Returns false when the edge has no
 * cover runtime (immediate mode) so the caller falls back to immediate
 * receipts, and drops oldest-first beyond the flood bound. Completion replaces
 * this root's unsent chunk ACKs so they cannot consume an extra reverse cycle.
 */
export const queueScheduledReceipt = (
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  token: Uint8Array,
): boolean => {
  const runtime = epc.coverRuntime;
  if (!runtime) return false;
  if (merkleRoot.length !== 64 || token.length !== 64) return false;
  const rootKey = uint8ArrayToHex(merkleRoot);
  if (uint8ArrayToHex(token) !== rootKey) return false;
  const state = receiptState(epc);
  let retained = 0;
  let terminalQueued = false;
  for (const entry of state.pending) {
    if (uint8ArrayToHex(entry.merkleRoot) === rootKey) {
      if (entry.tokens) {
        state.queuedTokens -= entry.tokens.length;
        if (state.latestBatchByRoot.get(rootKey) === entry)
          state.latestBatchByRoot.delete(rootKey);
        wipeControl(entry);
        continue;
      }
      if (entry.token && uint8ArrayToHex(entry.token) === rootKey)
        terminalQueued = true;
    }
    // Other transfers and CANCEL controls keep their existing FIFO order.
    state.pending[retained++] = entry;
  }
  state.pending.length = retained;
  if (terminalQueued) {
    ensureReceiptDrainJob(epc, runtime, state);
    return true;
  }
  state.pending.push({
    merkleRoot: Uint8Array.from(merkleRoot),
    token: Uint8Array.from(token),
  });
  state.queuedTokens++;
  boundScheduledControls(state);
  ensureReceiptDrainJob(epc, runtime, state);
  return true;
};

const ensureReceiptDrainJob = (
  epc: IRTCPeerConnection,
  runtime: CoverRuntime,
  state: ScheduledReceiptState,
): void => {
  if (state.released || state.drainJobActive || state.pending.length === 0)
    return;
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
      const next = removePendingControl(state);
      if (!next) return null; // dummy substitution for an empty slot
      try {
        if (next.tokens)
          return runtime.sealCoverContent({
            subtype: "chunk-receipts",
            merkleRoot: next.merkleRoot,
            tokens: next.tokens,
          });
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
        wipeControl(next);
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
  state.released = true;
  for (const entry of state.pending) wipeControl(entry);
  state.pending.length = 0;
  state.drainJobActive = false;
  state.queuedTokens = 0;
  state.latestBatchByRoot.clear();
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
  state.queuedTokens++;
  boundScheduledControls(state);
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

/** The scheduler surface a delivery wait polls; `CoverRuntime` satisfies it. */
export interface ScheduledJobProgressSource {
  getJobProgress(jobId: string): CoverJobProgress | undefined;
}

/** What one scheduled send has achieved; `CoverJobProgress` verbatim. */
export type ScheduledSendProgress = CoverJobProgress;

/**
 * What this send has achieved so far, or undefined once the scheduler no
 * longer holds the job.
 *
 * Batched chunk ACKs support selective resume, while older peers send only a
 * terminal receipt. Local progress also covers time before reverse receipts
 * can be admitted: the job moving up the queue and cells reaching the wire.
 */
export const scheduledSendProgress = (
  runtime: ScheduledJobProgressSource | undefined,
  jobId: string,
): ScheduledSendProgress | undefined => runtime?.getJobProgress(jobId);

/** queued → admitted → terminal, and never back again for a given attempt. */
const ADMISSION_STAGE: Readonly<
  Record<ScheduledSendProgress["state"], number>
> = { queued: 0, admitted: 1, terminal: 2 };

/**
 * Whether `next` is genuinely AHEAD of the best this send has managed so far.
 *
 * The progress signal is NOT monotone, so "it changed" is not "it advanced".
 * `CoverScheduler.sortQueue` ranks a cancel-pending job first and a `control`
 * job ahead of every `real` one (jobTier), so a receipt-drain job admitted
 * while this send waits pushes its queue position BACKWARDS; and every requeue
 * — backpressure, a lane that failed to open, a missed deadline, a suspension —
 * sends an admitted job back to "queued". Counting either as progress lets an
 * oscillating signal reset the budget forever: the send is never abandoned, the
 * receiver's partial is never cancelled, and because `sendScheduled` fans out
 * serially, every later peer in the room waits behind it unboundedly.
 *
 * So exactly three things count, in this order:
 *
 *  - the admission stage rising (queued → admitted → terminal);
 *  - within one stage, the queue position falling, which is a job climbing
 *    towards admission (-1 means "not queued at all", which the stage already
 *    carries, so it is never compared as a position);
 *  - cells accepted onto the wire rising — the one component the scheduler
 *    itself only ever increments.
 *
 * `sentCells` survives a requeue, so a job knocked back to the queue and
 * re-admitted has to emit past its own high-water mark to count again. That is
 * deliberate: a job that is requeued every cycle and never emits anything IS
 * stuck, and must still be caught.
 */
export const isForwardScheduledProgress = (
  previous: ScheduledSendProgress | undefined,
  next: ScheduledSendProgress,
): boolean => {
  if (previous === undefined) return true;
  const stage = ADMISSION_STAGE[next.state] - ADMISSION_STAGE[previous.state];
  if (stage !== 0) return stage > 0;
  if (next.queuePosition !== previous.queuePosition)
    return (
      next.queuePosition >= 0 &&
      previous.queuePosition >= 0 &&
      next.queuePosition < previous.queuePosition
    );
  return next.sentCells > previous.sentCells;
};

/**
 * True while this edge's cover scheduler is SUSPENDED: a browser-imposed gap
 * (a hidden tab, pagehide, freeze, offline) in which the schedule is not
 * running at all.
 *
 * Deliberately narrow. An absent runtime (the edge was torn down) and a stopped
 * one are NOT this: they are conditions the idle budget must still expire on,
 * so the send can reach its resume — or, failing that, tell the receiver.
 * Only the state that both keeps the job alive and makes progress impossible
 * holds the clock.
 */
export const scheduledCoverIsSuspended = (
  runtime: { readonly status: CoverSchedulerStatus } | undefined,
): boolean => runtime?.status === "suspended";

export interface ScheduledDeliveryWaitOptions {
  /** True once the receiver's terminal scheduled receipt has settled the send. */
  readonly isComplete: () => boolean;
  /** See scheduledSendProgress. */
  readonly progress: () => ScheduledSendProgress | undefined;
  /**
   * True while progress is IMPOSSIBLE rather than merely absent. See
   * scheduledCoverIsSuspended; omitted, the budget always accrues.
   */
  readonly isSuspended?: () => boolean;
  /** Explicit transport/PQ generation change retires this attempt immediately. */
  readonly isInvalidated?: () => boolean;
  /**
   * How long this send may make NO observable progress before it is given up
   * on. An IDLE budget, never a total deadline.
   */
  readonly idleTimeoutMs: number;
  readonly pollMs?: number;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly signal?: AbortSignal;
}

const SCHEDULED_DELIVERY_POLL_MS = 200;

/**
 * Wait for one scheduled send to be confirmed, giving up only when it stops
 * making progress.
 *
 * `scheduledDeliveryTimeoutMs` derives the arithmetic FLOOR of a confirmation:
 * two cycles plus the receipt's wait inside its own cycle. That floor assumes
 * this send is admitted at the very next cycle open — but only `coverLanes`
 * jobs are admitted per cycle (CoverScheduler.openCycle dequeues exactly that
 * many), so a third concurrent message on a two-lane five-minute edge is not
 * admitted for cycles and legitimately needs many times the floor. Treating
 * the floor as a total deadline therefore failed healthy sends, and — once an
 * inbound CANCEL sweeps the receiver's partial — that spurious failure DELETES
 * a transfer that was still arriving.
 *
 * Widening the arithmetic cannot fix this: the queue depth is not knowable
 * when the bound is computed and keeps changing while the send waits. So the
 * same derived number is used as an idle budget instead. A send that is still
 * climbing the queue or still emitting cells is never abandoned however long
 * it takes in total; a send that has genuinely stopped is abandoned exactly
 * one floor after its last sign of life.
 *
 * The budget measures time in which progress was POSSIBLE and did not happen.
 * `CoverRuntime` suspends the scheduler on visibilitychange→hidden, pagehide,
 * freeze and offline, and `CoverScheduler.suspend` requeues but KEEPS the job:
 * the signal freezes while the send is perfectly healthy. Spending the budget
 * through that gap abandons a live send, and the CANCEL that follows deletes a
 * partial the peer is still holding — so the clock is held while the scheduler
 * is suspended AND still holds this job. It is deliberately not held for a
 * runtime that is merely gone: only the state that makes progress impossible
 * without ending the job counts, so a genuinely stalled send is still caught.
 *
 * The boundary of holding the clock is a page that is hidden and never comes
 * back: this wait then does not return until it does, or until `signal` aborts.
 * That is the direction the peer can survive — the job stays queued and still
 * has every cell to give — where giving up would destroy its partial for good.
 */
export const waitForScheduledDelivery = async (
  options: ScheduledDeliveryWaitOptions,
): Promise<boolean> => {
  const now = options.now ?? (() => Date.now());
  const sleep =
    options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const pollMs = options.pollMs ?? SCHEDULED_DELIVERY_POLL_MS;
  if (!Number.isFinite(options.idleTimeoutMs) || options.idleTimeoutMs <= 0)
    throw new Error("coverTransfer: delivery idle budget must be positive");

  let best = options.progress();
  let lastProgressAt = now();
  for (;;) {
    if (options.signal?.aborted) return false;
    if (options.isComplete()) return true;
    if (options.isInvalidated?.()) return false;

    // `undefined` is the job having left the scheduler, not a step backwards:
    // it stops the clock being reset, so the remaining wait is exactly the
    // receipt window — and it is also what makes a torn-down edge expire.
    const current = options.progress();
    if (current !== undefined) {
      if (isForwardScheduledProgress(best, current)) {
        best = current;
        lastProgressAt = now();
      } else if (options.isSuspended?.() === true) {
        lastProgressAt = now();
      }
    }
    if (now() - lastProgressAt >= options.idleTimeoutMs) break;
    await sleep(pollMs);
  }

  return !options.signal?.aborted && options.isComplete();
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
  /** Live constant-time membership; preferred over repeated defensive copies. */
  readonly isChunkAcked?: (chunkIndex: number) => boolean;
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
    const acked = options.isChunkAcked
      ? undefined
      : (options.getAckedChunks?.() ?? EMPTY_ACK_SET);
    while (cursor < realIndices.length) {
      const index = realIndices[cursor];
      if (!(options.isChunkAcked?.(index) ?? acked!.has(index))) return index;
      cursor += 1;
    }
    return null;
  };

  return {
    id: options.channelMessageLabel,
    kind: "real",
    declaredCellCount: options.totalChunks,
    exhausted: () => cursor >= realIndices.length,
    nextCell: async (_slot: CoverJobSlot): Promise<Uint8Array | null> => {
      const index = nextRealIndex();
      if (index === null) return null; // dummy substitution: nothing left to send
      const cell = await options.sealSlotCell(index);
      if (cell === null) return null;
      if (cell.length !== WIRE_CHUNK_FRAME_LEN)
        throw new Error(
          "coverTransfer: sealed transfer cell is not the uniform length",
        );
      cursor += 1;
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
