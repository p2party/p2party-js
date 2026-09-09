import { CoverRuntime, type CoverLaneChannel } from "./coverRuntime";
import {
  buildScheduledSendJob,
  queueScheduledCancel,
  releaseScheduledReceipts,
} from "./coverTransfer";
import {
  createReceiptProcessingQueue,
  enqueueReceipt,
  releaseQueuedReceipts,
} from "./handleMessageQueueing";
import {
  acceptScheduledReceipt,
  acceptScheduledCancellation,
  type ScheduledReceiptDependencies,
  type ScheduledReceiptOwner,
} from "./scheduledReceiptAcceptance";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import type { ReceiptProcessingQueue } from "./handleMessageQueueing";
import { registerCoverChannelUntilClose } from "./coverChannelRegistry";
import { sweepCancelledInboundTransfer } from "./inboundTransferSweep";

import type { InboundTransferSweepDeps } from "./inboundTransferSweep";
import type { CoverStatusChange } from "./coverScheduler";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { RoomPolicyV1 } from "../roomPolicy";
import type { LibCrypto } from "../cryptography/libcrypto";

// ── protocol-v4 scheduled-cover edge installation ────────────────────────────
//
// In a scheduled room there are NO separate per-message DataChannels. Each
// endpoint opens exactly `coverLanes` outbound cover lanes per peer edge at
// every cycle boundary; real message chunks, receipts, and
// CANCEL substitute into already-scheduled slots as cells, and dummy cover
// cells fill the rest. This module owns the production lane wiring: the
// CoverRuntime's `openLaneChannel` creates real `RTCDataChannel`s via
// `epc.createDataChannel`, tracked in `epc.coverChannels` (never
// `messageChannels`, so continuous cover lanes never block healing quiescence
// or exhaust the message-channel budget). Cells route on the receive side
// purely by their leading type byte.

const LANE_LABEL_NAME = "p2party-cover";

/** Bind authenticated chunk/completion receipts to this exact outbound owner. */
const transferIdByRoot = new WeakMap<
  IRTCPeerConnection,
  Map<string, ScheduledReceiptOwner>
>();
const scheduledReceiptQueues = new WeakMap<
  IRTCPeerConnection,
  ReceiptProcessingQueue
>();

// ── per-edge cover generation ────────────────────────────────────────────────
//
// A monotonic counter per (roomId, peerId) that is bumped by, and only by, a
// successfully installed cover runtime or a durable PQ epoch change. Both
// retire old-key producers; the sender may re-derive on a replacement runtime
// or after its current runtime's epoch changed (C6/C8).
//
// It is deliberately NOT the job's progress: `CoverScheduler.getJobProgress`
// stops moving whenever the scheduler is suspended (a hidden tab, pagehide,
// freeze, offline) while the job is perfectly healthy, so a resume gated on
// progress would fire for an ordinary backgrounded tab. It is also deliberately
// not a teardown counter: an edge that only died has no replacement runtime to
// re-offer the message on, and re-offering it onto nothing would burn the
// sender's resume budget for free.
//
// Keyed by the EDGE, never by the RTCPeerConnection: a replacement connection
// and an in-place re-bind both keep the same room/peer identity, and the
// connection object is exactly what does not survive. The map holds two numbers
// per edge and no object references, so it retains nothing.
interface CoverEdgeGenerationState {
  generation: number;
  readonly waiters: Set<(generation: number) => void>;
}

const coverEdgeGenerations = new Map<string, CoverEdgeGenerationState>();

// The map is keyed by (room, peer), so a long-lived page that meets many peers
// across many rooms grows it without bound. Each entry holds two numbers and no
// object references, so this is a slow leak rather than a retention bug — but
// unbounded is unbounded, so it is capped.
//
// Eviction is only sound because a published generation now comes from ONE
// process-wide monotonic counter instead of a per-edge one. A re-created entry
// restarts at 0, which is below every number ever issued, so a caller still
// holding an old `since` can never read a recycled value as an advance; and the
// next install on that edge publishes a strictly larger number than anything
// that edge ever had. An entry with a waiter is never evicted: someone is on it.
const MAX_TRACKED_COVER_EDGES = 512;
let lastPublishedCoverGeneration = 0;

const pruneCoverEdgeGenerations = (reservedKey?: string): void => {
  if (coverEdgeGenerations.size <= MAX_TRACKED_COVER_EDGES) return;
  // A Map iterates in insertion order, so this drops the oldest idle edges.
  for (const [key, state] of coverEdgeGenerations) {
    if (coverEdgeGenerations.size <= MAX_TRACKED_COVER_EDGES) return;
    if (key !== reservedKey && state.waiters.size === 0)
      coverEdgeGenerations.delete(key);
  }
};

const coverEdgeKey = (roomId: string, peerId: string): string =>
  `${roomId}\u0000${peerId}`;

const ensureCoverEdgeState = (
  roomId: string,
  peerId: string,
): CoverEdgeGenerationState => {
  const key = coverEdgeKey(roomId, peerId);
  let state = coverEdgeGenerations.get(key);
  if (!state) {
    state = { generation: 0, waiters: new Set() };
    coverEdgeGenerations.set(key, state);
    // The caller is about to attach a waiter or publish a generation on this
    // state. If every older entry has waiters, evicting this new entry would
    // detach that caller from all future publications for its edge.
    pruneCoverEdgeGenerations(key);
  }
  return state;
};

/**
 * Monotonic scheduled-attempt generation: runtime installation or committed
 * PQ rekey. Zero before the first install and for immediate-mode edges.
 */
export const coverEdgeGeneration = (roomId: string, peerId: string): number =>
  coverEdgeGenerations.get(coverEdgeKey(roomId, peerId))?.generation ?? 0;

/**
 * Resolve with this edge's cover generation once it is past `since`, or with
 * the unchanged current generation if none is installed within `timeoutMs`.
 *
 * A caller compares the result with what it passed in: strictly greater means a
 * runtime or key epoch changed; the sender checks which current runtime/epoch
 * owns that change before re-deriving. Equal means this attempt is unchanged.
 *
 * `signal` ends the wait early with the CURRENT generation, i.e. with "nothing
 * replaced anything" unless something actually did. A cancelled send must not
 * sit here for the whole resume budget — the fan-out is serial, so that budget
 * is charged to every later peer as well — and answering "no replacement" is
 * the answer that makes the caller stop rather than re-derive onto an edge
 * nobody is waiting for any more.
 */
export const waitForCoverEdgeGeneration = (
  roomId: string,
  peerId: string,
  since: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<number> => {
  const state = ensureCoverEdgeState(roomId, peerId);
  if (state.generation > since) return Promise.resolve(state.generation);
  if (signal?.aborted === true) return Promise.resolve(state.generation);
  if (!(timeoutMs > 0)) return Promise.resolve(state.generation);
  return new Promise<number>((resolve) => {
    const settle = (generation: number): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      state.waiters.delete(waiter);
      pruneCoverEdgeGenerations();
      resolve(generation);
    };
    const waiter = (generation: number): void => {
      settle(generation);
    };
    const onAbort = (): void => {
      settle(state.generation);
    };
    const timer = setTimeout(() => {
      settle(state.generation);
    }, timeoutMs);
    state.waiters.add(waiter);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
};

/** Publish a newly installed runtime as this edge's next cover generation. */
const advanceCoverEdgeGeneration = (roomId: string, peerId: string): void => {
  const state = ensureCoverEdgeState(roomId, peerId);
  // Process-wide monotonic, not per-edge: see MAX_TRACKED_COVER_EDGES. It is
  // still strictly increasing for every individual edge, which is the only
  // property `since` comparisons rely on.
  lastPublishedCoverGeneration += 1;
  state.generation = lastPublishedCoverGeneration;
  const generation = state.generation;
  // Copy first: a waiter removes itself from the set as it settles.
  for (const waiter of [...state.waiters]) waiter(generation);
};

export interface InstallCoverEdgeOptions {
  readonly epc: IRTCPeerConnection;
  readonly roomId: string;
  readonly policy: RoomPolicyV1;
  readonly policyHash: Uint8Array;
  readonly amInitiator: boolean;
  readonly module: LibCrypto;
  readonly onRemoteCancel?: (merkleRootHex: string) => void;
  readonly onStatusChange?: (change: CoverStatusChange) => void;
  /**
   * Storage seam for the inbound half of a remote CANCEL. Defaults to the
   * production Worker-backed functions.
   */
  readonly inboundSweepDeps?: InboundTransferSweepDeps;
  readonly receiptDependencies?: ScheduledReceiptDependencies;
}

/**
 * Stop scheduled cover on an edge and release its lanes.
 *
 * destroy() emits the terminal "stopped" status, so any observer of
 * rooms[].coverStatusByPeer stops claiming cover for this edge. Safe to call
 * on an edge that never had a runtime.
 */
export const teardownCoverEdge = (epc: IRTCPeerConnection): void => {
  const queue = scheduledReceiptQueues.get(epc);
  if (queue) releaseQueuedReceipts(queue);
  scheduledReceiptQueues.delete(epc);
  transferIdByRoot.delete(epc);
  releaseScheduledReceipts(epc);
  if (epc.coverRuntime) {
    epc.coverRuntime.destroy();
    epc.coverRuntime = undefined;
  }
  if (epc.coverChannels) {
    for (const lane of epc.coverChannels)
      if (lane.readyState !== "closed") lane.close();
    epc.coverChannels.clear();
    epc.coverChannels = undefined;
  }
};

/**
 * Construct and START the scheduled-cover runtime for one authenticated edge.
 * Called after `runHandshake` on a `coverMode: "scheduled"` room. Idempotent
 * per connection: a replacement handshake destroys the previous runtime first.
 */
export const installCoverEdge = (options: InstallCoverEdgeOptions): void => {
  const { epc, roomId, policy } = options;
  if (policy.coverMode !== "scheduled") return;
  teardownCoverEdge(epc);
  epc.coverChannels ??= new Set<IRTCDataChannel>();

  const receiptQueue = createReceiptProcessingQueue(roomId, epc.withPeerId);
  scheduledReceiptQueues.set(epc, receiptQueue);
  const processReceipt = async (packed: Uint8Array): Promise<void> => {
    const merkleRootHex = uint8ArrayToHex(packed.subarray(1, 65));
    const owner = transferIdByRoot.get(epc)?.get(merkleRootHex);
    if (!owner) return;
    const isCurrent = (): boolean =>
      !receiptQueue.released &&
      transferIdByRoot.get(epc)?.get(merkleRootHex) === owner &&
      owner.roomId === roomId &&
      epc.roomId === roomId &&
      owner.peerId === epc.withPeerId &&
      owner.peerPublicKey === epc.withPeerPublicKey;
    if (packed[0] === 2) {
      if (
        await acceptScheduledCancellation(
          owner,
          isCurrent,
          options.receiptDependencies,
        )
      )
        options.onRemoteCancel?.(merkleRootHex);
      return;
    }
    await acceptScheduledReceipt(
      owner,
      packed.subarray(65),
      packed[0] === 1 ? "chunk" : "terminal",
      isCurrent,
      options.receiptDependencies,
    );
  };
  const queueReceipt = (
    root: string,
    token: Uint8Array,
    kind: 0 | 1 | 2,
  ): void => {
    if (token.length !== 64 || !/^[0-9a-f]{128}$/.test(root)) return;
    const packed = new Uint8Array(129);
    packed[0] = kind;
    packed.set(hexToUint8Array(root), 1);
    packed.set(token, 65);
    enqueueReceipt(packed, receiptQueue, processReceipt);
  };

  const runtime = new CoverRuntime({
    epc,
    roomId,
    module: options.module,
    amInitiator: options.amInitiator,
    schedule: {
      coverCadenceMs: policy.coverCadenceMs,
      coverLanes: policy.coverLanes,
      coverFramesPerCell: policy.coverFramesPerCell,
      coverDurationEpochs: policy.coverDurationEpochs,
    },
    policyHash: options.policyHash,
    laneLabelName: LANE_LABEL_NAME,
    openLaneChannel: (label): CoverLaneChannel => {
      const channel = epc.createDataChannel(label, {
        ordered: true,
        protocol: "raw",
      }) as IRTCDataChannel;
      channel.binaryType = "arraybuffer";
      channel.withPeerId = epc.withPeerId;
      channel.roomIds = [roomId];
      try {
        registerCoverChannelUntilClose(epc.coverChannels!, channel);
      } catch (error) {
        if (channel.readyState !== "closed") channel.close();
        throw error;
      }
      return {
        label: channel.label,
        get readyState() {
          return channel.readyState;
        },
        get bufferedAmount() {
          return channel.bufferedAmount;
        },
        send: (data) => channel.send(data),
        close: () => {
          if (channel.readyState !== "closed") channel.close();
        },
      };
    },
    onStatusChange: options.onStatusChange,
    onKeyEpochChanged: () => advanceCoverEdgeGeneration(roomId, epc.withPeerId),
    onRemoteCancel: (merkleRootHex) => {
      // Persist a recipient's refusal before waking its sender. The inbound
      // sweep is independent: never await it inside the receipt queue that it
      // drains, and never abort the other recipients of this logical send.
      if (transferIdByRoot.get(epc)?.has(merkleRootHex))
        queueReceipt(merkleRootHex, hexToUint8Array(merkleRootHex), 2);
      else options.onRemoteCancel?.(merkleRootHex);
      void sweepCancelledInboundTransfer(
        epc,
        roomId,
        merkleRootHex,
        options.inboundSweepDeps,
      );
    },
    onScheduledReceipt: (root, token) => queueReceipt(root, token, 0),
    onScheduledChunkReceipts: (root, tokens) => {
      for (const token of tokens) queueReceipt(root, token, 1);
    },
  });
  epc.coverRuntime = runtime;
  runtime.start();
  // Publish the replacement LAST, once the runtime is installed and started, so
  // a sender woken by the bump always finds an admitting runtime on the edge.
  // Synchronous: nothing here awaits, and the handshake path that calls this
  // must not gain a suspension point.
  advanceCoverEdgeGeneration(roomId, epc.withPeerId);
};

/** Record the root→transferId mapping so a terminal receipt settles the send. */
export const trackScheduledSend = (
  epc: IRTCPeerConnection,
  roomId: string,
  peerId: string,
  merkleRootHex: string,
  transferId: string,
): void => {
  let map = transferIdByRoot.get(epc);
  if (!map) {
    map = new Map();
    transferIdByRoot.set(epc, map);
  }
  map.set(merkleRootHex, {
    transferId,
    peerId,
    roomId,
    peerPublicKey: epc.withPeerPublicKey,
    merkleRootHex,
  });
};

export const untrackScheduledSend = (
  epc: IRTCPeerConnection,
  merkleRootHex: string,
  transferId: string,
): void => {
  const map = transferIdByRoot.get(epc);
  if (map?.get(merkleRootHex)?.transferId === transferId)
    map.delete(merkleRootHex);
};

export interface ScheduledSendParams {
  readonly epc: IRTCPeerConnection;
  readonly channelMessageLabel: string;
  readonly totalChunks: number;
  /** This transfer's 64-byte Merkle root; the job's wire CANCEL is scoped to it. */
  readonly merkleRoot: Uint8Array;
  readonly sealSlotCell: (chunkIndex: number) => Promise<Uint8Array | null>;
  readonly getAckedChunks?: () => ReadonlySet<number>;
  readonly isChunkAcked?: (chunkIndex: number) => boolean;
}

/**
 * Enqueue one message as a lazy scheduled-send job on this edge's cover
 * runtime. Returns false when the edge has no cover runtime (immediate mode).
 */
export const enqueueScheduledSend = (params: ScheduledSendParams): boolean => {
  const runtime = params.epc.coverRuntime;
  if (!runtime) return false;
  const job = buildScheduledSendJob({
    runtime,
    channelMessageLabel: params.channelMessageLabel,
    totalChunks: params.totalChunks,
    merkleRoot: params.merkleRoot,
    sealSlotCell: params.sealSlotCell,
    getAckedChunks: params.getAckedChunks,
    isChunkAcked: params.isChunkAcked,
  });
  runtime.enqueue(job);
  return true;
};

/**
 * Ask the runtime to emit this transfer's wire CANCEL in its next slot.
 *
 * A job the scheduler still holds carries its own `cancelCell`. A job that has
 * already settled — the usual state once a delivery bound expires, because the
 * cells were all emitted and only the receipt is missing — answers "not-found",
 * and before C3 that is where the receiver was abandoned: it kept an unfillable
 * N/M partial forever while the sender deleted the only thing that could have
 * filled it. That case falls back to a standalone CANCEL control cell, which
 * substitutes into an already-scheduled slot exactly as a receipt does, so it
 * changes nothing observable about the room's fixed schedule.
 */
export const cancelScheduledSend = (
  epc: IRTCPeerConnection,
  channelMessageLabel: string,
): "not-found" | "cancelled-before-admission" | "cancel-pending" => {
  const runtime = epc.coverRuntime;
  if (!runtime) return "not-found";
  let routed: ReturnType<CoverRuntime["cancel"]>;
  try {
    routed = runtime.cancel(channelMessageLabel);
  } catch (error) {
    console.error("coverEdge: could not cancel a scheduled send", error);
    routed = "not-found";
  }
  if (routed !== "not-found") return routed;
  return queueScheduledCancel(epc, channelMessageLabel)
    ? "cancel-pending"
    : "not-found";
};
