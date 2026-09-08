import { CoverRuntime, type CoverLaneChannel } from "./coverRuntime";
import { buildScheduledSendJob, queueScheduledCancel } from "./coverTransfer";
import { markTransferComplete } from "./reconcile";
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
// every cycle boundary; real message chunks, PQ control cells, receipts, and
// CANCEL substitute into already-scheduled slots as cells, and dummy cover
// cells fill the rest. This module owns the production lane wiring: the
// CoverRuntime's `openLaneChannel` creates real `RTCDataChannel`s via
// `epc.createDataChannel`, tracked in `epc.coverChannels` (never
// `messageChannels`, so continuous cover lanes never block healing quiescence
// or exhaust the message-channel budget). Cells route on the receive side
// purely by their leading type byte.

const LANE_LABEL_NAME = "p2party-cover";

/** Map a fully-received transfer root back to the sender's transferId so a
 * terminal scheduled receipt can settle the local send. */
const transferIdByRoot = new WeakMap<
  IRTCPeerConnection,
  Map<string, { transferId: string; peerId: string; roomId: string }>
>();

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
}

/**
 * Stop scheduled cover on an edge and release its lanes.
 *
 * destroy() emits the terminal "stopped" status, so any observer of
 * rooms[].coverStatusByPeer stops claiming cover for this edge. Safe to call
 * on an edge that never had a runtime.
 */
export const teardownCoverEdge = (epc: IRTCPeerConnection): void => {
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
    onRemoteCancel: (merkleRootHex) => {
      // A CANCEL is about ONE transfer root, and that root can be in flight in
      // either direction. The caller's hook aborts our outbound send of it
      // (abortTransfer, which only ever searches the outbound registry); the
      // sweep below drops the partial we are RECEIVING for it, which nothing
      // did before — the receiver kept an unfillable N/M transfer, its OPFS
      // file and its state row forever.
      options.onRemoteCancel?.(merkleRootHex);
      void sweepCancelledInboundTransfer(
        epc,
        roomId,
        merkleRootHex,
        options.inboundSweepDeps,
      );
    },
    onScheduledReceipt: (merkleRootHex) => {
      // A terminal scheduled receipt confirms the whole message landed; settle
      // the matching local send so its waiter resolves.
      const entry = transferIdByRoot.get(epc)?.get(merkleRootHex);
      if (entry)
        markTransferComplete(entry.roomId, entry.peerId, entry.transferId);
    },
  });
  epc.coverRuntime = runtime;
  runtime.start();
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
  map.set(merkleRootHex, { transferId, peerId, roomId });
};

export interface ScheduledSendParams {
  readonly epc: IRTCPeerConnection;
  readonly channelMessageLabel: string;
  readonly totalChunks: number;
  /** This transfer's 64-byte Merkle root; the job's wire CANCEL is scoped to it. */
  readonly merkleRoot: Uint8Array;
  readonly sealSlotCell: (chunkIndex: number) => Promise<Uint8Array | null>;
  readonly getAckedChunks?: () => ReadonlySet<number>;
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
