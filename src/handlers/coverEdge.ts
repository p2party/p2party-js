import { CoverRuntime, type CoverLaneChannel } from "./coverRuntime";
import { buildScheduledSendJob } from "./coverTransfer";
import { markTransferComplete } from "./reconcile";

import type { CoverStatusChange } from "./coverScheduler";
import type { IRTCDataChannel, IRTCPeerConnection } from "../api/webrtc/interfaces";
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
}

/**
 * Construct and START the scheduled-cover runtime for one authenticated edge.
 * Called after `runHandshake` on a `coverMode: "scheduled"` room. Idempotent
 * per connection: a replacement handshake destroys the previous runtime first.
 */
export const installCoverEdge = (options: InstallCoverEdgeOptions): void => {
  const { epc, roomId, policy } = options;
  if (policy.coverMode !== "scheduled") return;
  if (epc.coverRuntime) {
    epc.coverRuntime.destroy();
    epc.coverRuntime = undefined;
  }
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
      epc.coverChannels!.add(channel);
      channel.addEventListener("close", () => {
        epc.coverChannels?.delete(channel);
      });
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
    onRemoteCancel: options.onRemoteCancel,
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
    sealSlotCell: params.sealSlotCell,
    getAckedChunks: params.getAckedChunks,
  });
  runtime.enqueue(job);
  return true;
};
