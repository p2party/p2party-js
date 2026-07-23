import webrtcApi from "../api/webrtc";

import { getDBNewChunkByReceipt } from "../db/api";

import { decompileChannelMessageLabel } from "../utils/channelLabel";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { markChunkAcked, markTransferComplete } from "./reconcile";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export type ReadReceiptOutcome =
  | {
      kind: "ignored";
      peerId: string;
    }
  | {
      kind: "chunk-acked";
      peerId: string;
      transferId: string;
      chunkIndex: number;
      newlyAccepted: boolean;
    }
  | {
      kind: "peer-complete";
      peerId: string;
      transferId: string;
      newlyAccepted: boolean;
    };

export const handleReadReceipt = async (
  receivedChunkHash: Uint8Array,
  channel: string,
  peerId: string,
  roomId: string,
  api: BaseQueryApi,
): Promise<ReadReceiptOutcome> => {
  try {
    const hex = uint8ArrayToHex(receivedChunkHash);

    const { merkleRootHex } = await decompileChannelMessageLabel(
      channel, //.label,
    );

    // Read current state after the async label parse. A Room captured when the
    // DataChannel was configured is an immutable Redux snapshot and may predate
    // this transfer or its latest progress.
    const { rooms } = api.getState() as State;
    const room = rooms.find((candidate) => candidate.id === roomId);
    if (!room) return { kind: "ignored", peerId };

    const messageIndex = room.messages.findLastIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );

    if (messageIndex < 0) return { kind: "ignored", peerId };

    const hashHex = room.messages[messageIndex].sha512Hex;
    const transferId = room.messages[messageIndex].transferId;
    // Only locally-originated v18 messages own an outbound transfer identity.
    // A receipt on any other message/channel is not actionable.
    if (!transferId) return { kind: "ignored", peerId };

    if (hex === hashHex) {
      // Completion is an edge fact, not a room-global fact. Marking one peer
      // complete must not set the shared message to "all peers complete".
      const newlyAccepted = markTransferComplete(room.id, peerId, transferId);
      if (!newlyAccepted)
        return {
          kind: "peer-complete",
          peerId,
          transferId,
          newlyAccepted: false,
        };

      const messageHash = hexToUint8Array(hashHex);
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          roomId: room.id,
          peerId, //: channel.withPeerId,
          label: channel, //.label,
          messageHash,
          alsoDeleteData: false,
          alsoSendFinishedMessage: false,
        }),
      );

      return {
        kind: "peer-complete",
        peerId,
        transferId,
        newlyAccepted: true,
      };
    } else {
      const chunk = await getDBNewChunkByReceipt(merkleRootHex, hex);
      const chunkIndex = chunk?.chunkIndex ?? -1;
      if (chunk && chunk.transferId === transferId && chunkIndex > -1) {
        // The boolean is the idempotence boundary. Do not repeatedly increment
        // a shared Redux savedSize from stale snapshots; reconciliation and
        // delivery outcomes remain scoped to this exact peer edge.
        const newlyAccepted = markChunkAcked(
          room.id,
          peerId,
          transferId,
          chunkIndex,
        );
        return {
          kind: "chunk-acked",
          peerId,
          transferId,
          chunkIndex,
          newlyAccepted,
        };
      }
    }
    return { kind: "ignored", peerId };
  } catch (error) {
    console.error(error);
    throw error;
  }
};
