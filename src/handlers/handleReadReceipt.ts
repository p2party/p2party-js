import { getDBNewChunkByReceipt } from "../db/api";

import { decompileChannelMessageLabel } from "../utils/channelLabel";
import { uint8ArrayToHex } from "../utils/uint8array";
import {
  hasChunkAcked,
  isTransferComplete,
  isTransferCancelled,
  markChunkAcked,
  markTransferComplete,
} from "./reconcile";
import { persistOutboundReceipt } from "./outbox";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type { ScheduledReceiptDependencies } from "./scheduledReceiptAcceptance";

export interface ReadReceiptDependencies {
  readonly persist?: typeof persistOutboundReceipt;
  readonly getChunk?: ScheduledReceiptDependencies["getChunk"];
}

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
  dependencies: ReadReceiptDependencies = {},
): Promise<ReadReceiptOutcome> => {
  try {
    if (receivedChunkHash.length !== 64) return { kind: "ignored", peerId };
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
    if (!transferId || isTransferCancelled(roomId, peerId, transferId))
      return { kind: "ignored", peerId };
    const peerPublicKey = room.peers?.find(
      (peer) => peer.peerId === peerId,
    )?.peerPublicKey;
    if (!peerPublicKey) return { kind: "ignored", peerId };
    const isCurrent = (): boolean => {
      const current = (api.getState() as State).rooms.find(
        (candidate) => candidate.id === roomId,
      );
      return (
        !isTransferCancelled(roomId, peerId, transferId) &&
        current?.peers.some(
          (peer) =>
            peer.peerId === peerId && peer.peerPublicKey === peerPublicKey,
        ) === true &&
        current.messages.some(
          (message) =>
            message.transferId === transferId &&
            message.merkleRootHex === merkleRootHex,
        )
      );
    };
    const persist = (chunkIndex?: number) =>
      (dependencies.persist ?? persistOutboundReceipt)({
        roomId,
        peerId,
        peerPublicKey,
        transferId,
        merkleRootHex,
        ...(chunkIndex === undefined ? {} : { chunkIndex }),
      });

    if (hex === hashHex) {
      if (isTransferComplete(roomId, peerId, transferId))
        return {
          kind: "peer-complete",
          peerId,
          transferId,
          newlyAccepted: false,
        };
      if (!(await persist()) || !isCurrent())
        return { kind: "ignored", peerId };
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

      return {
        kind: "peer-complete",
        peerId,
        transferId,
        newlyAccepted: true,
      };
    } else {
      const chunk = await (dependencies.getChunk ?? getDBNewChunkByReceipt)(
        merkleRootHex,
        hex,
      );
      const chunkIndex = chunk?.chunkIndex ?? -1;
      if (
        chunk &&
        chunk.transferId === transferId &&
        chunk.merkleRoot === merkleRootHex &&
        chunk.receiptToken === hex &&
        Number.isSafeInteger(chunkIndex) &&
        chunkIndex > -1
      ) {
        if (!isCurrent()) return { kind: "ignored", peerId };
        if (hasChunkAcked(roomId, peerId, transferId, chunkIndex))
          return {
            kind: "chunk-acked",
            peerId,
            transferId,
            chunkIndex,
            newlyAccepted: false,
          };
        if (!isCurrent() || !(await persist(chunkIndex)) || !isCurrent())
          return { kind: "ignored", peerId };
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
