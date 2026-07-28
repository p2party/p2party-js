import {
  deleteDBNewChunk,
  deleteDBUniqueRoom,
  deleteReceiveTransfer,
  getDBRoomMessageData,
} from "../../db/api";

import type { MessageData } from "../../db/types";

export interface DeleteRoomDataDependencies {
  readonly getMessages: (roomId: string) => Promise<MessageData[]>;
  readonly deleteRoomRecord: (roomId: string) => Promise<void>;
  readonly deleteReceive: (merkleRootHex: string) => Promise<void>;
  readonly deleteOutgoing: (merkleRootHex: string) => Promise<void>;
}

const productionDependencies: DeleteRoomDataDependencies = {
  getMessages: getDBRoomMessageData,
  deleteRoomRecord: deleteDBUniqueRoom,
  deleteReceive: deleteReceiveTransfer,
  deleteOutgoing: async (merkleRootHex) =>
    await deleteDBNewChunk({ merkleRootHex }),
};

/**
 * Await every durable room-data deletion and report only after all reachable
 * records were attempted. `removeLocalMessage` is reducer-only; no background
 * listener owns storage completion after this function returns.
 */
export const deleteRoomDataTerminal = async (
  roomId: string,
  removeLocalMessage: (merkleRootHex: string) => void,
  dependencies: DeleteRoomDataDependencies = productionDependencies,
): Promise<void> => {
  const failures: unknown[] = [];
  let messages: MessageData[] = [];
  try {
    messages = await dependencies.getMessages(roomId);
  } catch (error) {
    failures.push(error);
  }
  try {
    await dependencies.deleteRoomRecord(roomId);
  } catch (error) {
    failures.push(error);
  }
  for (const message of messages) {
    try {
      await dependencies.deleteReceive(message.merkleRoot);
    } catch (error) {
      failures.push(error);
    }
    try {
      await dependencies.deleteOutgoing(message.merkleRoot);
    } catch (error) {
      failures.push(error);
    }
    removeLocalMessage(message.merkleRoot);
  }
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      "Room data deletion did not fully settle",
    );
};
