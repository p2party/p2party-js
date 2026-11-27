import {
  deleteDBNewChunk,
  deleteDBUniqueRoom,
  deleteReceiveTransfer,
  getDBRoomMessageData,
} from "../../db/api";

import type { MessageData } from "../../db/types";

export interface DeleteRoomDataDependencies {
  readonly getMessages: (roomId: string) => Promise<MessageData[]>;
  readonly deleteRoomRecord: (
    roomId: string,
  ) => Promise<readonly string[] | void>;
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
  const roots = new Set(messages.map((message) => message.merkleRoot));
  try {
    // Includes leases written before the first chunk and messages committed
    // since the listing above. The room deletion stamps them atomically.
    const stamped = await dependencies.deleteRoomRecord(roomId);
    for (const root of stamped ?? []) roots.add(root);
  } catch (error) {
    failures.push(error);
  }
  for (const root of roots) {
    try {
      await dependencies.deleteReceive(root);
    } catch (error) {
      failures.push(error);
    }
    try {
      await dependencies.deleteOutgoing(root);
    } catch (error) {
      failures.push(error);
    }
    removeLocalMessage(root);
  }
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      "Room data deletion did not fully settle",
    );
};
