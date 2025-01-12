import { openDB, deleteDB } from "idb";

import type { DBSchema, IDBPDatabase } from "idb";
import type {
  MessageData,
  Chunk,
  SendQueue,
  WorkerMessages,
  WorkerMethodReturnTypes,
} from "./types";
import type { SetMessageAllChunksArgs } from "../reducers/roomSlice";

export const dbName = "p2party";
export const dbVersion = 2;

export interface RepoSchema extends DBSchema {
  messageData: {
    value: MessageData;
    key: [string, string];
    indexes: { roomId: string };
  };
  chunks: {
    value: Chunk;
    key: [string, number];
    indexes: { merkleRoot: string };
  };
  sendQueue: {
    value: SendQueue;
    key: [number, string, string];
    indexes: { labelPeer: string };
  };
}

async function getDB(): Promise<IDBPDatabase<RepoSchema>> {
  return openDB<RepoSchema>(dbName, dbVersion, {
    upgrade(db) {
      if (!db.objectStoreNames.contains("messageData")) {
        const messageData = db.createObjectStore("messageData", {
          keyPath: ["roomId", "hash"],
        });
        messageData.createIndex("roomId", "roomId", { unique: false });
      }

      if (!db.objectStoreNames.contains("chunks")) {
        const chunks = db.createObjectStore("chunks", {
          keyPath: ["merkleRoot", "chunkIndex"],
        });
        chunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
      }

      if (!db.objectStoreNames.contains("sendQueue")) {
        const sendQueue = db.createObjectStore("sendQueue", {
          keyPath: ["position", "label", "toPeerId"],
        });
        sendQueue.createIndex("labelPeer", ["label", "toPeerId"], {
          unique: false,
        });
      }
    },
  });
}

// Define each function with the expected arguments and return type:

async function fnGetDBRoomMessageData(
  roomId: string,
): Promise<SetMessageAllChunksArgs[]> {
  const db = await getDB();
  const messageData = await db.getAllFromIndex("messageData", "roomId", roomId);
  db.close();

  const messages: SetMessageAllChunksArgs[] = [];
  const messageDataLen = messageData.length;
  for (let i = 0; i < messageDataLen; i++) {
    messages.push({
      merkleRootHex: messageData[i].merkleRoot,
      sha512Hex: messageData[i].hash,
      fromPeerId: messageData[i].fromPeedId,
      filename: messageData[i].filename,
      messageType: messageData[i].messageType,
      totalSize: messageData[i].totalSize,
      channelLabel: messageData[i].channelLabel,
    });
  }

  return messages;
}

async function fnSetDBRoomMessageData(
  roomId: string,
  message: SetMessageAllChunksArgs,
): Promise<void> {
  const db = await getDB();

  await db.put("messageData", {
    roomId,
    timestamp: Date.now(),
    merkleRoot: message.merkleRootHex,
    hash: message.sha512Hex,
    fromPeedId: message.fromPeerId,
    filename: message.filename,
    messageType: message.messageType,
    totalSize: message.totalSize,
    channelLabel: message.channelLabel,
  });

  db.close();
}

async function fnGetDBChunk(
  merkleRootHex: string,
  chunkIndex: number,
): Promise<ArrayBuffer | undefined> {
  const db = await getDB();
  const chunk = await db.get("chunks", [merkleRootHex, chunkIndex]);
  db.close();
  return chunk?.data;
}

async function fnExistsDBChunk(
  merkleRootHex: string,
  chunkIndex: number,
): Promise<boolean> {
  const db = await getDB();
  const count = await db.count("chunks", [merkleRootHex, chunkIndex]);
  db.close();
  return count > 0;
}

async function fnGetDBSendQueue(
  label: string,
  toPeerId: string,
  position?: number,
): Promise<SendQueue[]> {
  const db = await getDB();

  if (position) {
    const item = await db.get("sendQueue", [position, label, toPeerId]);
    db.close();

    if (!item) return [];
    return [item];
  }

  const tx = db.transaction("sendQueue", "readonly");
  const store = tx.objectStore("sendQueue");
  const index = store.index("labelPeer");
  const keyRange = IDBKeyRange.only([label, toPeerId]);
  const sendQueue = await index.getAll(keyRange);
  db.close();

  return sendQueue;
}

async function fnCountDBSendQueue(
  label: string,
  toPeerId: string,
): Promise<number> {
  const db = await getDB();
  // const sendQueueCount = await db.countFromIndex(
  //   "sendQueue",
  //   "labelPeer",
  //   label + toPeerId,
  // );

  const tx = db.transaction("sendQueue", "readonly");
  const store = tx.objectStore("sendQueue");
  const index = store.index("labelPeer");
  const keyRange = IDBKeyRange.only([label, toPeerId]);
  const sendQueueCount = await index.count(keyRange);
  db.close();

  return sendQueueCount;
}

async function fnGetDBAllChunks(merkleRootHex: string): Promise<Chunk[]> {
  const db = await getDB();
  const chunksCount = await db.countFromIndex(
    "chunks",
    "merkleRoot",
    merkleRootHex,
  );
  if (chunksCount > 0) {
    const chunks = await db.getAllFromIndex(
      "chunks",
      "merkleRoot",
      merkleRootHex,
    );
    db.close();
    return chunks;
  } else {
    const tx = db.transaction("chunks", "readonly");
    const store = tx.objectStore("chunks");
    const index = store.index("merkleRoot");
    const keyRange = IDBKeyRange.only(merkleRootHex);
    const chunks = await index.getAll(keyRange);
    db.close();
    return chunks;
  }
}

async function fnGetDBAllChunksCount(merkleRootHex: string): Promise<number> {
  const db = await getDB();
  const chunksCount = await db.countFromIndex(
    "chunks",
    "merkleRoot",
    merkleRootHex,
  );
  db.close();
  return chunksCount;
}

async function fnSetDBChunk(chunk: Chunk): Promise<void> {
  const db = await getDB();
  await db.put("chunks", chunk);
  db.close();
}

async function fnSetDBSendQueue(item: SendQueue): Promise<void> {
  const db = await getDB();
  await db.put("sendQueue", item);
  db.close();
}

async function fnDeleteDBChunk(
  merkleRootHex: string,
  chunkIndex?: number,
): Promise<void> {
  const db = await getDB();
  if (chunkIndex) {
    await db.delete("chunks", [merkleRootHex, chunkIndex]);
  } else {
    const keyRange = IDBKeyRange.only(merkleRootHex);
    await db.delete("chunks", keyRange);
  }

  db.close();
}

async function fnDeleteDBSendQueue(
  label: string,
  toPeerId: string,
  position?: number,
): Promise<void> {
  const db = await getDB();
  if (position) {
    await db.delete("sendQueue", [position, label, toPeerId]);
  } else {
    const keyRange = IDBKeyRange.only([label, toPeerId]);
    await db.delete("sendQueue", keyRange);
  }
  db.close();
}

async function fnDeleteDB(): Promise<void> {
  const db = await getDB();
  db.close();
  await deleteDB(dbName);
}

onmessage = async (e: MessageEvent) => {
  const message = e.data as WorkerMessages;
  const { id, method } = message;
  try {
    let result: WorkerMethodReturnTypes[typeof method];
    switch (method) {
      case "getDBRoomMessageData":
        result = (await fnGetDBRoomMessageData(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBRoomMessageData"];
        break;
      case "setDBRoomMessageData":
        result = (await fnSetDBRoomMessageData(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBRoomMessageData"];
        break;
      case "getDBChunk":
        result = (await fnGetDBChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBChunk"];
        break;
      case "existsDBChunk":
        result = (await fnExistsDBChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["existsDBChunk"];
        break;
      case "getDBSendQueue":
        result = (await fnGetDBSendQueue(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBSendQueue"];
        break;
      case "getDBAllChunks":
        result = (await fnGetDBAllChunks(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBAllChunks"];
        break;
      case "getDBAllChunksCount":
        result = (await fnGetDBAllChunksCount(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBAllChunksCount"];
        break;
      case "setDBChunk":
        result = (await fnSetDBChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBChunk"];
        break;
      case "setDBSendQueue":
        result = (await fnSetDBSendQueue(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBSendQueue"];
        break;
      case "countDBSendQueue":
        result = (await fnCountDBSendQueue(
          ...message.args,
        )) as WorkerMethodReturnTypes["countDBSendQueue"];
        break;
      case "deleteDBChunk":
        result = (await fnDeleteDBChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBChunk"];
        break;
      case "deleteDBSendQueue":
        result = (await fnDeleteDBSendQueue(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBSendQueue"];
        break;
      case "deleteDB":
        result = (await fnDeleteDB()) as WorkerMethodReturnTypes["deleteDB"];
        break;
      default:
        postMessage({ id, error: "Method not found" });
        return;
    }

    postMessage({ id, result });
  } catch (error: any) {
    postMessage({ id, error: String(error) });
  }
};
