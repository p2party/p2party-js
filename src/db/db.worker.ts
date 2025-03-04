import { openDB, deleteDB } from "idb";

import type { DBSchema, IDBPDatabase } from "idb";
import type {
  MessageData,
  Chunk,
  SendQueue,
  WorkerMessages,
  WorkerMethodReturnTypes,
  AddressBook,
  BlacklistedPeer,
  UsernamedPeer,
  UniqueRoom,
  NewChunk,
} from "./types";
import type { SetMessageAllChunksArgs } from "../reducers/roomSlice";

export const dbName = "p2party";
export const dbVersion = 7;

export interface RepoSchema extends DBSchema {
  addressBook: {
    value: AddressBook;
    key: [string];
    indexes: { peerId: string; peerPublicKey: string; username: string };
  };
  blacklist: {
    value: BlacklistedPeer;
    key: [string];
    indexes: { peerId: string; peerPublicKey: string; username: string };
  };
  uniqueRoom: {
    value: UniqueRoom;
    key: [string];
    indexes: { roomId: string; roomUrl: string };
  };
  messageData: {
    value: MessageData;
    key: [number, string, string];
    indexes: {
      roomId: string;
      hash: string;
      merkleRoot: string;
      fromPeerId: string;
    };
  };
  chunks: {
    value: Chunk;
    key: [string, number];
    indexes: { merkleRoot: string };
  };
  newChunks: {
    value: NewChunk;
    key: [string, number];
    indexes: { hash: string; merkleRoot: string };
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
      if (!db.objectStoreNames.contains("addressBook")) {
        const addressBook = db.createObjectStore("addressBook", {
          keyPath: ["peerId"],
        });
        addressBook.createIndex("username", "username", { unique: false });
        addressBook.createIndex("peerId", "peerId", { unique: true });
        addressBook.createIndex("peerPublicKey", "peerPublicKey", {
          unique: true,
        });
      }

      if (!db.objectStoreNames.contains("blacklist")) {
        const blacklist = db.createObjectStore("blacklist", {
          keyPath: ["peerId"],
        });
        blacklist.createIndex("username", "username", { unique: false });
        blacklist.createIndex("peerId", "peerId", { unique: true });
        blacklist.createIndex("peerPublicKey", "peerPublicKey", {
          unique: true,
        });
      }

      if (!db.objectStoreNames.contains("uniqueRoom")) {
        const uniqueRoom = db.createObjectStore("uniqueRoom", {
          keyPath: ["roomId"],
        });
        uniqueRoom.createIndex("roomUrl", "roomUrl", { unique: true });
        uniqueRoom.createIndex("roomId", "roomId", { unique: true });
      }

      if (!db.objectStoreNames.contains("messageData")) {
        const messageData = db.createObjectStore("messageData", {
          keyPath: ["timestamp", "roomId", "hash"],
        });
        messageData.createIndex("roomId", "roomId", { unique: false });
        messageData.createIndex("hash", "hash", { unique: false });
        messageData.createIndex("merkleRoot", "merkleRoot", { unique: true });
        messageData.createIndex("fromPeerId", "fromPeerId", { unique: false });
      }

      if (!db.objectStoreNames.contains("chunks")) {
        const chunks = db.createObjectStore("chunks", {
          keyPath: ["merkleRoot", "chunkIndex"],
        });
        chunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
      }

      if (!db.objectStoreNames.contains("newChunks")) {
        const newChunks = db.createObjectStore("newChunks", {
          keyPath: ["hash", "chunkIndex"],
        });
        newChunks.createIndex("hash", "hash", { unique: false });
        newChunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
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

async function fnGetDBAddressBookEntry(
  peerId?: string,
  peerPublicKey?: string,
): Promise<UsernamedPeer | undefined> {
  if (!peerId && !peerPublicKey) return undefined;
  if (peerId && peerId.length < 10 && !peerPublicKey) return undefined;
  if (peerPublicKey && peerPublicKey.length !== 64 && !peerId) return undefined;

  const db = await getDB();

  try {
    const tx = db.transaction("addressBook", "readonly");
    const index = peerId
      ? tx.objectStore("addressBook").index("peerId")
      : tx.objectStore("addressBook").index("peerPublicKey");
    const peer = peerId
      ? await index.get(peerId)
      : await index.get(peerPublicKey!);
    await tx.done;
    db.close();
    return peer
      ? {
          username: peer.username,
          peerId: peer.peerId,
          peerPublicKey: peer.peerPublicKey,
        }
      : undefined;
  } catch (error) {
    db.close();

    return undefined;
  }
}

async function fnGetAllDBAddressBookEntries(): Promise<UsernamedPeer[]> {
  const db = await getDB();

  try {
    const peers = await db.getAll("addressBook");
    db.close();

    return peers;
  } catch (error) {
    db.close();

    return [];
  }
}

async function fnSetDBAddressBookEntry(
  username: string,
  peerId: string,
  peerPublicKey: string,
): Promise<void> {
  const db = await getDB();

  try {
    const tx = db.transaction("addressBook", "readonly");
    const index1 = tx.objectStore("addressBook").index("peerId");
    const index2 = tx.objectStore("addressBook").index("peerPublicKey");

    const item1 = await index1.get(peerId);
    const item2 = await index2.get(peerPublicKey);

    await tx.done;

    if ((!item1 && !item2) || (item1 && !item2) || (!item1 && item2)) {
      await db.put("addressBook", {
        username,
        peerId,
        peerPublicKey,
        dateAdded: Date.now(),
      });
    }
  } catch (error) {
    await db.put("addressBook", {
      username,
      peerId,
      peerPublicKey,
      dateAdded: Date.now(),
    });
  }

  db.close();
}

async function fnDeleteDBAddressBookEntry(
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
): Promise<string> {
  const noUsername = !username || username.length === 0;
  const noPeerId = !peerId || peerId.length < 10;
  const noPeerPublicKey = !peerPublicKey || peerPublicKey.length !== 64;

  if (noUsername && noPeerId && noPeerPublicKey)
    throw new Error("Cannot delete address book with no data");

  const db = await getDB();

  const tx = db.transaction("addressBook", "readwrite");
  const store = tx.objectStore("addressBook");

  let pId = peerId ?? "";

  try {
    if (!noPeerId) {
      const index = store.index("peerId");
      const item = await index.getKey(peerId);

      if (item) await store.delete(item);
    } else if (!noPeerPublicKey) {
      const index = store.index("peerPublicKey");
      const item = await index.getKey(peerPublicKey);

      if (item) {
        const entry = await index.get(peerPublicKey);
        pId = entry?.peerId ?? "";

        await store.delete(item);
      }
    } else {
      const index = store.index("username");
      const item = await index.getKey(username!);

      if (item) {
        const entry = await index.get(username!);
        pId = entry?.peerId ?? "";

        await store.delete(item);
      }
    }

    await tx.done;
  } catch {}

  db.close();

  return pId;
}

async function fnGetDBPeerIsBlackisted(
  peerId?: string,
  peerPublicKey?: string,
): Promise<boolean> {
  if (!peerId && !peerPublicKey) return false;
  if (peerId && peerId.length < 10 && !peerPublicKey) return false;
  if (peerPublicKey && peerPublicKey.length !== 64 && !peerId) return false;

  const db = await getDB();

  try {
    const tx = db.transaction("blacklist", "readonly");
    const index = peerId
      ? tx.objectStore("blacklist").index("peerId")
      : tx.objectStore("blacklist").index("peerPublicKey");
    const peer = peerId
      ? await index.get(peerId)
      : await index.get(peerPublicKey!);
    await tx.done;

    db.close();

    return peer ? true : false;
  } catch (error) {
    db.close();

    return false;
  }
}

async function fnGetAllDBBlacklisted(): Promise<BlacklistedPeer[]> {
  const db = await getDB();

  try {
    const peers = await db.getAll("blacklist");
    db.close();

    return peers;
  } catch (error) {
    db.close();

    return [];
  }
}

async function fnSetDBPeerInBlacklist(
  // username: string,
  peerId: string,
  peerPublicKey: string,
): Promise<void> {
  const db = await getDB();

  try {
    const tx = db.transaction("blacklist", "readonly");
    const index1 = tx.objectStore("blacklist").index("peerId");
    const index2 = tx.objectStore("blacklist").index("peerPublicKey");

    const item1 = await index1.get(peerId);
    const item2 = await index2.get(peerPublicKey);

    await tx.done;

    if ((!item1 && !item2) || (item1 && !item2) || (!item1 && item2)) {
      await db.put("blacklist", {
        // username,
        peerId,
        peerPublicKey,
        dateAdded: Date.now(),
      });
    }
  } catch (error) {
    await db.put("blacklist", {
      // username,
      peerId,
      peerPublicKey,
      dateAdded: Date.now(),
    });
  }

  db.close();
}

async function fnDeleteDBPeerFromBlacklist(
  // username: string,
  peerId?: string,
  peerPublicKey?: string,
): Promise<void> {
  const noPeerId = !peerId || peerId.length < 10;
  const noPeerPublicKey = !peerPublicKey || peerPublicKey.length !== 64;

  if (noPeerId && noPeerPublicKey)
    throw new Error("Cannot delete blacklisted with no data");

  const db = await getDB();

  const tx = db.transaction("blacklist", "readwrite");
  const store = tx.objectStore("blacklist");

  try {
    if (!noPeerId) {
      const index = store.index("peerId");
      const item = await index.getKey(peerId);

      if (item) await store.delete(item);
    } else {
      const index = store.index("peerPublicKey");
      const item = await index.getKey(peerPublicKey!);

      if (item) await store.delete(item);
    }

    await tx.done;
  } catch {}

  db.close();
}

async function fnGetAllDBUniqueRooms(): Promise<UniqueRoom[]> {
  const db = await getDB();

  try {
    const rooms = await db.getAll("uniqueRoom");
    db.close();

    return rooms;
  } catch (error) {
    db.close();

    return [];
  }
}

async function fnSetDBUniqueRoom(
  roomUrl: string,
  roomId: string,
): Promise<void> {
  const db = await getDB();

  try {
    const tx = db.transaction("uniqueRoom", "readwrite");
    const index1 = tx.objectStore("uniqueRoom").index("roomUrl");
    const index2 = tx.objectStore("uniqueRoom").index("roomId");

    const item1 = await index1.get(roomUrl);
    const item2 = await index2.get(roomId);

    await tx.done;

    if (!item1 && !item2) {
      const d = Date.now();
      await db.put("uniqueRoom", {
        // username,
        roomId,
        roomUrl,
        messageCount: 0,
        lastMessageMerkleRoot: "",
        createdAt: d,
        updatedAt: d,
      });
    }
  } catch (error) {
    console.error(error);
  }

  db.close();
}

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
      roomId,
      merkleRootHex: messageData[i].merkleRoot,
      sha512Hex: messageData[i].hash,
      fromPeerId: messageData[i].fromPeedId,
      filename: messageData[i].filename,
      messageType: messageData[i].messageType,
      totalSize: messageData[i].totalSize,
      channelLabel: messageData[i].channelLabel,
      timestamp: messageData[i].timestamp,
    });
  }

  return messages;
}

async function fnSetDBRoomMessageData(
  roomId: string,
  message: SetMessageAllChunksArgs,
): Promise<void> {
  const db = await getDB();

  try {
    const tx = db.transaction("messageData", "readonly");
    const index = tx.objectStore("messageData").index("merkleRoot");
    const item = await index.get(message.merkleRootHex);
    await tx.done;

    if (!item) {
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

      const roomTx = db.transaction("uniqueRoom", "readwrite");
      const indx = roomTx.objectStore("uniqueRoom").index("roomId");
      const itm = await indx.get(roomId);
      await roomTx.done;

      if (itm && itm.lastMessageMerkleRoot !== message.merkleRootHex) {
        await db.put("uniqueRoom", {
          roomId,
          roomUrl: itm.roomUrl,
          messageCount: itm.messageCount + 1,
          lastMessageMerkleRoot: message.merkleRootHex,
          createdAt: itm.createdAt,
          updatedAt: Date.now(),
        });
      }
    }
  } catch (error) {
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

    const roomTx = db.transaction("uniqueRoom", "readwrite");
    const indx = roomTx.objectStore("uniqueRoom").index("roomId");
    const itm = await indx.get(roomId);
    await roomTx.done;

    if (itm && itm.lastMessageMerkleRoot !== message.merkleRootHex) {
      await db.put("uniqueRoom", {
        roomId,
        roomUrl: itm.roomUrl,
        messageCount: itm.messageCount + 1,
        lastMessageMerkleRoot: message.merkleRootHex,
        createdAt: itm.createdAt,
        updatedAt: Date.now(),
      });
    }
  }

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

async function fnGetDBNewChunk(
  hashHex: string,
  chunkIndex: number,
): Promise<NewChunk | undefined> {
  const db = await getDB();
  const chunk = await db.get("newChunks", [hashHex, chunkIndex]);
  db.close();
  return chunk;
}

async function fnExistsDBNewChunk(
  hashHex: string,
  chunkIndex: number,
): Promise<boolean> {
  const db = await getDB();
  const count = await db.count("newChunks", [hashHex, chunkIndex]);
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

async function fnGetDBAllNewChunks(
  hashHex?: string,
  merkleRootHex?: string,
): Promise<NewChunk[]> {
  if (!hashHex && !merkleRootHex) return [];
  const db = await getDB();
  const chunksCount = hashHex
    ? await db.countFromIndex("newChunks", "hash", hashHex)
    : await db.countFromIndex("newChunks", "merkleRoot", merkleRootHex);
  if (chunksCount > 0) {
    const chunks = hashHex
      ? await db.getAllFromIndex("newChunks", "hash", hashHex)
      : await db.getAllFromIndex("newChunks", "merkleRoot", merkleRootHex);
    db.close();
    return chunks;
  } else {
    const tx = db.transaction("newChunks", "readonly");
    const store = tx.objectStore("newChunks");
    const index = hashHex ? store.index("hash") : store.index("merkleRoot");
    const keyRange = hashHex
      ? IDBKeyRange.only(hashHex)
      : IDBKeyRange.only(merkleRootHex);
    const chunks = await index.getAll(keyRange);
    db.close();
    return chunks;
  }
}

async function fnGetDBAllNewChunksCount(hashHex: string): Promise<number> {
  const db = await getDB();
  const chunksCount = await db.countFromIndex("newChunks", "hash", hashHex);
  db.close();
  return chunksCount;
}

async function fnSetDBNewChunk(chunk: NewChunk): Promise<void> {
  const db = await getDB();
  await db.put("newChunks", chunk);
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
  try {
    const db = await getDB();
    const tx = db.transaction("chunks", "readwrite");
    const store = tx.objectStore("chunks");

    if (chunkIndex) {
      const keys = IDBKeyRange.only([merkleRootHex, chunkIndex]);
      await store.delete(keys);
    } else {
      const index = store.index("merkleRoot");
      const keys = await index.getAllKeys(merkleRootHex);
      const len = keys.length;
      for (let i = 0; i < len; i++) {
        await store.delete(keys[i]);
      }
    }

    await tx.done;
    db.close();
  } catch (error) {}
}

async function fnDeleteDBNewChunk(
  hashHex: string,
  chunkIndex?: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("newChunks", "readwrite");
    const store = tx.objectStore("newChunks");

    if (chunkIndex) {
      const keys = IDBKeyRange.only([hashHex, chunkIndex]);
      await store.delete(keys);
    } else {
      const index = store.index("hash");
      const keys = await index.getAllKeys(hashHex);
      const len = keys.length;
      for (let i = 0; i < len; i++) {
        await store.delete(keys[i]);
      }
    }

    await tx.done;
    db.close();
  } catch (error) {}
}

async function fnDeleteDBSendQueue(
  label: string,
  toPeerId: string,
  position?: number,
): Promise<void> {
  try {
    const db = await getDB();
    if (position) {
      await db.delete("sendQueue", [position, label, toPeerId]);
    } else {
      const keyRange = IDBKeyRange.only([label, toPeerId]);
      await db.delete("sendQueue", keyRange);
    }
    db.close();
  } catch (error) {}
}

async function fnDeleteDBMessageData(merkleRootHex: string): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("messageData", "readwrite");
    const store = tx.objectStore("messageData");
    const index = store.index("merkleRoot");
    const keys = await index.getAllKeys(merkleRootHex);
    const len = keys.length;
    for (let i = 0; i < len; i++) {
      await store.delete(keys[i]);
    }
    await tx.done;
    db.close();
  } catch (error) {}
}

async function fnDeleteDB(): Promise<void> {
  await deleteDB(dbName, {
    blocked() {
      console.error("DB deletion BLOCKED");
    },
  });
}

onmessage = async (e: MessageEvent) => {
  const message = e.data as WorkerMessages;
  const { id, method } = message;
  try {
    let result: WorkerMethodReturnTypes[typeof method];
    switch (method) {
      case "getDBAddressBookEntry":
        result = (await fnGetDBAddressBookEntry(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBAddressBookEntry"];
        break;
      case "getAllDBAddressBookEntries":
        result = (await fnGetAllDBAddressBookEntries(
          ...message.args,
        )) as WorkerMethodReturnTypes["getAllDBAddressBookEntries"];
        break;
      case "setDBAddressBookEntry":
        result = (await fnSetDBAddressBookEntry(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBAddressBookEntry"];
        break;
      case "deleteDBAddressBookEntry":
        result = (await fnDeleteDBAddressBookEntry(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBAddressBookEntry"];
        break;
      case "getDBPeerIsBlacklisted":
        result = (await fnGetDBPeerIsBlackisted(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBPeerIsBlacklisted"];
        break;
      case "getAllDBBlacklisted":
        result = (await fnGetAllDBBlacklisted(
          ...message.args,
        )) as WorkerMethodReturnTypes["getAllDBBlacklisted"];
        break;
      case "setDBPeerInBlacklist":
        result = (await fnSetDBPeerInBlacklist(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBPeerInBlacklist"];
        break;
      case "deleteDBPeerFromBlacklist":
        result = (await fnDeleteDBPeerFromBlacklist(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBPeerFromBlacklist"];
        break;
      case "getAllDBUniqueRooms":
        result = (await fnGetAllDBUniqueRooms(
          ...message.args,
        )) as WorkerMethodReturnTypes["getAllDBUniqueRooms"];
        break;
      case "setDBUniqueRoom":
        result = (await fnSetDBUniqueRoom(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBUniqueRoom"];
        break;
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
      case "getDBNewChunk":
        result = (await fnGetDBNewChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBNewChunk"];
        break;
      case "existsDBNewChunk":
        result = (await fnExistsDBNewChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["existsDBNewChunk"];
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
      case "getDBAllNewChunks":
        result = (await fnGetDBAllNewChunks(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBAllNewChunks"];
        break;
      case "getDBAllNewChunksCount":
        result = (await fnGetDBAllNewChunksCount(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBAllNewChunksCount"];
        break;
      case "setDBNewChunk":
        result = (await fnSetDBNewChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["setDBNewChunk"];
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
      case "deleteDBNewChunk":
        result = (await fnDeleteDBNewChunk(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBNewChunk"];
        break;
      case "deleteDBMessageData":
        result = (await fnDeleteDBMessageData(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBMessageData"];
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
