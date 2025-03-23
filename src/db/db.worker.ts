import { deleteDB } from "idb";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import { getDB, dbName } from "./src/getDB";

import type {
  MessageData,
  Chunk,
  SendQueue,
  WorkerMessages,
  WorkerMethodReturnTypes,
  BlacklistedPeer,
  UsernamedPeer,
  UniqueRoom,
  NewChunk,
} from "./types";
import type { MessageType } from "../utils/messageTypes";

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
  try {
    const db = await getDB();
    const peers = await db.getAll("addressBook");
    db.close();

    return peers;
  } catch (error) {
    return [];
  }
}

async function fnSetDBAddressBookEntry(
  username: string,
  peerId: string,
  peerPublicKey: string,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction(["addressBook"], "readwrite");
    const store = tx.objectStore("addressBook");
    const index1 = store.index("peerId");
    const index2 = store.index("peerPublicKey");

    const item1 = await index1.get(peerId);
    const item2 = await index2.get(peerPublicKey);

    if ((!item1 && !item2) || (item1 && !item2) || (!item1 && item2)) {
      await store.put({
        username,
        peerId,
        peerPublicKey,
        dateAdded: Date.now(),
      });
    }

    await tx.done;
    db.close();
  } catch (error) {
    // await db.put("addressBook", {
    //   username,
    //   peerId,
    //   peerPublicKey,
    //   dateAdded: Date.now(),
    // });
    console.error(error);
  }
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

  let pId = peerId ?? "";

  try {
    const db = await getDB();

    const tx = db.transaction("addressBook", "readwrite");
    const store = tx.objectStore("addressBook");

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
    db.close();
  } catch {}

  return pId;
}

async function fnGetDBPeerIsBlackisted(
  peerId?: string,
  peerPublicKey?: string,
): Promise<boolean> {
  if (!peerId && !peerPublicKey) return false;
  if (peerId && peerId.length < 10 && !peerPublicKey) return false;
  if (peerPublicKey && peerPublicKey.length !== 64 && !peerId) return false;

  try {
    const db = await getDB();
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
  try {
    const db = await getDB();
    const tx = db.transaction(["blacklist"], "readwrite");
    const store = tx.objectStore("blacklist");
    const index1 = store.index("peerId");
    const index2 = store.index("peerPublicKey");

    const item1 = await index1.get(peerId);
    const item2 = await index2.get(peerPublicKey);

    if ((!item1 && !item2) || (item1 && !item2) || (!item1 && item2)) {
      await store.put({
        // username,
        peerId,
        peerPublicKey,
        dateAdded: Date.now(),
      });
    }

    await tx.done;
    db.close();
  } catch (error) {
    console.error(error);
  }
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

  try {
    const db = await getDB();
    const tx = db.transaction("blacklist", "readwrite");
    const store = tx.objectStore("blacklist");

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
    db.close();
  } catch (error) {
    console.error(error);
  }
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
  try {
    const db = await getDB();
    const tx = db.transaction(["uniqueRoom"], "readwrite");
    const store = tx.objectStore("uniqueRoom");
    const index1 = store.index("roomUrl");
    const index2 = store.index("roomId");

    const item1 = await index1.get(roomUrl);
    const item2 = await index2.get(roomId);

    if (!item1 && !item2) {
      const d = Date.now();
      await store.put({
        // username,
        roomId,
        roomUrl,
        messageCount: 0,
        lastMessageMerkleRoot: "",
        createdAt: d,
        updatedAt: d,
      });
    }

    await tx.done;
    db.close();
  } catch (error) {
    console.error(error);
  }
}

async function fnGetDBMessageData(
  merkleRootHex?: string,
  hashHex?: string,
): Promise<MessageData | undefined> {
  try {
    const db = await getDB();
    const tx = db.transaction(["messageData"], "readonly");
    const store = tx.objectStore("messageData");
    const index1 = store.index("merkleRoot");
    const index2 = store.index("hash");

    if (
      merkleRootHex &&
      merkleRootHex.length === 2 * crypto_hash_sha512_BYTES
    ) {
      const messageData = await index1.get(merkleRootHex);

      if (!messageData) {
        if (hashHex && hashHex.length === 2 * crypto_hash_sha512_BYTES) {
          const messageData = await index2.get(hashHex);

          await tx.done;
          db.close();

          return messageData;
        } else {
          await tx.done;
          db.close();

          return undefined;
        }
      } else {
        await tx.done;
        db.close();

        return messageData;
      }
    } else if (hashHex && hashHex.length === 2 * crypto_hash_sha512_BYTES) {
      const messageData = await index2.get(hashHex);

      await tx.done;
      db.close();

      return messageData;
    } else {
      await tx.done;
      db.close();

      return undefined;
    }
  } catch (error) {
    console.error(error);

    return undefined;
  }
}

async function fnGetDBRoomMessageData(roomId: string): Promise<MessageData[]> {
  const db = await getDB();
  const messages = await db.getAllFromIndex("messageData", "roomId", roomId);
  db.close();

  const messagesLen = messages.length;

  const messageData: MessageData[] = [];
  for (let i = 0; i < messagesLen; i++) {
    messageData.push({
      roomId,
      merkleRoot: messages[i].merkleRoot,
      hash: messages[i].hash,
      fromPeerId: messages[i].fromPeerId,
      filename: messages[i].filename,
      messageType: messages[i].messageType,
      savedSize: messages[i].savedSize,
      totalSize: messages[i].totalSize,
      channelLabel: messages[i].channelLabel,
      timestamp: messages[i].timestamp,
    });
  }

  return messageData;
}

async function fnSetDBRoomMessageData(
  roomId: string,
  merkleRootHex: string,
  sha512Hex: string,
  fromPeerId: string,
  chunkSize: number,
  totalSize: number,
  messageType: MessageType,
  filename: string,
  channelLabel: string,
  timestamp: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction(["messageData", "uniqueRoom"], "readwrite");
    const messageStore = tx.objectStore("messageData");
    const roomStore = tx.objectStore("uniqueRoom");

    const msg = await messageStore.index("merkleRoot").get(merkleRootHex);

    // const msg = await db.getFromIndex(
    //   "messageData",
    //   "merkleRoot",
    //   merkleRootHex,
    // );

    const savedSize = msg?.savedSize ?? 0;

    // console.log(
    //   "Received " +
    //     (savedSize + chunkSize) +
    //     " with chunk size " +
    //     chunkSize +
    //     " of total " +
    //     totalSize,
    // );

    // await db.put("messageData", {
    await messageStore.put({
      roomId,
      timestamp,
      merkleRoot: merkleRootHex,
      hash: sha512Hex,
      fromPeerId,
      filename,
      messageType,
      savedSize: savedSize !== totalSize ? chunkSize + savedSize : chunkSize,
      totalSize,
      channelLabel,
    });

    if (!msg) {
      const room = await roomStore.index("roomId").get(roomId);
      // const room = await db.getFromIndex("uniqueRoom", "roomId", roomId);
      if (room && room.lastMessageMerkleRoot !== merkleRootHex) {
        // await db.put("uniqueRoom", {
        await roomStore.put({
          ...room,
          lastMessageMerkleRoot: merkleRootHex,
          messageCount: room.messageCount + 1,
          updatedAt: Date.now(),
        });
      }
    }

    await tx.done;
    db.close();
  } catch (error) {
    console.error(error);
    throw error;
  }
}

async function fnGetDBChunk(
  hashHex: string,
  chunkIndex: number,
): Promise<ArrayBuffer | undefined> {
  const db = await getDB();
  const chunk = await db.get("chunks", [hashHex, chunkIndex]);
  db.close();

  return chunk?.data;
}

async function fnExistsDBChunk(
  hashHex: string,
  chunkIndex: number,
): Promise<boolean> {
  const db = await getDB();
  const count = await db.count("chunks", [hashHex, chunkIndex]);
  db.close();

  return count > 0;
}

async function fnGetDBNewChunk(
  hashHex: string,
  chunkIndex?: number,
): Promise<NewChunk | undefined> {
  try {
    const db = await getDB();

    const c = chunkIndex ?? -1;
    if (c > -1) {
      const item = await db.get("newChunks", [hashHex, c]);
      db.close();

      return item;
    } else {
      const tx = db.transaction("newChunks");
      const store = tx.objectStore("newChunks");
      const index = store.index("realChunkHash");
      const item = await index.get(hashHex);

      await tx.done;
      db.close();

      return item;
    }
  } catch (error) {
    console.error(error);

    return undefined;
  }
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

async function fnGetDBAllChunks(
  merkleRootHex?: string,
  hashHex?: string,
): Promise<Chunk[]> {
  try {
    const db = await getDB();
    const tx = db.transaction("chunks", "readonly");
    const store = tx.objectStore("chunks");
    const index1 = store.index("hash");
    const index2 = store.index("merkleRoot");

    if (hashHex && hashHex.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index1.getAll(hashHex);

      if (chunks.length === 0) {
        if (
          merkleRootHex &&
          merkleRootHex.length === 2 * crypto_hash_sha512_BYTES
        ) {
          const chunks = await index2.getAll(merkleRootHex);

          await tx.done;
          db.close();

          return chunks;
        } else {
          await tx.done;
          db.close();

          return [];
        }
      } else {
        await tx.done;
        db.close();

        return chunks;
      }
    } else if (
      merkleRootHex &&
      merkleRootHex.length === 2 * crypto_hash_sha512_BYTES
    ) {
      const chunks = await index2.getAll(merkleRootHex);

      await tx.done;
      db.close();

      return chunks;
    } else {
      await tx.done;
      db.close();

      return [];
    }
  } catch (error) {
    console.error(error);

    return [];
  }
  //
  // try {
  //   const db = await getDB();
  //   const tx = db.transaction("chunks", "readonly");
  //   const store = tx.objectStore("chunks");
  //   const index = store.index("merkleRoot");
  //   const chunks = await index.getAll(merkleRootHex);
  //   db.close();
  //
  //   return chunks;
  // } catch (error) {
  //   console.error(error);
  //
  //   return [];
  // }
}

async function fnGetDBAllChunksCount(
  merkleRootHex?: string,
  hashHex?: string,
): Promise<number> {
  try {
    const db = await getDB();
    const tx = db.transaction(["chunks"], "readonly");
    const store = tx.objectStore("chunks");
    const index1 = store.index("hash");
    const index2 = store.index("merkleRoot");

    if (hashHex && hashHex.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index1.count(hashHex);

      if (chunks === 0) {
        if (
          merkleRootHex &&
          merkleRootHex.length === 2 * crypto_hash_sha512_BYTES
        ) {
          const chunks = await index2.count(merkleRootHex);

          await tx.done;
          db.close();

          return chunks;
        } else {
          await tx.done;
          db.close();

          return 0;
        }
      } else {
        await tx.done;
        db.close();

        return chunks;
      }
    } else if (
      merkleRootHex &&
      merkleRootHex.length === 2 * crypto_hash_sha512_BYTES
    ) {
      const chunks = await index2.count(merkleRootHex);

      await tx.done;
      db.close();

      return chunks;
    } else {
      await tx.done;
      db.close();

      return 0;
    }
  } catch (error) {
    return 0;
  }
}

async function fnSetDBChunk(chunk: Chunk): Promise<void> {
  const db = await getDB();
  await db.add("chunks", chunk);
  db.close();
}

async function fnGetDBAllNewChunks(
  hashHex?: string,
  merkleRootHex?: string,
): Promise<NewChunk[]> {
  if (!hashHex && !merkleRootHex) return [];
  if (
    hashHex?.length !== crypto_hash_sha512_BYTES * 2 &&
    merkleRootHex?.length !== crypto_hash_sha512_BYTES * 2
  )
    return [];

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

async function fnDeleteDBUniqueRoom(roomId: string): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("uniqueRoom", "readwrite");
    const store = tx.objectStore("uniqueRoom");
    const index = store.index("roomId");
    const item = await index.getKey(roomId);
    if (item) {
      await store.delete(item);
    }

    await tx.done;

    db.close();
  } catch (error) {}
}

async function fnDeleteDBChunk(
  hashHex: string,
  chunkIndex?: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("chunks", "readwrite");
    const store = tx.objectStore("chunks");

    if (chunkIndex) {
      const keys = IDBKeyRange.only([hashHex, chunkIndex]);
      await store.delete(keys);
    } else {
      const index = store.index("hash");
      const keys = await index.getAllKeys(hashHex);
      const len = keys.length;

      if (len === 0) {
        const index = store.index("merkleRoot");
        const keys = await index.getAllKeys(hashHex);
        const len = keys.length;
        for (let i = 0; i < len; i++) {
          await store.delete(keys[i]);
        }
      } else {
        for (let i = 0; i < len; i++) {
          await store.delete(keys[i]);
        }
      }
    }

    await tx.done;
    db.close();
  } catch (error) {}
}

async function fnDeleteDBNewChunk(
  merkleRootHex?: string,
  realChunkHashHex?: string,
  hashHex?: string,
  chunkIndex?: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("newChunks", "readwrite");
    const store = tx.objectStore("newChunks");

    if (merkleRootHex) {
      const index = store.index("merkleRoot");
      const keys = await index.getAllKeys(merkleRootHex);
      const len = keys.length;
      for (let i = 0; i < len; i++) {
        await store.delete(keys[i]);
      }
    } else if (hashHex && chunkIndex) {
      await store.delete([hashHex, chunkIndex]);
    } else if (realChunkHashHex) {
      const index = store.index("realChunkHash");
      const keyrange = await index.getKey(realChunkHashHex);
      if (keyrange) await store.delete(keyrange);
    }

    await tx.done;
    db.close();
  } catch (error) {
    console.error(error);
  }
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
    const tx = db.transaction(["messageData", "uniqueRoom"], "readwrite");
    const messageStore = tx.objectStore("messageData");
    const roomStore = tx.objectStore("uniqueRoom");

    const messageIndex = messageStore.index("merkleRoot");
    const keys = await messageIndex.getAllKeys(merkleRootHex);
    const len = keys.length;
    let roomId = "";
    for (let i = 0; i < len; i++) {
      if (i === 0 || roomId.length === 0) {
        const msg = await messageStore.get(keys[i]);
        roomId = msg?.roomId ?? "";
      }

      await messageStore.delete(keys[i]);
    }

    if (roomId.length > 0) {
      const roomIndex = roomStore.index("roomId");
      const room = await roomIndex.get(roomId);
      if (room) {
        const messageRoomIndex = messageStore.index("roomId");
        const messageKeys = await messageRoomIndex.getAllKeys(roomId);

        const messageKeysLen = messageKeys.length;
        const lastMessage =
          messageKeysLen > 0
            ? await messageStore.get(messageKeys[messageKeysLen - 1])
            : undefined;

        await roomStore.put({
          ...room,
          messageCount: room.messageCount > 0 ? room.messageCount - 1 : 0,
          updatedAt: lastMessage?.timestamp ?? Date.now(),
          lastMessageMerkleRoot: lastMessage?.merkleRoot ?? "",
        });
      }
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
      case "getDBMessageData":
        result = (await fnGetDBMessageData(
          ...message.args,
        )) as WorkerMethodReturnTypes["getDBMessageData"];
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
      case "deleteDBUniqueRoom":
        result = (await fnDeleteDBUniqueRoom(
          ...message.args,
        )) as WorkerMethodReturnTypes["deleteDBUniqueRoom"];
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
