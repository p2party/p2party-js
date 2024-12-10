import { openDB } from "idb";

import type { DBSchema, IDBPDatabase } from "idb";

export const dbName = "p2party";
export const dbVersion = 1;

export interface Chunk {
  merkleRoot: string;
  chunkIndex: number;
  totalSize: number;
  data: Blob;
  mimeType: string;
}

export interface SendQueue {
  position: number;
  label: string;
  toPeerId: string;
  encryptedData: Blob;
}

export interface RepoSchema extends DBSchema {
  chunks: {
    value: Chunk;
    key: [string, number]; // Composite key: [merkleRootHex, chunkIndex]
    indexes: {
      /** Index to query all chunks by merkleRoot */
      merkleRoot: string;
    };
  };

  sendQueue: {
    value: SendQueue;
    key: [number, string, string]; // Composite key: [position, label, toPeerId]
    indexes: {
      labelPeer: string;
    };
  };
}

export const getDB = async (): Promise<IDBPDatabase<RepoSchema>> => {
  return await openDB<RepoSchema>(dbName, dbVersion, {
    upgrade(db) {
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

    blocked() {
      console.error("IndexedDB is blocked");
    },

    blocking() {
      console.error("IndexedDB is blocking");
    },

    terminated() {
      console.error("IndexedDB is terminated");
    },
  });
};

export const getDBChunk = async (merkleRootHex: string, chunkIndex: number) => {
  const db = await getDB();

  const chunk = await db.get("chunks", [merkleRootHex, chunkIndex]);

  db.close();

  return chunk?.data;
};

export const existsDBChunk = async (
  merkleRootHex: string,
  chunkIndex: number,
) => {
  const db = await getDB();

  const count = await db.count("chunks", [merkleRootHex, chunkIndex]);

  db.close();

  return count > 0;
};

export const getDBSendQueue = async (label: string, toPeerId: string) => {
  const db = await getDB();

  const sendQueueCount = await db.countFromIndex(
    "sendQueue",
    "labelPeer",
    label + toPeerId,
  );

  if (sendQueueCount > 0) {
    const sendQueue = await db.getAllFromIndex(
      "sendQueue",
      "labelPeer",
      label + toPeerId,
    );

    db.close();

    return sendQueue;
  } else {
    const tx = db.transaction("sendQueue", "readonly");
    const store = tx.objectStore("sendQueue");
    const index = store.index("labelPeer");
    const keyRange = IDBKeyRange.only([label, toPeerId]);
    const sendQueue = await index.getAll(keyRange);

    db.close();

    return sendQueue;
  }
};

export const getDBAllChunks = async (merkleRootHex: string) => {
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
};

export const getDBAllChunksCount = async (merkleRootHex: string) => {
  const db = await getDB();

  const chunksCount = await db.countFromIndex(
    "chunks",
    "merkleRoot",
    merkleRootHex,
  );

  db.close();

  return chunksCount;
};

export const setDBChunk = async (chunk: Chunk) => {
  const db = await getDB();

  await db.put("chunks", chunk);

  db.close();
};

export const setDBSendQueue = async (chunk: SendQueue) => {
  const db = await getDB();

  await db.put("sendQueue", chunk);

  db.close();
};

export const deleteDBChunk = async (
  merkleRootHex: string,
  chunkIndex?: number,
) => {
  const db = await getDB();
  if (chunkIndex) {
    await db.delete("chunks", [merkleRootHex, chunkIndex]);
  } else {
    const chunks = await getDBAllChunks(merkleRootHex);
    const chunksLen = chunks.length;
    for (let i = 0; i < chunksLen; i++) {
      await db.delete("chunks", [merkleRootHex, chunks[i].chunkIndex]);
    }
  }

  db.close();
};

export const deleteDBSendQueueItem = async (
  position: number,
  label: string,
  toPeerId: string,
) => {
  const db = await getDB();
  await db.delete("sendQueue", [position, label, toPeerId]);

  db.close();
};

const methods: Record<string, (...args: any[]) => Promise<any>> = {
  getDBChunk,
  existsDBChunk,
  getDBSendQueue,
  getDBAllChunks,
  getDBAllChunksCount,
  setDBChunk,
  setDBSendQueue,
  deleteDBChunk,
  deleteDBSendQueueItem,
};

self.onmessage = async (e: MessageEvent) => {
  const { method, args } = e.data;
  if (methods[method]) {
    try {
      const result = await methods[method](...args);
      postMessage({ id: e.data.id, result });
    } catch (error) {
      postMessage({ id: e.data.id, error: String(error) });
    }
  } else {
    postMessage({ id: e.data.id, error: "Method not found" });
  }
};
