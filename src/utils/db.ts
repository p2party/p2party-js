import { openDB } from "idb";

// import { hexToUint8Array } from "./uint8array";

import type { DBSchema, IDBPDatabase } from "idb";

export const dbName = "p2party";
export const dbVersion = 1;

export interface Chunk {
  merkleRoot: string;
  chunkIndex: number;
  // totalSize: number;
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
          // autoIncrement: false,
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

export const getDBChunk = async (
  merkleRootHex: string,
  chunkIndex: number,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    const chunk = await db.get("chunks", [merkleRootHex, chunkIndex]);

    if (shouldClose) db.close();

    return chunk?.data;

    // if (chunk) return hexToUint8Array(chunk.data);

    // return;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const existsDBChunk = async (
  merkleRootHex: string,
  chunkIndex: number,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    const count = await db.count("chunks", [merkleRootHex, chunkIndex]);

    if (shouldClose) db.close();

    return count > 0;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const getDBSendQueue = async (
  label: string,
  toPeerId: string,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

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

      if (shouldClose) db.close();

      return sendQueue;
    } else {
      const tx = db.transaction("sendQueue", "readonly");
      const store = tx.objectStore("sendQueue");
      const index = store.index("labelPeer");
      const keyRange = IDBKeyRange.only([label, toPeerId]);
      const sendQueue = await index.getAll(keyRange);

      if (shouldClose) db.close();

      return sendQueue;
    }
  } catch (error) {
    console.error(error);

    throw error;
  }
};

export const getDBAllChunks = async (
  merkleRootHex: string,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

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

      if (shouldClose) db.close();

      return chunks;
    } else {
      const tx = db.transaction("chunks", "readonly");
      const store = tx.objectStore("chunks");
      const index = store.index("merkleRoot");
      const keyRange = IDBKeyRange.only(merkleRootHex);
      const chunks = await index.getAll(keyRange);

      if (shouldClose) db.close();

      return chunks;
    }
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const getDBAllChunksCount = async (
  merkleRootHex: string,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    const chunksCount = await db.countFromIndex(
      "chunks",
      "merkleRoot",
      merkleRootHex,
    );

    if (shouldClose) db.close();

    return chunksCount;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const setDBChunk = async (
  chunk: Chunk,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    await db.put("chunks", chunk);

    if (shouldClose) db.close();
  } catch (error) {
    throw error;
  }
};

export const setDBSendQueue = async (
  chunk: SendQueue,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    await db.put("sendQueue", chunk);

    if (shouldClose) db.close();
  } catch (error) {
    throw error;
  }
};

export const deleteDBChunk = async (
  merkleRootHex: string,
  chunkIndex?: number,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());
    if (chunkIndex) {
      await db.delete("chunks", [merkleRootHex, chunkIndex]);
    } else {
      const chunks = await getDBAllChunks(merkleRootHex, db);
      const chunksLen = chunks.length;
      for (let i = 0; i < chunksLen; i++) {
        await db.delete("chunks", [merkleRootHex, chunks[i].chunkIndex]);
      }
    }

    if (shouldClose) db.close();
  } catch (err) {
    console.error(err);
    throw err;
  }
};

export const deleteDBSendQueueItem = async (
  position: number,
  label: string,
  toPeerId: string,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());
    await db.delete("sendQueue", [position, label, toPeerId]);

    if (shouldClose) db.close();
  } catch (err) {
    console.error(err);
    throw err;
  }
};

// Create a WritableStream to write data to IndexedDB in chunks
export const createIDBWritableStream = async (
  merkleRoot: string,
  // totalSize: number,
  mimeType: string,
  db?: IDBPDatabase<RepoSchema>,
): Promise<WritableStream<Blob>> => {
  let chunkIndex = 0;
  const shouldClose = db == undefined;
  db = db ?? (await getDB());

  return new WritableStream<Blob>({
    async write(chunk) {
      const chunkData: Chunk = {
        merkleRoot,
        chunkIndex,
        // totalSize,
        data: chunk,
        mimeType,
      };
      await setDBChunk(chunkData, db);
      chunkIndex += 1;
    },
    close() {
      if (shouldClose) db?.close();
    },
    abort(reason) {
      console.error("WritableStream aborted:", reason);
      if (shouldClose) db?.close();
    },
  });
};

// Create a ReadableStream to read data from IndexedDB in chunks
export const createIDBReadableStream = async (
  merkleRootHex: string,
  db?: IDBPDatabase<RepoSchema>,
): Promise<ReadableStream<Chunk>> => {
  const shouldClose = db == undefined;
  db = db ?? (await getDB());

  return new ReadableStream<Chunk>(
    {
      async pull(controller) {
        const tx = db.transaction("chunks", "readonly");
        const store = tx.objectStore("chunks");
        // const index = store.index("merkleRoot");
        const keyRange = IDBKeyRange.only(merkleRootHex);
        let cursor = await store.openCursor(keyRange);
        // const chunksUnsorted = await index.getAll(keyRange);
        // const chunks = chunksUnsorted.sort((a, b) => a.chunkIndex - b.chunkIndex);

        while (cursor) {
          controller.enqueue(cursor.value);
          if (controller.desiredSize ?? 0 > 0) {
            cursor = await cursor.continue();
          } else {
            break;
          }
        }

        if (!cursor) {
          // Actually done with this store, not just paused
          console.log("Completely done");
          controller.close();
        }

        if (shouldClose) db.close();
      },

      cancel(reason) {
        console.error("ReadableStream cancelled:", reason);
        if (shouldClose) db.close();
      },
    },
    {
      highWaterMark: 100,
    },
  );
};

// export const readDataFromIndexedDB = async (
//   merkleRoot: string,
// ): Promise<Blob> => {
//   const readableStream = await createIDBReadableStream(merkleRoot);
//   const reader = readableStream.getReader();
//   const chunks: Blob[] = [];

//   while (true) {
//     const { value, done } = await reader.read();
//     if (done) break;
//     chunks.push(value);
//   }

//   const combinedBlob = new Blob(chunks);
//   return combinedBlob;
// };
