import { openDB } from "idb";

import { hexToUint8Array } from "./uint8array";

import type { DBSchema, IDBPDatabase } from "idb";

export const dbName = "p2party";
export const dbVersion = 1;

export interface Chunk {
  merkleRoot: string;
  chunkIndex: number;
  totalSize: number;
  data: string;
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

    if (chunk) return hexToUint8Array(chunk.data);

    return;
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

export const setDBChunk = async (
  chunk: Chunk,
  db?: IDBPDatabase<RepoSchema>,
) => {
  try {
    const shouldClose = db == undefined;

    db = db ?? (await getDB());

    const tx = db.transaction("chunks", "readwrite");
    const store = tx.objectStore("chunks");

    await store.put(chunk);
    await tx.done;

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
    const tx = db.transaction("chunks", "readwrite");
    const store = tx.objectStore("chunks");

    if (chunkIndex) {
      const chunk = await getDBChunk(merkleRootHex, chunkIndex, db);
      if (chunk) await store.delete([merkleRootHex, chunkIndex]);
    } else {
      const chunks = await getDBAllChunks(merkleRootHex, db);
      const chunksLen = chunks.length;
      for (let i = 0; i < chunksLen; i++) {
        await store.delete([merkleRootHex, chunks[i].chunkIndex]);
      }
    }

    await tx.done;

    if (shouldClose) db.close();
  } catch (err) {
    console.error(err);
    throw err;
  }
};
