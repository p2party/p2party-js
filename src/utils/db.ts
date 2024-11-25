import { openDB } from "idb";

// import { hexToUint8Array } from "./uint8array";

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

    return chunk?.data;

    // if (chunk) return hexToUint8Array(chunk.data);

    // return;
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

    await db.put("chunks", chunk);

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

// Create a WritableStream to write data to IndexedDB in chunks
export const createIDBWritableStream = async (
  merkleRoot: string,
  totalSize: number,
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
        totalSize,
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
  merkleRoot: string,
  db?: IDBPDatabase<RepoSchema>,
): Promise<ReadableStream<Blob>> => {
  const shouldClose = db == undefined;
  db = db ?? (await getDB());

  const chunks = await getDBAllChunks(merkleRoot, db);
  chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);

  let chunkIndex = 0;

  return new ReadableStream<Blob>({
    pull(controller) {
      if (chunkIndex < chunks.length) {
        const chunk = chunks[chunkIndex];
        controller.enqueue(chunk.data);
        chunkIndex += 1;
      } else {
        controller.close();
        if (shouldClose) db?.close();
      }
    },
    cancel(reason) {
      console.error("ReadableStream cancelled:", reason);
      if (shouldClose) db?.close();
    },
  });
};

export const readDataFromIndexedDB = async (
  merkleRoot: string,
): Promise<Blob> => {
  const readableStream = await createIDBReadableStream(merkleRoot);
  const reader = readableStream.getReader();
  const chunks: Blob[] = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const combinedBlob = new Blob(chunks);
  return combinedBlob;
};
