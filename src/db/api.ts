// import workerUrl from "./db.worker.js";

const workerUrl = new URL("./db.worker.js", import.meta.url);
const worker = new Worker(workerUrl, {
  type: "module",
});
let msgId = 0;
const pending = new Map<
  number,
  { resolve: (value: any) => void; reject: (reason?: any) => void }
>();

worker.onmessage = (e: MessageEvent) => {
  const { id, result, error } = e.data;
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  if (error) p.reject(error);
  else p.resolve(result);
};

const callWorker = (method: string, ...args: any[]) => {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, method, args });
  });
};

export const getDBChunk = (merkleRootHex: string, chunkIndex: number) => {
  return callWorker("getDBChunk", merkleRootHex, chunkIndex);
};

export const existsDBChunk = (merkleRootHex: string, chunkIndex: number) => {
  return callWorker("existsDBChunk", merkleRootHex, chunkIndex);
};

export const getDBSendQueue = (label: string, toPeerId: string) => {
  return callWorker("getDBSendQueue", label, toPeerId);
};

export const getDBAllChunks = (merkleRootHex: string) => {
  return callWorker("getDBAllChunks", merkleRootHex);
};

export const getDBAllChunksCount = (merkleRootHex: string) => {
  return callWorker("getDBAllChunksCount", merkleRootHex);
};

export const setDBChunk = (chunk: {
  merkleRoot: string;
  chunkIndex: number;
  totalSize: number;
  data: Blob;
  mimeType: string;
}) => {
  return callWorker("setDBChunk", chunk);
};

export const setDBSendQueue = (item: {
  position: number;
  label: string;
  toPeerId: string;
  encryptedData: Blob;
}) => {
  return callWorker("setDBSendQueue", item);
};

export const deleteDBChunk = (merkleRootHex: string, chunkIndex?: number) => {
  return callWorker("deleteDBChunk", merkleRootHex, chunkIndex);
};

export const deleteDBSendQueueItem = (
  position: number,
  label: string,
  toPeerId: string,
) => {
  return callWorker("deleteDBSendQueueItem", position, label, toPeerId);
};
