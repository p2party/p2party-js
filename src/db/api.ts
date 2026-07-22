import type {
  WorkerMessages,
  Chunk,
  ReceiveChunk,
  NewChunk,
  SendQueue,
  RatchetSession,
  IdentityX25519,
} from "./types";
// import type { MessageType } from "../utils/messageTypes";

const workerSrc = process.env.INDEXEDDB_WORKER_JS ?? "";
const workerBlob = new Blob([workerSrc], {
  type: "application/javascript",
});
const worker = new Worker(URL.createObjectURL(workerBlob), { type: "module" });

let msgId = 0;
const pending = new Map<
  number,
  { resolve: (value: unknown) => void; reject: (reason?: unknown) => void }
>();

worker.onmessage = (e: MessageEvent) => {
  const { id, result, error } = e.data as {
    id: number;
    result: unknown;
    error: unknown;
  };
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  if (error) p.reject(error);
  else p.resolve(result);
};

function callWorker<M extends WorkerMessages["method"]>(
  method: M,
  ...args: Extract<WorkerMessages, { method: M }>["args"]
): Promise<import("./types").WorkerMethodReturnTypes[M]> {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, {
      resolve: resolve as (value: unknown) => void,
      reject,
    });
    worker.postMessage({ id, method, args });
  });
}

export const getDBAddressBookEntry = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("getDBAddressBookEntry", peerId, peerPublicKey);

export const getAllDBAddressBookEntries = () =>
  callWorker("getAllDBAddressBookEntries");

export const setDBAddressBookEntry = (
  username: string,
  peerId: string,
  peerPublicKey: string,
) => callWorker("setDBAddressBookEntry", username, peerId, peerPublicKey);

export const deleteDBAddressBookEntry = (
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("deleteDBAddressBookEntry", username, peerId, peerPublicKey);

export const getDBPeerIsBlacklisted = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("getDBPeerIsBlacklisted", peerId, peerPublicKey);

export const getAllDBBlacklisted = () => callWorker("getAllDBBlacklisted");

export const setDBPeerInBlacklist = (peerId: string, peerPublicKey: string) =>
  callWorker("setDBPeerInBlacklist", peerId, peerPublicKey);

export const deleteDBPeerFromBlacklist = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("deleteDBPeerFromBlacklist", peerId, peerPublicKey);

export const getAllDBUniqueRooms = () => callWorker("getAllDBUniqueRooms");

export const setDBUniqueRoom = (roomUrl: string, roomId: string) =>
  callWorker("setDBUniqueRoom", roomUrl, roomId);

export const getDBMessageData = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBMessageData", merkleRootHex, hashHex);

export const getDBRoomMessageData = (roomId: string) =>
  callWorker("getDBRoomMessageData", roomId);

export const setDBRoomMessageData = (
  roomId: string,
  merkleRootHex: string,
  sha512Hex: string,
  fromPeerId: string,
  chunkSize: number,
  totalSize: number,
  messageType: number, // MessageType,
  filename: string,
  channelLabel: string,
  timestamp: number,
) =>
  callWorker(
    "setDBRoomMessageData",
    roomId,
    merkleRootHex,
    sha512Hex,
    fromPeerId,
    chunkSize,
    totalSize,
    messageType,
    filename,
    channelLabel,
    timestamp,
  );

export const getDBChunk = (hashHex: string, chunkIndex: number) =>
  callWorker("getDBChunk", hashHex, chunkIndex);

export const existsDBChunk = (hashHex: string, chunkIndex: number) =>
  callWorker("existsDBChunk", hashHex, chunkIndex);

export const getDBNewChunk = (hashHex: string, chunkIndex?: number) =>
  callWorker("getDBNewChunk", hashHex, chunkIndex);

export const existsDBNewChunk = (hashHex: string, chunkIndex: number) =>
  callWorker("existsDBNewChunk", hashHex, chunkIndex);

export const getDBSendQueue = (label: string, toPeerId: string) =>
  callWorker("getDBSendQueue", label, toPeerId);

export const getDBAllChunks = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBAllChunks", merkleRootHex, hashHex);

export const getDBAllChunkLeafHashes = (merkleRootHex: string) =>
  callWorker("getDBAllChunkLeafHashes", merkleRootHex);

export const assembleToOPFS = (
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
) => callWorker("assembleToOPFS", merkleRootHex, totalSize, filename, mimeType);

export const getDBAllChunksCount = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBAllChunksCount", merkleRootHex, hashHex);

export const setDBChunk = (chunk: Chunk) => callWorker("setDBChunk", chunk);

// Receive-time OPFS write: hand the worker a real chunk's bytes; it writes them
// straight into the message's pre-sized OPFS file at chunkIndex*uniformSize (or
// keeps them in IndexedDB if it can't place them yet / OPFS is unavailable) and
// records the bytesless have-set entry. Resolves true if newly stored.
export const storeReceiveChunk = (chunk: ReceiveChunk) =>
  callWorker("storeReceiveChunk", chunk);

// Open the finished (all offsets filled) OPFS file for a fully-received message
// and hand it back as a disk-backed File — no reassembly. Returns null if OPFS
// is unavailable, so the caller can fall back to the in-memory Blob path.
export const getReceiveFile = (
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
) => callWorker("getReceiveFile", merkleRootHex, totalSize, filename, mimeType);

// Flush + close the open write handle for a transfer (called on completion) so
// the finished file can be opened for reading without hitting the exclusive lock.
export const closeReceiveFile = (merkleRootHex: string) =>
  callWorker("closeReceiveFile", merkleRootHex);

export const getDBAllNewChunks = (hashHex?: string, merkleRootHex?: string) =>
  callWorker("getDBAllNewChunks", hashHex, merkleRootHex);

export const getDBAllNewChunksCount = (hashHex: string) =>
  callWorker("getDBAllNewChunksCount", hashHex);

export const setDBNewChunk = (chunk: NewChunk) =>
  callWorker("setDBNewChunk", chunk);

export const setDBSendQueue = (item: SendQueue) =>
  callWorker("setDBSendQueue", item);

export const countDBSendQueue = (label: string, toPeerId: string) =>
  callWorker("countDBSendQueue", label, toPeerId);

export const deleteDBChunk = (hashHex: string, chunkIndex?: number) =>
  callWorker("deleteDBChunk", hashHex, chunkIndex);

export const deleteDBNewChunk = (
  merkleRootHex?: string,
  realChunkHashHex?: string,
  hashHex?: string,
  chunkIndex?: number,
) =>
  callWorker(
    "deleteDBNewChunk",
    merkleRootHex,
    realChunkHashHex,
    hashHex,
    chunkIndex,
  );

export const deleteDBMessageData = (merkleRootHex: string) =>
  callWorker("deleteDBMessageData", merkleRootHex);

export const deleteDBUniqueRoom = (roomId: string) =>
  callWorker("deleteDBUniqueRoom", roomId);

export const deleteDB = () => callWorker("deleteDB");

export const deleteDBSendQueue = (
  label: string,
  toPeerId: string,
  position?: number,
) => callWorker("deleteDBSendQueue", label, toPeerId, position);

export const getRatchetSession = (roomId: string, peerPublicKey: string) =>
  callWorker("getRatchetSession", roomId, peerPublicKey);

export const setRatchetSession = (session: RatchetSession) =>
  callWorker("setRatchetSession", session);

export const deleteRatchetSession = (roomId: string, peerPublicKey: string) =>
  callWorker("deleteRatchetSession", roomId, peerPublicKey);

// D2=B: the dedicated X25519 identity, WebCrypto-wrapped at rest (worker-side).
export const getIdentityX25519 = () => callWorker("getIdentityX25519");

export const setIdentityX25519 = (identity: IdentityX25519) =>
  callWorker("setIdentityX25519", identity);

export const deleteIdentityX25519 = () => callWorker("deleteIdentityX25519");
