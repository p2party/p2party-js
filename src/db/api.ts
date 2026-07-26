import type {
  WorkerMessages,
  Chunk,
  ReceiveChunk,
  NewChunk,
  NewChunkSelector,
  SendQueue,
  RatchetSession,
  IdentityEd25519,
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

/**
 * A pending entry is only ever drained by a reply carrying its id, so anything
 * that kills the worker — a module-load failure, a structured-clone failure
 * posting a large chunk, an OOM — would otherwise leave every in-flight call
 * unsettled forever. Callers await these, so the transfer or handshake waiting
 * on one would hang silently rather than fail.
 */
const rejectAllPending = (reason: Error): void => {
  const inFlight = [...pending.values()];
  pending.clear();
  for (const p of inFlight) p.reject(reason);
};

worker.onerror = (event) => {
  rejectAllPending(
    new Error(
      `p2party: the database worker failed: ${
        (event as ErrorEvent).message || "unknown error"
      }`,
    ),
  );
};

worker.onmessageerror = () => {
  rejectAllPending(
    new Error("p2party: a database worker message could not be deserialized"),
  );
};

function callWorker<M extends WorkerMessages["method"]>(
  method: M,
  ...args: Extract<WorkerMessages, { method: M }>["args"]
): Promise<import("./types").WorkerMethodReturnTypes[M]> {
  return new Promise((resolve, reject) => {
    // An empty bundle builds a worker that never replies, so the call would
    // hang rather than fail. Say why instead of stalling the caller.
    if (workerSrc.length === 0) {
      reject(
        new Error(
          `p2party: cannot run "${method}" — the database worker bundle is ` +
            "missing (INDEXEDDB_WORKER_JS was not inlined at build time).",
        ),
      );
      return;
    }
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

/**
 * Fails CLOSED. This is the sole admission gate on every connection path, and
 * an indeterminate answer must never be reported as "not blacklisted" — that
 * would let a storage fault silently readmit every blocked peer. The denial is
 * scoped to the one peer being checked, so a transient fault cannot lock the
 * whole room out.
 */
export const getDBPeerIsBlacklisted = async (
  peerId?: string,
  peerPublicKey?: string,
): Promise<boolean> => {
  try {
    return await callWorker("getDBPeerIsBlacklisted", peerId, peerPublicKey);
  } catch (error) {
    console.error(
      "p2party: blacklist lookup failed; treating this peer as blocked",
      error,
    );
    return true;
  }
};

export const getAllDBBlacklisted = () => callWorker("getAllDBBlacklisted");

export const setDBPeerInBlacklist = (peerId: string, peerPublicKey: string) =>
  callWorker("setDBPeerInBlacklist", peerId, peerPublicKey);

export const deleteDBPeerFromBlacklist = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("deleteDBPeerFromBlacklist", peerId, peerPublicKey);

export const getAllDBUniqueRooms = () => callWorker("getAllDBUniqueRooms");

export const setDBUniqueRoom = (
  roomUrl: string,
  roomId: string,
  roomPolicy: ArrayBuffer,
) => callWorker("setDBUniqueRoom", roomUrl, roomId, roomPolicy);

export const getDBMessageData = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBMessageData", merkleRootHex, hashHex);

export const getDBRoomMessageData = (roomId: string) =>
  callWorker("getDBRoomMessageData", roomId);

export const getDBRoomStats = (roomId: string) =>
  callWorker("getDBRoomStats", roomId);

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
  transferId?: string,
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
    transferId,
  );

export const getDBChunk = (merkleRootHex: string, chunkIndex: number) =>
  callWorker("getDBChunk", merkleRootHex, chunkIndex);

export const existsDBChunk = (merkleRootHex: string, chunkIndex: number) =>
  callWorker("existsDBChunk", merkleRootHex, chunkIndex);

export const getDBNewChunk = (transferId: string, chunkIndex: number) =>
  callWorker("getDBNewChunk", transferId, chunkIndex);

export const getDBNewChunkByReceipt = (
  merkleRootHex: string,
  receiptTokenHex: string,
) => callWorker("getDBNewChunkByReceipt", merkleRootHex, receiptTokenHex);

export const existsDBNewChunk = (transferId: string, chunkIndex: number) =>
  callWorker("existsDBNewChunk", transferId, chunkIndex);

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

// Atomic receive-time insert + progress: text stays in IndexedDB; file bytes go
// to OPFS at chunkIndex*uniformSize when possible. The worker returns whether
// this distinct index was inserted and the authoritative committed byte count,
// so a duplicate can never be mistaken for the completing chunk.
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

/**
 * Atomically retires one inbound transfer behind the same per-Merkle worker
 * lock used by storeReceiveChunk. This is the cancellation primitive: a chunk
 * write that was already in flight completes first and is then removed, while
 * later writes are stopped by the channel's AbortSignal.
 */
export const deleteReceiveTransfer = (merkleRootHex: string) =>
  callWorker("deleteReceiveTransfer", merkleRootHex);

export const getDBAllNewChunks = (selector: NewChunkSelector) =>
  callWorker("getDBAllNewChunks", selector);

export const getDBAllNewChunksCount = (transferId: string) =>
  callWorker("getDBAllNewChunksCount", transferId);

export const setDBNewChunk = (chunk: NewChunk) =>
  callWorker("setDBNewChunk", chunk);

export const setDBSendQueue = (item: SendQueue) =>
  callWorker("setDBSendQueue", item);

export const countDBSendQueue = (label: string, toPeerId: string) =>
  callWorker("countDBSendQueue", label, toPeerId);

export const deleteDBChunk = (hashHex: string, chunkIndex?: number) =>
  callWorker("deleteDBChunk", hashHex, chunkIndex);

export const deleteDBNewChunk = (selector: NewChunkSelector) =>
  callWorker("deleteDBNewChunk", selector);

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

export const getPinAttemptState = (
  roomId: string,
  peerIdentityEd25519: string,
) => callWorker("getPinAttemptState", roomId, peerIdentityEd25519);

export const incrementPinAttemptState = (
  roomId: string,
  peerIdentityEd25519: string,
  now: number,
  maxImmediateAttempts: number,
  baseMs: number,
  maxMs: number,
) =>
  callWorker(
    "incrementPinAttemptState",
    roomId,
    peerIdentityEd25519,
    now,
    maxImmediateAttempts,
    baseMs,
    maxMs,
  );

export const deletePinAttemptState = (
  roomId: string,
  peerIdentityEd25519?: string,
) => callWorker("deletePinAttemptState", roomId, peerIdentityEd25519);

// D2=B: the dedicated X25519 identity, WebCrypto-wrapped at rest (worker-side).
export const getIdentityX25519 = () => callWorker("getIdentityX25519");

export const setIdentityX25519 = (identity: IdentityX25519) =>
  callWorker("setIdentityX25519", identity);

export const deleteIdentityX25519 = () => callWorker("deleteIdentityX25519");

// Ed25519 account identity, also WebCrypto-wrapped at rest (worker-side).
export const getIdentityEd25519 = () => callWorker("getIdentityEd25519");

export const setIdentityEd25519 = (identity: IdentityEd25519) =>
  callWorker("setIdentityEd25519", identity);

export const deleteIdentityEd25519 = () => callWorker("deleteIdentityEd25519");
