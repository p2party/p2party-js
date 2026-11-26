import { executeOutbox, storeOutboxChunk } from "./outboxStore";
import type { OutboxLease, ReceiveActivity } from "./outboxTypes";
import { deleteDB } from "idb";
import type { IDBPObjectStore, StoreNames } from "idb";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import {
  CHUNK_LEN,
  MAX_MESSAGE_SIZE,
  OPFS_REASSEMBLE_DIR,
  RECEIVE_VERIFY_BATCH_CHUNKS,
  RECEIVE_VERIFY_LEASE_RENEW_MS,
  RECEIVE_VERIFY_PROGRESS_BYTES,
  RECEIVE_VERIFY_RECEIPT_INTERVAL_MS,
  RECEIVE_VERIFY_SETTLED_MEMORY,
  RECEIVE_VERIFY_START_RETRY_WINDOW_MS,
} from "../utils/constants";

import { getDB, dbName } from "./src/getDB";
import { DatabaseUpgradeBlockedError, StorageFailedError } from "./dbErrors";
import type { RepoSchema } from "./src/getDB";
import { Sha512Stream } from "./sha512Stream";
import { uint8ArrayToHex } from "../utils/uint8array";
import {
  advanceReceiveManifest,
  buildReceiveManifest,
  EMPTY_RECEIVE_MANIFEST,
  isCurrentReceiveManifest,
  ReceiveChunkRejectedError,
  receiveProgress,
  type ReceiveManifest,
} from "./receiveManifest";
import {
  getWrapKey,
  wrapSecret,
  unwrapSecret,
  wrapRatchetSession,
  unwrapRatchetSession,
  RatchetRollbackGuard,
} from "./ratchetWrap";

import type {
  MessageData,
  Chunk,
  ChunkLeafHash,
  ReceiveChunk,
  ReceiveChunkStored,
  ReceiveChunkStoreFailure,
  ReceiveChunkStoreResult,
  HeldFileProgressNotice,
  HeldFileSettledNotice,
  ReceiveVerificationMarker,
  ReceiveVerificationOutcome,
  ReceiveVerificationVerdict,
  ReceiveDeleteGuard,
  RoomMessageLoadOptions,
  ExpiredReceiveTransfer,
  SendQueue,
  WorkerMessages,
  WorkerMethodReturnTypes,
  BlacklistedPeer,
  UsernamedPeer,
  UniqueRoom,
  RoomStats,
  NewChunk,
  NewChunkSelector,
  RatchetSession,
  IdentityEd25519,
  IdentityEd25519KeyMaterial,
  IdentityX25519,
  StoredIdentityEd25519,
  StoredIdentityEd25519Revision,
  StoredIdentityX25519,
  IdentityDerivation,
  StoredIdentityDerivation,
  PinAttemptState,
} from "./types";
// import type { MessageType } from "../utils/messageTypes";

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
      : await index.get(peerPublicKey ?? "");
    await tx.done;
    db.close();
    return peer
      ? {
          username: peer.username,
          peerId: peer.peerId,
          peerPublicKey: peer.peerPublicKey,
        }
      : undefined;
  } catch {
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
  } catch {
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
  const noPeerPublicKey = peerPublicKey?.length !== 64;

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
      const item = await index.getKey(username ?? "");

      if (item) {
        const entry = await index.get(username ?? "");
        pId = entry?.peerId ?? "";

        await store.delete(item);
      }
    }

    await tx.done;
    db.close();
  } catch {
    /* empty */
  }

  return pId;
}

async function fnGetDBPeerIsBlackisted(
  peerId?: string,
  peerPublicKey?: string,
): Promise<boolean> {
  if (!peerId && !peerPublicKey) return false;
  if (peerId && peerId.length < 10 && !peerPublicKey) return false;
  if (peerPublicKey && peerPublicKey.length !== 64 && !peerId) return false;

  // Deliberately unguarded: `false` is also the legitimate "not blacklisted"
  // answer, so swallowing a storage fault here would be indistinguishable from
  // a clean miss and would silently admit a blocked peer. Let the rejection
  // reach db/api.ts, which turns it into a fail-closed answer for this peer.
  const db = await getDB();
  try {
    const tx = db.transaction("blacklist", "readonly");
    const index = peerId
      ? tx.objectStore("blacklist").index("peerId")
      : tx.objectStore("blacklist").index("peerPublicKey");
    const peer = peerId
      ? await index.get(peerId)
      : await index.get(peerPublicKey ?? "");
    await tx.done;

    return peer ? true : false;
  } finally {
    db.close();
  }
}

async function fnGetAllDBBlacklisted(): Promise<BlacklistedPeer[]> {
  const db = await getDB();

  try {
    const peers = await db.getAll("blacklist");
    db.close();

    return peers;
  } catch {
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
    // Reject rather than resolve: a caller that blacklists a peer and is told
    // it succeeded will disconnect them and show them as blocked, while the
    // block survives only until reload.
    console.error(error);
    throw error;
  }
}

async function fnDeleteDBPeerFromBlacklist(
  // username: string,
  peerId?: string,
  peerPublicKey?: string,
): Promise<void> {
  const noPeerId = !peerId || peerId.length < 10;
  const noPeerPublicKey = peerPublicKey?.length !== 64;

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
      const item = await index.getKey(peerPublicKey ?? "");

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
  } catch {
    db.close();

    return [];
  }
}

async function fnSetDBUniqueRoom(
  roomUrl: string,
  roomId: string,
  roomPolicy: ArrayBuffer,
): Promise<void> {
  if (roomPolicy.byteLength !== 32)
    throw new Error("Room policy must be the canonical 32-byte descriptor");
  const db = await getDB();
  try {
    const tx = db.transaction(["uniqueRoom"], "readwrite");
    const store = tx.objectStore("uniqueRoom");
    const index1 = store.index("roomUrl");
    const index2 = store.index("roomId");

    const item1 = await index1.get(roomUrl);
    const item2 = await index2.get(roomId);

    const existing = item1 ?? item2;
    if (!existing) {
      const d = Date.now();
      await store.put({
        // username,
        roomId,
        roomUrl,
        roomPolicy,
        messageCount: 0,
        lastMessageMerkleRoot: "",
        createdAt: d,
        updatedAt: d,
      });
    } else {
      await store.put({
        ...existing,
        roomId,
        roomUrl,
        roomPolicy,
        updatedAt: Date.now(),
      });
    }

    await tx.done;
  } finally {
    db.close();
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

    if (merkleRootHex?.length === 2 * crypto_hash_sha512_BYTES) {
      const messageData = await index1.get(merkleRootHex);

      if (!messageData) {
        if (hashHex?.length === 2 * crypto_hash_sha512_BYTES) {
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
    } else if (hashHex?.length === 2 * crypto_hash_sha512_BYTES) {
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

/**
 * Aggregate one room's transfer history without shipping it anywhere.
 *
 * The alternative is handing every MessageData row to the main thread so the
 * UI can sum a few numbers, which for a room with thousands of messages means
 * serialising thousands of objects across the worker boundary on every render
 * of a list. The index is here; the arithmetic belongs here too.
 *
 * `transferId` is written only on rows this device sent, so it is also the
 * sent/received discriminator -- there is no need to know our own peer id.
 */
async function fnGetDBRoomStats(roomId: string): Promise<RoomStats> {
  const db = await getDB();
  const messages = await db.getAllFromIndex("messageData", "roomId", roomId);
  db.close();

  const peerIds = new Set<string>();
  let bytesSent = 0;
  let bytesReceived = 0;
  let messagesSent = 0;
  let messagesReceived = 0;

  for (const message of messages) {
    // totalSize is the logical message size; savedSize is how much of it has
    // landed. A cancelled or in-flight receive must not inflate the total.
    const sent = message.transferId !== undefined;
    const bytes = sent ? message.totalSize : message.savedSize;

    if (sent) {
      bytesSent += bytes;
      messagesSent += 1;
    } else {
      bytesReceived += bytes;
      messagesReceived += 1;
      if (message.fromPeerId.length > 0) peerIds.add(message.fromPeerId);
    }
  }

  return {
    messageCount: messages.length,
    messagesSent,
    messagesReceived,
    bytesSent,
    bytesReceived,
    bytesTotal: bytesSent + bytesReceived,
    peerIds: [...peerIds],
  };
}

async function fnGetDBRoomMessageData(
  roomId: string,
  options: RoomMessageLoadOptions = {},
): Promise<MessageData[]> {
  const db = await getDB();
  const messages = await db.getAllFromIndex("messageData", "roomId", roomId);
  db.close();

  // A room load (not a delete) queues this room's files left held by an
  // interrupted verification; they are verified after this reply, so the
  // room's list never waits for a hash.
  if (options.verifyHeld === true)
    for (const message of messages)
      if (message.receiveVerification && message.transferId === undefined)
        queueHeldFileAtStart(message.merkleRoot);

  const messagesLen = messages.length;

  const messageData: MessageData[] = [];
  for (let i = 0; i < messagesLen; i++) {
    messageData.push({
      transferId: messages[i].transferId,
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
  messageType: number, // MessageType,
  filename: string,
  channelLabel: string,
  timestamp: number,
  transferId?: string,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction(["messageData", "uniqueRoom"], "readwrite");
    const messageStore = tx.objectStore("messageData");
    const msg = await messageStore.index("merkleRoot").get(merkleRootHex);

    const savedSize = msg?.savedSize ?? 0;

    // console.log(
    //   "Received " +
    //     (savedSize + chunkSize) +
    //     " with chunk size " +
    //     chunkSize +
    //     " of total " +
    //     totalSize,
    // );

    try {
      await messageStore.put({
        transferId,
        roomId,
        timestamp,
        merkleRoot: merkleRootHex,
        hash: sha512Hex,
        fromPeerId,
        filename,
        messageType,
        savedSize:
          savedSize + chunkSize <= totalSize
            ? savedSize + chunkSize
            : totalSize,
        totalSize,
        channelLabel,
      });
    } catch (error) {
      await tx.done;
      db.close();
      throw error;
    }

    const roomStore = tx.objectStore("uniqueRoom");
    const room = await roomStore.index("roomId").get(roomId);
    if (room && room.lastMessageMerkleRoot !== merkleRootHex) {
      try {
        await roomStore.put({
          ...room,
          lastMessageMerkleRoot: merkleRootHex,
          messageCount: room.messageCount + 1,
          updatedAt: timestamp, // Date.now(),
        });
      } catch (error) {
        await tx.done;
        db.close();
        throw error;
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
  transferId: string,
  chunkIndex: number,
): Promise<NewChunk | undefined> {
  const db = await getDB();
  try {
    return await db.get("newChunks", [transferId, chunkIndex]);
  } finally {
    db.close();
  }
}

async function fnGetDBNewChunkByReceipt(
  merkleRootHex: string,
  receiptTokenHex: string,
): Promise<NewChunk | undefined> {
  if (
    merkleRootHex.length !== crypto_hash_sha512_BYTES * 2 ||
    receiptTokenHex.length !== crypto_hash_sha512_BYTES * 2
  )
    return undefined;
  const db = await getDB();
  try {
    return await db.getFromIndex("newChunks", "receiptScope", [
      merkleRootHex,
      receiptTokenHex,
    ]);
  } finally {
    db.close();
  }
}

async function fnExistsDBNewChunk(
  transferId: string,
  chunkIndex: number,
): Promise<boolean> {
  const db = await getDB();
  const count = await db.count("newChunks", [transferId, chunkIndex]);
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

    if (merkleRootHex?.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index2.getAll(merkleRootHex);

      if (chunks.length === 0) {
        await tx.done;
        db.close();

        return [];
      } else {
        await tx.done;
        db.close();

        return chunks;
      }
    } else if (hashHex?.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index1.getAll(hashHex);

      await tx.done;
      db.close();

      if (chunks.length > 0)
        return chunks.filter((c) => c.merkleRoot === chunks[0].merkleRoot);

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
}

// Project (chunkIndex, leafHash) for every stored chunk of a message. Used by
// the reconnect re-emit: the leaf hashes ARE the receiver's have-set, replayed
// as receipts so the sender reconciles. NOTE: a value cursor deserializes each
// full Chunk record (incl. its ~62KB `data`) one at a time, so peak *resident*
// memory is one record but total I/O is O(held message bytes). Fine at today's
// sizes; the GB-file streaming workstream should move leaf hashes into a
// key-only index / dedicated store so this becomes O(#chunks) — see
// [[p2party-arbitrary-big-files]].
async function fnGetDBAllChunkLeafHashes(
  merkleRootHex: string,
): Promise<ChunkLeafHash[]> {
  if (merkleRootHex.length !== 2 * crypto_hash_sha512_BYTES) return [];

  try {
    const db = await getDB();
    const tx = db.transaction("chunks", "readonly");
    const index = tx.objectStore("chunks").index("merkleRoot");
    const result: ChunkLeafHash[] = [];

    let cursor = await index.openCursor(merkleRootHex);
    while (cursor) {
      result.push({
        chunkIndex: cursor.value.chunkIndex,
        leafHash: cursor.value.leafHash,
      });
      cursor = await cursor.continue();
    }

    await tx.done;
    db.close();

    return result;
  } catch (error) {
    console.error(error);

    return [];
  }
}

// The OPFS StorageManager (worker context). getDirectory + the file handle's
// createSyncAccessHandle are the two capabilities we feature-detect.
const opfsStorage = ():
  { getDirectory?: () => Promise<FileSystemDirectoryHandle> } | undefined =>
  (
    globalThis as unknown as {
      navigator?: {
        storage?: { getDirectory?: () => Promise<FileSystemDirectoryHandle> };
      };
    }
  ).navigator?.storage;

// Coalesce concurrent assembles for the SAME message: readMessage is a poll-style
// API, so overlapping polls for one merkleRoot would each open a sync access
// handle. createSyncAccessHandle takes an EXCLUSIVE lock and rejects immediately
// if one is already open, so without this the losers would fall back to the
// in-memory Blob — reintroducing the whole-file-in-RAM OOM this feature removes.
// At most one assemble per merkleRoot is ever in flight; the rest share it.
const opfsAssembling = new Map<string, Promise<File | null>>();

// Wait for an assembly of this file (or of every file) to finish: it holds a
// sync access handle the receive-handle cache does not know, and the browser
// refuses to remove a file, or a directory holding one, while that is open
// (NoModificationAllowedError, measured: docs/e2e/opfs-remove/).
const settleAssemblies = async (merkleRootHex?: string): Promise<void> => {
  const runs =
    merkleRootHex === undefined
      ? [...opfsAssembling.values()]
      : [opfsAssembling.get(merkleRootHex)];
  for (const run of runs) await run?.catch(() => null);
};

// The worker-only synchronous OPFS file access handle (Safari-safe). getSize is
// used by the receive path to detect whether the file is already pre-sized.
type OPFSSyncAccessHandle = {
  getSize: () => number;
  truncate: (size: number) => void;
  read: (buffer: ArrayBufferView, options: { at: number }) => number;
  write: (buffer: ArrayBufferView, options: { at: number }) => number;
  flush: () => void;
  close: () => void;
};

const getCreateSyncAccessHandle = (
  fileHandle: FileSystemFileHandle,
): (() => Promise<OPFSSyncAccessHandle>) | undefined =>
  (
    fileHandle as unknown as {
      createSyncAccessHandle?: () => Promise<OPFSSyncAccessHandle>;
    }
  ).createSyncAccessHandle;

const wrapOPFSFile = (
  file: File,
  filename: string,
  merkleRootHex: string,
  mimeType: string,
): File =>
  // The OPFS handle is named by merkleRoot; hand back a File carrying the real
  // filename + mimeType. Blob parts are by-reference, so it stays disk-backed
  // (the whole file is never read into RAM).
  new File([file], filename.length > 0 ? filename : merkleRootHex, {
    type: mimeType,
  });

// Reassemble a completed FILE message from its IndexedDB chunks into a single
// disk-backed OPFS file WITHOUT ever holding the whole file in RAM: stream the
// chunks in ascending chunkIndex order (a cursor — one record resident at a
// time) and write each straight to the OPFS file via a sync access handle
// (worker-only / Safari-safe). Real chunks occupy contiguous indices 0..R-1 and
// their real slices are stored in order, so a sequential append reconstructs the
// file (no stored offset needed). Idempotent: the OPFS file is content-addressed
// by merkleRoot, so a correctly-sized existing file is returned as-is — never
// re-truncated (which would invalidate a File handed out earlier) or re-streamed.
// Returns null (OPFS unavailable / error) so the caller falls back to an
// in-memory Blob — that fallback DOES hold the file in RAM, so the never-in-RAM
// guarantee holds only where worker OPFS exists (Chrome/Edge, Firefox 111+,
// Safari 16.4+).
async function fnAssembleToOPFS(
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
): Promise<File | null> {
  if (merkleRootHex.length !== 2 * crypto_hash_sha512_BYTES) return null;

  const inFlight = opfsAssembling.get(merkleRootHex);
  if (inFlight) return inFlight;

  const run = assembleToOPFSImpl(merkleRootHex, totalSize, filename, mimeType);
  opfsAssembling.set(merkleRootHex, run);
  try {
    return await run;
  } finally {
    opfsAssembling.delete(merkleRootHex);
  }
}

async function assembleToOPFSImpl(
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
): Promise<File | null> {
  try {
    const storage = opfsStorage();
    if (!storage || typeof storage.getDirectory !== "function") {
      console.warn("OPFS unavailable — reassembling file in memory");
      return null;
    }

    const root = await storage.getDirectory();
    const dir = await root.getDirectoryHandle(OPFS_REASSEMBLE_DIR, {
      create: true,
    });
    const fileHandle = await dir.getFileHandle(merkleRootHex, { create: true });

    // Idempotency: a correctly-sized content-addressed file is already complete
    // and immutable — return it directly (O(1), no lock, no rewrite).
    const existing = await fileHandle.getFile();
    if (totalSize > 0 && existing.size === totalSize)
      return wrapOPFSFile(existing, filename, merkleRootHex, mimeType);

    const createSyncAccessHandle = (
      fileHandle as unknown as {
        createSyncAccessHandle?: () => Promise<{
          truncate: (size: number) => void;
          write: (buffer: ArrayBufferView, options: { at: number }) => number;
          flush: () => void;
          close: () => void;
        }>;
      }
    ).createSyncAccessHandle;
    if (typeof createSyncAccessHandle !== "function") {
      console.warn(
        "OPFS sync access handle unavailable — reassembling in memory",
      );
      return null;
    }

    const access = await createSyncAccessHandle.call(fileHandle);
    let db: Awaited<ReturnType<typeof getDB>> | undefined;
    try {
      db = await getDB();
      access.truncate(0);
      let offset = 0;

      const tx = db.transaction("chunks", "readonly");
      const index = tx.objectStore("chunks").index("merkleRoot");
      let cursor = await index.openCursor(merkleRootHex);
      while (cursor) {
        // This path streams a SENT copy, whose chunks always carry `data`; a
        // bytesless record (receiver have-set) contributes 0 bytes.
        const view = new Uint8Array(cursor.value.data ?? new ArrayBuffer(0));
        // write() may write fewer bytes than requested (storage pressure); loop
        // until the whole chunk lands so the file isn't silently truncated.
        let written = 0;
        while (written < view.length) {
          const n = access.write(view.subarray(written), {
            at: offset + written,
          });
          if (n <= 0) throw new Error("OPFS short write");
          written += n;
        }
        offset += view.length;
        cursor = await cursor.continue();
      }
      await tx.done;
      access.flush();
    } catch (streamError) {
      // Close, then drop the partial file so it can't linger and consume quota.
      try {
        access.close();
      } catch {
        /* ignore */
      }
      if (db)
        try {
          db.close();
        } catch {
          /* ignore */
        }
      await dir.removeEntry(merkleRootHex).catch(() => {
        /* ignore */
      });
      throw streamError;
    }
    access.close();
    db.close();

    return wrapOPFSFile(
      await fileHandle.getFile(),
      filename,
      merkleRootHex,
      mimeType,
    );
  } catch (error) {
    console.error(error);

    return null;
  }
}

// Remove a message's reassembled OPFS file (best-effort). Wired into the message
// deletion path so assembled files don't accumulate as orphaned full-size copies.
// Remove a received file. A file that is not there is fine; any other failure
// is retried once after its handle is closed, and then reported as a
// StorageFailedError: a delete must never leave the file behind silently.
async function fnDeleteOPFSFile(merkleRootHex: string): Promise<void> {
  const storage = opfsStorage();
  if (!storage || typeof storage.getDirectory !== "function") return;
  const remove = async (): Promise<void> => {
    const root = await storage.getDirectory!();
    let dir: FileSystemDirectoryHandle;
    try {
      dir = await root.getDirectoryHandle(OPFS_REASSEMBLE_DIR);
    } catch (error) {
      if ((error as { name?: string } | null)?.name === "NotFoundError") return;
      throw error;
    }
    try {
      await dir.removeEntry(merkleRootHex);
    } catch (error) {
      if ((error as { name?: string } | null)?.name === "NotFoundError") return;
      throw error;
    }
  };
  try {
    await remove();
  } catch {
    try {
      await fnCloseReceiveFile(merkleRootHex);
      await remove();
    } catch (error) {
      throw new StorageFailedError(
        `p2party: could not remove the received file ${merkleRootHex}: ${String(error)}`,
        { cause: error },
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Receive-time OPFS write path
//
// Instead of storing every received real chunk's bytes in IndexedDB and
// reassembling the whole file at read time (double storage — fatal for GB
// files), each received real chunk is written straight into a per-message OPFS
// file at its byte offset (chunkIndex * uniformSize) as it arrives, out of
// order. IndexedDB keeps only the leaf-hash have-set (bytesless records). The
// file is pre-sized to totalSize (truncate zero-fills), so not-yet-received
// chunks read as zeros and resume just overwrites the gaps.
//
// uniformSize (real bytes per full chunk) is NOT in the wire metadata and is a
// per-send tunable, so it is learned from the transfer's own chunks and kept
// in its running manifest (receiveManifest.ts): chunk 0's length, or the larger
// of the first two chunks held (only the last chunk is short). The one chunk
// that can arrive before it is known (a non-zero index as the transfer's first
// chunk) can't be offset-placed yet, so it is kept in IndexedDB WITH its bytes
// (durable, acked normally) and migrated into OPFS later by getReceiveFile.
//
// Invariant: a bytesless have-set record means the chunk's bytes are durably in
// OPFS, so the have-set is always a subset of the bytes on disk — this is what
// makes crash/reload resume safe (a resumed sender never skips a chunk whose
// bytes are missing).
// ---------------------------------------------------------------------------

interface ReceiveFileEntry {
  access: OPFSSyncAccessHandle;
  /** Readers that need the handle to stay open; never evicted while > 0. */
  pins: number;
}

// One open sync-access-handle per active transfer, held across all its writes.
const opfsReceiving = new Map<string, ReceiveFileEntry>();
// In-flight opens: createSyncAccessHandle takes an EXCLUSIVE lock and throws if
// one is already open, so concurrent openers (e.g. the same file broadcast from
// two peers) share a single open instead of each racing to lock.
const opfsReceivingOpening = new Map<
  string,
  Promise<ReceiveFileEntry | null>
>();
// Coalesce concurrent finalize/read opens for one merkleRoot (readMessage polls).
const opfsFinalizing = new Map<string, Promise<File | null>>();

// Serialize ALL receive-file operations (write / finalize / close / delete) for a
// given merkleRoot. The worker's onmessage is async and interleaves at awaits, so
// without this the same file arriving concurrently from two peers would race the
// shared ReceiveFileEntry (double-counting a chunk and locking uniformSize to the
// short final chunk) and the dedup count()->add() would be a TOCTOU. A single
// per-merkleRoot queue makes the whole receive path for one file strictly ordered.
const receiveLocks = new Map<string, Promise<void>>();
async function withReceiveLock<T>(
  key: string,
  fn: () => Promise<T>,
): Promise<T> {
  const prev = receiveLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const mine = prev.then(() => gate);
  receiveLocks.set(key, mine);
  await prev;
  try {
    const locks = globalThis.navigator?.locks;
    return locks
      ? await locks.request(`p2party:receive:${key}`, fn)
      : await fn();
  } finally {
    release();
    if (receiveLocks.get(key) === mine) receiveLocks.delete(key);
  }
}

// Bound the number of simultaneously-open receive handles. A transfer that stalls
// and is never completed/read/deleted would otherwise keep its exclusive handle
// open for the worker's lifetime; evicting the oldest (closing its handle) caps
// that — an evicted transfer's next chunk simply reopens the file (truncate is a
// no-op on the already-sized file), so eviction is safe.
const MAX_OPEN_RECEIVE_HANDLES = 8;

// `create: false` opens an existing file only, and never resizes it: a reader
// (verification) must not bring back a file a delete has just removed.
async function openReceiveHandleImpl(
  merkleRootHex: string,
  totalSize: number,
  create: boolean,
): Promise<ReceiveFileEntry | null> {
  const storage = opfsStorage();
  if (!storage || typeof storage.getDirectory !== "function") return null;
  const root = await storage.getDirectory();
  const dir = await root.getDirectoryHandle(OPFS_REASSEMBLE_DIR, { create });
  const fileHandle = await dir.getFileHandle(merkleRootHex, { create });
  const createSyncAccessHandle = getCreateSyncAccessHandle(fileHandle);
  if (typeof createSyncAccessHandle !== "function") return null;
  const access = await createSyncAccessHandle.call(fileHandle);
  try {
    // Pre-size to totalSize; truncate to a larger size zero-fills, so gaps are
    // zeros until their chunks land. On resume the file is already totalSize
    // (OPFS persists across reloads) so this is a no-op that preserves the data.
    if (create && totalSize > 0 && access.getSize() !== totalSize)
      access.truncate(totalSize);
    return {
      access,
      pins: 0,
    };
  } catch (error) {
    // createSyncAccessHandle is exclusive. Never strand that lock when setup or
    // pre-sizing fails (quota exhaustion, invalid state, storage fault).
    try {
      access.close();
    } catch {
      /* ignore close failure; preserve the setup error */
    }
    throw error;
  }
}

async function ensureReceiveHandle(
  merkleRootHex: string,
  totalSize: number,
  { create = true }: { create?: boolean } = {},
): Promise<ReceiveFileEntry | null> {
  const open = opfsReceiving.get(merkleRootHex);
  if (open) return open;
  const inflight = opfsReceivingOpening.get(merkleRootHex);
  if (inflight) return inflight;
  // Cap open handles: evict the oldest (never the one we're opening) so a set of
  // stalled, never-completed transfers can't pin exclusive handles forever.
  if (opfsReceiving.size >= MAX_OPEN_RECEIVE_HANDLES) {
    for (const [k, open] of opfsReceiving) {
      if (k !== merkleRootHex && open.pins === 0) {
        await fnCloseReceiveFile(k);
        break;
      }
    }
  }
  const p = openReceiveHandleImpl(merkleRootHex, totalSize, create).catch(
    (error) => {
      console.error(error);
      return null;
    },
  );
  opfsReceivingOpening.set(merkleRootHex, p);
  try {
    const entry = await p;
    if (entry) opfsReceiving.set(merkleRootHex, entry);
    return entry;
  } finally {
    opfsReceivingOpening.delete(merkleRootHex);
  }
}

// write() may write fewer bytes than requested (storage pressure) — loop until
// the whole chunk lands so the file is not silently truncated.
function writeReceiveAt(
  access: OPFSSyncAccessHandle,
  offset: number,
  data: ArrayBuffer,
): void {
  const view = new Uint8Array(data);
  let written = 0;
  while (written < view.length) {
    const n = access.write(view.subarray(written), { at: offset + written });
    if (n <= 0) throw new Error("OPFS short write");
    written += n;
  }
}

// Place a real chunk's bytes into the OPFS file at chunkIndex × uniformSize,
// the uniform size of the transfer's manifest with this chunk added. Return
// false when that size is not known yet (a lone out-of-order chunk) or OPFS is
// unavailable; the caller then keeps the bytes in IndexedDB. The offset never
// comes from what one handle happened to see: after a reload or an eviction a
// fresh handle may first see only the short last chunk.
async function placeReceiveChunk(
  merkleRootHex: string,
  chunkIndex: number,
  uniformSize: number,
  totalSize: number,
  data: ArrayBuffer,
): Promise<boolean> {
  if (uniformSize <= 0) return false;
  const entry = await ensureReceiveHandle(merkleRootHex, totalSize);
  if (!entry) return false; // OPFS unavailable

  writeReceiveAt(entry.access, chunkIndex * uniformSize, data);
  // Flush so the bytes are durable BEFORE fnStoreReceiveChunk commits the
  // (bytesless) have-set record. Without this a bytesless record could reach
  // disk while its OPFS write is still buffered (independent storage backends,
  // no cross-store ordering), and after a crash a resumed sender would skip a
  // chunk whose bytes were lost — a silent zero-gap. This is what makes the
  // "bytesless record ⇒ bytes durably in OPFS" invariant actually hold.
  entry.access.flush();
  return true;
}

// read() may return fewer bytes than requested — loop until `into` is full.
function readReceiveAt(
  access: OPFSSyncAccessHandle,
  offset: number,
  into: Uint8Array,
): void {
  let done = 0;
  while (done < into.length) {
    const n = access.read(into.subarray(done), { at: offset + done });
    if (n <= 0) throw new Error("OPFS short read");
    done += n;
  }
}

// ---------------------------------------------------------------------------
// Whole-file verification of a received file.
//
// The chunk that would complete a file is not recorded by storeReceiveChunk:
// it is held on the row (receiveVerification marker) with its bytes in OPFS,
// and each caller holding that attempt's token then
//   1. verifyReceivedFile: hashes the stored file once, in chunk order,
//      outside the per-file lock, on one database connection, reading in
//      short batches and yielding between them, so neither the file's other
//      requests nor the worker as a whole wait for it;
//   2. settleReceivedFileVerification: under the per-file lock, commits the
//      verdict (complete, or drop the file as failed) or, when told not to
//      commit and no other caller still holds the attempt, leaves the marker
//      for the next copy of that chunk, or the next start, to verify again.
// Several callers can hold one attempt: a copy of the held chunk that arrives
// on a new connection while the file is verified joins it, so that
// connection commits it. No failure in a run leaves the attempt live: the
// verdict always settles, and the attempt is retired once nothing can commit
// it any more.
// ---------------------------------------------------------------------------

interface LiveVerification {
  readonly token: string;
  aborted: boolean;
  /** Callers that hold this attempt: asked to verify it, not yet settled or detached. */
  holders: Set<string>;
  /** Callers that detached (abort) and have not settled yet. */
  detached: Set<string>;
  /** Always resolves; a failure is a verdict, never a rejection. */
  verdict: Promise<ReceiveVerificationVerdict>;
  /** While the file is being read: resolves once its handle is released. */
  hashing?: Promise<void>;
}
const liveVerifications = new Map<string, LiveVerification>();

// What recently committed attempts settled to, so a caller that settles after
// another caller committed the same attempt gets the same answer.
const settledVerifications = new Map<
  string,
  { verdict: ReceiveVerificationVerdict; outcome: ReceiveVerificationOutcome }
>();
const rememberSettled = (
  token: string,
  verdict: ReceiveVerificationVerdict,
  outcome: ReceiveVerificationOutcome,
): void => {
  settledVerifications.set(token, { verdict, outcome });
  while (settledVerifications.size > RECEIVE_VERIFY_SETTLED_MEMORY)
    settledVerifications.delete(settledVerifications.keys().next().value!);
};

class VerificationAborted extends Error {}

const releaseVerificationLease = async (
  merkleRoot: string,
  token: string,
): Promise<void> => {
  const db = await getDB();
  try {
    const tx = db.transaction("receiveActivity", "readwrite");
    const activity = await tx.store.get(merkleRoot);
    if (activity?.writeToken === token)
      await tx.store.put({
        ...activity,
        writeToken: undefined,
        leaseUntil: 0,
        lastActivityAt: Date.now(),
      });
    await tx.done;
  } finally {
    db.close();
  }
};

type RepoConnection = Awaited<ReturnType<typeof getDB>>;

// Stop a running verification of this file and wait until it no longer holds
// the file's handle, so the file can be removed. Used by every delete.
const stopVerification = async (merkleRoot: string): Promise<void> => {
  const live = liveVerifications.get(merkleRoot);
  if (!live) return;
  live.aborted = true;
  await live.hashing;
};

interface VerificationStart {
  row: MessageData;
  marker: ReceiveVerificationMarker;
  /** The manifest with the held chunk added: the whole file. */
  manifest: ReceiveManifest;
}

// Under the per-file lock: confirm the marker and take the receive lease, so a
// sweep or another tab leaves the transfer alone while it is hashed.
async function startVerification(
  db: RepoConnection,
  merkleRoot: string,
  token: string,
  live: LiveVerification,
): Promise<VerificationStart | undefined> {
  if (live.aborted) return undefined;
  const tx = db.transaction(
    ["chunks", "messageData", "receiveActivity"],
    "readwrite",
  );
  try {
    const row = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(merkleRoot);
    const marker = row?.receiveVerification;
    const activity = await tx.objectStore("receiveActivity").get(merkleRoot);
    if (
      !row ||
      !marker ||
      marker.token !== token ||
      activity?.deletedAt !== undefined ||
      (activity?.writeToken !== undefined &&
        (activity.leaseUntil ?? 0) > Date.now())
    ) {
      await tx.done;
      return undefined;
    }
    const manifest = await loadReceiveManifest(
      tx.objectStore("chunks"),
      merkleRoot,
      row,
      row.totalSize,
    );
    await tx.objectStore("receiveActivity").put({
      merkleRoot,
      roomId: row.roomId,
      fromPeerId: row.fromPeerId,
      lastActivityAt: Date.now(),
      writeToken: token,
      leaseUntil: Date.now() + RECEIVE_WRITE_LEASE_MS,
    });
    await tx.done;
    return {
      row,
      marker,
      manifest: advanceReceiveManifest(
        manifest,
        row.totalSize,
        marker.chunkIndex,
        marker.realLen,
      ),
    };
  } catch (error) {
    await abortQuietly(tx);
    throw error;
  }
}

// Hash the stored file once, in chunk order: from OPFS for chunks placed
// there, from a record or the marker for bytes kept in IndexedDB. Yields after
// every batch so the worker answers other requests in between. Never creates
// or resizes the file: a file that is gone ends the run.
async function hashHeldFile(
  db: RepoConnection,
  merkleRoot: string,
  token: string,
  { row, marker, manifest }: VerificationStart,
  live: LiveVerification,
): Promise<string> {
  const hasher = new Sha512Stream();
  const scratch = new Uint8Array(manifest.uniformSize);
  let handle: ReceiveFileEntry | undefined;
  const fromOpfs = async (index: number, length: number) => {
    if (!handle) {
      const opened = await ensureReceiveHandle(merkleRoot, row.totalSize, {
        create: false,
      });
      if (!opened)
        throw new Error("received file bytes are in unavailable OPFS");
      if (live.aborted) throw new VerificationAborted();
      handle = opened;
      handle.pins += 1;
    }
    const bytes = scratch.subarray(0, length);
    readReceiveAt(handle.access, index * manifest.uniformSize, bytes);
    return bytes;
  };
  let renewedAt = Date.now();
  // Progress reports, driven by work done: a stalled run reports nothing.
  let hashedBytes = 0;
  let reportedBytes = 0;
  let reportedAt = Date.now();
  try {
    for (
      let first = 0;
      first < manifest.count;
      first += RECEIVE_VERIFY_BATCH_CHUNKS
    ) {
      if (live.aborted) throw new VerificationAborted();
      const last =
        Math.min(manifest.count, first + RECEIVE_VERIFY_BATCH_CHUNKS) - 1;
      const records = await db.getAll(
        "chunks",
        IDBKeyRange.bound([merkleRoot, first], [merkleRoot, last]),
      );
      let next = 0;
      for (let index = first; index <= last; index++) {
        if (live.aborted) throw new VerificationAborted();
        if (index === marker.chunkIndex) {
          hasher.update(
            marker.data
              ? new Uint8Array(marker.data)
              : await fromOpfs(index, marker.realLen),
          );
          continue;
        }
        const record = records[next++] as Chunk | undefined;
        const length = record?.realLen ?? -1;
        if (
          record?.chunkIndex !== index ||
          length <= 0 ||
          length > scratch.length
        )
          throw new Error("received file layout does not match its manifest");
        if (record.data) {
          if (record.data.byteLength !== length)
            throw new Error("received chunk length does not match its record");
          hasher.update(new Uint8Array(record.data));
        } else hasher.update(await fromOpfs(index, length));
      }
      if (next !== records.length)
        throw new Error("received file layout does not match its manifest");
      for (let index = first; index <= last; index++)
        hashedBytes +=
          index === manifest.count - 1
            ? row.totalSize - manifest.uniformSize * (manifest.count - 1)
            : manifest.uniformSize;
      if (
        hashedBytes - reportedBytes >= RECEIVE_VERIFY_PROGRESS_BYTES ||
        Date.now() - reportedAt >= RECEIVE_VERIFY_RECEIPT_INTERVAL_MS
      ) {
        const progress: HeldFileProgressNotice = {
          merkleRoot,
          token,
          hashedBytes,
        };
        postMessage({ progress });
        reportedBytes = hashedBytes;
        reportedAt = Date.now();
      }
      if (Date.now() - renewedAt >= RECEIVE_VERIFY_LEASE_RENEW_MS) {
        const tx = db.transaction("receiveActivity", "readwrite");
        const activity = await tx.store.get(merkleRoot);
        if (activity?.writeToken !== token) {
          await tx.done;
          throw new VerificationAborted();
        }
        await tx.store.put({
          ...activity,
          leaseUntil: Date.now() + RECEIVE_WRITE_LEASE_MS,
          lastActivityAt: Date.now(),
        });
        await tx.done;
        renewedAt = Date.now();
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  } finally {
    if (handle) handle.pins -= 1;
  }
  if (live.aborted) throw new VerificationAborted();
  return uint8ArrayToHex(hasher.digest());
}

// One run: one database connection for the start, every batch and the lease,
// closed at the end. Never rejects: a failure anywhere is the verdict
// "storage-failed" (or "aborted" when the run was stopped).
async function runVerification(
  merkleRoot: string,
  token: string,
  live: LiveVerification,
): Promise<ReceiveVerificationVerdict> {
  let db: RepoConnection | undefined;
  try {
    db = await getDB();
    const connection = db;
    const start = await withReceiveLock(merkleRoot, () =>
      startVerification(connection, merkleRoot, token, live),
    );
    if (!start) return "aborted";
    let released!: () => void;
    live.hashing = new Promise<void>((resolve) => {
      released = resolve;
    });
    try {
      const digest = await hashHeldFile(
        connection,
        merkleRoot,
        token,
        start,
        live,
      );
      return digest === start.row.hash ? "match" : "mismatch";
    } finally {
      released();
    }
  } catch (error) {
    if (live.aborted || error instanceof VerificationAborted) return "aborted";
    console.error("p2party: could not verify a received file", error);
    return "storage-failed";
  } finally {
    db?.close();
  }
}

async function fnVerifyReceivedFile(
  merkleRoot: string,
  token: string,
  holder: string,
): Promise<ReceiveVerificationVerdict> {
  const settled = settledVerifications.get(token);
  if (settled) return settled.verdict;
  const running = liveVerifications.get(merkleRoot);
  if (running) {
    if (running.token !== token) return "aborted";
    // Another caller holds the same attempt: it joins, it never hashes twice.
    running.holders.add(holder);
    return running.verdict;
  }
  const live = {
    token,
    aborted: false,
    holders: new Set([holder]),
    detached: new Set<string>(),
  } as LiveVerification;
  liveVerifications.set(merkleRoot, live);
  live.verdict = runVerification(merkleRoot, token, live);
  return live.verdict;
}

// One holder leaves (its edge went away). The others keep the attempt; the
// run stops only when no holder is left to commit it. The detached holder
// still settles, with commit false.
function fnAbortReceivedFileVerification(
  merkleRoot: string,
  token: string,
  holder: string,
): void {
  const live = liveVerifications.get(merkleRoot);
  if (live?.token !== token || !live.holders.delete(holder)) return;
  live.detached.add(holder);
  if (live.holders.size === 0) live.aborted = true;
}

async function fnSettleReceivedFileVerification(
  merkleRoot: string,
  token: string,
  commit: boolean,
  holder: string,
): Promise<ReceiveVerificationOutcome> {
  const recorded = settledVerifications.get(token);
  if (recorded) return commit ? recorded.outcome : "aborted";
  const live = liveVerifications.get(merkleRoot);
  if (live?.token !== token) return "aborted";
  const verdict = await live.verdict;
  let retire = false;
  try {
    return await withReceiveLock(merkleRoot, async () => {
      // Another holder may have committed this attempt while we waited.
      const already = settledVerifications.get(token);
      const held = live.holders.delete(holder);
      live.detached.delete(holder);
      if (already) return commit ? already.outcome : "aborted";
      // A detached holder no longer commits anything.
      const decided =
        held && commit && (verdict === "match" || verdict === "mismatch")
          ? verdict
          : undefined;
      // Someone else may still commit it: leave the attempt to them.
      if (!decided && live.holders.size > 0) return "aborted";
      retire = true;
      let outcome: ReceiveVerificationOutcome = "aborted";
      const db = await getDB();
      const tx = db.transaction(
        ["chunks", "messageData", "receiveActivity"],
        "readwrite",
      );
      try {
        const chunks = tx.objectStore("chunks");
        const messages = tx.objectStore("messageData");
        const activityStore = tx.objectStore("receiveActivity");
        const row = await messages.index("merkleRoot").get(merkleRoot);
        const activity = await activityStore.get(merkleRoot);
        const leased =
          activity?.writeToken === token && activity.deletedAt === undefined;
        const marker = row?.receiveVerification;
        if (row && marker?.token === token && leased && decided) {
          const manifest = await loadReceiveManifest(
            chunks,
            merkleRoot,
            row,
            row.totalSize,
          );
          const {
            receiveVerification: _held,
            integrityFailed: _failed,
            ...rest
          } = row;
          void _held;
          void _failed;
          if (decided === "match") {
            const completed = advanceReceiveManifest(
              manifest,
              row.totalSize,
              marker.chunkIndex,
              marker.realLen,
            );
            const progress = receiveProgress(completed, row.totalSize);
            await chunks.add({
              merkleRoot,
              hash: row.hash,
              chunkIndex: marker.chunkIndex,
              mimeType: marker.mimeType,
              realLen: marker.realLen,
              leafHash: marker.leafHash,
              ...(marker.data ? { data: marker.data } : {}),
            });
            await messages.put({
              ...rest,
              savedSize: progress.savedSize,
              receiveManifest: completed,
            });
            await activityStore.delete(merkleRoot);
            outcome = "complete";
          } else {
            // The sender's resume replays only what this device still holds,
            // so a dropped have-set lets the next connection fetch it again.
            const keys = await chunks
              .index("merkleRoot")
              .getAllKeys(merkleRoot);
            for (const key of keys) await chunks.delete(key);
            await messages.put({
              ...rest,
              savedSize: 0,
              receiveManifest: { ...EMPTY_RECEIVE_MANIFEST },
              integrityFailed: true,
            });
            await activityStore.put({
              ...activity,
              writeToken: undefined,
              leaseUntil: 0,
              lastActivityAt: Date.now(),
            });
            outcome = "integrity";
          }
        } else if (leased)
          // Not committed: the marker stays, and the next copy of the held
          // chunk (or the next start) verifies the file again.
          await activityStore.put({
            ...activity,
            writeToken: undefined,
            leaseUntil: 0,
            lastActivityAt: Date.now(),
          });
        await tx.done;
      } catch (error) {
        // Nothing commits; the marker stays for the next copy of the chunk.
        await abortQuietly(tx);
        throw error;
      } finally {
        db.close();
      }
      if (outcome !== "aborted") rememberSettled(token, verdict, outcome);
      if (outcome === "integrity") {
        await fnCloseReceiveFile(merkleRoot);
        await fnDeleteOPFSFile(merkleRoot);
      }
      return outcome;
    });
  } catch (error) {
    retire = true;
    // Nothing was committed; give the lease back so the next copy of the held
    // chunk does not wait for it to expire.
    await releaseVerificationLease(merkleRoot, token).catch(() => undefined);
    throw error;
  } finally {
    // Retire the attempt once nothing can commit it any more, whatever
    // happened above; a later copy of the held chunk starts a fresh one.
    if (
      (retire || (live.holders.size === 0 && live.detached.size === 0)) &&
      liveVerifications.get(merkleRoot) === live
    )
      liveVerifications.delete(merkleRoot);
  }
}

// ---------------------------------------------------------------------------
// Verification at the next start.
//
// A file whose last chunk is held but whose verification no running worker
// owns (the page reloaded mid-verification, or its edge went away first) holds
// every byte it needs. It is verified without the sender when the SDK loads
// that file's room to show it (getDBRoomMessageData with `verifyHeld`; a room
// delete reads the same rows without it), through the same verification as a
// live one. Every such file goes through one queue for the whole worker, so
// these verifications run one at a time whatever rooms are loaded. The
// outcome is posted to the main thread as a HeldFileSettledNotice.
//
// A file whose receive lease another context holds (another tab verifying or
// writing it) is retried when that lease ends, by one timer per file. If the
// lease was renewed meanwhile the timer is re-armed to the new end; after
// RECEIVE_VERIFY_START_RETRY_WINDOW_MS from the first try the file is left
// for the next start. Nothing polls.
// ---------------------------------------------------------------------------

let startupQueue: Promise<void> = Promise.resolve();
const startupQueued = new Set<string>();
const startupRetries = new Map<
  string,
  { since: number; timer?: ReturnType<typeof setTimeout> }
>();

const queueHeldFileAtStart = (merkleRoot: string): void => {
  if (startupQueued.has(merkleRoot)) return;
  startupQueued.add(merkleRoot);
  startupQueue = startupQueue.then(async () => {
    try {
      await verifyHeldFileAtStart(merkleRoot);
    } catch (error) {
      console.error("p2party: could not verify a held file", error);
    } finally {
      startupQueued.delete(merkleRoot);
    }
  });
};

const forgetStartupRetries = (): void => {
  for (const retry of startupRetries.values()) clearTimeout(retry.timer);
  startupRetries.clear();
};

async function verifyHeldFileAtStart(merkleRoot: string): Promise<void> {
  if (liveVerifications.has(merkleRoot)) return;
  const db = await getDB();
  let row: MessageData | undefined;
  let activity: ReceiveActivity | undefined;
  try {
    const tx = db.transaction(["messageData", "receiveActivity"], "readonly");
    row = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(merkleRoot);
    activity = await tx.objectStore("receiveActivity").get(merkleRoot);
    await tx.done;
  } finally {
    db.close();
  }
  const marker = row?.receiveVerification;
  if (!row || !marker || activity?.deletedAt !== undefined) {
    startupRetries.delete(merkleRoot);
    return;
  }
  const leasedUntil =
    activity?.writeToken !== undefined ? (activity.leaseUntil ?? 0) : 0;
  if (leasedUntil > Date.now()) {
    // Another context holds the file: try again when its lease ends.
    const retry = startupRetries.get(merkleRoot);
    const since = retry?.since ?? Date.now();
    clearTimeout(retry?.timer);
    if (Date.now() - since >= RECEIVE_VERIFY_START_RETRY_WINDOW_MS) {
      startupRetries.delete(merkleRoot);
      return;
    }
    startupRetries.set(merkleRoot, {
      since,
      timer: setTimeout(
        () => queueHeldFileAtStart(merkleRoot),
        leasedUntil - Date.now() + 50,
      ),
    });
    return;
  }
  startupRetries.delete(merkleRoot);
  // No edge is involved: a device holding every byte commits the verdict.
  const holder = `start:${crypto.randomUUID()}`;
  const verdict = await fnVerifyReceivedFile(merkleRoot, marker.token, holder);
  let outcome: ReceiveVerificationOutcome;
  try {
    outcome = await fnSettleReceivedFileVerification(
      merkleRoot,
      marker.token,
      verdict === "match" || verdict === "mismatch",
      holder,
    );
  } catch (error) {
    console.error("p2party: could not settle a held file", error);
    outcome = "aborted";
  }
  const notice: HeldFileSettledNotice = {
    roomId: row.roomId,
    fromPeerId: row.fromPeerId,
    merkleRoot,
    hash: row.hash,
    filename: row.filename,
    messageType: row.messageType,
    channelLabel: row.channelLabel,
    timestamp: row.timestamp,
    totalSize: row.totalSize,
    chunkIndex: marker.chunkIndex,
    verdict:
      outcome === "aborted" && verdict !== "aborted"
        ? "storage-failed"
        : verdict,
    outcome,
  };
  postMessage({ notice });
}

// A store that arrives while this worker verifies the file: every chunk of it
// is already held (in the have-set, or as the marker), so nothing changes. A
// copy of the held chunk itself is handed the attempt's token: it arrived on
// a connection that may outlive the one the run started on, and that
// connection commits the attempt when it settles.
async function storeWhileVerifying(
  chunk: ReceiveChunk,
  live: LiveVerification,
): Promise<ReceiveChunkStored> {
  const db = await getDB();
  try {
    const tx = db.transaction(["chunks", "messageData"], "readonly");
    const row = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(chunk.merkleRoot);
    const isHeldChunk =
      row?.receiveVerification?.chunkIndex === chunk.chunkIndex;
    const recorded =
      (await tx
        .objectStore("chunks")
        .getKey([chunk.merkleRoot, chunk.chunkIndex])) !== undefined;
    await tx.done;
    if (
      !row ||
      row.receiveVerification?.token !== live.token ||
      row.roomId !== chunk.roomId ||
      row.fromPeerId !== chunk.fromPeerId ||
      row.hash !== chunk.hash ||
      !(recorded || isHeldChunk)
    )
      throw new ReceiveChunkRejectedError(
        "receive chunk conflicts with a file being verified",
      );
    return {
      stored: false,
      savedSize: row.savedSize,
      complete: false,
      ...(isHeldChunk ? { verification: live.token } : {}),
    };
  } finally {
    db.close();
  }
}

// Abort a transaction whose body threw, so none of its writes commit. An
// exception in our code does not abort an IndexedDB transaction by itself: the
// requests it already issued would commit when it goes idle.
const abortQuietly = async (tx: {
  abort(): void;
  done: Promise<void>;
}): Promise<void> => {
  try {
    tx.abort();
  } catch {
    /* already finished or aborted */
  }
  await tx.done.catch(() => undefined);
};

// The running manifest of a received transfer, read from its messageData row.
// A row without a current one (written by 0.14.10, or by a writer that does
// not maintain it) is summarized once from its chunk records instead.
async function loadReceiveManifest<
  Stores extends ArrayLike<StoreNames<RepoSchema>>,
  Mode extends IDBTransactionMode,
>(
  chunks: IDBPObjectStore<RepoSchema, Stores, "chunks", Mode>,
  merkleRoot: string,
  message: MessageData | undefined,
  totalSize: number,
): Promise<ReceiveManifest> {
  if (
    message &&
    isCurrentReceiveManifest(
      message.receiveManifest,
      message.savedSize,
      totalSize,
    )
  )
    return message.receiveManifest;
  const records: Array<{ chunkIndex: number; realLen?: number }> = [];
  let cursor = await chunks.index("merkleRoot").openCursor(merkleRoot);
  while (cursor) {
    records.push({
      chunkIndex: cursor.value.chunkIndex,
      realLen: cursor.value.realLen,
    });
    cursor = await cursor.continue();
  }
  return buildReceiveManifest(records, totalSize);
}

// Store one received real chunk and compute authoritative distinct-byte
// progress. File bytes go to OPFS first; text bytes stay in the record. The
// insert/dedup decision and the manifest update share one readwrite
// transaction, so a duplicate can never be mistaken for the chunk that
// completed a message. The work per chunk does not depend on how many chunks
// are already held: the manifest replaces a scan of every held record.
//
// A file is complete only once its stored bytes hash to the whole-file hash
// its message carries. The chunk that would complete a file is written but not
// recorded: it is held on the row and returned with a `verification` token
// (see "Whole-file verification" above).
async function storeReceiveChunkLocked(
  chunk: ReceiveChunk,
  writeToken: string,
): Promise<ReceiveChunkStored> {
  const {
    schemaVersion,
    roomId,
    fromPeerId,
    channelLabel,
    timestamp,
    merkleRoot,
    hash,
    filename,
    messageType,
    chunkIndex,
    mimeType,
    leafHash,
    realLen,
    totalSize,
    data,
    storage,
  } = chunk;

  if (
    schemaVersion !== 1 ||
    !Number.isSafeInteger(messageType) ||
    messageType < 1 ||
    messageType > 64 ||
    !Number.isSafeInteger(chunkIndex) ||
    chunkIndex < 0 ||
    !Number.isSafeInteger(realLen) ||
    realLen <= 0 ||
    realLen > CHUNK_LEN ||
    !Number.isSafeInteger(totalSize) ||
    totalSize <= 0 ||
    totalSize > MAX_MESSAGE_SIZE ||
    realLen > totalSize ||
    chunkIndex >= totalSize ||
    data.byteLength !== realLen ||
    !Number.isSafeInteger(timestamp)
  )
    throw new ReceiveChunkRejectedError("invalid receive chunk bounds");

  const assertManifest = (previous: MessageData | undefined): void => {
    if (
      previous &&
      (previous.roomId !== roomId ||
        previous.fromPeerId !== fromPeerId ||
        previous.hash !== hash ||
        previous.totalSize !== totalSize ||
        previous.messageType !== messageType ||
        previous.filename !== filename ||
        previous.channelLabel !== channelLabel ||
        previous.timestamp !== timestamp)
    )
      throw new ReceiveChunkRejectedError(
        "receive chunk metadata conflicts with message",
      );
  };

  // Dedup and validate the candidate against the manifest before touching
  // OPFS (a duplicate needs no write, an invalid chunk must not overwrite
  // bytes). The worker dispatcher holds the per-Merkle lock across this whole
  // function, so this view cannot change before the committing transaction
  // below, which nevertheless re-derives everything it decides on.
  let completed: ReceiveManifest;
  const readDb = await getDB();
  try {
    const tx = readDb.transaction(["chunks", "messageData"], "readonly");
    const chunks = tx.objectStore("chunks");
    const held = (await chunks.getKey([merkleRoot, chunkIndex])) !== undefined;
    const previous = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(merkleRoot);
    assertManifest(previous);
    const manifest = await loadReceiveManifest(
      chunks,
      merkleRoot,
      previous,
      totalSize,
    );
    await tx.done;
    if (held) return { stored: false, ...receiveProgress(manifest, totalSize) };
    // A held chunk no running verification owns arrives again: write it and
    // verify the file again below.
    completed = advanceReceiveManifest(
      manifest,
      totalSize,
      chunkIndex,
      realLen,
    );
  } finally {
    readDb.close();
  }
  const verifies =
    storage === "opfs" && receiveProgress(completed, totalSize).complete;

  // Write bytes to OPFS FIRST (durable), then record the have-set entry: if we
  // crash between the two we get bytes-without-record (resent + rewritten
  // idempotently) — never the corrupting record-without-bytes.
  let wroteToOPFS = false;
  if (storage === "opfs") {
    try {
      wroteToOPFS = await placeReceiveChunk(
        merkleRoot,
        chunkIndex,
        completed.uniformSize,
        totalSize,
        data,
      );
    } catch (error) {
      console.error(error);
      wroteToOPFS = false;
    }
  }

  const record: Chunk =
    storage === "opfs" && wroteToOPFS
      ? { merkleRoot, hash, chunkIndex, mimeType, realLen, leafHash }
      : { merkleRoot, hash, chunkIndex, mimeType, realLen, leafHash, data };

  const db = await getDB();
  const tx = db.transaction(
    ["chunks", "messageData", "uniqueRoom", "receiveActivity"],
    "readwrite",
  );
  try {
    const activity = await tx.objectStore("receiveActivity").get(merkleRoot);
    if (activity?.writeToken !== writeToken || activity.deletedAt !== undefined)
      throw new ReceiveChunkRejectedError(
        "Receive write was fenced by cancellation or expiry",
      );
    const store = tx.objectStore("chunks");
    const existing = await store.getKey([merkleRoot, chunkIndex]);
    const messageStore = tx.objectStore("messageData");
    const previous = await messageStore.index("merkleRoot").get(merkleRoot);
    assertManifest(previous);
    const manifest = await loadReceiveManifest(
      store,
      merkleRoot,
      previous,
      totalSize,
    );
    if (existing !== undefined) {
      await tx.done;
      return { stored: false, ...receiveProgress(manifest, totalSize) };
    }
    const next = advanceReceiveManifest(
      manifest,
      totalSize,
      chunkIndex,
      realLen,
    );
    if (
      (storage === "opfs" && receiveProgress(next, totalSize).complete) !==
      verifies
    )
      throw new Error("receive state changed while storing a chunk");

    let result: ReceiveChunkStored;
    let row: MessageData = {
      roomId,
      timestamp: previous?.timestamp ?? timestamp,
      merkleRoot,
      hash,
      fromPeerId,
      filename,
      messageType,
      savedSize: 0,
      totalSize,
      channelLabel,
      // Cleared only by a verified completion.
      ...(previous?.integrityFailed === true ? { integrityFailed: true } : {}),
    };
    if (verifies) {
      // Hold the completing chunk on the row, outside the have-set, until the
      // file verifies. The progress it reports does not include it yet.
      const verification = crypto.randomUUID();
      row = {
        ...row,
        savedSize: manifest.savedSize,
        receiveManifest: manifest,
        receiveVerification: {
          token: verification,
          chunkIndex,
          realLen,
          leafHash,
          mimeType,
          ...(wroteToOPFS ? {} : { data }),
        },
      };
      result = {
        stored: true,
        savedSize: manifest.savedSize,
        complete: false,
        verification,
      };
    } else {
      await store.add(record);
      const progress = receiveProgress(next, totalSize);
      const { integrityFailed: _cleared, ...unflagged } = row;
      void _cleared;
      row = {
        ...(progress.complete ? unflagged : row),
        savedSize: progress.savedSize,
        receiveManifest: next,
      };
      result = { stored: true, ...progress };
    }
    await messageStore.put(row);

    const roomStore = tx.objectStore("uniqueRoom");
    const room = await roomStore.index("roomId").get(roomId);
    if (room && room.lastMessageMerkleRoot !== merkleRoot) {
      await roomStore.put({
        ...room,
        lastMessageMerkleRoot: merkleRoot,
        messageCount: room.messageCount + 1,
        updatedAt: timestamp,
      });
    }

    await tx.done;
    return result;
  } catch (error) {
    await abortQuietly(tx);
    throw error;
  } finally {
    db.close();
  }
}

export const INCOMPLETE_RECEIVE_RETENTION_MS = 24 * 60 * 60 * 1000;
const RECEIVE_WRITE_LEASE_MS = 120_000;

type StorageEstimator = () => Promise<{ quota?: number; usage?: number }>;

const storageEstimator = (): StorageEstimator | undefined => {
  const storage = (
    globalThis as unknown as { navigator?: { storage?: StorageManager } }
  ).navigator?.storage;
  return typeof storage?.estimate === "function"
    ? () => storage.estimate()
    : undefined;
};

// Refuse a new transfer that cannot fit in the estimated free quota. An
// estimate that is unavailable or incomplete does not block the transfer; a
// write that then runs out of space is still reported as quota-exceeded.
async function refuseOverQuota(
  estimate: StorageEstimator,
  totalSize: number,
): Promise<ReceiveChunkStoreFailure | undefined> {
  let quota: number | undefined;
  let usage: number | undefined;
  try {
    ({ quota, usage } = await estimate());
  } catch (error) {
    console.error("p2party: storage estimate failed", error);
    return undefined;
  }
  if (!Number.isFinite(quota) || !Number.isFinite(usage)) return undefined;
  const availableBytes = Math.max(0, quota! - usage!);
  return totalSize > availableBytes
    ? {
        failure: "insufficient-quota",
        requiredBytes: totalSize,
        availableBytes,
      }
    : undefined;
}

const QUOTA_ERROR_NAMES = new Set([
  "QuotaExceededError",
  // Firefox before the DOMException name was standardized.
  "NS_ERROR_DOM_QUOTA_REACHED",
]);

// Anything thrown while storing that is not a refusal of the chunk itself.
const receiveStorageFailure = (error: unknown): ReceiveChunkStoreFailure => ({
  failure: QUOTA_ERROR_NAMES.has(
    (error as { name?: unknown } | null)?.name as string,
  )
    ? "quota-exceeded"
    : "storage-failed",
});

async function fnStoreReceiveChunk(
  chunk: ReceiveChunk,
  admittedAt: number,
): Promise<ReceiveChunkStoreResult> {
  if (
    !/^[0-9a-f]{128}$/.test(chunk.merkleRoot) ||
    !chunk.roomId ||
    !chunk.fromPeerId
  )
    throw new ReceiveChunkRejectedError("Invalid receive identity");
  // A copy that arrives while the file is verified joins that attempt. One
  // that arrives after the attempt was stopped takes the normal path: until
  // the stopped run gives its lease back it is refused, and the sender's next
  // retransmission starts a fresh attempt.
  const verifying = liveVerifications.get(chunk.merkleRoot);
  if (verifying && !verifying.aborted)
    return storeWhileVerifying(chunk, verifying);
  const token = crypto.randomUUID();
  const estimate = storageEstimator();
  let quotaChecked = estimate === undefined;
  for (;;) {
    const db = await getDB();
    try {
      const tx = db.transaction(
        ["receiveActivity", "messageData"],
        "readwrite",
      );
      const store = tx.objectStore("receiveActivity");
      const current = await store.get(chunk.merkleRoot);
      const prior = await tx
        .objectStore("messageData")
        .index("merkleRoot")
        .get(chunk.merkleRoot);
      if (
        (current &&
          (current.roomId !== chunk.roomId ||
            current.fromPeerId !== chunk.fromPeerId)) ||
        (prior &&
          (prior.roomId !== chunk.roomId ||
            prior.fromPeerId !== chunk.fromPeerId ||
            prior.transferId !== undefined)) ||
        (current?.deletedAt !== undefined && admittedAt <= current.deletedAt)
      ) {
        tx.abort();
        await tx.done.catch(() => undefined);
        throw new ReceiveChunkRejectedError(
          "Receive transfer ownership conflicts or was cancelled",
        );
      }
      if (current?.writeToken && (current.leaseUntil ?? 0) > Date.now()) {
        tx.abort();
        await tx.done.catch(() => undefined);
        throw new ReceiveChunkRejectedError(
          "Receive transfer is active in another worker",
        );
      }
      if (!prior && !quotaChecked) {
        // No byte of this transfer is held yet. Check it fits before the
        // first write (this lease row included); an IndexedDB transaction
        // cannot stay open across the estimate, so drop it and start over.
        tx.abort();
        await tx.done.catch(() => undefined);
        quotaChecked = true;
        const refusal = await refuseOverQuota(estimate!, chunk.totalSize);
        if (refusal) return refusal;
        continue;
      }
      await store.put({
        merkleRoot: chunk.merkleRoot,
        roomId: chunk.roomId,
        fromPeerId: chunk.fromPeerId,
        lastActivityAt: Date.now(),
        writeToken: token,
        leaseUntil: Date.now() + RECEIVE_WRITE_LEASE_MS,
      });
      await tx.done;
      break;
    } finally {
      db.close();
    }
  }
  try {
    return await storeReceiveChunkLocked(chunk, token);
  } finally {
    const db = await getDB();
    try {
      const tx = db.transaction(
        ["receiveActivity", "messageData"],
        "readwrite",
      );
      const row = await tx.objectStore("receiveActivity").get(chunk.merkleRoot);
      if (row?.writeToken === token) {
        const message = await tx
          .objectStore("messageData")
          .index("merkleRoot")
          .get(chunk.merkleRoot);
        if (message && message.savedSize >= message.totalSize)
          await tx.objectStore("receiveActivity").delete(chunk.merkleRoot);
        else
          await tx.objectStore("receiveActivity").put({
            ...row,
            writeToken: undefined,
            leaseUntil: 0,
            lastActivityAt: Date.now(),
          });
      }
      await tx.done;
    } finally {
      db.close();
    }
  }
}

async function fnSweepStaleReceives(): Promise<ExpiredReceiveTransfer[]> {
  const cutoff = Date.now() - INCOMPLETE_RECEIVE_RETENTION_MS;
  const db = await getDB();
  let candidates;
  try {
    candidates = await db.getAllFromIndex(
      "receiveActivity",
      "lastActivityAt",
      IDBKeyRange.upperBound(cutoff),
      64,
    );
  } finally {
    db.close();
  }
  const removed: ExpiredReceiveTransfer[] = [];
  for (const row of candidates) {
    if (row.deletedAt !== undefined) {
      // Tombstones carry no payload. Keep them through one receive retention window
      // so pre-cancel queued writes cannot recreate abandoned rows.
      const db = await getDB();
      try {
        const tx = db.transaction("receiveActivity", "readwrite");
        const latest = await tx.store.get(row.merkleRoot);
        if (latest?.deletedAt === row.deletedAt && latest.deletedAt! <= cutoff)
          await tx.store.delete(row.merkleRoot);
        await tx.done;
      } finally {
        db.close();
      }
      continue;
    }
    if ((row.leaseUntil ?? 0) > Date.now()) continue;
    let deletedScope: ExpiredReceiveTransfer | undefined;
    const deleted = await withReceiveLock(row.merkleRoot, () =>
      fnDeleteReceiveTransferLocked(
        row.merkleRoot,
        cutoff,
        undefined,
        (scope) => {
          deletedScope = scope;
        },
      ),
    );
    if (deleted && deletedScope) removed.push(deletedScope);
  }
  return removed;
}

// Flush + close the open write handle for a transfer so the finished file can be
// opened for reading without hitting the exclusive lock. Idempotent.
async function fnCloseReceiveFile(merkleRootHex: string): Promise<void> {
  const inflight = opfsReceivingOpening.get(merkleRootHex);
  if (inflight) {
    try {
      await inflight;
    } catch {
      /* ignore */
    }
  }
  const entry = opfsReceiving.get(merkleRootHex);
  if (entry) {
    opfsReceiving.delete(merkleRootHex);
    try {
      entry.access.flush();
      entry.access.close();
    } catch {
      /* ignore */
    }
  }
}

async function closeAllReceiveFiles(): Promise<void> {
  // Await in-flight opens too, so a handle that is opening concurrently with a
  // full wipe is captured and closed rather than leaked past removeEntry.
  const opening = [...opfsReceivingOpening.values()];
  for (let i = 0; i < opening.length; i++) {
    try {
      await opening[i];
    } catch {
      /* ignore */
    }
  }
  const keys = [...opfsReceiving.keys()];
  for (let i = 0; i < keys.length; i++) await fnCloseReceiveFile(keys[i]);
}

// Return a fully-received message's OPFS file as a disk-backed File (no
// reassembly). Migrates any straggler bytes still in IndexedDB into the file
// first. Returns null (→ caller falls back to an in-memory Blob) when OPFS is
// unavailable or the records are old-format (no realLen to derive offsets).
async function fnGetReceiveFile(
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
): Promise<File | null> {
  if (merkleRootHex.length !== 2 * crypto_hash_sha512_BYTES) return null;
  // Drop any open write handle so we can finalize/read under a fresh lock.
  await fnCloseReceiveFile(merkleRootHex);

  const inFlight = opfsFinalizing.get(merkleRootHex);
  if (inFlight) return inFlight;
  const run = getReceiveFileImpl(merkleRootHex, totalSize, filename, mimeType);
  opfsFinalizing.set(merkleRootHex, run);
  try {
    return await run;
  } finally {
    opfsFinalizing.delete(merkleRootHex);
  }
}

async function getReceiveFileImpl(
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
): Promise<File | null> {
  try {
    const storage = opfsStorage();
    if (!storage || typeof storage.getDirectory !== "function") return null;
    const root = await storage.getDirectory();
    const dir = await root.getDirectoryHandle(OPFS_REASSEMBLE_DIR, {
      create: true,
    });
    const fileHandle = await dir.getFileHandle(merkleRootHex, { create: true });

    const db = await getDB();

    // Scan the have-set with a cursor (one record resident) to find any chunks
    // still carrying bytes (the <=1 straggler received before uniformSize was
    // known, or everything if OPFS was unavailable during receive) and to derive
    // uniformSize = max(realLen). Bytesless records deserialize to a few hundred
    // bytes each, so this never loads the file into RAM.
    const dataBearing: Chunk[] = [];
    let uniformSize = 0;
    try {
      const tx = db.transaction("chunks", "readonly");
      const index = tx.objectStore("chunks").index("merkleRoot");
      let cursor = await index.openCursor(merkleRootHex);
      while (cursor) {
        const v = cursor.value;
        if (v.realLen && v.realLen > uniformSize) uniformSize = v.realLen;
        if (v.data && v.data.byteLength > 0) dataBearing.push(v);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch (error) {
      console.error(error);
      db.close();
      return null;
    }

    // Fast path: file is the right size and there is nothing left to migrate.
    const existing = await fileHandle.getFile();
    if (
      totalSize > 0 &&
      existing.size === totalSize &&
      dataBearing.length === 0
    ) {
      db.close();
      return wrapOPFSFile(existing, filename, merkleRootHex, mimeType);
    }

    // Old-format straggler (bytes but no realLen) → can't compute its offset;
    // bail to the in-memory Blob fallback (its bytes are still in IndexedDB).
    if (
      dataBearing.length > 0 &&
      (uniformSize === 0 || dataBearing.some((r) => r.realLen == null))
    ) {
      db.close();
      return null;
    }

    const createSyncAccessHandle = getCreateSyncAccessHandle(fileHandle);
    if (typeof createSyncAccessHandle !== "function") {
      db.close();
      return null;
    }
    const access = await createSyncAccessHandle.call(fileHandle);
    try {
      if (totalSize > 0 && access.getSize() !== totalSize)
        access.truncate(totalSize);
      for (let i = 0; i < dataBearing.length; i++) {
        const r = dataBearing[i];
        const offset = r.chunkIndex === 0 ? 0 : r.chunkIndex * uniformSize;
        writeReceiveAt(access, offset, r.data as ArrayBuffer);
      }
      access.flush();
    } finally {
      access.close();
    }

    // Strip the now-redundant bytes from the migrated have-set records so the
    // invariant (bytesless record ⇒ bytes in OPFS) is restored.
    if (dataBearing.length > 0) {
      try {
        const tx = db.transaction("chunks", "readwrite");
        const store = tx.objectStore("chunks");
        for (let i = 0; i < dataBearing.length; i++) {
          const r = dataBearing[i];
          await store.put({
            merkleRoot: r.merkleRoot,
            hash: r.hash,
            chunkIndex: r.chunkIndex,
            mimeType: r.mimeType,
            realLen: r.realLen,
            leafHash: r.leafHash,
          });
        }
        await tx.done;
      } catch (error) {
        console.error(error);
      }
    }
    db.close();

    const file = await fileHandle.getFile();
    if (totalSize > 0 && file.size !== totalSize) return null; // incomplete
    return wrapOPFSFile(file, filename, merkleRootHex, mimeType);
  } catch (error) {
    console.error(error);
    return null;
  }
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

    if (hashHex?.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index1.count(hashHex);

      if (chunks === 0) {
        if (merkleRootHex?.length === 2 * crypto_hash_sha512_BYTES) {
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
    } else if (merkleRootHex?.length === 2 * crypto_hash_sha512_BYTES) {
      const chunks = await index2.count(merkleRootHex);

      await tx.done;
      db.close();

      return chunks;
    } else {
      await tx.done;
      db.close();

      return 0;
    }
  } catch {
    return 0;
  }
}

async function fnSetDBChunk(chunk: Chunk): Promise<void> {
  const db = await getDB();
  try {
    await db.add("chunks", chunk);
  } finally {
    db.close();
  }
}

async function fnGetDBAllNewChunks(
  selector: NewChunkSelector,
): Promise<NewChunk[]> {
  const { transferId, merkleRootHex, hashHex } = selector;
  const indexName = transferId
    ? "transferId"
    : merkleRootHex
      ? "merkleRoot"
      : hashHex
        ? "hash"
        : undefined;
  const value = transferId ?? merkleRootHex ?? hashHex;
  if (!indexName || !value) return [];

  const db = await getDB();
  try {
    return await db.getAllFromIndex("newChunks", indexName, value);
  } finally {
    db.close();
  }
}

async function fnGetDBAllNewChunksCount(transferId: string): Promise<number> {
  const db = await getDB();
  try {
    return await db.countFromIndex("newChunks", "transferId", transferId);
  } finally {
    db.close();
  }
}

async function fnSetDBNewChunk(
  chunk: NewChunk,
  lease?: OutboxLease,
): Promise<void> {
  await storeOutboxChunk(chunk, lease);
}

async function fnSetDBSendQueue(item: SendQueue): Promise<void> {
  const db = await getDB();
  await db.put("sendQueue", item);
  db.close();
}

const ratchetRollbackGuard = new RatchetRollbackGuard();
const ratchetLastWrite = new Map<string, number>();
const ratchetWorkerLocks = new Map<string, Promise<void>>();

const ratchetWorkerKey = (roomId: string, peerPublicKey: string): string =>
  `${String(roomId.length)}:${roomId}${String(peerPublicKey.length)}:${peerPublicKey}`;

const withRatchetWorkerLock = async <T>(
  roomId: string,
  peerPublicKey: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const key = ratchetWorkerKey(roomId, peerPublicKey);
  const previous = ratchetWorkerLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.catch(() => undefined).then(() => held);
  ratchetWorkerLocks.set(key, tail);
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    if (ratchetWorkerLocks.get(key) === tail) ratchetWorkerLocks.delete(key);
  }
};

const wipeWorkerRatchetSecrets = (session: RatchetSession): void => {
  new Uint8Array(session.rootKey).fill(0);
  if (session.sendingChainKey) new Uint8Array(session.sendingChainKey).fill(0);
  if (session.receivingChainKey)
    new Uint8Array(session.receivingChainKey).fill(0);
  new Uint8Array(session.dhSelfSec).fill(0);
  for (const skipped of session.skippedMessageKeys)
    new Uint8Array(skipped.messageKey).fill(0);
  if (session.edgeCryptoState) new Uint8Array(session.edgeCryptoState).fill(0);
};

async function fnGetRatchetSession(
  roomId: string,
  peerPublicKey: string,
): Promise<RatchetSession | undefined> {
  return withRatchetWorkerLock(roomId, peerPublicKey, async () => {
    try {
      const db = await getDB();
      let stored: RatchetSession | undefined;
      try {
        stored = await db.get("ratchetSessions", [roomId, peerPublicKey]);
      } finally {
        db.close();
      }
      if (!stored) return undefined;
      const key = await getWrapKey();
      const restored = await unwrapRatchetSession(
        stored,
        key,
        ratchetRollbackGuard,
      );
      const edge = ratchetWorkerKey(roomId, peerPublicKey);
      ratchetLastWrite.set(
        edge,
        Math.max(ratchetLastWrite.get(edge) ?? 0, restored.updatedAt),
      );
      return restored;
    } catch (error) {
      console.error(error);
      return undefined;
    }
  });
}

async function fnSetRatchetSession(session: RatchetSession): Promise<void> {
  await withRatchetWorkerLock(
    session.roomId,
    session.peerPublicKey,
    async () => {
      const edge = ratchetWorkerKey(session.roomId, session.peerPublicKey);
      const previous = ratchetLastWrite.get(edge) ?? 0;
      const requested = Math.max(Date.now(), session.updatedAt);
      const updatedAt = requested > previous ? requested : previous + 1;
      if (!Number.isSafeInteger(updatedAt))
        throw new Error("Ratchet persistence timestamp exhausted");

      const stamped: RatchetSession = { ...session, updatedAt };
      try {
        const key = await getWrapKey();
        const wrapped = await wrapRatchetSession(stamped, key);
        const db = await getDB();
        try {
          await db.put("ratchetSessions", wrapped);
        } finally {
          db.close();
        }
        // Advance the process-local high-water mark only after the row is
        // durable. This is a locally produced envelope, so no redundant
        // decrypt-all-fields pass is needed.
        await ratchetRollbackGuard.rememberTrustedWrite(wrapped);
        ratchetLastWrite.set(edge, updatedAt);
      } finally {
        // postMessage cloned these inputs into the worker; erase that worker
        // copy after wrapping regardless of storage success.
        wipeWorkerRatchetSecrets(stamped);
      }
    },
  );
}

async function fnDeleteRatchetSession(
  roomId: string,
  peerPublicKey: string,
): Promise<void> {
  await withRatchetWorkerLock(roomId, peerPublicKey, async () => {
    try {
      const db = await getDB();
      await db.delete("ratchetSessions", [roomId, peerPublicKey]);
      db.close();
      ratchetRollbackGuard.forget(roomId, peerPublicKey);
      ratchetLastWrite.delete(ratchetWorkerKey(roomId, peerPublicKey));
    } catch (error) {
      console.error(error);
    }
  });
}

const PIN_ATTEMPT_META_PREFIX = "pinAttempts:v2:";
const PIN_IDENTITY_RE = /^[0-9a-f]{64}$/;

const assertPinAttemptScope = (
  roomId: string,
  peerIdentityEd25519?: string,
): void => {
  if (typeof roomId !== "string" || roomId.length === 0)
    throw new Error("PIN attempt room ID must not be empty");
  if (
    peerIdentityEd25519 !== undefined &&
    !PIN_IDENTITY_RE.test(peerIdentityEd25519)
  )
    throw new Error(
      "PIN attempt peer identity must be 32-byte lowercase hexadecimal",
    );
};

// A length-prefixed room component prevents one room ID from becoming another
// room's deletion prefix. The stable Ed25519 identity — never the transient
// signaling peer ID — is the bucket that follows a peer across reconnects.
const pinAttemptRoomMetaPrefix = (roomId: string): string =>
  `${PIN_ATTEMPT_META_PREFIX}${roomId.length}:${roomId}:`;

const pinAttemptMetaId = (
  roomId: string,
  peerIdentityEd25519: string,
): string => `${pinAttemptRoomMetaPrefix(roomId)}${peerIdentityEd25519}`;

async function fnGetPinAttemptState(
  roomId: string,
  peerIdentityEd25519: string,
): Promise<PinAttemptState | undefined> {
  assertPinAttemptScope(roomId, peerIdentityEd25519);
  const db = await getDB();
  try {
    return (await db.get(
      "meta",
      pinAttemptMetaId(roomId, peerIdentityEd25519),
    )) as PinAttemptState | undefined;
  } finally {
    db.close();
  }
}

async function fnIncrementPinAttemptState(
  roomId: string,
  peerIdentityEd25519: string,
  now: number,
  maxImmediateAttempts: number,
  baseMs: number,
  maxMs: number,
): Promise<PinAttemptState> {
  assertPinAttemptScope(roomId, peerIdentityEd25519);
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(maxImmediateAttempts) ||
    !Number.isSafeInteger(baseMs) ||
    !Number.isSafeInteger(maxMs) ||
    now < 0 ||
    maxImmediateAttempts < 1 ||
    baseMs < 1 ||
    maxMs < baseMs
  )
    throw new Error("Invalid PIN backoff parameters");

  const db = await getDB();
  try {
    // A single readwrite transaction makes concurrent failures for this
    // room/identity bucket serialize instead of losing increments in a
    // get-then-put race.
    const tx = db.transaction("meta", "readwrite");
    const store = tx.objectStore("meta");
    const key = pinAttemptMetaId(roomId, peerIdentityEd25519);
    const current = (await store.get(key)) as PinAttemptState | undefined;
    const failures = (current?.failures ?? 0) + 1;
    const delay =
      failures < maxImmediateAttempts
        ? 0
        : Math.min(baseMs * 2 ** (failures - maxImmediateAttempts), maxMs);
    const next = { failures, retryAfter: now + delay };
    await store.put(next, key);
    await tx.done;
    return next;
  } finally {
    db.close();
  }
}

async function fnDeletePinAttemptState(
  roomId: string,
  peerIdentityEd25519?: string,
): Promise<void> {
  assertPinAttemptScope(roomId, peerIdentityEd25519);
  const db = await getDB();
  try {
    if (peerIdentityEd25519 !== undefined) {
      await db.delete("meta", pinAttemptMetaId(roomId, peerIdentityEd25519));
      return;
    }

    const tx = db.transaction("meta", "readwrite");
    const store = tx.objectStore("meta");
    const prefix = pinAttemptRoomMetaPrefix(roomId);
    const keys = await store.getAllKeys();
    await Promise.all(
      keys
        .filter((key): key is string => {
          return typeof key === "string" && key.startsWith(prefix);
        })
        .map((key) => store.delete(key)),
    );
    // Remove the obsolete room-wide v1 bucket too. It is intentionally never
    // consulted: carrying it forward would preserve the cross-peer DoS.
    await store.delete(`pinAttempts:${roomId}`);
    await tx.done;
  } finally {
    db.close();
  }
}

// D2=B: the dedicated X25519 identity, stored in the `meta` store under
// IDENTITY_X25519_META_ID. Only the secret is WebCrypto-wrapped at rest (getWrapKey/
// wrapSecret); pub + crossSig are public and stored in the clear.
const IDENTITY_X25519_META_ID = "identityX25519";

async function fnGetIdentityX25519(): Promise<IdentityX25519 | undefined> {
  const db = await getDB();
  let stored: StoredIdentityX25519 | undefined;
  try {
    stored = (await db.get("meta", IDENTITY_X25519_META_ID)) as
      StoredIdentityX25519 | undefined;
  } finally {
    db.close();
  }
  if (!stored) return undefined;
  if (stored.pub.byteLength !== 32 || stored.crossSig.byteLength !== 64)
    throw new Error("Stored X25519 identity has invalid public fields");
  const key = await getWrapKey();
  const secret = await unwrapSecret(key, stored.wrappedSecret);
  if (secret.byteLength !== 32)
    throw new Error("Stored X25519 identity has an invalid secret length");
  return { pub: stored.pub, secret, crossSig: stored.crossSig };
}

async function fnSetIdentityX25519(identity: IdentityX25519): Promise<void> {
  if (
    identity.pub.byteLength !== 32 ||
    identity.secret.byteLength !== 32 ||
    identity.crossSig.byteLength !== 64
  )
    throw new Error("X25519 identity has invalid field lengths");
  const key = await getWrapKey();
  const wrappedSecret = await wrapSecret(key, identity.secret);
  const stored: StoredIdentityX25519 = {
    pub: identity.pub,
    wrappedSecret,
    crossSig: identity.crossSig,
  };
  const db = await getDB();
  try {
    await db.put("meta", stored, IDENTITY_X25519_META_ID);
  } finally {
    db.close();
  }
}

async function fnDeleteIdentityX25519(): Promise<void> {
  const db = await getDB();
  try {
    const tx = db.transaction(["meta", "ratchetSessions"], "readwrite");
    await tx.objectStore("meta").delete(IDENTITY_X25519_META_ID);
    // Every persisted ratchet is authenticated to the identity being purged;
    // retaining one across identity rotation would restore an orphaned edge.
    await tx.objectStore("ratchetSessions").clear();
    await tx.done;
  } finally {
    db.close();
  }
  ratchetRollbackGuard.clear();
  ratchetLastWrite.clear();
}

// The account-signing identity is no longer persisted in localStorage. Its
// secret uses the same non-extractable AES-GCM wrapping key as ratchet/X25519
// secrets; the public half remains inspectable. The high-water record is kept
// separately so deleting the identity cannot make a later key reuse a revision.
// Both values live in the existing out-of-line `meta` store, so this adds no
// IndexedDB schema and intentionally requires no dbVersion bump.
const IDENTITY_ED25519_META_ID = "identityEd25519";
const IDENTITY_ED25519_REVISION_META_ID = "identityEd25519Revision";
const IDENTITY_ED25519_RECORD_VERSION = 1;
const FIRST_IDENTITY_ED25519_REVISION = 1n;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;
const WRAPPED_ED25519_SECRET_BYTES = 12 + 64 + 16;

interface LegacyStoredIdentityEd25519 {
  pub: ArrayBuffer;
  wrappedSecret: ArrayBuffer;
}

type ParsedStoredIdentityEd25519 =
  | {
      kind: "legacy";
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
    }
  | {
      kind: "current";
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      recordRevision: bigint;
    };

interface IdentityEd25519StorageSnapshot {
  identity: ParsedStoredIdentityEd25519 | undefined;
  revision: StoredIdentityEd25519Revision | undefined;
}

const edIdentityCopyBuffer = (value: ArrayBuffer): ArrayBuffer =>
  value.slice(0);

const edIdentityBuffersEqual = (
  left: ArrayBuffer,
  right: ArrayBuffer,
): boolean => {
  if (left.byteLength !== right.byteLength) return false;
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  let difference = 0;
  for (let i = 0; i < a.byteLength; i++) difference |= a[i] ^ b[i];
  return difference === 0;
};

// Defense in depth for direct worker messages and stored rows. Full
// seed-derived consistency is enforced by the main-realm client boundary.
const edIdentityPublicMatchesSecretSuffix = (
  pub: ArrayBuffer,
  secret: ArrayBuffer,
): boolean => {
  if (pub.byteLength !== 32 || secret.byteLength !== 64) return false;
  const publicBytes = new Uint8Array(pub);
  const secretBytes = new Uint8Array(secret);
  let difference = 0;
  for (let i = 0; i < publicBytes.byteLength; i++) {
    difference |= publicBytes[i] ^ secretBytes[32 + i];
  }
  return difference === 0;
};

const requireExactEdIdentityDataRecord = (
  value: unknown,
  expectedKeys: readonly string[],
  name: string,
): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${name} is malformed`);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  )
    throw new Error(`${name} is malformed`);
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor))
      throw new Error(`${name} is malformed`);
  }
  return value as Record<string, unknown>;
};

const requireEdIdentityU64 = (
  value: unknown,
  name: string,
  allowZero: boolean,
): bigint => {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value > UINT64_MAX ||
    (!allowZero && value === 0n)
  )
    throw new Error(`${name} must be a ${allowZero ? "" : "non-zero "}uint64`);
  return value;
};

const requireStoredEdIdentityBytes = (
  record: Record<string, unknown>,
): LegacyStoredIdentityEd25519 => {
  const pub = record.pub;
  const wrappedSecret = record.wrappedSecret;
  if (!(pub instanceof ArrayBuffer) || pub.byteLength !== 32)
    throw new Error("Stored Ed25519 public key has an invalid length");
  if (
    !(wrappedSecret instanceof ArrayBuffer) ||
    wrappedSecret.byteLength !== WRAPPED_ED25519_SECRET_BYTES
  )
    throw new Error("Stored Ed25519 wrapped secret is malformed");
  return { pub, wrappedSecret };
};

const parseStoredIdentityEd25519 = (
  value: unknown,
): ParsedStoredIdentityEd25519 | undefined => {
  if (value === undefined) return undefined;
  if (
    typeof value === "object" &&
    value !== null &&
    Object.prototype.hasOwnProperty.call(value, "version")
  ) {
    const record = requireExactEdIdentityDataRecord(
      value,
      ["version", "pub", "wrappedSecret", "recordRevision"],
      "Stored Ed25519 identity",
    );
    if (record.version !== IDENTITY_ED25519_RECORD_VERSION)
      throw new Error("Stored Ed25519 identity version is unsupported");
    const bytes = requireStoredEdIdentityBytes(record);
    return {
      kind: "current",
      ...bytes,
      recordRevision: requireEdIdentityU64(
        record.recordRevision,
        "Stored Ed25519 identity revision",
        false,
      ),
    };
  }
  const record = requireExactEdIdentityDataRecord(
    value,
    ["pub", "wrappedSecret"],
    "Legacy stored Ed25519 identity",
  );
  return { kind: "legacy", ...requireStoredEdIdentityBytes(record) };
};

const parseIdentityEd25519Revision = (
  value: unknown,
): StoredIdentityEd25519Revision | undefined => {
  if (value === undefined) return undefined;
  const record = requireExactEdIdentityDataRecord(
    value,
    ["version", "lastRevision"],
    "Ed25519 identity revision record",
  );
  if (record.version !== IDENTITY_ED25519_RECORD_VERSION)
    throw new Error("Ed25519 identity revision version is unsupported");
  return {
    version: IDENTITY_ED25519_RECORD_VERSION,
    lastRevision: requireEdIdentityU64(
      record.lastRevision,
      "Ed25519 identity high-water revision",
      true,
    ),
  };
};

const assertEdIdentityRevisionConsistency = (
  identity: ParsedStoredIdentityEd25519 | undefined,
  revision: StoredIdentityEd25519Revision | undefined,
): void => {
  if (identity?.kind === "legacy" && revision !== undefined)
    throw new Error("Stored Ed25519 identity revision state is inconsistent");
  if (
    identity?.kind === "current" &&
    (revision === undefined ||
      identity.recordRevision !== revision.lastRevision)
  )
    throw new Error("Stored Ed25519 identity revision state is inconsistent");
};

const identityEd25519HighWater = (
  identity: ParsedStoredIdentityEd25519 | undefined,
  revision: StoredIdentityEd25519Revision | undefined,
): bigint => {
  // The actual legacy row predates revisions. Its existing key owns revision 1,
  // so a direct overwrite/delete must allocate after it just as if get migrated.
  if (identity?.kind === "legacy") return FIRST_IDENTITY_ED25519_REVISION;
  return revision?.lastRevision ?? 0n;
};

const incrementEdIdentityRevision = (revision: bigint): bigint => {
  if (revision >= UINT64_MAX)
    throw new Error("Ed25519 identity revision overflow");
  return revision + 1n;
};

type RepoDatabase = Awaited<ReturnType<typeof getDB>>;

const readIdentityEd25519StorageSnapshot = async (
  db: RepoDatabase,
): Promise<IdentityEd25519StorageSnapshot> => {
  const tx = db.transaction("meta", "readonly");
  const store = tx.objectStore("meta");
  const [identityValue, revisionValue] = await Promise.all([
    store.get(IDENTITY_ED25519_META_ID),
    store.get(IDENTITY_ED25519_REVISION_META_ID),
  ]);
  await tx.done;
  const identity = parseStoredIdentityEd25519(identityValue);
  const revision = parseIdentityEd25519Revision(revisionValue);
  assertEdIdentityRevisionConsistency(identity, revision);
  return { identity, revision };
};

const migrateLegacyIdentityEd25519IfUnchanged = async (
  db: RepoDatabase,
  expected: IdentityEd25519StorageSnapshot,
): Promise<boolean> => {
  if (expected.identity?.kind !== "legacy" || expected.revision !== undefined)
    throw new Error("Legacy Ed25519 migration state is inconsistent");
  const tx = db.transaction("meta", "readwrite");
  const store = tx.objectStore("meta");
  const [identityValue, revisionValue] = await Promise.all([
    store.get(IDENTITY_ED25519_META_ID),
    store.get(IDENTITY_ED25519_REVISION_META_ID),
  ]);
  const current = {
    identity: parseStoredIdentityEd25519(identityValue),
    revision: parseIdentityEd25519Revision(revisionValue),
  };
  assertEdIdentityRevisionConsistency(current.identity, current.revision);
  if (
    current.identity?.kind !== "legacy" ||
    current.revision !== undefined ||
    !edIdentityBuffersEqual(expected.identity.pub, current.identity.pub) ||
    !edIdentityBuffersEqual(
      expected.identity.wrappedSecret,
      current.identity.wrappedSecret,
    )
  ) {
    await tx.done;
    return false;
  }
  await Promise.all([
    store.put(
      {
        version: IDENTITY_ED25519_RECORD_VERSION,
        pub: edIdentityCopyBuffer(expected.identity.pub),
        wrappedSecret: edIdentityCopyBuffer(expected.identity.wrappedSecret),
        recordRevision: FIRST_IDENTITY_ED25519_REVISION,
      } satisfies StoredIdentityEd25519,
      IDENTITY_ED25519_META_ID,
    ),
    store.put(
      {
        version: IDENTITY_ED25519_RECORD_VERSION,
        lastRevision: FIRST_IDENTITY_ED25519_REVISION,
      } satisfies StoredIdentityEd25519Revision,
      IDENTITY_ED25519_REVISION_META_ID,
    ),
  ]);
  await tx.done;
  return true;
};

async function fnGetIdentityEd25519(): Promise<IdentityEd25519 | undefined> {
  const db = await getDB();
  let wrapKey: CryptoKey | undefined;
  try {
    for (;;) {
      const snapshot = await readIdentityEd25519StorageSnapshot(db);
      if (!snapshot.identity) return undefined;

      wrapKey ??= await getWrapKey();
      const secret = await unwrapSecret(
        wrapKey,
        snapshot.identity.wrappedSecret,
      );
      if (
        secret.byteLength !== 64 ||
        !edIdentityPublicMatchesSecretSuffix(snapshot.identity.pub, secret)
      ) {
        new Uint8Array(secret).fill(0);
        throw new Error(
          "Stored Ed25519 public and secret keys are inconsistent",
        );
      }
      try {
        if (
          snapshot.identity.kind === "legacy" &&
          !(await migrateLegacyIdentityEd25519IfUnchanged(db, snapshot))
        ) {
          new Uint8Array(secret).fill(0);
          continue;
        }
        return {
          pub: edIdentityCopyBuffer(snapshot.identity.pub),
          secret,
          recordRevision:
            snapshot.identity.kind === "legacy"
              ? FIRST_IDENTITY_ED25519_REVISION
              : snapshot.identity.recordRevision,
        };
      } catch (error) {
        new Uint8Array(secret).fill(0);
        throw error;
      }
    }
  } finally {
    db.close();
  }
}

async function fnSetIdentityEd25519(
  identity: IdentityEd25519KeyMaterial,
): Promise<bigint> {
  const ownedMessageSecret =
    typeof identity === "object" &&
    identity !== null &&
    identity.secret instanceof ArrayBuffer
      ? new Uint8Array(identity.secret)
      : undefined;
  try {
    if (
      !(identity.pub instanceof ArrayBuffer) ||
      !(identity.secret instanceof ArrayBuffer) ||
      identity.pub.byteLength !== 32 ||
      identity.secret.byteLength !== 64
    )
      throw new Error("Ed25519 identity has invalid key lengths");
    if (!edIdentityPublicMatchesSecretSuffix(identity.pub, identity.secret))
      throw new Error("Ed25519 public key does not match the secret key");

    const pub = edIdentityCopyBuffer(identity.pub);
    const secret = edIdentityCopyBuffer(identity.secret);
    let wrappedSecret: ArrayBuffer;
    try {
      const key = await getWrapKey();
      wrappedSecret = await wrapSecret(key, secret);
    } finally {
      new Uint8Array(secret).fill(0);
    }

    const db = await getDB();
    try {
      const tx = db.transaction("meta", "readwrite");
      const store = tx.objectStore("meta");
      const [identityValue, revisionValue] = await Promise.all([
        store.get(IDENTITY_ED25519_META_ID),
        store.get(IDENTITY_ED25519_REVISION_META_ID),
      ]);
      const currentIdentity = parseStoredIdentityEd25519(identityValue);
      const currentRevision = parseIdentityEd25519Revision(revisionValue);
      assertEdIdentityRevisionConsistency(currentIdentity, currentRevision);
      const highWaterRevision = identityEd25519HighWater(
        currentIdentity,
        currentRevision,
      );
      const recordRevision = incrementEdIdentityRevision(highWaterRevision);
      const stored: StoredIdentityEd25519 = {
        version: IDENTITY_ED25519_RECORD_VERSION,
        pub,
        wrappedSecret,
        recordRevision,
      };
      const revision: StoredIdentityEd25519Revision = {
        version: IDENTITY_ED25519_RECORD_VERSION,
        lastRevision: recordRevision,
      };
      await Promise.all([
        store.put(stored, IDENTITY_ED25519_META_ID),
        store.put(revision, IDENTITY_ED25519_REVISION_META_ID),
      ]);
      await tx.done;
      return recordRevision;
    } finally {
      db.close();
    }
  } finally {
    ownedMessageSecret?.fill(0);
  }
}

async function fnDeleteIdentityEd25519(): Promise<void> {
  const db = await getDB();
  try {
    const tx = db.transaction(["meta", "ratchetSessions"], "readwrite");
    const meta = tx.objectStore("meta");
    const [identityValue, revisionValue] = await Promise.all([
      meta.get(IDENTITY_ED25519_META_ID),
      meta.get(IDENTITY_ED25519_REVISION_META_ID),
    ]);
    const identity = parseStoredIdentityEd25519(identityValue);
    const revision = parseIdentityEd25519Revision(revisionValue);
    assertEdIdentityRevisionConsistency(identity, revision);
    if (identity !== undefined) {
      const highWaterRevision = identityEd25519HighWater(identity, revision);
      const retiredRevision = incrementEdIdentityRevision(highWaterRevision);
      await meta.put(
        {
          version: IDENTITY_ED25519_RECORD_VERSION,
          lastRevision: retiredRevision,
        } satisfies StoredIdentityEd25519Revision,
        IDENTITY_ED25519_REVISION_META_ID,
      );
      await meta.delete(IDENTITY_ED25519_META_ID);
    }
    await tx.objectStore("ratchetSessions").clear();
    await tx.done;
  } finally {
    db.close();
  }
  ratchetRollbackGuard.clear();
  ratchetLastWrite.clear();
}

// Whether the account identity was derived from a recovery phrase. Non-secret
// and never a key, but durable: after a reload the app can only tell the user
// "you can back this identity up" if it remembers how the key was created.
// Like both identity records this lives in the existing out-of-line `meta`
// store, so it adds no IndexedDB schema and requires no dbVersion bump.
const IDENTITY_DERIVATION_META_ID = "identityDerivation";
const IDENTITY_DERIVATION_RECORD_VERSION = 1;

const isIdentityDerivation = (value: unknown): value is IdentityDerivation =>
  value === "random" || value === "mnemonic";

/**
 * A malformed or future-versioned row is reported as unknown rather than
 * thrown: the only fail-safe reading of an unreadable provenance hint is "we
 * cannot promise this identity is recoverable", and a throw here would break
 * signaling bootstrap over a value no protocol step depends on.
 */
const parseStoredIdentityDerivation = (
  value: unknown,
): StoredIdentityDerivation | undefined => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return undefined;
  const record = value as Record<string, unknown>;
  if (record.version !== IDENTITY_DERIVATION_RECORD_VERSION) return undefined;
  if (!isIdentityDerivation(record.derivation)) return undefined;
  const boundPub = record.boundPub;
  if (boundPub !== null && !(boundPub instanceof ArrayBuffer)) return undefined;
  if (boundPub instanceof ArrayBuffer && boundPub.byteLength !== 32)
    return undefined;
  return {
    version: IDENTITY_DERIVATION_RECORD_VERSION,
    derivation: record.derivation,
    boundPub,
  };
};

const storedIdentityEd25519Pub = (value: unknown): ArrayBuffer | undefined => {
  try {
    return parseStoredIdentityEd25519(value)?.pub;
  } catch {
    // An unreadable identity row is the Ed25519 path's problem to report; here
    // it only means the flag has nothing it can still be bound to.
    return undefined;
  }
};

async function fnGetIdentityDerivation(): Promise<IdentityDerivation | null> {
  const db = await getDB();
  let derivationValue: unknown;
  let identityValue: unknown;
  try {
    const tx = db.transaction("meta", "readonly");
    const store = tx.objectStore("meta");
    [derivationValue, identityValue] = await Promise.all([
      store.get(IDENTITY_DERIVATION_META_ID),
      store.get(IDENTITY_ED25519_META_ID),
    ]);
    await tx.done;
  } finally {
    db.close();
  }

  const stored = parseStoredIdentityDerivation(derivationValue);
  if (stored === undefined) return null;
  if (stored.boundPub === null) return stored.derivation;

  // The claim was recorded against a specific account key. If that key is gone
  // or was replaced, the claim no longer describes the identity in use.
  const currentPub = storedIdentityEd25519Pub(identityValue);
  if (currentPub === undefined) return null;
  return edIdentityBuffersEqual(stored.boundPub, currentPub)
    ? stored.derivation
    : null;
}

async function fnSetIdentityDerivation(
  derivation: IdentityDerivation,
): Promise<void> {
  if (!isIdentityDerivation(derivation))
    throw new Error("Identity derivation value is unsupported");
  const db = await getDB();
  try {
    const tx = db.transaction("meta", "readwrite");
    const store = tx.objectStore("meta");
    // Bind in the same transaction that writes the flag, so a concurrent
    // identity rotation cannot be recorded as the key this claim describes.
    const boundPub = storedIdentityEd25519Pub(
      await store.get(IDENTITY_ED25519_META_ID),
    );
    await store.put(
      {
        version: IDENTITY_DERIVATION_RECORD_VERSION,
        derivation,
        boundPub:
          boundPub === undefined ? null : edIdentityCopyBuffer(boundPub),
      } satisfies StoredIdentityDerivation,
      IDENTITY_DERIVATION_META_ID,
    );
    await tx.done;
  } finally {
    db.close();
  }
}

async function fnDeleteIdentityDerivation(): Promise<void> {
  const db = await getDB();
  try {
    await db.delete("meta", IDENTITY_DERIVATION_META_ID);
  } finally {
    db.close();
  }
}

async function fnDeleteDBUniqueRoom(roomId: string): Promise<void> {
  const db = await getDB();
  try {
    const tx = db.transaction(["uniqueRoom", "ratchetSessions"], "readwrite");
    const store = tx.objectStore("uniqueRoom");
    const index = store.index("roomId");
    const item = await index.getKey(roomId);
    if (item !== undefined) {
      await store.delete(item);
    }
    const ratchets = tx.objectStore("ratchetSessions");
    const ratchetKeys = await ratchets.index("roomId").getAllKeys(roomId);
    for (const key of ratchetKeys) {
      await ratchets.delete(key);
      if (Array.isArray(key) && typeof key[1] === "string") {
        ratchetRollbackGuard.forget(roomId, key[1]);
        ratchetLastWrite.delete(ratchetWorkerKey(roomId, key[1]));
      }
    }

    await tx.done;
  } finally {
    db.close();
  }
}

async function fnDeleteDBChunk(
  hashHex: string,
  chunkIndex?: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction(["chunks", "messageData"], "readwrite");
    const store = tx.objectStore("chunks");
    // Roots that lose chunk records here. A received root's running manifest
    // would no longer describe its records, so it is dropped and rebuilt from
    // the records on the next receive.
    const roots = new Set<string>();

    if (chunkIndex !== undefined) {
      const keys = IDBKeyRange.only([hashHex, chunkIndex]);
      await store.delete(keys);
      roots.add(hashHex);
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
          roots.add(keys[i][0]);
        }
      } else {
        for (let i = 0; i < len; i++) {
          await store.delete(keys[i]);
          roots.add(keys[i][0]);
        }
      }
    }

    const messages = tx.objectStore("messageData");
    for (const root of roots) {
      const message = await messages.index("merkleRoot").get(root);
      if (message?.receiveManifest !== undefined) {
        const { receiveManifest: _stale, ...rest } = message;
        void _stale;
        await messages.put(rest);
      }
    }

    await tx.done;
    db.close();
  } catch {
    /* empty */
  }
}

async function fnDeleteDBNewChunk(selector: NewChunkSelector): Promise<void> {
  const { transferId, merkleRootHex, hashHex, chunkIndex } = selector;
  const db = await getDB();
  try {
    const tx = db.transaction("newChunks", "readwrite");
    const store = tx.objectStore("newChunks");

    if (transferId && chunkIndex !== undefined) {
      await store.delete([transferId, chunkIndex]);
    } else if (transferId) {
      const keys = await store.index("transferId").getAllKeys(transferId);
      for (const key of keys) await store.delete(key);
    } else if (merkleRootHex) {
      const keys = await store.index("merkleRoot").getAllKeys(merkleRootHex);
      for (const key of keys) await store.delete(key);
    } else if (hashHex) {
      const keys = await store.index("hash").getAllKeys(hashHex);
      for (const key of keys) await store.delete(key);
    }

    await tx.done;
  } catch (error) {
    console.error(error);
    throw error;
  } finally {
    db.close();
  }
}

async function fnDeleteDBSendQueue(
  label: string,
  toPeerId: string,
  position?: number,
): Promise<void> {
  try {
    const db = await getDB();
    if (position !== undefined) {
      await db.delete("sendQueue", [position, label, toPeerId]);
    } else {
      const keyRange = IDBKeyRange.only([label, toPeerId]);
      await db.delete("sendQueue", keyRange);
    }
    db.close();
  } catch {
    /* empty */
  }
}

/**
 * Remove every receiver-owned artifact for one Merkle root.
 *
 * The dispatcher calls this while holding the same per-root lock as
 * storeReceiveChunk. Consequently, cancellation that races a write is ordered
 * after that write and cannot leave a newly-created chunk/message row behind.
 * The IndexedDB records share one transaction; the OPFS handle is closed before
 * its file is removed.
 */
async function fnDeleteReceiveTransferLocked(
  merkleRootHex: string,
  staleBefore?: number,
  guard?: ReceiveDeleteGuard,
  onDeleted?: (scope: ExpiredReceiveTransfer) => void,
): Promise<boolean> {
  if (
    merkleRootHex.length !== crypto_hash_sha512_BYTES * 2 ||
    !/^[0-9a-f]+$/.test(merkleRootHex)
  )
    throw new Error("invalid receive transfer Merkle root");

  // A verification of this file stops and releases its handle first; deleting
  // the row below keeps its verdict from ever being committed. An assembly of
  // it finishes and closes its own handle; then the receive handle is closed.
  // The browser refuses to remove a file while any handle on it is open.
  await stopVerification(merkleRootHex);
  await settleAssemblies(merkleRootHex);

  await fnCloseReceiveFile(merkleRootHex);

  const db = await getDB();
  try {
    const tx = db.transaction(
      ["chunks", "messageData", "uniqueRoom", "receiveActivity"],
      "readwrite",
    );
    const activityStore = tx.objectStore("receiveActivity");
    const activity = await activityStore.get(merkleRootHex);
    const previous = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(merkleRootHex);
    if (
      guard &&
      (!previous ||
        guard.incompleteOnly !== true ||
        previous.transferId !== undefined ||
        previous.roomId !== guard.roomId ||
        previous.fromPeerId !== guard.fromPeerId ||
        previous.savedSize >= previous.totalSize)
    ) {
      await tx.done;
      return false;
    }
    if (
      staleBefore !== undefined &&
      (!activity ||
        activity.deletedAt !== undefined ||
        activity.lastActivityAt > staleBefore ||
        (activity.leaseUntil ?? 0) > Date.now() ||
        (previous &&
          (previous.transferId !== undefined ||
            previous.roomId !== activity.roomId ||
            previous.fromPeerId !== activity.fromPeerId ||
            previous.savedSize >= previous.totalSize)))
    ) {
      await tx.done;
      return false;
    }
    if (activity || previous)
      await activityStore.put({
        merkleRoot: merkleRootHex,
        roomId: activity?.roomId ?? previous!.roomId,
        fromPeerId: activity?.fromPeerId ?? previous!.fromPeerId,
        lastActivityAt: Date.now(),
        deletedAt: Date.now(),
      });
    const chunkStore = tx.objectStore("chunks");
    const messageStore = tx.objectStore("messageData");
    const roomStore = tx.objectStore("uniqueRoom");

    const chunkKeys = await chunkStore
      .index("merkleRoot")
      .getAllKeys(merkleRootHex);
    for (const key of chunkKeys) await chunkStore.delete(key);

    const messageKeys = await messageStore
      .index("merkleRoot")
      .getAllKeys(merkleRootHex);
    let roomId = "";
    for (const key of messageKeys) {
      const message = await messageStore.get(key);
      if (!roomId && message) roomId = message.roomId;
      await messageStore.delete(key);
    }

    if (roomId) {
      const room = await roomStore.index("roomId").get(roomId);
      if (room) {
        const roomMessages = messageStore.index("roomId");
        const remainingCount = await roomMessages.count(roomId);
        const latest = await roomMessages.openCursor(
          IDBKeyRange.only(roomId),
          "prev",
        );
        await roomStore.put({
          ...room,
          messageCount: remainingCount,
          updatedAt: latest?.value.timestamp ?? Date.now(),
          lastMessageMerkleRoot: latest?.value.merkleRoot ?? "",
        });
      }
    }

    await tx.done;
    // Capture ownership from the SAME transaction that authorized deletion.
    // A later main-thread projection must never infer it from another room.
    if (activity || previous)
      onDeleted?.({
        merkleRoot: merkleRootHex,
        roomId: activity?.roomId ?? previous!.roomId,
        fromPeerId: activity?.fromPeerId ?? previous!.fromPeerId,
      });
  } finally {
    db.close();
  }

  await fnDeleteOPFSFile(merkleRootHex);
  return true;
}

// A full wipe. It does everything it can, and then reports a received file it
// could not remove: a purge never reports done while plaintext it tried to
// remove is still on disk.
async function fnDeleteDB(): Promise<void> {
  let leftBehind: unknown;
  try {
    // Stop every verification, let every assembly finish, and close every
    // receive handle first: the browser refuses to remove the directory while
    // a handle on a file inside it is open (NoModificationAllowedError, as
    // measured by docs/e2e/opfs-remove/), though the File System Standard's
    // removeEntry steps name no lock.
    forgetStartupRetries();
    for (const merkleRoot of [...liveVerifications.keys()])
      await stopVerification(merkleRoot);
    await settleAssemblies();
    await closeAllReceiveFiles();
    // Also remove the whole OPFS reassembly subtree (a separate storage system
    // that deleteDatabase cannot touch), so a full wipe reclaims that disk too.
    const storage = opfsStorage();
    if (storage && typeof storage.getDirectory === "function") {
      const root = (await storage.getDirectory()) as unknown as {
        removeEntry: (
          name: string,
          options: { recursive: boolean },
        ) => Promise<void>;
      };
      try {
        await root.removeEntry(OPFS_REASSEMBLE_DIR, { recursive: true });
      } catch (error) {
        // Not there is fine: nothing was left.
        if ((error as { name?: string } | null)?.name !== "NotFoundError")
          leftBehind = error;
      }
    }
  } catch (error) {
    leftBehind = error;
  }

  await deleteDB(dbName, {
    blocked() {
      console.error("DB deletion BLOCKED");
    },
  });
  ratchetRollbackGuard.clear();
  ratchetLastWrite.clear();
  if (leftBehind !== undefined)
    throw new StorageFailedError(
      `p2party: the purge could not remove received files: ${String(leftBehind)}`,
      { cause: leftBehind },
    );
}

onmessage = async (e: MessageEvent) => {
  const message = e.data as WorkerMessages;
  const { id, method } = message;
  try {
    let result: WorkerMethodReturnTypes[typeof method];
    switch (method) {
      case "outboxRequest":
        result = await executeOutbox(...message.args);
        break;
      case "sweepStaleReceives":
        result = (await fnSweepStaleReceives()).map((row) => row.merkleRoot);
        break;
      case "sweepStaleReceiveDetails":
        result = await fnSweepStaleReceives();
        break;
      case "getDBAddressBookEntry":
        result = await fnGetDBAddressBookEntry(...message.args);
        break;
      case "getAllDBAddressBookEntries":
        result = await fnGetAllDBAddressBookEntries(...message.args);
        break;
      case "setDBAddressBookEntry":
        await fnSetDBAddressBookEntry(...message.args);
        result = undefined;
        break;
      case "deleteDBAddressBookEntry":
        result = await fnDeleteDBAddressBookEntry(...message.args);
        break;
      case "getDBPeerIsBlacklisted":
        result = await fnGetDBPeerIsBlackisted(...message.args);
        break;
      case "getAllDBBlacklisted":
        result = await fnGetAllDBBlacklisted(...message.args);
        break;
      case "setDBPeerInBlacklist":
        await fnSetDBPeerInBlacklist(...message.args);
        result = undefined;
        break;
      case "deleteDBPeerFromBlacklist":
        await fnDeleteDBPeerFromBlacklist(...message.args);
        result = undefined;
        break;
      case "getAllDBUniqueRooms":
        result = await fnGetAllDBUniqueRooms(...message.args);
        break;
      case "setDBUniqueRoom":
        await fnSetDBUniqueRoom(...message.args);
        result = undefined;
        break;
      case "getDBMessageData":
        result = await fnGetDBMessageData(...message.args);
        break;
      case "getDBRoomMessageData":
        result = await fnGetDBRoomMessageData(...message.args);
        break;
      case "getDBRoomStats":
        result = await fnGetDBRoomStats(...message.args);
        break;
      case "setDBRoomMessageData":
        await fnSetDBRoomMessageData(...message.args);
        result = undefined;
        break;
      case "getDBChunk":
        result = await fnGetDBChunk(...message.args);
        break;
      case "existsDBChunk":
        result = await fnExistsDBChunk(...message.args);
        break;
      case "getDBNewChunk":
        result = await fnGetDBNewChunk(...message.args);
        break;
      case "getDBNewChunkByReceipt":
        result = await fnGetDBNewChunkByReceipt(...message.args);
        break;
      case "existsDBNewChunk":
        result = await fnExistsDBNewChunk(...message.args);
        break;
      case "getDBSendQueue":
        result = await fnGetDBSendQueue(...message.args);
        break;
      case "getDBAllChunks":
        result = await fnGetDBAllChunks(...message.args);
        break;
      case "getDBAllChunkLeafHashes":
        result = await fnGetDBAllChunkLeafHashes(...message.args);
        break;
      case "assembleToOPFS":
        result = await fnAssembleToOPFS(...message.args);
        break;
      case "getDBAllChunksCount":
        result = await fnGetDBAllChunksCount(...message.args);
        break;
      case "setDBChunk":
        await fnSetDBChunk(...message.args);
        result = undefined;
        break;
      case "storeReceiveChunk": {
        const admittedAt = Date.now();
        const chunk = message.args[0];
        try {
          result = await withReceiveLock(chunk.merkleRoot, () =>
            fnStoreReceiveChunk(chunk, admittedAt),
          );
        } catch (error) {
          // A refused chunk stays an error. A storage fault becomes a typed
          // result, so the receiver can tell its app and withhold the receipt.
          if (error instanceof ReceiveChunkRejectedError) throw error;
          console.error("p2party: could not store a received chunk", error);
          result = receiveStorageFailure(error);
        }
        break;
      }
      case "verifyReceivedFile":
        // Takes the per-file lock itself, only to start and not to hash.
        result = await fnVerifyReceivedFile(...message.args);
        break;
      case "settleReceivedFileVerification":
        result = await fnSettleReceivedFileVerification(...message.args);
        break;
      case "abortReceivedFileVerification":
        fnAbortReceivedFileVerification(...message.args);
        result = undefined;
        break;
      case "getReceiveFile": {
        const args = message.args;
        result = await withReceiveLock(args[0], () =>
          fnGetReceiveFile(...args),
        );
        break;
      }
      case "closeReceiveFile":
        await withReceiveLock(message.args[0], () =>
          fnCloseReceiveFile(...message.args),
        );
        result = undefined;
        break;
      case "deleteReceiveTransfer": {
        const [root, guard] = message.args;
        const removed = await withReceiveLock(root, () =>
          fnDeleteReceiveTransferLocked(root, undefined, guard),
        );
        result = guard ? removed : undefined;
        break;
      }
      case "getDBAllNewChunks":
        result = await fnGetDBAllNewChunks(...message.args);
        break;
      case "getDBAllNewChunksCount":
        result = await fnGetDBAllNewChunksCount(...message.args);
        break;
      case "setDBNewChunk":
        await fnSetDBNewChunk(...message.args);
        result = undefined;
        break;
      case "setDBSendQueue":
        await fnSetDBSendQueue(...message.args);
        result = undefined;
        break;
      case "countDBSendQueue":
        result = await fnCountDBSendQueue(...message.args);
        break;
      case "deleteDBChunk":
        await fnDeleteDBChunk(...message.args);
        result = undefined;
        break;
      case "deleteDBNewChunk":
        await fnDeleteDBNewChunk(...message.args);
        result = undefined;
        break;
      case "deleteDBUniqueRoom":
        await fnDeleteDBUniqueRoom(...message.args);
        result = undefined;
        break;
      case "deleteDBSendQueue":
        await fnDeleteDBSendQueue(...message.args);
        result = undefined;
        break;
      case "getRatchetSession":
        result = await fnGetRatchetSession(...message.args);
        break;
      case "setRatchetSession":
        await fnSetRatchetSession(...message.args);
        result = undefined;
        break;
      case "deleteRatchetSession":
        await fnDeleteRatchetSession(...message.args);
        result = undefined;
        break;
      case "getPinAttemptState":
        result = await fnGetPinAttemptState(...message.args);
        break;
      case "incrementPinAttemptState":
        result = await fnIncrementPinAttemptState(...message.args);
        break;
      case "deletePinAttemptState":
        await fnDeletePinAttemptState(...message.args);
        result = undefined;
        break;
      case "getIdentityX25519":
        result = await fnGetIdentityX25519();
        break;
      case "setIdentityX25519":
        await fnSetIdentityX25519(...message.args);
        result = undefined;
        break;
      case "deleteIdentityX25519":
        await fnDeleteIdentityX25519();
        result = undefined;
        break;
      case "getIdentityEd25519":
        result = await fnGetIdentityEd25519();
        break;
      case "setIdentityEd25519":
        result = await fnSetIdentityEd25519(...message.args);
        break;
      case "deleteIdentityEd25519":
        await fnDeleteIdentityEd25519();
        result = undefined;
        break;
      case "getIdentityDerivation":
        result = await fnGetIdentityDerivation();
        break;
      case "setIdentityDerivation":
        await fnSetIdentityDerivation(...message.args);
        result = undefined;
        break;
      case "deleteIdentityDerivation":
        await fnDeleteIdentityDerivation();
        result = undefined;
        break;
      case "deleteDB":
        await fnDeleteDB();
        result = undefined;
        break;
      default:
        postMessage({ id, error: "Method not found" });
        return;
    }

    if (message.method === "getIdentityEd25519" && result !== undefined) {
      const secret = (result as IdentityEd25519).secret;
      try {
        (
          globalThis as unknown as {
            postMessage: (message: unknown, transfer?: Transferable[]) => void;
          }
        ).postMessage({ id, result }, [secret]);
      } catch (error) {
        new Uint8Array(secret).fill(0);
        throw error;
      }
    } else {
      postMessage({ id, result });
    }
  } catch (error: unknown) {
    postMessage({
      id,
      error: String(error),
      ...(error instanceof DatabaseUpgradeBlockedError ||
      error instanceof StorageFailedError
        ? { errorCode: error.code }
        : {}),
    });
  }
};
