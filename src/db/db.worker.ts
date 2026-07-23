import { deleteDB } from "idb";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import {
  CHUNK_LEN,
  MAX_MESSAGE_SIZE,
  OPFS_REASSEMBLE_DIR,
} from "../utils/constants";

import { getDB, dbName } from "./src/getDB";
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
  ReceiveChunkStoreResult,
  SendQueue,
  WorkerMessages,
  WorkerMethodReturnTypes,
  BlacklistedPeer,
  UsernamedPeer,
  UniqueRoom,
  NewChunk,
  NewChunkSelector,
  RatchetSession,
  IdentityEd25519,
  IdentityX25519,
  StoredIdentityEd25519,
  StoredIdentityX25519,
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

  try {
    const db = await getDB();
    const tx = db.transaction("blacklist", "readonly");
    const index = peerId
      ? tx.objectStore("blacklist").index("peerId")
      : tx.objectStore("blacklist").index("peerPublicKey");
    const peer = peerId
      ? await index.get(peerId)
      : await index.get(peerPublicKey ?? "");
    await tx.done;

    db.close();
    return peer ? true : false;
  } catch {
    return false;
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
    console.error(error);
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

async function fnGetDBRoomMessageData(roomId: string): Promise<MessageData[]> {
  const db = await getDB();
  const messages = await db.getAllFromIndex("messageData", "roomId", roomId);
  db.close();

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
    return await db.getFromIndex(
      "newChunks",
      "receiptScope",
      [merkleRootHex, receiptTokenHex],
    );
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

// The worker-only synchronous OPFS file access handle (Safari-safe). getSize is
// used by the receive path to detect whether the file is already pre-sized.
type OPFSSyncAccessHandle = {
  getSize: () => number;
  truncate: (size: number) => void;
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
async function fnDeleteOPFSFile(merkleRootHex: string): Promise<void> {
  try {
    const storage = opfsStorage();
    if (!storage || typeof storage.getDirectory !== "function") return;
    const root = await storage.getDirectory();
    const dir = await root
      .getDirectoryHandle(OPFS_REASSEMBLE_DIR)
      .catch(() => null);
    if (dir)
      await dir.removeEntry(merkleRootHex).catch(() => {
        /* not present — fine */
      });
  } catch {
    /* ignore */
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
// per-send tunable, so it is learned empirically: max(realLen) over received
// chunks — exact once >=2 chunks have been seen, or immediately from chunk 0
// (always a full chunk unless the file is a single chunk). The <=1 chunk that
// arrives before uniformSize is known (a non-zero index as the first received
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
  uniformSize: number; // real bytes per full chunk; 0 until known
  uniformKnown: boolean;
  maxRealLen: number;
  seenCount: number;
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
    return await fn();
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

async function openReceiveHandleImpl(
  merkleRootHex: string,
  totalSize: number,
): Promise<ReceiveFileEntry | null> {
  const storage = opfsStorage();
  if (!storage || typeof storage.getDirectory !== "function") return null;
  const root = await storage.getDirectory();
  const dir = await root.getDirectoryHandle(OPFS_REASSEMBLE_DIR, {
    create: true,
  });
  const fileHandle = await dir.getFileHandle(merkleRootHex, { create: true });
  const createSyncAccessHandle = getCreateSyncAccessHandle(fileHandle);
  if (typeof createSyncAccessHandle !== "function") return null;
  const access = await createSyncAccessHandle.call(fileHandle);
  try {
    // Pre-size to totalSize; truncate to a larger size zero-fills, so gaps are
    // zeros until their chunks land. On resume the file is already totalSize
    // (OPFS persists across reloads) so this is a no-op that preserves the data.
    if (totalSize > 0 && access.getSize() !== totalSize)
      access.truncate(totalSize);
    return {
      access,
      uniformSize: 0,
      uniformKnown: false,
      maxRealLen: 0,
      seenCount: 0,
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
): Promise<ReceiveFileEntry | null> {
  const open = opfsReceiving.get(merkleRootHex);
  if (open) return open;
  const inflight = opfsReceivingOpening.get(merkleRootHex);
  if (inflight) return inflight;
  // Cap open handles: evict the oldest (never the one we're opening) so a set of
  // stalled, never-completed transfers can't pin exclusive handles forever.
  if (opfsReceiving.size >= MAX_OPEN_RECEIVE_HANDLES) {
    for (const k of opfsReceiving.keys()) {
      if (k !== merkleRootHex) {
        await fnCloseReceiveFile(k);
        break;
      }
    }
  }
  const p = openReceiveHandleImpl(merkleRootHex, totalSize).catch((error) => {
    console.error(error);
    return null;
  });
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

// Place a real chunk's bytes into the OPFS file if its offset is computable;
// return false if it isn't yet (uniformSize unknown for a non-zero chunk) or
// OPFS is unavailable — in which case the caller keeps the bytes in IndexedDB.
async function placeReceiveChunk(
  merkleRootHex: string,
  chunkIndex: number,
  realLen: number,
  totalSize: number,
  data: ArrayBuffer,
): Promise<boolean> {
  const entry = await ensureReceiveHandle(merkleRootHex, totalSize);
  if (!entry) return false; // OPFS unavailable

  entry.maxRealLen = Math.max(entry.maxRealLen, realLen);
  entry.seenCount += 1;

  if (!entry.uniformKnown) {
    if (chunkIndex === 0) {
      // Chunk 0 is a full chunk whenever the file has >1 chunk, so it pins
      // uniformSize exactly. A single-chunk file (realLen === totalSize) writes
      // at offset 0 regardless, so uniformSize stays irrelevant.
      if (realLen < totalSize) entry.uniformSize = realLen;
      entry.uniformKnown = true;
    } else if (entry.seenCount >= 2) {
      // Any 2 chunks include >=1 full one (only the last chunk is short), so
      // max(realLen) is the exact uniform size.
      entry.uniformSize = entry.maxRealLen;
      entry.uniformKnown = true;
    }
  }

  if (!entry.uniformKnown) return false; // first non-zero chunk — keep in IDB

  const offset = chunkIndex === 0 ? 0 : chunkIndex * entry.uniformSize;
  writeReceiveAt(entry.access, offset, data);
  // Flush so the bytes are durable BEFORE fnStoreReceiveChunk commits the
  // (bytesless) have-set record. Without this a bytesless record could reach
  // disk while its OPFS write is still buffered (independent storage backends,
  // no cross-store ordering), and after a crash a resumed sender would skip a
  // chunk whose bytes were lost — a silent zero-gap. This is what makes the
  // "bytesless record ⇒ bytes durably in OPFS" invariant actually hold.
  entry.access.flush();
  return true;
}

// Store one received real chunk and compute authoritative distinct-byte
// progress. File bytes go to OPFS first; text bytes stay in the record. The
// insert/dedup decision and saved-size scan share one readwrite transaction, so
// a duplicate can never be mistaken for the chunk that completed a message.
async function storeReceiveChunkLocked(
  chunk: ReceiveChunk,
): Promise<ReceiveChunkStoreResult> {
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
    throw new Error("invalid receive chunk bounds");

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
      throw new Error("receive chunk metadata conflicts with message");
  };

  const validateLayout = (
    records: Array<{ chunkIndex: number; realLen?: number }>,
  ): { savedSize: number; complete: boolean } => {
    const ordered = records
      .map((record) => ({
        chunkIndex: record.chunkIndex,
        realLen: record.realLen ?? 0,
      }))
      .sort((a, b) => a.chunkIndex - b.chunkIndex);
    let savedSize = 0;
    for (let i = 0; i < ordered.length; i++) {
      const record = ordered[i];
      if (
        !Number.isSafeInteger(record.chunkIndex) ||
        record.chunkIndex < 0 ||
        !Number.isSafeInteger(record.realLen) ||
        record.realLen <= 0 ||
        record.realLen > CHUNK_LEN ||
        record.realLen > totalSize ||
        record.chunkIndex >= totalSize ||
        (i > 0 && ordered[i - 1].chunkIndex === record.chunkIndex)
      )
        throw new Error("invalid receive chunk layout");
      savedSize += record.realLen;
      if (!Number.isSafeInteger(savedSize) || savedSize > totalSize)
        throw new Error("receive chunks exceed declared total");
    }

    const zero = ordered.find((record) => record.chunkIndex === 0);
    let uniformSize: number | undefined;
    if (zero) uniformSize = zero.realLen;
    else if (ordered.length >= 2) {
      uniformSize = 0;
      for (const record of ordered)
        uniformSize = Math.max(uniformSize, record.realLen);
    }

    if (uniformSize !== undefined) {
      const expectedCount = Math.ceil(totalSize / uniformSize);
      const finalIndex = expectedCount - 1;
      const finalLength = totalSize - uniformSize * finalIndex;
      for (const record of ordered) {
        if (record.chunkIndex >= expectedCount)
          throw new Error("receive chunk index exceeds canonical manifest");
        const expectedLength =
          record.chunkIndex === finalIndex ? finalLength : uniformSize;
        if (record.realLen !== expectedLength)
          throw new Error("receive chunk length conflicts with manifest");
      }

      const complete =
        savedSize === totalSize &&
        ordered.length === expectedCount &&
        ordered.every((record, index) => record.chunkIndex === index);
      if (savedSize === totalSize && !complete)
        throw new Error("receive completion has a chunk-index gap");
      return { savedSize, complete };
    }

    // One non-zero out-of-order chunk cannot establish the uniform size. It is
    // valid partial progress, but can never by itself claim completion.
    if (savedSize === totalSize)
      throw new Error("receive completion is missing chunk zero");
    return { savedSize, complete: false };
  };

  // Dedup first — also skips a redundant OPFS write for a chunk we already have.
  const existsDb = await getDB();
  let already: number;
  try {
    const tx = existsDb.transaction(
      ["chunks", "messageData"],
      "readonly",
    );
    already = await tx
      .objectStore("chunks")
      .count([merkleRoot, chunkIndex]);
    const previous = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .get(merkleRoot);
    assertManifest(previous);
    await tx.done;
  } finally {
    existsDb.close();
  }
  if (already > 0) {
    const db = await getDB();
    try {
      const tx = db.transaction(
        ["chunks", "messageData"],
        "readonly",
      );
      const index = tx.objectStore("chunks").index("merkleRoot");
      const records: Chunk[] = [];
      let cursor = await index.openCursor(merkleRoot);
      while (cursor) {
        records.push(cursor.value);
        cursor = await cursor.continue();
      }
      assertManifest(
        await tx
          .objectStore("messageData")
          .index("merkleRoot")
          .get(merkleRoot),
      );
      const progress = validateLayout(records);
      await tx.done;
      return {
        stored: false,
        ...progress,
      };
    } finally {
      db.close();
    }
  }

  // Validate the candidate manifest before touching OPFS. The worker dispatcher
  // holds the per-Merkle lock across this whole function, so the preflight view
  // cannot change before the committing transaction below.
  const preflightDb = await getDB();
  try {
    const tx = preflightDb.transaction(
      ["chunks", "messageData"],
      "readonly",
    );
    const records: Chunk[] = [];
    let cursor = await tx
      .objectStore("chunks")
      .index("merkleRoot")
      .openCursor(merkleRoot);
    while (cursor) {
      records.push(cursor.value);
      cursor = await cursor.continue();
    }
    assertManifest(
      await tx
        .objectStore("messageData")
        .index("merkleRoot")
        .get(merkleRoot),
    );
    validateLayout([...records, { chunkIndex, realLen }]);
    await tx.done;
  } finally {
    preflightDb.close();
  }

  // Write bytes to OPFS FIRST (durable), then record the have-set entry: if we
  // crash between the two we get bytes-without-record (resent + rewritten
  // idempotently) — never the corrupting record-without-bytes.
  let wroteToOPFS = false;
  if (storage === "opfs") {
    try {
      wroteToOPFS = await placeReceiveChunk(
        merkleRoot,
        chunkIndex,
        realLen,
        totalSize,
        data,
      );
    } catch (error) {
      console.error(error);
      wroteToOPFS = false;
    }
  }

  const record: Chunk = storage === "opfs" && wroteToOPFS
    ? { merkleRoot, hash, chunkIndex, mimeType, realLen, leafHash }
    : { merkleRoot, hash, chunkIndex, mimeType, realLen, leafHash, data };

  const db = await getDB();
  try {
    const tx = db.transaction(
      ["chunks", "messageData", "uniqueRoom"],
      "readwrite",
    );
    const store = tx.objectStore("chunks");
    const existing = await store.getKey([merkleRoot, chunkIndex]);
    let stored = false;
    const records: Chunk[] = [];
    let recordsCursor = await store.index("merkleRoot").openCursor(merkleRoot);
    while (recordsCursor) {
      records.push(recordsCursor.value);
      recordsCursor = await recordsCursor.continue();
    }
    if (existing === undefined) {
      validateLayout([...records, { chunkIndex, realLen }]);
      await store.add(record);
      records.push(record);
      stored = true;
    }

    const progress = validateLayout(records);

    if (stored) {
      const messageStore = tx.objectStore("messageData");
      const previous = await messageStore.index("merkleRoot").get(merkleRoot);
      assertManifest(previous);

      await messageStore.put({
        roomId,
        timestamp: previous?.timestamp ?? timestamp,
        merkleRoot,
        hash,
        fromPeerId,
        filename,
        messageType,
        savedSize: progress.savedSize,
        totalSize,
        channelLabel,
      });

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
    }

    await tx.done;
    return {
      stored,
      ...progress,
    };
  } finally {
    db.close();
  }
}

async function fnStoreReceiveChunk(
  chunk: ReceiveChunk,
): Promise<ReceiveChunkStoreResult> {
  return storeReceiveChunkLocked(chunk);
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

async function fnSetDBNewChunk(chunk: NewChunk): Promise<void> {
  const db = await getDB();
  try {
    await db.put("newChunks", chunk);
  } finally {
    db.close();
  }
}

async function fnSetDBSendQueue(item: SendQueue): Promise<void> {
  const db = await getDB();
  await db.put("sendQueue", item);
  db.close();
}

const ratchetRollbackGuard = new RatchetRollbackGuard();
const ratchetLastWrite = new Map<string, number>();
const ratchetWorkerLocks = new Map<string, Promise<void>>();

const ratchetWorkerKey = (
  roomId: string,
  peerPublicKey: string,
): string =>
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
  if (session.sendingChainKey)
    new Uint8Array(session.sendingChainKey).fill(0);
  if (session.receivingChainKey)
    new Uint8Array(session.receivingChainKey).fill(0);
  new Uint8Array(session.dhSelfSec).fill(0);
  for (const skipped of session.skippedMessageKeys)
    new Uint8Array(skipped.messageKey).fill(0);
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
        Math.max(
          ratchetLastWrite.get(edge) ?? 0,
          restored.updatedAt,
        ),
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
    )) as
      | PinAttemptState
      | undefined;
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
        : Math.min(
            baseMs * 2 ** (failures - maxImmediateAttempts),
            maxMs,
          );
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
      await db.delete(
        "meta",
        pinAttemptMetaId(roomId, peerIdentityEd25519),
      );
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
      | StoredIdentityX25519
      | undefined;
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
// secrets; the public half remains inspectable.
const IDENTITY_ED25519_META_ID = "identityEd25519";

async function fnGetIdentityEd25519(): Promise<IdentityEd25519 | undefined> {
  const db = await getDB();
  let stored: StoredIdentityEd25519 | undefined;
  try {
    stored = (await db.get("meta", IDENTITY_ED25519_META_ID)) as
      | StoredIdentityEd25519
      | undefined;
  } finally {
    db.close();
  }
  if (!stored) return undefined;
  if (stored.pub.byteLength !== 32)
    throw new Error("Stored Ed25519 public key has an invalid length");

  const key = await getWrapKey();
  const secret = await unwrapSecret(key, stored.wrappedSecret);
  if (secret.byteLength !== 64)
    throw new Error("Stored Ed25519 secret key has an invalid length");
  return { pub: stored.pub, secret };
}

async function fnSetIdentityEd25519(
  identity: IdentityEd25519,
): Promise<void> {
  if (identity.pub.byteLength !== 32 || identity.secret.byteLength !== 64)
    throw new Error("Ed25519 identity has invalid key lengths");

  const key = await getWrapKey();
  const wrappedSecret = await wrapSecret(key, identity.secret);
  const stored: StoredIdentityEd25519 = {
    pub: identity.pub,
    wrappedSecret,
  };
  const db = await getDB();
  try {
    await db.put("meta", stored, IDENTITY_ED25519_META_ID);
  } finally {
    db.close();
  }
}

async function fnDeleteIdentityEd25519(): Promise<void> {
  const db = await getDB();
  try {
    const tx = db.transaction(["meta", "ratchetSessions"], "readwrite");
    await tx.objectStore("meta").delete(IDENTITY_ED25519_META_ID);
    await tx.objectStore("ratchetSessions").clear();
    await tx.done;
  } finally {
    db.close();
  }
  ratchetRollbackGuard.clear();
  ratchetLastWrite.clear();
}

async function fnDeleteDBUniqueRoom(roomId: string): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction(
      ["uniqueRoom", "ratchetSessions"],
      "readwrite",
    );
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

    db.close();
  } catch {
    /* empty */
  }
}

async function fnDeleteDBChunk(
  hashHex: string,
  chunkIndex?: number,
): Promise<void> {
  try {
    const db = await getDB();
    const tx = db.transaction("chunks", "readwrite");
    const store = tx.objectStore("chunks");

    if (chunkIndex !== undefined) {
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
  } catch {
    /* empty */
  }
}

async function fnDeleteDBNewChunk(
  selector: NewChunkSelector,
): Promise<void> {
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

    // Drop any open receive write handle FIRST — removeEntry fails while the
    // exclusive sync-access-handle is held — then reclaim the OPFS file, which
    // IndexedDB deletion alone would leave as an orphaned full-size copy. Under
    // the per-merkleRoot lock so a chunk arriving mid-delete can't reopen the
    // handle between the close and the removeEntry (which would throw + leak).
    await withReceiveLock(merkleRootHex, async () => {
      await fnCloseReceiveFile(merkleRootHex);
      await fnDeleteOPFSFile(merkleRootHex);
    });
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
): Promise<void> {
  if (
    merkleRootHex.length !== crypto_hash_sha512_BYTES * 2 ||
    !/^[0-9a-f]+$/.test(merkleRootHex)
  )
    throw new Error("invalid receive transfer Merkle root");

  await fnCloseReceiveFile(merkleRootHex);

  const db = await getDB();
  try {
    const tx = db.transaction(
      ["chunks", "messageData", "uniqueRoom"],
      "readwrite",
    );
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
  } finally {
    db.close();
  }

  await fnDeleteOPFSFile(merkleRootHex);
}

async function fnDeleteDB(): Promise<void> {
  // Also remove the whole OPFS reassembly subtree (a separate storage system
  // that deleteDatabase cannot touch), so a full wipe reclaims that disk too.
  try {
    // Close every open receive handle first, or removeEntry(recursive) trips
    // over the still-held exclusive locks.
    await closeAllReceiveFiles();
    const storage = opfsStorage();
    if (storage && typeof storage.getDirectory === "function") {
      const root = await storage.getDirectory();
      await (
        root as unknown as {
          removeEntry: (
            name: string,
            opts: { recursive: boolean },
          ) => Promise<void>;
        }
      )
        .removeEntry(OPFS_REASSEMBLE_DIR, { recursive: true })
        .catch(() => {
          /* not present — fine */
        });
    }
  } catch {
    /* ignore */
  }

  await deleteDB(dbName, {
    blocked() {
      console.error("DB deletion BLOCKED");
    },
  });
  ratchetRollbackGuard.clear();
  ratchetLastWrite.clear();
}

onmessage = async (e: MessageEvent) => {
  const message = e.data as WorkerMessages;
  const { id, method } = message;
  try {
    let result: WorkerMethodReturnTypes[typeof method];
    switch (method) {
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
        const chunk = message.args[0];
        result = await withReceiveLock(chunk.merkleRoot, () =>
          fnStoreReceiveChunk(chunk),
        );
        break;
      }
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
      case "deleteReceiveTransfer":
        await withReceiveLock(message.args[0], () =>
          fnDeleteReceiveTransferLocked(...message.args),
        );
        result = undefined;
        break;
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
      case "deleteDBMessageData":
        await fnDeleteDBMessageData(...message.args);
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
        await fnSetIdentityEd25519(...message.args);
        result = undefined;
        break;
      case "deleteIdentityEd25519":
        await fnDeleteIdentityEd25519();
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

    postMessage({ id, result });
  } catch (error: unknown) {
    postMessage({ id, error: String(error) });
  }
};
