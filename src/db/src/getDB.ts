import type {
  OutboxManifest,
  OutboxAckRecord,
  ReceiveActivity,
} from "../outboxTypes";
import { openDB, unwrap } from "idb";
import { isCanonicalEd25519Identity } from "../../utils/identityRole";

import { DatabaseUpgradeBlockedError } from "../dbErrors";

import type { DBSchema, IDBPDatabase } from "idb";
import type {
  MessageData,
  Chunk,
  SendQueue,
  AddressBook,
  BlacklistedPeer,
  UniqueRoom,
  NewChunk,
  RatchetSession,
  StoredIdentityX25519,
  StoredIdentityEd25519,
  StoredIdentityEd25519Revision,
  StoredIdentityDerivation,
  PinAttemptState,
} from "../types";

export const dbName = "p2party";
export const dbVersion = 23;

export interface RepoSchema extends DBSchema {
  outbox: {
    value: OutboxManifest;
    key: string;
    indexes: { senderPublicKey: string; roomId: string; expiresAt: number };
  };
  outboxTrees: {
    value: { transferId: string; chunkHashes: ArrayBuffer };
    key: string;
  };
  outboxAcks: {
    value: OutboxAckRecord;
    key: [string, string];
    indexes: { transferId: string };
  };
  receiveActivity: {
    value: ReceiveActivity;
    key: string;
    indexes: { lastActivityAt: number };
  };
  addressBook: {
    value: AddressBook;
    key: string;
  };
  blacklist: {
    value: BlacklistedPeer;
    key: string;
  };
  uniqueRoom: {
    value: UniqueRoom;
    key: [string];
    indexes: { roomId: string; roomUrl: string };
  };
  messageData: {
    value: MessageData;
    key: [number, string, string];
    indexes: {
      roomId: string;
      hash: string;
      merkleRoot: string;
      fromPeerId: string;
    };
  };
  chunks: {
    value: Chunk;
    key: [string, number];
    indexes: { merkleRoot: string; hash: string };
  };
  newChunks: {
    value: NewChunk & { accountedBytes?: number };
    key: [string, number];
    indexes: {
      transferId: string;
      hash: string;
      merkleRoot: string;
      receiptScope: [string, string];
      stagedSize: [string, number, number];
    };
  };
  sendQueue: {
    value: SendQueue;
    key: [number, string, string];
    indexes: { labelPeer: string };
  };
  ratchetSessions: {
    value: RatchetSession;
    key: [string, string];
    indexes: { peerId: string; peerPublicKey: string; roomId: string };
  };
  // Out-of-line store for the single non-extractable AES-GCM wrap CryptoKey
  // (key = "ratchetWrapKey"). Value is a live CryptoKey object (structured-
  // cloneable, never its raw bytes).
  meta: {
    value:
      | CryptoKey
      | StoredIdentityX25519
      | StoredIdentityEd25519
      | StoredIdentityEd25519Revision
      | StoredIdentityDerivation
      | PinAttemptState;
    key: string;
  };
}

// Opens that have not settled yet. When one of them is blocked by an older
// tab, IndexedDB queues every other open behind it, so all of them fail at
// once rather than only the one that saw `blocked`.
interface UnsettledOpen {
  readonly reject: (error: DatabaseUpgradeBlockedError) => void;
  /** Failed as blocked, and counted in blockedOpensPending. */
  counted: boolean;
}
const unsettledOpens = new Set<UnsettledOpen>();
// Opens that failed as blocked but are still queued in IndexedDB. Each is
// counted the moment `blocked` fires, so an open requested before their
// rejections have landed fails at once too; each is closed when it finally
// succeeds. Until the last has, new opens fail at once.
let blockedOpensPending = 0;

/**
 * Open the database. The connection closes itself when another context asks
 * to upgrade, so a newer tab is never blocked by this one. When this version's
 * own upgrade is blocked by an older tab that keeps its connection open, the
 * open rejects with DatabaseUpgradeBlockedError instead of waiting.
 */
export async function getDB(): Promise<IDBPDatabase<RepoSchema>> {
  if (blockedOpensPending > 0) throw new DatabaseUpgradeBlockedError();
  let rejectBlocked!: (error: DatabaseUpgradeBlockedError) => void;
  const blocked = new Promise<never>((_resolve, reject) => {
    rejectBlocked = reject;
  });
  const pending: UnsettledOpen = { reject: rejectBlocked, counted: false };
  unsettledOpens.add(pending);
  const opening = openDB<RepoSchema>(dbName, dbVersion, {
    blocked() {
      for (const open of unsettledOpens) {
        if (open.counted) continue;
        open.counted = true;
        blockedOpensPending += 1;
        open.reject(new DatabaseUpgradeBlockedError());
      }
    },
    blocking(_currentVersion, _blockedVersion, event) {
      (event.target as IDBDatabase).close();
    },
    upgrade(db, oldVersion, _newVersion, tx) {
      if (!db.objectStoreNames.contains("outbox")) {
        const outbox = db.createObjectStore("outbox", {
          keyPath: "transferId",
        });
        outbox.createIndex("senderPublicKey", "senderPublicKey");
        outbox.createIndex("roomId", "roomId");
        outbox.createIndex("expiresAt", "expiresAt");
        db.createObjectStore("outboxTrees", { keyPath: "transferId" });
        const acks = db.createObjectStore("outboxAcks", {
          keyPath: ["transferId", "publicKey"],
        });
        acks.createIndex("transferId", "transferId");
        const activity = db.createObjectStore("receiveActivity", {
          keyPath: "merkleRoot",
        });
        activity.createIndex("lastActivityAt", "lastActivityAt");
      }
      // Keep the old store available to its cursor until every row has moved.
      // Store creation, copying, and deletion share one versionchange transaction.
      if (oldVersion < 23) {
        const database = unwrap(db);
        for (const name of ["addressBook", "blacklist"]) {
          const legacy = database.objectStoreNames.contains(name)
            ? unwrap(tx).objectStore(name)
            : undefined;
          if (legacy) legacy.name = `${name}Before23`;
          const target = database.createObjectStore(name, {
            keyPath: "peerPublicKey",
          });
          if (!legacy) continue;
          let invalid = 0;
          const request = legacy.openCursor();
          request.onsuccess = () => {
            const cursor = request.result;
            if (!cursor) {
              database.deleteObjectStore(legacy.name);
              if (invalid)
                console.debug(
                  `p2party: ${name} upgrade skipped ${String(invalid)} rows without a usable identity key`,
                );
              return;
            }
            const row = cursor.value as AddressBook | BlacklistedPeer;
            const key =
              typeof row.peerPublicKey === "string"
                ? row.peerPublicKey.toLowerCase()
                : undefined;
            if (isCanonicalEd25519Identity(key))
              target.put({ ...row, peerPublicKey: key });
            else invalid++;
            cursor.continue();
          };
        }
      }

      if (!db.objectStoreNames.contains("uniqueRoom")) {
        const uniqueRoom = db.createObjectStore("uniqueRoom", {
          keyPath: ["roomId"],
        });
        uniqueRoom.createIndex("roomUrl", "roomUrl", { unique: true });
        uniqueRoom.createIndex("roomId", "roomId", { unique: true });
      } else {
        const store = tx.objectStore("uniqueRoom");

        if (!store.indexNames.contains("roomUrl")) {
          store.createIndex("roomUrl", "roomUrl", { unique: true });
        }

        if (!store.indexNames.contains("roomId")) {
          store.createIndex("roomId", "roomId", { unique: true });
        }
      }

      if (!db.objectStoreNames.contains("messageData")) {
        const messageData = db.createObjectStore("messageData", {
          keyPath: ["timestamp", "roomId", "merkleRoot"],
        });
        messageData.createIndex("roomId", "roomId", { unique: false });
        messageData.createIndex("hash", "hash", { unique: false });
        messageData.createIndex("merkleRoot", "merkleRoot", { unique: true });
        messageData.createIndex("fromPeerId", "fromPeerId", { unique: false });
      } else {
        const store = tx.objectStore("messageData");

        if (!store.indexNames.contains("roomId")) {
          store.createIndex("roomId", "roomId", { unique: false });
        }

        if (!store.indexNames.contains("hash")) {
          store.createIndex("hash", "hash", { unique: false });
        }

        if (!store.indexNames.contains("merkleRoot")) {
          store.createIndex("merkleRoot", "merkleRoot", { unique: true });
        }

        if (!store.indexNames.contains("fromPeerId")) {
          store.createIndex("fromPeerId", "fromPeerId", { unique: false });
        }
      }

      if (!db.objectStoreNames.contains("chunks")) {
        const chunks = db.createObjectStore("chunks", {
          keyPath: ["merkleRoot", "chunkIndex"],
        });
        chunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
        chunks.createIndex("hash", "hash", { unique: false });
      } else {
        const store = tx.objectStore("chunks");

        if (!store.indexNames.contains("merkleRoot")) {
          store.createIndex("merkleRoot", "merkleRoot", { unique: false });
        }

        if (!store.indexNames.contains("hash")) {
          store.createIndex("hash", "hash", { unique: false });
        }
      }

      // v18 changes the outbound staging identity from content hash to a random
      // per-send transferId. Old rows cannot be mapped unambiguously when two
      // identical sends overlap, so recreate ONLY this outbound/transient
      // store. Received chunks, messages, rooms, and ratchets remain intact.
      if (oldVersion < 18 && db.objectStoreNames.contains("newChunks"))
        db.deleteObjectStore("newChunks");

      if (!db.objectStoreNames.contains("newChunks")) {
        const newChunks = db.createObjectStore("newChunks", {
          keyPath: ["transferId", "chunkIndex"],
        });
        newChunks.createIndex("transferId", "transferId", { unique: false });
        newChunks.createIndex("hash", "hash", { unique: false });
        newChunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
        newChunks.createIndex("receiptScope", ["merkleRoot", "receiptToken"], {
          unique: false,
        });
      } else {
        const store = tx.objectStore("newChunks");

        if (!store.indexNames.contains("transferId")) {
          store.createIndex("transferId", "transferId", { unique: false });
        }

        if (!store.indexNames.contains("hash")) {
          store.createIndex("hash", "hash", { unique: false });
        }

        if (!store.indexNames.contains("merkleRoot")) {
          store.createIndex("merkleRoot", "merkleRoot", { unique: false });
        }

        if (!store.indexNames.contains("receiptScope")) {
          store.createIndex("receiptScope", ["merkleRoot", "receiptToken"], {
            unique: false,
          });
        }
      }

      const staged = tx.objectStore("newChunks");
      if (!staged.indexNames.contains("stagedSize"))
        staged.createIndex("stagedSize", [
          "transferId",
          "chunkIndex",
          "accountedBytes",
        ]);

      if (!db.objectStoreNames.contains("sendQueue")) {
        const sendQueue = db.createObjectStore("sendQueue", {
          keyPath: ["position", "label", "toPeerId"],
        });
        sendQueue.createIndex("labelPeer", ["label", "toPeerId"], {
          unique: false,
        });
      } else {
        const store = tx.objectStore("sendQueue");

        if (!store.indexNames.contains("labelPeer")) {
          store.createIndex("labelPeer", ["label", "toPeerId"], {
            unique: false,
          });
        }
      }

      if (!db.objectStoreNames.contains("ratchetSessions")) {
        const ratchetSessions = db.createObjectStore("ratchetSessions", {
          keyPath: ["roomId", "peerPublicKey"],
        });
        ratchetSessions.createIndex("peerId", "peerId", { unique: false });
        ratchetSessions.createIndex("peerPublicKey", "peerPublicKey", {
          unique: false,
        });
        ratchetSessions.createIndex("roomId", "roomId", { unique: false });
      }

      // Protocol v4 changes the authenticated wire epoch, handshake domains,
      // root-suite provenance, and the at-rest edge row by adding one atomic
      // PQ/outbox checkpoint. A v3 ratchet must never be interpreted as a v4
      // root. Both stores are cryptographic/transient state, so discard them
      // while preserving rooms, message history, and received chunks.
      if (oldVersion > 0 && oldVersion < 20) {
        // Old staging had no durable manifest/owner and could never resume after
        // reload. Preserve received history while retiring those orphan bytes.
        void tx.objectStore("newChunks").clear();
        const migrationTime = Date.now();
        const seedActivity = async () => {
          let cursor = await tx.objectStore("messageData").openCursor();
          while (cursor) {
            const message = cursor.value;
            if (
              message.transferId === undefined &&
              message.savedSize < message.totalSize
            )
              await tx.objectStore("receiveActivity").put({
                merkleRoot: message.merkleRoot,
                roomId: message.roomId,
                fromPeerId: message.fromPeerId,
                lastActivityAt: migrationTime,
              });
            cursor = await cursor.continue();
          }
        };
        void seedActivity();
      }
      if (oldVersion > 0 && oldVersion < 19) {
        tx.objectStore("ratchetSessions").clear();
        tx.objectStore("sendQueue").clear();
      }
      // v21 wraps ratchet rows in envelope version 3. A row in an older form
      // is refused before anything is decrypted, but would stay on disk until
      // its edge persists again, or forever for a peer who never returns.
      // Clear them at upgrade; each edge re-handshakes once.
      if (oldVersion > 0 && oldVersion < 21)
        tx.objectStore("ratchetSessions").clear();

      if (!db.objectStoreNames.contains("meta")) {
        db.createObjectStore("meta");
      } else if (oldVersion > 0 && oldVersion < 22) {
        // All prior PIN counters and authenticated-peer exemptions were keyed
        // by server-assigned room ID. Start v5 with locator-keyed records.
        const pinRows = tx.objectStore("meta");
        const range = IDBKeyRange.bound(
          "pinAttempts:",
          "pinAttempts;",
          false,
          true,
        );
        void pinRows.getAllKeys(range).then((keys) => {
          for (const key of keys) {
            if (typeof key !== "string") continue;
            const scope =
              /^pinAttempts:v2:(\d+):((?:pin-room-window:|pin-known-peers:)?[0-9a-f]{128}):[0-9a-f]{64}$/.exec(
                key,
              );
            if (!scope || Number(scope[1]) !== scope[2].length)
              void pinRows.delete(key);
          }
        });
      }
    },
  });
  let db: IDBPDatabase<RepoSchema>;
  try {
    db = await Promise.race([opening, blocked]);
  } catch (error) {
    if (pending.counted)
      void opening
        .then(
          (late) => late.close(),
          () => undefined,
        )
        .finally(() => {
          blockedOpensPending -= 1;
        });
    throw error;
  } finally {
    unsettledOpens.delete(pending);
  }
  // Opened before another open's `blocked` counted it: not pending after all.
  if (pending.counted) blockedOpensPending -= 1;
  return db;
}
