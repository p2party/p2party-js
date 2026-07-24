import { openDB } from "idb";

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
  PinAttemptState,
} from "../types";

export const dbName = "p2party";
export const dbVersion = 19;

export interface RepoSchema extends DBSchema {
  addressBook: {
    value: AddressBook;
    key: [string];
    indexes: { peerId: string; peerPublicKey: string; username: string };
  };
  blacklist: {
    value: BlacklistedPeer;
    key: [string];
    indexes: { peerId: string; peerPublicKey: string; username: string };
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
    value: NewChunk;
    key: [string, number];
    indexes: {
      transferId: string;
      hash: string;
      merkleRoot: string;
      receiptScope: [string, string];
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
      | PinAttemptState;
    key: string;
  };
}

export async function getDB(): Promise<IDBPDatabase<RepoSchema>> {
  return openDB<RepoSchema>(dbName, dbVersion, {
    upgrade(db, oldVersion, _newVersion, tx) {
      if (!db.objectStoreNames.contains("addressBook")) {
        const addressBook = db.createObjectStore("addressBook", {
          keyPath: ["peerId"],
        });
        addressBook.createIndex("username", "username", { unique: false });
        addressBook.createIndex("peerId", "peerId", { unique: true });
        addressBook.createIndex("peerPublicKey", "peerPublicKey", {
          unique: true,
        });
      } else {
        const store = tx.objectStore("addressBook");

        if (!store.indexNames.contains("username")) {
          store.createIndex("username", "username", { unique: false });
        }

        if (!store.indexNames.contains("peerId")) {
          store.createIndex("peerId", "peerId", { unique: true });
        }

        if (!store.indexNames.contains("peerPublicKey")) {
          store.createIndex("peerPublicKey", "peerPublicKey", {
            unique: true,
          });
        }
      }

      if (!db.objectStoreNames.contains("blacklist")) {
        const blacklist = db.createObjectStore("blacklist", {
          keyPath: ["peerId"],
        });
        blacklist.createIndex("username", "username", { unique: false });
        blacklist.createIndex("peerId", "peerId", { unique: true });
        blacklist.createIndex("peerPublicKey", "peerPublicKey", {
          unique: true,
        });
      } else {
        const store = tx.objectStore("blacklist");

        if (!store.indexNames.contains("username")) {
          store.createIndex("username", "username", { unique: false });
        }

        if (!store.indexNames.contains("peerId")) {
          store.createIndex("peerId", "peerId", { unique: true });
        }

        if (!store.indexNames.contains("peerPublicKey")) {
          store.createIndex("peerPublicKey", "peerPublicKey", {
            unique: true,
          });
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
        newChunks.createIndex(
          "receiptScope",
          ["merkleRoot", "receiptToken"],
          {
            unique: false,
          },
        );
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
          store.createIndex(
            "receiptScope",
            ["merkleRoot", "receiptToken"],
            {
              unique: false,
            },
          );
        }
      }

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
      if (oldVersion > 0 && oldVersion < 19) {
        tx.objectStore("ratchetSessions").clear();
        tx.objectStore("sendQueue").clear();
      }

      if (!db.objectStoreNames.contains("meta")) {
        db.createObjectStore("meta");
      }
    },
  });
}
