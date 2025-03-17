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
} from "../types";

export const dbName = "p2party";
export const dbVersion = 11;

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
    indexes: { merkleRoot: string };
  };
  newChunks: {
    value: NewChunk;
    key: [string, number];
    indexes: { hash: string; merkleRoot: string; realChunkHash: string };
  };
  sendQueue: {
    value: SendQueue;
    key: [number, string, string];
    indexes: { labelPeer: string };
  };
}

export async function getDB(): Promise<IDBPDatabase<RepoSchema>> {
  return openDB<RepoSchema>(dbName, dbVersion, {
    upgrade(db, _oldVersion, _newVersion, tx) {
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
      } else {
        const store = tx.objectStore("chunks");

        if (!store.indexNames.contains("merkleRoot")) {
          store.createIndex("merkleRoot", "merkleRoot", { unique: false });
        }
      }

      if (!db.objectStoreNames.contains("newChunks")) {
        const newChunks = db.createObjectStore("newChunks", {
          keyPath: ["hash", "chunkIndex"],
        });
        newChunks.createIndex("hash", "hash", { unique: false });
        newChunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
        newChunks.createIndex("realChunkHash", "realChunkHash", {
          unique: true,
        });
      } else {
        const store = tx.objectStore("newChunks");

        if (!store.indexNames.contains("hash")) {
          store.createIndex("hash", "hash", { unique: false });
        }

        if (!store.indexNames.contains("merkleRoot")) {
          store.createIndex("merkleRoot", "merkleRoot", { unique: false });
        }

        if (!store.indexNames.contains("realChunkHash")) {
          store.createIndex("realChunkHash", "realChunkHash", {
            unique: true,
          });
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
    },
  });
}
