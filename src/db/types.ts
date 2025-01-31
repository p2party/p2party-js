import type { Peer, SetMessageAllChunksArgs } from "../reducers/roomSlice";
import type { MessageType } from "../utils/messageTypes";

export interface UsernamedPeer extends Peer {
  username: string;
}

export interface AddressBook extends UsernamedPeer {
  dateAdded: number;
  challenge?: string;
  signature?: string;
}

export interface BlacklistedPeer extends Peer {
  dateAdded: number;
}

export interface MessageData {
  roomId: string;
  timestamp: number;
  fromPeedId: string;
  channelLabel: string;
  hash: string;
  merkleRoot: string;
  filename: string;
  messageType: MessageType;
  totalSize: number;
}

export interface Chunk {
  merkleRoot: string;
  chunkIndex: number;
  data: ArrayBuffer;
  mimeType: string;
}

export interface SendQueue {
  position: number;
  label: string;
  toPeerId: string;
  encryptedData: ArrayBuffer;
}

// Each method and its arguments/return type
export type WorkerMessages =
  | {
      id: number;
      method: "getDBAddressBookEntry";
      args: [peerId?: string, peerPublicKey?: string];
    }
  | {
      id: number;
      method: "getAllDBAddressBookEntries";
      args: [];
    }
  | {
      id: number;
      method: "setDBAddressBookEntry";
      args: [username: string, peerId: string, peerPublicKey: string];
    }
  | {
      id: number;
      method: "deleteDBAddressBookEntry";
      args: [username?: string, peerId?: string, peerPublicKey?: string];
    }
  | {
      id: number;
      method: "getDBPeerIsBlacklisted";
      args: [peerId?: string, peerPublicKey?: string];
    }
  | {
      id: number;
      method: "getAllDBBlacklisted";
      args: [];
    }
  | {
      id: number;
      method: "setDBPeerInBlacklist";
      args: [peerId: string, peerPublicKey: string];
    }
  | {
      id: number;
      method: "deleteDBPeerFromBlacklist";
      args: [peerId?: string, peerPublicKey?: string];
    }
  | {
      id: number;
      method: "getDBRoomMessageData";
      args: [roomId: string];
    }
  | {
      id: number;
      method: "setDBRoomMessageData";
      args: [roomId: string, message: SetMessageAllChunksArgs];
    }
  | {
      id: number;
      method: "getDBChunk";
      args: [merkleRootHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "existsDBChunk";
      args: [merkleRootHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "getDBSendQueue";
      args: [label: string, toPeerId: string, position?: number];
    }
  | { id: number; method: "getDBAllChunks"; args: [merkleRootHex: string] }
  | { id: number; method: "getDBAllChunksCount"; args: [merkleRootHex: string] }
  | { id: number; method: "setDBChunk"; args: [chunk: Chunk] }
  | { id: number; method: "setDBSendQueue"; args: [item: SendQueue] }
  | {
      id: number;
      method: "countDBSendQueue";
      args: [label: string, toPeerId: string];
    }
  | {
      id: number;
      method: "deleteDBChunk";
      args: [merkleRootHex: string, chunkIndex?: number];
    }
  | {
      id: number;
      method: "deleteDBMessageData";
      args: [merkleRootHex: string];
    }
  | {
      id: number;
      method: "deleteDBSendQueue";
      args: [label: string, toPeerId: string, position?: number];
    }
  | {
      id: number;
      method: "deleteDB";
      args: [];
    };

// Return types for each method
export interface WorkerMethodReturnTypes {
  getDBAddressBookEntry: UsernamedPeer | undefined;
  getAllDBAddressBookEntries: UsernamedPeer[];
  setDBAddressBookEntry: void;
  deleteDBAddressBookEntry: string;
  getDBPeerIsBlacklisted: boolean;
  getAllDBBlacklisted: BlacklistedPeer[];
  setDBPeerInBlacklist: void;
  deleteDBPeerFromBlacklist: void;
  getDBRoomMessageData: SetMessageAllChunksArgs[];
  getDBChunk: Blob | undefined;
  existsDBChunk: boolean;
  getDBSendQueue: SendQueue[];
  getDBAllChunks: Chunk[];
  getDBAllChunksCount: number;
  setDBRoomMessageData: void;
  setDBChunk: void;
  setDBSendQueue: void;
  countDBSendQueue: number;
  deleteDBChunk: void;
  deleteDBMessageData: void;
  deleteDBSendQueue: void;
  deleteDB: void;
}
