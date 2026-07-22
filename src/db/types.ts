import type { Peer } from "../reducers/roomSlice";
// import type { MessageType } from "../utils/messageTypes";

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

export interface UniqueRoom {
  roomUrl: string;
  roomId: string;
  messageCount: number;
  lastMessageMerkleRoot: string;
  createdAt: number;
  updatedAt: number;
}

export interface MessageData {
  roomId: string;
  timestamp: number;
  fromPeerId: string;
  channelLabel: string;
  hash: string;
  merkleRoot: string;
  filename: string;
  messageType: number; // MessageType;
  savedSize: number;
  totalSize: number;
  // recipients: number;
}

export interface Chunk {
  merkleRoot: string;
  hash: string;
  chunkIndex: number;
  // The real chunk bytes. OPTIONAL on the receiver: a received FILE chunk is
  // written straight into its pre-sized OPFS file at chunkIndex*uniformSize as it
  // arrives, and only its leaf-hash is kept here (the have-set), so `data` is
  // absent. It IS present for (a) the sender's self-copy, (b) received TEXT
  // chunks, and (c) the <=1 receiver "straggler" chunk that arrived before
  // uniformSize was known (kept in IndexedDB until getReceiveFile migrates it
  // into OPFS). Invariant: a receiver have-set record with NO `data` means its
  // bytes are durably in OPFS — so the have-set is always a subset of the bytes
  // actually on disk, which is what makes crash/reload resume safe.
  data?: ArrayBuffer;
  mimeType: string;
  // Real byte length of this chunk (chunkEndIndex - chunkStartIndex). Persisted
  // on the receiver so uniformSize = max(realLen) is recomputable at any time
  // (e.g. at read-time migration), even from bytesless records. Absent on old
  // rows and on the sender's self-copy.
  realLen?: number;
  // The domain-separated leaf hash SHA-512(0x00 || chunk) hex — the exact
  // read-receipt token this chunk drew. Persisted (receiver only) so it can be
  // re-emitted on reconnect without re-hashing (the padded chunk it was hashed
  // over is discarded; only the real slice is stored). Optional: the sender's
  // self-copy has no receipt token, and pre-existing rows predate this field.
  leafHash?: string;
}

// Input to the receive-time OPFS write path. Carries the real chunk bytes plus
// everything the worker needs to (a) place them at chunkIndex*uniformSize in the
// pre-sized OPFS file and (b) persist the bytesless have-set record.
export interface ReceiveChunk {
  merkleRoot: string;
  hash: string;
  chunkIndex: number;
  mimeType: string;
  leafHash: string;
  realLen: number;
  totalSize: number;
  data: ArrayBuffer;
}

// Lightweight projection of a stored chunk used by the reconnect re-emit — just
// the receipt token and its index, never the (potentially huge) chunk body.
export interface ChunkLeafHash {
  chunkIndex: number;
  leafHash?: string;
}

export interface NewChunk {
  hash: string;
  chunkIndex: number;
  merkleRoot: string;
  realChunkHash: string;
  data: ArrayBuffer;
  metadata: ArrayBuffer;
  merkleProof: ArrayBuffer;
}

export interface SendQueue {
  position: number;
  label: string;
  toPeerId: string;
  encryptedData: ArrayBuffer;
}

// One Double-Ratchet session per STABLE identity edge (roomId, peerPublicKey) —
// not per per-session peerId, which changes on reconnect — so the ratchet
// survives reconnect/reload. All secret fields (rootKey, both chain keys,
// dhSelfSec, and each skipped messageKey) are stored WRAPPED (AES-GCM under the
// non-extractable CryptoKey in the `meta` store); public/counter fields are
// stored plaintext. See src/db/ratchetWrap.ts.
export interface RatchetSession {
  roomId: string;
  peerPublicKey: string;
  peerId: string;
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer | null;
  receivingChainKey: ArrayBuffer | null;
  dhSelfPub: ArrayBuffer;
  dhSelfSec: ArrayBuffer;
  dhRemotePub: ArrayBuffer | null;
  Ns: number;
  Nr: number;
  PN: number;
  skippedMessageKeys: Array<{
    dhPub: ArrayBuffer;
    n: number;
    messageKey: ArrayBuffer;
  }>; // capped at MAX_SKIP_SESSION (total, evict-oldest) by the ratchet layer (Stage 2)
  updatedAt: number;
}

// The dedicated X25519 identity keypair (D2=B). `secret` is plaintext at the api
// boundary; it is WebCrypto-wrapped (getWrapKey/wrapSecret) before it touches disk.
export interface IdentityX25519 {
  pub: ArrayBuffer;
  secret: ArrayBuffer;
  crossSig: ArrayBuffer;
}

// The at-rest shape in the `meta` store (key "identityX25519"): the secret is the
// wrapped iv‖ciphertext blob; pub + crossSig are public and stored in the clear.
export interface StoredIdentityX25519 {
  pub: ArrayBuffer;
  wrappedSecret: ArrayBuffer;
  crossSig: ArrayBuffer;
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
      method: "getAllDBUniqueRooms";
      args: [];
    }
  | {
      id: number;
      method: "setDBUniqueRoom";
      args: [roomUrl: string, roomId: string];
    }
  | {
      id: number;
      method: "deleteDBPeerFromBlacklist";
      args: [peerId?: string, peerPublicKey?: string];
    }
  | {
      id: number;
      method: "getDBMessageData";
      args: [merkleRootHex?: string, hashHex?: string];
    }
  | {
      id: number;
      method: "getDBRoomMessageData";
      args: [roomId: string];
    }
  | {
      id: number;
      method: "setDBRoomMessageData";
      args: [
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
      ];
    }
  | {
      id: number;
      method: "getDBChunk";
      args: [hashHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "existsDBChunk";
      args: [hashHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "getDBNewChunk";
      args: [hashHex: string, chunkIndex?: number];
    }
  | {
      id: number;
      method: "existsDBNewChunk";
      args: [hashHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "getDBSendQueue";
      args: [label: string, toPeerId: string, position?: number];
    }
  | {
      id: number;
      method: "getDBAllChunks";
      args: [merkleRootHex?: string, hashHex?: string];
    }
  | {
      id: number;
      method: "getDBAllChunkLeafHashes";
      args: [merkleRootHex: string];
    }
  | {
      id: number;
      method: "assembleToOPFS";
      args: [
        merkleRootHex: string,
        totalSize: number,
        filename: string,
        mimeType: string,
      ];
    }
  | {
      id: number;
      method: "getDBAllChunksCount";
      args: [merkleRootHex?: string, hashHex?: string];
    }
  | { id: number; method: "setDBChunk"; args: [chunk: Chunk] }
  | {
      id: number;
      method: "storeReceiveChunk";
      args: [chunk: ReceiveChunk];
    }
  | {
      id: number;
      method: "getReceiveFile";
      args: [
        merkleRootHex: string,
        totalSize: number,
        filename: string,
        mimeType: string,
      ];
    }
  | { id: number; method: "closeReceiveFile"; args: [merkleRootHex: string] }
  | {
      id: number;
      method: "getDBAllNewChunks";
      args: [hashHex?: string, merkleRootHex?: string];
    }
  | { id: number; method: "getDBAllNewChunksCount"; args: [hashHex: string] }
  | { id: number; method: "setDBNewChunk"; args: [chunk: NewChunk] }
  | { id: number; method: "setDBSendQueue"; args: [item: SendQueue] }
  | {
      id: number;
      method: "countDBSendQueue";
      args: [label: string, toPeerId: string];
    }
  | {
      id: number;
      method: "deleteDBChunk";
      args: [hashHex: string, chunkIndex?: number];
    }
  | {
      id: number;
      method: "deleteDBNewChunk";
      args: [
        merkleRootHex?: string,
        realChunkHashHex?: string,
        hashHex?: string,
        chunkIndex?: number,
      ];
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
      method: "deleteDBUniqueRoom";
      args: [roomId: string];
    }
  | {
      id: number;
      method: "getRatchetSession";
      args: [roomId: string, peerPublicKey: string];
    }
  | {
      id: number;
      method: "setRatchetSession";
      args: [session: RatchetSession];
    }
  | {
      id: number;
      method: "deleteRatchetSession";
      args: [roomId: string, peerPublicKey: string];
    }
  | {
      id: number;
      method: "getIdentityX25519";
      args: [];
    }
  | {
      id: number;
      method: "setIdentityX25519";
      args: [identity: IdentityX25519];
    }
  | {
      id: number;
      method: "deleteIdentityX25519";
      args: [];
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
  setDBAddressBookEntry: undefined;
  deleteDBAddressBookEntry: string;
  getDBPeerIsBlacklisted: boolean;
  getAllDBBlacklisted: BlacklistedPeer[];
  setDBPeerInBlacklist: undefined;
  getAllDBUniqueRooms: UniqueRoom[];
  setDBUniqueRoom: undefined;
  deleteDBPeerFromBlacklist: undefined;
  getDBMessageData: MessageData | undefined;
  getDBRoomMessageData: MessageData[];
  getDBChunk: ArrayBuffer | undefined;
  existsDBChunk: boolean;
  getDBNewChunk: NewChunk | undefined;
  existsDBNewChunk: boolean;
  getDBSendQueue: SendQueue[];
  getDBAllChunks: Chunk[];
  getDBAllChunkLeafHashes: ChunkLeafHash[];
  assembleToOPFS: File | null;
  getDBAllChunksCount: number;
  setDBChunk: undefined;
  // true if the chunk was newly stored; false if it was already present (dedup).
  storeReceiveChunk: boolean;
  getReceiveFile: File | null;
  closeReceiveFile: undefined;
  getDBAllNewChunks: NewChunk[];
  getDBAllNewChunksCount: number;
  setDBNewChunk: undefined;
  setDBRoomMessageData: undefined;
  setDBSendQueue: undefined;
  countDBSendQueue: number;
  deleteDBChunk: undefined;
  deleteDBNewChunk: undefined;
  deleteDBMessageData: undefined;
  deleteDBSendQueue: undefined;
  deleteDBUniqueRoom: undefined;
  getRatchetSession: RatchetSession | undefined;
  setRatchetSession: undefined;
  deleteRatchetSession: undefined;
  getIdentityX25519: IdentityX25519 | undefined;
  setIdentityX25519: undefined;
  deleteIdentityX25519: undefined;
  deleteDB: undefined;
}
