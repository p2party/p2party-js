import type { Peer } from "../reducers/roomSlice";
import type { RatchetRootSuite } from "../utils/constants";
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
  /** Canonical 32-byte public RoomPolicyV1 descriptor; absent on pre-v3 rows. */
  roomPolicy?: ArrayBuffer;
  messageCount: number;
  lastMessageMerkleRoot: string;
  createdAt: number;
  updatedAt: number;
}

export interface MessageData {
  /** Sender-only random logical-send identity; absent on received/legacy rows. */
  transferId?: string;
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
  /** Authenticated wire-metadata schema; protocol v3 accepts exactly v1. */
  schemaVersion: number;
  roomId: string;
  fromPeerId: string;
  channelLabel: string;
  timestamp: number;
  merkleRoot: string;
  hash: string;
  filename: string;
  messageType: number;
  chunkIndex: number;
  mimeType: string;
  leafHash: string;
  realLen: number;
  totalSize: number;
  data: ArrayBuffer;
  /** Text stays in IndexedDB; files use the OPFS-first receive path. */
  storage: "indexeddb" | "opfs";
}

export interface ReceiveChunkStoreResult {
  /** True only when this call inserted a previously absent chunk index. */
  stored: boolean;
  /** Sum of distinct committed realLen values for this Merkle root. */
  savedSize: number;
  /** Authoritative distinct-byte completion after this transaction. */
  complete: boolean;
}

// Lightweight projection of a stored chunk used by the reconnect re-emit — just
// the receipt token and its index, never the (potentially huge) chunk body.
export interface ChunkLeafHash {
  chunkIndex: number;
  leafHash?: string;
}

export interface NewChunk {
  /** Random 32-byte lowercase-hex identity of this logical outbound send. */
  transferId: string;
  hash: string;
  chunkIndex: number;
  merkleRoot: string;
  /** Domain-separated Merkle leaf hash SHA-512(0x00 || paddedChunk). */
  leafHash: string;
  /** SHA-512(receipt-domain || root || u64(index) || leafHash), once rooted. */
  receiptToken: string;
  data: ArrayBuffer;
  metadata: ArrayBuffer;
  merkleProof: ArrayBuffer;
}

export interface NewChunkSelector {
  transferId?: string;
  merkleRootHex?: string;
  hashHex?: string;
  chunkIndex?: number;
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
  /**
   * Mandatory identity-possession root: interactive 3DH + ML-KEM-768 in every
   * room, with draft-21 CPace ISK additionally mixed for PIN rooms.
   */
  rootSuite: RatchetRootSuite;
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
  /**
   * Protocol-v4 edge checkpoint. The plaintext API value is a bounded,
   * canonical snapshot containing the sparse-PQ machine, exact sealed control
   * outbox/replay cache, and epoch-bound active receive keys. ratchetWrap wraps
   * this whole blob as one variable-length secret field before it reaches disk.
   *
   * `null` exists only for store-free/legacy test fixtures. A live v4 edge
   * always persists a non-null checkpoint in the same row as the Double
   * Ratchet, so the two ratchets cannot cross a crash boundary independently.
   */
  edgeCryptoState: ArrayBuffer | null;
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

/** Ed25519 account identity at the worker API boundary. */
export interface IdentityEd25519 {
  pub: ArrayBuffer;
  secret: ArrayBuffer;
}

/** At-rest Ed25519 record (meta key "identityEd25519"). */
export interface StoredIdentityEd25519 {
  pub: ArrayBuffer;
  wrappedSecret: ArrayBuffer;
}

/** Non-secret online PIN-guess throttle state for one room/peer-identity edge. */
export interface PinAttemptState {
  failures: number;
  retryAfter: number;
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
      args: [roomUrl: string, roomId: string, roomPolicy: ArrayBuffer];
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
        transferId?: string,
      ];
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
      method: "getDBNewChunk";
      args: [transferId: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "getDBNewChunkByReceipt";
      args: [merkleRootHex: string, receiptTokenHex: string];
    }
  | {
      id: number;
      method: "existsDBNewChunk";
      args: [transferId: string, chunkIndex: number];
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
      method: "deleteReceiveTransfer";
      args: [merkleRootHex: string];
    }
  | {
      id: number;
      method: "getDBAllNewChunks";
      args: [selector: NewChunkSelector];
    }
  | {
      id: number;
      method: "getDBAllNewChunksCount";
      args: [transferId: string];
    }
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
      args: [selector: NewChunkSelector];
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
      method: "getPinAttemptState";
      args: [roomId: string, peerIdentityEd25519: string];
    }
  | {
      id: number;
      method: "incrementPinAttemptState";
      args: [
        roomId: string,
        peerIdentityEd25519: string,
        now: number,
        maxImmediateAttempts: number,
        baseMs: number,
        maxMs: number,
      ];
    }
  | {
      id: number;
      method: "deletePinAttemptState";
      args: [roomId: string, peerIdentityEd25519?: string];
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
      method: "getIdentityEd25519";
      args: [];
    }
  | {
      id: number;
      method: "setIdentityEd25519";
      args: [identity: IdentityEd25519];
    }
  | {
      id: number;
      method: "deleteIdentityEd25519";
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
  getDBNewChunkByReceipt: NewChunk | undefined;
  existsDBNewChunk: boolean;
  getDBSendQueue: SendQueue[];
  getDBAllChunks: Chunk[];
  getDBAllChunkLeafHashes: ChunkLeafHash[];
  assembleToOPFS: File | null;
  getDBAllChunksCount: number;
  setDBChunk: undefined;
  // true if the chunk was newly stored; false if it was already present (dedup).
  storeReceiveChunk: ReceiveChunkStoreResult;
  getReceiveFile: File | null;
  closeReceiveFile: undefined;
  deleteReceiveTransfer: undefined;
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
  getPinAttemptState: PinAttemptState | undefined;
  incrementPinAttemptState: PinAttemptState;
  deletePinAttemptState: undefined;
  getIdentityX25519: IdentityX25519 | undefined;
  setIdentityX25519: undefined;
  deleteIdentityX25519: undefined;
  getIdentityEd25519: IdentityEd25519 | undefined;
  setIdentityEd25519: undefined;
  deleteIdentityEd25519: undefined;
  deleteDB: undefined;
}
