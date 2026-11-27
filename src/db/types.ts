import type { OutboxLease, OutboxRequest, OutboxResponse } from "./outboxTypes";
import type { Peer } from "../reducers/roomSlice";
import type { RatchetRootSuite } from "../utils/constants";
import type { ReceiveManifest } from "./receiveManifest";
import type { SerializedError } from "./dbErrors";
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

export interface RoomMembershipAuthority {
  signalingServerUrl: string;
  membershipPublicKey: string;
}

export interface UniqueRoom {
  /** Signaling server that authenticated this room membership. */
  signalingServerUrl?: string;
  membershipPublicKey?: string;
  onlyConnectWithKnownPeers?: boolean;
  roomUrl: string;
  roomId: string;
  /** Canonical 32-byte public RoomPolicyV1 descriptor; absent on pre-v3 rows. */
  roomPolicy?: ArrayBuffer;
  messageCount: number;
  lastMessageMerkleRoot: string;
  createdAt: number;
  updatedAt: number;
}

/**
 * Aggregate history for one saved room, computed inside the database worker.
 *
 * Sizes are logical message bytes, not wire bytes: p2party pads everything to
 * uniform 65,490-byte cells, so what actually crossed the network is always
 * larger and is a property of the padding policy rather than of the
 * conversation. Reporting the padded figure would describe the cover traffic,
 * not what the user sent.
 */
export interface RoomStats {
  messageCount: number;
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  bytesTotal: number;
  /** Distinct peers this device has received from, ever. */
  peerIds: string[];
}

export interface MessageData {
  /** Sender-only random logical-send identity; absent on received/legacy rows. */
  transferId?: string;
  roomId: string;
  timestamp: number;
  fromPeerId: string;
  fromPeerPublicKey?: string;
  channelLabel: string;
  hash: string;
  merkleRoot: string;
  filename: string;
  messageType: number; // MessageType;
  savedSize: number;
  totalSize: number;
  /**
   * Receiver only: running summary of the chunks held, rewritten with every
   * chunk insert. Absent on sent rows and on rows written by 0.14.10.
   */
  receiveManifest?: ReceiveManifest;
  /**
   * Receiver only: the file's stored bytes did not match its whole-file hash
   * when it last completed, so its chunks were dropped. Cleared when a later
   * re-receive completes and verifies.
   */
  integrityFailed?: true;
  /**
   * Receiver only: the chunk that would complete this file, held here (not in
   * the have-set) until the file verifies against its whole-file hash.
   */
  receiveVerification?: ReceiveVerificationMarker;
  /**
   * Set when the room's record is deleted while this row still exists: a
   * digest of the room's URL (never the URL). If this message's file then
   * cannot be removed, the digest moves to the deleted transfer's row, so a
   * later purge of the same URL can find the file. See `ReceiveActivity`.
   */
  roomKey?: string;
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
  fromPeerPublicKey?: string;
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

export interface ExpiredReceiveTransfer {
  merkleRoot: string;
  roomId: string;
  fromPeerId: string;
}

export interface ReceiveDeleteGuard {
  roomId: string;
  fromPeerId: string;
  incompleteOnly: true;
}

/**
 * Posted by the worker (outside any request) when a removal the SDK started
 * itself left a file in the origin private file system: a peer's cancel, the
 * stale-receive sweep, the drop after a failed verification, or the retry at
 * the worker's start. `roomId`, `fromPeerId`, `filename` and `totalSize` are
 * empty or 0 when no record of the file's message remains.
 */
export interface FileRemovalNotice {
  merkleRoot: string;
  roomId: string;
  fromPeerId: string;
  filename: string;
  totalSize: number;
  /** What the browser threw: its error's name and message. */
  error: SerializedError;
}

/**
 * Which pending removals to try again (retryFileRemovals). A scope that
 * names a room covers only what that room's deleted messages left behind:
 * - `roomId` with one name of a message (its Merkle root, the transfer ID it
 *   was sent under, or its whole-file hash): that message's file. By Merkle
 *   root this also covers a file that no record of any room names.
 * - `roomId` alone: every file the room's deleted messages left.
 * - `roomUrl`, with or without `roomId`: the same for a room whose record
 *   was deleted (its files are found by a digest of the URL), together with
 *   what the room left under the id it has now, if it has one.
 * - `exceptRoomIds`: every file the deleted messages of any room left, the
 *   listed rooms excepted (leaving all rooms with their messages).
 */
export type FileRemovalRetryScope =
  | { roomId: string; merkleRootHex: string }
  | { roomId: string; transferId: string }
  | { roomId: string; hash: string }
  | { roomId: string; roomUrl?: string }
  | { roomUrl: string }
  | { exceptRoomIds: readonly string[] };

export interface ReceiveChunkStored {
  /** True only when this call inserted a previously absent chunk index. */
  stored: boolean;
  fromPeerPublicKey?: string;
  /** Sum of distinct committed realLen values for this Merkle root. */
  savedSize: number;
  /** Authoritative distinct-byte completion after this transaction. */
  complete: boolean;
  /**
   * Set when this chunk would complete a file: it is held pending
   * verification and the caller verifies the file with this token
   * (verifyReceivedFile, then settleReceivedFileVerification).
   */
  verification?: string;
  failure?: undefined;
}

/** The chunk that would complete a received file, held until it verifies. */
export interface ReceiveVerificationMarker {
  /** Identifies one verification attempt. */
  token: string;
  chunkIndex: number;
  realLen: number;
  leafHash: string;
  mimeType: string;
  /** The chunk's bytes, only when they could not be placed in OPFS. */
  data?: ArrayBuffer;
}

/**
 * How a room's messages are loaded (getDBRoomMessageData). `verifyHeld` is set
 * only when the SDK loads a room to show it: that room's held files are then
 * queued for verification without their sender. A room delete reads the same
 * rows without it, so it starts no verification.
 */
export interface RoomMessageLoadOptions {
  verifyHeld?: boolean;
}

/** What hashing the stored file found (verifyReceivedFile). */
export type ReceiveVerificationVerdict =
  "match" | "mismatch" | "aborted" | "storage-failed";

/** What settling a verification did (settleReceivedFileVerification). */
export type ReceiveVerificationOutcome = "complete" | "integrity" | "aborted";

/**
 * Posted by the worker (outside any request) while it verifies a held file:
 * after every RECEIVE_VERIFY_PROGRESS_BYTES hashed, or once
 * RECEIVE_VERIFY_RECEIPT_INTERVAL_MS have passed since the last report.
 * `hashedBytes` only grows within one attempt.
 */
export interface HeldFileProgressNotice {
  merkleRoot: string;
  token: string;
  hashedBytes: number;
}

/**
 * Posted by the worker (outside any request) when it verified a held file on
 * its own: at the next start, when the SDK loaded that file's room.
 */
export interface HeldFileSettledNotice {
  roomId: string;
  fromPeerId: string;
  fromPeerPublicKey?: string;
  merkleRoot: string;
  hash: string;
  filename: string;
  messageType: number;
  channelLabel: string;
  timestamp: number;
  totalSize: number;
  chunkIndex: number;
  verdict: ReceiveVerificationVerdict;
  outcome: ReceiveVerificationOutcome;
}

/**
 * Why a received chunk could not be stored. Nothing for it was committed.
 * - `insufficient-quota`: the first chunk of a transfer larger than the
 *   estimated free storage; refused before anything was written.
 * - `quota-exceeded`: the browser refused a write for lack of space.
 * - `storage-failed`: any other storage fault.
 * - `integrity`: the chunk would have completed a file whose stored bytes do
 *   not hash to the message's whole-file hash; the file's chunks were dropped.
 */
export type ReceiveStorageFailure =
  | "insufficient-quota"
  | "quota-exceeded"
  | "storage-failed"
  | "integrity"
  | "not-removed";

export interface ReceiveChunkStoreFailure {
  failure: ReceiveStorageFailure;
  /** `insufficient-quota` only: the transfer's total size in bytes. */
  requiredBytes?: number;
  /** `insufficient-quota` only: estimated free bytes (quota minus usage). */
  availableBytes?: number;
}

export type ReceiveChunkStoreResult =
  ReceiveChunkStored | ReceiveChunkStoreFailure;

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

/** Ed25519 account key material accepted by the worker write boundary. */
export interface IdentityEd25519KeyMaterial {
  pub: ArrayBuffer;
  secret: ArrayBuffer;
}

/** Ed25519 account identity returned by the worker read boundary. */
export interface IdentityEd25519 extends IdentityEd25519KeyMaterial {
  /** Persistent, non-reused uint64 revision allocated by IndexedDB. */
  recordRevision: bigint;
}

/** At-rest Ed25519 record (meta key "identityEd25519"). */
export interface StoredIdentityEd25519 {
  version: 1;
  pub: ArrayBuffer;
  wrappedSecret: ArrayBuffer;
  recordRevision: bigint;
}

/** Persistent Ed25519 revision high-water/tombstone record in the meta store. */
export interface StoredIdentityEd25519Revision {
  version: 1;
  lastRevision: bigint;
}

/**
 * How the current Ed25519 account identity came into being. "mnemonic" means it
 * was derived from a recovery phrase and can therefore be reproduced from one;
 * "random" means it was generated from a random seed and is unrecoverable.
 * Non-secret: it says nothing about the phrase or the key, only about whether a
 * backup is possible at all.
 */
export type IdentityDerivation = "random" | "mnemonic";

/** At-rest derivation record (meta key "identityDerivation"). */
export interface StoredIdentityDerivation {
  version: 1;
  derivation: IdentityDerivation;
  /**
   * The Ed25519 public key this claim describes, when one was stored at the
   * time it was recorded. A flag whose binding no longer matches the stored
   * account key is reported as unknown rather than carried over: claiming
   * recoverability for a key that was never derived from a phrase would hand
   * the user a backup that restores someone else's identity.
   */
  boundPub: ArrayBuffer | null;
}

/** Non-secret online PIN-guess throttle state for one room/peer-identity edge. */
export interface PinAttemptState {
  failures: number;
  retryAfter: number;
}

// Each method and its arguments/return type
export type WorkerMessages =
  | { id: number; method: "outboxRequest"; args: [request: OutboxRequest] }
  | { id: number; method: "sweepStaleReceives"; args: [] }
  | { id: number; method: "sweepStaleReceiveDetails"; args: [] }
  | {
      id: number;
      method: "getDBAddressBookEntry";
      args: [peerPublicKey: string];
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
      args: [peerPublicKey: string];
    }
  | {
      id: number;
      method: "recordAuthenticatedPeer";
      args: [peerId: string, peerPublicKey: string];
    }
  | {
      id: number;
      method: "getDBPeerIsBlacklisted";
      args: [peerPublicKey: string];
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
      args: [legacyPreferences?: Record<string, boolean>];
    }
  | {
      id: number;
      method: "setDBUniqueRoom";
      args: [
        roomUrl: string,
        roomId: string,
        roomPolicy: ArrayBuffer,
        initialKnownOnly?: boolean,
        authority?: RoomMembershipAuthority,
      ];
    }
  | {
      id: number;
      method: "setDBRoomKnownOnly";
      args: [roomUrl: string, knownOnly: boolean];
    }
  | {
      id: number;
      method: "deleteDBPeerFromBlacklist";
      args: [peerPublicKey: string];
    }
  | {
      id: number;
      method: "getDBMessageData";
      args: [merkleRootHex?: string, hashHex?: string];
    }
  | {
      id: number;
      method: "getDBRoomMessageData";
      args: [roomId: string, options?: RoomMessageLoadOptions];
    }
  | {
      id: number;
      method: "getDBRoomStats";
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
        fromPeerPublicKey?: string,
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
      method: "verifyReceivedFile";
      args: [merkleRootHex: string, token: string, holder: string];
    }
  | {
      id: number;
      method: "settleReceivedFileVerification";
      args: [
        merkleRootHex: string,
        token: string,
        commit: boolean,
        holder: string,
      ];
    }
  | {
      id: number;
      method: "abortReceivedFileVerification";
      args: [merkleRootHex: string, token: string, holder: string];
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
      args: [merkleRootHex: string, guard?: ReceiveDeleteGuard];
    }
  | {
      id: number;
      method: "retryFileRemovals";
      args: [scope: FileRemovalRetryScope];
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
  | {
      id: number;
      method: "setDBNewChunk";
      args: [chunk: NewChunk, lease?: OutboxLease];
    }
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
      args: [identity: IdentityEd25519KeyMaterial];
    }
  | {
      id: number;
      method: "deleteIdentityEd25519";
      args: [];
    }
  | {
      id: number;
      method: "getIdentityDerivation";
      args: [];
    }
  | {
      id: number;
      method: "setIdentityDerivation";
      args: [derivation: IdentityDerivation];
    }
  | {
      id: number;
      method: "deleteIdentityDerivation";
      args: [];
    }
  | {
      id: number;
      method: "deleteDB";
      args: [];
    };

// Return types for each method
export interface WorkerMethodReturnTypes {
  outboxRequest: OutboxResponse;
  sweepStaleReceives: string[];
  sweepStaleReceiveDetails: ExpiredReceiveTransfer[];
  getDBAddressBookEntry: UsernamedPeer | undefined;
  getAllDBAddressBookEntries: UsernamedPeer[];
  setDBAddressBookEntry: undefined;
  deleteDBAddressBookEntry: undefined;
  recordAuthenticatedPeer: { known: boolean; blocked: boolean };
  getDBPeerIsBlacklisted: boolean;
  getAllDBBlacklisted: BlacklistedPeer[];
  setDBPeerInBlacklist: undefined;
  getAllDBUniqueRooms: UniqueRoom[];
  setDBUniqueRoom: undefined;
  setDBRoomKnownOnly: undefined;
  deleteDBPeerFromBlacklist: undefined;
  getDBMessageData: MessageData | undefined;
  getDBRoomMessageData: MessageData[];
  getDBRoomStats: RoomStats;
  getDBChunk: ArrayBuffer | undefined;
  existsDBChunk: boolean;
  getDBNewChunk: NewChunk | undefined;
  getDBNewChunkByReceipt:
    | Pick<
        NewChunk,
        "transferId" | "chunkIndex" | "merkleRoot" | "receiptToken"
      >
    | undefined;
  existsDBNewChunk: boolean;
  getDBSendQueue: SendQueue[];
  getDBAllChunks: Chunk[];
  getDBAllChunkLeafHashes: ChunkLeafHash[];
  assembleToOPFS: File | null;
  getDBAllChunksCount: number;
  setDBChunk: undefined;
  // true if the chunk was newly stored; false if it was already present (dedup).
  storeReceiveChunk: ReceiveChunkStoreResult;
  verifyReceivedFile: ReceiveVerificationVerdict;
  settleReceivedFileVerification: ReceiveVerificationOutcome;
  abortReceivedFileVerification: undefined;
  getReceiveFile: File | null;
  closeReceiveFile: undefined;
  deleteReceiveTransfer: boolean | undefined;
  retryFileRemovals: string[];
  getDBAllNewChunks: NewChunk[];
  getDBAllNewChunksCount: number;
  setDBNewChunk: undefined;
  setDBRoomMessageData: undefined;
  setDBSendQueue: undefined;
  countDBSendQueue: number;
  deleteDBChunk: undefined;
  deleteDBNewChunk: undefined;
  deleteDBSendQueue: undefined;
  deleteDBUniqueRoom: string[];
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
  setIdentityEd25519: bigint;
  deleteIdentityEd25519: undefined;
  getIdentityDerivation: IdentityDerivation | null;
  setIdentityDerivation: undefined;
  deleteIdentityDerivation: undefined;
  deleteDB: undefined;
}
