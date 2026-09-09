import type { Chunk, MessageData } from "./types";
/** Durable resend metadata; secrets remain exclusively in the ratchet vault. */
export interface OutboxLease {
  transferId: string;
  owner: string;
  fence: number;
}

export interface OutboxRecipient {
  peerId: string;
  publicKey: string;
  delivered: boolean;
  cancelled?: boolean;
}

export interface OutboxManifest {
  transferId: string;
  senderPublicKey: string;
  identityRevision: bigint;
  roomId: string;
  roomUrl: string;
  policyHex: string;
  channelLabel: string;
  filename: string;
  totalSize: number;
  totalChunks: number;
  stagedBytes: number;
  writtenBytes: number;
  localBytes: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  phase: "staging" | "pending" | "sending";
  merkleRootHex: string;
  hashHex: string;
  recipients: OutboxRecipient[];
  owner: string;
  fence: number;
  leaseUntil: number;
  lastError?: string;
}

export interface OutboxCreate {
  transferId: string;
  senderPublicKey: string;
  roomId: string;
  roomUrl: string;
  policyHex: string;
  channelLabel: string;
  filename: string;
  totalSize: number;
  totalChunks: number;
  stagedBytes: number;
  recipients: Array<{ peerId: string; publicKey: string }>;
  owner: string;
}

export interface OutboxReceipt {
  roomId: string;
  peerId: string;
  peerPublicKey: string;
  transferId: string;
  merkleRootHex: string;
  chunkIndex?: number;
  cancelled?: boolean;
}

export interface OutboxAckRecord {
  transferId: string;
  publicKey: string;
  bitmap: Uint8Array;
}

export type OutboxRequest =
  | { kind: "create"; input: OutboxCreate }
  | {
      kind: "publish";
      lease: OutboxLease;
      merkleRootHex: string;
      hashHex: string;
      chunkHashes: ArrayBuffer;
    }
  | {
      kind: "claim";
      transferId: string;
      owner: string;
      senderPublicKey: string;
      roomId: string;
      roomUrl: string;
      policyHex: string;
    }
  | { kind: "selfChunk"; lease: OutboxLease; chunk: Chunk }
  | { kind: "selfMessage"; lease: OutboxLease; message: MessageData }
  | { kind: "renew"; lease: OutboxLease }
  | { kind: "release"; lease: OutboxLease; lastError?: string }
  | { kind: "receipt"; receipt: OutboxReceipt }
  | { kind: "list"; senderPublicKey: string; roomId?: string }
  | {
      kind: "remove";
      transferId?: string;
      roomId?: string;
      lease?: OutboxLease;
    }
  | { kind: "sweep" };

export interface OutboxResponse {
  accepted: boolean;
  manifest?: OutboxManifest;
  manifests?: OutboxManifest[];
  lease?: OutboxLease;
  chunkHashes?: ArrayBuffer;
  acknowledgments?: OutboxAckRecord[];
}

export interface ReceiveActivity {
  merkleRoot: string;
  roomId: string;
  fromPeerId: string;
  lastActivityAt: number;
  /** Deletion fences work queued before the terminal operation. */
  deletedAt?: number;
  writeToken?: string;
  leaseUntil?: number;
}
