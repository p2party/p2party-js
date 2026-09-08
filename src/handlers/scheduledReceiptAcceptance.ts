import { getDBNewChunkByReceipt } from "../db/api";
import { uint8ArrayToHex } from "../utils/uint8array";
import {
  hasChunkAcked,
  isTransferComplete,
  isTransferCancelled,
  markChunkAcked,
  markTransferComplete,
  markTransferCancelled,
} from "./reconcile";

export interface ScheduledReceiptOwner {
  readonly roomId: string;
  readonly peerId: string;
  readonly peerPublicKey: string;
  readonly transferId: string;
  readonly merkleRootHex: string;
}

export interface ScheduledReceiptDependencies {
  readonly getChunk: (
    root: string,
    token: string,
  ) => Promise<
    | {
        readonly transferId: string;
        readonly merkleRoot: string;
        readonly receiptToken: string;
        readonly chunkIndex: number;
      }
    | undefined
  >;
  /** Persist before exposing an ACK to selective resume or UI state. */
  readonly persist: (
    receipt: ScheduledReceiptOwner & { readonly chunkIndex?: number },
  ) => Promise<boolean>;
  readonly persistCancellation?: (
    owner: ScheduledReceiptOwner,
  ) => Promise<boolean>;
}

const defaultDependencies: ScheduledReceiptDependencies = {
  getChunk: getDBNewChunkByReceipt,
  persist: async (receipt) =>
    (await import("./outbox")).persistOutboundReceipt(receipt),
};

/** Called only after CoverRuntime authenticated the edge, epoch and replay window. */
export const acceptScheduledReceipt = async (
  owner: ScheduledReceiptOwner,
  token: Uint8Array,
  kind: "chunk" | "terminal",
  isCurrent: () => boolean,
  dependencies: ScheduledReceiptDependencies = defaultDependencies,
): Promise<boolean> => {
  if (
    !isCurrent() ||
    isTransferCancelled(owner.roomId, owner.peerId, owner.transferId) ||
    token.length !== 64 ||
    !/^[0-9a-f]{128}$/.test(owner.merkleRootHex)
  )
    return false;
  const hex = uint8ArrayToHex(token);
  if (kind === "terminal") {
    // Legacy scheduled completion used token==root. A chunk token is never a
    // completion token, even when supplied by the authenticated recipient.
    if (hex !== owner.merkleRootHex) return false;
    if (isTransferComplete(owner.roomId, owner.peerId, owner.transferId))
      return true;
    if (!(await dependencies.persist(owner)) || !isCurrent()) return false;
    markTransferComplete(owner.roomId, owner.peerId, owner.transferId);
    return true;
  }
  const chunk = await dependencies.getChunk(owner.merkleRootHex, hex);
  if (
    !chunk ||
    !isCurrent() ||
    chunk.transferId !== owner.transferId ||
    chunk.merkleRoot !== owner.merkleRootHex ||
    chunk.receiptToken !== hex ||
    !Number.isSafeInteger(chunk.chunkIndex) ||
    chunk.chunkIndex < 0
  )
    return false;
  if (
    hasChunkAcked(
      owner.roomId,
      owner.peerId,
      owner.transferId,
      chunk.chunkIndex,
    )
  )
    return true;
  if (
    !(await dependencies.persist({ ...owner, chunkIndex: chunk.chunkIndex })) ||
    !isCurrent()
  )
    return false;
  markChunkAcked(
    owner.roomId,
    owner.peerId,
    owner.transferId,
    chunk.chunkIndex,
  );
  return true;
};

/** Authenticated refusal uses the same owner and persistence boundary as ACKs. */
export const acceptScheduledCancellation = async (
  owner: ScheduledReceiptOwner,
  isCurrent: () => boolean,
  dependencies: ScheduledReceiptDependencies = defaultDependencies,
): Promise<boolean> => {
  if (!isCurrent() || !/^[0-9a-f]{128}$/.test(owner.merkleRootHex))
    return false;
  if (isTransferComplete(owner.roomId, owner.peerId, owner.transferId))
    return false;
  if (isTransferCancelled(owner.roomId, owner.peerId, owner.transferId))
    return true;
  const persist =
    dependencies.persistCancellation ??
    (async (value: ScheduledReceiptOwner) =>
      (await import("./outbox")).persistOutboundCancellation(value));
  if (!(await persist(owner)) || !isCurrent()) return false;
  markTransferCancelled(owner.roomId, owner.peerId, owner.transferId);
  return true;
};
