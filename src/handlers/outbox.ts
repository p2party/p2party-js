import {
  outboxRequest,
  sweepStaleReceives,
  sweepStaleReceiveDetails,
} from "../db/api";
import type {
  OutboxLease,
  OutboxManifest,
  OutboxReceipt,
  OutboxRequest,
  OutboxResponse,
} from "../db/outboxTypes";

export interface PendingMessage {
  transferId: string;
  roomId: string;
  channelLabel: string;
  filename: string;
  totalSize: number;
  totalChunks: number;
  merkleRootHex: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  phase: "staging" | "pending" | "sending";
  remainingRecipients: Array<{ peerId: string; publicKey: string }>;
  lastError?: string;
  retryable: boolean;
  retryAfter: number;
}

export const pendingMessageView = (row: OutboxManifest): PendingMessage => ({
  transferId: row.transferId,
  roomId: row.roomId,
  channelLabel: row.channelLabel,
  filename: row.filename,
  totalSize: row.totalSize,
  totalChunks: row.totalChunks,
  merkleRootHex: row.merkleRootHex,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
  expiresAt: row.expiresAt,
  phase: row.phase,
  remainingRecipients: row.recipients
    .filter((r) => !r.delivered && !r.cancelled)
    .map(({ peerId, publicKey }) => ({ peerId, publicKey })),
  lastError: row.lastError,
  retryable: row.phase !== "staging" && row.expiresAt > Date.now(),
  retryAfter: row.leaseUntil,
});

export const persistOutboundReceipt = async (
  receipt: OutboxReceipt,
): Promise<boolean> =>
  (await outboxRequest({ kind: "receipt", receipt })).accepted;

export const persistOutboundCancellation = async (
  receipt: Omit<OutboxReceipt, "chunkIndex" | "cancelled">,
): Promise<boolean> =>
  (
    await outboxRequest({
      kind: "receipt",
      receipt: { ...receipt, cancelled: true },
    })
  ).accepted;

export class OutboxOwnershipLostError extends Error {
  constructor() {
    super(
      "Durable send ownership ended; pending data remains available to its owner",
    );
    this.name = "OutboxOwnershipLostError";
  }
}

const owners = new Map<string, Set<AbortController>>();

/** Stop lease renewal synchronously on identity replacement / terminal signaling refusal. */
export const stopOutboxOwners = (_reason?: string, roomId?: string): void => {
  for (const [room, controllers] of owners) {
    if (roomId && room !== roomId) continue;
    for (const controller of controllers)
      controller.abort(new OutboxOwnershipLostError());
  }
};

export interface OutboxSession {
  lease: OutboxLease;
  signal: AbortSignal;
  finish(): void;
}

/** Local deadline prevents a suspended old tab sending before its renewal notices a fence. */
export const startOutboxSession = (
  lease: OutboxLease,
  roomId: string,
  leaseUntil: number,
  parentSignal: AbortSignal,
  stillAuthorized: () => boolean,
): OutboxSession => {
  const controller = new AbortController();
  let until = leaseUntil;
  let finished = false;
  let renewing = false;
  const abort = (): void => controller.abort(parentSignal.reason);
  if (parentSignal.aborted) abort();
  else parentSignal.addEventListener("abort", abort, { once: true });
  const roomOwners = owners.get(roomId) ?? new Set<AbortController>();
  roomOwners.add(controller);
  owners.set(roomId, roomOwners);
  // A getter checks expiry at every existing transfer abort boundary, including
  // the very first operation after the browser wakes from a long suspension.
  const signal = new Proxy(controller.signal, {
    get(target, key) {
      if (
        key === "aborted" &&
        !target.aborted &&
        (Date.now() >= until || !stillAuthorized())
      )
        controller.abort(new OutboxOwnershipLostError());
      const value = Reflect.get(target, key, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const timer = setInterval(() => {
    if (finished || signal.aborted || renewing) return;
    renewing = true;
    void outboxRequest({ kind: "renew", lease })
      .then((result) => {
        if (finished || signal.aborted) return;
        if (!result.accepted || !result.manifest)
          controller.abort(new OutboxOwnershipLostError());
        else until = result.manifest.leaseUntil;
      })
      .catch(() => controller.abort(new OutboxOwnershipLostError()))
      .finally(() => {
        renewing = false;
      });
  }, 10_000);
  controller.signal.addEventListener("abort", () => clearInterval(timer), {
    once: true,
  });
  return {
    lease,
    signal,
    finish() {
      finished = true;
      clearInterval(timer);
      parentSignal.removeEventListener("abort", abort);
      roomOwners.delete(controller);
      if (!roomOwners.size) owners.delete(roomId);
    },
  };
};

export const discardRoomOutbox = async (roomId: string): Promise<void> => {
  stopOutboxOwners("room left", roomId);
  await outboxRequest({ kind: "remove", roomId });
};

export const sweepTransferStorage = async (): Promise<string[]> => {
  await outboxRequest({ kind: "sweep" });
  return await sweepStaleReceives();
};

export const sweepTransferStorageDetails = async (
  canSweep: () => boolean = () => true,
) => {
  await outboxRequest({ kind: "sweep" });
  if (!canSweep()) return [];
  return await sweepStaleReceiveDetails();
};

/** Exact IDs cancel synchronously; hash/root selectors validate ambiguity first. */
export const discardPendingSelection = async (
  selection: {
    roomId: string;
    senderPublicKey: string;
    transferId?: string;
    merkleRootHex?: string;
    hashHex?: string;
  },
  abortLive: () => void,
  request: (request: OutboxRequest) => Promise<OutboxResponse> = outboxRequest,
): Promise<void> => {
  if (selection.transferId) {
    abortLive();
    await request({
      kind: "remove",
      transferId: selection.transferId,
      roomId: selection.roomId,
    });
    return;
  }
  const rows =
    (
      await request({
        kind: "list",
        senderPublicKey: selection.senderPublicKey,
        roomId: selection.roomId,
      })
    ).manifests ?? [];
  const matches = rows.filter((row) =>
    selection.merkleRootHex
      ? row.merkleRootHex === selection.merkleRootHex
      : row.hashHex === selection.hashHex,
  );
  if (matches.length > 1)
    throw new Error(
      "Transfer selector is ambiguous; cancel with the random transfer ID",
    );
  abortLive();
  for (const row of matches)
    await request({
      kind: "remove",
      transferId: row.transferId,
      roomId: selection.roomId,
    });
};
