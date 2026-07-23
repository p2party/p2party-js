export interface TransferAbortHandle {
  readonly transferId: string;
  readonly signal: AbortSignal;
  bindHash(hashHex: string): void;
  bindMerkleRoot(merkleRootHex: string): void;
  finish(): void;
}

interface ActiveTransfer {
  transferId: string;
  controller: AbortController;
  finished: boolean;
  hashHex?: string;
  merkleRootHex?: string;
}

const activeByRoom = new Map<string, Set<ActiveTransfer>>();

const removeActive = (roomId: string, transfer: ActiveTransfer): void => {
  const roomTransfers = activeByRoom.get(roomId);
  if (!roomTransfers) return;
  roomTransfers.delete(transfer);
  if (roomTransfers.size === 0) activeByRoom.delete(roomId);
};

const abortActive = (transfer: ActiveTransfer, reason: Error): void => {
  if (!transfer.controller.signal.aborted)
    transfer.controller.abort(reason);
};

/**
 * Registers one logical outbound message. Its identifiers are bound as soon as
 * streaming hashing/Merkle construction learns them, so cancellation remains
 * message-scoped instead of broadcasting a window-global event.
 */
export const createTransferId = (): string => {
  const id = new Uint8Array(32);
  globalThis.crypto.getRandomValues(id);
  let hex = "";
  for (const byte of id) hex += byte.toString(16).padStart(2, "0");
  return hex;
};

const isTransferId = (value: string): boolean =>
  /^[0-9a-f]{64}$/.test(value);

export const beginTransfer = (
  roomId: string,
  transferId = createTransferId(),
): TransferAbortHandle => {
  if (roomId.length === 0) throw new Error("Transfer roomId must not be empty");
  if (!isTransferId(transferId))
    throw new Error("Transfer ID must be 32-byte lowercase hex");
  if (
    [...(activeByRoom.get(roomId) ?? [])].some(
      (active) => active.transferId === transferId,
    )
  )
    throw new Error("Transfer ID is already active in this room");
  const transfer: ActiveTransfer = {
    transferId,
    controller: new AbortController(),
    finished: false,
  };
  let roomTransfers = activeByRoom.get(roomId);
  if (!roomTransfers) {
    roomTransfers = new Set();
    activeByRoom.set(roomId, roomTransfers);
  }
  roomTransfers.add(transfer);

  return {
    transferId,
    signal: transfer.controller.signal,
    bindHash(hashHex: string): void {
      transfer.hashHex = hashHex;
    },
    bindMerkleRoot(merkleRootHex: string): void {
      transfer.merkleRootHex = merkleRootHex;
    },
    finish(): void {
      if (transfer.finished) return;
      transfer.finished = true;
      removeActive(roomId, transfer);
    },
  };
};

/**
 * Internal handoff from the public API to the async send pipeline. The public
 * boundary registers first so `handle.cancel()` works even while WASM is still
 * loading; the handler later claims that exact live controller.
 */
export const claimTransfer = (
  roomId: string,
  transferId: string,
): TransferAbortHandle => {
  const active = [...(activeByRoom.get(roomId) ?? [])].find(
    (candidate) => candidate.transferId === transferId,
  );
  if (!active) return beginTransfer(roomId, transferId);

  return {
    transferId,
    signal: active.controller.signal,
    bindHash(hashHex: string): void {
      active.hashHex = hashHex;
    },
    bindMerkleRoot(merkleRootHex: string): void {
      active.merkleRootHex = merkleRootHex;
    },
    finish(): void {
      if (active.finished) return;
      active.finished = true;
      removeActive(roomId, active);
    },
  };
};

export interface TransferSelector {
  transferId?: string;
  hashHex?: string;
  merkleRootHex?: string;
}

export interface IncomingTransferProgress {
  fromPeerId: string;
  savedSize: number;
  totalSize: number;
}

/**
 * In immediate mode, closing only a message-scoped DataChannel while its
 * authenticated peer connection remains alive is the remote CANCEL signal.
 * Delete only an incomplete receive owned by that peer; completed messages and
 * the sender's local self-copy must survive the ordinary terminal close.
 */
export const isRemoteCancelClose = (
  progress: IncomingTransferProgress | undefined,
  remotePeerId: string,
  authenticatedTransportStillAlive: boolean,
): boolean =>
  authenticatedTransportStillAlive &&
  progress !== undefined &&
  progress.fromPeerId === remotePeerId &&
  Number.isFinite(progress.totalSize) &&
  Number.isFinite(progress.savedSize) &&
  progress.totalSize > 0 &&
  progress.savedSize >= 0 &&
  progress.savedSize < progress.totalSize;

export const abortTransfer = (
  roomId: string,
  selector: TransferSelector,
): number => {
  if (!selector.transferId && !selector.hashHex && !selector.merkleRootHex)
    throw new Error(
      "Transfer cancellation requires a transfer ID, hash, or Merkle root",
    );
  if (selector.transferId && !isTransferId(selector.transferId))
    throw new Error("Transfer ID must be 32-byte lowercase hex");
  const roomTransfers = activeByRoom.get(roomId);
  if (!roomTransfers) return 0;
  const matches = [...roomTransfers].filter((transfer) =>
    selector.transferId !== undefined
      ? transfer.transferId === selector.transferId
      : selector.merkleRootHex !== undefined
        ? transfer.merkleRootHex === selector.merkleRootHex
        : transfer.hashHex === selector.hashHex,
  );
  if (selector.transferId === undefined && matches.length > 1)
    throw new Error(
      "Transfer selector is ambiguous; cancel with the random transfer ID",
    );
  let aborted = 0;
  for (const transfer of matches) {
    abortActive(transfer, new Error("Message transfer cancelled"));
    aborted++;
  }
  return aborted;
};

export const abortRoomTransfers = (roomId: string): number => {
  const roomTransfers = activeByRoom.get(roomId);
  if (!roomTransfers) return 0;
  let aborted = 0;
  for (const transfer of roomTransfers) {
    abortActive(transfer, new Error("Room transfers cancelled"));
    aborted++;
  }
  return aborted;
};

export const abortAllTransfers = (): number => {
  let aborted = 0;
  for (const roomId of [...activeByRoom.keys()])
    aborted += abortRoomTransfers(roomId);
  return aborted;
};

export const throwIfTransferAborted = (signal?: AbortSignal): void => {
  if (!signal?.aborted) return;
  if (signal.reason instanceof Error) throw signal.reason;
  throw new Error("Message transfer cancelled");
};

export const waitWithTransferAbort = async <T>(
  pending: Promise<T>,
  signal?: AbortSignal,
): Promise<T> => {
  throwIfTransferAborted(signal);
  if (!signal) return pending;

  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      cleanup();
      reject(
        signal.reason instanceof Error
          ? signal.reason
          : new Error("Message transfer cancelled"),
      );
    };
    const cleanup = (): void => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    void pending.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(error);
      },
    );
  });
};
