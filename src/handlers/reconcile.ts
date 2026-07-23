// Selective retransmit / resume state — in-memory, per
// (roomId, peerId, random transferId). Content hashes are not identities:
// concurrent sends of the same bytes must never share acknowledgements.
//
// The receipts ARE the have-set: the sender resolves each received leaf-hash
// receipt to a chunk index (handleReadReceipt → getDBNewChunk → chunkIndex) and
// records it here. reconcile() then resends ONLY the un-acked real chunks (read
// real-vs-decoy from each chunk's metadata; decoys are cover and never resent).
// The same operation serves live retransmit (timeout trigger) and resume
// (reconnect trigger, where the receiver re-emits its receipts first).
//
// This state is disposable: rebuilt from receipts on reconnect. The durable
// resend source is `newChunks` (IndexedDB, already persisted). No persistent
// store and no wire change — receipts do all the work.
type Edge = { acked: Set<number>; complete: boolean };

const edges = new Map<string, Edge>();
const key = (roomId: string, peerId: string, transferId: string): string =>
  `${roomId}\u0000${peerId}\u0000${transferId}`;

const edge = (roomId: string, peerId: string, transferId: string): Edge => {
  const k = key(roomId, peerId, transferId);
  let e = edges.get(k);
  if (!e) {
    e = { acked: new Set<number>(), complete: false };
    edges.set(k, e);
  }
  return e;
};

export const markChunkAcked = (
  roomId: string,
  peerId: string,
  transferId: string,
  chunkIndex: number,
): boolean => {
  const acked = edge(roomId, peerId, transferId).acked;
  const previousSize = acked.size;
  acked.add(chunkIndex);
  return acked.size !== previousSize;
};

// A defensive copy — the caller (sendChunks reconcile filter) must not mutate
// the live set, which keeps growing as more receipts arrive.
export const getAckedChunks = (
  roomId: string,
  peerId: string,
  transferId: string,
): Set<number> => new Set(edge(roomId, peerId, transferId).acked);

export const markTransferComplete = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => {
  const state = edge(roomId, peerId, transferId);
  if (state.complete) return false;
  state.complete = true;
  return true;
};

export interface PeerTransferOutcome {
  readonly roomId: string;
  readonly peerId: string;
  readonly transferId: string;
  readonly ackedChunks: ReadonlySet<number>;
  readonly complete: boolean;
}

/** Accurate, defensive per-peer delivery state for UI/diagnostics consumers. */
export const getPeerTransferOutcome = (
  roomId: string,
  peerId: string,
  transferId: string,
): PeerTransferOutcome => {
  const state = edges.get(key(roomId, peerId, transferId));
  return {
    roomId,
    peerId,
    transferId,
    ackedChunks: new Set(state?.acked ?? []),
    complete: state?.complete ?? false,
  };
};

export const isTransferComplete = (
  roomId: string,
  peerId: string,
  transferId: string,
): boolean => edges.get(key(roomId, peerId, transferId))?.complete ?? false;

export const clearTransfer = (
  roomId: string,
  peerId: string,
  transferId: string,
): void => {
  edges.delete(key(roomId, peerId, transferId));
};

// Poll for completion up to timeoutMs; returns true as soon as complete so a
// healthy transfer isn't delayed a full interval.
export const waitForCompletion = async (
  roomId: string,
  peerId: string,
  transferId: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<boolean> => {
  const deadline = Date.now() + timeoutMs;
  while (
    Date.now() < deadline &&
    !isTransferComplete(roomId, peerId, transferId) &&
    !signal?.aborted
  ) {
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return !signal?.aborted && isTransferComplete(roomId, peerId, transferId);
};
