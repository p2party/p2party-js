// Selective retransmit / resume reconcile state — in-memory, per (peerId, hashHex).
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
const key = (peerId: string, hashHex: string): string => `${peerId}:${hashHex}`;

const edge = (peerId: string, hashHex: string): Edge => {
  const k = key(peerId, hashHex);
  let e = edges.get(k);
  if (!e) {
    e = { acked: new Set<number>(), complete: false };
    edges.set(k, e);
  }
  return e;
};

export const markChunkAcked = (
  peerId: string,
  hashHex: string,
  chunkIndex: number,
): void => {
  edge(peerId, hashHex).acked.add(chunkIndex);
};

// A defensive copy — the caller (sendChunks reconcile filter) must not mutate
// the live set, which keeps growing as more receipts arrive.
export const getAckedChunks = (peerId: string, hashHex: string): Set<number> =>
  new Set(edge(peerId, hashHex).acked);

export const markTransferComplete = (peerId: string, hashHex: string): void => {
  edge(peerId, hashHex).complete = true;
};

export const isTransferComplete = (peerId: string, hashHex: string): boolean =>
  edges.get(key(peerId, hashHex))?.complete ?? false;

export const clearTransfer = (peerId: string, hashHex: string): void => {
  edges.delete(key(peerId, hashHex));
};

// Poll for completion up to timeoutMs; returns true as soon as complete so a
// healthy transfer isn't delayed a full interval.
export const waitForCompletion = async (
  peerId: string,
  hashHex: string,
  timeoutMs: number,
): Promise<boolean> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && !isTransferComplete(peerId, hashHex)) {
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return isTransferComplete(peerId, hashHex);
};
