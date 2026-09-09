// Close a DataChannel only after its send buffer has drained.
//
// RTCDataChannel.close() discards anything still queued in the SCTP send buffer
// (bufferedAmount > 0), so `send(x); close()` can wipe `x` before it reaches the
// wire — a long-standing race that dropped the final "finished" receipt and any
// still-buffered chunks. Wait for bufferedAmount to reach 0 (bounded by a
// timeout so a stalled channel can't hang teardown) before closing. Note:
// bufferedAmount === 0 means the bytes left the local SCTP buffer; the graceful
// SCTP shutdown that close() performs then delivers them. Peer-level receipt is
// a separate guarantee provided by the application read receipts.
export const drainAndClose = async (
  dc: { readyState: string; bufferedAmount: number; close: () => void },
  timeoutMs = 5000,
  pollMs = 25,
): Promise<void> => {
  if (dc.readyState !== "open") {
    try {
      dc.close();
    } catch {
      /* already closing/closed */
    }
    return;
  }

  const start = Date.now();
  while (
    dc.readyState === "open" &&
    dc.bufferedAmount > 0 &&
    Date.now() - start < timeoutMs
  ) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }

  try {
    if (dc.readyState === "open") dc.close();
  } catch {
    /* already closing/closed */
  }
};
