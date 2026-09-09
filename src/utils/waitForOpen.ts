import { CHANNEL_OPEN_TIMEOUT_MS, CHANNEL_OPEN_POLL_MS } from "./constants";

// Wait for a data channel to reach "open" before sending, so a per-message
// channel's first frames aren't spilled to the WS relay while it is still
// "connecting" (which leaks sender/receiver/size/timing to the signaling
// server). Bounded by a timeout — anything that still slips is recovered by
// reconcile(). Returns whether the channel is open.
export const waitForOpen = async (
  dc: { readyState: string },
  timeoutMs = CHANNEL_OPEN_TIMEOUT_MS,
  pollMs = CHANNEL_OPEN_POLL_MS,
  signal?: AbortSignal,
): Promise<boolean> => {
  const start = Date.now();
  while (
    dc.readyState === "connecting" &&
    Date.now() - start < timeoutMs &&
    !signal?.aborted
  ) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return !signal?.aborted && dc.readyState === "open";
};
