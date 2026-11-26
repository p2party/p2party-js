import { CHANNEL_OPEN_TIMEOUT_MS, CHANNEL_OPEN_POLL_MS } from "./constants";

/** The clock a poll reads and sleeps on; the browser's by default. */
export interface PollClock {
  readonly now: () => number;
  readonly setTimeout: (callback: () => void, ms: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
}

export const realPollClock: PollClock = {
  now: () => Date.now(),
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
};

/** Sleep `ms` on `clock`, or until `signal` aborts, whichever comes first. */
export const sleepUnlessAborted = (
  ms: number,
  signal?: AbortSignal,
  clock: PollClock = realPollClock,
): Promise<void> =>
  new Promise((resolve) => {
    if (signal?.aborted === true) {
      resolve();
      return;
    }
    const finish = (): void => {
      clock.clearTimeout(handle);
      signal?.removeEventListener("abort", finish);
      resolve();
    };
    const handle = clock.setTimeout(finish, ms);
    signal?.addEventListener("abort", finish, { once: true });
  });

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
  clock: PollClock = realPollClock,
): Promise<boolean> => {
  const start = clock.now();
  while (
    dc.readyState === "connecting" &&
    clock.now() - start < timeoutMs &&
    !signal?.aborted
  ) {
    await sleepUnlessAborted(pollMs, signal, clock);
  }
  return !signal?.aborted && dc.readyState === "open";
};
