import { getRatchetGate } from "./ratchetGate";
import { throwIfTransferAborted, waitWithTransferAbort } from "./transferAbort";
import { RATCHET_GATE_WAIT_TIMEOUT_MS } from "../utils/constants";

export const RATCHET_GATE_WAIT_TIMEOUT_MESSAGE =
  "Peer is not authenticated on this transport: the handshake did not complete within the wait budget";

export const isRatchetGateWaitTimeout = (error: unknown): boolean =>
  error instanceof Error &&
  error.message === RATCHET_GATE_WAIT_TIMEOUT_MESSAGE;

/**
 * Await the per-(room, peer) ratchet gate with a wall-clock budget.
 *
 * The gate itself is unbounded by design (it is the "handshake succeeded"
 * signal), but a send must not wait on it forever: after an edge re-dial the
 * remote may hold a stale authenticated view and never open a fresh `main`,
 * so its handshake never starts and the gate never settles. The transfer
 * abort signal still wins first; a gate that opens or rejects on its own
 * clears the timer and settles with its own outcome.
 */
export const waitForRatchetGate = async (
  roomId: string,
  peerId: string,
  signal?: AbortSignal,
  timeoutMs = RATCHET_GATE_WAIT_TIMEOUT_MS,
): Promise<void> => {
  // Check before racing anything: a synchronous abort must not leave a race
  // promise with no handler attached, or a later gate reset would surface as
  // an unhandled rejection.
  throwIfTransferAborted(signal);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(RATCHET_GATE_WAIT_TIMEOUT_MESSAGE));
    }, timeoutMs);
  });
  try {
    await waitWithTransferAbort(
      Promise.race([getRatchetGate(roomId, peerId), budget]),
      signal,
    );
  } finally {
    clearTimeout(timer);
  }
};
