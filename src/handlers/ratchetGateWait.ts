import {
  getRatchetGate,
  isRatchetGateOpen,
  isRatchetGatePending,
} from "./ratchetGate";
import { throwIfTransferAborted, waitWithTransferAbort } from "./transferAbort";
import {
  MAX_PARKED_PRE_AUTH_BYTES,
  RATCHET_GATE_WAIT_TIMEOUT_MS,
} from "../utils/constants";

import type { RatchetGateLease } from "./ratchetGate";

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

/**
 * Wait for the gate to settle, reporting the outcome instead of throwing.
 *
 * True only when it OPENED inside the budget; a rejection, a replacement and a
 * timeout are all false. Used by the pre-authentication frame guard, which must
 * park an early frame but must still close on a genuinely dead edge.
 */
export const waitForRatchetGateSettled = async (
  roomId: string,
  peerId: string,
  timeoutMs: number,
): Promise<boolean> => {
  try {
    await waitForRatchetGate(roomId, peerId, undefined, timeoutMs);
    return true;
  } catch {
    return false;
  }
};

/**
 * What a per-message frame that arrived before this side's gate opened is owed.
 *
 * `close` is a decision about the EDGE, not about the frame: only an edge that
 * will never authenticate earns it. `drop` is the decision about the frame
 * alone — it costs the peer a retransmission and costs this side nothing.
 */
export type PreAuthFrameDecision = "admit" | "drop" | "close";

/**
 * May a per-message frame that arrived before this side's gate opened be
 * processed, and if not, must its channel close or may the frame just go?
 *
 * The old guard answered this with `isRatchetGateOpen` alone, so a frame that
 * merely beat the gate by one IndexedDB persist closed a healthy channel — and
 * that self-inflicted close was then read back as the peer's immediate-mode
 * CANCEL, deleting the sender's staging AND the receiver's partial file (C7).
 *
 * The distinction the answer turns on is `pending` versus `settled`: a gate
 * still pending on this transport's own lease is a handshake in flight and is
 * worth a bounded park; a rejected gate, a replaced (stale) lease, or a park
 * that ran out of budget is a genuinely unauthenticated edge and must still
 * close. `parkedBytes` bounds how much an unauthenticated peer can pin while we
 * wait — and at that bound the frame is DROPPED, never closed on. Closing there
 * pins no less memory than dropping, and it puts a close on a healthy,
 * authenticating edge, which the peer cannot tell from a cancel: the local
 * marker that distinguishes our closes is RAM-only and never transmitted, so
 * the peer deletes its partial file. That is the exact deletion the park exists
 * to prevent, arrived at through the park's own DoS bound (C-1).
 *
 * Dropping does not weaken the bound: a peer that never authenticates still has
 * its channel closed by the first parked frame when the park budget expires.
 *
 * Callers keep the synchronous `isRatchetGateOpen` fast path ahead of this, so
 * an authenticated channel never awaits anything it did not await before.
 */
export const admitPreAuthenticatedFrame = async (
  roomId: string,
  peerId: string,
  lease: RatchetGateLease | undefined,
  parkMs: number,
  parkedBytes: number,
): Promise<PreAuthFrameDecision> => {
  if (isRatchetGateOpen(roomId, peerId, lease)) return "admit";
  // Tested BEFORE the ceiling: a gate that is not pending on this lease — a
  // rejected handshake, a replaced transport, no gate at all — is a dead edge
  // whatever the ceiling says, and closing it is the whole point of the guard.
  if (!isRatchetGatePending(roomId, peerId, lease)) return "close";
  if (parkedBytes > MAX_PARKED_PRE_AUTH_BYTES) return "drop";
  if (!(await waitForRatchetGateSettled(roomId, peerId, parkMs))) return "close";
  // Re-read under the caller's own lease: the gate may have settled by being
  // REPLACED, which resolves a fresh gate this transport does not own.
  return isRatchetGateOpen(roomId, peerId, lease) ? "admit" : "close";
};
