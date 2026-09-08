import type { PeerHandshakeFailureReason } from "../reducers/roomSlice";

/**
 * A handshake failure that already knows why it failed.
 *
 * The catch in handleOpenChannel used to classify by regex on the error
 * message alone, which mis-typed the framing rejection in deliverHandshakeFrame
 * as "transport" — so a pq-suite or policy mismatch re-dialled forever and was
 * never reported as a policy failure (C2).
 */
export class HandshakeFailure extends Error {
  readonly reason: PeerHandshakeFailureReason;
  readonly retryAfter?: number;

  constructor(
    message: string,
    reason: PeerHandshakeFailureReason,
    retryAfter?: number,
  ) {
    super(message);
    this.name = "HandshakeFailure";
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}

export interface HandshakeFailureContext {
  /** False before the first frame: a failure there is a transport failure. */
  readonly handshakeStarted: boolean;
  readonly pinRoom: boolean;
}

export interface ClassifiedHandshakeFailure {
  readonly reason: PeerHandshakeFailureReason;
  readonly retryAfter?: number;
}

/**
 * "transport" is the ONLY reason a fresh transport can fix. A PIN or policy
 * mismatch fails again on any transport, and a re-dial would burn another
 * attempt against the PIN throttle.
 */
export const isTerminalHandshakeFailure = (
  reason: PeerHandshakeFailureReason,
): boolean => reason !== "transport";

export const classifyHandshakeFailure = (
  error: unknown,
  context: HandshakeFailureContext,
): ClassifiedHandshakeFailure => {
  if (error instanceof HandshakeFailure)
    return { reason: error.reason, retryAfter: error.retryAfter };

  const message = error instanceof Error ? error.message : "";

  const throttleMatch = /throttled until (\S+)/.exec(message);
  if (throttleMatch) {
    const parsed = Date.parse(throttleMatch[1]);
    return {
      reason: "pin-throttled",
      retryAfter: Number.isFinite(parsed) ? parsed : undefined,
    };
  }

  if (context.handshakeStarted && /key-confirmation/i.test(message))
    return {
      reason: context.pinRoom ? "pin-mismatch" : "policy",
      retryAfter: undefined,
    };

  return { reason: "transport", retryAfter: undefined };
};
