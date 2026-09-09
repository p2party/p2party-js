import {
  PC_OPERATION_POLL_MS,
  PC_OPERATION_TIMEOUT_MS,
} from "../../utils/constants";

/** The slice of an RTCPeerConnection that proves the transport is gone. */
export type PcOperationTarget = Pick<
  RTCPeerConnection,
  "signalingState" | "connectionState"
>;

export interface AwaitPcOperationOptions {
  /** How often the transport is inspected while the operation is in flight. */
  readonly pollMs?: number;
  /** Wall-clock budget after which the operation is abandoned. */
  readonly maxMs?: number;
  /** Named in the timeout warning so a stuck operation is identifiable. */
  readonly name?: string;
}

export const isPcOperationTargetClosed = (epc: PcOperationTarget): boolean =>
  epc.signalingState === "closed" || epc.connectionState === "closed";

type PcOperationRace<T> =
  | { readonly kind: "value"; readonly value: T }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "tick" };

/**
 * Await one RTCPeerConnection operation without ever waiting forever on it.
 *
 * Closing an RTCPeerConnection aborts every operation in flight on it, and the
 * specification aborts them *without settling* their promises — while close()
 * itself fires no `connectionstatechange`. An `await pc.addIceCandidate(...)`
 * or `await pc.setRemoteDescription(...)` on a connection that closes
 * underneath it therefore never returns. In this codebase those awaits run
 * inside the (room, peer) negotiation mutex, which is entered from the socket's
 * strictly serial ingress queue: one such await strands the edge's mutex
 * forever AND stops every later signaling frame on that socket, so a peer's
 * re-introductions go unanswered indefinitely.
 *
 * The returned promise settles three ways:
 * - the operation's own result (or rejection, rethrown for the caller's
 *   existing error handling),
 * - `"closed"` as soon as a poll observes the transport closed — the operation
 *   is abandoned, since nothing it could still do matters,
 * - `"timeout"` once the budget expires, which callers treat exactly like a
 *   failure of that operation.
 *
 * An abandoned operation's later rejection is consumed here, so walking away
 * from it can never surface as an unhandled rejection.
 */
export const awaitPcOperation = async <T>(
  epc: PcOperationTarget,
  operation: Promise<T>,
  {
    pollMs = PC_OPERATION_POLL_MS,
    maxMs = PC_OPERATION_TIMEOUT_MS,
    name = "operation",
  }: AwaitPcOperationOptions = {},
): Promise<T | "closed" | "timeout"> => {
  const settled: Promise<PcOperationRace<T>> = operation.then(
    (value) => ({ kind: "value", value }) as const,
    (error: unknown) => ({ kind: "error", error }) as const,
  );

  const started = Date.now();
  for (;;) {
    const waitMs = Math.max(0, Math.min(pollMs, maxMs - (Date.now() - started)));
    let timer: ReturnType<typeof setTimeout> | undefined;
    let outcome: PcOperationRace<T>;
    try {
      outcome = await Promise.race<PcOperationRace<T>>([
        settled,
        new Promise<PcOperationRace<T>>((resolve) => {
          timer = setTimeout(() => {
            resolve({ kind: "tick" });
          }, waitMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }

    // A result the browser actually produced wins over the transport state:
    // the operation completed before close() landed.
    if (outcome.kind === "value") return outcome.value;
    if (outcome.kind === "error") throw outcome.error;

    if (isPcOperationTargetClosed(epc)) return "closed";
    if (Date.now() - started >= maxMs) {
      console.warn(
        `Peer connection ${name} did not settle within ${String(maxMs)} ms on a live transport; abandoning it`,
      );
      return "timeout";
    }
  }
};
