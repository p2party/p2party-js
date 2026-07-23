// Per-(room, peer) "the main-channel ratchet is established" gate (spec §5/R2).
// It is a
// promise the `main` channel resolves after runHandshake succeeds; per-message
// data channels and the reconnect receipt-replay burst await it before doing
// anything, so nothing races ahead of the handshake.
interface Gate {
  promise: Promise<void>;
  resolve: () => void;
  reject: (err: unknown) => void;
  settled: boolean;
  outcome: "pending" | "open" | "rejected";
  lease: RatchetGateLease;
}

/**
 * Opaque ownership token for one concrete room/peer transport attempt.
 *
 * A reconnect replaces the gate at the same map key. Async completion from the
 * old transport must present its old lease and is then ignored instead of
 * opening/rejecting the replacement transport's promise.
 */
export interface RatchetGateLease {
  readonly token: symbol;
}

const gates = new Map<string, Gate>();

const gateKey = (roomId: string, peerId: string): string =>
  `${roomId}\u0000${peerId}`;

const ensure = (roomId: string, peerId: string): Gate => {
  const key = gateKey(roomId, peerId);
  let gate = gates.get(key);
  if (!gate) {
    let resolve!: () => void;
    let reject!: (err: unknown) => void;
    const promise = new Promise<void>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    // Attach a no-op handler synchronously so a reject() on a peer nobody has
    // awaited yet never fires the runtime's unhandled-rejection event. This
    // does not consume the rejection for real awaiters: `getRatchetGate`
    // returns this same promise, and each independent `.catch`/`await` on it
    // still observes the rejection (a promise may have multiple listeners).
    promise.catch(() => {});
    gate = {
      promise,
      resolve,
      reject,
      settled: false,
      outcome: "pending",
      lease: { token: Symbol("ratchet-gate") },
    };
    gates.set(key, gate);
  }
  return gate;
};

export const getRatchetGate = (
  roomId: string,
  peerId: string,
): Promise<void> => ensure(roomId, peerId).promise;

/** Claim the gate already created for the current transport attempt. */
export const claimRatchetGate = (
  roomId: string,
  peerId: string,
): RatchetGateLease => ensure(roomId, peerId).lease;

export const isCurrentRatchetGateLease = (
  roomId: string,
  peerId: string,
  lease: RatchetGateLease,
): boolean => gates.get(gateKey(roomId, peerId))?.lease === lease;

export const isRatchetGateOpen = (
  roomId: string,
  peerId: string,
  lease?: RatchetGateLease,
): boolean => {
  const gate = gates.get(gateKey(roomId, peerId));
  return (
    gate?.outcome === "open" &&
    (lease === undefined || gate.lease === lease)
  );
};

export const openRatchetGate = (
  roomId: string,
  peerId: string,
  lease: RatchetGateLease,
): boolean => {
  const gate = ensure(roomId, peerId);
  if (gate.lease !== lease || gate.settled) return false;
  gate.settled = true;
  gate.outcome = "open";
  gate.resolve();
  return true;
};

export const rejectRatchetGate = (
  roomId: string,
  peerId: string,
  err: unknown,
  lease?: RatchetGateLease,
): boolean => {
  const gate = ensure(roomId, peerId);
  // Omitting the lease is the explicit force-teardown path used when the
  // current room/peer transport itself is being destroyed. Async handshake
  // completion/failure must always pass its attempt lease.
  if (lease && gate.lease !== lease) return false;
  if (!gate.settled) {
    gate.settled = true;
    gate.outcome = "rejected";
    gate.reject(err);
  }
  return true;
};

export const resetRatchetGate = (
  roomId: string,
  peerId: string,
  reason: unknown = new Error("Ratchet gate reset"),
): RatchetGateLease => {
  const key = gateKey(roomId, peerId);
  const gate = gates.get(key);
  if (gate && !gate.settled) {
    gate.settled = true;
    gate.outcome = "rejected";
    gate.reject(reason);
  }
  gates.delete(key);
  return ensure(roomId, peerId).lease;
};
