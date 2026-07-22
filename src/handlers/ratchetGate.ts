// Per-peer "the main-channel ratchet is established" gate (spec §5/R2). It is a
// promise the `main` channel resolves after runHandshake succeeds; per-message
// data channels and the reconnect receipt-replay burst await it before doing
// anything, so nothing races ahead of the handshake. Keyed to the transient
// peerId (a single live connection); rebuilt fresh on reconnect via reset.
interface Gate {
  promise: Promise<void>;
  resolve: () => void;
  reject: (err: unknown) => void;
  settled: boolean;
}

const gates = new Map<string, Gate>();

const ensure = (peerId: string): Gate => {
  let gate = gates.get(peerId);
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
    gate = { promise, resolve, reject, settled: false };
    gates.set(peerId, gate);
  }
  return gate;
};

export const getRatchetGate = (peerId: string): Promise<void> =>
  ensure(peerId).promise;

export const openRatchetGate = (peerId: string): void => {
  const gate = ensure(peerId);
  if (!gate.settled) {
    gate.settled = true;
    gate.resolve();
  }
};

export const rejectRatchetGate = (peerId: string, err: unknown): void => {
  const gate = ensure(peerId);
  if (!gate.settled) {
    gate.settled = true;
    gate.reject(err);
  }
};

export const resetRatchetGate = (peerId: string): void => {
  gates.delete(peerId);
};
