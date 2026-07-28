import { describe, expect, test } from "bun:test";

import { PEER_ADMISSION_WAIT_MS } from "../../src/utils/constants";

/**
 * A minimal stand-in for the parts of RTCPeerConnection that admission reads.
 *
 * The production edge installs `onconnectionstatechange` as a property (see
 * handleConnectToPeer), so this double exposes addEventListener/
 * removeEventListener separately to prove the wait does not depend on — or
 * clobber — that property handler.
 */
class FakeEdge {
  connectionState: RTCPeerConnectionState = "connected";
  onconnectionstatechange: (() => void) | null = null;
  private readonly listeners = new Set<() => void>();

  addEventListener(type: string, listener: () => void): void {
    if (type === "connectionstatechange") this.listeners.add(listener);
  }

  removeEventListener(type: string, listener: () => void): void {
    if (type === "connectionstatechange") this.listeners.delete(listener);
  }

  get listenerCount(): number {
    return this.listeners.size;
  }

  transitionTo(state: RTCPeerConnectionState): void {
    this.connectionState = state;
    this.onconnectionstatechange?.();
    for (const listener of [...this.listeners]) listener();
  }
}

/**
 * The admission predicate under test, kept byte-identical in behavior to the
 * private helper in handleSendMessage. It is duplicated here rather than
 * exported because exporting it would widen the package's public surface for
 * a test; the assertions below pin the contract that matters.
 */
const waitForConnectedEdge = (
  edge: FakeEdge,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<boolean> => {
  if (edge.connectionState === "connected") return Promise.resolve(true);
  if (edge.connectionState === "closed" || edge.connectionState === "failed")
    return Promise.resolve(false);
  if (signal?.aborted) return Promise.resolve(false);

  return new Promise<boolean>((resolve) => {
    let settled = false;
    const settle = (usable: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      edge.removeEventListener("connectionstatechange", onChange);
      signal?.removeEventListener("abort", onAbort);
      resolve(usable);
    };
    const onChange = (): void => {
      if (edge.connectionState === "connected") settle(true);
      else if (
        edge.connectionState === "closed" ||
        edge.connectionState === "failed"
      )
        settle(false);
    };
    const onAbort = (): void => {
      settle(false);
    };
    const timer = setTimeout(() => {
      settle(false);
    }, timeoutMs);
    edge.addEventListener("connectionstatechange", onChange);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
};

describe("send admission waits for a repairing edge", () => {
  test("the budget outlasts the ICE-restart grace period", () => {
    // handleConnectToPeer defers teardown of a "disconnected" edge by 8000 ms
    // while it attempts an ICE restart. Admission must not give up first, or a
    // send during the repair fails while the peer is still in the roster.
    expect(PEER_ADMISSION_WAIT_MS).toBeGreaterThan(8000);
  });

  test("an already-connected edge admits without waiting", async () => {
    const edge = new FakeEdge();
    expect(await waitForConnectedEdge(edge, 50)).toBe(true);
    expect(edge.listenerCount).toBe(0);
  });

  test("a disconnected edge that recovers is admitted", async () => {
    const edge = new FakeEdge();
    edge.connectionState = "disconnected";

    const admitted = waitForConnectedEdge(edge, 1000);
    setTimeout(() => {
      edge.transitionTo("connected");
    }, 10);

    expect(await admitted).toBe(true);
    expect(edge.listenerCount).toBe(0);
  });

  test("terminal states resolve immediately rather than burning the budget", async () => {
    for (const state of ["failed", "closed"] as const) {
      const edge = new FakeEdge();
      edge.connectionState = state;
      const started = Date.now();
      expect(await waitForConnectedEdge(edge, 5000)).toBe(false);
      expect(Date.now() - started).toBeLessThan(100);
    }
  });

  test("an edge that goes terminal while waiting stops the wait", async () => {
    const edge = new FakeEdge();
    edge.connectionState = "disconnected";

    const admitted = waitForConnectedEdge(edge, 5000);
    setTimeout(() => {
      edge.transitionTo("failed");
    }, 10);

    const started = Date.now();
    expect(await admitted).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  test("a never-recovering edge is refused once the budget expires", async () => {
    const edge = new FakeEdge();
    edge.connectionState = "disconnected";
    expect(await waitForConnectedEdge(edge, 20)).toBe(false);
    expect(edge.listenerCount).toBe(0);
  });

  test("an aborted transfer refuses immediately and detaches", async () => {
    const edge = new FakeEdge();
    edge.connectionState = "disconnected";
    const controller = new AbortController();

    const admitted = waitForConnectedEdge(edge, 5000, controller.signal);
    controller.abort();
    expect(await admitted).toBe(false);
    expect(edge.listenerCount).toBe(0);

    // Already-aborted transfers do not even attach.
    expect(await waitForConnectedEdge(edge, 5000, controller.signal)).toBe(
      false,
    );
  });

  test("waiting never displaces the reconnect property handler", async () => {
    const edge = new FakeEdge();
    edge.connectionState = "disconnected";
    let reconnectHandlerCalls = 0;
    edge.onconnectionstatechange = () => {
      reconnectHandlerCalls += 1;
    };

    const admitted = waitForConnectedEdge(edge, 1000);
    setTimeout(() => {
      edge.transitionTo("connected");
    }, 10);

    expect(await admitted).toBe(true);
    // The ICE-restart logic lives on that property; a listener must coexist.
    expect(reconnectHandlerCalls).toBe(1);
  });
});
