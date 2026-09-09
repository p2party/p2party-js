import { describe, expect, test } from "bun:test";

import {
  awaitPcOperation,
  isPcOperationTargetClosed,
} from "../../../src/api/webrtc/settleOnClose";

import type { PcOperationTarget } from "../../../src/api/webrtc/settleOnClose";

const liveTarget = (): PcOperationTarget & {
  signalingState: RTCSignalingState;
  connectionState: RTCPeerConnectionState;
} => ({ signalingState: "stable", connectionState: "connected" });

/** A promise that never settles: what a closed PC leaves behind. */
const never = <T,>(): Promise<T> => new Promise<T>(() => undefined);

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const captureWarnings = async <T,>(
  run: () => Promise<T>,
): Promise<{ result: T; warnings: string[] }> => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map((arg) => String(arg)).join(" "));
  };
  try {
    return { result: await run(), warnings };
  } finally {
    console.warn = original;
  }
};

describe("awaitPcOperation", () => {
  test("resolves with the operation result when it settles first", async () => {
    const target = liveTarget();

    await expect(
      awaitPcOperation(target, Promise.resolve("applied"), {
        pollMs: 5,
        maxMs: 200,
      }),
    ).resolves.toBe("applied");
  });

  test("a void operation resolves with undefined, not a sentinel", async () => {
    const target = liveTarget();

    const outcome = await awaitPcOperation(
      target,
      (async () => undefined)(),
      { pollMs: 5, maxMs: 200 },
    );

    expect(outcome).toBeUndefined();
  });

  test("propagates an operation that rejects on its own", async () => {
    const target = liveTarget();

    await expect(
      awaitPcOperation(target, Promise.reject(new Error("wrong state")), {
        pollMs: 5,
        maxMs: 200,
      }),
    ).rejects.toThrow("wrong state");
  });

  test("an operation that already settled wins over a closed connection", async () => {
    // Nothing is gained by discarding work the browser actually completed
    // before close() landed.
    const target = liveTarget();
    target.signalingState = "closed";
    target.connectionState = "closed";

    await expect(
      awaitPcOperation(target, Promise.resolve("applied"), {
        pollMs: 5,
        maxMs: 200,
      }),
    ).resolves.toBe("applied");
  });

  test("resolves 'closed' within a poll of the connection closing", async () => {
    // close() fires no event and aborts the in-flight operation WITHOUT
    // settling its promise, so only polling can observe it.
    const target = liveTarget();
    setTimeout(() => {
      target.signalingState = "closed";
      target.connectionState = "closed";
    }, 20);

    const started = Date.now();
    const outcome = await awaitPcOperation(target, never<void>(), {
      pollMs: 10,
      maxMs: 5000,
    });
    const elapsed = Date.now() - started;

    expect(outcome).toBe("closed");
    expect(elapsed).toBeLessThan(1000);
  });

  test("connectionState alone is enough to call the transport closed", async () => {
    const target = liveTarget();
    setTimeout(() => {
      target.connectionState = "closed";
    }, 10);

    await expect(
      awaitPcOperation(target, never<void>(), { pollMs: 5, maxMs: 5000 }),
    ).resolves.toBe("closed");
  });

  test("resolves 'timeout' and names the operation in the warning", async () => {
    const target = liveTarget();

    const started = Date.now();
    const { result, warnings } = await captureWarnings(() =>
      awaitPcOperation(target, never<void>(), {
        pollMs: 5,
        maxMs: 40,
        name: "setRemoteDescription(peer-7)",
      }),
    );

    expect(result).toBe("timeout");
    expect(Date.now() - started).toBeGreaterThanOrEqual(35);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("setRemoteDescription(peer-7)");
  });

  test("a live operation is never abandoned before its budget", async () => {
    const target = liveTarget();

    const outcome = await awaitPcOperation(target, delay(30).then(() => "slow"), {
      pollMs: 5,
      maxMs: 5000,
    });

    expect(outcome).toBe("slow");
  });

  // Bun fails the running test on any unhandled rejection, so an operation
  // whose rejection lands after this function returned must already carry a
  // handler: the abandoned setRemoteDescription of a closed transport
  // routinely rejects long after its caller walked away.
  test("a rejection arriving after 'closed' is already handled", async () => {
    const target = liveTarget();
    const abandoned = new Promise<void>((_, reject) => {
      setTimeout(() => {
        reject(new Error("The RTCPeerConnection is closed"));
      }, 40);
    });
    setTimeout(() => {
      target.signalingState = "closed";
      target.connectionState = "closed";
    }, 5);

    await expect(
      awaitPcOperation(target, abandoned, { pollMs: 5, maxMs: 5000 }),
    ).resolves.toBe("closed");

    await delay(80);
  });

  test("a rejection arriving after 'timeout' is already handled", async () => {
    const target = liveTarget();
    const abandoned = new Promise<void>((_, reject) => {
      setTimeout(() => {
        reject(new Error("too late"));
      }, 60);
    });

    const { result } = await captureWarnings(() =>
      awaitPcOperation(target, abandoned, {
        pollMs: 5,
        maxMs: 20,
        name: "addIceCandidate",
      }),
    );
    expect(result).toBe("timeout");

    await delay(80);
  });
});

describe("isPcOperationTargetClosed", () => {
  test("reports only a closed signaling or connection state", () => {
    expect(isPcOperationTargetClosed(liveTarget())).toBe(false);
    expect(
      isPcOperationTargetClosed({
        signalingState: "have-local-offer",
        connectionState: "failed",
      }),
    ).toBe(false);
    expect(
      isPcOperationTargetClosed({
        signalingState: "closed",
        connectionState: "failed",
      }),
    ).toBe(true);
    expect(
      isPcOperationTargetClosed({
        signalingState: "stable",
        connectionState: "closed",
      }),
    ).toBe(true);
  });
});
