import { describe, expect, test } from "bun:test";

import {
  answerImmediateSignalingHeartbeat,
  classifySignalingHeartbeat,
  SignalingIngressQueue,
  SignalingSocketIngressLease,
} from "../../src/utils/signalingIngressQueue";

describe("bounded signaling ingress FIFO", () => {
  test("preserves wire order while only one handler is active", async () => {
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const started = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    const observed: number[] = [];
    const queue = new SignalingIngressQueue({
      maxPending: 4,
      onOverflow: () => {
        throw new Error("unexpected overflow");
      },
    });

    queue.enqueue(async () => {
      observed.push(1);
      firstStarted();
      await firstGate;
    });
    queue.enqueue(() => {
      observed.push(2);
    });
    queue.enqueue(() => {
      observed.push(3);
    });

    await started;
    expect(observed).toEqual([1]);
    releaseFirst();
    await Bun.sleep(0);
    await Bun.sleep(0);
    expect(observed).toEqual([1, 2, 3]);
    expect(queue.pendingCount).toBe(0);
  });

  test("a burst behind a deferred frame is bounded and fails the socket closed", async () => {
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const started = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    let overflowCount = 0;
    let handlersStarted = 0;
    const queue = new SignalingIngressQueue({
      maxPending: 8,
      onOverflow: () => {
        overflowCount += 1;
      },
    });

    expect(
      queue.enqueue(async () => {
        handlersStarted += 1;
        firstStarted();
        await firstGate;
      }),
    ).toBe(true);
    for (let index = 1; index < 8; index++)
      expect(
        queue.enqueue(() => {
          handlersStarted += 1;
        }),
      ).toBe(true);

    await started;
    expect(queue.pendingCount).toBe(8);
    expect(queue.enqueue(() => undefined)).toBe(false);
    expect(queue.enqueue(() => undefined)).toBe(false);
    expect(queue.isClosed).toBe(true);
    expect(overflowCount).toBe(1);
    expect(handlersStarted).toBe(1);

    releaseFirst();
    await Bun.sleep(0);
    await Bun.sleep(0);
    expect(handlersStarted).toBe(1);
    expect(queue.pendingCount).toBe(0);
  });

  test("overflow revokes a running task before the WebSocket close event", async () => {
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const started = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    const lease = new SignalingSocketIngressLease();
    const ownsSocket = () => true;
    let effects = 0;
    const queue = new SignalingIngressQueue({
      maxPending: 1,
      onOverflow: () => lease.invalidate(),
    });

    queue.enqueue(async () => {
      firstStarted();
      await firstGate;
      if (lease.isCurrent(ownsSocket)) effects += 1;
    });
    await started;
    expect(queue.enqueue(() => undefined)).toBe(false);
    expect(lease.isCurrent(ownsSocket)).toBe(false);

    releaseFirst();
    await Bun.sleep(0);
    expect(effects).toBe(0);
  });

  test("queued payload bytes are bounded independently of frame count", async () => {
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let overflows = 0;
    const queue = new SignalingIngressQueue({
      maxPending: 128,
      maxPendingBytes: 10,
      onOverflow: () => {
        overflows += 1;
      },
    });

    expect(queue.enqueue(async () => await firstGate, 4)).toBe(true);
    expect(queue.enqueue(() => undefined, 4)).toBe(true);
    expect(queue.pendingBytes).toBe(8);
    expect(queue.enqueue(() => undefined, 3)).toBe(false);
    expect(overflows).toBe(1);
    expect(queue.pendingBytes).toBe(8);

    releaseFirst();
    await Bun.sleep(0);
    await Bun.sleep(0);
    expect(queue.pendingBytes).toBe(0);
  });

  test("an exact heartbeat bypasses a deferred protocol frame", async () => {
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const started = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    const observed: string[] = [];
    const queue = new SignalingIngressQueue({
      onOverflow: () => undefined,
    });
    queue.enqueue(async () => {
      observed.push("protocol-start");
      firstStarted();
      await firstGate;
      observed.push("protocol-finish");
    });

    await started;
    expect(
      answerImmediateSignalingHeartbeat('{"type":"ping"}', {
        raw: () => observed.push("PONG-raw"),
        json: () => observed.push("PONG-json"),
      }),
    ).toBe(true);
    expect(observed).toEqual(["protocol-start", "PONG-json"]);

    releaseFirst();
    await Bun.sleep(0);
    expect(observed).toEqual([
      "protocol-start",
      "PONG-json",
      "protocol-finish",
    ]);
  });

  test("only exact heartbeat shapes take the immediate path", () => {
    expect(classifySignalingHeartbeat("PING")).toBe("raw");
    expect(classifySignalingHeartbeat('{"type":"ping"}')).toBe("json");
    expect(
      classifySignalingHeartbeat('{"type":"ping","extra":true}'),
    ).toBeNull();
    expect(
      classifySignalingHeartbeat('{"type":"ping","type":"ping"}'),
    ).toBeNull();
    expect(classifySignalingHeartbeat('["ping"]')).toBeNull();
  });

  test("task rejection is observed without breaking the next queued frame", async () => {
    const errors: unknown[] = [];
    const observed: string[] = [];
    const queue = new SignalingIngressQueue({
      onOverflow: () => undefined,
      onTaskError: (error) => errors.push(error),
    });

    queue.enqueue(() => {
      throw new Error("injected handler failure");
    });
    queue.enqueue(() => {
      observed.push("next");
    });

    await Bun.sleep(0);
    await Bun.sleep(0);
    expect(errors).toHaveLength(1);
    expect(observed).toEqual(["next"]);
    expect(queue.pendingCount).toBe(0);
  });
});
