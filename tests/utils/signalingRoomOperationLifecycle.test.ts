import { describe, expect, test } from "bun:test";

import { SignalingRoomOperationLifecycle } from "../../src/utils/signalingRoomOperationLifecycle";

const ROOM_URL = "a".repeat(64);

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => {
    resolve = () => settle();
  });
  return { promise, resolve };
};

describe("signaling room operation lifecycle", () => {
  test("a room purge invoked during delayed join prework owns the final state", async () => {
    const lifecycle = new SignalingRoomOperationLifecycle();
    const prework = deferred();
    const entered = deferred();
    let active = false;
    const order: string[] = [];

    const joining = lifecycle.runJoin(async () => {
      entered.resolve();
      await prework.promise;
      active = true;
      order.push("join");
    });
    await entered.promise;
    const purging = lifecycle.runRoomTerminal(ROOM_URL, async () => {
      active = false;
      order.push("purge");
    });
    prework.resolve();

    await joining;
    await purging;
    expect(order).toEqual(["join", "purge"]);
    expect(active).toBe(false);
  });

  test("a global disconnect invoked during delayed join prework runs last", async () => {
    const lifecycle = new SignalingRoomOperationLifecycle();
    const prework = deferred();
    const entered = deferred();
    let connected = false;
    const order: string[] = [];

    const joining = lifecycle.runJoin(async () => {
      entered.resolve();
      await prework.promise;
      connected = true;
      order.push("connect");
    });
    await entered.promise;
    const disconnecting = lifecycle.runGlobalTerminal(async () => {
      connected = false;
      order.push("disconnect");
    });
    prework.resolve();

    await joining;
    await disconnecting;
    expect(order).toEqual(["connect", "disconnect"]);
    expect(connected).toBe(false);
  });

  test("a later invalid join cannot cancel an earlier valid join", async () => {
    const lifecycle = new SignalingRoomOperationLifecycle();
    const activation = deferred();
    const entered = deferred();
    let activated = false;

    const joining = lifecycle.runJoin(async () => {
      entered.resolve();
      await activation.promise;
      activated = true;
    });
    await entered.promise;
    const invalidJoin = lifecycle.runJoin(async () => {
      throw new Error("invalid later join");
    });
    activation.resolve();

    await joining;
    await expect(invalidJoin).rejects.toThrow("invalid later join");
    expect(activated).toBe(true);
  });
});
