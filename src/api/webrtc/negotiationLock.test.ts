import { describe, expect, test } from "bun:test";

import {
  getRoomPeerMutex,
  getRoomIdentityMutex,
  hasRoomPeerMutex,
  releaseRoomIdentityMutex,
  releaseRoomPeerMutex,
} from "./negotiationLock";

describe("room/peer negotiation lock", () => {
  test("reuses a lock only for the same room/peer pair", () => {
    const first = getRoomPeerMutex("room-a", "peer-a");

    expect(getRoomPeerMutex("room-a", "peer-a")).toBe(first);
    expect(getRoomPeerMutex("room-b", "peer-a")).not.toBe(first);
    expect(getRoomPeerMutex("room-a", "peer-b")).not.toBe(first);
  });

  test("length-prefixing prevents concatenation collisions", () => {
    expect(getRoomPeerMutex("ab", "c")).not.toBe(
      getRoomPeerMutex("a", "bc"),
    );
  });

  test("terminal release waits for an active critical section", async () => {
    const mutex = getRoomPeerMutex("release-room", "release-peer");
    let unblock!: () => void;
    const held = mutex.runExclusive(
      () =>
        new Promise<void>((resolve) => {
          unblock = resolve;
        }),
    );
    await Promise.resolve();

    releaseRoomPeerMutex("release-room", "release-peer");
    expect(hasRoomPeerMutex("release-room", "release-peer")).toBe(true);

    unblock();
    await held;
    await Promise.resolve();
    expect(hasRoomPeerMutex("release-room", "release-peer")).toBe(false);
  });

  test("serializes transient peer aliases by stable identity", async () => {
    const first = getRoomIdentityMutex("identity-room", "ed25519-key");
    const second = getRoomIdentityMutex("identity-room", "ed25519-key");
    expect(second).toBe(first);

    const order: string[] = [];
    let releaseFirst!: () => void;
    const held = first.runExclusive(
      () =>
        new Promise<void>((resolve) => {
          order.push("first");
          releaseFirst = resolve;
        }),
    );
    const queued = second.runExclusive(async () => {
      order.push("second");
    });
    await Promise.resolve();
    expect(order).toEqual(["first"]);
    releaseFirst();
    await Promise.all([held, queued]);
    expect(order).toEqual(["first", "second"]);
    releaseRoomIdentityMutex("identity-room", "ed25519-key");
  });
});
