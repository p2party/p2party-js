import { describe, expect, test } from "bun:test";

import {
  getRoomPeerMutex,
  getRoomIdentityMutex,
  getRoomIceConfigurationMutex,
  hasRoomIceConfigurationMutex,
  hasRoomPeerMutex,
  releaseRoomIdentityMutex,
  releaseRoomIceConfigurationMutex,
  releaseRoomPeerMutex,
  roomPeerMutexCount,
  runRoomPeerExclusive,
} from "../../../src/api/webrtc/negotiationLock";
import { assertTransportIdentityCurrent } from "../../../src/utils/transportIdentity";

describe("room/peer negotiation lock", () => {
  test("reuses a lock only for the same room/peer pair", () => {
    const first = getRoomPeerMutex("room-a", "peer-a");

    expect(getRoomPeerMutex("room-a", "peer-a")).toBe(first);
    expect(getRoomPeerMutex("room-b", "peer-a")).not.toBe(first);
    expect(getRoomPeerMutex("room-a", "peer-b")).not.toBe(first);
  });

  test("length-prefixing prevents concatenation collisions", () => {
    expect(getRoomPeerMutex("ab", "c")).not.toBe(getRoomPeerMutex("a", "bc"));
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

  test("repeated unknown-peer frames cannot retain mutex registry keys", async () => {
    const baseline = roomPeerMutexCount();
    for (let index = 0; index < 128; index += 1) {
      await runRoomPeerExclusive(
        "adversarial-room",
        `unknown-peer-${String(index)}`,
        async () => undefined,
      );
    }
    await Promise.resolve();
    await Promise.resolve();

    expect(roomPeerMutexCount()).toBe(baseline);
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

  test("a PC queued during a room response reads configuration only after publication", async () => {
    const mutex = getRoomIceConfigurationMutex("configuration-room");
    let authoritativeConfiguration = "old";
    let constructedWith: string | undefined;

    await mutex.acquire();
    const construct = (async () => {
      await mutex.acquire();
      try {
        constructedWith = authoritativeConfiguration;
      } finally {
        mutex.release();
      }
    })();
    await Promise.resolve();
    expect(constructedWith).toBeUndefined();

    authoritativeConfiguration = "new";
    mutex.release();
    await construct;
    expect(constructedWith).toBe("new");
  });

  test("room configuration mutex release waits for the active transition", async () => {
    const roomId = "configuration-release-room";
    const mutex = getRoomIceConfigurationMutex(roomId);
    await mutex.acquire();
    releaseRoomIceConfigurationMutex(roomId);
    expect(hasRoomIceConfigurationMutex(roomId)).toBe(true);
    mutex.release();
    await Promise.resolve();
    expect(hasRoomIceConfigurationMutex(roomId)).toBe(false);
  });

  test("a failed pending-room response releases its stable room-URL mutex", async () => {
    const roomUrl = "a".repeat(64);
    getRoomIceConfigurationMutex(roomUrl);
    releaseRoomIceConfigurationMutex(roomUrl);
    await Promise.resolve();
    expect(hasRoomIceConfigurationMutex(roomUrl)).toBe(false);
  });

  test("terminal configuration cleanup survives an immediate reacquire at the idle handoff", async () => {
    const roomId = "configuration-reacquire-room";
    const mutex = getRoomIceConfigurationMutex(roomId);
    await mutex.acquire();
    releaseRoomIceConfigurationMutex(roomId);
    mutex.release();
    await mutex.acquire();
    await Promise.resolve();
    expect(hasRoomIceConfigurationMutex(roomId)).toBe(true);
    mutex.release();
    await Promise.resolve();
    await Promise.resolve();
    expect(hasRoomIceConfigurationMutex(roomId)).toBe(false);
  });

  test("room teardown completes before an immediate same-URL reactivation", async () => {
    const roomUrl = "b".repeat(64);
    const mutex = getRoomIceConfigurationMutex(roomUrl);
    const order: string[] = [];
    let finishTeardown!: () => void;
    const teardownGate = new Promise<void>((resolve) => {
      finishTeardown = resolve;
    });
    const teardown = mutex.runExclusive(async () => {
      order.push("teardown-start");
      await teardownGate;
      order.push("teardown-finish");
    });
    const reactivate = mutex.runExclusive(async () => {
      order.push("reactivate");
    });
    await Promise.resolve();
    expect(order).toEqual(["teardown-start"]);
    finishTeardown();
    await Promise.all([teardown, reactivate]);
    expect(order).toEqual(["teardown-start", "teardown-finish", "reactivate"]);
    releaseRoomIceConfigurationMutex(roomUrl);
  });

  test("purge/reset during the final config wait cannot resurrect a transport", async () => {
    const roomUrl = "c".repeat(64);
    const initialIdentity = "ab".repeat(32);
    let currentIdentity = initialIdentity;
    let inserted = false;
    const mutex = getRoomIceConfigurationMutex(roomUrl);
    await mutex.acquire();
    const create = mutex
      .runExclusive(async () => {
        assertTransportIdentityCurrent(initialIdentity, currentIdentity);
        inserted = true;
      })
      .catch((error: unknown) => error);
    currentIdentity = "";
    mutex.release();
    const error = await create;
    expect(error).toBeInstanceOf(Error);
    expect(inserted).toBe(false);
    releaseRoomIceConfigurationMutex(roomUrl);
  });
});
