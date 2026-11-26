// The PIN attempt limiter runs for real against the real database worker
// (db.worker.ts's own onmessage handler over fake-indexeddb), the same rows the
// browser writes. A "reload" is a second limiter over the same IndexedDB: it
// starts with empty in-tab state, exactly as a reloaded page does.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "bun:test";

import {
  MAX_PIN_ATTEMPTS,
  MAX_ROOM_PIN_FAILURES_PER_WINDOW,
  PIN_BACKOFF_BASE_MS,
  PIN_BACKOFF_MAX_MS,
  ROOM_PIN_FAILURE_WINDOW_MS,
  createPinAttemptLimiter,
  pinBackoffMs,
} from "../src/roomPinAttempts";

import type { PinAttemptStore } from "../src/roomPinAttempts";
import type { PinAttemptState } from "../src/db/types";

beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});

let nextWorkerId = 1;
const pendingWorkerCalls = new Map<
  number,
  { resolve: (value: unknown) => void; reject: (reason: Error) => void }
>();

const deliverWorkerReply = (message: unknown): void => {
  const reply = message as { id: number; result?: unknown; error?: unknown };
  const call = pendingWorkerCalls.get(reply.id);
  if (!call) return;
  pendingWorkerCalls.delete(reply.id);
  if (reply.error) call.reject(new Error(String(reply.error)));
  else call.resolve(reply.result);
};

const callWorker = async (
  method: string,
  ...args: unknown[]
): Promise<unknown> => {
  await import("../src/db/db.worker"); // installs onmessage once
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    deliverWorkerReply;
  const handler = (
    globalThis as unknown as {
      onmessage: (event: MessageEvent) => Promise<void>;
    }
  ).onmessage;
  const id = nextWorkerId++;
  return new Promise((resolve, reject) => {
    pendingWorkerCalls.set(id, { resolve, reject });
    void handler({
      data: structuredClone({ id, method, args }),
    } as MessageEvent);
  });
};

const workerStore: PinAttemptStore = {
  get: (roomId, id) =>
    callWorker("getPinAttemptState", roomId, id) as Promise<
      PinAttemptState | undefined
    >,
  increment: (roomId, id, now, maxImmediateAttempts, baseMs, maxMs) =>
    callWorker(
      "incrementPinAttemptState",
      roomId,
      id,
      now,
      maxImmediateAttempts,
      baseMs,
      maxMs,
    ) as Promise<PinAttemptState>,
  delete: async (roomId, id) => {
    await callWorker("deletePinAttemptState", roomId, id);
  },
};

const ROOM = "00000000-0000-4000-8000-00000000a003";
const OTHER_ROOM = "00000000-0000-4000-8000-00000000a004";
const KNOWN = "ab".repeat(32);
const NEVER_SEEN = "cd".repeat(32);
const T0 = 1_000_000;
const WINDOW = ROOM_PIN_FAILURE_WINDOW_MS;
const LIMIT = MAX_ROOM_PIN_FAILURES_PER_WINDOW;

/** A distinct, never-reused Ed25519-shaped identity per failure. */
const freshIdentity = (n: number): string => n.toString(16).padStart(64, "0");

const failFromFreshIdentities = async (
  limiter: ReturnType<typeof createPinAttemptLimiter>,
  count: number,
  start: number,
  room = ROOM,
): Promise<void> => {
  for (let i = 1; i <= count; i++)
    await limiter.recordFailure(room, freshIdentity(start + i), start + i);
};

const outcome = (attempt: Promise<void>): Promise<string> =>
  attempt.then(
    () => "allowed",
    (error: unknown) => (error instanceof Error ? error.message : "rejected"),
  );

const roomThrottledUntil = (until: number): string =>
  `PIN attempts from identities new to this room are temporarily throttled until ${new Date(until).toISOString()}`;

describe("per-room/per-peer PIN attempt backoff", () => {
  test("starts throttling after the third failure and doubles to the five-minute cap", () => {
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS - 1)).toBe(0);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS)).toBe(PIN_BACKOFF_BASE_MS);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 1)).toBe(PIN_BACKOFF_BASE_MS * 2);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 40)).toBe(PIN_BACKOFF_MAX_MS);
  });

  test("a per-identity backoff row written by 0.14.10 still throttles that identity", async () => {
    // 0.14.10 wrote exactly these rows through the same worker method.
    for (let i = 0; i < MAX_PIN_ATTEMPTS; i++)
      await callWorker(
        "incrementPinAttemptState",
        ROOM,
        NEVER_SEEN,
        T0,
        MAX_PIN_ATTEMPTS,
        PIN_BACKOFF_BASE_MS,
        PIN_BACKOFF_MAX_MS,
      );
    const limiter = createPinAttemptLimiter(workerStore);
    expect(
      await outcome(limiter.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 1)),
    ).toBe(
      `PIN retry for this peer identity is throttled until ${new Date(
        T0 + PIN_BACKOFF_BASE_MS,
      ).toISOString()}`,
    );
    expect(
      await outcome(
        limiter.assertAttemptAllowed(
          ROOM,
          NEVER_SEEN,
          T0 + PIN_BACKOFF_BASE_MS,
        ),
      ),
    ).toBe("allowed");
  });
});

describe("room-wide PIN failure window", () => {
  test("30 failures block a never-seen identity", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(tab, LIMIT - 1, T0);
    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe("allowed");

    await tab.recordFailure(ROOM, freshIdentity(T0 + LIMIT), T0 + LIMIT);
    // The window opened at the first failure and lasts WINDOW from there.
    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
    expect(
      await outcome(
        tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 1 + WINDOW),
      ),
    ).toBe("allowed");
  });

  test("room window survives reload", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(tab, LIMIT, T0);

    const reloaded = createPinAttemptLimiter(workerStore);
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
    expect(
      await outcome(
        reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 1 + WINDOW),
      ),
    ).toBe("allowed");
  });

  test("failures after a reload extend the persisted window's count, not its end", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(tab, LIMIT - 1, T0);

    const reloaded = createPinAttemptLimiter(workerStore);
    await reloaded.recordFailure(ROOM, freshIdentity(T0 + 500), T0 + 500);
    expect(
      await outcome(
        createPinAttemptLimiter(workerStore).assertAttemptAllowed(
          ROOM,
          NEVER_SEEN,
          T0 + 600,
        ),
      ),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
  });

  test("30 failures from fresh identities do not block a known peer", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(ROOM, KNOWN, T0);
    await failFromFreshIdentities(tab, LIMIT, T0);

    expect(await outcome(tab.assertAttemptAllowed(ROOM, KNOWN, T0 + 100))).toBe(
      "allowed",
    );
    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));

    const reloaded = createPinAttemptLimiter(workerStore);
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, KNOWN, T0 + 100)),
    ).toBe("allowed");
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
  });

  test("a known peer's success does not clear the room window", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(tab, LIMIT, T0);
    await tab.recordSuccess(ROOM, KNOWN, T0 + 50);

    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
    const reloaded = createPinAttemptLimiter(workerStore);
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
  });

  test("a known peer keeps its own per-identity backoff", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(ROOM, KNOWN, T0);
    for (let i = 0; i < MAX_PIN_ATTEMPTS; i++)
      await tab.recordFailure(ROOM, KNOWN, T0 + 10);
    expect(await outcome(tab.assertAttemptAllowed(ROOM, KNOWN, T0 + 11))).toBe(
      `PIN retry for this peer identity is throttled until ${new Date(
        T0 + 10 + PIN_BACKOFF_BASE_MS,
      ).toISOString()}`,
    );
  });

  test("a peer known in one room is new in another", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(OTHER_ROOM, KNOWN, T0);
    await failFromFreshIdentities(tab, LIMIT, T0);
    expect(await outcome(tab.assertAttemptAllowed(ROOM, KNOWN, T0 + 100))).toBe(
      roomThrottledUntil(T0 + 1 + WINDOW),
    );
  });

  test("a failure from a known peer counts toward the room window", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(ROOM, KNOWN, T0);
    await failFromFreshIdentities(tab, LIMIT - 1, T0);
    await tab.recordFailure(ROOM, KNOWN, T0 + 200);
    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 300)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
  });

  test("a full window that has ended starts counting again from one", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(tab, LIMIT, T0);
    const later = T0 + 1 + WINDOW;
    await tab.recordFailure(ROOM, freshIdentity(later), later);

    const reloaded = createPinAttemptLimiter(workerStore);
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, later + 1)),
    ).toBe("allowed");
    await failFromFreshIdentities(reloaded, LIMIT - 2, later);
    expect(
      await outcome(
        reloaded.assertAttemptAllowed(ROOM, NEVER_SEEN, later + 100),
      ),
    ).toBe("allowed");
    await reloaded.recordFailure(ROOM, NEVER_SEEN, later + LIMIT);
    expect(
      await outcome(
        createPinAttemptLimiter(workerStore).assertAttemptAllowed(
          ROOM,
          freshIdentity(later + 10_000),
          later + 100,
        ),
      ),
    ).toBe(roomThrottledUntil(later + WINDOW));
  });

  test("concurrent failures are all counted, including when they restart an ended window", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await Promise.all(
      Array.from({ length: LIMIT }, (_, i) =>
        tab.recordFailure(ROOM, freshIdentity(i + 1), T0),
      ),
    );
    expect(
      await outcome(
        createPinAttemptLimiter(workerStore).assertAttemptAllowed(
          ROOM,
          NEVER_SEEN,
          T0 + 1,
        ),
      ),
    ).toBe(roomThrottledUntil(T0 + WINDOW));

    // Every one of these finds the ended window; exactly one may restart it.
    // The first restart's delete is held until another failure has written
    // the window (or 50 ms pass, when writes are serialized and none can):
    // unserialized, that delete would erase the other failure's count.
    let releaseHeldDelete!: () => void;
    const otherWindowWrite = new Promise<void>((resolve) => {
      releaseHeldDelete = resolve;
    });
    let held = false;
    const lateDeleteStore: PinAttemptStore = {
      ...workerStore,
      increment: async (roomId, id, ...rest) => {
        const row = await workerStore.increment(roomId, id, ...rest);
        if (roomId !== ROOM) releaseHeldDelete();
        return row;
      },
      delete: async (roomId, id) => {
        if (!held && roomId !== ROOM) {
          held = true;
          await Promise.race([
            otherWindowWrite,
            new Promise((resolve) => setTimeout(resolve, 50)),
          ]);
        }
        await workerStore.delete(roomId, id);
      },
    };
    const sameTabLater = createPinAttemptLimiter(lateDeleteStore);
    const later = T0 + WINDOW + 10;
    await Promise.all(
      Array.from({ length: LIMIT }, (_, i) =>
        sameTabLater.recordFailure(ROOM, freshIdentity(1_000 + i), later),
      ),
    );
    expect(held).toBe(true);
    expect(
      await outcome(
        createPinAttemptLimiter(workerStore).assertAttemptAllowed(
          ROOM,
          NEVER_SEEN,
          later + 1,
        ),
      ),
    ).toBe(roomThrottledUntil(later + WINDOW));
  });

  test("a failed window write still counts in this tab", async () => {
    let failNextWindowWrite = true;
    const flakyStore: PinAttemptStore = {
      ...workerStore,
      increment: (roomId, id, ...rest) => {
        if (failNextWindowWrite && roomId !== ROOM) {
          failNextWindowWrite = false;
          return Promise.reject(new Error("injected: storage full"));
        }
        return workerStore.increment(roomId, id, ...rest);
      },
    };
    const tab = createPinAttemptLimiter(flakyStore);
    await expect(
      tab.recordFailure(ROOM, freshIdentity(T0 + 1), T0 + 1),
    ).rejects.toThrow("injected: storage full");
    await failFromFreshIdentities(tab, LIMIT - 1, T0 + 1);

    expect(
      await outcome(tab.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
    // The lost write is lost to a reload: the persisted window holds 29.
    expect(
      await outcome(
        createPinAttemptLimiter(workerStore).assertAttemptAllowed(
          ROOM,
          NEVER_SEEN,
          T0 + 100,
        ),
      ),
    ).toBe("allowed");
  });

  test("an unreadable known-peer record refuses the peer while the window is full", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(ROOM, KNOWN, T0);
    await failFromFreshIdentities(tab, LIMIT, T0);

    const unreadableKnown: PinAttemptStore = {
      ...workerStore,
      get: (roomId, id) =>
        id === KNOWN
          ? Promise.reject(new Error("injected: read failed"))
          : workerStore.get(roomId, id),
    };
    expect(
      await outcome(
        createPinAttemptLimiter(unreadableKnown).assertAttemptAllowed(
          ROOM,
          KNOWN,
          T0 + 100,
        ),
      ),
    ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
  });

  test("clearing a room removes its window, its known peers and every identity's backoff", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    await tab.recordSuccess(ROOM, KNOWN, T0);
    await tab.recordSuccess(OTHER_ROOM, KNOWN, T0);
    await failFromFreshIdentities(tab, LIMIT, T0);
    await failFromFreshIdentities(tab, LIMIT, T0, OTHER_ROOM);
    for (let i = 0; i < MAX_PIN_ATTEMPTS; i++)
      await tab.recordFailure(ROOM, NEVER_SEEN, T0 + 50);

    await tab.clear(ROOM);

    for (const limiter of [tab, createPinAttemptLimiter(workerStore)]) {
      expect(
        await outcome(limiter.assertAttemptAllowed(ROOM, NEVER_SEEN, T0 + 100)),
      ).toBe("allowed");
      // Untouched: the other room keeps its window and its known peer.
      expect(
        await outcome(
          limiter.assertAttemptAllowed(OTHER_ROOM, NEVER_SEEN, T0 + 100),
        ),
      ).toBe(roomThrottledUntil(T0 + 1 + WINDOW));
      expect(
        await outcome(
          limiter.assertAttemptAllowed(OTHER_ROOM, KNOWN, T0 + 100),
        ),
      ).toBe("allowed");
    }

    // KNOWN is no longer remembered in the cleared room.
    const reloaded = createPinAttemptLimiter(workerStore);
    await failFromFreshIdentities(reloaded, LIMIT, T0 + 1_000);
    expect(
      await outcome(reloaded.assertAttemptAllowed(ROOM, KNOWN, T0 + 1_100)),
    ).toBe(roomThrottledUntil(T0 + 1_001 + WINDOW));
  });

  test("a room ID cannot alias another room's window or known-peer record", async () => {
    const tab = createPinAttemptLimiter(workerStore);
    for (const aliasing of [
      `pin-room-window:${ROOM}`,
      `pin-known-peers:${ROOM}`,
    ]) {
      await expect(tab.recordFailure(aliasing, KNOWN, T0)).rejects.toThrow(
        "reserved",
      );
      await expect(tab.recordSuccess(aliasing, KNOWN, T0)).rejects.toThrow(
        "reserved",
      );
      await expect(
        tab.assertAttemptAllowed(aliasing, KNOWN, T0),
      ).rejects.toThrow("reserved");
    }
  });
});
