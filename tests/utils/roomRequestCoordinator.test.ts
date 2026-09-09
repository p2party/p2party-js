import { afterEach, describe, expect, test } from "bun:test";

import {
  MAX_ACTIVE_SIGNALING_ROOMS,
  MAX_TURN_REFRESH_ATTEMPTS,
  canScheduleRoomCredentialRefresh,
  claimRoomResponse,
  clearRoomCredentialRefresh,
  clearRoomCredentialRefreshIfOwned,
  completeRoomResponse,
  markFreshSocketProof,
  pendingRoomRequestId,
  rejectRoomResponse,
  reserveRoomCredentialRefresh,
  finalizeRoomCredentialRefresh,
  requestRoomResponse,
  resetRoomRequestLifecycle,
  roomRequestCoordinatorCounts,
  scheduleRoomCredentialRefresh,
  turnRefreshRetryDelayMs,
  waitForFreshSocketProof,
} from "../../src/utils/roomRequestCoordinator";

import type { WebSocketMessageRoomIdRequest } from "../../src/utils/interfaces";

const PEER_ID = "00000000-0000-4000-8000-000000000001";
const ROOM_URL = "ab".repeat(32);
const OTHER_ROOM_URL = "cd".repeat(32);
const ROOM_ID = "00000000-0000-4000-8000-000000000002";
const REQUEST_ID = "00000000-0000-4000-8000-000000000003";
const NEXT_REQUEST_ID = "00000000-0000-4000-8000-000000000004";

const anotherRequestId = (roomRequestId: string): string =>
  roomRequestId === REQUEST_ID ? NEXT_REQUEST_ID : REQUEST_ID;

afterEach(() => {
  resetRoomRequestLifecycle("test cleanup");
});

describe("wire-correlated room requests", () => {
  test("only the exact echoed UUID can claim and complete a pending request", async () => {
    let sent: WebSocketMessageRoomIdRequest | undefined;
    const pending = requestRoomResponse(PEER_ID, ROOM_URL, (request) => {
      sent = request;
    });

    expect(sent?.type).toBe("room");
    expect(sent?.fromPeerId).toBe(PEER_ID);
    expect(sent?.roomUrl).toBe(ROOM_URL);
    expect(sent?.protocolVersion).toBe(4);
    const requestId = sent?.roomRequestId;
    if (!requestId) throw new Error("expected mandatory request correlation");
    expect(claimRoomResponse(ROOM_URL, anotherRequestId(requestId))).toBeNull();
    const claimed = claimRoomResponse(ROOM_URL, requestId);
    expect(claimed).not.toBeNull();
    if (!claimed) throw new Error("expected exact request claim");

    expect(
      completeRoomResponse({
        ...claimed,
        roomId: ROOM_ID,
        expiresAtUnixSeconds: null,
      }),
    ).toBe(true);
    expect(await pending).toEqual({
      ...claimed,
      roomId: ROOM_ID,
      expiresAtUnixSeconds: null,
    });
    expect(pendingRoomRequestId(ROOM_URL)).toBeNull();
  });

  test("old and unsolicited responses cannot claim a later generation", async () => {
    expect(claimRoomResponse(ROOM_URL, REQUEST_ID)).toBeNull();

    let firstRequestId = "";
    const first = requestRoomResponse(PEER_ID, ROOM_URL, (request) => {
      firstRequestId = request.roomRequestId;
    });
    const firstClaim = claimRoomResponse(ROOM_URL, firstRequestId);
    if (!firstClaim) throw new Error("first claim missing");
    completeRoomResponse({
      ...firstClaim,
      roomId: ROOM_ID,
      expiresAtUnixSeconds: null,
    });
    await first;

    let secondRequestId = "";
    const second = requestRoomResponse(PEER_ID, ROOM_URL, (request) => {
      secondRequestId = request.roomRequestId;
    });
    expect(secondRequestId).not.toBe(firstRequestId);
    expect(claimRoomResponse(ROOM_URL, firstRequestId)).toBeNull();
    const secondClaim = claimRoomResponse(ROOM_URL, secondRequestId);
    expect(secondClaim?.requestGeneration).toBeGreaterThan(
      firstClaim.requestGeneration,
    );
    rejectRoomResponse(
      ROOM_URL,
      secondRequestId,
      new Error("expected test rejection"),
    );
    await expect(second).rejects.toThrow("expected test rejection");
  });

  test("different rooms remain independent single flights", async () => {
    let firstRequestId = "";
    const first = requestRoomResponse(PEER_ID, ROOM_URL, (request) => {
      firstRequestId = request.roomRequestId;
    });
    let secondRequestId = "";
    const second = requestRoomResponse(PEER_ID, OTHER_ROOM_URL, (request) => {
      secondRequestId = request.roomRequestId;
    });
    expect(roomRequestCoordinatorCounts().pending).toBe(2);

    for (const [roomUrl, roomRequestId, pending] of [
      [ROOM_URL, firstRequestId, first],
      [OTHER_ROOM_URL, secondRequestId, second],
    ] as const) {
      const claimed = claimRoomResponse(roomUrl, roomRequestId);
      if (!claimed) throw new Error("room claim missing");
      completeRoomResponse({
        ...claimed,
        roomId: ROOM_ID,
        expiresAtUnixSeconds: null,
      });
      await pending;
    }
    expect(roomRequestCoordinatorCounts().pending).toBe(0);
  });

  test("socket teardown rejects pending requests and proof waiters, clears TURN state, and leaves no lifecycle handles", async () => {
    let managedTurn = true;
    let liveConfiguration = "managed";
    const pending = requestRoomResponse(PEER_ID, ROOM_URL, () => undefined);
    const proof = waitForFreshSocketProof(false);
    scheduleRoomCredentialRefresh(
      ROOM_URL,
      Math.floor(Date.now() / 1_000) + 3_600,
      () => Promise.resolve(),
      async () => {
        managedTurn = false;
        await Promise.resolve();
        liveConfiguration = "caller";
      },
    );
    expect(roomRequestCoordinatorCounts()).toEqual({
      pending: 1,
      proofWaiters: 1,
      retryWaiters: 0,
      refreshTimers: 1,
      refreshReservations: 0,
    });

    const pendingRejected = pending.catch((error: unknown) => error);
    const proofRejected = proof.catch((error: unknown) => error);
    resetRoomRequestLifecycle("socket closed in test");
    const [pendingError, proofError] = await Promise.all([
      pendingRejected,
      proofRejected,
    ]);
    expect(pendingError).toBeInstanceOf(Error);
    expect((pendingError as Error).message).toContain("socket closed in test");
    expect(proofError).toBeInstanceOf(Error);
    expect((proofError as Error).message).toContain("socket closed in test");
    await Promise.resolve();

    expect(managedTurn).toBe(false);
    expect(liveConfiguration).toBe("caller");
    expect(roomRequestCoordinatorCounts()).toEqual({
      pending: 0,
      proofWaiters: 0,
      retryWaiters: 0,
      refreshTimers: 0,
      refreshReservations: 0,
    });
  });

  test("a completed fresh proof clears every waiter exactly once", async () => {
    const first = waitForFreshSocketProof(false);
    const second = waitForFreshSocketProof(false);
    expect(second).toBe(first);
    expect(roomRequestCoordinatorCounts().proofWaiters).toBe(1);
    markFreshSocketProof();
    await Promise.all([first, second]);
    expect(roomRequestCoordinatorCounts().proofWaiters).toBe(0);
    markFreshSocketProof();
    expect(roomRequestCoordinatorCounts().proofWaiters).toBe(0);
  });
});

describe("TURN refresh lifecycle", () => {
  test("retries a transient failure with bounded exponential backoff", async () => {
    const expiry = Math.floor(Date.now() / 1_000) + 60;
    let attempts = 0;
    let expired = false;
    let resolveSuccess = () => {};
    const success = new Promise<void>((resolve) => {
      resolveSuccess = resolve;
    });

    scheduleRoomCredentialRefresh(
      ROOM_URL,
      expiry,
      () => {
        attempts += 1;
        if (attempts === 1) return Promise.reject(new Error("transient"));
        resolveSuccess();
        return Promise.resolve();
      },
      () => {
        expired = true;
      },
      {
        nowMs: expiry * 1_000 - 5 * 60_000 - 1,
        retryBaseMs: 2,
        maxRetryMs: 4,
        maxAttempts: 2,
        minimumInitialDelayMs: 1,
      },
    );

    await success;
    expect(attempts).toBe(2);
    expect(expired).toBe(false);
  });

  test("retry delay is capped and exhaustion waits only for fail-closed expiry", () => {
    expect(turnRefreshRetryDelayMs(1, 60_000)).toBe(1_000);
    expect(turnRefreshRetryDelayMs(7, 60_000)).toBe(30_000);
    expect(turnRefreshRetryDelayMs(MAX_TURN_REFRESH_ATTEMPTS + 1, 12_345)).toBe(
      12_345,
    );
  });

  test("an expired bundle invokes the fail-closed removal callback", async () => {
    const expiry = Math.floor(Date.now() / 1_000) - 1;
    let refreshes = 0;
    let resolveExpired = () => {};
    const expired = new Promise<void>((resolve) => {
      resolveExpired = resolve;
    });

    scheduleRoomCredentialRefresh(
      ROOM_URL,
      expiry,
      () => {
        refreshes += 1;
        return Promise.resolve();
      },
      resolveExpired,
      {
        nowMs: expiry * 1_000 - 5 * 60_000 - 1,
        minimumInitialDelayMs: 1,
      },
    );
    await expired;
    expect(refreshes).toBe(0);
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(0);
  });

  test("crossing expiry while refresh is awaited removes credentials without scheduling a stale retry", async () => {
    const expiry = Math.floor(Date.now() / 1_000) + 60;
    let currentTime = expiry * 1_000 - 100;
    let rejectRefresh = (_error: Error) => {};
    const refreshStarted = Promise.withResolvers<void>();
    const refreshDeferred = new Promise<void>((_resolve, reject) => {
      rejectRefresh = reject;
    });
    const expired = Promise.withResolvers<void>();

    scheduleRoomCredentialRefresh(
      ROOM_URL,
      expiry,
      () => {
        refreshStarted.resolve();
        return refreshDeferred;
      },
      () => expired.resolve(),
      {
        nowMs: expiry * 1_000 - 5 * 60_000 - 1,
        now: () => currentTime,
        minimumInitialDelayMs: 1,
        retryBaseMs: 60_000,
      },
    );

    await refreshStarted.promise;
    currentTime = expiry * 1_000 + 1;
    rejectRefresh(new Error("network completed after credential expiry"));
    await expired.promise;
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(0);
  });

  test("timer replacement cancels the old lifecycle and keeps one SSOT entry", async () => {
    let oldExpired = false;
    let resolveNewExpired = () => {};
    const newExpired = new Promise<void>((resolve) => {
      resolveNewExpired = resolve;
    });
    scheduleRoomCredentialRefresh(
      ROOM_URL,
      Math.floor(Date.now() / 1_000) + 3_600,
      () => Promise.resolve(),
      () => {
        oldExpired = true;
      },
    );
    const expired = Math.floor(Date.now() / 1_000) - 1;
    scheduleRoomCredentialRefresh(
      ROOM_URL,
      expired,
      () => Promise.resolve(),
      resolveNewExpired,
      {
        nowMs: expired * 1_000 - 5 * 60_000 - 1,
        minimumInitialDelayMs: 1,
      },
    );
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(1);
    await newExpired;
    expect(oldExpired).toBe(false);
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(0);
  });

  test("the timer bound is atomic for rejection and permits in-place replacement", () => {
    const expiry = Math.floor(Date.now() / 1_000) + 3_600;
    const urls = Array.from(
      { length: MAX_ACTIVE_SIGNALING_ROOMS },
      (_, index) => index.toString(16).padStart(64, "0"),
    );
    for (const roomUrl of urls)
      scheduleRoomCredentialRefresh(roomUrl, expiry, () => Promise.resolve());

    const extraRoom = "f".repeat(64);
    expect(canScheduleRoomCredentialRefresh(extraRoom, expiry)).toBe(false);
    expect(canScheduleRoomCredentialRefresh(urls[0], expiry)).toBe(true);
    expect(canScheduleRoomCredentialRefresh(extraRoom, null)).toBe(true);
    expect(() =>
      scheduleRoomCredentialRefresh(extraRoom, expiry, () => Promise.resolve()),
    ).toThrow("room refresh timer bound is exhausted");
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(
      MAX_ACTIVE_SIGNALING_ROOMS,
    );

    expect(() =>
      scheduleRoomCredentialRefresh(urls[0], expiry + 60, () =>
        Promise.resolve(),
      ),
    ).not.toThrow();
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(
      MAX_ACTIVE_SIGNALING_ROOMS,
    );
    clearRoomCredentialRefresh(urls[0]);
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(
      MAX_ACTIVE_SIGNALING_ROOMS - 1,
    );
  });

  test("a reservation consumes capacity until synchronous finalization", () => {
    const expiry = Math.floor(Date.now() / 1_000) + 3_600;
    const urls = Array.from(
      { length: MAX_ACTIVE_SIGNALING_ROOMS - 1 },
      (_, index) => index.toString(16).padStart(64, "0"),
    );
    for (const roomUrl of urls)
      scheduleRoomCredentialRefresh(roomUrl, expiry, () => Promise.resolve());

    const reservedRoom = "e".repeat(64);
    const extraRoom = "f".repeat(64);
    const reservation = reserveRoomCredentialRefresh(reservedRoom, expiry);
    expect(roomRequestCoordinatorCounts()).toEqual({
      pending: 0,
      proofWaiters: 0,
      retryWaiters: 0,
      refreshTimers: MAX_ACTIVE_SIGNALING_ROOMS - 1,
      refreshReservations: 1,
    });
    expect(canScheduleRoomCredentialRefresh(extraRoom, expiry)).toBe(false);

    finalizeRoomCredentialRefresh(reservation, expiry, () => Promise.resolve());
    expect(roomRequestCoordinatorCounts()).toEqual({
      pending: 0,
      proofWaiters: 0,
      retryWaiters: 0,
      refreshTimers: MAX_ACTIVE_SIGNALING_ROOMS,
      refreshReservations: 0,
    });
  });

  test("stale response cleanup cannot clear a newer same-room refresh timer", () => {
    const expiry = Math.floor(Date.now() / 1_000) + 3_600;
    const oldReservation = reserveRoomCredentialRefresh(ROOM_URL, expiry);

    // Room deletion/socket reset cancels the old in-flight owner.
    clearRoomCredentialRefresh(ROOM_URL);
    const newReservation = reserveRoomCredentialRefresh(ROOM_URL, expiry + 60);
    finalizeRoomCredentialRefresh(newReservation, expiry + 60, () =>
      Promise.resolve(),
    );

    expect(clearRoomCredentialRefreshIfOwned(oldReservation)).toBe(false);
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(1);
    expect(clearRoomCredentialRefreshIfOwned(newReservation)).toBe(true);
    expect(roomRequestCoordinatorCounts().refreshTimers).toBe(0);
  });
});
