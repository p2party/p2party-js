import { afterEach, describe, expect, test } from "bun:test";

(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

const [
  {
    requestAllActiveRooms,
    requestRoomFromSignaling,
    requestRoomFromSignalingWithRetry,
  },
  {
    claimRoomResponse,
    completeRoomResponse,
    pendingRoomRequestId,
    resetRoomRequestLifecycle,
    roomRequestCoordinatorCounts,
  },
  { default: roomReducer, deleteRoom, setRoom },
] = await Promise.all([
  import("../../src/handlers/requestRoom"),
  import("../../src/utils/roomRequestCoordinator"),
  import("../../src/reducers/roomSlice"),
]);

import type { RoomRequestApi } from "../../src/handlers/requestRoom";

const PEER_ID = "00000000-0000-4000-8000-000000000001";
const ROOM_ID = "00000000-0000-4000-8000-000000000002";
const ROOM_URLS = ["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)];

afterEach(() => {
  resetRoomRequestLifecycle("test cleanup");
});

const stateWithRooms = () => {
  let rooms = roomReducer(
    undefined,
    setRoom({ url: ROOM_URLS[0], id: ROOM_ID }),
  );
  rooms = roomReducer(
    rooms,
    setRoom({
      url: ROOM_URLS[1],
      id: "00000000-0000-4000-8000-000000000003",
    }),
  );
  rooms = roomReducer(
    rooms,
    setRoom({
      url: ROOM_URLS[2],
      id: "00000000-0000-4000-8000-000000000004",
    }),
  );
  rooms = roomReducer(rooms, deleteRoom(ROOM_URLS[2]));
  return {
    keyPair: { peerId: PEER_ID },
    signalingServer: {
      isConnected: true,
      isVerified: true,
    },
    rooms,
  };
};

describe("room request orchestration", () => {
  test("fresh proof refreshes every retained active room, not the deleted room", async () => {
    const state = stateWithRooms();
    const api = {
      getState: () => state,
    } as unknown as RoomRequestApi;

    const refreshing = requestAllActiveRooms(api, () => Promise.resolve());
    expect(roomRequestCoordinatorCounts().pending).toBe(2);
    expect(pendingRoomRequestId(ROOM_URLS[2])).toBeNull();

    for (const roomUrl of ROOM_URLS.slice(0, 2)) {
      const requestId = pendingRoomRequestId(roomUrl);
      if (!requestId) throw new Error("active room request was not emitted");
      const claimed = claimRoomResponse(roomUrl, requestId);
      if (!claimed) throw new Error("active room response was not claimable");
      completeRoomResponse({
        ...claimed,
        roomId: ROOM_ID,
        expiresAtUnixSeconds: null,
      });
    }
    await refreshing;
    expect(roomRequestCoordinatorCounts().pending).toBe(0);
  });

  test("a signaling mutation error rejects immediately and clears pending state", async () => {
    const state = stateWithRooms();
    const api = {
      getState: () => state,
    } as unknown as RoomRequestApi;

    await expect(
      requestRoomFromSignaling(api, ROOM_URLS[0], () =>
        Promise.reject(new Error("WebSocket is not open")),
      ),
    ).rejects.toThrow("WebSocket is not open");
    expect(roomRequestCoordinatorCounts().pending).toBe(0);
  });

  test("a transient send failure retries only that room", async () => {
    const state = stateWithRooms();
    const api = {
      getState: () => state,
    } as unknown as RoomRequestApi;
    let attempts = 0;

    const response = requestRoomFromSignalingWithRetry(
      api,
      ROOM_URLS[0],
      (request) => {
        attempts += 1;
        if (attempts === 1)
          return Promise.reject(new Error("transient signaling failure"));
        const claimed = claimRoomResponse(
          request.roomUrl,
          request.roomRequestId!,
        );
        if (!claimed) throw new Error("retried response was not claimable");
        completeRoomResponse({
          ...claimed,
          roomId: ROOM_ID,
          expiresAtUnixSeconds: null,
        });
        return Promise.resolve();
      },
      { retryBaseMs: 1, maxRetryMs: 1, maxAttempts: 2 },
    );

    await response;
    expect(attempts).toBe(2);
  });

  test("bounded workers eventually process more rooms than the pending-request cap", async () => {
    const roomUrls = Array.from({ length: 300 }, (_, index) =>
      index.toString(16).padStart(64, "0"),
    );
    const state = {
      keyPair: { peerId: PEER_ID },
      signalingServer: { isConnected: true, isVerified: true },
      rooms: roomUrls.map((url) => ({ url, signalingActive: true })),
    };
    const api = {
      getState: () => state,
    } as unknown as RoomRequestApi;
    const emitted = new Set<string>();
    let maximumPending = 0;

    await requestAllActiveRooms(
      api,
      (request) => {
        emitted.add(request.roomUrl);
        maximumPending = Math.max(
          maximumPending,
          roomRequestCoordinatorCounts().pending,
        );
        const claimed = claimRoomResponse(
          request.roomUrl,
          request.roomRequestId!,
        );
        if (!claimed) throw new Error("worker response was not claimable");
        completeRoomResponse({
          ...claimed,
          roomId: ROOM_ID,
          expiresAtUnixSeconds: null,
        });
        return Promise.resolve();
      },
      { concurrency: 7 },
    );

    expect(emitted.size).toBe(300);
    expect(maximumPending).toBeLessThanOrEqual(7);
    expect(roomRequestCoordinatorCounts().pending).toBe(0);
  });
});
