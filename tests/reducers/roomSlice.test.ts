import { describe, expect, test } from "bun:test";

import {
  DEFAULT_ROOM_POLICY_V1,
  roomPoliciesEqualV1,
} from "../../src/roomPolicy";

(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

const {
  default: roomReducer,
  deletePeer,
  deleteRoom,
  setMessage,
  setPeerCoverStatus,
  setPeerHandshakeStatus,
  setRoom,
  setRoomPolicy,
} = await import("../../src/reducers/roomSlice");

describe("room policy reducer boundary", () => {
  test("new rooms receive the mandatory hybrid-v3 default", () => {
    const roomUrl = "a".repeat(64);
    const state = roomReducer(
      undefined,
      setRoom({ url: roomUrl, id: "" }),
    );

    expect(state).toHaveLength(1);
    expect(state[0].policy.pqMode).toBe("hybrid-mlkem768");
    expect("pin" in state[0].policy).toBe(false);
  });

  test("an existing room accepts an idempotent policy but rejects changes", () => {
    const roomUrl = "b".repeat(64);
    const initial = roomReducer(
      undefined,
      setRoom({ url: roomUrl, id: "", policy: DEFAULT_ROOM_POLICY_V1 }),
    );

    const idempotent = roomReducer(
      initial,
      setRoomPolicy({
        roomContext: roomUrl,
        policy: { ...DEFAULT_ROOM_POLICY_V1 },
      }),
    );
    expect(idempotent).toBe(initial);
    expect(
      roomPoliciesEqualV1(idempotent[0].policy, DEFAULT_ROOM_POLICY_V1),
    ).toBe(true);

    const changedPolicy = {
      ...DEFAULT_ROOM_POLICY_V1,
      revision: 1,
      authMode: "pin" as const,
    };
    expect(() =>
      roomReducer(
        idempotent,
        setRoomPolicy({ roomContext: roomUrl, policy: changedPolicy }),
      ),
    ).toThrow("room policy is immutable after creation");
    expect(
      roomPoliciesEqualV1(idempotent[0].policy, DEFAULT_ROOM_POLICY_V1),
    ).toBe(true);
  });

  test("setRoom cannot bypass immutability for an existing room", () => {
    const roomUrl = "c".repeat(64);
    const initial = roomReducer(
      undefined,
      setRoom({ url: roomUrl, id: "", policy: DEFAULT_ROOM_POLICY_V1 }),
    );
    const changedPolicy = {
      ...DEFAULT_ROOM_POLICY_V1,
      revision: 1,
      authMode: "pin" as const,
    };

    expect(() =>
      roomReducer(
        initial,
        setRoom({ url: roomUrl, id: "", policy: changedPolicy }),
      ),
    ).toThrow("room policy is immutable after creation");
    expect(roomPoliciesEqualV1(initial[0].policy, DEFAULT_ROOM_POLICY_V1)).toBe(
      true,
    );
  });

  test("disconnecting a retained room URL cannot downgrade its PIN policy", () => {
    const roomUrl = "d".repeat(64);
    const roomId = "00000000-0000-4000-8000-000000000004";
    const pinPolicy = {
      ...DEFAULT_ROOM_POLICY_V1,
      revision: 4,
      authMode: "pin" as const,
    };
    const connected = roomReducer(
      undefined,
      setRoom({ url: roomUrl, id: roomId, policy: pinPolicy }),
    );

    const disconnected = roomReducer(connected, deleteRoom(roomId));
    expect(disconnected[0].id).toBe("");
    expect(roomPoliciesEqualV1(disconnected[0].policy, pinPolicy)).toBe(true);

    expect(() =>
      roomReducer(
        disconnected,
        setRoomPolicy({ roomContext: roomUrl, policy: pinPolicy }),
      ),
    ).not.toThrow();
    expect(() =>
      roomReducer(
        disconnected,
        setRoomPolicy({
          roomContext: roomUrl,
          policy: DEFAULT_ROOM_POLICY_V1,
        }),
      ),
    ).toThrow("room policy is immutable after creation");
  });

  test("concurrent identical outbound content remains two logical messages", () => {
    const roomId = "00000000-0000-4000-8000-000000000005";
    const fromPeerId = "00000000-0000-4000-8000-000000000006";
    let state = roomReducer(
      undefined,
      setRoom({ url: "e".repeat(64), id: roomId }),
    );
    const common = {
      roomId,
      merkleRootHex: "",
      sha512Hex: "ff".repeat(64),
      fromPeerId,
      chunkSize: 0,
      totalSize: 10,
      chunksCreated: 1,
      totalChunks: 2,
      messageType: 1,
      filename: "same.txt",
      channelLabel: "main",
      timestamp: 123,
    };

    state = roomReducer(
      state,
      setMessage({ ...common, transferId: "11".repeat(32) }),
    );
    state = roomReducer(
      state,
      setMessage({ ...common, transferId: "22".repeat(32) }),
    );

    expect(state[0].messages).toHaveLength(2);
    expect(state[0].messages.map((message) => message.transferId)).toEqual([
      "11".repeat(32),
      "22".repeat(32),
    ]);
  });
});

describe("per-peer scheduled-cover status", () => {
  const roomId = "00000000-0000-4000-8000-0000000000aa";
  const peerId = "00000000-0000-4000-8000-0000000000bb";

  test("status transitions are stored per peer, including stopped", () => {
    let state = roomReducer(
      undefined,
      setRoom({ url: "f".repeat(64), id: roomId }),
    );
    expect(state[0].coverStatusByPeer).toBeUndefined();

    state = roomReducer(
      state,
      setPeerCoverStatus({ roomId, peerId, status: "starting" }),
    );
    expect(state[0].coverStatusByPeer).toEqual({ [peerId]: "starting" });

    state = roomReducer(
      state,
      setPeerCoverStatus({ roomId, peerId, status: "active" }),
    );
    state = roomReducer(
      state,
      setPeerCoverStatus({ roomId, peerId, status: "suspended" }),
    );
    expect(state[0].coverStatusByPeer).toEqual({ [peerId]: "suspended" });

    // A runtime teardown reports "stopped" explicitly: the UI must be able to
    // distinguish "cover halted" from "never scheduled" (absent).
    state = roomReducer(
      state,
      setPeerCoverStatus({ roomId, peerId, status: "stopped" }),
    );
    expect(state[0].coverStatusByPeer).toEqual({ [peerId]: "stopped" });
  });

  test("unknown room is a no-op and peer deletion clears the entry", () => {
    let state = roomReducer(
      undefined,
      setRoom({ url: "f".repeat(64), id: roomId }),
    );
    const untouched = roomReducer(
      state,
      setPeerCoverStatus({
        roomId: "00000000-0000-4000-8000-0000000000cc",
        peerId,
        status: "active",
      }),
    );
    expect(untouched).toBe(state);

    state = roomReducer(
      state,
      setPeerCoverStatus({ roomId, peerId, status: "active" }),
    );
    state = roomReducer(state, deletePeer({ roomId, peerId }));
    expect(state[0].coverStatusByPeer?.[peerId]).toBeUndefined();
  });
});

describe("per-peer handshake status", () => {
  const roomId = "00000000-0000-4000-8000-0000000000dd";
  const peerId = "00000000-0000-4000-8000-0000000000ee";

  test("authenticating → failed with reason and retry deadline", () => {
    let state = roomReducer(
      undefined,
      setRoom({ url: "9".repeat(64), id: roomId }),
    );
    expect(state[0].handshakeStatusByPeer).toBeUndefined();

    state = roomReducer(
      state,
      setPeerHandshakeStatus({ roomId, peerId, status: "authenticating" }),
    );
    expect(state[0].handshakeStatusByPeer?.[peerId]).toEqual({
      status: "authenticating",
      reason: undefined,
      retryAfter: undefined,
    });

    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId,
        status: "failed",
        reason: "pin-throttled",
        retryAfter: 1_753_500_000_000,
      }),
    );
    expect(state[0].handshakeStatusByPeer?.[peerId]).toEqual({
      status: "failed",
      reason: "pin-throttled",
      retryAfter: 1_753_500_000_000,
    });

    state = roomReducer(
      state,
      setPeerHandshakeStatus({ roomId, peerId, status: "authenticated" }),
    );
    expect(state[0].handshakeStatusByPeer?.[peerId]?.status).toBe(
      "authenticated",
    );

    state = roomReducer(state, deletePeer({ roomId, peerId }));
    expect(state[0].handshakeStatusByPeer?.[peerId]).toBeUndefined();
  });

  test("a failed handshake survives the peer teardown that follows it", () => {
    let state = roomReducer(
      undefined,
      setRoom({ url: "a".repeat(63) + "b", id: roomId }),
    );
    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId,
        status: "failed",
        reason: "pin-mismatch",
      }),
    );
    // The library tears the edge down immediately after a failed handshake;
    // the reason must remain so the UI can explain the missing peer.
    state = roomReducer(state, deletePeer({ roomId, peerId }));
    expect(state[0].handshakeStatusByPeer?.[peerId]).toEqual({
      status: "failed",
      reason: "pin-mismatch",
      retryAfter: undefined,
    });

    // A fresh attempt replaces it.
    state = roomReducer(
      state,
      setPeerHandshakeStatus({ roomId, peerId, status: "authenticating" }),
    );
    expect(state[0].handshakeStatusByPeer?.[peerId]?.status).toBe(
      "authenticating",
    );
    state = roomReducer(state, deletePeer({ roomId, peerId }));
    expect(state[0].handshakeStatusByPeer?.[peerId]).toBeUndefined();
  });
});
