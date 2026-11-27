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
  defaultRTCConfig,
  setMessage,
  hydrateRoomHistory,
  resetMessageReceiveProgress,
  setIceServers,
  setChannel,
  setPeer,
  setKnownRoomPeers,
  setPeerCoverStatus,
  setPeerHandshakeStatus,
  clearPeerHandshakeStatus,
  setRoom,
  setRoomPolicy,
  purgeAllRooms,
} = await import("../../src/reducers/roomSlice");
const { MAX_SIGNALING_ROOM_PEERS } =
  await import("../../src/utils/signalingBounds");

test("history hydration is idempotent across a reload and retains repeated logical sends", () => {
  const roomId = "00000000-0000-4000-8000-000000000017";
  const initial = roomReducer(
    [],
    setRoom({ url: "ac".repeat(32), id: roomId }),
  );
  const messages = Array.from({ length: 2000 }, (_, i) => ({
    transferId: i.toString(16).padStart(64, "0"),
    merkleRootHex: "ab".repeat(64),
    sha512Hex: "cd".repeat(64),
    fromPeerId: roomId,
    filename: "photo",
    messageType: 1,
    savedSize: 4,
    totalSize: 10,
    chunksCreated: 0,
    totalChunks: 0,
    channelLabel: "images",
    timestamp: 1000,
  }));
  const action = hydrateRoomHistory({ roomId, messages });
  const once = roomReducer(initial, action);
  const twice = roomReducer(once, action);
  expect(twice[0].messages).toHaveLength(2000);
  expect(twice[0].messages.at(-1)?.savedSize).toBe(4);
  expect(twice[0].messages[0].transferId).not.toBe(
    twice[0].messages[1].transferId,
  );
});

describe("room policy reducer boundary", () => {
  test("member discovery survives transport teardown but replacement snapshots and leave remove it", () => {
    const roomId = "00000000-0000-4000-8000-0000000000e6",
      url = "e6".repeat(32);
    const b = {
      peerId: "00000000-0000-4000-8000-000000000002",
      peerPublicKey: "22".repeat(32),
    };
    const c = {
      peerId: "00000000-0000-4000-8000-000000000003",
      peerPublicKey: "33".repeat(32),
    };
    let state = roomReducer(undefined, setRoom({ url, id: roomId }));
    state = roomReducer(state, setKnownRoomPeers({ roomId, peers: [b, c] }));
    state = roomReducer(state, setPeer({ roomId, ...c }));
    state = roomReducer(state, deletePeer({ roomId, peerId: c.peerId }));
    expect(state[0].peers).toEqual([]);
    expect(state[0].knownPeers).toEqual([b, c]);
    state = roomReducer(state, setKnownRoomPeers({ roomId, peers: [b] }));
    expect(state[0].knownPeers).toEqual([b]);
    state = roomReducer(state, deleteRoom(roomId));
    state = roomReducer(state, setKnownRoomPeers({ roomId, peers: [b, c] }));
    expect(state[0].knownPeers).toBeUndefined();
    expect(state[0].signalingActive).toBe(false);
  });
  test("deliberate retry clears failed handshakes and preserves authenticated peers", () => {
    const roomUrl = "e5".repeat(32);
    const roomId = "00000000-0000-4000-8000-0000000000e5";
    let state = roomReducer(undefined, setRoom({ url: roomUrl, id: roomId }));
    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId: "failed-peer",
        status: "failed",
        reason: "pin-mismatch",
      }),
    );
    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId: "healthy-peer",
        status: "authenticated",
      }),
    );
    const retried = roomReducer(state, {
      type: "rooms/clearPeerHandshakeFailures",
      payload: roomUrl,
    });
    expect(retried[0].handshakeStatusByPeer?.["failed-peer"]).toBeUndefined();
    expect(retried[0].handshakeStatusByPeer?.["healthy-peer"]?.status).toBe(
      "authenticated",
    );
  });

  test("new rooms receive the mandatory hybrid-v3 default", () => {
    const roomUrl = "a".repeat(64);
    const state = roomReducer(undefined, setRoom({ url: roomUrl, id: "" }));

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

  test("deleting by URL targets the exact pending room when ids are still empty", () => {
    const firstUrl = "1".repeat(64);
    const secondUrl = "2".repeat(64);
    let state = roomReducer(undefined, setRoom({ url: firstUrl, id: "" }));
    state = roomReducer(state, setRoom({ url: secondUrl, id: "" }));

    const next = roomReducer(state, deleteRoom(secondUrl));
    expect(next.find((room) => room.url === firstUrl)?.signalingActive).toBe(
      true,
    );
    expect(next.find((room) => room.url === secondUrl)?.signalingActive).toBe(
      false,
    );
  });

  test("reactivating a tombstone cannot bypass the active signaling-room bound", () => {
    const tombstoneUrl = "e".repeat(64);
    let state = roomReducer(undefined, setRoom({ url: tombstoneUrl, id: "" }));
    state = roomReducer(state, deleteRoom(tombstoneUrl));
    for (let index = 0; index < 256; index++)
      state = roomReducer(
        state,
        setRoom({
          url: (index + 1).toString(16).padStart(64, "0"),
          id: "",
        }),
      );

    expect(() =>
      roomReducer(state, setRoom({ url: tombstoneUrl, id: "" })),
    ).toThrow("cannot activate more than 256 rooms");
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

describe("signaling-derived room state bounds", () => {
  test("peer and per-channel membership cannot exceed the room edge cap", () => {
    const roomId = "00000000-0000-4000-8000-0000000000aa";
    let state = roomReducer(
      undefined,
      setRoom({ url: "f".repeat(64), id: roomId }),
    );

    for (let index = 0; index <= MAX_SIGNALING_ROOM_PEERS; index += 1) {
      const peerId = `00000000-0000-4000-8000-${index
        .toString(16)
        .padStart(12, "0")}`;
      state = roomReducer(
        state,
        setPeer({
          roomId,
          peerId,
          peerPublicKey: index.toString(16).padStart(64, "0"),
        }),
      );
      state = roomReducer(state, setChannel({ roomId, peerId, label: "main" }));
    }

    expect(state[0].peers).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
    expect(state[0].channels[0].peerIds).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
  });

  test("full purge removes capabilities and all retained room state", () => {
    let state = roomReducer(
      undefined,
      setRoom({
        url: "e".repeat(64),
        id: "00000000-0000-4000-8000-0000000000ab",
      }),
    );
    state = roomReducer(
      state,
      setPeer({
        roomId: state[0].id,
        peerId: "00000000-0000-4000-8000-0000000000ac",
        peerPublicKey: "ab".repeat(32),
      }),
    );
    state = roomReducer(state, deleteRoom(state[0].url));
    expect(state).toHaveLength(1);
    expect(state[0].url).toBe("e".repeat(64));

    state = roomReducer(state, purgeAllRooms());
    expect(state).toEqual([]);
  });
});

describe("room ICE configuration", () => {
  const roomId = "00000000-0000-4000-8000-000000000080";

  test("an explicit reconnect RTC configuration replaces the caller baseline", () => {
    const roomUrl = "6".repeat(64);
    const callerConfig: RTCConfiguration = {
      iceServers: [{ urls: "stun:caller.example:3478" }],
      iceTransportPolicy: "all",
    };
    const state = roomReducer(
      undefined,
      setRoom({ url: roomUrl, id: roomId, rtcConfig: callerConfig }),
    );
    expect(
      roomReducer(
        state,
        setRoom({
          url: roomUrl,
          id: roomId,
          rtcConfig: structuredClone(callerConfig),
        }),
      )[0].callerRtcConfig,
    ).toEqual(callerConfig);
    const changed = roomReducer(
      state,
      setRoom({
        url: roomUrl,
        id: roomId,
        rtcConfig: {
          iceServers: [{ urls: "stun:different.example:3478" }],
        },
      }),
    );
    expect(changed[0].callerRtcConfig.iceServers).toEqual([
      { urls: "stun:different.example:3478" },
    ]);
    expect(changed[0].rtcConfig.iceServers).toEqual([
      { urls: "stun:different.example:3478" },
    ]);
  });

  test("TURN refresh preserves caller RTC options and unrelated STUN", () => {
    const callerConfig: RTCConfiguration = {
      bundlePolicy: "max-bundle",
      iceCandidatePoolSize: 7,
      iceTransportPolicy: "relay",
      iceServers: [
        { urls: "stun:custom.example:3478" },
        {
          urls: ["turns:relay.example:443", "turn:old.example:3478"],
          username: "expired",
          credential: "expired",
        },
      ],
    };
    let state = roomReducer(
      undefined,
      setRoom({
        url: "8".repeat(64),
        id: roomId,
        rtcConfig: callerConfig,
      }),
    );

    state = roomReducer(
      state,
      setIceServers({
        roomId,
        iceServers: [
          {
            urls: ["turns:relay.example:443"],
            username: "fresh",
            credential: "fresh",
          },
        ],
      }),
    );

    expect(state[0].rtcConfig.bundlePolicy).toBe("max-bundle");
    expect(state[0].rtcConfig.iceCandidatePoolSize).toBe(7);
    expect(state[0].rtcConfig.iceTransportPolicy).toBe("relay");
    expect(state[0].rtcConfig.iceServers).toEqual([
      { urls: "stun:custom.example:3478" },
      {
        urls: ["turn:old.example:3478"],
        username: "expired",
        credential: "expired",
      },
      {
        urls: ["turns:relay.example:443"],
        username: "fresh",
        credential: "fresh",
      },
    ]);
    expect(callerConfig.iceServers?.[1]).toEqual({
      urls: ["turns:relay.example:443", "turn:old.example:3478"],
      username: "expired",
      credential: "expired",
    });
  });

  test("TURN can populate an empty ICE list without mutating defaults", () => {
    const defaultBefore = structuredClone(defaultRTCConfig);
    let state = roomReducer(
      undefined,
      setRoom({
        url: "7".repeat(64),
        id: roomId,
        rtcConfig: { iceTransportPolicy: "all" },
      }),
    );
    state = roomReducer(
      state,
      setIceServers({
        roomId,
        iceServers: [
          {
            urls: "turn:relay.example:3478",
            username: "fresh",
            credential: "fresh",
          },
        ],
      }),
    );

    expect(state[0].rtcConfig.iceServers).toEqual([
      {
        urls: "turn:relay.example:3478",
        username: "fresh",
        credential: "fresh",
      },
    ]);
    expect(defaultRTCConfig).toEqual(defaultBefore);
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

  test("a retired generation's status is cleared, its roster entry and a failure are kept", () => {
    const peerPublicKey = "d".repeat(64);
    const otherPeerId = "00000000-0000-4000-8000-0000000000ef";
    let state = roomReducer(
      undefined,
      setRoom({ url: "c".repeat(63) + "d", id: roomId }),
    );
    state = roomReducer(state, setPeer({ roomId, peerId, peerPublicKey }));
    state = roomReducer(
      state,
      setPeerHandshakeStatus({ roomId, peerId, status: "authenticated" }),
    );
    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId: otherPeerId,
        status: "failed",
        reason: "policy",
      }),
    );

    state = roomReducer(state, clearPeerHandshakeStatus({ roomId, peerId }));
    state = roomReducer(
      state,
      clearPeerHandshakeStatus({ roomId, peerId: otherPeerId }),
    );

    expect(state[0].handshakeStatusByPeer?.[peerId]).toBeUndefined();
    expect(state[0].peers).toEqual([{ peerId, peerPublicKey }]);
    expect(state[0].handshakeStatusByPeer?.[otherPeerId]?.status).toBe(
      "failed",
    );
  });

  test("a failure carries the stable peer identity, not just the peerId", () => {
    const peerPublicKey = "c".repeat(64);
    let state = roomReducer(
      undefined,
      setRoom({ url: "b".repeat(63) + "c", id: roomId }),
    );
    state = roomReducer(state, setPeer({ roomId, peerId, peerPublicKey }));
    state = roomReducer(
      state,
      setPeerHandshakeStatus({
        roomId,
        peerId,
        peerPublicKey,
        status: "failed",
        reason: "pin-mismatch",
      }),
    );
    expect(state[0].handshakeStatusByPeer?.[peerId]?.peerPublicKey).toBe(
      peerPublicKey,
    );

    // The peerId is transient — a joiner that failed is dropped from the
    // roster and comes back under a new one — so the identity is what a UI
    // must key the failure on, and it has to outlive the teardown too.
    state = roomReducer(state, deletePeer({ roomId, peerId }));
    expect(state[0].peers).toHaveLength(0);
    expect(state[0].handshakeStatusByPeer?.[peerId]).toEqual({
      status: "failed",
      reason: "pin-mismatch",
      retryAfter: undefined,
      peerPublicKey,
    });
  });
});

describe("received message progress", () => {
  test("a failed verification resets the message's progress without moving it", () => {
    const roomId = "00000000-0000-4000-8000-0000000000e7";
    const fromPeerId = "00000000-0000-4000-8000-0000000000e8";
    let state = roomReducer(
      undefined,
      setRoom({ url: "e7".repeat(32), id: roomId }),
    );
    const roots = ["a1", "b2", "c3"].map((byte) => byte.repeat(64));
    for (const merkleRootHex of roots)
      state = roomReducer(
        state,
        setMessage({
          roomId,
          merkleRootHex,
          sha512Hex: "cd".repeat(64),
          fromPeerId,
          chunkSize: 5,
          totalSize: 8,
          messageType: 2,
          filename: "f.bin",
          channelLabel: "chat",
          timestamp: 1,
        }),
      );
    const before = state[0].messages.map((message) => ({ ...message }));

    state = roomReducer(
      state,
      resetMessageReceiveProgress({ roomId, merkleRootHex: roots[1] }),
    );

    expect(state[0].messages.map((message) => message.merkleRootHex)).toEqual(
      roots,
    );
    expect(state[0].messages[1]).toEqual({ ...before[1], savedSize: 0 });
    expect(state[0].messages[0]).toEqual(before[0]);
    expect(state[0].messages[2]).toEqual(before[2]);
  });

  test("a failed verification resets the entry setMessage updates when a root is listed twice", () => {
    const roomId = "00000000-0000-4000-8000-0000000000e9";
    const fromPeerId = "00000000-0000-4000-8000-0000000000ea";
    const merkleRootHex = "d4".repeat(64);
    const chunk = (chunkSize: number) =>
      setMessage({
        roomId,
        merkleRootHex,
        sha512Hex: "cd".repeat(64),
        fromPeerId,
        chunkSize,
        totalSize: 16,
        messageType: 2,
        filename: "f.bin",
        channelLabel: "chat",
        timestamp: 1,
      });
    let state = roomReducer(
      undefined,
      setRoom({ url: "e9".repeat(32), id: roomId }),
    );
    state = roomReducer(state, chunk(5));
    // The same root listed twice: an older entry, then the live one.
    state = [
      {
        ...state[0],
        messages: [state[0].messages[0], { ...state[0].messages[0] }],
      },
    ];
    // setMessage updates the last entry for the root...
    state = roomReducer(state, chunk(3));
    expect(state[0].messages.map((message) => message.savedSize)).toEqual([
      5, 8,
    ]);
    // ...and so does the reset.
    state = roomReducer(
      state,
      resetMessageReceiveProgress({ roomId, merkleRootHex }),
    );
    expect(state[0].messages.map((message) => message.savedSize)).toEqual([
      5, 0,
    ]);
  });
});
