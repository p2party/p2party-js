import { afterEach, describe, expect, test } from "bun:test";
import { configureStore } from "@reduxjs/toolkit";

import { parseTurnCredentials } from "../../src/utils/signalingAuth";
import { PROTOCOL_VERSION } from "../../src/utils/constants";
import { applyRoomIceConfiguration } from "../../src/api/webrtc/applyIceConfiguration";
import {
  getRoomIceConfigurationMutex,
  releaseRoomIceConfigurationMutex,
  runRoomResponseCommitExclusive,
} from "../../src/api/webrtc/negotiationLock";

import type { PendingRoomResponseClaim } from "../../src/utils/roomRequestCoordinator";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import {
  claimRoomResponse,
  isRoomResponseClaimCurrent,
  requestRoomResponse,
  resetRoomRequestLifecycle,
} from "../../src/utils/roomRequestCoordinator";

(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

const [
  { commitRoomResponsePlan, isExactExpiredTurnGeneration, planRoomResponse },
  {
    default: roomReducer,
    deleteRoom,
    expireRoomTurnCredentials,
    rollbackRoomResponse,
    setRoom,
  },
] = await Promise.all([
  import("../../src/handlers/roomResponse"),
  import("../../src/reducers/roomSlice"),
]);

const NOW_MS = 1_700_000_000_000;
const EXPIRY = Math.floor(NOW_MS / 1_000) + 3_600;
const PUBLIC_KEY = "ab".repeat(32);
const OTHER_PUBLIC_KEY = "cd".repeat(32);
const ROOM_ID = "00000000-0000-4000-8000-000000000080";
const OTHER_ROOM_ID = "00000000-0000-4000-8000-000000000081";
const ROOM_URL = "8".repeat(64);
const OTHER_ROOM_URL = "7".repeat(64);
const REQUEST_ID = "00000000-0000-4000-8000-000000000090";

afterEach(() => {
  resetRoomRequestLifecycle("turn credential test cleanup");
});

const valid = {
  urls: [
    "turns:turn.p2party.com:443?transport=tcp",
    "turn:turn.p2party.com:3478",
  ],
  username: `${String(EXPIRY)}:${PUBLIC_KEY}`,
  credential: "XY6V5LzRrbIFUOH5w0qdZ90iYuQ=",
  expiresAtUnixSeconds: EXPIRY,
};

const claim = (
  requestGeneration = 1,
  roomUrl = ROOM_URL,
  roomRequestId = REQUEST_ID,
): PendingRoomResponseClaim => ({
  roomUrl,
  roomRequestId,
  requestGeneration,
});

const response = (overrides: Record<string, unknown> = {}) => ({
  type: "roomId",
  roomId: ROOM_ID,
  roomUrl: ROOM_URL,
  roomRequestId: REQUEST_ID,
  protocolVersion: PROTOCOL_VERSION,
  turnCredentials: valid,
  ...overrides,
});

describe("relay credentials from signaling", () => {
  test("accepts an exact bounded bundle bound to this identity and expiry", () => {
    const accepted = parseTurnCredentials(valid, NOW_MS, PUBLIC_KEY);
    expect(accepted).toEqual(valid);
  });

  test("rejects invalid relay URLs, shape, expiry, or identity binding", () => {
    for (const url of [
      "https://evil.example.com",
      "stun:stun.example.com:3478",
      "javascript:alert(1)",
    ])
      expect(
        parseTurnCredentials(
          { ...valid, urls: [valid.urls[0], url] },
          NOW_MS,
          PUBLIC_KEY,
        ),
      ).toBeNull();

    expect(
      parseTurnCredentials(
        { ...valid, urls: [valid.urls[0], valid.urls[0]] },
        NOW_MS,
        PUBLIC_KEY,
      ),
    ).toBeNull();
    expect(
      parseTurnCredentials({ ...valid, ttl: 3_600 }, NOW_MS, PUBLIC_KEY),
    ).toBeNull();
    expect(
      parseTurnCredentials(
        { ...valid, expiresAtUnixSeconds: EXPIRY + 1 },
        NOW_MS,
        PUBLIC_KEY,
      ),
    ).toBeNull();
    expect(
      parseTurnCredentials(
        {
          ...valid,
          username: `${String(EXPIRY)}:${OTHER_PUBLIC_KEY}`,
        },
        NOW_MS,
        PUBLIC_KEY,
      ),
    ).toBeNull();
    expect(
      parseTurnCredentials(
        {
          urls: valid.urls,
          username: valid.username,
          credential: valid.credential,
        },
        NOW_MS,
        PUBLIC_KEY,
      ),
    ).toBeNull();
  });
});

describe("atomic correlated room response", () => {
  test("preserves caller RTC options and replaces only overlapping managed URLs", () => {
    const callerConfig: RTCConfiguration = {
      bundlePolicy: "max-bundle",
      iceCandidatePoolSize: 7,
      iceTransportPolicy: "relay",
      rtcpMuxPolicy: "require",
      iceServers: [
        { urls: "stun:custom.example:3478" },
        {
          urls: [
            "turns:turn.p2party.com:443?transport=tcp",
            "turn:caller.example:3478",
          ],
          username: "caller",
          credential: "caller",
        },
      ],
    };
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: "", rtcConfig: callerConfig }));

    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    expect(plan.accepted).toBe(true);
    if (!plan.accepted) throw new Error(plan.reason);
    expect(plan.action.type).toBe("rooms/applyRoomResponse");
    store.dispatch(plan.action);

    const room = store.getState().rooms[0];
    expect(room.id).toBe(ROOM_ID);
    expect(room.signalingTurnCredentials).toEqual(valid);
    expect(room.callerRtcConfig).toEqual(callerConfig);
    expect(room.rtcConfig).toEqual({
      bundlePolicy: "max-bundle",
      iceCandidatePoolSize: 7,
      iceTransportPolicy: "relay",
      rtcpMuxPolicy: "require",
      iceServers: [
        { urls: "stun:custom.example:3478" },
        {
          urls: ["turn:caller.example:3478"],
          username: "caller",
          credential: "caller",
        },
        {
          urls: valid.urls,
          username: valid.username,
          credential: valid.credential,
        },
      ],
    });
    expect(callerConfig.iceServers?.[1]).toEqual({
      urls: [
        "turns:turn.p2party.com:443?transport=tcp",
        "turn:caller.example:3478",
      ],
      username: "caller",
      credential: "caller",
    });
  });

  test("rotation removes the old managed bundle and omission clears it", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: "",
        rtcConfig: { iceServers: [{ urls: "stun:caller.example:3478" }] },
      }),
    );
    const first = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(1),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!first.accepted) throw new Error(first.reason);
    store.dispatch(first.action);

    const rotated = {
      ...valid,
      urls: ["turns:new-relay.example:443"],
      credential: "rotated",
    };
    const second = planRoomResponse(
      response({ turnCredentials: rotated }),
      store.getState().rooms,
      claim(2),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!second.accepted) throw new Error(second.reason);
    store.dispatch(second.action);
    expect(store.getState().rooms[0].rtcConfig.iceServers).toEqual([
      { urls: "stun:caller.example:3478" },
      {
        urls: rotated.urls,
        username: rotated.username,
        credential: rotated.credential,
      },
    ]);

    const { turnCredentials: _turnCredentials, ...clearedResponse } =
      response();
    const cleared = planRoomResponse(
      clearedResponse,
      store.getState().rooms,
      claim(3),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!cleared.accepted) throw new Error(cleared.reason);
    store.dispatch(cleared.action);
    expect(store.getState().rooms[0].signalingTurnCredentials).toBeNull();
    expect(store.getState().rooms[0].rtcConfig).toEqual({
      iceServers: [{ urls: "stun:caller.example:3478" }],
    });
  });

  test("local expiry removes only the matching managed generation", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: "",
        rtcConfig: { iceServers: [{ urls: "stun:caller.example:3478" }] },
      }),
    );
    const accepted = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!accepted.accepted) throw new Error(accepted.reason);
    store.dispatch(accepted.action);

    store.dispatch(
      expireRoomTurnCredentials({
        roomUrl: ROOM_URL,
        expiresAtUnixSeconds: EXPIRY + 1,
        requestGeneration: 1,
      }),
    );
    expect(store.getState().rooms[0].signalingTurnCredentials).toEqual(valid);
    store.dispatch(
      expireRoomTurnCredentials({
        roomUrl: ROOM_URL,
        expiresAtUnixSeconds: EXPIRY,
        requestGeneration: 1,
      }),
    );
    expect(store.getState().rooms[0].signalingTurnCredentials).toBeNull();
    expect(store.getState().rooms[0].rtcConfig.iceServers).toEqual([
      { urls: "stun:caller.example:3478" },
    ]);
  });

  test("an old expiry callback cannot remove a newer rotation with the same second", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: ROOM_ID }));
    const first = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(1),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!first.accepted) throw new Error(first.reason);
    store.dispatch(first.action);
    const second = planRoomResponse(
      response({
        turnCredentials: { ...valid, credential: "new-generation" },
      }),
      store.getState().rooms,
      claim(2),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!second.accepted) throw new Error(second.reason);
    store.dispatch(second.action);

    store.dispatch(
      expireRoomTurnCredentials({
        roomUrl: ROOM_URL,
        expiresAtUnixSeconds: EXPIRY,
        requestGeneration: 1,
      }),
    );
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(2);
    expect(store.getState().rooms[0].signalingTurnCredentials?.credential).toBe(
      "new-generation",
    );
  });

  test("an old expiry callback cannot reapply or restart a newer no-TURN generation", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: ROOM_ID }));
    const first = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(1),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!first.accepted) throw new Error(first.reason);
    store.dispatch(first.action);

    const { turnCredentials: _turnCredentials, ...withoutTurn } = response();
    const second = planRoomResponse(
      withoutTurn,
      store.getState().rooms,
      claim(2),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!second.accepted) throw new Error(second.reason);
    store.dispatch(second.action);
    store.dispatch(
      expireRoomTurnCredentials({
        roomUrl: ROOM_URL,
        expiresAtUnixSeconds: EXPIRY,
        requestGeneration: first.requestGeneration,
      }),
    );

    const room = store.getState().rooms[0];
    expect(room.roomResponseGeneration).toBe(second.requestGeneration);
    expect(room.signalingTurnCredentials).toBeNull();
    expect(isExactExpiredTurnGeneration(room, first)).toBe(false);
  });

  test("a live-PC configuration failure cannot publish a new generation", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: ROOM_ID }));
    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);
    let dispatches = 0;

    await expect(
      commitRoomResponsePlan(
        plan,
        () => Promise.reject(new Error("setConfiguration failed")),
        () => true,
        () => {
          dispatches += 1;
          store.dispatch(plan.action);
          return true;
        },
        (roomUrl) =>
          store.getState().rooms.find((room) => room.url === roomUrl),
      ),
    ).rejects.toThrow("setConfiguration failed");
    expect(dispatches).toBe(0);
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(0);
    expect(store.getState().rooms[0].signalingTurnCredentials).toBeNull();
  });

  test("a lease lost during live apply publishes nothing and restores authoritative RTC config", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: ROOM_ID,
        rtcConfig: { iceServers: [{ urls: "stun:authoritative.example" }] },
      }),
    );
    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);

    let leaseCurrent = true;
    let dispatches = 0;
    const applied: RTCConfiguration[] = [];
    const failurePolicies: Array<"rollback" | "close"> = [];
    const committed = await commitRoomResponsePlan(
      plan,
      (_roomId, rtcConfig, failurePolicy) => {
        applied.push(rtcConfig);
        failurePolicies.push(failurePolicy);
        if (applied.length === 1) leaseCurrent = false;
        return Promise.resolve();
      },
      () => leaseCurrent,
      () => {
        dispatches += 1;
        store.dispatch(plan.action);
        return true;
      },
      (roomUrl) => store.getState().rooms.find((room) => room.url === roomUrl),
    );

    expect(committed).toBe(false);
    expect(dispatches).toBe(0);
    expect(applied).toEqual([
      plan.nextRtcConfig,
      store.getState().rooms[0].rtcConfig,
    ]);
    expect(failurePolicies).toEqual(["rollback", "close"]);
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(0);
    expect(store.getState().rooms[0].signalingTurnCredentials).toBeNull();
  });

  test("room deletion during live apply stays terminal and restores the tombstone RTC config", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: ROOM_ID,
        rtcConfig: { iceServers: [{ urls: "stun:before-delete.example" }] },
      }),
    );
    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);

    let dispatches = 0;
    const applied: RTCConfiguration[] = [];
    const committed = await commitRoomResponsePlan(
      plan,
      (_roomId, rtcConfig) => {
        applied.push(rtcConfig);
        if (applied.length === 1) store.dispatch(deleteRoom(ROOM_URL));
        return Promise.resolve();
      },
      () => {
        const room = store
          .getState()
          .rooms.find((candidate) => candidate.url === ROOM_URL);
        return (
          room !== undefined &&
          room.signalingActive &&
          room.roomResponseGeneration < plan.requestGeneration
        );
      },
      () => {
        dispatches += 1;
        store.dispatch(plan.action);
        return true;
      },
      (roomUrl) => store.getState().rooms.find((room) => room.url === roomUrl),
    );

    const tombstone = store.getState().rooms[0];
    expect(committed).toBe(false);
    expect(dispatches).toBe(0);
    expect(tombstone.signalingActive).toBe(false);
    expect(tombstone.id).toBe("");
    expect(tombstone.roomResponseGeneration).toBe(0);
    expect(applied).toEqual([plan.nextRtcConfig, tombstone.rtcConfig]);
  });

  test("socket reset during live apply invalidates the real claim and rolls live ICE back", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: ROOM_ID,
        rtcConfig: { iceServers: [{ urls: "stun:authoritative.example" }] },
      }),
    );
    let roomRequestId = "";
    const pending = requestRoomResponse(
      "00000000-0000-4000-8000-000000000001",
      ROOM_URL,
      (request) => {
        roomRequestId = request.roomRequestId;
      },
    );
    const pendingRejection = pending.catch((error: unknown) => error);
    const realClaim = claimRoomResponse(ROOM_URL, roomRequestId);
    if (!realClaim) throw new Error("expected real coordinator claim");
    const plan = planRoomResponse(
      response({ roomRequestId }),
      store.getState().rooms,
      realClaim,
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);

    const applied: RTCConfiguration[] = [];
    const committed = await commitRoomResponsePlan(
      plan,
      (_roomId, rtcConfig) => {
        applied.push(rtcConfig);
        if (applied.length === 1)
          resetRoomRequestLifecycle("socket reset during live apply");
        return Promise.resolve();
      },
      () => isRoomResponseClaimCurrent(realClaim),
      () => {
        store.dispatch(plan.action);
        return true;
      },
      (roomUrl) => store.getState().rooms.find((room) => room.url === roomUrl),
    );

    const pendingError = await pendingRejection;
    expect(pendingError).toBeInstanceOf(Error);
    expect((pendingError as Error).message).toContain(
      "socket reset during live apply",
    );
    expect(committed).toBe(false);
    expect(applied).toEqual([
      plan.nextRtcConfig,
      store.getState().rooms[0].rtcConfig,
    ]);
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(0);
  });

  test("a partial authoritative restore closes every transport rather than restoring the rejected generation", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    const authoritative = {
      iceServers: [{ urls: "turn:authoritative-old.example" }],
    } satisfies RTCConfiguration;
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: ROOM_ID,
        rtcConfig: authoritative,
      }),
    );
    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);

    let leaseCurrent = true;
    const currentUrls = [
      "turn:authoritative-old.example",
      "turn:authoritative-old.example",
    ];
    const closed = [false, false];
    const peers = currentUrls.map(
      (_url, index) =>
        ({
          roomId: ROOM_ID,
          connectionState: "connected",
          signalingState: "stable",
          localDescription: { type: "offer", sdp: "offer" },
          remoteDescription: null,
          getConfiguration: () => ({
            iceServers: [{ urls: currentUrls[index] }],
          }),
          setConfiguration: (configuration: RTCConfiguration) => {
            const url = String(configuration.iceServers?.at(-1)?.urls);
            if (
              index === 1 &&
              url === "turn:authoritative-old.example" &&
              currentUrls[index] !== url
            )
              throw new Error("peer rejected authoritative restore");
            currentUrls[index] = url;
          },
          restartIce: () => undefined,
          close: () => {
            closed[index] = true;
          },
        }) as unknown as IRTCPeerConnection,
    );

    const committing = commitRoomResponsePlan(
      plan,
      async (roomId, rtcConfig, failurePolicy) => {
        applyRoomIceConfiguration(
          peers,
          roomId,
          rtcConfig,
          true,
          failurePolicy,
        );
        if (failurePolicy === "rollback") leaseCurrent = false;
      },
      () => leaseCurrent,
      () => {
        store.dispatch(plan.action);
        return true;
      },
      (roomUrl) => store.getState().rooms.find((room) => room.url === roomUrl),
    );

    await expect(committing).rejects.toThrow(
      "peer rejected authoritative restore",
    );
    expect(closed).toEqual([true, true]);
    expect(
      currentUrls.every(
        (url, index) =>
          closed[index] || url === "turn:authoritative-old.example",
      ),
    ).toBe(true);
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(0);
  });

  test("a reentrant publication failure restores Redux and live ICE to the pre-apply generation", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(
      setRoom({
        url: ROOM_URL,
        id: ROOM_ID,
        rtcConfig: { iceServers: [{ urls: "stun:before.example" }] },
      }),
    );
    const plan = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!plan.accepted) throw new Error(plan.reason);
    const applied: RTCConfiguration[] = [];

    const committing = commitRoomResponsePlan(
      plan,
      async (_roomId, rtcConfig) => {
        applied.push(rtcConfig);
      },
      () => true,
      () => {
        store.dispatch(plan.action);
        throw new Error("synchronous subscriber cancelled publication");
      },
      (roomUrl) => store.getState().rooms.find((room) => room.url === roomUrl),
      (previous) => {
        store.dispatch(
          rollbackRoomResponse({
            roomUrl: ROOM_URL,
            failedRoomId: ROOM_ID,
            failedRequestGeneration: plan.requestGeneration,
            previousRoomId: previous.id,
            previousRequestGeneration: previous.roomResponseGeneration,
            previousTurnCredentials: previous.signalingTurnCredentials,
            previousSignalingActive: previous.signalingActive,
          }),
        );
      },
    );

    await expect(committing).rejects.toThrow(
      "synchronous subscriber cancelled publication",
    );
    expect(store.getState().rooms[0].roomResponseGeneration).toBe(0);
    expect(store.getState().rooms[0].signalingTurnCredentials).toBeNull();
    expect(store.getState().rooms[0].rtcConfig.iceServers).toEqual([
      { urls: "stun:before.example" },
    ]);
    expect(applied).toEqual([
      plan.nextRtcConfig,
      store.getState().rooms[0].rtcConfig,
    ]);
  });

  test("rejects malformed credentials, reassignment, collision, and stale generations", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: "" }));
    store.dispatch(setRoom({ url: OTHER_ROOM_URL, id: OTHER_ROOM_ID }));

    expect(
      planRoomResponse(
        response({
          turnCredentials: {
            ...valid,
            urls: [...valid.urls, "https://not-a-relay.example"],
          },
        }),
        store.getState().rooms,
        claim(),
        PUBLIC_KEY,
        NOW_MS,
      ),
    ).toEqual({
      accepted: false,
      reason: "malformed-turn-credentials",
    });
    expect(
      planRoomResponse(
        response({ roomId: OTHER_ROOM_ID }),
        store.getState().rooms,
        claim(),
        PUBLIC_KEY,
        NOW_MS,
      ),
    ).toEqual({ accepted: false, reason: "room-id-collision" });

    const accepted = planRoomResponse(
      response(),
      store.getState().rooms,
      claim(2),
      PUBLIC_KEY,
      NOW_MS,
    );
    if (!accepted.accepted) throw new Error(accepted.reason);
    store.dispatch(accepted.action);

    expect(
      planRoomResponse(
        response({ roomId: OTHER_ROOM_ID }),
        store.getState().rooms,
        claim(3),
        PUBLIC_KEY,
        NOW_MS,
      ),
    ).toEqual({ accepted: false, reason: "room-id-reassignment" });
    expect(
      planRoomResponse(
        response(),
        store.getState().rooms,
        claim(1),
        PUBLIC_KEY,
        NOW_MS,
      ),
    ).toEqual({ accepted: false, reason: "stale-room-response" });
  });

  test("concurrent responses cannot publish the same server room id for two room URLs", async () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: "" }));
    store.dispatch(setRoom({ url: OTHER_ROOM_URL, id: "" }));
    const otherRequestId = "00000000-0000-4000-8000-000000000091";
    const firstMessage = response();
    const secondMessage = response({
      roomUrl: OTHER_ROOM_URL,
      roomRequestId: otherRequestId,
    });
    const firstClaim = claim(1);
    const secondClaim = claim(1, OTHER_ROOM_URL, otherRequestId);
    expect(
      planRoomResponse(
        firstMessage,
        store.getState().rooms,
        firstClaim,
        PUBLIC_KEY,
        NOW_MS,
      ).accepted,
    ).toBe(true);
    expect(
      planRoomResponse(
        secondMessage,
        store.getState().rooms,
        secondClaim,
        PUBLIC_KEY,
        NOW_MS,
      ).accepted,
    ).toBe(true);

    const publish = (
      roomUrl: string,
      message: ReturnType<typeof response>,
      pendingClaim: PendingRoomResponseClaim,
    ) =>
      runRoomResponseCommitExclusive(() =>
        getRoomIceConfigurationMutex(roomUrl).runExclusive(async () => {
          const fresh = planRoomResponse(
            message,
            store.getState().rooms,
            pendingClaim,
            PUBLIC_KEY,
            NOW_MS,
          );
          if (!fresh.accepted) return fresh.reason;
          store.dispatch(fresh.action);
          return "accepted";
        }),
      );

    const results = await Promise.all([
      publish(ROOM_URL, firstMessage, firstClaim),
      publish(OTHER_ROOM_URL, secondMessage, secondClaim),
    ]);
    expect(results.sort()).toEqual(["accepted", "room-id-collision"]);
    expect(
      store.getState().rooms.filter((room) => room.id === ROOM_ID),
    ).toHaveLength(1);

    releaseRoomIceConfigurationMutex(ROOM_URL);
    releaseRoomIceConfigurationMutex(OTHER_ROOM_URL);
  });

  test("rejects unknown fields at the signaling boundary", () => {
    const store = configureStore({ reducer: { rooms: roomReducer } });
    store.dispatch(setRoom({ url: ROOM_URL, id: "" }));
    expect(
      planRoomResponse(
        response({ socialGraphHint: "leak" }),
        store.getState().rooms,
        claim(),
        PUBLIC_KEY,
        NOW_MS,
      ),
    ).toEqual({ accepted: false, reason: "malformed-room-response" });
  });
});
