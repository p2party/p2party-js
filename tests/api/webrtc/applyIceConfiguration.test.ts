import { describe, expect, test } from "bun:test";

import { applyRoomIceConfiguration as applyWithRetire } from "../../../src/api/webrtc/applyIceConfiguration";

import type { IRTCPeerConnection } from "../../../src/api/webrtc/interfaces";

// How a transport that cannot hold the configuration is retired is the
// caller's to say; production passes the shared edge teardown (see
// applyRoomConfigurationEndpoint.test.ts). These tests observe the
// transport's own close(), so here retiring is closing.
const applyRoomIceConfiguration = (
  peerConnections: readonly IRTCPeerConnection[],
  roomId: string,
  rtcConfig: RTCConfiguration,
  restartIceAfterApply = false,
  failurePolicy: "rollback" | "close" = "rollback",
): number =>
  applyWithRetire(
    peerConnections,
    roomId,
    rtcConfig,
    restartIceAfterApply,
    failurePolicy,
    (connection) => connection.close(),
  );

const connection = (
  roomId: string,
  connectionState: RTCPeerConnectionState,
  applied: RTCConfiguration[],
): IRTCPeerConnection =>
  ({
    roomId,
    connectionState,
    signalingState: connectionState === "closed" ? "closed" : "stable",
    getConfiguration: () => ({
      bundlePolicy: "max-bundle",
      iceCandidatePoolSize: 3,
      iceServers: [{ urls: "turn:old.example:3478" }],
    }),
    setConfiguration: (configuration: RTCConfiguration) => {
      applied.push(configuration);
    },
  }) as unknown as IRTCPeerConnection;

describe("live room ICE configuration", () => {
  test("updates every live PC in the room while preserving browser options", () => {
    const roomId = "00000000-0000-4000-8000-000000000001";
    const applied: RTCConfiguration[] = [];
    const peers = [
      connection(roomId, "connected", applied),
      connection(roomId, "connecting", applied),
      connection(roomId, "closed", applied),
      connection("00000000-0000-4000-8000-000000000002", "connected", applied),
    ];
    const nextIce = [
      {
        urls: ["turns:new.example:443"],
        username: "fresh",
        credential: "fresh",
      },
    ];

    expect(
      applyRoomIceConfiguration(peers, roomId, { iceServers: nextIce }),
    ).toBe(2);
    expect(applied).toEqual([
      {
        bundlePolicy: "max-bundle",
        iceCandidatePoolSize: 3,
        iceServers: nextIce,
      },
      {
        bundlePolicy: "max-bundle",
        iceCandidatePoolSize: 3,
        iceServers: nextIce,
      },
    ]);
    expect(applied[0].iceServers).not.toBe(applied[1].iceServers);
  });

  test("configures every peer before restarting the room ICE generation", () => {
    const events: string[] = [];
    const makePeer = (name: string) =>
      ({
        roomId: "room",
        connectionState: "connected",
        signalingState: "stable",
        localDescription: { type: "offer", sdp: `${name}-offer` },
        remoteDescription: null,
        getConfiguration: () => ({
          iceServers: [{ urls: `turn:${name}-old.example` }],
        }),
        setConfiguration: () => {
          events.push(`${name}:configure`);
        },
        restartIce: () => {
          events.push(`${name}:restart`);
        },
        close: () => {
          events.push(`${name}:close`);
        },
      }) as unknown as IRTCPeerConnection;

    expect(
      applyRoomIceConfiguration(
        [makePeer("a"), makePeer("b")],
        "room",
        { iceServers: [{ urls: "turn:new.example" }] },
        true,
      ),
    ).toBe(2);
    expect(events).toEqual([
      "a:configure",
      "b:configure",
      "a:restart",
      "b:restart",
    ]);
  });

  test("a partial update restores the authoritative configuration on every peer", () => {
    const events: string[] = [];
    let secondCalls = 0;
    const makePeer = (name: string, failFirst = false) =>
      ({
        roomId: "room",
        connectionState: "connected",
        signalingState: "stable",
        localDescription: { type: "offer", sdp: `${name}-offer` },
        remoteDescription: null,
        getConfiguration: () => ({
          iceServers: [{ urls: `turn:${name}-old.example` }],
        }),
        setConfiguration: (configuration: RTCConfiguration) => {
          events.push(`${name}:${String(configuration.iceServers?.[0]?.urls)}`);
          if (failFirst && secondCalls++ === 0)
            throw new Error("second peer rejected the rotation");
        },
        restartIce: () => {
          events.push(`${name}:restart`);
        },
        close: () => {
          events.push(`${name}:close`);
        },
      }) as unknown as IRTCPeerConnection;

    expect(() =>
      applyRoomIceConfiguration([makePeer("a"), makePeer("b", true)], "room", {
        iceServers: [{ urls: "turn:new.example" }],
      }),
    ).toThrow("second peer rejected the rotation");
    expect(events).toEqual([
      "a:turn:new.example",
      "b:turn:new.example",
      "a:turn:a-old.example",
      "b:turn:b-old.example",
    ]);
  });

  test("closes a peer if rollback cannot restore one authoritative generation", () => {
    const events: string[] = [];
    let calls = 0;
    const peer = {
      roomId: "room",
      connectionState: "connected",
      signalingState: "stable",
      localDescription: { type: "offer", sdp: "offer" },
      remoteDescription: null,
      getConfiguration: () => ({
        iceServers: [{ urls: "turn:old.example" }],
      }),
      setConfiguration: () => {
        calls += 1;
        throw new Error(calls === 1 ? "rotation failed" : "rollback failed");
      },
      restartIce: () => undefined,
      close: () => {
        events.push("close");
      },
    } as unknown as IRTCPeerConnection;

    expect(() =>
      applyRoomIceConfiguration(
        [peer],
        "room",
        { iceServers: [{ urls: "turn:new.example" }] },
        true,
      ),
    ).toThrow("rotation failed");
    expect(events).toEqual(["close"]);
  });

  test("expiry closes every room peer instead of restoring an expired generation", () => {
    const events: string[] = [];
    const makePeer = (name: string, rejectsCallerConfig = false) =>
      ({
        roomId: "room",
        connectionState: "connected",
        signalingState: "stable",
        localDescription: { type: "offer", sdp: `${name}-offer` },
        remoteDescription: null,
        getConfiguration: () => ({
          iceServers: [{ urls: "turn:expired.example" }],
        }),
        setConfiguration: () => {
          events.push(`${name}:configure-caller`);
          if (rejectsCallerConfig) throw new Error("browser rejected removal");
        },
        restartIce: () => {
          events.push(`${name}:restart`);
        },
        close: () => {
          events.push(`${name}:close`);
        },
      }) as unknown as IRTCPeerConnection;

    expect(() =>
      applyRoomIceConfiguration(
        [makePeer("a"), makePeer("b", true)],
        "room",
        { iceServers: [{ urls: "stun:caller.example" }] },
        true,
        "close",
      ),
    ).toThrow("browser rejected removal");
    expect(events).toEqual([
      "a:configure-caller",
      "b:configure-caller",
      "a:close",
      "b:close",
    ]);
    expect(events).not.toContain("a:restart");
  });

  test("an unnegotiated newly inserted PC gets fresh config without a lost restart event", () => {
    const events: string[] = [];
    const peer = {
      roomId: "room",
      connectionState: "new",
      signalingState: "stable",
      localDescription: null,
      remoteDescription: null,
      getConfiguration: () => ({
        iceServers: [{ urls: "turn:old.example" }],
      }),
      setConfiguration: () => {
        events.push("configure");
      },
      restartIce: () => {
        events.push("restart");
      },
      close: () => {
        events.push("close");
      },
    } as unknown as IRTCPeerConnection;

    expect(
      applyRoomIceConfiguration(
        [peer],
        "room",
        { iceServers: [{ urls: "turn:fresh.example" }] },
        true,
      ),
    ).toBe(1);
    expect(events).toEqual(["configure"]);
  });
});
