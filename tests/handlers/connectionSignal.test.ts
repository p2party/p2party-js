import { describe, expect, test } from "bun:test";

import { establishSignaledConnection } from "../../src/handlers/connectionSignal";
import { assertRoomEdgeBudget } from "../../src/api/webrtc/roomEdgeBudget";
import { MAX_SIGNALING_ROOM_PEERS } from "../../src/utils/signalingBounds";

import type {
  IRTCPeerConnection,
  RTCPeerConnectionParams,
} from "../../src/api/webrtc/interfaces";
import type { Peer } from "../../src/reducers/roomSlice";
import type { WebSocketMessagePeerConnectionResponse } from "../../src/utils/interfaces";

const signal = (
  peerId: string,
  peerPublicKey: string,
  fromPeerSocketGeneration?: string,
): WebSocketMessagePeerConnectionResponse => ({
  type: "connection",
  roomId: "room",
  fromPeerId: peerId,
  fromPeerPublicKey: peerPublicKey,
  labels: ["main"],
  fromPeerSocketGeneration,
  protocolVersion: 4,
});

describe("accepted connection signaling", () => {
  test("concurrent three-peer joins allocate both signaled mesh edges", async () => {
    const connections: RTCPeerConnectionParams[] = [];
    const peers: string[] = [];
    const channels: string[] = [];
    const rtcConfig = { iceServers: [] };

    await Promise.all(
      [
        signal("peer-a", "11".repeat(32)),
        signal("peer-b", "22".repeat(32)),
      ].map((message) =>
        establishSignaledConnection(message, rtcConfig, {
          recordPeer: ({ peerId }) => peers.push(peerId),
          recordChannel: ({ peerId, label }) =>
            channels.push(`${peerId}:${label}`),
          ensureConnection: async (params) => {
            connections.push(params);
          },
        }),
      ),
    );

    expect(new Set(peers)).toEqual(new Set(["peer-a", "peer-b"]));
    expect(new Set(channels)).toEqual(new Set(["peer-a:main", "peer-b:main"]));
    expect(new Set(connections.map(({ peerId }) => peerId))).toEqual(
      new Set(["peer-a", "peer-b"]),
    );
    expect(connections.every((params) => params.rtcConfig === rtcConfig)).toBe(
      true,
    );
  });

  // C1. This frame is emitted only after the peer built a FRESH transport, so
  // it is the one introduction allowed to retire a live edge. It must reach the
  // transport layer with that provenance attached, or the generation is inert.
  test("the dialling socket's generation reaches the transport as a connection-frame observation", async () => {
    const connections: RTCPeerConnectionParams[] = [];
    const generation = "11111111-1111-4111-8111-111111111111";

    await establishSignaledConnection(
      signal("peer-a", "11".repeat(32), generation),
      {},
      {
        recordPeer: () => undefined,
        recordChannel: () => undefined,
        ensureConnection: async (params) => {
          connections.push(params);
        },
      },
    );

    expect(connections).toHaveLength(1);
    expect(connections[0].peerSocketGeneration).toBe(generation);
    expect(connections[0].peerSocketGenerationSource).toBe("connection");
  });

  test("a pre-generation server leaves the generation absent, not invented", async () => {
    const connections: RTCPeerConnectionParams[] = [];

    await establishSignaledConnection(
      signal("peer-a", "11".repeat(32)),
      {},
      {
        recordPeer: () => undefined,
        recordChannel: () => undefined,
        ensureConnection: async (params) => {
          connections.push(params);
        },
      },
    );

    expect(connections[0].peerSocketGeneration).toBeUndefined();
    expect(connections[0].peerSocketGenerationSource).toBe("connection");
  });

  test("a rejected transport admission publishes no peer or channel metadata", async () => {
    const peers: string[] = [];
    const channels: string[] = [];

    await expect(
      establishSignaledConnection(
        signal("peer", "33".repeat(32)),
        {},
        {
          recordPeer: ({ peerId }) => peers.push(peerId),
          recordChannel: ({ label }) => channels.push(label),
          ensureConnection: async () => {
            throw new Error("edge budget exhausted");
          },
        },
      ),
    ).rejects.toThrow("edge budget exhausted");
    expect(peers).toEqual([]);
    expect(channels).toEqual([]);
  });

  test("a connection-frame flood stops atomically at the room edge cap", async () => {
    const peers: Peer[] = [];
    const peerConnections: IRTCPeerConnection[] = [];
    const channels: string[] = [];
    const effects = {
      recordPeer: ({
        peerId,
        peerPublicKey,
      }: {
        peerId: string;
        peerPublicKey: string;
      }) => peers.push({ peerId, peerPublicKey }),
      recordChannel: ({ peerId, label }: { peerId: string; label: string }) =>
        channels.push(`${peerId}:${label}`),
      ensureConnection: async (params: RTCPeerConnectionParams) => {
        assertRoomEdgeBudget(
          params.roomId,
          peers,
          peerConnections,
          params.peerPublicKey,
        );
        peerConnections.push({
          roomId: params.roomId,
          withPeerId: params.peerId,
          withPeerPublicKey: params.peerPublicKey,
        } as IRTCPeerConnection);
      },
    };

    for (let index = 0; index < MAX_SIGNALING_ROOM_PEERS; index += 1) {
      await establishSignaledConnection(
        signal(`peer-${String(index)}`, index.toString(16).padStart(64, "0")),
        {},
        effects,
      );
    }
    await expect(
      establishSignaledConnection(
        signal("overflow", "ff".repeat(32)),
        {},
        effects,
      ),
    ).rejects.toThrow("edge budget");

    expect(peers).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
    expect(peerConnections).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
    expect(channels).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
  });
});
