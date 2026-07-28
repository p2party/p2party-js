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
): WebSocketMessagePeerConnectionResponse => ({
  type: "connection",
  roomId: "room",
  fromPeerId: peerId,
  fromPeerPublicKey: peerPublicKey,
  labels: ["main"],
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
