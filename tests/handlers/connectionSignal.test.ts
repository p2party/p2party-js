import { describe, expect, test } from "bun:test";

import { establishSignaledConnection } from "../../src/handlers/connectionSignal";

import type { RTCPeerConnectionParams } from "../../src/api/webrtc/interfaces";
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
});
