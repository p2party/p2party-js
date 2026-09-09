import { describe, expect, test } from "bun:test";

import { assertRoomEdgeBudget } from "../../../src/api/webrtc/roomEdgeBudget";
import { MAX_SIGNALING_ROOM_PEERS } from "../../../src/utils/signalingBounds";

import type { IRTCPeerConnection } from "../../../src/api/webrtc/interfaces";

const identity = (index: number): string =>
  index.toString(16).padStart(64, "0");

describe("room transport edge budget", () => {
  test("counts live and initializing PCs in addition to the stored roster", () => {
    const peers = Array.from(
      { length: MAX_SIGNALING_ROOM_PEERS - 1 },
      (_, index) => ({
        peerId: `peer-${String(index)}`,
        peerPublicKey: identity(index + 1),
      }),
    );
    const initialization = new Promise<void>(() => undefined);
    const peerConnections = [
      {
        roomId: "room",
        withPeerPublicKey: identity(MAX_SIGNALING_ROOM_PEERS),
        initialization,
      } as IRTCPeerConnection,
    ];

    expect(() =>
      assertRoomEdgeBudget(
        "room",
        peers,
        peerConnections,
        identity(MAX_SIGNALING_ROOM_PEERS),
      ),
    ).not.toThrow();
    expect(() =>
      assertRoomEdgeBudget(
        "room",
        peers,
        peerConnections,
        identity(MAX_SIGNALING_ROOM_PEERS + 1),
      ),
    ).toThrow("edge budget");
  });

  test("ignores transports from another room", () => {
    const otherRoomConnections = Array.from(
      { length: MAX_SIGNALING_ROOM_PEERS },
      (_, index) =>
        ({
          roomId: "other-room",
          withPeerPublicKey: identity(index + 1),
        }) as IRTCPeerConnection,
    );

    expect(() =>
      assertRoomEdgeBudget(
        "room",
        [],
        otherRoomConnections,
        identity(MAX_SIGNALING_ROOM_PEERS + 1),
      ),
    ).not.toThrow();
  });
});
