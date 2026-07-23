import { describe, expect, test } from "bun:test";

import {
  findRoomPeerConnection,
  findRoomPeerConnectionIndex,
  findRoomIdentityAliases,
  isRoomPeerConnection,
} from "./roomPeer";

import type { IRTCPeerConnection } from "./interfaces";

const connection = (
  roomId: string,
  withPeerId: string,
  withPeerPublicKey = "",
): IRTCPeerConnection =>
  ({ roomId, withPeerId, withPeerPublicKey }) as unknown as IRTCPeerConnection;

describe("room/peer WebRTC identity", () => {
  test("the same peer in two rooms resolves to two transports", () => {
    const roomOne = connection("room-one", "peer");
    const roomTwo = connection("room-two", "peer");
    const connections = [roomOne, roomTwo];

    expect(findRoomPeerConnectionIndex(connections, "room-one", "peer")).toBe(
      0,
    );
    expect(findRoomPeerConnection(connections, "room-two", "peer")).toBe(
      roomTwo,
    );
  });

  test("both roomId and peerId are part of the identity", () => {
    const value = connection("room-one", "peer-one");

    expect(isRoomPeerConnection(value, "room-one", "peer-one")).toBe(true);
    expect(isRoomPeerConnection(value, "room-two", "peer-one")).toBe(false);
    expect(isRoomPeerConnection(value, "room-one", "peer-two")).toBe(false);
  });

  test("finds a transient peerId alias for the same stable identity", () => {
    const oldTransport = connection("room-one", "old-id", "ed25519-a");
    const currentTransport = connection("room-one", "new-id", "ed25519-a");
    const otherIdentity = connection("room-one", "other-id", "ed25519-b");
    const otherRoom = connection("room-two", "old-id", "ed25519-a");

    expect(
      findRoomIdentityAliases(
        [oldTransport, currentTransport, otherIdentity, otherRoom],
        "room-one",
        "new-id",
        "ed25519-a",
      ),
    ).toEqual([oldTransport]);
  });
});
