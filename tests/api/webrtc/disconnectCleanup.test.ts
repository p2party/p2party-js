import { describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

const loadQueries = async () => {
  if (!("localStorage" in globalThis)) {
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        getItem: () => null,
        setItem: () => undefined,
        removeItem: () => undefined,
        clear: () => undefined,
        key: () => null,
        length: 0,
      } satisfies Storage,
    });
  }
  const [all, room, allRooms, retired] = await Promise.all([
    import("../../../src/api/webrtc/disconnectQuery"),
    import("../../../src/api/webrtc/disconnectFromRoomQuery"),
    import("../../../src/api/webrtc/disconnectFromAllRoomsQuery"),
    import("../../../src/api/webrtc/retiredRemoteTransports"),
  ]);
  return {
    disconnectAll: all.default,
    disconnectRoom: room.default,
    disconnectAllRooms: allRooms.default,
    isRetiredRemoteTransport: retired.isRetiredRemoteTransport,
    retireRemoteTransport: retired.retireRemoteTransport,
  };
};

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n`;

const roomPeerConnection = (roomId: string, withPeerId: string) =>
  ({ roomId, withPeerId }) as unknown as IRTCPeerConnection;

const api = {
  dispatch: (action: unknown) => action,
  getState: () => ({ rooms: [] }),
} as unknown as BaseQueryApi;

const channel = (
  roomIds: string[],
): {
  value: IRTCDataChannel;
  released: { count: number };
  closed: { count: number };
} => {
  const released = { count: 0 };
  const closed = { count: 0 };
  return {
    value: {
      roomIds,
      readyState: "open",
      releaseProtocolResources: () => {
        released.count++;
      },
      close: () => {
        closed.count++;
      },
    } as unknown as IRTCDataChannel,
    released,
    closed,
  };
};

describe("bulk DataChannel cleanup", () => {
  test("global disconnect releases queue accounting before removing channels", async () => {
    const { disconnectAll } = await loadQueries();
    const target = channel(["room-a"]);
    const channels = [target.value];
    await disconnectAll(
      {
        alsoDeleteDB: false,
        peerConnections: [],
        dataChannels: channels,
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );
    expect(target.released.count).toBe(1);
    expect(target.closed.count).toBe(1);
    expect(channels).toHaveLength(0);
  });

  test("room disconnect releases only matching channels", async () => {
    const { disconnectRoom } = await loadQueries();
    const target = channel(["room-a"]);
    const preserved = channel(["room-b"]);
    const channels = [target.value, preserved.value];
    await disconnectRoom(
      {
        roomId: "room-a",
        deleteMessages: false,
        peerConnections: [],
        dataChannels: channels,
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );
    expect(target.released.count).toBe(1);
    expect(preserved.released.count).toBe(0);
    expect(channels).toEqual([preserved.value]);
  });

  test("all-rooms disconnect respects exceptions and releases every target", async () => {
    const { disconnectAllRooms } = await loadQueries();
    const target = channel(["room-a"]);
    const preserved = channel(["room-b"]);
    const channels = [target.value, preserved.value];
    await disconnectAllRooms(
      {
        deleteMessages: false,
        exceptionRoomIds: ["room-b"],
        peerConnections: [],
        dataChannels: channels,
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );
    expect(target.released.count).toBe(1);
    expect(preserved.released.count).toBe(0);
    expect(channels).toEqual([preserved.value]);
  });
});

describe("retired remote transports of a left room", () => {
  test("leaving a room forgets the retired transports of its edges only", async () => {
    const { disconnectRoom, isRetiredRemoteTransport, retireRemoteTransport } =
      await loadQueries();
    retireRemoteTransport("room-a", "peer-1", fingerprintSdp("aa"));
    retireRemoteTransport("room-b", "peer-1", fingerprintSdp("aa"));

    await disconnectRoom(
      {
        roomId: "room-a",
        deleteMessages: false,
        peerConnections: [roomPeerConnection("room-a", "peer-1")],
        dataChannels: [],
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );

    expect(
      isRetiredRemoteTransport("room-a", "peer-1", fingerprintSdp("aa")),
    ).toBe(false);
    // The same peer's edge in a room we stay in keeps its retirements.
    expect(
      isRetiredRemoteTransport("room-b", "peer-1", fingerprintSdp("aa")),
    ).toBe(true);
  });

  test("leaving every room forgets the retired transports of each", async () => {
    const {
      disconnectAllRooms,
      isRetiredRemoteTransport,
      retireRemoteTransport,
    } = await loadQueries();
    retireRemoteTransport("room-c", "peer-2", fingerprintSdp("bb"));
    retireRemoteTransport("room-d", "peer-2", fingerprintSdp("bb"));

    await disconnectAllRooms(
      {
        deleteMessages: false,
        exceptionRoomIds: ["room-d"],
        peerConnections: [
          roomPeerConnection("room-c", "peer-2"),
          roomPeerConnection("room-d", "peer-2"),
        ],
        dataChannels: [],
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );

    expect(
      isRetiredRemoteTransport("room-c", "peer-2", fingerprintSdp("bb")),
    ).toBe(false);
    // The excepted room is not left, so its edge keeps its retirements.
    expect(
      isRetiredRemoteTransport("room-d", "peer-2", fingerprintSdp("bb")),
    ).toBe(true);
  });
});
