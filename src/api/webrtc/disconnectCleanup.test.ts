import { describe, expect, mock, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCDataChannel } from "./interfaces";

mock.module("./index", () => ({
  default: {
    endpoints: {
      disconnectFromPeer: {
        initiate: (value: unknown) => value,
      },
    },
  },
}));

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
  const [all, room, allRooms] = await Promise.all([
    import("./disconnectQuery"),
    import("./disconnectFromRoomQuery"),
    import("./disconnectFromAllRoomsQuery"),
  ]);
  return {
    disconnectAll: all.default,
    disconnectRoom: room.default,
    disconnectAllRooms: allRooms.default,
  };
};

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
      },
      api,
      {},
    );
    expect(target.released.count).toBe(1);
    expect(preserved.released.count).toBe(0);
    expect(channels).toEqual([preserved.value]);
  });
});
