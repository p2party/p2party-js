import { describe, expect, test } from "bun:test";

import { requestPeersAfterEdgeTeardown } from "../../src/handlers/edgeTeardownFollowUp";
import { setConnectingToPeers } from "../../src/reducers/roomSlice";

const ROOM_ID = "00000000-0000-4000-8000-000000000002";

const fakeApi = (signalingServer: {
  isConnected: boolean;
  isVerified: boolean;
}) => {
  const dispatched: unknown[] = [];
  return {
    dispatched,
    api: {
      getState: () => ({ signalingServer }),
      dispatch: (action: unknown) => {
        dispatched.push(action);
        return action;
      },
    },
  };
};

describe("requestPeersAfterEdgeTeardown", () => {
  test("re-dials the room through setConnectingToPeers on a verified socket", () => {
    const { api, dispatched } = fakeApi({
      isConnected: true,
      isVerified: true,
    });

    expect(requestPeersAfterEdgeTeardown(api, ROOM_ID)).toBe(true);
    expect(dispatched).toEqual([
      setConnectingToPeers({
        roomId: ROOM_ID,
        connectingToPeers: true,
        reason: "redial",
      }),
    ]);
  });

  test("records an intent on a connected but unverified socket", () => {
    const { api, dispatched } = fakeApi({
      isConnected: true,
      isVerified: false,
    });

    expect(requestPeersAfterEdgeTeardown(api, ROOM_ID)).toBe(false);
    expect(dispatched).toEqual([
      setConnectingToPeers({
        roomId: ROOM_ID,
        connectingToPeers: true,
        reason: "redial",
      }),
    ]);
  });

  test("records an intent on a disconnected socket", () => {
    const { api, dispatched } = fakeApi({
      isConnected: false,
      isVerified: false,
    });

    expect(requestPeersAfterEdgeTeardown(api, ROOM_ID)).toBe(false);
    expect(dispatched).toEqual([
      setConnectingToPeers({
        roomId: ROOM_ID,
        connectingToPeers: true,
        reason: "redial",
      }),
    ]);
  });
});
