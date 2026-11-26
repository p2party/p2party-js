import { describe, expect, test } from "bun:test";

import { applyRoomIceConfiguration } from "../../../src/api/webrtc/applyIceConfiguration";

import type { IRTCPeerConnection } from "../../../src/api/webrtc/interfaces";

// applyRoomIceConfiguration closes a transport when the room's authoritative
// ICE configuration can neither be applied nor restored on it. pc.close()
// fires no event, so a bare close left the transport's ratchet and PQ runtime
// in memory and its PQ healing interval ticking (transport audit 2026-11,
// item 4, the remaining close sites). The helper therefore never closes a
// transport itself: it hands it to the caller's `retire`, which in production
// is the shared edge teardown (src/api/webrtc/index.ts; the wipe through the
// real endpoint is pinned in applyRoomConfigurationEndpoint.test.ts).
//
// The helper imports nothing but types, so it no longer pulls the Redux store
// in at import time: this file needs no localStorage stand-in.

const ROOM_ID = "00000000-0000-4000-8000-0000000000a7";

interface Edge {
  readonly epc: IRTCPeerConnection;
  readonly closes: { count: number };
}

/** A negotiated transport whose setConfiguration always or never throws. */
const edge = (rejects: "always" | "never"): Edge => {
  const closes = { count: 0 };
  const epc = {
    roomId: ROOM_ID,
    connectionState: "connected",
    signalingState: "stable",
    localDescription: { type: "offer", sdp: "offer" },
    remoteDescription: null,
    getConfiguration: () => ({ iceServers: [{ urls: "turn:old.example" }] }),
    setConfiguration: () => {
      if (rejects === "always") throw new Error("configuration rejected");
    },
    restartIce: () => undefined,
    close: () => {
      closes.count += 1;
    },
  } as unknown as IRTCPeerConnection;
  return { epc, closes };
};

const recordingRetire = (): {
  retired: IRTCPeerConnection[];
  retire: (connection: IRTCPeerConnection) => void;
} => {
  const retired: IRTCPeerConnection[] = [];
  return { retired, retire: (connection) => retired.push(connection) };
};

describe("an ICE configuration that cannot be held retires its transport", () => {
  test("a transport whose configuration cannot be restored is retired, never just closed", () => {
    const rejecting = edge("always");
    const { retired, retire } = recordingRetire();

    expect(() =>
      applyRoomIceConfiguration(
        [rejecting.epc],
        ROOM_ID,
        { iceServers: [{ urls: "turn:new.example" }] },
        false,
        "rollback",
        retire,
      ),
    ).toThrow("configuration rejected");

    expect(retired).toEqual([rejecting.epc]);
    expect(rejecting.closes.count).toBe(0);
  });

  test("an expired ICE generation retires every room transport, the healthy one included", () => {
    const healthy = edge("never");
    const rejecting = edge("always");
    const { retired, retire } = recordingRetire();

    expect(() =>
      applyRoomIceConfiguration(
        [healthy.epc, rejecting.epc],
        ROOM_ID,
        { iceServers: [{ urls: "stun:caller.example" }] },
        true,
        "close",
        retire,
      ),
    ).toThrow("configuration rejected");

    expect(retired).toEqual([healthy.epc, rejecting.epc]);
    expect(healthy.closes.count + rejecting.closes.count).toBe(0);
  });

  test("a configuration every transport holds retires nothing", () => {
    const healthy = edge("never");
    const { retired, retire } = recordingRetire();

    expect(
      applyRoomIceConfiguration(
        [healthy.epc],
        ROOM_ID,
        { iceServers: [{ urls: "turn:new.example" }] },
        true,
        "close",
        retire,
      ),
    ).toBe(1);

    expect(retired).toEqual([]);
  });
});
