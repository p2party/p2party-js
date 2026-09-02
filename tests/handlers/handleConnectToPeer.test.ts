import { afterEach, beforeAll, describe, expect, jest, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

// handleConnectToPeer imports the signaling API, which imports the Redux
// store, whose identity slice reads localStorage at module initialization.
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

/**
 * The slice of RTCPeerConnection that handleConnectToPeer drives: it installs
 * handlers, reads negotiation state, and offers through setLocalDescription.
 * Tests flip the state fields and invoke the installed handlers directly.
 */
class FakeRTCPeerConnection {
  connectionState: RTCPeerConnectionState = "new";
  signalingState: RTCSignalingState = "stable";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  readonly configuration: RTCConfiguration;

  constructor(configuration: RTCConfiguration) {
    this.configuration = configuration;
  }

  getConfiguration(): RTCConfiguration {
    return this.configuration;
  }

  setConfiguration(): void {}

  async setLocalDescription(init?: RTCSessionDescriptionInit): Promise<void> {
    if (init?.type === "rollback") {
      this.signalingState = "stable";
      return;
    }
    this.localDescription = {
      type: "offer",
      sdp: "v=0\r\n",
    } as RTCSessionDescription;
    this.signalingState = "have-local-offer";
  }

  async setRemoteDescription(init: RTCSessionDescriptionInit): Promise<void> {
    this.remoteDescription = init as RTCSessionDescription;
    this.signalingState = "stable";
  }

  restartIce(): void {}

  close(): void {
    this.connectionState = "closed";
    this.signalingState = "closed";
  }
}

(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
  FakeRTCPeerConnection;

type HandleConnectToPeer =
  typeof import("../../src/handlers/handleConnectToPeer");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type PendingOffer = typeof import("../../src/api/webrtc/pendingOffer");

let handleConnectToPeer: HandleConnectToPeer["handleConnectToPeer"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let setPeer: RoomSlice["setPeer"];
let PENDING_OFFER_TIMEOUT_MS: PendingOffer["PENDING_OFFER_TIMEOUT_MS"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the handler modules load.
  await import("../../src/store");
  ({ handleConnectToPeer } =
    await import("../../src/handlers/handleConnectToPeer"));
  ({ setConnectingToPeers, setPeer } =
    await import("../../src/reducers/roomSlice"));
  ({ PENDING_OFFER_TIMEOUT_MS } =
    await import("../../src/api/webrtc/pendingOffer"));
});

afterEach(() => {
  jest.useRealTimers();
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000bb";
const ROOM_URL = "bb".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
// The lexicographically lower canonical identity is the initiator that offers.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fakeApi = (): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      publicKey: LOWER_PUBLIC_KEY,
      secretKey: "",
      challengeId: "",
      challenge: "",
      signature: "",
    },
    rooms: [
      {
        id: ROOM_ID,
        url: ROOM_URL,
        rtcConfig: { iceServers: [] },
        signalingActive: true,
        peers: [],
        channels: [],
        messages: [],
      },
    ],
    signalingServer: {
      isConnected: true,
      isEstablishingConnection: false,
      isVerified: true,
      serverUrl: "wss://signal.example/ws",
    },
  };
  const api = {
    dispatch: (action: unknown) => {
      dispatched.push(action);
      // RTK Query's `initiate` yields a thunk; the handler awaits, unwraps or
      // chains its dispatch result, so hand back a resolved, unwrappable
      // promise for those and echo plain actions.
      if (typeof action === "function")
        return Object.assign(Promise.resolve({ data: undefined }), {
          unwrap: async () => undefined,
        });
      return action;
    },
    getState: () => state,
  } as unknown as BaseQueryApi;
  return { api, dispatched };
};

const connect = async (
  api: BaseQueryApi,
): Promise<{
  epc: IRTCPeerConnection;
  peerConnections: IRTCPeerConnection[];
}> => {
  const peerConnections: IRTCPeerConnection[] = [];
  const epc = await handleConnectToPeer(
    {
      peerId: PEER_ID,
      peerPublicKey: HIGHER_PUBLIC_KEY,
      roomId: ROOM_ID,
      peerConnections,
    },
    api,
  );
  return { epc, peerConnections };
};

const driveConnectionState = async (
  epc: IRTCPeerConnection,
  connectionState: RTCPeerConnectionState,
): Promise<void> => {
  (epc as { connectionState: RTCPeerConnectionState }).connectionState =
    connectionState;
  await epc.onconnectionstatechange?.call(
    epc,
    new Event("connectionstatechange"),
  );
};

const flushMicrotasks = async (): Promise<void> => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};

const REDIAL = () =>
  setConnectingToPeers({
    roomId: ROOM_ID,
    connectingToPeers: true,
    reason: "redial",
  });

const thunks = (dispatched: unknown[]): unknown[] =>
  dispatched.filter((action) => typeof action === "function");

const redials = (dispatched: unknown[]): unknown[] =>
  dispatched.filter(
    (action) =>
      (action as { type?: string }).type === setConnectingToPeers.type,
  );

describe("handleConnectToPeer edge teardown follow-up", () => {
  test("an edge that had connected re-dials the room after a failed teardown", async () => {
    const { api, dispatched } = fakeApi();
    const { epc } = await connect(api);
    const before = dispatched.length;

    await driveConnectionState(epc, "connected");
    expect(dispatched.slice(before)).toEqual([
      setPeer({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerPublicKey: HIGHER_PUBLIC_KEY,
      }),
    ]);

    const beforeFailure = dispatched.length;
    await driveConnectionState(epc, "failed");
    const afterFailure = dispatched.slice(beforeFailure);
    // The disconnectFromPeer thunk goes out first, then the re-dial.
    expect(afterFailure).toHaveLength(2);
    expect(typeof afterFailure[0]).toBe("function");
    expect(afterFailure[1]).toEqual(REDIAL());
  });

  test("an edge that never connected is torn down without a re-dial", async () => {
    const { api, dispatched } = fakeApi();
    const { epc } = await connect(api);
    const before = dispatched.length;

    await driveConnectionState(epc, "failed");
    const afterFailure = dispatched.slice(before);
    expect(thunks(afterFailure)).toHaveLength(1);
    expect(redials(afterFailure)).toEqual([]);
  });

  test("a first offer that is never answered tears the transport down and re-dials", async () => {
    const { api, dispatched } = fakeApi();
    const { epc, peerConnections } = await connect(api);
    jest.useFakeTimers();

    await epc.onnegotiationneeded?.call(epc, new Event("negotiationneeded"));
    expect(epc.signalingState).toBe("have-local-offer");
    const afterOffer = dispatched.length;
    expect(thunks(dispatched)).toHaveLength(2); // connectWithPeer + offer

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS - 1);
    await flushMicrotasks();
    expect(dispatched.slice(afterOffer)).toEqual([]);

    jest.advanceTimersByTime(1);
    await flushMicrotasks();
    const followUp = dispatched.slice(afterOffer);
    expect(followUp).toHaveLength(2);
    expect(typeof followUp[0]).toBe("function");
    expect(followUp[1]).toEqual(REDIAL());
    expect(peerConnections).toContain(epc);
  });

  test("an answered first offer leaves the transport alone", async () => {
    const { api, dispatched } = fakeApi();
    const { epc } = await connect(api);
    jest.useFakeTimers();

    await epc.onnegotiationneeded?.call(epc, new Event("negotiationneeded"));
    await epc.setRemoteDescription({ type: "answer", sdp: "v=0\r\n" });
    const afterAnswer = dispatched.length;

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS * 2);
    await flushMicrotasks();
    expect(dispatched.slice(afterAnswer)).toEqual([]);
  });

  test("a transport removed before the watchdog fires is not torn down twice", async () => {
    const { api, dispatched } = fakeApi();
    const { epc, peerConnections } = await connect(api);
    jest.useFakeTimers();

    await epc.onnegotiationneeded?.call(epc, new Event("negotiationneeded"));
    peerConnections.splice(peerConnections.indexOf(epc), 1);
    const afterRemoval = dispatched.length;

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS);
    await flushMicrotasks();
    expect(dispatched.slice(afterRemoval)).toEqual([]);
  });
});
