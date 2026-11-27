import { afterEach, beforeAll, describe, expect, jest, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { PeerHandshakeStatus } from "../../src/reducers/roomSlice";

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
type UnnegotiatedTransport =
  typeof import("../../src/api/webrtc/unnegotiatedTransport");

let handleConnectToPeer: HandleConnectToPeer["handleConnectToPeer"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let setPeer: RoomSlice["setPeer"];
let PENDING_OFFER_TIMEOUT_MS: PendingOffer["PENDING_OFFER_TIMEOUT_MS"];
let MAX_UNNEGOTIATED_TRANSPORT_REBUILDS: UnnegotiatedTransport["MAX_UNNEGOTIATED_TRANSPORT_REBUILDS"];
let clearUnnegotiatedTransportRebuilds: UnnegotiatedTransport["clearUnnegotiatedTransportRebuilds"];
let recordUnnegotiatedTransportRebuild: UnnegotiatedTransport["recordUnnegotiatedTransportRebuild"];
let unnegotiatedTransportRebuilds: UnnegotiatedTransport["unnegotiatedTransportRebuilds"];

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
  ({
    MAX_UNNEGOTIATED_TRANSPORT_REBUILDS,
    clearUnnegotiatedTransportRebuilds,
    recordUnnegotiatedTransportRebuild,
    unnegotiatedTransportRebuilds,
  } = await import("../../src/api/webrtc/unnegotiatedTransport"));
});

afterEach(() => {
  jest.useRealTimers();
  clearUnnegotiatedTransportRebuilds(ROOM_ID, PEER_ID);
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000bb";
const ROOM_URL = "bb".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
// The lexicographically lower canonical identity is the initiator that offers.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fakeApi = (
  selfPublicKey: string = LOWER_PUBLIC_KEY,
  handshakeStatusByPeer: Record<string, PeerHandshakeStatus> = {},
  rtcConfig: RTCConfiguration = { iceServers: [] },
): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      publicKey: selfPublicKey,
      secretKey: "",
      challengeId: "",
      challenge: "",
      signature: "",
    },
    rooms: [
      {
        id: ROOM_ID,
        url: ROOM_URL,
        rtcConfig,
        signalingActive: true,
        handshakeStatusByPeer,
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
  peerPublicKey: string = HIGHER_PUBLIC_KEY,
  peerConnections: IRTCPeerConnection[] = [],
): Promise<{
  epc: IRTCPeerConnection;
  peerConnections: IRTCPeerConnection[];
}> => {
  const epc = await handleConnectToPeer(
    {
      peerId: PEER_ID,
      peerPublicKey,
      roomId: ROOM_ID,
      peerConnections,
    },
    api,
  );
  return { epc, peerConnections };
};

/**
 * The protocol RESPONDER side of an edge: the higher identity holds it, and it
 * creates no data channel, so its fresh transport negotiates nothing at all.
 */
const connectAsResponder = (
  api: BaseQueryApi,
  peerConnections: IRTCPeerConnection[] = [],
) => connect(api, LOWER_PUBLIC_KEY, peerConnections);

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
  test("relay-only signaling forwards only local relay candidates", async () => {
    const { api, dispatched } = fakeApi(
      LOWER_PUBLIC_KEY,
      {},
      { iceTransportPolicy: "relay" },
    );
    const { epc } = await connect(api);
    const baseline = thunks(dispatched).length;
    const emit = (type: RTCIceCandidateType) =>
      epc.onicecandidate!.call(epc, {
        candidate: { type, candidate: "candidate:fixture" },
      } as RTCPeerConnectionIceEvent);
    await emit("host");
    await emit("srflx");
    await emit("prflx");
    expect(thunks(dispatched)).toHaveLength(baseline);
    await emit("relay");
    expect(thunks(dispatched)).toHaveLength(baseline + 1);
    epc.close();
  });

  test.each(["pin-mismatch", "pin-throttled", "policy"] as const)(
    "%s cannot create another transport until deliberate retry",
    async (reason) => {
      const { api } = fakeApi(LOWER_PUBLIC_KEY, {
        [PEER_ID]: {
          status: "failed",
          reason,
          peerPublicKey: HIGHER_PUBLIC_KEY,
        },
      });
      await expect(connect(api)).rejects.toThrow("requires deliberate retry");
    },
  );

  test("a new signaling peerId cannot bypass the same identity's terminal failure", async () => {
    const { api } = fakeApi(LOWER_PUBLIC_KEY, {
      "old-peer-id": {
        status: "failed",
        reason: "pin-mismatch",
        peerPublicKey: HIGHER_PUBLIC_KEY,
      },
    });
    await expect(connect(api)).rejects.toThrow("requires deliberate retry");
  });

  test("transport failure and a different identity's failure still allow recovery", async () => {
    const { api } = fakeApi(LOWER_PUBLIC_KEY, {
      [PEER_ID]: {
        status: "failed",
        reason: "transport",
        peerPublicKey: HIGHER_PUBLIC_KEY,
      },
      "other-peer": {
        status: "failed",
        reason: "pin-mismatch",
        peerPublicKey: "aa".repeat(32),
      },
    });
    const { epc } = await connect(api);
    expect(epc.withPeerPublicKey).toBe(HIGHER_PUBLIC_KEY);
    epc.close();
  });

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

// C1, client half. A responder builds no channel, so onnegotiationneeded never
// fires: the transport holds no description of any kind, no ICE runs, nothing
// fails, and neither the offer watchdog nor the rebind deadline watches it. It
// is the state the second session of one identity is stranded in.
describe("handleConnectToPeer un-negotiated responder transport", () => {
  test("a responder transport nobody ever dials is torn down and re-dialled", async () => {
    // The watchdog is armed while the transport is built, so the clock has to
    // be fake before that: nothing in this path awaits a timer.
    jest.useFakeTimers();
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);
    const { epc, peerConnections } = await connectAsResponder(api);
    const afterConnect = dispatched.length;
    expect(epc.signalingState).toBe("stable");
    expect(epc.localDescription).toBeNull();
    expect(epc.remoteDescription).toBeNull();

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS - 1);
    await flushMicrotasks();
    expect(dispatched.slice(afterConnect)).toEqual([]);

    jest.advanceTimersByTime(1);
    await flushMicrotasks();
    const followUp = dispatched.slice(afterConnect);
    expect(followUp).toHaveLength(2);
    expect(typeof followUp[0]).toBe("function");
    expect(followUp[1]).toEqual(REDIAL());
    expect(unnegotiatedTransportRebuilds(ROOM_ID, PEER_ID)).toBe(1);
    expect(peerConnections).toContain(epc);
  });

  test("a responder transport that received a description is left alone", async () => {
    jest.useFakeTimers();
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);
    const { epc } = await connectAsResponder(api);
    await epc.setRemoteDescription({ type: "offer", sdp: "v=0\r\n" });
    const afterOffer = dispatched.length;

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS * 2);
    await flushMicrotasks();
    expect(dispatched.slice(afterOffer)).toEqual([]);
    expect(unnegotiatedTransportRebuilds(ROOM_ID, PEER_ID)).toBe(0);
  });

  // The initiator's un-answered first offer is the OTHER watchdog's job; both
  // firing on one transport would double every teardown.
  test("an initiator transport is not watched by the un-negotiated watchdog", async () => {
    jest.useFakeTimers();
    const { api, dispatched } = fakeApi();
    await connect(api);
    const afterConnect = dispatched.length;

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS * 2);
    await flushMicrotasks();
    expect(dispatched.slice(afterConnect)).toEqual([]);
    expect(unnegotiatedTransportRebuilds(ROOM_ID, PEER_ID)).toBe(0);
  });

  // Against a PRE-generation server the peer never rebuilds its own side, so
  // an uncapped watchdog would tear this edge down every 15 s forever.
  test("a spent rebuild budget stops the churn instead of re-dialling", async () => {
    jest.useFakeTimers();
    for (let i = 0; i < MAX_UNNEGOTIATED_TRANSPORT_REBUILDS; i++)
      recordUnnegotiatedTransportRebuild(ROOM_ID, PEER_ID);
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);
    await connectAsResponder(api);
    const afterConnect = dispatched.length;

    jest.advanceTimersByTime(PENDING_OFFER_TIMEOUT_MS);
    await flushMicrotasks();
    expect(dispatched.slice(afterConnect)).toEqual([]);
    expect(unnegotiatedTransportRebuilds(ROOM_ID, PEER_ID)).toBe(
      MAX_UNNEGOTIATED_TRANSPORT_REBUILDS,
    );
  });

  test("an edge that reaches connected starts from a clean budget again", async () => {
    jest.useFakeTimers();
    recordUnnegotiatedTransportRebuild(ROOM_ID, PEER_ID);
    const { api } = fakeApi(HIGHER_PUBLIC_KEY);
    const { epc } = await connectAsResponder(api);

    await driveConnectionState(epc, "connected");
    expect(unnegotiatedTransportRebuilds(ROOM_ID, PEER_ID)).toBe(0);
  });
});
