import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";

import { configureStore } from "@reduxjs/toolkit";

import type { Store } from "@reduxjs/toolkit";
import type {
  IRTCPeerConnection,
  RTCPeerConnectionParams,
} from "../../../src/api/webrtc/interfaces";
import type { PeerSocketGenerationObservation } from "../../../src/api/webrtc/peerSocketGeneration";

// The webrtc api imports the Redux store, whose identity slice reads
// localStorage at module initialization. Install the minimal shim first.
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

const ROOM_ID = "00000000-0000-4000-8000-0000000000d1";
const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000d2";
const PEER_ID = "00000000-0000-4000-8000-0000000000d3";
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
// The higher identity is the protocol RESPONDER, so baseQuery opens no main
// channel and no handshake runs: the seam is all that is under test here.
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const G1 = "11111111-1111-4111-8111-111111111111";
const G2 = "22222222-2222-4222-8222-222222222222";

type WebrtcApi = (typeof import("../../../src/api/webrtc"))["default"];

let webrtcApi: WebrtcApi;
let store: Store;
let restore: () => void;

/** Every transport handleConnectToPeer was asked to build, in order. */
const built: (IRTCPeerConnection & { closed: boolean })[] = [];
/** Every generation decision baseQuery asked for, in order. */
const observations: PeerSocketGenerationObservation[] = [];

const fakeTransport = (): IRTCPeerConnection & { closed: boolean } => {
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: LOWER_PUBLIC_KEY,
    // Connected on purpose: only a frame whose SOURCE says "connection" may
    // retire a healthy edge, so the rebuild below cannot happen unless the
    // source label crossed the seam too.
    connectionState: "connected" as RTCPeerConnectionState,
    signalingState: "stable" as RTCSignalingState,
    localDescription: null,
    remoteDescription: null,
    iceCandidates: [] as RTCIceCandidateInit[],
    closed: false,
    close: () => {
      epc.closed = true;
      (epc as { connectionState: RTCPeerConnectionState }).connectionState =
        "closed";
    },
  } as unknown as IRTCPeerConnection & { closed: boolean };
  return epc;
};

beforeAll(async () => {
  await import("../../../src/store");
  // The database worker bundle is not inlined under `bun test`, so the
  // fail-closed blacklist lookup would report every peer as blocked and
  // baseQuery would return before it ever looked at a generation.
  const dbApi = await import("../../../src/db/api");
  const blacklist = spyOn(dbApi, "getDBPeerIsBlacklisted").mockImplementation(
    async () => false,
  );

  // Building a real RTCPeerConnection is not what this test is about: stand in
  // for it so the assertions can be about the parameters baseQuery received.
  const connectModule =
    await import("../../../src/handlers/handleConnectToPeer");
  const connect = spyOn(
    connectModule,
    "handleConnectToPeer",
  ).mockImplementation((async () => {
    const epc = fakeTransport();
    built.push(epc);
    return epc;
  }) as never);

  // Record what baseQuery asks, then answer it for real: the decision must stay
  // the production one, or the rebuild asserted below would prove nothing.
  const generationModule =
    await import("../../../src/api/webrtc/peerSocketGeneration");
  const decide = generationModule.shouldRetireTransportForSocketGeneration;
  const observe = spyOn(
    generationModule,
    "shouldRetireTransportForSocketGeneration",
  ).mockImplementation((observation: PeerSocketGenerationObservation) => {
    observations.push(observation);
    return decide(observation);
  });

  ({ default: webrtcApi } = await import("../../../src/api/webrtc"));

  store = configureStore({
    reducer: {
      [webrtcApi.reducerPath]: webrtcApi.reducer,
      keyPair: () => ({
        peerId: SELF_PEER_ID,
        publicKey: HIGHER_PUBLIC_KEY,
        secretKey: "",
        challengeId: "",
        challenge: "",
        signature: "",
      }),
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware({
        serializableCheck: false,
        immutableCheck: false,
      }).concat(webrtcApi.middleware),
    enhancers: (defaults) => defaults({ autoBatch: { type: "tick" } }),
  });

  restore = () => {
    blacklist.mockRestore();
    connect.mockRestore();
    observe.mockRestore();
  };
});

afterAll(async () => {
  restore();
  const { clearRetiredPeerSocketGenerations } =
    await import("../../../src/api/webrtc/peerSocketGeneration");
  clearRetiredPeerSocketGenerations(ROOM_ID, PEER_ID);
});

const dispatchConnectWithPeer = async (
  params: Partial<RTCPeerConnectionParams>,
): Promise<void> => {
  await store.dispatch(
    webrtcApi.endpoints.connectWithPeer.initiate({
      roomId: ROOM_ID,
      peerId: PEER_ID,
      peerPublicKey: LOWER_PUBLIC_KEY,
      rtcConfig: { iceServers: [] },
      ...params,
    }) as never,
  );
};

// THE SEAM. The producers (connectionSignal, handleWebSocketMessage) hand the
// generation to `connectWithPeer.initiate`, which runs BEFORE the endpoint's
// query transform; baseQuery reads it AFTER. A test on either side passes even
// when the transform in between drops the field, which is exactly what shipped:
// both generation fields were absent from the object the transform built, so
// every generation decision in production saw `undefined` and the C1 fix was
// dead code. This test dispatches the real endpoint through a real store, so
// initiate -> transform -> baseQuery all run, and asserts on values only
// baseQuery can produce.
describe("connectWithPeer carries the socket generation across the endpoint seam", () => {
  test("a dispatched connection frame's generation and source reach baseQuery", async () => {
    await dispatchConnectWithPeer({
      peerSocketGeneration: G1,
      peerSocketGenerationSource: "connection",
    });

    // Only baseQuery stamps this, and only from the parameter it was handed.
    expect(built).toHaveLength(1);
    expect(built[0].peerSocketGeneration).toBe(G1);

    await dispatchConnectWithPeer({
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "connection",
    });

    // The edge existed this time, so baseQuery had to weigh the new generation
    // against the recorded one -- with the source that decides whether a
    // CONNECTED transport may be retired at all.
    expect(observations).toHaveLength(1);
    expect(observations[0].recorded).toBe(G1);
    expect(observations[0].observed).toBe(G2);
    expect(observations[0].source).toBe("connection");

    // And the edge was actually rebuilt, which a dropped source label alone
    // would have prevented.
    expect(built).toHaveLength(2);
    expect(built[0].closed).toBe(true);
    expect(built[1].peerSocketGeneration).toBe(G2);
  }, 20000);
});
