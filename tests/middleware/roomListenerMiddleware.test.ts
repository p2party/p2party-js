import { beforeAll, describe, expect, test } from "bun:test";
import { configureStore } from "@reduxjs/toolkit";

import type { Middleware } from "@reduxjs/toolkit";
import type { State } from "../../src/store";
import type { ManagedRoom } from "../../src/reducers/roomSlice";

// The listener middleware imports the signaling API, which imports the Redux
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

type Store = typeof import("../../src/store");
type CommonSlice = typeof import("../../src/reducers/commonSlice");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type SignalingSlice = typeof import("../../src/reducers/signalingServerSlice");
type KeyPairSlice = typeof import("../../src/reducers/keyPairSlice");
type SignalingApi = typeof import("../../src/api/signalingServerApi");
type WebrtcApi = typeof import("../../src/api/webrtc");
type RoomListener =
  typeof import("../../src/middleware/roomListenerMiddleware");

let appStore: Store["store"];
let commonStateReducer: CommonSlice["default"];
let roomReducer: RoomSlice["default"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let signalingServerReducer: SignalingSlice["default"];
let keyPairReducer: KeyPairSlice["default"];
let signalingServerApi: SignalingApi["default"];
let webrtcApi: WebrtcApi["default"];
let roomListenerMiddleware: RoomListener["default"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the middleware module loads.
  ({ store: appStore } = await import("../../src/store"));
  ({ default: commonStateReducer } =
    await import("../../src/reducers/commonSlice"));
  ({ default: roomReducer, setConnectingToPeers } =
    await import("../../src/reducers/roomSlice"));
  ({ default: signalingServerReducer } =
    await import("../../src/reducers/signalingServerSlice"));
  ({ default: keyPairReducer } =
    await import("../../src/reducers/keyPairSlice"));
  ({ default: signalingServerApi } =
    await import("../../src/api/signalingServerApi"));
  ({ default: webrtcApi } = await import("../../src/api/webrtc"));
  ({ default: roomListenerMiddleware } =
    await import("../../src/middleware/roomListenerMiddleware"));
});

// Unique to this file: the peer-request debouncer is a module singleton keyed
// by room, and Bun shares module state across test files.
const ROOM_ID = "00000000-0000-4000-8000-0000000000cc";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";

/**
 * A store with the production reducer/middleware set plus a recorder. The
 * signaling socket is never opened here, so every peers request fails at the
 * queryFn; what matters is whether the listener dispatched it at all, which
 * RTK Query exposes as the mutation's `pending` action.
 *
 * The preloaded state starts from the application store's own initial state
 * so that it is a complete `State`, then installs a verified socket, a
 * signaling identity and one active room.
 */
const testStore = () => {
  let peersRequests = 0;
  let settled = 0;
  const recorder: Middleware = () => (next) => (action) => {
    const typed = action as {
      type?: string;
      payload?: { connectingToPeers?: boolean };
      meta?: { arg?: { originalArgs?: { content?: { type?: string } } } };
    };
    if (
      typed.type ===
        `${signalingServerApi.reducerPath}/executeMutation/pending` &&
      typed.meta?.arg?.originalArgs?.content?.type === "peers"
    )
      peersRequests += 1;
    // The listener ends every setConnectingToPeers(true) effect by resetting
    // the flag, so counting those is how a test waits for the effect.
    if (
      typed.type === setConnectingToPeers.type &&
      typed.payload?.connectingToPeers === false
    )
      settled += 1;
    return next(action);
  };
  const base = appStore.getState();
  const room = {
    id: ROOM_ID,
    url: "cc".repeat(32),
    rtcConfig: { iceServers: [] },
    callerRtcConfig: { iceServers: [] },
    signalingTurnCredentials: null,
    roomResponseGeneration: 0,
    signalingActive: true,
    connectingToPeers: false,
    connectedToPeers: false,
    canBeConnectionRelay: false,
    onlyConnectWithKnownAddresses: false,
    peers: [],
    channels: [],
    messages: [],
  } as unknown as ManagedRoom;
  const preloadedState: State = {
    ...base,
    keyPair: {
      ...base.keyPair,
      peerId: SELF_PEER_ID,
      publicKey: `${"00".repeat(31)}01`,
    },
    rooms: [room],
    signalingServer: {
      isEstablishingConnection: false,
      isConnected: true,
      isVerified: true,
      serverUrl: "wss://signal.example/ws",
    },
  };
  const store = configureStore({
    reducer: {
      commonState: commonStateReducer,
      keyPair: keyPairReducer,
      rooms: roomReducer,
      signalingServer: signalingServerReducer,
      [signalingServerApi.reducerPath]: signalingServerApi.reducer,
      [webrtcApi.reducerPath]: webrtcApi.reducer,
    },
    preloadedState,
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware({
        serializableCheck: false,
        immutableCheck: false,
      }).concat([
        recorder,
        signalingServerApi.middleware,
        webrtcApi.middleware,
        roomListenerMiddleware.middleware,
      ]),
  });
  return {
    store,
    peersRequests: () => peersRequests,
    settled: () => settled,
  };
};

const waitFor = async (predicate: () => boolean): Promise<void> => {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for effect");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
};

describe("roomListenerMiddleware peers request debounce keys", () => {
  test("a re-dial inside the join window still sends a peers request, a second join does not", async () => {
    const { store, peersRequests, settled } = testStore();

    store.dispatch(
      setConnectingToPeers({ roomId: ROOM_ID, connectingToPeers: true }),
    );
    await waitFor(() => settled() === 1);
    expect(peersRequests()).toBe(1);

    // Same key within PEERS_REQUEST_DEBOUNCE_MS: swallowed.
    store.dispatch(
      setConnectingToPeers({ roomId: ROOM_ID, connectingToPeers: true }),
    );
    await waitFor(() => settled() === 2);
    expect(peersRequests()).toBe(1);

    // An edge teardown re-dial has its own budget and goes out.
    store.dispatch(
      setConnectingToPeers({
        roomId: ROOM_ID,
        connectingToPeers: true,
        reason: "redial",
      }),
    );
    await waitFor(() => settled() === 3);
    expect(peersRequests()).toBe(2);

    // ...and is itself debounced.
    store.dispatch(
      setConnectingToPeers({
        roomId: ROOM_ID,
        connectingToPeers: true,
        reason: "redial",
      }),
    );
    await waitFor(() => settled() === 4);
    expect(peersRequests()).toBe(2);
  });
});
