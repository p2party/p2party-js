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
type Reconciler = typeof import("../../src/utils/roomRosterReconciler");

let appStore: Store["store"];
let commonStateReducer: CommonSlice["default"];
let roomReducer: RoomSlice["default"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let setPeer: RoomSlice["setPeer"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let signalingServerReducer: SignalingSlice["default"];
let keyPairReducer: KeyPairSlice["default"];
let signalingServerApi: SignalingApi["default"];
let webrtcApi: WebrtcApi["default"];
let roomListenerMiddleware: RoomListener["default"];
let createRoomListenerMiddleware: RoomListener["createRoomListenerMiddleware"];
let createRoomRosterReconciler: Reconciler["createRoomRosterReconciler"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the middleware module loads.
  ({ store: appStore } = await import("../../src/store"));
  ({ default: commonStateReducer } =
    await import("../../src/reducers/commonSlice"));
  ({
    default: roomReducer,
    setConnectingToPeers,
    setPeer,
    setPeerHandshakeStatus,
  } = await import("../../src/reducers/roomSlice"));
  ({ default: signalingServerReducer } =
    await import("../../src/reducers/signalingServerSlice"));
  ({ default: keyPairReducer } =
    await import("../../src/reducers/keyPairSlice"));
  ({ default: signalingServerApi } =
    await import("../../src/api/signalingServerApi"));
  ({ default: webrtcApi } = await import("../../src/api/webrtc"));
  ({ default: roomListenerMiddleware, createRoomListenerMiddleware } =
    await import("../../src/middleware/roomListenerMiddleware"));
  ({ createRoomRosterReconciler } =
    await import("../../src/utils/roomRosterReconciler"));
});

// Unique to this file: the peer-request debouncer is a module singleton keyed
// by room, so every test here uses a room id of its own.
const ROOM_ID = "00000000-0000-4000-8000-0000000000cc";
const EMPTY_ROOM_ID = "00000000-0000-4000-8000-0000000000cd";
const LEFT_ROOM_ID = "00000000-0000-4000-8000-0000000000ce";
const REJOINED_ROOM_ID = "00000000-0000-4000-8000-0000000000cf";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const OTHER_PEER_ID = "00000000-0000-4000-8000-000000000002";

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
interface TestStoreOptions {
  readonly roomId?: string;
  readonly signalingActive?: boolean;
  readonly middleware?: Middleware;
}

const testStore = (options: TestStoreOptions = {}) => {
  const roomId = options.roomId ?? ROOM_ID;
  let peersRequests = 0;
  let settled = 0;
  const reasons: (string | undefined)[] = [];
  const recorder: Middleware = () => (next) => (action) => {
    const typed = action as {
      type?: string;
      payload?: { connectingToPeers?: boolean; reason?: string };
      meta?: { arg?: { originalArgs?: { content?: { type?: string } } } };
    };
    if (
      typed.type === setConnectingToPeers.type &&
      typed.payload?.connectingToPeers === true
    )
      reasons.push(typed.payload.reason);
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
    id: roomId,
    url: roomId.slice(-2).repeat(32),
    rtcConfig: { iceServers: [] },
    callerRtcConfig: { iceServers: [] },
    signalingTurnCredentials: null,
    roomResponseGeneration: 0,
    signalingActive: options.signalingActive ?? true,
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
        options.middleware ?? roomListenerMiddleware.middleware,
      ]),
  });
  return {
    store,
    roomId,
    peersRequests: () => peersRequests,
    settled: () => settled,
    reasons: () => [...reasons],
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

/** Virtual timeouts, so the backoff is driven without waiting on a real clock. */
class FakeTimeouts {
  #next = 1;
  #now = 0;
  readonly #timers = new Map<number, { at: number; run: () => void }>();

  readonly setTimeout = (run: () => void, delayMs: number): number => {
    const handle = this.#next++;
    this.#timers.set(handle, { at: this.#now + delayMs, run });
    return handle;
  };

  readonly clearTimeout = (handle: number): void => {
    this.#timers.delete(handle);
  };

  advance(ms: number): void {
    const target = this.#now + ms;
    for (;;) {
      const due = [...this.#timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      this.#now = due[1].at;
      this.#timers.delete(due[0]);
      due[1].run();
    }
    this.#now = target;
  }
}

const reconcilingStore = (options: TestStoreOptions = {}) => {
  const timeouts = new FakeTimeouts();
  const reconciler = createRoomRosterReconciler({
    schedule: {
      setTimeout: timeouts.setTimeout,
      clearTimeout: timeouts.clearTimeout,
    },
    delaysMs: [5_000, 10_000],
    maxAttempts: 4,
  });
  const listener = createRoomListenerMiddleware(reconciler);
  return {
    ...testStore({ ...options, middleware: listener.middleware }),
    timeouts,
    reconciler,
  };
};

describe("roomListenerMiddleware empty-room reconciliation", () => {
  test("an active room with nobody in it is asked again on the backoff", async () => {
    const { store, timeouts, reconciler, peersRequests, settled, reasons } =
      reconcilingStore({ roomId: EMPTY_ROOM_ID });

    store.dispatch(
      setConnectingToPeers({ roomId: EMPTY_ROOM_ID, connectingToPeers: true }),
    );
    await waitFor(() => settled() === 1);
    expect(peersRequests()).toBe(1);
    await waitFor(() => reconciler.armedRooms().includes(EMPTY_ROOM_ID));

    timeouts.advance(5_000);
    await waitFor(() => settled() === 2);
    // A second request went out within the join debounce window, so it can
    // only have come from the reconcile budget.
    expect(peersRequests()).toBe(2);
    expect(reasons()).toEqual([undefined, "reconcile"]);
    // Still stranded, so the backoff continues rather than retiring the room.
    expect(reconciler.armedRooms()).toEqual([EMPTY_ROOM_ID]);
  });

  test("a room the user left is never reconciled", async () => {
    const { store, timeouts, reconciler, peersRequests, settled } =
      reconcilingStore({ roomId: LEFT_ROOM_ID, signalingActive: false });

    store.dispatch(
      setConnectingToPeers({ roomId: LEFT_ROOM_ID, connectingToPeers: true }),
    );
    await waitFor(() => settled() === 1);
    const afterJoin = peersRequests();

    expect(reconciler.armedRooms()).toEqual([]);
    timeouts.advance(600_000);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(peersRequests()).toBe(afterJoin);
  });

  test("an authenticated peer ends the reconciliation", async () => {
    const { store, timeouts, reconciler, peersRequests, settled } =
      reconcilingStore({ roomId: REJOINED_ROOM_ID });

    store.dispatch(
      setConnectingToPeers({
        roomId: REJOINED_ROOM_ID,
        connectingToPeers: true,
      }),
    );
    await waitFor(() => settled() === 1);
    await waitFor(() => reconciler.armedRooms().includes(REJOINED_ROOM_ID));
    const afterJoin = peersRequests();

    store.dispatch(
      setPeer({
        roomId: REJOINED_ROOM_ID,
        peerId: OTHER_PEER_ID,
        peerPublicKey: `${"00".repeat(31)}02`,
      }),
    );
    store.dispatch(
      setPeerHandshakeStatus({
        roomId: REJOINED_ROOM_ID,
        peerId: OTHER_PEER_ID,
        peerPublicKey: `${"00".repeat(31)}02`,
        status: "authenticated",
      }),
    );
    await waitFor(() => reconciler.armedRooms().length === 0);

    timeouts.advance(600_000);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(peersRequests()).toBe(afterJoin);
  });
});
