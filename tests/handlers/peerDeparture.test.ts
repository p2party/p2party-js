import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import { configureStore } from "@reduxjs/toolkit";

import type { Middleware } from "@reduxjs/toolkit";
import type { State } from "../../src/store";
import type { ManagedRoom } from "../../src/reducers/roomSlice";
import type { RoomRosterReconciler } from "../../src/utils/roomRosterReconciler";

// The message handler imports the signaling API, which imports the Redux
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

const ROOM_ID = "00000000-0000-4000-8000-0000000000f1";
const OTHER_ROOM_ID = "00000000-0000-4000-8000-0000000000f2";
const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000f3";
const PEER_ID = "00000000-0000-4000-8000-0000000000f4";
const UNKNOWN_PEER_ID = "00000000-0000-4000-8000-0000000000f5";
const SELF_PUBLIC_KEY = `${"00".repeat(31)}01`;
const PEER_PUBLIC_KEY = "f4".repeat(32);
/** The peer's socket before it went away, and the one it came back on. */
const GENERATION = "11111111-1111-4111-8111-111111111111";
const RETURN_GENERATION = "22222222-2222-4222-8222-222222222222";

type Handler = typeof import("../../src/handlers/handleWebSocketMessage");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type Debouncer = typeof import("../../src/utils/signalingPeerRequestDebouncer");

/** What the transport registry holds for the peer, as the handler reads it. */
interface FakeEdge {
  roomId: string;
  withPeerId: string;
  connectionState: RTCPeerConnectionState;
  closes: number;
  close: () => void;
}

let handleWebSocketMessage: Handler["default"];
let roomSlice: RoomSlice;
let debouncer: Debouncer["signalingPeerRequestDebouncer"];
let makeStore: () => {
  store: ReturnType<typeof configureStore>;
  timeouts: FakeTimeouts;
  reconciler: RoomRosterReconciler;
  reconcileTargets: (string | undefined)[];
};
let edges: FakeEdge[] = [];
let dialled: { roomId: string; peerId: string }[] = [];
let disconnected: { roomId?: string; peerId: string }[] = [];
let restore: () => void;
const live: { reconciler: RoomRosterReconciler; roomIds: string[] }[] = [];

/** Virtual timeouts for the reconcile backoff: no wall-clock waits. */
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

const thunk = () =>
  Object.assign(async () => ({ data: undefined }), {
    unwrap: async () => undefined,
  });

beforeAll(async () => {
  const { store: appStore } = await import("../../src/store");
  const dbApi = await import("../../src/db/api");
  // Under `bun test` the database worker is absent and the fail-closed
  // blacklist lookup would refuse every peer.
  const blacklist = spyOn(dbApi, "getDBPeerIsBlacklisted").mockImplementation(
    async () => false,
  );
  const webrtc = await import("../../src/api/webrtc");
  const registry = spyOn(webrtc, "snapshotPeerConnections").mockImplementation(
    () => edges as never,
  );
  const connect = spyOn(
    webrtc.default.endpoints.connectWithPeer,
    "initiate",
  ).mockImplementation(((params: { roomId: string; peerId: string }) => {
    dialled.push({ roomId: params.roomId, peerId: params.peerId });
    return thunk();
  }) as never);
  const disconnect = spyOn(
    webrtc.default.endpoints.disconnectFromPeer,
    "initiate",
  ).mockImplementation(((params: { roomId?: string; peerId: string }) => {
    disconnected.push({ roomId: params.roomId, peerId: params.peerId });
    return thunk();
  }) as never);
  restore = () => {
    blacklist.mockRestore();
    registry.mockRestore();
    connect.mockRestore();
    disconnect.mockRestore();
  };

  ({ default: handleWebSocketMessage } =
    await import("../../src/handlers/handleWebSocketMessage"));
  roomSlice = await import("../../src/reducers/roomSlice");
  ({ signalingPeerRequestDebouncer: debouncer } =
    await import("../../src/utils/signalingPeerRequestDebouncer"));
  const { default: commonStateReducer } =
    await import("../../src/reducers/commonSlice");
  const { default: signalingServerReducer } =
    await import("../../src/reducers/signalingServerSlice");
  const { default: keyPairReducer } =
    await import("../../src/reducers/keyPairSlice");
  const { default: signalingServerApi } =
    await import("../../src/api/signalingServerApi");
  const { createRoomListenerMiddleware } =
    await import("../../src/middleware/roomListenerMiddleware");
  const { createRoomRosterReconciler } =
    await import("../../src/utils/roomRosterReconciler");

  makeStore = () => {
    const timeouts = new FakeTimeouts();
    const reconciler = createRoomRosterReconciler({
      schedule: {
        setTimeout: timeouts.setTimeout,
        clearTimeout: timeouts.clearTimeout,
      },
      delaysMs: [5_000, 10_000],
      maxAttempts: 4,
    });
    const reconcileTargets: (string | undefined)[] = [];
    const recorder: Middleware = () => (next) => (action) => {
      const typed = action as {
        type?: string;
        payload?: { connectingToPeers?: boolean; peerId?: string };
      };
      if (
        typed.type === roomSlice.setConnectingToPeers.type &&
        typed.payload?.connectingToPeers === true
      )
        reconcileTargets.push(typed.payload.peerId);
      return next(action);
    };
    const room = (id: string) =>
      ({
        id,
        url: id.slice(-2).repeat(32),
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
      }) as unknown as ManagedRoom;
    const base = appStore.getState();
    const store = configureStore({
      reducer: {
        commonState: commonStateReducer,
        keyPair: keyPairReducer,
        rooms: roomSlice.default,
        signalingServer: signalingServerReducer,
        [signalingServerApi.reducerPath]: signalingServerApi.reducer,
        [webrtc.default.reducerPath]: webrtc.default.reducer,
      },
      preloadedState: {
        ...base,
        keyPair: {
          ...base.keyPair,
          peerId: SELF_PEER_ID,
          publicKey: SELF_PUBLIC_KEY,
        },
        rooms: [room(ROOM_ID), room(OTHER_ROOM_ID)],
        signalingServer: {
          isEstablishingConnection: false,
          isConnected: true,
          isVerified: true,
          serverUrl: "wss://signal.example/ws",
        },
      } as State,
      // RTK Query's batched notifications on a microtask, not on the default
      // 10 ms timer, so no timer of this store outlives the file.
      enhancers: (getDefaultEnhancers) =>
        getDefaultEnhancers({ autoBatch: { type: "tick" } }),
      middleware: (getDefaultMiddleware) =>
        getDefaultMiddleware({
          serializableCheck: false,
          immutableCheck: false,
        }).concat([
          recorder,
          signalingServerApi.middleware,
          webrtc.default.middleware,
          createRoomListenerMiddleware(reconciler).middleware,
        ]),
    });
    live.push({ reconciler, roomIds: [ROOM_ID, OTHER_ROOM_ID] });
    return { store, timeouts, reconciler, reconcileTargets };
  };
});

afterEach(() => {
  // Every timer a test started: the fake reconcile backoff, and the shared
  // peer-request debouncer's trailing requests.
  for (const { reconciler, roomIds } of live.splice(0)) {
    reconciler.cancelAll();
    for (const roomId of roomIds) debouncer.cancelRoom(roomId);
  }
  edges = [];
  dialled = [];
  disconnected = [];
});

afterAll(() => {
  restore();
});

type TestStore = ReturnType<typeof makeStore>["store"];

const rooms = (store: TestStore) => (store.getState() as State).rooms;
const room = (store: TestStore, roomId = ROOM_ID) =>
  rooms(store).find((candidate) => candidate.id === roomId)!;
const ids = (peers: readonly { peerId: string }[] | undefined) =>
  (peers ?? []).map((peer) => peer.peerId);

const deliver = async (store: TestStore, frame: unknown): Promise<void> => {
  await handleWebSocketMessage(
    { data: JSON.stringify(frame) } as MessageEvent,
    { readyState: 1, send: () => undefined } as unknown as WebSocket,
    store as never,
    () => true,
  );
};

const peerLeft = (
  reason: string,
  socketGeneration: unknown = GENERATION,
  overrides: Record<string, unknown> = {},
) => ({
  type: "peerLeft",
  roomId: ROOM_ID,
  peerId: PEER_ID,
  reason,
  socketGeneration,
  protocolVersion: 4,
  ...overrides,
});

/** The server's acceptance delta naming the peer on `socketGeneration`. */
const delta = (socketGeneration: string, roomId = ROOM_ID) => ({
  type: "peers",
  rosterKind: "delta",
  roomId,
  protocolVersion: 4,
  peers: [{ id: PEER_ID, publicKey: PEER_PUBLIC_KEY, socketGeneration }],
});

/** The server introducing the peer, which asked for peers on `socketGeneration`. */
const introduction = (socketGeneration: string) => ({
  type: "peerConnection",
  roomId: ROOM_ID,
  peer: { id: PEER_ID, publicKey: PEER_PUBLIC_KEY, socketGeneration },
  protocolVersion: 4,
});

const edge = (connectionState: RTCPeerConnectionState): FakeEdge => {
  const fake: FakeEdge = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    connectionState,
    closes: 0,
    close: () => {
      fake.closes += 1;
    },
  };
  return fake;
};

/**
 * A room whose last snapshot lists the peer, and which the server introduced
 * on GENERATION. The edge, if any, is in `connectionState`; the peer has not
 * authenticated, so the reconciler keeps retrying it.
 */
const joined = async (connectionState?: RTCPeerConnectionState) => {
  const harness = makeStore();
  harness.store.dispatch(
    roomSlice.setKnownRoomPeers({
      roomId: ROOM_ID,
      peers: [{ peerId: PEER_ID, peerPublicKey: PEER_PUBLIC_KEY }],
    }),
  );
  await deliver(harness.store, delta(GENERATION));
  if (connectionState) edges = [edge(connectionState)];
  dialled = [];
  return harness;
};

const retryKey = `${ROOM_ID}/${PEER_ID}`;

/** Reconcile retries aimed at the peer while `ms` of virtual time pass. */
const retriesOver = (harness: ReturnType<typeof makeStore>, ms: number) => {
  const before = harness.reconcileTargets.filter((id) => id === PEER_ID).length;
  harness.timeouts.advance(ms);
  return (
    harness.reconcileTargets.filter((id) => id === PEER_ID).length - before
  );
};

/** The edge closing: disconnectFromPeer's reducer step. */
const edgeCloses = (store: TestStore) => {
  store.dispatch(roomSlice.deletePeer({ peerId: PEER_ID, roomId: ROOM_ID }));
};

describe("peerLeft: reason left", () => {
  test("left removes a peer that has no connected edge and cancels dialling", async () => {
    const harness = await joined("connecting");
    const { store, reconciler } = harness;
    expect(reconciler.armedRooms()).toContain(retryKey);

    await deliver(store, peerLeft("left"));

    expect(ids(room(store).peers)).toEqual([]);
    expect(ids(room(store).knownPeers)).toEqual([]);
    expect(room(store).peerPresence?.[PEER_ID]).toBeUndefined();
    // The negotiation still in progress is abandoned...
    expect(disconnected).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    // ...and nothing retries the peer.
    expect(reconciler.armedRooms()).not.toContain(retryKey);
    expect(retriesOver(harness, 600_000)).toBe(0);
    expect(dialled).toEqual([]);
  });

  test("left keeps a connected edge and removes the peer when it closes", async () => {
    const harness = await joined("connected");
    const { store, reconciler } = harness;

    await deliver(store, peerLeft("left"));

    expect(ids(room(store).peers)).toEqual([PEER_ID]);
    expect(ids(room(store).knownPeers)).toEqual([PEER_ID]);
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: GENERATION,
      departure: "left",
    });
    expect(disconnected).toEqual([]);
    expect(edges[0].closes).toBe(0);
    expect(reconciler.armedRooms()).not.toContain(retryKey);

    // A peer that really leaves closes its own connections.
    edgeCloses(store);

    expect(ids(room(store).peers)).toEqual([]);
    expect(ids(room(store).knownPeers)).toEqual([]);
    expect(room(store).peerPresence?.[PEER_ID]).toBeUndefined();
    expect(reconciler.armedRooms()).not.toContain(retryKey);
    expect(retriesOver(harness, 600_000)).toBe(0);
  });
});

describe("peerLeft: reason offline", () => {
  test("offline keeps a connected edge", async () => {
    const harness = await joined("connected");
    const { store, reconciler } = harness;

    await deliver(store, peerLeft("offline"));

    expect(ids(room(store).peers)).toEqual([PEER_ID]);
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: GENERATION,
      departure: "offline",
    });
    expect(disconnected).toEqual([]);
    expect(edges[0].closes).toBe(0);

    // When the edge closes the member stays in the snapshot, marked, and is
    // not re-dialled.
    edgeCloses(store);
    expect(ids(room(store).peers)).toEqual([]);
    expect(ids(room(store).knownPeers)).toEqual([PEER_ID]);
    expect(room(store).peerPresence?.[PEER_ID]?.departure).toBe("offline");
    expect(reconciler.armedRooms()).not.toContain(retryKey);
    expect(retriesOver(harness, 600_000)).toBe(0);
  });

  test("a peer reported offline is not re-dialled until it is announced again", async () => {
    const harness = await joined();
    const { store, reconciler } = harness;
    expect(retriesOver(harness, 5_000)).toBe(1);

    await deliver(store, peerLeft("offline"));
    expect(reconciler.armedRooms()).not.toContain(retryKey);
    expect(retriesOver(harness, 600_000)).toBe(0);

    // A snapshot lists offline members too: without a newer socket for the
    // peer it does not end the report.
    const rosterRequestId = debouncer.beginRosterRequest(ROOM_ID);
    await deliver(store, {
      type: "peers",
      rosterKind: "snapshot",
      rosterRequestId,
      roomId: ROOM_ID,
      protocolVersion: 4,
      peers: [{ id: PEER_ID, publicKey: PEER_PUBLIC_KEY }],
    });
    expect(room(store).peerPresence?.[PEER_ID]?.departure).toBe("offline");
    expect(retriesOver(harness, 600_000)).toBe(0);

    // The peer comes back and asks for peers: it is a member to retry again.
    await deliver(store, introduction(RETURN_GENERATION));
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: RETURN_GENERATION,
    });
    expect(reconciler.armedRooms()).toContain(retryKey);
    expect(retriesOver(harness, 5_000)).toBe(1);
  });

  test("a snapshot naming a new generation clears the offline mark, and one naming none does not", async () => {
    const harness = await joined();
    const { store, reconciler } = harness;
    await deliver(store, peerLeft("offline"));
    const snapshot = (socketGeneration?: string) => ({
      type: "peers",
      rosterKind: "snapshot",
      rosterRequestId: debouncer.beginRosterRequest(ROOM_ID),
      roomId: ROOM_ID,
      protocolVersion: 4,
      peers: [{ id: PEER_ID, publicKey: PEER_PUBLIC_KEY, socketGeneration }],
    });

    // Listed without a generation, as every offline member is: still offline.
    await deliver(store, snapshot());
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: GENERATION,
      departure: "offline",
    });
    // Listed on the socket that went offline: the snapshot is older than the
    // report, and still offline.
    await deliver(store, snapshot(GENERATION));
    expect(room(store).peerPresence?.[PEER_ID]?.departure).toBe("offline");
    expect(reconciler.armedRooms()).not.toContain(retryKey);
    expect(retriesOver(harness, 600_000)).toBe(0);

    // Listed on a new socket: the member is online again and retried.
    await deliver(store, snapshot(RETURN_GENERATION));
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: RETURN_GENERATION,
    });
    expect(reconciler.armedRooms()).toContain(retryKey);
    expect(retriesOver(harness, 5_000)).toBe(1);
    // A snapshot discovers; it never dials.
    expect(dialled).toEqual([]);
  });
});

describe("peerLeft: the server cannot end an edge", () => {
  test("a peerLeft frame never closes a connected edge", async () => {
    for (const reason of ["left", "offline"] as const)
      for (const state of ["connected", "disconnected"] as const) {
        const { store } = await joined(state);

        await deliver(store, peerLeft(reason));

        expect(disconnected).toEqual([]);
        expect(edges[0].closes).toBe(0);
        expect(ids(room(store).peers)).toEqual([PEER_ID]);
        // Recorded, so it governs what happens when the edge closes.
        expect(room(store).peerPresence?.[PEER_ID]?.departure).toBe(reason);
        for (const { reconciler, roomIds } of live.splice(0)) {
          reconciler.cancelAll();
          for (const roomId of roomIds) debouncer.cancelRoom(roomId);
        }
      }
  });

  test("a peer named again by a peers message is a member again", async () => {
    // Left with no edge: dropped, then accepted again by the server.
    const first = await joined();
    await deliver(first.store, peerLeft("left"));
    expect(ids(room(first.store).knownPeers)).toEqual([]);

    await deliver(first.store, delta(RETURN_GENERATION));
    expect(ids(room(first.store).peers)).toEqual([PEER_ID]);
    expect(ids(room(first.store).knownPeers)).toEqual([PEER_ID]);
    expect(room(first.store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: RETURN_GENERATION,
    });
    expect(dialled).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);

    // Left while connected: the report is withdrawn, so the closing edge
    // keeps the member and its retries.
    const second = await joined("connected");
    await deliver(second.store, peerLeft("left"));
    await deliver(second.store, delta(GENERATION));
    expect(room(second.store).peerPresence?.[PEER_ID]?.departure).toBe(
      undefined,
    );
    edgeCloses(second.store);
    expect(ids(room(second.store).knownPeers)).toEqual([PEER_ID]);
    expect(second.reconciler.armedRooms()).toContain(retryKey);
  });
});

describe("peerLeft: what changes nothing", () => {
  test("a peerLeft naming this client or an unknown peer changes nothing", async () => {
    const { store } = await joined("connecting");
    const logged: string[] = [];
    const consoleError = spyOn(console, "error").mockImplementation(
      (message: unknown) => {
        logged.push(String(message));
      },
    );
    const before = JSON.stringify(rooms(store));
    try {
      for (const frame of [
        peerLeft("left", GENERATION, { peerId: SELF_PEER_ID }),
        peerLeft("offline", GENERATION, { peerId: UNKNOWN_PEER_ID }),
        peerLeft("left", GENERATION, {
          roomId: "00000000-0000-4000-8000-0000000000ff",
        }),
        peerLeft("left", GENERATION, { peerId: "not-a-peer-id" }),
        peerLeft("kicked"),
        // No generation at all: JSON drops the undefined field.
        peerLeft("left", GENERATION, { socketGeneration: undefined }),
        peerLeft("left", "not-a-generation"),
        peerLeft("left", GENERATION, { protocolVersion: 3 }),
      ])
        await deliver(store, frame);
    } finally {
      consoleError.mockRestore();
    }

    expect(JSON.stringify(rooms(store))).toBe(before);
    expect(disconnected).toEqual([]);
    // Refused at the boundary, like other malformed server frames, and the
    // log names no peer.
    expect(logged).toEqual([
      ...Array(3).fill(
        "Rejecting a peer departure for this client, an unknown peer or an unknown room",
      ),
      ...Array(5).fill("Rejecting malformed peer departure"),
    ]);

    // The same frame for a tracked peer is applied, so the refusals above
    // are about what they name, not about the frame type.
    await deliver(store, peerLeft("left"));
    expect(ids(room(store).knownPeers)).toEqual([]);
  });
});

describe("peerLeft: ordering", () => {
  test("a stale peerLeft that arrives after the peer's return does not remove it", async () => {
    // The peer went away on GENERATION and came back on RETURN_GENERATION;
    // the report of its departure is delivered after its return (it was
    // produced by another worker, or queued behind the return).
    const harness = await joined("connecting");
    const { store, reconciler } = harness;
    await deliver(store, introduction(RETURN_GENERATION));

    await deliver(store, peerLeft("left", GENERATION));
    await deliver(store, peerLeft("offline", GENERATION));

    expect(ids(room(store).peers)).toEqual([PEER_ID]);
    expect(ids(room(store).knownPeers)).toEqual([PEER_ID]);
    expect(room(store).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: RETURN_GENERATION,
    });
    expect(disconnected).toEqual([]);
    expect(reconciler.armedRooms()).toContain(retryKey);

    // A departure of the session it came back on is applied.
    await deliver(store, peerLeft("left", RETURN_GENERATION));
    expect(ids(room(store).knownPeers)).toEqual([]);
    expect(disconnected).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
  });

  test("a departure in one room leaves the peer's other rooms alone", async () => {
    const harness = await joined();
    const { store } = harness;
    await deliver(store, delta(GENERATION, OTHER_ROOM_ID));

    await deliver(store, peerLeft("left"));

    expect(ids(room(store).peers)).toEqual([]);
    expect(ids(room(store, OTHER_ROOM_ID).peers)).toEqual([PEER_ID]);
    expect(room(store, OTHER_ROOM_ID).peerPresence?.[PEER_ID]).toEqual({
      socketGeneration: GENERATION,
    });
  });
});
