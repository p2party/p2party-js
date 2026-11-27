import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";

import { configureStore } from "@reduxjs/toolkit";

import type { Store } from "@reduxjs/toolkit";
import type {
  ManagedRoom,
  PeerHandshakeStatus,
} from "../../../src/reducers/roomSlice";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// When the room's authoritative ICE configuration can neither be applied nor
// restored, applyRoomIceConfiguration retires every live transport of the room
// through the shared edge teardown. Through the real `applyRoomConfiguration`
// endpoint that teardown must get the API's own data-channel registry and
// dispatch, so the retired edge's channels leave the registry and its
// handshake status is cleared at once, not only when the closed transport is
// next retired. Everything here runs through real endpoints: connectWithPeer
// builds the transport and its main channel, applyRoomConfiguration retires
// it, and disconnectFromRoom (whose sweep visits every registered channel of
// the room) shows what the registry still holds.

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

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

/** The slice of RTCPeerConnection handleConnectToPeer builds and drives. */
class FakeRTCPeerConnection {
  /** Set to make every setConfiguration throw, as an unusable relay does. */
  static rejectConfiguration = false;

  connectionState: RTCPeerConnectionState = "new";
  signalingState: RTCSignalingState = "stable";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  readonly channels: RTCDataChannel[] = [];
  readonly configuration: RTCConfiguration;

  constructor(configuration: RTCConfiguration) {
    this.configuration = configuration;
  }

  getConfiguration(): RTCConfiguration {
    return this.configuration;
  }

  setConfiguration(): void {
    if (FakeRTCPeerConnection.rejectConfiguration)
      throw new Error("relay configuration rejected");
  }

  async setLocalDescription(): Promise<void> {}

  async setRemoteDescription(): Promise<void> {}

  restartIce(): void {}

  /** Parks the handshake at its DTLS fingerprint check for the whole test. */
  getStats(): Promise<RTCStatsReport> {
    return new Promise(() => undefined);
  }

  createDataChannel(label: string): RTCDataChannel {
    let readyState: RTCDataChannelState = "connecting";
    const channel = {
      label,
      get readyState() {
        return readyState;
      },
      binaryType: "blob",
      bufferedAmount: 0,
      send: () => undefined,
      close: () => {
        readyState = "closed";
      },
      open: () => {
        readyState = "open";
      },
    } as unknown as RTCDataChannel;
    this.channels.push(channel);
    return channel;
  }

  close(): void {
    this.connectionState = "closed";
    this.signalingState = "closed";
  }
}

(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
  FakeRTCPeerConnection;

const ROOM_ID = "00000000-0000-4000-8000-0000000000c9";
const ROOM_URL = "c9".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000ca";
const PEER_ID = "00000000-0000-4000-8000-0000000000cb";
// The lower identity is the protocol INITIATOR: connectWithPeer opens main.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

type WebrtcModule = typeof import("../../../src/api/webrtc");
type Orchestrator =
  typeof import("../../../src/handlers/pqHealingOrchestrator");

let webrtcApi: WebrtcModule["default"];
let snapshotPeerConnections: WebrtcModule["snapshotPeerConnections"];
let installPqHealingOrchestrator: Orchestrator["installPqHealingOrchestrator"];
let destroyPqHealingOrchestrator: Orchestrator["destroyPqHealingOrchestrator"];
let store: Store;
let restore: () => void;

/** Dispatch one endpoint thunk on the test store and await its outcome. */
const run = (thunk: unknown): Promise<unknown> =>
  (
    store.dispatch(thunk as never) as unknown as {
      unwrap: () => Promise<unknown>;
    }
  ).unwrap();

const room = (): ManagedRoom =>
  (store.getState() as { rooms: ManagedRoom[] }).rooms[0];

beforeAll(async () => {
  await import("../../../src/store");
  const { default: roomReducer } =
    await import("../../../src/reducers/roomSlice");
  const { DEFAULT_ROOM_POLICY_V1 } = await import("../../../src/roomPolicy");
  // The database worker bundle is not inlined under `bun test`: the
  // fail-closed blacklist lookup would refuse every peer, and the teardown's
  // delete of the edge's persisted ratchet row would only log a failure.
  const dbApi = await import("../../../src/db/api");
  const blacklist = spyOn(dbApi, "getDBPeerIsBlacklisted").mockImplementation(
    async () => false,
  );
  ({ default: webrtcApi, snapshotPeerConnections } =
    await import("../../../src/api/webrtc"));
  ({ installPqHealingOrchestrator, destroyPqHealingOrchestrator } =
    await import("../../../src/handlers/pqHealingOrchestrator"));

  const initialRoom = {
    id: ROOM_ID,
    url: ROOM_URL,
    rtcConfig: { iceServers: [] },
    signalingActive: true,
    policy: DEFAULT_ROOM_POLICY_V1,
    handshakeStatusByPeer: {} as Record<string, PeerHandshakeStatus>,
    peers: [],
    channels: [],
    messages: [],
  } as unknown as ManagedRoom;
  store = configureStore({
    reducer: {
      [webrtcApi.reducerPath]: webrtcApi.reducer,
      keyPair: () => ({
        peerId: SELF_PEER_ID,
        publicKey: LOWER_PUBLIC_KEY,
        secretKey: "",
        challengeId: "",
        challenge: "",
        signature: "",
      }),
      rooms: (state: ManagedRoom[] = [initialRoom], action) =>
        roomReducer(state, action),
      // Not connected: the transport skips the signaling `connectWithPeer`.
      signalingServer: () => ({
        isConnected: false,
        isEstablishingConnection: false,
        isVerified: false,
        serverUrl: "",
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
  };
});

afterAll(() => {
  FakeRTCPeerConnection.rejectConfiguration = false;
  restore();
});

describe("the applyRoomConfiguration endpoint", () => {
  test("applying a new ICE configuration clears the retired edge's registry entry and handshake status", async () => {
    // The endpoint reports the rejected configuration on console.error.
    const consoleError = spyOn(console, "error").mockImplementation(
      () => undefined,
    );
    try {
      // A real transport and its main channel, built by the real endpoint.
      await run(
        webrtcApi.endpoints.connectWithPeer.initiate({
          peerId: PEER_ID,
          peerPublicKey: HIGHER_PUBLIC_KEY,
          roomId: ROOM_ID,
        }),
      );
      const edges = snapshotPeerConnections().filter(
        (connection) => connection.roomId === ROOM_ID,
      );
      expect(edges).toHaveLength(1);
      const epc = edges[0] as IRTCPeerConnection;
      const main = epc.mainChannel as IRTCDataChannel & { open: () => void };
      expect(main).toBeDefined();

      // Main opens: it enters the registry and the handshake starts (and
      // parks at its fingerprint check), so the room says "authenticating".
      Object.assign(epc, {
        localDescription: { type: "offer", sdp: fingerprintSdp("11") },
        remoteDescription: { type: "answer", sdp: fingerprintSdp("aa") },
      });
      main.open();
      main.onopen?.call(main, new Event("open"));
      expect(room().handshakeStatusByPeer?.[PEER_ID]?.status).toBe(
        "authenticating",
      );

      // The relay credentials expire and the browser refuses the change: the
      // room's transports are retired.
      FakeRTCPeerConnection.rejectConfiguration = true;
      await expect(
        run(
          webrtcApi.endpoints.applyRoomConfiguration.initiate({
            roomId: ROOM_ID,
            rtcConfig: { iceServers: [{ urls: "stun:caller.example" }] },
            restartIce: true,
            failurePolicy: "close",
          }),
        ),
      ).rejects.toBeDefined();
      FakeRTCPeerConnection.rejectConfiguration = false;
      expect(epc.connectionState).toBe("closed");

      // Cleared at once, not when the closed transport is next retired.
      expect(room().handshakeStatusByPeer?.[PEER_ID]).toBeUndefined();

      // The registry no longer holds the retired main: the room sweep that
      // visits every registered channel of the room does not reach it.
      let sweptAfterRetire = 0;
      main.releaseProtocolResources = () => {
        sweptAfterRetire += 1;
      };
      await run(
        webrtcApi.endpoints.disconnectFromRoom.initiate({
          roomId: ROOM_ID,
          deleteMessages: false,
        }),
      );
      expect(sweptAfterRetire).toBe(0);
      expect(
        snapshotPeerConnections().filter(
          (connection) => connection.roomId === ROOM_ID,
        ),
      ).toEqual([]);
    } finally {
      consoleError.mockRestore();
    }
  }, 20000);

  /**
   * Build a real transport through connectWithPeer, give it what an
   * authenticated edge holds (a ratchet, a PQ runtime, a running healing
   * interval), then have the real endpoint fail to hold a configuration on it.
   */
  const retireAuthenticatedEdge = async (
    peerId: string,
    failurePolicy: "rollback" | "close",
  ): Promise<void> => {
    const consoleError = spyOn(console, "error").mockImplementation(
      () => undefined,
    );
    const setIntervalSpy = spyOn(globalThis, "setInterval");
    const clearIntervalSpy = spyOn(globalThis, "clearInterval");
    let epc: IRTCPeerConnection | undefined;
    try {
      await run(
        webrtcApi.endpoints.connectWithPeer.initiate({
          peerId,
          peerPublicKey: HIGHER_PUBLIC_KEY,
          roomId: ROOM_ID,
        }),
      );
      epc = snapshotPeerConnections().find(
        (connection) =>
          connection.roomId === ROOM_ID && connection.withPeerId === peerId,
      );
      expect(epc).toBeDefined();
      const rootKey = new Uint8Array(32).fill(1);
      const dhSelfSec = new Uint8Array(32).fill(4);
      const cached = new Uint8Array(32).fill(6);
      const pq = { destroyed: 0 };
      epc!.ratchetState = {
        rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
        rootKey,
        sendingChainKey: null,
        receivingChainKey: null,
        dhSelfPub: new Uint8Array(32),
        dhSelfSec,
        dhRemotePub: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        skipped: new Map(),
      };
      epc!.messageKeyCache = new Map([["cached", cached]]);
      epc!.pqHealingState = {
        destroy: () => {
          pq.destroyed += 1;
        },
      } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
      // An hour-long tick: the interval is observed through its handle.
      installPqHealingOrchestrator(epc!, ROOM_ID, {
        sendControlFrame: () => true,
        failEdge: () => undefined,
        tickMs: 3_600_000,
      });
      const handle = setIntervalSpy.mock.results.at(-1)?.value as unknown;
      expect(handle).toBeDefined();

      FakeRTCPeerConnection.rejectConfiguration = true;
      await expect(
        run(
          webrtcApi.endpoints.applyRoomConfiguration.initiate({
            roomId: ROOM_ID,
            rtcConfig: { iceServers: [{ urls: "turn:new.example" }] },
            restartIce: true,
            failurePolicy,
          }),
        ),
      ).rejects.toBeDefined();
      FakeRTCPeerConnection.rejectConfiguration = false;

      expect(epc!.connectionState).toBe("closed");
      for (const secret of [rootKey, dhSelfSec, cached])
        expect(secret.every((byte) => byte === 0)).toBe(true);
      expect(epc!.ratchetState).toBeUndefined();
      expect(epc!.messageKeyCache).toBeUndefined();
      expect(pq.destroyed).toBe(1);
      expect(epc!.pqHealingState).toBeUndefined();
      expect(
        clearIntervalSpy.mock.calls.some(
          ([cleared]: unknown[]) => cleared === handle,
        ),
      ).toBe(true);
    } finally {
      FakeRTCPeerConnection.rejectConfiguration = false;
      if (epc) destroyPqHealingOrchestrator(epc);
      await run(
        webrtcApi.endpoints.disconnectFromRoom.initiate({
          roomId: ROOM_ID,
          deleteMessages: false,
        }),
      );
      setIntervalSpy.mockRestore();
      clearIntervalSpy.mockRestore();
      consoleError.mockRestore();
    }
  };

  test("a failed ICE rollback close wipes ratchet and PQ state", async () => {
    await retireAuthenticatedEdge(
      "00000000-0000-4000-8000-0000000000cc",
      "rollback",
    );
  }, 20000);

  test("an expired ICE generation close wipes ratchet and PQ state", async () => {
    await retireAuthenticatedEdge(
      "00000000-0000-4000-8000-0000000000cd",
      "close",
    );
  }, 20000);
});
