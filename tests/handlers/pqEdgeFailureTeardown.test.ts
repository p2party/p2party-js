// An authenticated edge whose sparse-PQ healing exchange fails (the control
// retry budget is spent, or a control cell is forked or unauthenticated) is
// failed by the orchestrator through handleOpenChannel's `failEdge`. That hook
// used to close main and the RTCPeerConnection and nothing else, relying on
// main's close handler to run disconnectFromPeer, an event a browser need not
// deliver after pc.close(). Until then the ratchet and the PQ runtime stayed
// in memory (transport audit 2026-11, item 4, the remaining close sites).
//
// Reaching `failEdge` needs a completed handshake, and a real handshake needs
// two identities and a database worker each, which a unit run does not have.
// So runHandshake alone is replaced, by a delegate that is the real function
// except inside the test below (the same seam handleOpenChannelPinSuccess
// uses). Everything after it (status dispatch, orchestrator install, the
// orchestrator's own failure path, failEdge) runs for real.
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  mock,
  spyOn,
  test,
} from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

// handleOpenChannel imports the WebRTC API, which imports the Redux store,
// whose identity slice reads localStorage at module initialization.
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

type RunHandshake =
  (typeof import("../../src/handlers/handleHandshake"))["runHandshake"];
const realHandshake = await import("../../src/handlers/handleHandshake");
const realRunHandshake: RunHandshake = realHandshake.runHandshake;
let runHandshakeImpl: RunHandshake = realRunHandshake;
mock.module("../../src/handlers/handleHandshake", () => ({
  ...realHandshake,
  runHandshake: (...args: Parameters<RunHandshake>) =>
    runHandshakeImpl(...args),
}));

type HandleOpenChannel = typeof import("../../src/handlers/handleOpenChannel");
type RatchetGate = typeof import("../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type RoomPolicy = typeof import("../../src/roomPolicy");
type Orchestrator = typeof import("../../src/handlers/pqHealingOrchestrator");

let handleOpenChannel: HandleOpenChannel["handleOpenChannel"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let clearPeerHandshakeStatus: RoomSlice["clearPeerHandshakeStatus"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];
let tickPqHealing: Orchestrator["tickPqHealing"];
let destroyPqHealingOrchestrator: Orchestrator["destroyPqHealingOrchestrator"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ resetRatchetGate } = await import("../../src/handlers/ratchetGate"));
  ({ setPeerHandshakeStatus, clearPeerHandshakeStatus, setConnectingToPeers } =
    await import("../../src/reducers/roomSlice"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
  ({ tickPqHealing, destroyPqHealingOrchestrator } =
    await import("../../src/handlers/pqHealingOrchestrator"));
});

afterAll(() => {
  runHandshakeImpl = realRunHandshake;
});

// failEdge reports its reason on console.error; keep it out of the output.
let consoleError: ReturnType<typeof spyOn>;
beforeEach(() => {
  consoleError = spyOn(console, "error").mockImplementation(() => undefined);
});
afterEach(() => {
  consoleError.mockRestore();
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000f7";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
// The lexicographically lower canonical identity is the initiator that opens main.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

/** A main channel whose close event never arrives on its own. */
const fakeMain = (): IRTCDataChannel & { closes: number } => {
  let state: RTCDataChannelState = "connecting";
  const channel = {
    label: "main",
    closes: 0,
    get readyState() {
      return state;
    },
    binaryType: "blob",
    send: () => undefined,
    close: () => {
      channel.closes += 1;
      state = "closed";
    },
  } as unknown as IRTCDataChannel & { closes: number };
  return channel;
};

type FakeEdge = IRTCPeerConnection & { closes: number };

const fakePeerConnection = (): FakeEdge => {
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: HIGHER_PUBLIC_KEY,
    connectionState: "connected",
    signalingState: "stable",
    localDescription: { type: "offer", sdp: fingerprintSdp("11") },
    remoteDescription: { type: "answer", sdp: fingerprintSdp("aa") },
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    closes: 0,
    close: () => {
      epc.closes += 1;
      (epc as { connectionState: string }).connectionState = "closed";
    },
  } as unknown as FakeEdge;
  return epc;
};

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
        url: "f7".repeat(32),
        rtcConfig: { iceServers: [] },
        signalingActive: true,
        policy: DEFAULT_ROOM_POLICY_V1,
        peers: [{ peerId: PEER_ID, peerPublicKey: HIGHER_PUBLIC_KEY }],
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
      return { unwrap: async () => undefined };
    },
    getState: () => state,
  } as unknown as BaseQueryApi;
  return { api, dispatched };
};

const turns = async (count: number): Promise<void> => {
  for (let turn = 0; turn < count; turn++)
    await new Promise((resolve) => setTimeout(resolve, 0));
};

describe("a failed PQ healing exchange retires its generation through the edge teardown", () => {
  test("a PQ healing edge failure wipes ratchet and PQ state", async () => {
    const epc = fakePeerConnection();
    const main = fakeMain();
    const dataChannels: IRTCDataChannel[] = [];
    const { api, dispatched } = fakeApi();
    const rootKey = new Uint8Array(32).fill(1);
    const dhSelfSec = new Uint8Array(32).fill(4);
    const pq = { destroyed: 0 };
    const setIntervalSpy = spyOn(globalThis, "setInterval");
    const clearIntervalSpy = spyOn(globalThis, "clearInterval");

    // What the real handshake leaves behind: a live ratchet and a PQ runtime,
    // here one whose persisted control frame has spent its retry budget.
    runHandshakeImpl = async (edge) => {
      edge.ratchetState = {
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
      edge.pqHealingState = {
        pendingRetryAt: 0,
        pendingAttempts: Number.MAX_SAFE_INTEGER,
        trafficBlocked: false,
        healingDue: () => false,
        destroy: () => {
          pq.destroyed += 1;
        },
      } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
    };

    try {
      const channel = await handleOpenChannel(
        { channel: main, epc, roomId: ROOM_ID, dataChannels },
        api,
      );
      channel.onopen?.call(channel, new Event("open"));
      const authenticated = () =>
        dispatched.some(
          (action) =>
            (action as { type?: string }).type ===
              setPeerHandshakeStatus.type &&
            (action as { payload: { status: string } }).payload.status ===
              "authenticated",
        );
      for (let turn = 0; turn < 200 && !authenticated(); turn++) await turns(1);
      expect(authenticated()).toBe(true);
      const handle = setIntervalSpy.mock.results.at(-1)?.value as unknown;
      expect(handle).toBeDefined();
      expect(dataChannels).toContain(channel);
      const beforeFailure = dispatched.length;

      // One deterministic orchestrator pass: the retry budget is spent, so it
      // fails the authenticated edge through failEdge.
      await tickPqHealing(epc);
      await turns(3);

      expect(epc.closes).toBe(1);
      expect(main.closes).toBe(1);
      for (const secret of [rootKey, dhSelfSec])
        expect(secret.every((byte) => byte === 0)).toBe(true);
      expect(epc.ratchetState).toBeUndefined();
      expect(pq.destroyed).toBe(1);
      expect(epc.pqHealingState).toBeUndefined();
      expect(
        clearIntervalSpy.mock.calls.some(([cleared]) => cleared === handle),
      ).toBe(true);
      // Main is detached and unregistered: no close event is relied on.
      expect(channel.onclose).toBeNull();
      expect(dataChannels).not.toContain(channel);

      // The status no longer claims an authenticated edge, the peer teardown
      // (disconnectFromPeer, an opaque RTK thunk) runs without a close event,
      // and the room is re-dialled after it.
      const afterFailure = dispatched.slice(beforeFailure);
      expect(afterFailure[0]).toEqual(
        clearPeerHandshakeStatus({ roomId: ROOM_ID, peerId: PEER_ID }),
      );
      expect(typeof afterFailure[1]).toBe("function");
      expect(afterFailure[2]).toEqual(
        setConnectingToPeers({
          roomId: ROOM_ID,
          connectingToPeers: true,
          reason: "redial",
        }),
      );
    } finally {
      runHandshakeImpl = realRunHandshake;
      setIntervalSpy.mockRestore();
      clearIntervalSpy.mockRestore();
      destroyPqHealingOrchestrator(epc);
      resetRatchetGate(ROOM_ID, PEER_ID);
    }
  });
});
