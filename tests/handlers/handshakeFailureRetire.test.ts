import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import { HandshakeFailure } from "../../src/handlers/handshakeFailure";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

// A failed protocol-v4 handshake retires its transport from handleOpenChannel's
// catch. That catch used to call pc.close() directly, the same direct close
// the generation retire in baseQuery had (transport audit 2026-11, item 4):
// whatever the generation already held (a ratchet seeded before a later step
// threw, the PQ runtime and its healing interval, cover lanes) stayed attached
// to a closed connection that a terminal failure deliberately leaves in the
// registry. These tests drive the real handleOpenChannel through a failing
// handshake and inspect the generation afterwards.

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

type HandleOpenChannel = typeof import("../../src/handlers/handleOpenChannel");
type RatchetGate = typeof import("../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type RoomPolicy = typeof import("../../src/roomPolicy");
type Orchestrator = typeof import("../../src/handlers/pqHealingOrchestrator");

let handleOpenChannel: HandleOpenChannel["handleOpenChannel"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];
let installPqHealingOrchestrator: Orchestrator["installPqHealingOrchestrator"];
let destroyPqHealingOrchestrator: Orchestrator["destroyPqHealingOrchestrator"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ resetRatchetGate } = await import("../../src/handlers/ratchetGate"));
  ({ setConnectingToPeers } = await import("../../src/reducers/roomSlice"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
  ({ installPqHealingOrchestrator, destroyPqHealingOrchestrator } =
    await import("../../src/handlers/pqHealingOrchestrator"));
});

// Every test here fails a handshake on purpose, and the catch reports each
// failure on console.error. Keep that out of the test output.
let consoleError: ReturnType<typeof spyOn>;
beforeEach(() => {
  consoleError = spyOn(console, "error").mockImplementation(() => undefined);
});
afterEach(() => {
  consoleError.mockRestore();
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000d7";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
// The lexicographically lower canonical identity is the initiator that opens main.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

interface FakeMain {
  channel: IRTCDataChannel;
  closes: { count: number };
}

/**
 * A main channel whose close event is delivered only when the test says so.
 * pc.close() closes every channel abruptly and a browser need not deliver the
 * channel's own close event afterwards, so nothing in the retire path may rely
 * on main.onclose running.
 */
const fakeMain = (): FakeMain & { deliverClose: () => Promise<void> } => {
  const closes = { count: 0 };
  let state: RTCDataChannelState = "connecting";
  const channel = {
    label: "main",
    get readyState() {
      return state;
    },
    binaryType: "blob",
    send: () => undefined,
    close: () => {
      closes.count += 1;
      state = "closed";
    },
  } as unknown as IRTCDataChannel;
  const deliverClose = async (): Promise<void> => {
    const handler = (
      channel as unknown as { onclose?: ((event: Event) => unknown) | null }
    ).onclose;
    if (typeof handler === "function")
      await handler.call(channel, new Event("close"));
  };
  return { channel, closes, deliverClose };
};

type FakeEdge = IRTCPeerConnection & {
  connectionState: RTCPeerConnectionState;
  closes: number;
};

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
      epc.connectionState = "closed";
    },
  } as unknown as FakeEdge;
  return epc;
};

/** runHandshake's first await is the DTLS fingerprint check (getStats). */
const failNextHandshakeWith = (epc: IRTCPeerConnection, error: unknown) => {
  (epc as unknown as { getStats: () => Promise<RTCStatsReport> }).getStats =
    () => Promise.reject(error);
};

const activeRoom = () => ({
  id: ROOM_ID,
  url: "d7".repeat(32),
  rtcConfig: { iceServers: [] },
  signalingActive: true,
  policy: DEFAULT_ROOM_POLICY_V1,
  peers: [{ peerId: PEER_ID, peerPublicKey: HIGHER_PUBLIC_KEY }],
  channels: [],
  messages: [],
});

const fakeApi = (
  rooms: unknown[],
): { api: BaseQueryApi; dispatched: unknown[] } => {
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
    rooms,
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

// The handshake's failure path crosses timers, so settle a few macrotask turns.
const settle = async (): Promise<void> => {
  for (let i = 0; i < 5; i++) {
    for (let j = 0; j < 20; j++) await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
};

const REDIAL = () =>
  setConnectingToPeers({
    roomId: ROOM_ID,
    connectingToPeers: true,
    reason: "redial",
    peerId: PEER_ID,
  });

/** Secrets a generation can hold when a step after the seed throws. */
const seedGenerationSecrets = (epc: IRTCPeerConnection) => {
  const rootKey = new Uint8Array(32).fill(1);
  const dhSelfSec = new Uint8Array(32).fill(4);
  const cached = new Uint8Array(32).fill(6);
  epc.ratchetState = {
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
  epc.messageKeyCache = new Map([["cached", cached]]);
  const pq = { destroyed: 0 };
  epc.pqHealingState = {
    pendingRetryAt: null,
    pendingAttempts: 0,
    trafficBlocked: false,
    healingDue: () => false,
    destroy: () => {
      pq.destroyed += 1;
    },
  } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
  return { secrets: [rootKey, dhSelfSec, cached], pq };
};

describe("a failed handshake retires its generation through the edge teardown", () => {
  test("a terminal failure wipes the generation and stops its healing interval", async () => {
    const epc = fakePeerConnection();
    const main = fakeMain();
    const dataChannels: IRTCDataChannel[] = [];
    const { api, dispatched } = fakeApi([activeRoom()]);
    const { secrets, pq } = seedGenerationSecrets(epc);
    const setIntervalSpy = spyOn(globalThis, "setInterval");
    const clearIntervalSpy = spyOn(globalThis, "clearInterval");

    try {
      installPqHealingOrchestrator(epc, ROOM_ID, {
        sendControlFrame: () => true,
        failEdge: () => undefined,
        tickMs: 3_600_000,
      });
      const handle = setIntervalSpy.mock.results[0]?.value as unknown;
      expect(handle).toBeDefined();

      const channel = await handleOpenChannel(
        { channel: main.channel, epc, roomId: ROOM_ID, dataChannels },
        api,
      );
      const beforeOpen = dispatched.length;
      failNextHandshakeWith(
        epc,
        new HandshakeFailure(
          "Malformed, surplus, or out-of-order handshake frame",
          "policy",
        ),
      );
      channel.onopen?.call(channel, new Event("open"));
      await settle();

      expect(epc.handshakeTerminalFailure).toBe("policy");
      expect(epc.closes).toBe(1);
      expect(main.closes.count).toBe(1);
      for (const secret of secrets)
        expect(secret.every((byte) => byte === 0)).toBe(true);
      expect(epc.ratchetState).toBeUndefined();
      expect(epc.messageKeyCache).toBeUndefined();
      expect(pq.destroyed).toBe(1);
      expect(epc.pqHealingState).toBeUndefined();
      expect(
        clearIntervalSpy.mock.calls.some(([cleared]) => cleared === handle),
      ).toBe(true);
      // The main this generation opened is no longer registered.
      expect(dataChannels).not.toContain(channel);
      expect(epc.mainChannel).toBeUndefined();
      // C2 still holds: a terminal failure neither tears the peer down nor
      // re-dials; the closed transport stays for the next introduction.
      const afterOpen = dispatched.slice(beforeOpen);
      expect(
        afterOpen.filter((action) => typeof action === "function"),
      ).toEqual([]);
      expect(afterOpen).not.toContainEqual(REDIAL());
    } finally {
      setIntervalSpy.mockRestore();
      clearIntervalSpy.mockRestore();
      destroyPqHealingOrchestrator(epc);
      resetRatchetGate(ROOM_ID, PEER_ID);
    }
  });

  test("a transport failure wipes the generation and tears the peer down without waiting for a close event", async () => {
    // No room in state: the handshake fails before it starts ("transport").
    const epc = fakePeerConnection();
    const main = fakeMain();
    const dataChannels: IRTCDataChannel[] = [];
    const { api, dispatched } = fakeApi([]);
    const { secrets, pq } = seedGenerationSecrets(epc);

    try {
      const channel = await handleOpenChannel(
        { channel: main.channel, epc, roomId: ROOM_ID, dataChannels },
        api,
      );
      const beforeOpen = dispatched.length;
      channel.onopen?.call(channel, new Event("open"));
      await settle();

      expect(epc.handshakeTerminalFailure).toBeUndefined();
      expect(epc.closes).toBe(1);
      expect(main.closes.count).toBe(1);
      for (const secret of secrets)
        expect(secret.every((byte) => byte === 0)).toBe(true);
      expect(pq.destroyed).toBe(1);

      // The close event never arrived, yet the room/peer teardown
      // (disconnectFromPeer, an opaque RTK thunk) still ran, before the
      // re-dial, exactly once.
      const afterOpen = dispatched.slice(beforeOpen);
      const disconnectIndex = afterOpen.findIndex(
        (action) => typeof action === "function",
      );
      const redialIndex = afterOpen.findIndex(
        (action) =>
          (action as { type?: string }).type === setConnectingToPeers.type,
      );
      expect(disconnectIndex).toBeGreaterThan(-1);
      expect(redialIndex).toBeGreaterThan(disconnectIndex);
      expect(
        afterOpen.filter((action) => typeof action === "function"),
      ).toHaveLength(1);

      // A close event that does arrive late finds nothing attached.
      const beforeLateClose = dispatched.length;
      await main.deliverClose();
      expect(dispatched.slice(beforeLateClose)).toEqual([]);
    } finally {
      resetRatchetGate(ROOM_ID, PEER_ID);
    }
  });
});
