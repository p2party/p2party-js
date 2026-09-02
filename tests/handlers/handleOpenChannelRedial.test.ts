import { beforeAll, describe, expect, test } from "bun:test";

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

type HandleOpenChannel = typeof import("../../src/handlers/handleOpenChannel");
type RatchetGate = typeof import("../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type RoomPolicy = typeof import("../../src/roomPolicy");
type RoomPinVault = typeof import("../../src/roomPinVault");
type RoomPinAttempts = typeof import("../../src/roomPinAttempts");

let handleOpenChannel: HandleOpenChannel["handleOpenChannel"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];
let putRoomPin: RoomPinVault["putRoomPin"];
let deleteRoomPin: RoomPinVault["deleteRoomPin"];
let recordRoomPinAggregateFailure: RoomPinAttempts["recordRoomPinAggregateFailure"];
let MAX_ROOM_PIN_FAILURES_PER_WINDOW: RoomPinAttempts["MAX_ROOM_PIN_FAILURES_PER_WINDOW"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } = await import("../../src/handlers/handleOpenChannel"));
  ({ resetRatchetGate } = await import("../../src/handlers/ratchetGate"));
  ({ setConnectingToPeers, setPeerHandshakeStatus } =
    await import("../../src/reducers/roomSlice"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
  ({ putRoomPin, deleteRoomPin } = await import("../../src/roomPinVault"));
  ({ recordRoomPinAggregateFailure, MAX_ROOM_PIN_FAILURES_PER_WINDOW } =
    await import("../../src/roomPinAttempts"));
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000cc";
const PIN_ROOM_ID = "00000000-0000-4000-8000-0000000000cd";
const PIN_ROOM_URL = "cd".repeat(32);
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

const fakeMain = (): FakeMain => {
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
  return { channel, closes };
};

interface FakePeerConnection {
  epc: IRTCPeerConnection;
  closes: { count: number };
}

const fakePeerConnection = (roomId: string): FakePeerConnection => {
  const closes = { count: 0 };
  const epc = {
    roomId,
    withPeerId: PEER_ID,
    withPeerPublicKey: HIGHER_PUBLIC_KEY,
    connectionState: "connected",
    signalingState: "stable",
    localDescription: { type: "offer", sdp: fingerprintSdp("11") },
    remoteDescription: { type: "answer", sdp: fingerprintSdp("aa") },
    ratchetGateLease: resetRatchetGate(roomId, PEER_ID),
    close: () => {
      closes.count += 1;
      epc.connectionState = "closed";
    },
  } as unknown as IRTCPeerConnection & {
    connectionState: RTCPeerConnectionState;
  };
  return { epc, closes };
};

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

const flushMicrotasks = async (): Promise<void> => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

const REDIAL = (roomId: string) =>
  setConnectingToPeers({ roomId, connectingToPeers: true, reason: "redial" });

const redials = (dispatched: unknown[]): unknown[] =>
  dispatched.filter(
    (action) =>
      (action as { type?: string }).type === setConnectingToPeers.type,
  );

const handshakeStatuses = (dispatched: unknown[]): unknown[] =>
  dispatched.filter(
    (action) =>
      (action as { type?: string }).type === setPeerHandshakeStatus.type,
  );

describe("handleOpenChannel main-channel failure re-dials", () => {
  test("a transport handshake failure closes the edge and re-dials the room under the redial budget", async () => {
    // No room in state: the handshake fails before it starts, which is a
    // "transport" failure. The catch closes both the channel and the PC;
    // pc.close() fires no connectionstatechange, so the catch itself must
    // re-dial or the edge stays down with a stale "failed" status.
    const pc = fakePeerConnection(ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    const beforeOpen = dispatched.length;
    channel.onopen?.call(channel, new Event("open"));
    await flushMicrotasks();

    const afterOpen = dispatched.slice(beforeOpen);
    expect(handshakeStatuses(afterOpen)).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "failed",
        reason: "transport",
        retryAfter: undefined,
      }),
    ]);
    expect(main.closes.count).toBe(1);
    expect(pc.closes.count).toBe(1);
    // The re-dial comes after the failure status and the closes.
    expect(redials(afterOpen)).toEqual([REDIAL(ROOM_ID)]);
    const failedIndex = afterOpen.findIndex(
      (action) =>
        (action as { payload?: { status?: string } }).payload?.status ===
        "failed",
    );
    const redialIndex = afterOpen.findIndex(
      (action) =>
        (action as { type?: string }).type === setConnectingToPeers.type,
    );
    expect(redialIndex).toBeGreaterThan(failedIndex);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a PIN-throttled handshake failure closes the edge without a re-dial", async () => {
    // A re-dial cannot fix a PIN failure; rebuilding the edge would only burn
    // another attempt against the throttle. The failed status stays for the UI.
    const pinRoom = {
      id: PIN_ROOM_ID,
      url: PIN_ROOM_URL,
      rtcConfig: { iceServers: [] },
      signalingActive: true,
      policy: { ...DEFAULT_ROOM_POLICY_V1, authMode: "pin" },
      peers: [],
      channels: [],
      messages: [],
    };
    putRoomPin(PIN_ROOM_URL, new Uint8Array([1, 2, 3, 4]));
    for (let i = 0; i < MAX_ROOM_PIN_FAILURES_PER_WINDOW; i++)
      recordRoomPinAggregateFailure(PIN_ROOM_ID);
    const pc = fakePeerConnection(PIN_ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([pinRoom]);

    try {
      const channel = await handleOpenChannel(
        {
          channel: main.channel,
          epc: pc.epc,
          roomId: PIN_ROOM_ID,
          dataChannels: [],
        },
        api,
      );
      const beforeOpen = dispatched.length;
      channel.onopen?.call(channel, new Event("open"));
      await flushMicrotasks();

      const afterOpen = dispatched.slice(beforeOpen);
      const failed = handshakeStatuses(afterOpen).at(-1) as {
        payload: { status: string; reason?: string };
      };
      expect(failed.payload.status).toBe("failed");
      expect(failed.payload.reason).toBe("pin-throttled");
      expect(main.closes.count).toBe(1);
      expect(pc.closes.count).toBe(1);
      expect(redials(afterOpen)).toEqual([]);
    } finally {
      deleteRoomPin(PIN_ROOM_URL);
      resetRatchetGate(PIN_ROOM_ID, PEER_ID);
    }
  });

  test("a main channel that closes tears the edge down and re-dials under the redial budget", async () => {
    const pc = fakePeerConnection(ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    const beforeClose = dispatched.length;
    await channel.onclose?.call(channel, new Event("close"));

    const afterClose = dispatched.slice(beforeClose);
    // disconnectFromPeer (an opaque RTK thunk) first, then the re-dial.
    expect(afterClose).toHaveLength(2);
    expect(typeof afterClose[0]).toBe("function");
    expect(afterClose[1]).toEqual(REDIAL(ROOM_ID));

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a main channel whose transport was already replaced closes silently", async () => {
    const pc = fakePeerConnection(ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    // A replacement transport claimed the gate: this main's lease is stale.
    resetRatchetGate(ROOM_ID, PEER_ID);
    const beforeClose = dispatched.length;
    await channel.onclose?.call(channel, new Event("close"));

    expect(dispatched.slice(beforeClose)).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});
