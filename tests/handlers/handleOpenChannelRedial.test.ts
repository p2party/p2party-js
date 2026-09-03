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
type DisconnectFromPeerQuery =
  typeof import("../../src/api/webrtc/disconnectFromPeerQuery");
type RemoteTransportChange =
  typeof import("../../src/api/webrtc/remoteTransportChange");
type RatchetGate = typeof import("../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../src/reducers/roomSlice");
type RoomPolicy = typeof import("../../src/roomPolicy");
type RoomPinVault = typeof import("../../src/roomPinVault");
type RoomPinAttempts = typeof import("../../src/roomPinAttempts");

let handleOpenChannel: HandleOpenChannel["handleOpenChannel"];
let webrtcDisconnectPeerQuery: DisconnectFromPeerQuery["default"];
let resetEdgeAuthenticationForNewRemoteTransport: RemoteTransportChange["resetEdgeAuthenticationForNewRemoteTransport"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
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
  ({ default: webrtcDisconnectPeerQuery } =
    await import("../../src/api/webrtc/disconnectFromPeerQuery"));
  ({ resetEdgeAuthenticationForNewRemoteTransport } = await import(
    "../../src/api/webrtc/remoteTransportChange"
  ));
  ({ resetRatchetGate, isCurrentRatchetGateLease } = await import(
    "../../src/handlers/ratchetGate"
  ));
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

/**
 * A getStats the test releases by hand: the handshake's first await is the
 * DTLS fingerprint check, so the handshake can be parked exactly there while
 * something else happens to the transport.
 */
interface DeferredStats {
  getStats: () => Promise<RTCStatsReport>;
  /** Resolves the parked call with an empty report (no certificate rows). */
  release: () => void;
  calls: { count: number };
}

const deferredStats = (): DeferredStats => {
  const calls = { count: 0 };
  let resolve: ((report: RTCStatsReport) => void) | undefined;
  const pending = new Promise<RTCStatsReport>((r) => {
    resolve = r;
  });
  return {
    calls,
    getStats: () => {
      calls.count += 1;
      return pending;
    },
    release: () => {
      resolve?.({ forEach: () => undefined } as unknown as RTCStatsReport);
    },
  };
};

const fakePeerConnection = (
  roomId: string,
  getStats?: DeferredStats["getStats"],
): FakePeerConnection => {
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
    getStats,
    close: () => {
      closes.count += 1;
      epc.connectionState = "closed";
    },
  } as unknown as IRTCPeerConnection & {
    connectionState: RTCPeerConnectionState;
  };
  return { epc, closes };
};

const activeRoom = (id: string) => ({
  id,
  url: "cc".repeat(32),
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

const flushMicrotasks = async (): Promise<void> => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

// The handshake's failure path crosses timers (the IndexedDB worker call it
// makes after the fingerprint check settles asynchronously), so settle a few
// macrotask turns too.
const settle = async (): Promise<void> => {
  for (let i = 0; i < 5; i++) {
    await flushMicrotasks();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
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

  test("a handshake rejected by a deliberate teardown of its transport neither fails the status nor re-dials", async () => {
    // Park the handshake at its DTLS fingerprint check, then tear the edge
    // down through the real disconnectFromPeer query (the path behind the
    // public disconnectFromPeer, purge/leave, address-book removal and the
    // T7 replacement) while it is parked. That teardown rejects the in-flight
    // handshake without a lease; the catch must recognise that the transport
    // was already closed by someone else and leave both the status and the
    // follow-up to that path: a "failed" status here would describe a peer
    // deletePeer just removed, and a re-dial would rebuild the edge the user
    // just dropped.
    const stats = deferredStats();
    const pc = fakePeerConnection(ROOM_ID, stats.getStats);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([activeRoom(ROOM_ID)]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    const beforeOpen = dispatched.length;
    channel.onopen?.call(channel, new Event("open"));
    await settle();
    expect(stats.calls.count).toBe(1);
    expect(handshakeStatuses(dispatched.slice(beforeOpen))).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    ]);

    webrtcDisconnectPeerQuery(
      {
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerConnections: [pc.epc],
        dataChannels: [channel],
        iceCandidates: [],
      },
      api,
      {},
    );
    expect(pc.closes.count).toBe(1);
    const afterTeardown = dispatched.length;

    stats.release();
    await settle();

    const afterRejection = dispatched.slice(afterTeardown);
    expect(handshakeStatuses(afterRejection)).toEqual([]);
    expect(redials(afterRejection)).toEqual([]);
    // The teardown owned the close; the catch did not close it again.
    expect(pc.closes.count).toBe(1);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a handshake that fails while its transport is still open reports the failure and re-dials", async () => {
    // Same parked handshake, but nothing else touched the transport: releasing
    // the fingerprint check lets it fail on its own (no identity is
    // provisioned under this runtime), and the catch still owns the outcome.
    const stats = deferredStats();
    const pc = fakePeerConnection(ROOM_ID, stats.getStats);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([activeRoom(ROOM_ID)]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    const beforeOpen = dispatched.length;
    channel.onopen?.call(channel, new Event("open"));
    await settle();
    expect(stats.calls.count).toBe(1);

    stats.release();
    await settle();

    const afterOpen = dispatched.slice(beforeOpen);
    const failed = handshakeStatuses(afterOpen).at(-1) as {
      payload: { status: string; reason?: string };
    };
    expect(failed.payload.status).toBe("failed");
    expect(failed.payload.reason).toBe("transport");
    expect(main.closes.count).toBe(1);
    expect(pc.closes.count).toBe(1);
    expect(redials(afterOpen)).toEqual([REDIAL(ROOM_ID)]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a handshake superseded by an in-place edge re-authentication dies quietly", async () => {
    // Park the handshake at its DTLS fingerprint check, then re-bind the edge
    // IN PLACE for a new remote certificate (the T1 path,
    // resetEdgeAuthenticationForNewRemoteTransport): it rejects the parked
    // transcript and hands the edge a fresh ratchet-gate lease while KEEPING
    // the RTCPeerConnection. The rejection that then reaches this catch
    // belongs to the superseded attempt, so it must not overwrite the
    // "authenticating" status the reset just set with a "failed" one, must not
    // close the connection the reset deliberately kept, and must not re-dial.
    const stats = deferredStats();
    const pc = fakePeerConnection(ROOM_ID, stats.getStats);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([activeRoom(ROOM_ID)]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    channel.onopen?.call(channel, new Event("open"));
    await settle();
    expect(stats.calls.count).toBe(1);

    resetEdgeAuthenticationForNewRemoteTransport({
      epc: pc.epc,
      roomId: ROOM_ID,
      peerId: PEER_ID,
      api,
      dataChannels: [],
      // This test is about the superseded handshake, not the re-bind
      // deadline: arm nothing real and tear nothing down.
      disconnectPeer: () => Promise.resolve(),
      schedule: {
        setTimeout: () => 0 as unknown as ReturnType<typeof setTimeout>,
        clearTimeout: () => undefined,
      },
      reason: new Error("Remote DTLS certificate changed"),
    });
    const newLease = pc.epc.ratchetGateLease;
    expect(newLease).toBeDefined();
    const afterReset = dispatched.length;

    stats.release();
    await settle();

    const afterRejection = dispatched.slice(afterReset);
    expect(handshakeStatuses(afterRejection)).toEqual([]);
    expect(redials(afterRejection)).toEqual([]);
    // The reset kept the RTCPeerConnection; the superseded catch left it alone.
    expect(pc.closes.count).toBe(0);
    expect(pc.epc.connectionState).toBe("connected");
    // The replacement attempt still owns the edge.
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, newLease!)).toBe(true);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a main channel error tears the edge down and re-dials under the redial budget", async () => {
    // disconnectFromPeer nulls onclose before closing, so this is the only
    // re-dial an errored main gets; under the join budget it was swallowed
    // whenever a socket reconnect's roster request had just gone out.
    const pc = fakePeerConnection(ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    const beforeError = dispatched.length;
    await channel.onerror?.call(
      channel,
      new Event("error") as RTCErrorEvent,
    );

    const afterError = dispatched.slice(beforeError);
    expect(afterError).toHaveLength(2);
    expect(typeof afterError[0]).toBe("function");
    expect(afterError[1]).toEqual(REDIAL(ROOM_ID));

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a main channel error on a replaced transport neither tears down nor re-dials", async () => {
    const pc = fakePeerConnection(ROOM_ID);
    const main = fakeMain();
    const { api, dispatched } = fakeApi([]);

    const channel = await handleOpenChannel(
      { channel: main.channel, epc: pc.epc, roomId: ROOM_ID, dataChannels: [] },
      api,
    );
    resetRatchetGate(ROOM_ID, PEER_ID);
    const beforeError = dispatched.length;
    await channel.onerror?.call(
      channel,
      new Event("error") as RTCErrorEvent,
    );

    expect(dispatched.slice(beforeError)).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});
