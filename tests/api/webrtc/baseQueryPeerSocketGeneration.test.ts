import { ownTestTransports } from "../../support/transportFixture";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  PeerHandshakeStatus,
  ManagedRoom,
} from "../../../src/reducers/roomSlice";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// baseQuery imports the signaling API and channel orchestration, which import
// the Redux store, whose identity slice reads localStorage at module
// initialization. Install the minimal browser shim before importing it.
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

/** The slice of RTCPeerConnection handleConnectToPeer builds and drives. */
const ownTransport = ownTestTransports();

class FakeRTCPeerConnection {
  connectionState: RTCPeerConnectionState = "new";
  signalingState: RTCSignalingState = "stable";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  readonly configuration: RTCConfiguration;

  constructor(configuration: RTCConfiguration) {
    ownTransport(this);
    this.configuration = configuration;
  }

  getConfiguration(): RTCConfiguration {
    return this.configuration;
  }

  setConfiguration(): void {}

  async setLocalDescription(): Promise<void> {}

  async setRemoteDescription(): Promise<void> {}

  restartIce(): void {}

  createDataChannel(label: string): RTCDataChannel {
    return { label, readyState: "connecting" } as unknown as RTCDataChannel;
  }

  close(): void {
    this.connectionState = "closed";
    this.signalingState = "closed";
  }
}

(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
  FakeRTCPeerConnection;

const ROOM_ID = "00000000-0000-4000-8000-0000000000c1";
const ROOM_URL = "c1".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const G1 = "11111111-1111-4111-8111-111111111111";
const G2 = "22222222-2222-4222-8222-222222222222";

type BaseQuery = typeof import("../../../src/api/webrtc/baseQuery");
type PeerSocketGeneration =
  typeof import("../../../src/api/webrtc/peerSocketGeneration");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");

let webrtcBaseQuery: BaseQuery["default"];
let clearRetiredPeerSocketGenerations: PeerSocketGeneration["clearRetiredPeerSocketGenerations"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let restoreBlacklist: () => void;
let roomReducer: (typeof import("../../../src/reducers/roomSlice"))["default"];

beforeAll(async () => {
  await import("../../../src/store");
  ({ default: roomReducer } = await import("../../../src/reducers/roomSlice"));
  // The database worker bundle is not inlined under `bun test`, so the
  // fail-closed blacklist lookup would report every peer as blocked and
  // baseQuery would return before it ever looked at a transport.
  const dbApi = await import("../../../src/db/api");
  const spy = spyOn(dbApi, "getDBPeerIsBlacklisted").mockImplementation(
    async () => false,
  );
  restoreBlacklist = () => {
    spy.mockRestore();
  };
  ({ default: webrtcBaseQuery } =
    await import("../../../src/api/webrtc/baseQuery"));
  ({ clearRetiredPeerSocketGenerations } =
    await import("../../../src/api/webrtc/peerSocketGeneration"));
  ({ resetRatchetGate } = await import("../../../src/handlers/ratchetGate"));
});

afterAll(() => {
  restoreBlacklist();
});

afterEach(() => {
  clearRetiredPeerSocketGenerations(ROOM_ID, PEER_ID);
});

const fakeApi = (
  handshakeStatusByPeer: Record<string, PeerHandshakeStatus> = {},
): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      // The higher identity is the protocol RESPONDER: it opens no channel, so
      // no handshake runs and the transport under test stays un-negotiated —
      // exactly the side C1 strands.
      publicKey: HIGHER_PUBLIC_KEY,
      secretKey: "",
      challengeId: "",
      challenge: "",
      signature: "",
    },
    rooms: [
      {
        id: ROOM_ID,
        url: ROOM_URL,
        rtcConfig: { iceServers: [] },
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
      if (typeof action === "function")
        return Object.assign(Promise.resolve({ data: undefined }), {
          unwrap: async () => undefined,
        });
      Object.assign(state, {
        rooms: roomReducer(
          state.rooms as unknown as ManagedRoom[],
          action as { type: string },
        ),
      });
      return action;
    },
    getState: () => state,
  } as unknown as BaseQueryApi;
  return { api, dispatched };
};

interface SeedOptions {
  connectionState?: RTCPeerConnectionState;
  peerSocketGeneration?: string;
  handshakeTerminalFailure?: "pin-mismatch";
}

/** A transport already in the registry, as an inbound frame would find it. */
const seedTransport = ({
  connectionState = "connected",
  peerSocketGeneration,
  handshakeTerminalFailure,
}: SeedOptions = {}): IRTCPeerConnection & { closed: boolean } => {
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: LOWER_PUBLIC_KEY,
    peerSocketGeneration,
    handshakeTerminalFailure,
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [] as RTCIceCandidateInit[],
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    remoteTransportRebinds: 0,
    connectionState,
    signalingState: "stable" as RTCSignalingState,
    localDescription: null,
    remoteDescription: null,
    closed: false,
    close: () => {
      epc.closed = true;
      (epc as { connectionState: RTCPeerConnectionState }).connectionState =
        "closed";
    },
  } as unknown as IRTCPeerConnection & { closed: boolean };
  return epc;
};

const run = async (
  api: BaseQueryApi,
  peerConnections: IRTCPeerConnection[],
  params: {
    peerSocketGeneration?: string;
    peerSocketGenerationSource?: "connection" | "roster";
  },
): Promise<void> => {
  const result = await webrtcBaseQuery(
    {
      peerId: PEER_ID,
      peerPublicKey: LOWER_PUBLIC_KEY,
      roomId: ROOM_ID,
      peerConnections,
      dataChannels: [] as IRTCDataChannel[],
      ...params,
    },
    api,
    {},
  );
  expect(result).toEqual({ data: undefined });
};

describe("baseQuery reacts to a peer's socket generation", () => {
  test("a fresh remote connection retries only that identity after a terminal PIN failure", async () => {
    const { api } = fakeApi({
      [PEER_ID]: {
        status: "failed",
        reason: "pin-mismatch",
        peerPublicKey: LOWER_PUBLIC_KEY,
      },
      other: {
        status: "failed",
        reason: "policy",
        peerPublicKey: "ab".repeat(32),
      },
    });
    const peers: IRTCPeerConnection[] = [];
    await expect(
      run(api, peers, {
        peerSocketGenerationSource: "roster",
        peerSocketGeneration: G1,
      }),
    ).rejects.toThrow("requires deliberate retry");
    expect(peers).toHaveLength(0);
    await run(api, peers, {
      peerSocketGenerationSource: "connection",
      peerSocketGeneration: G2,
    });
    expect(peers).toHaveLength(1);
    const room = (api.getState() as { rooms: ManagedRoom[] }).rooms[0];
    expect(room.handshakeStatusByPeer?.[PEER_ID]).toBeUndefined();
    expect(room.handshakeStatusByPeer?.other?.reason).toBe("policy");
    peers[0].close();
  });

  // C1: the peer's identity reappeared on a second socket, the server evicted
  // the first, and this transport is bound to a socket that no longer exists.
  // Nothing on it will ever fail, so only the generation can retire it.
  test("a connection frame naming a new generation replaces a connected transport", async () => {
    const { api } = fakeApi();
    const stale = seedTransport({ peerSocketGeneration: G1 });
    const peerConnections: IRTCPeerConnection[] = [stale];

    await run(api, peerConnections, {
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "connection",
    });

    expect(peerConnections).not.toContain(stale);
    expect(stale.closed).toBe(true);
    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0].peerSocketGeneration).toBe(G2);
  }, 20000);

  // THE C4 REGRESSION GUARD. Roster introductions are re-sent on join, on
  // redial and on reconcile, and a signaling socket now reconnects on its own,
  // so a perfectly healthy session sees a changed generation in a roster it
  // never asked for. Tearing the edge down there is the bug that was fixed
  // this morning, wearing a new hat.
  test("a roster frame naming a new generation leaves a connected transport alone", async () => {
    const { api, dispatched } = fakeApi();
    const live = seedTransport({ peerSocketGeneration: G1 });
    const peerConnections: IRTCPeerConnection[] = [live];

    await run(api, peerConnections, {
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "roster",
    });

    // Reference identity, not deep equality: a rebuilt transport would print
    // a multi-thousand-line diff and hide which assertion actually broke.
    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0]).toBe(live);
    expect(live.closed).toBe(false);
    // The baseline is NOT overwritten from the roster: the peer's next
    // `connection` frame must still read as a change and rebuild the edge.
    expect(live.peerSocketGeneration).toBe(G1);
    expect(dispatched).toEqual([]);
  }, 20000);

  // The stranded responder of C1: no channel, no description, no ICE, nothing
  // watching it. A roster frame is safe to act on there because the edge is
  // demonstrably not working.
  test("a roster frame naming a new generation replaces a transport that never connected", async () => {
    const { api } = fakeApi();
    const stranded = seedTransport({
      connectionState: "new",
      peerSocketGeneration: G1,
    });
    const peerConnections: IRTCPeerConnection[] = [stranded];

    await run(api, peerConnections, {
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "roster",
    });

    expect(peerConnections).not.toContain(stranded);
    expect(peerConnections[0].peerSocketGeneration).toBe(G2);
  }, 20000);

  test("a pre-generation server never retires a live transport", async () => {
    const { api } = fakeApi();
    const live = seedTransport({ peerSocketGeneration: G1 });
    const peerConnections: IRTCPeerConnection[] = [live];

    await run(api, peerConnections, {
      peerSocketGenerationSource: "connection",
    });
    await run(api, peerConnections, {
      peerSocketGeneration: "",
      peerSocketGenerationSource: "connection",
    });

    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0]).toBe(live);
    expect(live.closed).toBe(false);
    expect(live.peerSocketGeneration).toBe(G1);
  }, 20000);

  test("the first frame that names a generation adopts it as the baseline", async () => {
    const { api } = fakeApi();
    const live = seedTransport();
    const peerConnections: IRTCPeerConnection[] = [live];

    await run(api, peerConnections, {
      peerSocketGeneration: G1,
      peerSocketGenerationSource: "roster",
    });

    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0]).toBe(live);
    expect(live.peerSocketGeneration).toBe(G1);
  }, 20000);

  // The same introduction reaches handlePeerConnection directly AND through
  // pub/sub, and frames can cross on the wire. A UUIDv4 carries no ordering,
  // so only an already-retired set can tell a stale name from a new one.
  test("a re-introduction naming the generation just retired does not retire the replacement", async () => {
    const { api } = fakeApi();
    const stale = seedTransport({ peerSocketGeneration: G1 });
    const peerConnections: IRTCPeerConnection[] = [stale];

    await run(api, peerConnections, {
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "connection",
    });
    const replacement = peerConnections[0];

    await run(api, peerConnections, {
      peerSocketGeneration: G1,
      peerSocketGenerationSource: "connection",
    });

    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0]).toBe(replacement);
    expect(replacement.peerSocketGeneration).toBe(G2);
  }, 20000);

  // C2's disclosed residual, routed here: a terminal handshake failure closes
  // the transport with main's close handler detached, so nothing removes it
  // from the registry. A re-introduction must rebuild the edge, not fail.
  test("a transport a terminal handshake failure left closed in the registry is rebuilt", async () => {
    const { api } = fakeApi();
    const terminal = seedTransport({
      connectionState: "closed",
      handshakeTerminalFailure: "pin-mismatch",
    });
    const peerConnections: IRTCPeerConnection[] = [terminal];

    await run(api, peerConnections, {
      peerSocketGeneration: G1,
      peerSocketGenerationSource: "roster",
    });

    expect(peerConnections).not.toContain(terminal);
    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0].handshakeTerminalFailure).toBeUndefined();
  }, 20000);
});
