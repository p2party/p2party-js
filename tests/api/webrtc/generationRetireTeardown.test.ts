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
  ManagedRoom,
  PeerHandshakeStatus,
} from "../../../src/reducers/roomSlice";
import { RATCHET_ROOT_SUITE_MLKEM512 } from "../../../src/utils/constants";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// A peer that reloads or opens a second tab reappears on a new signaling
// socket, and baseQuery retires the transport bound to the old one (C1). That
// retirement used to close the RTCPeerConnection and nothing else: the PQ
// healing interval kept ticking against it forever, and the ratchet, the PQ
// runtime and the cached message keys stayed in memory un-wiped (transport
// audit 2026-11, item 4). These tests drive the real baseQuery with a changed
// generation from a `connection` frame and inspect what the retired
// generation still holds afterwards.

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

const ROOM_ID = "00000000-0000-4000-8000-0000000000c7";
const ROOM_URL = "c7".repeat(32);
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
type Orchestrator =
  typeof import("../../../src/handlers/pqHealingOrchestrator");
type Handshake = typeof import("../../../src/handlers/handleHandshake");
type DisconnectFromPeerQuery =
  typeof import("../../../src/api/webrtc/disconnectFromPeerQuery");
type RatchetPersist = typeof import("../../../src/handlers/ratchetPersist");
type PqRuntime = typeof import("../../../src/handlers/pqHealingRuntime");

let webrtcBaseQuery: BaseQuery["default"];
let clearRetiredPeerSocketGenerations: PeerSocketGeneration["clearRetiredPeerSocketGenerations"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
let isRatchetGatePending: RatchetGate["isRatchetGatePending"];
let installPqHealingOrchestrator: Orchestrator["installPqHealingOrchestrator"];
let destroyPqHealingOrchestrator: Orchestrator["destroyPqHealingOrchestrator"];
let tickPqHealing: Orchestrator["tickPqHealing"];
let setHandshakeChannel: Handshake["setHandshakeChannel"];
let clearHandshakeChannel: Handshake["clearHandshakeChannel"];
let disconnectModule: DisconnectFromPeerQuery;
let claimRatchetGeneration: RatchetPersist["claimRatchetGeneration"];
let assertCurrentRatchetGeneration: RatchetPersist["assertCurrentRatchetGeneration"];
let SparsePqHealingState: PqRuntime["SparsePqHealingState"];
let pqModule: Awaited<
  ReturnType<
    (typeof import("../../../src/cryptography/testModule"))["loadTestModule"]
  >
>;
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
  ({ resetRatchetGate, isCurrentRatchetGateLease, isRatchetGatePending } =
    await import("../../../src/handlers/ratchetGate"));
  ({
    installPqHealingOrchestrator,
    destroyPqHealingOrchestrator,
    tickPqHealing,
  } = await import("../../../src/handlers/pqHealingOrchestrator"));
  ({ setHandshakeChannel, clearHandshakeChannel } =
    await import("../../../src/handlers/handleHandshake"));
  disconnectModule =
    await import("../../../src/api/webrtc/disconnectFromPeerQuery");
  ({ claimRatchetGeneration, assertCurrentRatchetGeneration } =
    await import("../../../src/handlers/ratchetPersist"));
  ({ SparsePqHealingState } =
    await import("../../../src/handlers/pqHealingRuntime"));
  pqModule = await (
    await import("../../../src/cryptography/testModule")
  ).loadTestModule();
});

afterAll(() => {
  restoreBlacklist();
});

afterEach(() => {
  clearRetiredPeerSocketGenerations(ROOM_ID, PEER_ID);
  clearHandshakeChannel(ROOM_ID, PEER_ID);
  resetRatchetGate(ROOM_ID, PEER_ID);
});

const fakeApi = (
  handshakeStatusByPeer: Record<string, PeerHandshakeStatus> = {},
): BaseQueryApi => {
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      // The higher identity is the protocol RESPONDER: it opens no channel on
      // the replacement, so nothing but the retirement touches the old edge.
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
  return {
    dispatch: (action: unknown) => {
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
};

type RetiredEdge = IRTCPeerConnection & { closes: number };

/** An authenticated transport bound to the peer's first socket. */
const seedAuthenticatedEdge = (): RetiredEdge => {
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: LOWER_PUBLIC_KEY,
    peerSocketGeneration: G1,
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [] as RTCIceCandidateInit[],
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    remoteTransportRebinds: 0,
    connectionState: "connected" as RTCPeerConnectionState,
    signalingState: "stable" as RTCSignalingState,
    localDescription: null,
    remoteDescription: null,
    closes: 0,
    close: () => {
      epc.closes += 1;
      epc.connectionState = "closed";
    },
  };
  return epc as unknown as RetiredEdge;
};

const retireForNewGeneration = async (
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[] = [],
  api: BaseQueryApi = fakeApi(),
): Promise<void> => {
  const result = await webrtcBaseQuery(
    {
      peerId: PEER_ID,
      peerPublicKey: LOWER_PUBLIC_KEY,
      roomId: ROOM_ID,
      peerConnections,
      dataChannels,
      peerSocketGeneration: G2,
      peerSocketGenerationSource: "connection",
    },
    api,
    {},
  );
  expect(result).toEqual({ data: undefined });
};

interface FakeChannel {
  readonly channel: IRTCDataChannel;
  readonly closes: { count: number };
  readonly releases: { count: number };
}

const fakeChannel = (label: string): FakeChannel => {
  const closes = { count: 0 };
  const releases = { count: 0 };
  let readyState: RTCDataChannelState = "open";
  const channel = {
    label,
    withPeerId: PEER_ID,
    roomIds: [ROOM_ID],
    get readyState() {
      return readyState;
    },
    releaseProtocolResources: () => {
      releases.count += 1;
    },
    close: () => {
      closes.count += 1;
      readyState = "closed";
    },
    onopen: () => undefined,
    onclose: () => undefined,
    onerror: () => undefined,
    onclosing: () => undefined,
    onmessage: () => undefined,
    onbufferedamountlow: () => undefined,
  } as unknown as IRTCDataChannel;
  return { channel, closes, releases };
};

describe("a generation retire releases what the retired edge held", () => {
  test("generation retire wipes ratchet and PQ state", async () => {
    const old = seedAuthenticatedEdge();
    const rootKey = new Uint8Array(32).fill(1);
    const sendingChainKey = new Uint8Array(32).fill(2);
    const receivingChainKey = new Uint8Array(32).fill(3);
    const dhSelfSec = new Uint8Array(32).fill(4);
    const skipped = new Uint8Array(32).fill(5);
    const cached = new Uint8Array(32).fill(6);
    old.ratchetState = {
      rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfPub: new Uint8Array(32),
      dhSelfSec,
      dhRemotePub: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      skipped: new Map([["skipped", skipped]]),
    };
    old.messageKeyCache = new Map([["cached", cached]]);
    old.messageKeyByMerkleRoot = new Map([["root", "cached"]]);
    let pqDestroyed = 0;
    old.pqHealingState = {
      destroy: () => {
        pqDestroyed += 1;
      },
    } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
    const peerConnections: IRTCPeerConnection[] = [old];

    await retireForNewGeneration(peerConnections);

    // The retire itself ran: the old transport is closed and replaced.
    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0]).not.toBe(old);
    expect(old.closes).toBe(1);

    for (const secret of [
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfSec,
      skipped,
      cached,
    ])
      expect(secret.every((byte) => byte === 0)).toBe(true);
    expect(old.ratchetState).toBeUndefined();
    expect(pqDestroyed).toBe(1);
    expect(old.pqHealingState).toBeUndefined();
    expect(old.messageKeyCache).toBeUndefined();
    expect(old.messageKeyByMerkleRoot).toBeUndefined();
  }, 20000);

  test("generation retire stops the healing interval", async () => {
    const old = seedAuthenticatedEdge();
    let healingConsulted = 0;
    old.pqHealingState = {
      pendingRetryAt: null,
      pendingAttempts: 0,
      trafficBlocked: false,
      healingDue: () => {
        healingConsulted += 1;
        return false;
      },
      destroy: () => undefined,
    } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;

    const setIntervalSpy = spyOn(globalThis, "setInterval");
    const clearIntervalSpy = spyOn(globalThis, "clearInterval");
    try {
      // An hour-long tick: the real interval never fires during the test, so
      // the interval is observed through its handle, never through time.
      installPqHealingOrchestrator(old, ROOM_ID, {
        sendControlFrame: () => true,
        failEdge: () => undefined,
        tickMs: 3_600_000,
      });
      expect(setIntervalSpy).toHaveBeenCalledTimes(1);
      const handle = setIntervalSpy.mock.results[0]?.value as unknown;
      expect(handle).toBeDefined();
      // The orchestrator is live: one deterministic tick consults the runtime.
      await tickPqHealing(old);
      expect(healingConsulted).toBe(1);

      await retireForNewGeneration([old]);

      expect(
        clearIntervalSpy.mock.calls.some(([cleared]) => cleared === handle),
      ).toBe(true);
      // And nothing on the retired edge drives a healing pass any more.
      await tickPqHealing(old);
      expect(healingConsulted).toBe(1);
    } finally {
      setIntervalSpy.mockRestore();
      clearIntervalSpy.mockRestore();
      destroyPqHealingOrchestrator(old);
    }
  }, 20000);

  test("generation retire detaches and unregisters the retired generation's channels", async () => {
    const old = seedAuthenticatedEdge();
    const main = fakeChannel("main");
    const message = fakeChannel(`${"61".repeat(32)}~${"62".repeat(64)}`);
    old.mainChannel = main.channel;
    old.messageChannels = new Set([message.channel]);
    const dataChannels: IRTCDataChannel[] = [main.channel, message.channel];

    await retireForNewGeneration([old], dataChannels);

    expect(dataChannels).toEqual([]);
    for (const { channel, closes, releases } of [main, message]) {
      // A late close or error event from the retired main would otherwise run
      // its disconnectFromPeer against whatever owns the edge by then.
      expect(channel.onclose).toBeNull();
      expect(channel.onerror).toBeNull();
      expect(channel.onmessage).toBeNull();
      expect(closes.count).toBe(1);
      expect(releases.count).toBe(1);
    }
    expect(old.mainChannel).toBeUndefined();
    expect(old.messageChannels).toBeUndefined();
  }, 20000);

  test("generation retire releases the handshake inbox and the re-bind deadline", async () => {
    const old = seedAuthenticatedEdge();
    setHandshakeChannel(ROOM_ID, PEER_ID, { send: () => undefined });
    const cleared: unknown[] = [];
    const deadline = 41 as unknown as ReturnType<typeof setTimeout>;
    old.rebindDeadline = deadline;
    old.rebindDeadlineClear = (handle) => {
      cleared.push(handle);
    };

    await retireForNewGeneration([old]);

    // The responder opens no main on the replacement, so an inbox that is
    // still registered can only be the retired generation's.
    expect(clearHandshakeChannel(ROOM_ID, PEER_ID)).toBe(false);
    expect(cleared).toEqual([deadline]);
    expect(old.rebindDeadline).toBeUndefined();
  }, 20000);
});

describe("the shared edge teardown", () => {
  // Re-entrancy: a teardown can reach a generation late (a handshake catch
  // that resumed after an await, a duplicate retire). The gate, the handshake
  // inbox and the registry entries for this room/peer then belong to the
  // replacement and must be left exactly as they are.
  test("a teardown of a superseded generation leaves the replacement alone", () => {
    const old = seedAuthenticatedEdge();
    const oldMain = fakeChannel("main");
    old.mainChannel = oldMain.channel;
    // The replacement transport now owns the edge.
    const replacementLease = resetRatchetGate(ROOM_ID, PEER_ID);
    const replacementInbox = setHandshakeChannel(ROOM_ID, PEER_ID, {
      send: () => undefined,
    });
    const replacementMain = fakeChannel("main");
    const dataChannels: IRTCDataChannel[] = [replacementMain.channel];

    disconnectModule.teardownEdgeGeneration(old, { dataChannels });

    expect(old.closes).toBe(1);
    expect(oldMain.closes.count).toBe(1);
    expect(oldMain.channel.onclose).toBeNull();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, replacementLease)).toBe(
      true,
    );
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, replacementLease)).toBe(true);
    expect(dataChannels).toEqual([replacementMain.channel]);
    expect(replacementMain.closes.count).toBe(0);
    expect(replacementMain.channel.onclose).not.toBeNull();
    expect(
      clearHandshakeChannel(ROOM_ID, PEER_ID, undefined, replacementInbox),
    ).toBe(true);
  });

  test("tearing the same generation down twice is harmless", () => {
    const old = seedAuthenticatedEdge();
    const main = fakeChannel("main");
    old.mainChannel = main.channel;
    const dataChannels: IRTCDataChannel[] = [main.channel];

    disconnectModule.teardownEdgeGeneration(old, { dataChannels });
    disconnectModule.teardownEdgeGeneration(old, { dataChannels });

    expect(old.closes).toBe(1);
    expect(main.closes.count).toBe(1);
    expect(main.releases.count).toBe(1);
    expect(dataChannels).toEqual([]);
  });
});

describe("a retired generation's handshake status", () => {
  test("retiring a generation clears its handshake status", async () => {
    const api = fakeApi({
      [PEER_ID]: { status: "authenticated", peerPublicKey: LOWER_PUBLIC_KEY },
    });
    const room = () => (api.getState() as { rooms: ManagedRoom[] }).rooms[0];
    expect(room().handshakeStatusByPeer?.[PEER_ID]?.status).toBe(
      "authenticated",
    );

    await retireForNewGeneration([seedAuthenticatedEdge()], [], api);

    // The replacement (the protocol responder here) has not authenticated and
    // may never: nothing may still describe the peer as authenticated.
    expect(room().handshakeStatusByPeer?.[PEER_ID]).toBeUndefined();
  }, 20000);

  test("a teardown of a superseded generation leaves the replacement's status alone", () => {
    const old = seedAuthenticatedEdge();
    resetRatchetGate(ROOM_ID, PEER_ID); // the replacement owns the edge now
    const dispatched: unknown[] = [];

    disconnectModule.teardownEdgeGeneration(old, {
      dispatch: (action) => dispatched.push(action),
    });

    expect(dispatched).toEqual([]);
  });
});

// The wrapped ratchet row is keyed by the EDGE (room, peer identity), not by
// the transport, and every generation writes it. A retired generation's row
// must not stay on disk, and a late teardown must never take the row a
// replacement has written since.
describe("ratchet generation ownership", () => {
  test("late teardown cannot revoke a replacement and retired transports cannot reclaim their generation", () => {
    const old = seedAuthenticatedEdge();
    claimRatchetGeneration(old, ROOM_ID);
    const replacement = seedAuthenticatedEdge();
    claimRatchetGeneration(replacement, ROOM_ID);
    disconnectModule.teardownEdgeGeneration(old);
    expect(() => claimRatchetGeneration(old, ROOM_ID)).toThrow();
    expect(() => assertCurrentRatchetGeneration(old, ROOM_ID)).toThrow();
    assertCurrentRatchetGeneration(replacement, ROOM_ID);
    disconnectModule.teardownEdgeGeneration(replacement);
    expect(() =>
      assertCurrentRatchetGeneration(replacement, ROOM_ID),
    ).toThrow();
  });
});

describe("both teardown paths release the same things", () => {
  const paths: Array<{
    readonly name: string;
    readonly run: (
      edge: RetiredEdge,
      dataChannels: IRTCDataChannel[],
      api: BaseQueryApi,
    ) => Promise<void>;
  }> = [
    {
      name: "a generation retire",
      run: (edge, dataChannels, api) =>
        retireForNewGeneration([edge], dataChannels, api),
    },
    {
      name: "an explicit disconnect",
      run: async (edge, dataChannels, api) => {
        await disconnectModule.default(
          {
            peerId: PEER_ID,
            roomId: ROOM_ID,
            peerConnections: [edge],
            dataChannels,
            iceCandidates: [],
          },
          api,
          {},
        );
      },
    },
  ];

  for (const path of paths)
    test(`${path.name} releases everything the generation held`, async () => {
      const setIntervalSpy = spyOn(globalThis, "setInterval");
      const clearIntervalSpy = spyOn(globalThis, "clearInterval");
      const edge = seedAuthenticatedEdge();
      try {
        const rootKey = new Uint8Array(32).fill(1);
        const dhSelfSec = new Uint8Array(32).fill(4);
        const cached = new Uint8Array(32).fill(6);
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
        edge.messageKeyCache = new Map([["cached", cached]]);
        let pqDestroyed = 0;
        edge.pqHealingState = {
          destroy: () => {
            pqDestroyed += 1;
          },
        } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
        installPqHealingOrchestrator(edge, ROOM_ID, {
          sendControlFrame: () => true,
          failEdge: () => undefined,
          tickMs: 3_600_000,
        });
        const interval = setIntervalSpy.mock.results.at(-1)?.value as unknown;
        const main = fakeChannel("main");
        edge.mainChannel = main.channel;
        const dataChannels: IRTCDataChannel[] = [main.channel];
        setHandshakeChannel(ROOM_ID, PEER_ID, { send: () => undefined });
        const deadlinesCleared: unknown[] = [];
        edge.rebindDeadline = 7 as unknown as ReturnType<typeof setTimeout>;
        edge.rebindDeadlineClear = (handle) => {
          deadlinesCleared.push(handle);
        };
        claimRatchetGeneration(edge, ROOM_ID);
        const api = fakeApi({
          [PEER_ID]: {
            status: "authenticated",
            peerPublicKey: LOWER_PUBLIC_KEY,
          },
        });

        await path.run(edge, dataChannels, api);
        for (let turn = 0; turn < 3; turn++)
          await new Promise((resolve) => setTimeout(resolve, 0));

        expect(edge.closes).toBe(1);
        for (const secret of [rootKey, dhSelfSec, cached])
          expect(secret.every((byte) => byte === 0)).toBe(true);
        expect(pqDestroyed).toBe(1);
        expect(
          clearIntervalSpy.mock.calls.some(
            ([cleared]: unknown[]) => cleared === interval,
          ),
        ).toBe(true);
        expect(main.closes.count).toBe(1);
        expect(main.channel.onclose).toBeNull();
        expect(dataChannels).toEqual([]);
        expect(clearHandshakeChannel(ROOM_ID, PEER_ID)).toBe(false);
        expect(deadlinesCleared).toEqual([7]);
        expect(
          (api.getState() as { rooms: ManagedRoom[] }).rooms[0]
            .handshakeStatusByPeer?.[PEER_ID],
        ).toBeUndefined();
        expect(() => assertCurrentRatchetGeneration(edge, ROOM_ID)).toThrow();
      } finally {
        destroyPqHealingOrchestrator(edge);
        setIntervalSpy.mockRestore();
        clearIntervalSpy.mockRestore();
      }
    }, 20000);
});

describe("a real post-quantum runtime through the teardown", () => {
  test("the teardown wipes the PQ runtime's key bytes", () => {
    const pq = new SparsePqHealingState({
      module: pqModule,
      pqMode: "hybrid-mlkem512",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      binding: new Uint8Array(32).fill(0x42),
      rootKey: new Uint8Array(32).fill(0x19),
      nextOfferer: "local",
      amInitiator: true,
      now: 0,
    });
    const edge = seedAuthenticatedEdge();
    edge.pqHealingState = pq;
    // Live views of what the runtime holds: its message root, its edge
    // binding and an active combined receive key.
    const context = pq.currentMessageContext();
    const receiveKey = new Uint8Array(32).fill(0x5a);
    pq.activeReceiveKeys.set("receive", receiveKey);
    for (const bytes of [context.rootKey, context.binding, receiveKey])
      expect(bytes.some((byte) => byte !== 0)).toBe(true);

    disconnectModule.teardownEdgeGeneration(edge, {});

    for (const bytes of [context.rootKey, context.binding, receiveKey])
      expect(bytes.every((byte) => byte === 0)).toBe(true);
    expect(edge.pqHealingState).toBeUndefined();
    expect(pq.trafficBlocked).toBe(true);
  });
});
