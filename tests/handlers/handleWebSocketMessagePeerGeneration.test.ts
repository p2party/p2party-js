import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";

import type { RTCPeerConnectionParams } from "../../src/api/webrtc/interfaces";
import { signalingPeerRequestDebouncer } from "../../src/utils/signalingPeerRequestDebouncer";

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

const ROOM_ID = "00000000-0000-4000-8000-0000000000e1";
const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000e2";
const PEER_ID = "00000000-0000-4000-8000-0000000000e3";
const SELF_PUBLIC_KEY = `${"00".repeat(31)}01`;
const PEER_PUBLIC_KEY = "ff".repeat(32);
const GENERATION = "11111111-1111-4111-8111-111111111111";

type Handler = typeof import("../../src/handlers/handleWebSocketMessage");

let handleWebSocketMessage: Handler["default"];
let connectParams: RTCPeerConnectionParams[];
let restore: () => void;
let blacklistLookup: () => Promise<boolean> = async () => false;

beforeAll(async () => {
  await import("../../src/store");
  const dbApi = await import("../../src/db/api");
  // The database worker bundle is not inlined under `bun test`, so the
  // fail-closed blacklist lookup reports every peer as blocked and the roster
  // loop would skip the peer before it ever dialled.
  const blacklist = spyOn(dbApi, "getDBPeerIsBlacklisted").mockImplementation(
    async () => blacklistLookup(),
  );
  const { default: webrtcApi } = await import("../../src/api/webrtc");
  connectParams = [];
  const initiate = spyOn(
    webrtcApi.endpoints.connectWithPeer,
    "initiate",
  ).mockImplementation(((params: RTCPeerConnectionParams) => {
    connectParams.push(params);
    return Object.assign(async () => ({ data: undefined }), {
      unwrap: async () => undefined,
    });
  }) as never);
  restore = () => {
    blacklist.mockRestore();
    initiate.mockRestore();
  };
  ({ default: handleWebSocketMessage } =
    await import("../../src/handlers/handleWebSocketMessage"));
});

afterAll(() => {
  restore();
});

const deliverRoster = async (socketGeneration?: string): Promise<void> => {
  connectParams.length = 0;
  const state = {
    keyPair: { peerId: SELF_PEER_ID, publicKey: SELF_PUBLIC_KEY },
    rooms: [
      {
        id: ROOM_ID,
        url: "e1".repeat(32),
        rtcConfig: { iceServers: [] },
        signalingActive: true,
        peers: [],
        channels: [],
        messages: [],
      },
    ],
    signalingServer: { isConnected: true, isVerified: true },
  };
  const api = {
    getState: () => state,
    dispatch: (action: unknown) =>
      typeof action === "function"
        ? Object.assign(Promise.resolve({ data: undefined }), {
            unwrap: async () => undefined,
          })
        : action,
  };
  await handleWebSocketMessage(
    {
      data: JSON.stringify({
        type: "peers",
        roomId: ROOM_ID,
        protocolVersion: 4,
        peers: [{ id: PEER_ID, publicKey: PEER_PUBLIC_KEY, socketGeneration }],
      }),
    } as MessageEvent,
    { readyState: 1, send: () => undefined } as unknown as WebSocket,
    api as never,
    () => true,
  );
};

describe("roster introductions carry the peer's socket generation", () => {
  // C1 needs the generation to reach the transport layer; C4 needs it to
  // arrive labelled as advisory, because the roster is re-requested on join,
  // on re-dial and on reconcile, and the signaling socket now reconnects on
  // its own.
  test("a peers frame forwards the raw generation as a roster observation", async () => {
    await deliverRoster(GENERATION);

    expect(connectParams).toHaveLength(1);
    expect(connectParams[0].peerId).toBe(PEER_ID);
    expect(connectParams[0].peerSocketGeneration).toBe(GENERATION);
    expect(connectParams[0].peerSocketGenerationSource).toBe("roster");
  });

  test("a pre-generation server leaves it absent, still labelled roster", async () => {
    await deliverRoster();

    expect(connectParams).toHaveLength(1);
    expect(connectParams[0].peerSocketGeneration).toBeUndefined();
    expect(connectParams[0].peerSocketGenerationSource).toBe("roster");
  });
});

describe("correlated room membership snapshots", () => {
  const deliverSnapshot = async (
    requestId: unknown,
    options: {
      active?: boolean;
      current?: () => boolean;
      peers?: readonly unknown[];
      kind?: string;
    } = {},
  ) => {
    connectParams.length = 0;
    const actions: { type: string; payload?: unknown }[] = [];
    const state = {
      keyPair: { peerId: SELF_PEER_ID, publicKey: SELF_PUBLIC_KEY },
      rooms: [
        {
          id: ROOM_ID,
          signalingActive: options.active ?? true,
          peers: [],
          rtcConfig: { iceServers: [] },
        },
      ],
    };
    await handleWebSocketMessage(
      {
        data: JSON.stringify({
          type: "peers",
          roomId: ROOM_ID,
          protocolVersion: 4,
          rosterKind: options.kind ?? "snapshot",
          rosterRequestId: requestId,
          peers: options.peers ?? [{ id: PEER_ID, publicKey: PEER_PUBLIC_KEY }],
        }),
      } as MessageEvent,
      {} as WebSocket,
      {
        getState: () => state,
        dispatch: (action: { type: string }) => {
          actions.push(action);
          return action;
        },
      } as never,
      options.current ?? (() => true),
    );
    return actions;
  };

  test("snapshot learns a missing member without bypassing peer acceptance", async () => {
    signalingPeerRequestDebouncer.resetSocketLifecycle();
    const id = signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
    const actions = await deliverSnapshot(id);
    expect(actions).toEqual([
      {
        type: "rooms/setKnownRoomPeers",
        payload: {
          roomId: ROOM_ID,
          peers: [{ peerId: PEER_ID, peerPublicKey: PEER_PUBLIC_KEY }],
        },
      },
      // Membership evidence only: it never dials and never ends an
      // "offline" report on its own.
      {
        type: "rooms/notePeerPresence",
        payload: {
          roomId: ROOM_ID,
          peerId: PEER_ID,
          socketGeneration: undefined,
          evidence: "membership",
        },
      },
    ]);
    expect(connectParams).toEqual([]);
    expect(signalingPeerRequestDebouncer.supportsRosterSnapshots).toBe(true);
    expect(await deliverSnapshot(id, { peers: [] })).toEqual([]);
  });

  test("empty snapshot records an authoritative empty membership", async () => {
    const id = signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
    const actions = await deliverSnapshot(id, { peers: [] });
    expect(actions).toEqual([
      {
        type: "rooms/setKnownRoomPeers",
        payload: { roomId: ROOM_ID, peers: [] },
      },
    ]);
    expect(connectParams).toEqual([]);
  });

  test("unsolicited, obsolete, disconnected, left and malformed snapshots cannot revive members", async () => {
    const old = signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
    const latest = signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
    for (const [id, options] of [
      [undefined, {}],
      [old, {}],
      [latest, { active: false }],
      [latest, { current: () => false }],
      [latest, { peers: [{ id: "broken", publicKey: PEER_PUBLIC_KEY }] }],
      [latest, { kind: "replacement" }],
    ] as const)
      expect(await deliverSnapshot(id, options)).toEqual([]);
    signalingPeerRequestDebouncer.resetSocketLifecycle();
    expect(await deliverSnapshot(latest)).toEqual([]);
  });

  test("a snapshot replaced during the blacklist await never commits its old membership", async () => {
    const id = signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
    blacklistLookup = async () => {
      signalingPeerRequestDebouncer.beginRosterRequest(ROOM_ID);
      return false;
    };
    try {
      expect(await deliverSnapshot(id)).toEqual([]);
    } finally {
      blacklistLookup = async () => false;
    }
  });
});
