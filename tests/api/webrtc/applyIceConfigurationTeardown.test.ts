import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// applyIceConfiguration retires a transport through the shared edge teardown,
// whose module graph reaches the Redux store, whose identity slice reads
// localStorage at module initialization. Install the shim before importing.
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

const { applyRoomIceConfiguration } =
  await import("../../../src/api/webrtc/applyIceConfiguration");
const { destroyPqHealingOrchestrator, installPqHealingOrchestrator } =
  await import("../../../src/handlers/pqHealingOrchestrator");
const { resetRatchetGate } = await import("../../../src/handlers/ratchetGate");
const { clearPeerHandshakeStatus } =
  await import("../../../src/reducers/roomSlice");

// applyRoomIceConfiguration closes a transport when the room's authoritative
// ICE configuration can neither be applied nor restored on it. pc.close()
// fires no event, so before the shared edge teardown nothing ever wiped what
// that transport held: its ratchet and PQ runtime stayed in memory and its PQ
// healing interval kept ticking (transport audit 2026-11, item 4, the
// remaining close sites).

const ROOM_ID = "00000000-0000-4000-8000-0000000000a7";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const OTHER_PEER_ID = "00000000-0000-4000-8000-000000000003";
const PEER_PUBLIC_KEY = `${"00".repeat(31)}01`;

interface Edge {
  readonly epc: IRTCPeerConnection;
  readonly closes: { count: number };
  readonly secrets: Uint8Array[];
  readonly pq: { destroyed: number };
  readonly intervalHandle: unknown;
  readonly main: IRTCDataChannel & { closes: number };
}

let setIntervalSpy: ReturnType<typeof spyOn>;
let clearIntervalSpy: ReturnType<typeof spyOn>;
let edges: Edge[];

beforeEach(() => {
  setIntervalSpy = spyOn(globalThis, "setInterval");
  clearIntervalSpy = spyOn(globalThis, "clearInterval");
  edges = [];
});

afterEach(() => {
  for (const { epc } of edges) destroyPqHealingOrchestrator(epc);
  setIntervalSpy.mockRestore();
  clearIntervalSpy.mockRestore();
  resetRatchetGate(ROOM_ID, PEER_ID);
  resetRatchetGate(ROOM_ID, OTHER_PEER_ID);
});

/**
 * An authenticated transport with a PQ healing interval running, whose
 * setConfiguration either always throws or always succeeds.
 */
const authenticatedEdge = (
  rejects: "always" | "never",
  peerId = PEER_ID,
): Edge => {
  const closes = { count: 0 };
  const rootKey = new Uint8Array(32).fill(1);
  const dhSelfSec = new Uint8Array(32).fill(4);
  const cached = new Uint8Array(32).fill(6);
  const pq = { destroyed: 0 };
  let mainState: RTCDataChannelState = "open";
  const main = {
    label: "main",
    withPeerId: peerId,
    roomIds: [ROOM_ID],
    get readyState() {
      return mainState;
    },
    closes: 0,
    onclose: () => undefined,
    onerror: () => undefined,
    onmessage: () => undefined,
    close() {
      main.closes += 1;
      mainState = "closed";
    },
  } as unknown as IRTCDataChannel & { closes: number };
  const epc = {
    roomId: ROOM_ID,
    withPeerId: peerId,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    ratchetGateLease: resetRatchetGate(ROOM_ID, peerId),
    connectionState: "connected",
    signalingState: "stable",
    localDescription: { type: "offer", sdp: "offer" },
    remoteDescription: null,
    mainChannel: main,
    ratchetState: {
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
    },
    messageKeyCache: new Map([["cached", cached]]),
    pqHealingState: {
      destroy: () => {
        pq.destroyed += 1;
      },
    },
    getConfiguration: () => ({ iceServers: [{ urls: "turn:old.example" }] }),
    setConfiguration: () => {
      if (rejects === "always") throw new Error("configuration rejected");
    },
    restartIce: () => undefined,
    close: () => {
      closes.count += 1;
      (epc as { connectionState: string }).connectionState = "closed";
    },
  } as unknown as IRTCPeerConnection;
  // An hour-long tick: the interval is observed through its handle, not time.
  installPqHealingOrchestrator(epc, ROOM_ID, {
    sendControlFrame: () => true,
    failEdge: () => undefined,
    tickMs: 3_600_000,
  });
  const intervalHandle = setIntervalSpy.mock.results.at(-1)?.value as unknown;
  const edge = {
    epc,
    closes,
    secrets: [rootKey, dhSelfSec, cached],
    pq,
    intervalHandle,
    main,
  };
  edges.push(edge);
  return edge;
};

const expectRetired = (edge: Edge): void => {
  expect(edge.closes.count).toBe(1);
  for (const secret of edge.secrets)
    expect(secret.every((byte) => byte === 0)).toBe(true);
  expect(edge.epc.ratchetState).toBeUndefined();
  expect(edge.epc.messageKeyCache).toBeUndefined();
  expect(edge.pq.destroyed).toBe(1);
  expect(edge.epc.pqHealingState).toBeUndefined();
  expect(edge.intervalHandle).toBeDefined();
  expect(
    clearIntervalSpy.mock.calls.some(
      ([cleared]: unknown[]) => cleared === edge.intervalHandle,
    ),
  ).toBe(true);
  // Its main is detached before it closes: a late close event must not run
  // disconnectFromPeer against whatever owns the edge by then.
  expect(edge.main.closes).toBe(1);
  expect(edge.main.onclose).toBeNull();
  expect(edge.epc.mainChannel).toBeUndefined();
};

describe("an ICE configuration that cannot be held retires its transport", () => {
  test("a failed ICE rollback close wipes ratchet and PQ state", () => {
    const edge = authenticatedEdge("always");

    expect(() =>
      applyRoomIceConfiguration([edge.epc], ROOM_ID, {
        iceServers: [{ urls: "turn:new.example" }],
      }),
    ).toThrow("configuration rejected");

    expectRetired(edge);
  });

  test("an expired ICE generation close wipes ratchet and PQ state", () => {
    // The "close" policy closes every room peer, the healthy one included.
    const healthy = authenticatedEdge("never", OTHER_PEER_ID);
    const rejecting = authenticatedEdge("always");

    expect(() =>
      applyRoomIceConfiguration(
        [healthy.epc, rejecting.epc],
        ROOM_ID,
        { iceServers: [{ urls: "stun:caller.example" }] },
        true,
        "close",
      ),
    ).toThrow("configuration rejected");

    expectRetired(healthy);
    expectRetired(rejecting);
  });

  test("with the caller's registry and dispatch, the retired transport is unregistered and its status cleared", () => {
    const edge = authenticatedEdge("always");
    const dataChannels: IRTCDataChannel[] = [edge.main];
    const dispatched: unknown[] = [];

    expect(() =>
      applyRoomIceConfiguration(
        [edge.epc],
        ROOM_ID,
        { iceServers: [{ urls: "turn:new.example" }] },
        false,
        "rollback",
        { dataChannels, dispatch: (action) => dispatched.push(action) },
      ),
    ).toThrow("configuration rejected");

    expectRetired(edge);
    expect(dataChannels).toEqual([]);
    expect(dispatched).toEqual([
      clearPeerHandshakeStatus({ roomId: ROOM_ID, peerId: PEER_ID }),
    ]);
  });
});
