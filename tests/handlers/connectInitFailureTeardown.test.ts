import { afterEach, beforeAll, describe, expect, spyOn, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  ManagedRoom,
  PeerHandshakeStatus,
} from "../../src/reducers/roomSlice";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

// handleConnectToPeer registers a new transport, then initializes it (WASM,
// then the signaling `connectWithPeer`). When initialization fails it used to
// splice the transport out and pc.close() it, and nothing else: the edge's
// gate, freshly reset for this transport, stayed pending for every awaiter,
// and whatever had been attached to the transport by then was never wiped
// (transport audit 2026-11, item 4, the remaining close sites).

// handleConnectToPeer imports the signaling API and the Redux store, whose
// identity slice reads localStorage at module initialization.
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

class FakeRTCPeerConnection {
  connectionState: RTCPeerConnectionState = "new";
  signalingState: RTCSignalingState = "stable";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  closes = 0;
  readonly configuration: RTCConfiguration;

  constructor(configuration: RTCConfiguration) {
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
    this.closes += 1;
    this.connectionState = "closed";
    this.signalingState = "closed";
  }
}

(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
  FakeRTCPeerConnection;

const ROOM_ID = "00000000-0000-4000-8000-0000000000b7";
const ROOM_URL = "b7".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

type HandleConnectToPeer =
  typeof import("../../src/handlers/handleConnectToPeer");
type RatchetGate = typeof import("../../src/handlers/ratchetGate");
type Orchestrator = typeof import("../../src/handlers/pqHealingOrchestrator");
type DbApi = typeof import("../../src/db/api");

let handleConnectToPeer: HandleConnectToPeer["handleConnectToPeer"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let isRatchetGatePending: RatchetGate["isRatchetGatePending"];
let installPqHealingOrchestrator: Orchestrator["installPqHealingOrchestrator"];
let destroyPqHealingOrchestrator: Orchestrator["destroyPqHealingOrchestrator"];
let roomReducer: (typeof import("../../src/reducers/roomSlice"))["default"];
let dbApi: DbApi;

beforeAll(async () => {
  await import("../../src/store");
  dbApi = await import("../../src/db/api");
  ({ default: roomReducer } = await import("../../src/reducers/roomSlice"));
  ({ handleConnectToPeer } =
    await import("../../src/handlers/handleConnectToPeer"));
  ({ resetRatchetGate, isRatchetGatePending } =
    await import("../../src/handlers/ratchetGate"));
  ({ installPqHealingOrchestrator, destroyPqHealingOrchestrator } =
    await import("../../src/handlers/pqHealingOrchestrator"));
});

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  resetRatchetGate(ROOM_ID, PEER_ID);
});

describe("a transport whose initialization fails is retired through the edge teardown", () => {
  test("a failed transport initialization wipes ratchet and PQ state", async () => {
    const peerConnections: IRTCPeerConnection[] = [];
    const rootKey = new Uint8Array(32).fill(1);
    const dhSelfSec = new Uint8Array(32).fill(4);
    const pq = { destroyed: 0 };
    const setIntervalSpy = spyOn(globalThis, "setInterval");
    const clearIntervalSpy = spyOn(globalThis, "clearInterval");
    // The transport claimed the edge's persisted ratchet row when it was
    // registered; the database worker is not available under bun test.
    const deletedRows: string[] = [];
    const deleteSpy = spyOn(dbApi, "deleteRatchetSession").mockImplementation(
      async (roomId: string, peerPublicKey: string) => {
        deletedRows.push(`${roomId}/${peerPublicKey}`);
      },
    );
    cleanups.push(() => {
      setIntervalSpy.mockRestore();
      clearIntervalSpy.mockRestore();
      deleteSpy.mockRestore();
    });
    let attached: IRTCPeerConnection | undefined;

    const state = {
      keyPair: {
        peerId: SELF_PEER_ID,
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
          // Left over from the transport this one was built to replace.
          handshakeStatusByPeer: {
            [PEER_ID]: {
              status: "authenticated",
              peerPublicKey: LOWER_PUBLIC_KEY,
            },
          } as Record<string, PeerHandshakeStatus>,
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
        if (typeof action === "function") {
          // The signaling `connectWithPeer`, the last initialization step. By
          // the time it fails the transport is registered; give it the state
          // a transport can hold, then fail the step.
          const epc = peerConnections[0];
          attached = epc;
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
          epc.pqHealingState = {
            destroy: () => {
              pq.destroyed += 1;
            },
          } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
          installPqHealingOrchestrator(epc, ROOM_ID, {
            sendControlFrame: () => true,
            failEdge: () => undefined,
            tickMs: 3_600_000,
          });
          cleanups.push(() => destroyPqHealingOrchestrator(epc));
          return {
            unwrap: () => Promise.reject(new Error("signaling socket dropped")),
          };
        }
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

    await expect(
      handleConnectToPeer(
        {
          peerId: PEER_ID,
          peerPublicKey: LOWER_PUBLIC_KEY,
          roomId: ROOM_ID,
          peerConnections,
        },
        api,
      ),
    ).rejects.toThrow("signaling socket dropped");

    expect(attached).toBeDefined();
    const epc = attached!;
    const handle = setIntervalSpy.mock.results.at(-1)?.value as unknown;
    expect(peerConnections).toEqual([]);
    expect((epc as unknown as FakeRTCPeerConnection).closes).toBe(1);
    for (const secret of [rootKey, dhSelfSec])
      expect(secret.every((byte) => byte === 0)).toBe(true);
    expect(epc.ratchetState).toBeUndefined();
    expect(pq.destroyed).toBe(1);
    expect(epc.pqHealingState).toBeUndefined();
    expect(handle).toBeDefined();
    expect(
      clearIntervalSpy.mock.calls.some(([cleared]) => cleared === handle),
    ).toBe(true);
    // The gate this transport claimed no longer leaves awaiters hanging.
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, epc.ratchetGateLease)).toBe(
      false,
    );
    // Nor does the room describe the edge as authenticated.
    expect(state.rooms[0].handshakeStatusByPeer[PEER_ID]).toBeUndefined();
    // And the edge's persisted ratchet row this transport owned is deleted.
    for (let turn = 0; turn < 5 && deletedRows.length === 0; turn++)
      await new Promise((resolve) => setTimeout(resolve, 0));
    expect(deletedRows).toEqual([`${ROOM_ID}/${LOWER_PUBLIC_KEY}`]);
  }, 20000);
});
