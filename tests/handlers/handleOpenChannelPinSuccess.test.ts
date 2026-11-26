// The production seam between a completed PIN handshake and the attempt
// limiter: handleOpenChannel must record the peer as authenticated in the
// room, or the room window's exemption for established members never applies.
//
// A real handshake needs two identities and a database worker each, which a
// unit run does not have, so runHandshake alone is replaced — by a delegate
// that is the real function except inside the test below. Everything after
// it (status dispatch, PQ orchestrator install, cover install, the limiter
// call) runs for real, and the limiter writes to the real database worker over
// fake-indexeddb.
import { IDBFactory } from "fake-indexeddb";
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";

import { workerPinAttemptStore, callPinWorker } from "../pinAttemptStores";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { PinAttemptStore } from "../../src/roomPinAttempts";

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
type RoomPinVault = typeof import("../../src/roomPinVault");
type RoomPinAttempts = typeof import("../../src/roomPinAttempts");
type PqHealingOrchestrator =
  typeof import("../../src/handlers/pqHealingOrchestrator");

let handleOpenChannel: HandleOpenChannel["handleOpenChannel"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];
let putRoomPin: RoomPinVault["putRoomPin"];
let deleteRoomPin: RoomPinVault["deleteRoomPin"];
let pinAttempts: RoomPinAttempts;
let destroyPqHealingOrchestrator: PqHealingOrchestrator["destroyPqHealingOrchestrator"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ resetRatchetGate } = await import("../../src/handlers/ratchetGate"));
  ({ setPeerHandshakeStatus } = await import("../../src/reducers/roomSlice"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
  ({ putRoomPin, deleteRoomPin } = await import("../../src/roomPinVault"));
  pinAttempts = await import("../../src/roomPinAttempts");
  ({ destroyPqHealingOrchestrator } =
    await import("../../src/handlers/pqHealingOrchestrator"));
});

afterAll(() => {
  runHandshakeImpl = realRunHandshake;
  pinAttempts.usePinAttemptStoreForTests();
});

const PIN_ROOM_ID = "00000000-0000-4000-8000-0000000000e1";
const PIN_ROOM_URL = "e1".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000e2";
const PEER_ID = "00000000-0000-4000-8000-0000000000e3";
// The lexicographically lower canonical identity is the initiator that opens main.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

const fakeMain = (): IRTCDataChannel => {
  let state: RTCDataChannelState = "connecting";
  const channel = {
    label: "main",
    get readyState() {
      return state;
    },
    binaryType: "blob",
    send: () => undefined,
    close: () => {
      state = "closed";
    },
  } as unknown as IRTCDataChannel;
  return channel;
};

const fakePeerConnection = (): IRTCPeerConnection =>
  ({
    roomId: PIN_ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: HIGHER_PUBLIC_KEY,
    connectionState: "connected",
    signalingState: "stable",
    localDescription: { type: "offer", sdp: fingerprintSdp("11") },
    remoteDescription: { type: "answer", sdp: fingerprintSdp("aa") },
    ratchetGateLease: resetRatchetGate(PIN_ROOM_ID, PEER_ID),
    close: () => undefined,
  }) as unknown as IRTCPeerConnection;

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

/** Counts store operations still in flight, so the test can wait them out. */
const trackedStore = (
  inner: PinAttemptStore,
): { store: PinAttemptStore; idle: () => boolean; deletes: () => number } => {
  let inFlight = 0;
  let deleteCount = 0;
  const track = <T>(operation: Promise<T>): Promise<T> => {
    inFlight += 1;
    return operation.finally(() => {
      inFlight -= 1;
    });
  };
  return {
    store: {
      get: (roomId, id) => track(inner.get(roomId, id)),
      increment: (...args) => track(inner.increment(...args)),
      delete: (roomId, id) => {
        deleteCount += 1;
        return track(inner.delete(roomId, id));
      },
    },
    idle: () => inFlight === 0,
    deletes: () => deleteCount,
  };
};

describe("handleOpenChannel PIN success", () => {
  test("a completed handshake records the peer as authenticated", async () => {
    (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
      new IDBFactory();
    const tracked = trackedStore(workerPinAttemptStore);
    pinAttempts.usePinAttemptStoreForTests(tracked.store);
    // The peer had two failed attempts before it got the PIN right.
    for (let i = 0; i < pinAttempts.MAX_PIN_ATTEMPTS - 1; i++)
      await pinAttempts.recordPinFailure(PIN_ROOM_ID, HIGHER_PUBLIC_KEY);
    const deletesBefore = tracked.deletes();

    let handshakes = 0;
    runHandshakeImpl = async (epc) => {
      handshakes += 1;
      // What the real handshake leaves behind for the orchestrator install.
      (epc as unknown as { pqHealingState: object }).pqHealingState = {};
    };

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
    const epc = fakePeerConnection();
    const { api, dispatched } = fakeApi([pinRoom]);
    try {
      const channel = await handleOpenChannel(
        { channel: fakeMain(), epc, roomId: PIN_ROOM_ID, dataChannels: [] },
        api,
      );
      channel.onopen?.call(channel, new Event("open"));

      // Wait (in turns, not time) for the authenticated status and for every
      // limiter write the success path started to settle.
      const authenticated = () =>
        dispatched.some(
          (action) =>
            (action as { type?: string }).type ===
              setPeerHandshakeStatus.type &&
            (action as { payload: { status: string } }).payload.status ===
              "authenticated",
        );
      for (
        let turn = 0;
        turn < 500 &&
        !(
          authenticated() &&
          tracked.deletes() > deletesBefore &&
          tracked.idle()
        );
        turn++
      )
        await new Promise((resolve) => setTimeout(resolve, 0));

      expect(handshakes).toBe(1);
      expect(authenticated()).toBe(true);
      // Its backoff is gone: a reload finds no throttle for it.
      expect(
        await callPinWorker(
          "getPinAttemptState",
          PIN_ROOM_ID,
          HIGHER_PUBLIC_KEY,
        ),
      ).toBeUndefined();

      // A reloaded device whose room window is then filled by fresh
      // identities still lets this peer in, and refuses a new one.
      const reloaded = pinAttempts.createPinAttemptLimiter(
        workerPinAttemptStore,
      );
      for (let i = 1; i <= pinAttempts.MAX_ROOM_PIN_FAILURES_PER_WINDOW; i++)
        await reloaded.recordFailure(
          PIN_ROOM_ID,
          (0x1000 + i).toString(16).padStart(64, "0"),
        );
      await expect(
        reloaded.assertAttemptAllowed(PIN_ROOM_ID, HIGHER_PUBLIC_KEY),
      ).resolves.toBeUndefined();
      await expect(
        reloaded.assertAttemptAllowed(PIN_ROOM_ID, "cd".repeat(32)),
      ).rejects.toThrow("identities new to this room");
    } finally {
      destroyPqHealingOrchestrator(epc);
      runHandshakeImpl = realRunHandshake;
      pinAttempts.usePinAttemptStoreForTests();
      deleteRoomPin(PIN_ROOM_URL);
      resetRatchetGate(PIN_ROOM_ID, PEER_ID);
    }
  });
});
