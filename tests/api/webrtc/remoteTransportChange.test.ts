import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// The edge re-authentication helper imports the handshake inbox, which imports
// the Redux store, whose identity slice reads localStorage at module
// initialization. Install the minimal browser shim before dynamically
// importing it under Bun.
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

type RemoteTransportChange =
  typeof import("../../../src/api/webrtc/remoteTransportChange");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type HandleHandshake = typeof import("../../../src/handlers/handleHandshake");
type RoomSlice = typeof import("../../../src/reducers/roomSlice");

let detectRemoteTransportChange: RemoteTransportChange["detectRemoteTransportChange"];
let resetEdgeAuthenticationForNewRemoteTransport: RemoteTransportChange["resetEdgeAuthenticationForNewRemoteTransport"];
let claimRatchetGate: RatchetGate["claimRatchetGate"];
let getRatchetGate: RatchetGate["getRatchetGate"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setHandshakeChannel: HandleHandshake["setHandshakeChannel"];
let clearHandshakeChannel: HandleHandshake["clearHandshakeChannel"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the WebRTC query modules load.
  await import("../../../src/store");
  ({
    detectRemoteTransportChange,
    resetEdgeAuthenticationForNewRemoteTransport,
  } = await import("../../../src/api/webrtc/remoteTransportChange"));
  ({
    claimRatchetGate,
    getRatchetGate,
    isCurrentRatchetGateLease,
    resetRatchetGate,
  } = await import("../../../src/handlers/ratchetGate"));
  ({ setHandshakeChannel, clearHandshakeChannel } =
    await import("../../../src/handlers/handleHandshake"));
  ({ setPeerHandshakeStatus } =
    await import("../../../src/reducers/roomSlice"));
});

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

describe("detectRemoteTransportChange", () => {
  test("the same remote fingerprint is not a transport change", () => {
    expect(
      detectRemoteTransportChange(fingerprintSdp("AA"), fingerprintSdp("aa")),
    ).toBe(false);
  });

  test("a different remote fingerprint is a new remote transport", () => {
    expect(
      detectRemoteTransportChange(fingerprintSdp("AA"), fingerprintSdp("BB")),
    ).toBe(true);
  });

  test("no previous remote description is not a transport change", () => {
    expect(detectRemoteTransportChange(undefined, fingerprintSdp("AA"))).toBe(
      false,
    );
  });

  test("a missing or malformed fingerprint on either side is not a change", () => {
    expect(detectRemoteTransportChange("v=0\r\n", fingerprintSdp("AA"))).toBe(
      false,
    );
    expect(detectRemoteTransportChange(fingerprintSdp("AA"), "v=0\r\n")).toBe(
      false,
    );
    expect(
      detectRemoteTransportChange(
        fingerprintSdp("AA"),
        "v=0\r\na=fingerprint:sha-256 AA:BB\r\n",
      ),
    ).toBe(false);
  });
});

const ROOM_ID = "00000000-0000-4000-8000-00000000000a";
const PEER_ID = "00000000-0000-4000-8000-00000000000b";
const PEER_PUBLIC_KEY = "cd".repeat(32);

const fakeApi = (): {
  api: Pick<BaseQueryApi, "dispatch">;
  dispatched: unknown[];
} => {
  const dispatched: unknown[] = [];
  const api = {
    dispatch: (action: unknown) => {
      dispatched.push(action);
      return action;
    },
  } as unknown as Pick<BaseQueryApi, "dispatch">;
  return { api, dispatched };
};

describe("resetEdgeAuthenticationForNewRemoteTransport", () => {
  test("wipes the authenticated edge state and reopens the gate for a fresh handshake", async () => {
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    expect(claimRatchetGate(ROOM_ID, PEER_ID)).toBe(oldLease);
    const oldGate = getRatchetGate(ROOM_ID, PEER_ID);
    setHandshakeChannel(ROOM_ID, PEER_ID, { send: () => undefined });

    let mainCloses = 0;
    let mainReadyState: RTCDataChannelState = "open";
    const main = {
      label: "main",
      get readyState() {
        return mainReadyState;
      },
      close: () => {
        mainCloses += 1;
        mainReadyState = "closed";
      },
    } as unknown as IRTCDataChannel;
    const messageChannel = {
      label: "message",
      readyState: "open",
      close: () => {
        throw new Error("per-message channels must be left alone");
      },
    } as unknown as IRTCDataChannel;
    const rootKey = new Uint8Array(32).fill(1);
    const sendingChainKey = new Uint8Array(32).fill(2);
    const receivingChainKey = new Uint8Array(32).fill(3);
    const dhSelfSec = new Uint8Array(32).fill(4);
    const skipped = new Uint8Array(32).fill(5);
    const cached = new Uint8Array(32).fill(6);
    let pqDestroyed = 0;
    let coverDestroyed = 0;
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: oldLease,
      mainChannel: main,
      messageChannels: new Set([messageChannel]),
      ratchetState: {
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
      },
      messageKeyCache: new Map([["cached", cached]]),
      messageKeyByMerkleRoot: new Map([["root", "cached"]]),
      pqHealingState: {
        destroy: () => {
          pqDestroyed += 1;
        },
      },
      serializeEdgeCryptoState: () => new Uint8Array(1),
      coverRuntime: {
        destroy: () => {
          coverDestroyed += 1;
        },
      },
    } as unknown as IRTCPeerConnection;
    const { api, dispatched } = fakeApi();

    resetEdgeAuthenticationForNewRemoteTransport({
      epc,
      roomId: ROOM_ID,
      peerId: PEER_ID,
      api,
      reason: new Error("Remote DTLS certificate changed"),
    });

    // Gate: the old lease is stale, the edge now owns a fresh unsettled gate.
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(false);
    expect(epc.ratchetGateLease).not.toBe(oldLease);
    expect(
      isCurrentRatchetGateLease(ROOM_ID, PEER_ID, epc.ratchetGateLease),
    ).toBe(true);
    await expect(oldGate).rejects.toThrow("Remote DTLS certificate changed");

    // Handshake inbox: nothing left to clear.
    expect(clearHandshakeChannel(ROOM_ID, PEER_ID)).toBe(false);

    // Main channel closed and detached WITHOUT touching per-message channels.
    expect(mainCloses).toBe(1);
    expect(epc.mainChannel).toBeUndefined();
    expect(epc.messageChannels?.has(messageChannel)).toBe(true);

    // Crypto state wiped.
    for (const secret of [
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfSec,
      skipped,
      cached,
    ])
      expect(secret.every((byte) => byte === 0)).toBe(true);
    expect(epc.ratchetState).toBeUndefined();
    expect(pqDestroyed).toBe(1);
    expect(epc.pqHealingState).toBeUndefined();
    expect(epc.messageKeyCache).toBeUndefined();
    expect(epc.messageKeyByMerkleRoot).toBeUndefined();
    expect(epc.serializeEdgeCryptoState).toBeUndefined();
    expect(coverDestroyed).toBe(1);
    expect(epc.coverRuntime).toBeUndefined();

    // The app sees the edge as re-authenticating, never as still authenticated.
    expect(dispatched).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    ]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a bare edge with no main or crypto state still gets a fresh gate and status", () => {
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    let mainCloses = 0;
    const closedMain = {
      label: "main",
      readyState: "closed",
      close: () => {
        mainCloses += 1;
      },
    } as unknown as IRTCDataChannel;
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: oldLease,
      mainChannel: closedMain,
    } as unknown as IRTCPeerConnection;
    const { api, dispatched } = fakeApi();

    expect(() =>
      resetEdgeAuthenticationForNewRemoteTransport({
        epc,
        roomId: ROOM_ID,
        peerId: PEER_ID,
        api,
        reason: new Error("Remote DTLS certificate changed"),
      }),
    ).not.toThrow();

    expect(mainCloses).toBe(0);
    expect(epc.mainChannel).toBeUndefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(false);
    expect(
      isCurrentRatchetGateLease(ROOM_ID, PEER_ID, epc.ratchetGateLease),
    ).toBe(true);
    expect(dispatched).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    ]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});
