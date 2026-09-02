import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// setDescriptionQuery imports the signaling API and channel orchestration,
// which import the Redux store, whose identity slice reads localStorage at
// module initialization. Install the minimal browser shim before dynamically
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

type SetDescriptionQuery =
  typeof import("../../../src/api/webrtc/setDescriptionQuery");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../../src/reducers/roomSlice");

let webrtcSetDescriptionQuery: SetDescriptionQuery["default"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the WebRTC query modules load.
  await import("../../../src/store");
  ({ default: webrtcSetDescriptionQuery } =
    await import("../../../src/api/webrtc/setDescriptionQuery"));
  ({ isCurrentRatchetGateLease, resetRatchetGate } =
    await import("../../../src/handlers/ratchetGate"));
  ({ setPeerHandshakeStatus } =
    await import("../../../src/reducers/roomSlice"));
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000aa";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
// The lexicographically lower canonical Ed25519 identity is the initiator that
// creates `main`.
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

const description = (
  type: "offer" | "answer",
  fingerprintByte: string,
): RTCSessionDescription =>
  ({ type, sdp: fingerprintSdp(fingerprintByte) }) as RTCSessionDescription;

interface FakeChannel {
  channel: IRTCDataChannel;
  closes: { count: number };
}

const fakeChannel = (
  label: string,
  readyState: RTCDataChannelState,
): FakeChannel => {
  const closes = { count: 0 };
  let state = readyState;
  const channel = {
    label,
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

interface FakePeerConnectionOptions {
  peerPublicKey: string;
  signalingState: RTCSignalingState;
  connectionState: RTCPeerConnectionState;
  /** Fingerprint byte of the remote description already applied, if any. */
  remoteFingerprint?: string;
  /** Install an open `main` plus live ratchet state (an authenticated edge). */
  authenticated?: boolean;
}

interface FakePeerConnection {
  epc: IRTCPeerConnection;
  createdLabels: string[];
  appliedRemote: RTCSessionDescriptionInit[];
  main?: FakeChannel;
  rootKey: Uint8Array;
}

const fakePeerConnection = ({
  peerPublicKey,
  signalingState,
  connectionState,
  remoteFingerprint,
  authenticated = false,
}: FakePeerConnectionOptions): FakePeerConnection => {
  const createdLabels: string[] = [];
  const appliedRemote: RTCSessionDescriptionInit[] = [];
  const main = authenticated ? fakeChannel("main", "open") : undefined;
  const rootKey = new Uint8Array(32).fill(7);
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: peerPublicKey,
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [],
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    signalingState,
    connectionState,
    remoteDescription:
      remoteFingerprint === undefined
        ? null
        : { type: "answer", sdp: fingerprintSdp(remoteFingerprint) },
    localDescription: { type: "offer", sdp: fingerprintSdp("11") },
    ondatachannel: null,
    mainChannel: main?.channel,
    ratchetState: authenticated
      ? {
          rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
          rootKey,
          sendingChainKey: null,
          receivingChainKey: null,
          dhSelfPub: new Uint8Array(32),
          dhSelfSec: new Uint8Array(32),
          dhRemotePub: null,
          Ns: 0,
          Nr: 0,
          PN: 0,
          skipped: new Map<string, Uint8Array>(),
        }
      : undefined,
    setRemoteDescription: async (next: RTCSessionDescriptionInit) => {
      appliedRemote.push(next);
      epc.remoteDescription = next as RTCSessionDescription;
      epc.signalingState =
        next.type === "offer" ? "have-remote-offer" : "stable";
    },
    setLocalDescription: async (next?: RTCSessionDescriptionInit) => {
      if (next?.type === "rollback") {
        epc.signalingState = "stable";
        return;
      }
      epc.localDescription = {
        type: "answer",
        sdp: fingerprintSdp("11"),
      } as RTCSessionDescription;
      epc.signalingState = "stable";
    },
    createDataChannel: (label: string) => {
      createdLabels.push(label);
      return fakeChannel(label, "connecting").channel;
    },
    close: () => undefined,
  } as unknown as IRTCPeerConnection & {
    remoteDescription: RTCSessionDescription | RTCSessionDescriptionInit | null;
    localDescription: RTCSessionDescription | null;
    signalingState: RTCSignalingState;
  };
  return { epc, createdLabels, appliedRemote, main, rootKey };
};

const fakeApi = (
  selfPublicKey: string,
): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      publicKey: selfPublicKey,
      secretKey: "",
      challengeId: "",
      challenge: "",
      signature: "",
    },
    rooms: [],
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

const handshakeStatuses = (dispatched: unknown[]): unknown[] =>
  dispatched.filter(
    (action) =>
      (action as { type?: string }).type === setPeerHandshakeStatus.type,
  );

const applyDescription = (
  epc: IRTCPeerConnection,
  next: RTCSessionDescription,
  api: BaseQueryApi,
  peerPublicKey: string,
) =>
  webrtcSetDescriptionQuery(
    {
      peerId: PEER_ID,
      peerPublicKey,
      roomId: ROOM_ID,
      description: next,
      peerConnections: [epc],
      iceCandidates: [],
      dataChannels: [],
    },
    api,
    {},
  );

describe("setDescriptionQuery remote transport binding", () => {
  test("an answer with a new remote fingerprint re-authenticates the edge and the initiator reopens main", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    // The old authenticated state is gone...
    expect(pc.main?.closes.count).toBe(1);
    expect(pc.epc.ratchetState).toBeUndefined();
    expect(pc.rootKey.every((byte) => byte === 0)).toBe(true);
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(false);
    expect(
      isCurrentRatchetGateLease(ROOM_ID, PEER_ID, pc.epc.ratchetGateLease),
    ).toBe(true);
    expect(handshakeStatuses(dispatched)).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    ]);
    // ...and exactly one fresh main was opened on the SAME peer connection.
    expect(pc.createdLabels).toEqual(["main"]);
    expect(pc.epc.mainChannel).toBeDefined();
    expect(pc.epc.mainChannel).not.toBe(pc.main?.channel);
    expect(pc.epc.mainChannel?.label).toBe("main");

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an answer with the unchanged remote fingerprint leaves the authenticated edge alone", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    expect(pc.main?.closes.count).toBe(0);
    expect(pc.epc.mainChannel).toBe(pc.main?.channel);
    expect(pc.epc.ratchetState).toBeDefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(true);
    expect(handshakeStatuses(dispatched)).toEqual([]);
    expect(pc.createdLabels).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("the responder resets the edge on a new remote fingerprint but does not create main", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: LOWER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      LOWER_PUBLIC_KEY,
    );

    expect(pc.main?.closes.count).toBe(1);
    expect(pc.epc.mainChannel).toBeUndefined();
    expect(pc.epc.ratchetState).toBeUndefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(false);
    expect(handshakeStatuses(dispatched)).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    ]);
    expect(pc.createdLabels).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a stale answer with a new fingerprint is ignored without touching the edge", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote).toEqual([]);
    expect(pc.main?.closes.count).toBe(0);
    expect(pc.epc.ratchetState).toBeDefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(true);
    expect(handshakeStatuses(dispatched)).toEqual([]);
    expect(pc.createdLabels).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("the initiator opens main on a still-connecting transport that has none", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connecting",
    });
    const { api } = fakeApi(LOWER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    expect(pc.createdLabels).toEqual(["main"]);
    expect(pc.epc.mainChannel?.label).toBe("main");

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a responder-first offer on a new transport is answered and then main is opened by the initiator", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "new",
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);

    await applyDescription(
      pc.epc,
      description("offer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    // The answer was produced locally and handed to signaling: RTK Query's
    // `initiate` yields an opaque thunk, so the fake dispatch sees exactly one
    // function-shaped action for the answer send.
    expect(pc.epc.localDescription?.type).toBe("answer");
    expect(
      dispatched.filter((action) => typeof action === "function"),
    ).toHaveLength(1);
    expect(pc.createdLabels).toEqual(["main"]);
    expect(pc.epc.mainChannel?.label).toBe("main");

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});
