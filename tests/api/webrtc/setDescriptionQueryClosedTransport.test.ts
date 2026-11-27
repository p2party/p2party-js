import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCIceCandidate,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
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

const ROOM_ID = "00000000-0000-4000-8000-0000000000ab";
const ROOM_URL = "ab".repeat(32);
const OTHER_ROOM_ID = "00000000-0000-4000-8000-0000000000ac";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const sdp = (): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill("aa").join(":")}\r\n` +
  "a=setup:actpass\r\n";

const description = (type: "offer" | "answer"): RTCSessionDescription =>
  ({ type, sdp: sdp() }) as RTCSessionDescription;

type SetDescriptionQuery =
  typeof import("../../../src/api/webrtc/setDescriptionQuery");
type NegotiationLock = typeof import("../../../src/api/webrtc/negotiationLock");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type RoomPolicy = typeof import("../../../src/roomPolicy");

let webrtcSetDescriptionQuery: SetDescriptionQuery["default"];
let runRoomPeerExclusive: NegotiationLock["runRoomPeerExclusive"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  await import("../../../src/store");
  ({ default: webrtcSetDescriptionQuery } =
    await import("../../../src/api/webrtc/setDescriptionQuery"));
  ({ runRoomPeerExclusive } =
    await import("../../../src/api/webrtc/negotiationLock"));
  ({ resetRatchetGate } = await import("../../../src/handlers/ratchetGate"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../../src/roomPolicy"));
});

const fakeApi = (): { api: BaseQueryApi; dispatched: unknown[] } => {
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
    rooms: [
      {
        id: ROOM_ID,
        url: ROOM_URL,
        rtcConfig: { iceServers: [] },
        signalingActive: true,
        policy: DEFAULT_ROOM_POLICY_V1,
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
      return { unwrap: async () => undefined };
    },
    getState: () => state,
  } as unknown as BaseQueryApi;
  return { api, dispatched };
};

interface StuckOptions {
  signalingState: RTCSignalingState;
  /** Which SDP operation never settles once it is entered. */
  stuckOn: "setRemoteDescription" | "setLocalDescription";
}

interface StuckPeerConnection {
  epc: IRTCPeerConnection;
  /** Resolves when the never-settling operation has been entered. */
  entered: Promise<void>;
  close: () => void;
  createdLabels: string[];
}

/**
 * A transport whose SDP operation never settles — what the WebRTC
 * specification leaves behind when close() aborts an operation in flight.
 */
const stuckPeerConnection = ({
  signalingState,
  stuckOn,
}: StuckOptions): StuckPeerConnection => {
  let markEntered!: () => void;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  const createdLabels: string[] = [];
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: HIGHER_PUBLIC_KEY,
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [] as RTCIceCandidateInit[],
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    signalingState,
    connectionState: "connected" as RTCPeerConnectionState,
    remoteDescription: null,
    localDescription: null,
    ondatachannel: null,
    setRemoteDescription: (next: RTCSessionDescriptionInit) => {
      if (stuckOn === "setRemoteDescription") {
        markEntered();
        return new Promise<void>(() => undefined);
      }
      epc.remoteDescription = next as RTCSessionDescription;
      epc.signalingState =
        next.type === "offer" ? "have-remote-offer" : "stable";
      return Promise.resolve();
    },
    setLocalDescription: () => {
      if (stuckOn === "setLocalDescription") {
        markEntered();
        return new Promise<void>(() => undefined);
      }
      return Promise.resolve();
    },
    createDataChannel: (label: string) => {
      createdLabels.push(label);
      return { label, readyState: "connecting" } as unknown as RTCDataChannel;
    },
    close: () => {
      epc.signalingState = "closed";
      epc.connectionState = "closed";
    },
  } as unknown as IRTCPeerConnection & {
    signalingState: RTCSignalingState;
    connectionState: RTCPeerConnectionState;
    remoteDescription: RTCSessionDescription | null;
    close: () => void;
  };
  return {
    epc,
    entered,
    createdLabels,
    close: () => {
      epc.close();
    },
  };
};

const pendingIce = (): IRTCIceCandidate[] => [
  {
    candidate: "candidate:pending",
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
  } as IRTCIceCandidate,
  {
    candidate: "candidate:other-room",
    roomId: OTHER_ROOM_ID,
    withPeerId: PEER_ID,
  } as IRTCIceCandidate,
];

const expectMutexFree = async (): Promise<void> => {
  let ran = false;
  const next = runRoomPeerExclusive(ROOM_ID, PEER_ID, async () => {
    ran = true;
  });
  // Bun's test deadline bounds this await when the mutex was left held.
  await next;
  expect(ran).toBe(true);
};

describe("setDescriptionQuery on a transport that closes underneath it", () => {
  test("an answer whose setRemoteDescription never settles abandons the attempt", async () => {
    const { api, dispatched } = fakeApi();
    const pc = stuckPeerConnection({
      signalingState: "have-local-offer",
      stuckOn: "setRemoteDescription",
    });
    pc.epc.iceCandidates.push({ candidate: "candidate:buffered" });
    const iceCandidates = pendingIce();
    const disconnects: RTCDisconnectFromPeerParams[] = [];

    const query = webrtcSetDescriptionQuery(
      {
        peerId: PEER_ID,
        peerPublicKey: HIGHER_PUBLIC_KEY,
        roomId: ROOM_ID,
        description: description("answer"),
        peerConnections: [pc.epc],
        iceCandidates,
        dataChannels: [] as IRTCDataChannel[],
        disconnectPeer: async (params) => {
          disconnects.push(params);
        },
      },
      api,
      {},
    );

    await pc.entered;
    setTimeout(pc.close, 50);

    expect(await query).toEqual({ data: undefined });
    // This attempt's ICE is gone, another room's is untouched...
    expect(pc.epc.iceCandidates).toEqual([]);
    expect(iceCandidates.map((candidate) => candidate.candidate)).toEqual([
      "candidate:other-room",
    ]);
    // ...nothing was opened on the dead transport, and the closed transport's
    // own path — not this query — owns the teardown.
    expect(pc.createdLabels).toEqual([]);
    expect(disconnects).toEqual([]);
    expect(dispatched).toEqual([]);

    await expectMutexFree();
  }, 20000);

  test("an offer whose setLocalDescription never settles sends no answer", async () => {
    const { api, dispatched } = fakeApi();
    const pc = stuckPeerConnection({
      signalingState: "stable",
      stuckOn: "setLocalDescription",
    });
    const iceCandidates = pendingIce();

    const query = webrtcSetDescriptionQuery(
      {
        peerId: PEER_ID,
        peerPublicKey: HIGHER_PUBLIC_KEY,
        roomId: ROOM_ID,
        description: description("offer"),
        peerConnections: [pc.epc],
        iceCandidates,
        dataChannels: [] as IRTCDataChannel[],
        disconnectPeer: async () => undefined,
      },
      api,
      {},
    );

    await pc.entered;
    setTimeout(pc.close, 50);

    expect(await query).toEqual({ data: undefined });
    expect(pc.epc.iceCandidates).toEqual([]);
    expect(iceCandidates.map((candidate) => candidate.candidate)).toEqual([
      "candidate:other-room",
    ]);
    // No answer can be sent for a local description that never existed, and
    // `main` is never opened on a closed transport.
    expect(dispatched).toEqual([]);
    expect(pc.createdLabels).toEqual([]);

    await expectMutexFree();
  }, 20000);
});
