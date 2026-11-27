import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCIceCandidate,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// setCandidateQuery imports the WebRTC API, which imports the Redux store,
// whose identity slice reads localStorage at module initialization. Install the
// minimal browser shim before dynamically importing it under Bun.
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

const ROOM_ID = "00000000-0000-4000-8000-0000000000cc";
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";

type SetCandidateQuery =
  typeof import("../../../src/api/webrtc/setCandidateQuery");
type NegotiationLock = typeof import("../../../src/api/webrtc/negotiationLock");

let webrtcSetIceCandidateQuery: SetCandidateQuery["default"];
let runRoomPeerExclusive: NegotiationLock["runRoomPeerExclusive"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the WebRTC query modules load.
  await import("../../../src/store");
  ({ default: webrtcSetIceCandidateQuery } =
    await import("../../../src/api/webrtc/setCandidateQuery"));
  ({ runRoomPeerExclusive } =
    await import("../../../src/api/webrtc/negotiationLock"));
});

const fakeApi = (): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      publicKey: `${"00".repeat(31)}01`,
      secretKey: "",
      challengeId: "",
      challenge: "",
      signature: "",
    },
    rooms: [],
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

interface StuckPeerConnection {
  epc: IRTCPeerConnection;
  /** Resolved when the never-settling addIceCandidate has been entered. */
  entered: Promise<void>;
  close: () => void;
  restarts: number;
}

/**
 * A transport whose addIceCandidate never settles — exactly what the WebRTC
 * specification leaves behind when close() aborts an operation in flight.
 */
const stuckPeerConnection = (): StuckPeerConnection => {
  let markEntered!: () => void;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  const state = { restarts: 0 };
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: "ff".repeat(32),
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [] as RTCIceCandidateInit[],
    signalingState: "stable" as RTCSignalingState,
    connectionState: "connected" as RTCPeerConnectionState,
    // No a=ice-ufrag: every candidate matches the active generation.
    remoteDescription: { type: "answer", sdp: "v=0\r\n" },
    localDescription: null,
    addIceCandidate: () => {
      markEntered();
      return new Promise<void>(() => undefined);
    },
    restartIce: () => {
      state.restarts += 1;
    },
    close: () => {
      epc.signalingState = "closed";
      epc.connectionState = "closed";
    },
  } as unknown as IRTCPeerConnection & {
    signalingState: RTCSignalingState;
    connectionState: RTCPeerConnectionState;
    close: () => void;
  };
  return {
    epc,
    entered,
    close: () => {
      epc.close();
    },
    get restarts() {
      return state.restarts;
    },
  };
};

describe("setCandidateQuery on a transport that closes underneath it", () => {
  test("a closed connection mid-addIceCandidate releases the room/peer mutex", async () => {
    // The regression: addIceCandidate on a closed RTCPeerConnection is aborted
    // WITHOUT its promise ever settling, so awaiting it inside
    // runRoomPeerExclusive held the (room, peer) mutex forever. Because the
    // socket's ingress queue awaits this dispatch and is strictly serial, no
    // later signaling frame on that socket was ever processed either.
    const { api, dispatched } = fakeApi();
    const pc = stuckPeerConnection();
    pc.epc.iceCandidates.push({ candidate: "candidate:buffered" });
    const iceCandidates: IRTCIceCandidate[] = [
      {
        candidate: "candidate:pending",
        roomId: ROOM_ID,
        withPeerId: PEER_ID,
      } as IRTCIceCandidate,
      {
        candidate: "candidate:other-room",
        roomId: "00000000-0000-4000-8000-0000000000dd",
        withPeerId: PEER_ID,
      } as IRTCIceCandidate,
    ];

    const query = webrtcSetIceCandidateQuery(
      {
        peerId: PEER_ID,
        roomId: ROOM_ID,
        candidate: { candidate: "candidate:incoming" },
        peerConnections: [pc.epc],
        iceCandidates,
      },
      api,
      {},
    );

    await pc.entered;
    setTimeout(pc.close, 50);

    const result = await query;
    expect(result).toEqual({ data: undefined });

    // The dead attempt's ICE is dropped, and only this room/peer's.
    expect(pc.epc.iceCandidates).toEqual([]);
    expect(iceCandidates.map((candidate) => candidate.candidate)).toEqual([
      "candidate:other-room",
    ]);
    // Nothing was repaired or torn down: the transport is already closed and
    // its own close path owns the follow-up.
    expect(pc.restarts).toBe(0);
    expect(dispatched).toEqual([]);

    // The next signaling frame for the same edge must get the lock.
    let ran = false;
    const next = runRoomPeerExclusive(ROOM_ID, PEER_ID, async () => {
      ran = true;
    });
    // Bun's test deadline bounds this await when the mutex was left held.
    await next;
    expect(ran).toBe(true);
  }, 20000);
});

test("a failed candidate never waits in the ingress queue for its credential response", async () => {
  const { api } = fakeApi();
  const { epc } = stuckPeerConnection();
  Object.assign(epc, {
    iceConnectionState: "failed",
    addIceCandidate: async () => {
      throw new Error("failed candidate");
    },
  });
  let release!: () => void;
  let started = false;
  epc.ensureFreshIceConfiguration = () => {
    started = true;
    return new Promise((resolve) => {
      release = () => resolve(false);
    });
  };
  let restarted = false;
  epc.restartIce = () => {
    restarted = true;
  };
  const outbound = webrtcSetIceCandidateQuery(
    {
      roomId: ROOM_ID,
      peerId: PEER_ID,
      candidate: { candidate: "candidate:1 1 UDP 1 127.0.0.1 6000 typ host" },
      peerConnections: [epc],
      iceCandidates: [],
    },
    api,
    {},
  );
  await outbound;
  expect(started).toBe(true);
  expect(restarted).toBe(false);
  // The response is free to enter on the same ordered socket queue.
  release();
  await Promise.resolve();
  expect(restarted).toBe(true);
});
