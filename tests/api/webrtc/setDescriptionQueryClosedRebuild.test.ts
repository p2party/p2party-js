import { ownTestTransports } from "../../support/transportFixture";
import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCIceCandidate,
  IRTCPeerConnection,
} from "../../../src/api/webrtc/interfaces";

// setDescriptionQuery imports the signaling API and channel orchestration,
// which import the Redux store, whose identity slice reads localStorage at
// module initialization.
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

/** The slice of RTCPeerConnection the rebuilt transport has to provide. */
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

  async setLocalDescription(init?: RTCSessionDescriptionInit): Promise<void> {
    if (init?.type === "rollback") {
      this.signalingState = "stable";
      return;
    }
    this.localDescription = {
      type: this.remoteDescription ? "answer" : "offer",
      sdp: "v=0\r\n",
    } as RTCSessionDescription;
    this.signalingState = this.remoteDescription
      ? "stable"
      : "have-local-offer";
  }

  async setRemoteDescription(init: RTCSessionDescriptionInit): Promise<void> {
    this.remoteDescription = init as RTCSessionDescription;
    this.signalingState =
      init.type === "offer" ? "have-remote-offer" : "stable";
  }

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

const ROOM_ID = "00000000-0000-4000-8000-0000000000d1";
const ROOM_URL = "d1".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const LOWER_PUBLIC_KEY = `${"00".repeat(31)}01`;
const HIGHER_PUBLIC_KEY = "ff".repeat(32);

const sdp = (): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill("bb").join(":")}\r\n` +
  "a=setup:actpass\r\n";

type SetDescriptionQuery =
  typeof import("../../../src/api/webrtc/setDescriptionQuery");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type RoomPolicy = typeof import("../../../src/roomPolicy");

let webrtcSetDescriptionQuery: SetDescriptionQuery["default"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  await import("../../../src/store");
  ({ default: webrtcSetDescriptionQuery } =
    await import("../../../src/api/webrtc/setDescriptionQuery"));
  ({ resetRatchetGate } = await import("../../../src/handlers/ratchetGate"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../../src/roomPolicy"));
});

const fakeApi = (): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: SELF_PEER_ID,
      // The higher identity is the RESPONDER, so this side never opens `main`
      // and the test stays clear of the handshake machinery.
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
      if (typeof action === "function")
        return Object.assign(Promise.resolve({ data: undefined }), {
          unwrap: async () => undefined,
        });
      return action;
    },
    getState: () => state,
  } as unknown as BaseQueryApi;
  return { api, dispatched };
};

/**
 * What a terminal handshake failure leaves behind: the transport is closed,
 * but `main`'s close handler was detached before the close, so nothing removed
 * it from the registry (C2's disclosed residual).
 */
const closedTransport = (): IRTCPeerConnection => {
  // A closed RTCPeerConnection still answers every method — it rejects with
  // InvalidStateError. Modelling that rather than omitting the methods keeps a
  // reverted fix failing on this file's own assertions instead of on a
  // TypeError from an incomplete double.
  const invalidState = () =>
    Promise.reject(
      Object.assign(
        new Error("The RTCPeerConnection's signalingState is 'closed'."),
        {
          name: "InvalidStateError",
        },
      ),
    );
  return {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: LOWER_PUBLIC_KEY,
    makingOffer: false,
    ignoreOffer: false,
    iceCandidates: [] as RTCIceCandidateInit[],
    ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
    remoteTransportRebinds: 0,
    handshakeTerminalFailure: "pin-mismatch",
    connectionState: "closed" as RTCPeerConnectionState,
    signalingState: "closed" as RTCSignalingState,
    localDescription: null,
    remoteDescription: null,
    ondatachannel: null,
    setLocalDescription: invalidState,
    setRemoteDescription: invalidState,
    addIceCandidate: invalidState,
    createDataChannel: () => {
      throw new Error("InvalidStateError");
    },
    close: () => undefined,
  } as unknown as IRTCPeerConnection;
};

describe("setDescriptionQuery on a transport the registry never released", () => {
  // The user-visible symptom: a peer mistypes a PIN, both sides fail key
  // confirmation and close, the peer fixes the PIN and re-offers on a FRESH
  // transport — and the offer landed on our corpse and was dropped, leaving
  // the edge dead until an unrelated signaling reconnect rebuilt it.
  test("a re-offer onto a closed transport rebuilds the edge and is answered", async () => {
    const { api, dispatched } = fakeApi();
    const stale = closedTransport();
    const peerConnections: IRTCPeerConnection[] = [stale];
    const disconnects: { roomId?: string; peerId: string }[] = [];

    const result = await webrtcSetDescriptionQuery(
      {
        peerId: PEER_ID,
        peerPublicKey: LOWER_PUBLIC_KEY,
        roomId: ROOM_ID,
        description: { type: "offer", sdp: sdp() } as RTCSessionDescription,
        rtcConfig: { iceServers: [] },
        peerConnections,
        iceCandidates: [] as IRTCIceCandidate[],
        dataChannels: [] as IRTCDataChannel[],
        // The real disconnectFromPeer query removes the transport from the
        // registry; mirror exactly that much of it.
        disconnectPeer: async (params) => {
          disconnects.push(params);
          const index = peerConnections.indexOf(stale);
          if (index > -1) peerConnections.splice(index, 1);
        },
      },
      api,
      {},
    );

    expect(result).toEqual({ data: undefined });
    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    expect(peerConnections).not.toContain(stale);
    expect(peerConnections).toHaveLength(1);

    const rebuilt = peerConnections[0];
    expect(rebuilt.connectionState).not.toBe("closed");
    expect(rebuilt.remoteDescription?.type).toBe("offer");
    expect(rebuilt.localDescription?.type).toBe("answer");
    // The answer went back out: the edge is alive again, not merely rebuilt.
    expect(dispatched.filter((a) => typeof a === "function").length).toBe(2);
  }, 20000);

  test("a live transport is not torn down by this path", async () => {
    const { api } = fakeApi();
    const live = closedTransport() as IRTCPeerConnection & {
      connectionState: RTCPeerConnectionState;
      signalingState: RTCSignalingState;
    };
    live.connectionState = "connected";
    live.signalingState = "stable";
    const peerConnections: IRTCPeerConnection[] = [live];
    const disconnects: unknown[] = [];

    await webrtcSetDescriptionQuery(
      {
        peerId: PEER_ID,
        peerPublicKey: LOWER_PUBLIC_KEY,
        roomId: ROOM_ID,
        description: { type: "answer", sdp: sdp() } as RTCSessionDescription,
        rtcConfig: { iceServers: [] },
        peerConnections,
        iceCandidates: [] as IRTCIceCandidate[],
        dataChannels: [] as IRTCDataChannel[],
        disconnectPeer: async (params) => {
          disconnects.push(params);
        },
      },
      api,
      {},
    );

    expect(disconnects).toEqual([]);
    expect(peerConnections).toEqual([live]);
  }, 20000);
});
