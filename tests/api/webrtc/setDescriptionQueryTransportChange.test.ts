import { afterEach, beforeAll, describe, expect, test } from "bun:test";

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

const ROOM_ID = "00000000-0000-4000-8000-0000000000aa";
const ROOM_URL = "aa".repeat(32);
const SELF_PEER_ID = "00000000-0000-4000-8000-000000000001";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const OTHER_PEER_ID = "00000000-0000-4000-8000-000000000004";
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

/**
 * The slice of RTCPeerConnection that handleConnectToPeer + setDescriptionQuery
 * drive on a FRESH transport: construction from an RTCConfiguration, offer /
 * answer / rollback through setLocalDescription, remote application, data
 * channel creation, and close. Every instance is recorded so a test can find
 * the transport a replacement path built.
 */
class FakeRTCPeerConnection {
  static created: FakeRTCPeerConnection[] = [];

  connectionState: RTCPeerConnectionState = "new";
  signalingState: RTCSignalingState = "stable";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  readonly configuration: RTCConfiguration;
  readonly createdLabels: string[] = [];
  readonly appliedRemote: RTCSessionDescriptionInit[] = [];
  closes = 0;

  constructor(configuration: RTCConfiguration) {
    this.configuration = configuration;
    FakeRTCPeerConnection.created.push(this);
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
    if (this.signalingState === "have-remote-offer") {
      this.localDescription = {
        type: "answer",
        sdp: fingerprintSdp("11"),
      } as RTCSessionDescription;
      this.signalingState = "stable";
      return;
    }
    this.localDescription = {
      type: "offer",
      sdp: fingerprintSdp("11"),
    } as RTCSessionDescription;
    this.signalingState = "have-local-offer";
  }

  async setRemoteDescription(init: RTCSessionDescriptionInit): Promise<void> {
    this.appliedRemote.push(init);
    this.remoteDescription = init as RTCSessionDescription;
    this.signalingState = init.type === "offer" ? "have-remote-offer" : "stable";
  }

  createDataChannel(label: string): RTCDataChannel {
    this.createdLabels.push(label);
    return fakeChannel(label, "connecting").channel as unknown as RTCDataChannel;
  }

  restartIce(): void {}

  close(): void {
    this.closes += 1;
    this.connectionState = "closed";
    this.signalingState = "closed";
  }
}

(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
  FakeRTCPeerConnection;

type SetDescriptionQuery =
  typeof import("../../../src/api/webrtc/setDescriptionQuery");
type DisconnectFromPeerQuery =
  typeof import("../../../src/api/webrtc/disconnectFromPeerQuery");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type RoomSlice = typeof import("../../../src/reducers/roomSlice");
type RoomPolicy = typeof import("../../../src/roomPolicy");
type PendingOffer = typeof import("../../../src/api/webrtc/pendingOffer");
type RetiredRemoteTransports =
  typeof import("../../../src/api/webrtc/retiredRemoteTransports");

let webrtcSetDescriptionQuery: SetDescriptionQuery["default"];
let webrtcDisconnectPeerQuery: DisconnectFromPeerQuery["default"];
let hasUnansweredFirstOffer: PendingOffer["hasUnansweredFirstOffer"];
let forgetRetiredRemoteTransports: RetiredRemoteTransports["forgetRetiredRemoteTransports"];
let isRetiredRemoteTransport: RetiredRemoteTransports["isRetiredRemoteTransport"];
let retireRemoteTransport: RetiredRemoteTransports["retireRemoteTransport"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let deletePeer: RoomSlice["deletePeer"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let setPeer: RoomSlice["setPeer"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let DEFAULT_ROOM_POLICY_V1: RoomPolicy["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the WebRTC query modules load.
  await import("../../../src/store");
  ({ default: webrtcSetDescriptionQuery } =
    await import("../../../src/api/webrtc/setDescriptionQuery"));
  ({ default: webrtcDisconnectPeerQuery } =
    await import("../../../src/api/webrtc/disconnectFromPeerQuery"));
  ({ isCurrentRatchetGateLease, resetRatchetGate } =
    await import("../../../src/handlers/ratchetGate"));
  ({ deletePeer, setConnectingToPeers, setPeer, setPeerHandshakeStatus } =
    await import("../../../src/reducers/roomSlice"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../../src/roomPolicy"));
  ({ hasUnansweredFirstOffer } =
    await import("../../../src/api/webrtc/pendingOffer"));
  ({
    forgetRetiredRemoteTransports,
    isRetiredRemoteTransport,
    retireRemoteTransport,
  } = await import("../../../src/api/webrtc/retiredRemoteTransports"));
});

// Retirement is per-edge module state that outlives one query, exactly as the
// ratchet gate does; every test starts from a clean edge.
afterEach(() => {
  forgetRetiredRemoteTransports(ROOM_ID, PEER_ID);
  forgetRetiredRemoteTransports(ROOM_ID, OTHER_PEER_ID);
});

interface FakePeerConnectionOptions {
  peerPublicKey: string;
  signalingState: RTCSignalingState;
  connectionState: RTCPeerConnectionState;
  /** Fingerprint byte of the remote description already applied, if any. */
  remoteFingerprint?: string;
  /** Install an open `main` plus live ratchet state (an authenticated edge). */
  authenticated?: boolean;
  /**
   * Install a still-connecting `main` and no ratchet state: the initiator has
   * created the channel and offered on a fresh transport, nothing answered yet.
   */
  pendingMain?: boolean;
}

interface FakePeerConnection {
  epc: IRTCPeerConnection;
  createdLabels: string[];
  appliedRemote: RTCSessionDescriptionInit[];
  /** Every setLocalDescription argument, in order (`undefined` = implicit). */
  localCalls: (RTCSessionDescriptionInit | undefined)[];
  closes: { count: number };
  main?: FakeChannel;
  rootKey: Uint8Array;
}

const fakePeerConnection = ({
  peerPublicKey,
  signalingState,
  connectionState,
  remoteFingerprint,
  authenticated = false,
  pendingMain = false,
}: FakePeerConnectionOptions): FakePeerConnection => {
  const createdLabels: string[] = [];
  const appliedRemote: RTCSessionDescriptionInit[] = [];
  const localCalls: (RTCSessionDescriptionInit | undefined)[] = [];
  const closes = { count: 0 };
  const main = authenticated
    ? fakeChannel("main", "open")
    : pendingMain
      ? fakeChannel("main", "connecting")
      : undefined;
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
      localCalls.push(next);
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
    close: () => {
      closes.count += 1;
      epc.connectionState = "closed";
      epc.signalingState = "closed";
    },
  } as unknown as IRTCPeerConnection & {
    remoteDescription: RTCSessionDescription | RTCSessionDescriptionInit | null;
    localDescription: RTCSessionDescription | null;
    signalingState: RTCSignalingState;
    connectionState: RTCPeerConnectionState;
  };
  return {
    epc,
    createdLabels,
    appliedRemote,
    localCalls,
    closes,
    main,
    rootKey,
  };
};

const fakeApi = (
  selfPublicKey: string,
  selfPeerId = SELF_PEER_ID,
): { api: BaseQueryApi; dispatched: unknown[] } => {
  const dispatched: unknown[] = [];
  const state = {
    keyPair: {
      peerId: selfPeerId,
      publicKey: selfPublicKey,
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

const ofType = (dispatched: unknown[], type: string): unknown[] =>
  dispatched.filter((action) => (action as { type?: string }).type === type);

const handshakeStatuses = (dispatched: unknown[]): unknown[] =>
  ofType(dispatched, setPeerHandshakeStatus.type);

const thunks = (dispatched: unknown[]): unknown[] =>
  dispatched.filter((action) => typeof action === "function");

const REDIAL = () =>
  setConnectingToPeers({
    roomId: ROOM_ID,
    connectingToPeers: true,
    reason: "redial",
  });

interface Applied {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  /** Every teardown the query requested through its injected dependency. */
  disconnects: RTCDisconnectFromPeerParams[];
}

/**
 * Run the query against one existing transport. The injected teardown is the
 * real disconnectFromPeer query bound to these same arrays, exactly as the
 * production `disconnectPeerThroughApi` dependency reaches it through RTK.
 */
const applyDescription = async (
  epc: IRTCPeerConnection,
  next: RTCSessionDescription,
  api: BaseQueryApi,
  peerPublicKey: string,
  /** Runs right after the injected teardown, before the query continues. */
  afterDisconnect?: () => void,
): Promise<Applied> => {
  const peerConnections: IRTCPeerConnection[] = [epc];
  const dataChannels: IRTCDataChannel[] = [];
  const iceCandidates: IRTCIceCandidate[] = [];
  const disconnects: RTCDisconnectFromPeerParams[] = [];
  await webrtcSetDescriptionQuery(
    {
      peerId: PEER_ID,
      peerPublicKey,
      roomId: ROOM_ID,
      description: next,
      peerConnections,
      iceCandidates,
      dataChannels,
      disconnectPeer: async (params) => {
        disconnects.push(params);
        await webrtcDisconnectPeerQuery(
          { ...params, peerConnections, dataChannels, iceCandidates },
          api,
          {},
        );
        afterDisconnect?.();
      },
    },
    api,
    {},
  );
  return { peerConnections, dataChannels, disconnects };
};

const freshTransports = (): FakeRTCPeerConnection[] => {
  const fresh = FakeRTCPeerConnection.created.splice(0);
  return fresh;
};

describe("setDescriptionQuery remote transport binding", () => {
  test("the initiator replaces an authenticated transport when the answer carries a new fingerprint", async () => {
    // The initiator woke from a freeze and ICE-restarted on its surviving
    // transport; the peer had rebuilt its own and answers from that new one.
    // Our SCTP association is dead on the far side but still writable here,
    // so re-binding in place would open the next main on it and the
    // handshake would read the old certificate. Replace instead.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    freshTransports();

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    // The stale transport went down through the transport-failure path...
    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    expect(peerConnections).toEqual([]);
    expect(pc.closes.count).toBe(1);
    expect(pc.epc.ratchetState).toBeUndefined();
    expect(pc.rootKey.every((byte) => byte === 0)).toBe(true);
    expect(ofType(dispatched, deletePeer.type)).toEqual([
      deletePeer({ roomId: ROOM_ID, peerId: PEER_ID }),
    ]);
    // ...the answer that belonged to its offer was discarded, nothing was
    // opened on the closed transport and no fresh one was built here...
    expect(pc.appliedRemote).toEqual([]);
    expect(pc.createdLabels).toEqual([]);
    expect(freshTransports()).toEqual([]);
    expect(thunks(dispatched)).toEqual([]);
    // ...and the room was re-dialed under the redial budget so the roster
    // round rebuilds the edge on a fresh transport of ours.
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([REDIAL()]);
    // The replaced peer is not a user-visible failure: deletePeer dropped its
    // authenticated status with the roster entry and nothing re-added one.
    expect(handshakeStatuses(dispatched)).toEqual([]);
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(true);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an authenticated transport is replaced by a fresh one that answers a new-fingerprint offer, and the initiator opens main on it", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    freshTransports();

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("offer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    // Old transport torn down through the failure path, nothing applied on it.
    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    expect(pc.closes.count).toBe(1);
    expect(pc.appliedRemote).toEqual([]);
    expect(pc.createdLabels).toEqual([]);
    expect(pc.epc.ratchetState).toBeUndefined();

    // A fresh transport was built exactly as the no-transport path builds one.
    const fresh = freshTransports();
    expect(fresh).toHaveLength(1);
    const [next] = fresh;
    expect(peerConnections).toHaveLength(1);
    expect(peerConnections[0] as unknown).toBe(next);
    const nextEpc = peerConnections[0];
    expect(nextEpc.roomId).toBe(ROOM_ID);
    expect(nextEpc.withPeerId).toBe(PEER_ID);
    expect(nextEpc.withPeerPublicKey).toBe(HIGHER_PUBLIC_KEY);
    expect(typeof nextEpc.ondatachannel).toBe("function");
    expect(
      isCurrentRatchetGateLease(ROOM_ID, PEER_ID, nextEpc.ratchetGateLease),
    ).toBe(true);

    // The offer was applied on the fresh transport and answered from it.
    expect(next.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    expect(next.localDescription?.type).toBe("answer");
    // Two opaque RTK thunks: the fresh transport's `connection` frame from its
    // initialization, then the answer send.
    expect(thunks(dispatched)).toHaveLength(2);
    // The peer proved liveness by offering: it is back on the roster before
    // main's handshake reports "authenticating", so no status key ever exists
    // for a peer outside the roster.
    const roster = dispatched.filter(
      (action) =>
        (action as { type?: string }).type === deletePeer.type ||
        (action as { type?: string }).type === setPeer.type,
    );
    expect(roster).toEqual([
      deletePeer({ roomId: ROOM_ID, peerId: PEER_ID }),
      setPeer({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerPublicKey: HIGHER_PUBLIC_KEY,
      }),
    ]);
    // The initiator opened exactly one main on the FRESH transport.
    expect(next.createdLabels).toEqual(["main"]);
    expect(nextEpc.mainChannel?.label).toBe("main");
    // No re-dial: the edge is being rebuilt right here.
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("the responder also replaces an authenticated transport on a new-fingerprint offer but creates no main", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: LOWER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);
    freshTransports();

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("offer", "bb"),
      api,
      LOWER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    expect(pc.closes.count).toBe(1);
    expect(pc.appliedRemote).toEqual([]);
    const fresh = freshTransports();
    expect(fresh).toHaveLength(1);
    const [next] = fresh;
    expect(peerConnections[0] as unknown).toBe(next);
    expect(next.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    expect(next.localDescription?.type).toBe("answer");
    expect(thunks(dispatched)).toHaveLength(2);
    expect(next.createdLabels).toEqual([]);
    expect(peerConnections[0].mainChannel).toBeUndefined();
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a replacement that cannot be built after the stale transport is gone re-dials the room and reports the failure", async () => {
    // The room went inactive between the teardown and the rebuild: the
    // authenticated edge is already down and no transport event will ever
    // fire for it, so the next roster round is the only thing that can
    // rebuild it. The refusal itself still surfaces to the caller exactly as
    // it does on the no-transport path.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    freshTransports();
    const peerConnections: IRTCPeerConnection[] = [pc.epc];
    const disconnects: RTCDisconnectFromPeerParams[] = [];

    await expect(
      webrtcSetDescriptionQuery(
        {
          peerId: PEER_ID,
          peerPublicKey: HIGHER_PUBLIC_KEY,
          roomId: ROOM_ID,
          description: description("offer", "bb"),
          peerConnections,
          iceCandidates: [],
          dataChannels: [],
          disconnectPeer: async (params) => {
            disconnects.push(params);
            await webrtcDisconnectPeerQuery(
              {
                ...params,
                peerConnections,
                dataChannels: [],
                iceCandidates: [],
              },
              api,
              {},
            );
            (
              api.getState() as { rooms: { signalingActive: boolean }[] }
            ).rooms[0].signalingActive = false;
          },
        },
        api,
        {},
      ),
    ).rejects.toThrow("inactive room");

    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    expect(pc.closes.count).toBe(1);
    expect(peerConnections).toEqual([]);
    expect(freshTransports()).toEqual([]);
    expect(pc.appliedRemote).toEqual([]);
    expect(thunks(dispatched)).toEqual([]);
    expect(ofType(dispatched, setPeer.type)).toEqual([]);
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([REDIAL()]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a never-authenticated transport is re-bound in place on a new fingerprint and the initiator opens main on it", async () => {
    // The fresh side: our transport negotiated with the peer's old one (a
    // remote description exists) but nothing was ever proven on it. The
    // peer's fresh transport answers with a new certificate; the browser
    // renegotiates DTLS on this same PC and there is no live SCTP association
    // for a new main to open on prematurely.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connecting",
      remoteFingerprint: "aa",
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    freshTransports();

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
    expect(pc.closes.count).toBe(0);
    expect(peerConnections).toEqual([pc.epc]);
    expect(freshTransports()).toEqual([]);
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
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
    expect(pc.createdLabels).toEqual(["main"]);
    expect(pc.epc.mainChannel?.label).toBe("main");
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([]);

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

    const { disconnects } = await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    expect(pc.main?.closes.count).toBe(0);
    expect(pc.epc.mainChannel).toBe(pc.main?.channel);
    expect(pc.epc.ratchetState).toBeDefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(true);
    expect(handshakeStatuses(dispatched)).toEqual([]);
    expect(pc.createdLabels).toEqual([]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("the responder re-binds its authenticated transport in place on a new-fingerprint answer and does not create main", async () => {
    // The responder woke and ICE-restarted; the initiator answers from a
    // fresh transport that already holds the next main, which opens only once
    // DTLS has re-run against the new certificate. The responder opens nothing
    // on the old association, so the in-place re-bind is safe, and replacing
    // would leave the initiator's fresh transport bound to a closed one.
    const pc = fakePeerConnection({
      peerPublicKey: LOWER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const oldLease = pc.epc.ratchetGateLease;
    const { api, dispatched } = fakeApi(HIGHER_PUBLIC_KEY);

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      LOWER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
    expect(pc.closes.count).toBe(0);
    expect(peerConnections).toEqual([pc.epc]);
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
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
    expect(ofType(dispatched, setConnectingToPeers.type)).toEqual([]);

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

    const { disconnects } = await applyDescription(
      pc.epc,
      description("answer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
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
    expect(thunks(dispatched)).toHaveLength(1);
    expect(pc.createdLabels).toEqual(["main"]);
    expect(pc.epc.mainChannel?.label).toBe("main");

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  // Impolite by peerId ordering: the polite peer has the lexicographically
  // smaller peerId, so a self peerId above PEER_ID would normally ignore any
  // colliding offer.
  const IMPOLITE_SELF_PEER_ID = "00000000-0000-4000-8000-000000000003";

  test("an impolite initiator rolls back a never-answered first offer for the peer's colliding offer", async () => {
    // The awake initiator re-dialed the room, built a fresh PC, created main
    // and offered while the peer was unreachable; the offer was lost. The
    // peer's own offer (an ICE restart on its surviving PC) arrives now.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "new",
      pendingMain: true,
    });
    const { api, dispatched } = fakeApi(
      LOWER_PUBLIC_KEY,
      IMPOLITE_SELF_PEER_ID,
    );

    await applyDescription(
      pc.epc,
      description("offer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.epc.ignoreOffer).toBe(false);
    // Rollback first, then the peer's offer is applied and answered.
    expect(pc.localCalls[0]).toEqual({ type: "rollback" });
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    expect(pc.epc.localDescription?.type).toBe("answer");
    expect(thunks(dispatched)).toHaveLength(1);
    // The pending main survives the rollback; no duplicate is created.
    expect(pc.createdLabels).toEqual([]);
    expect(pc.epc.mainChannel).toBe(pc.main?.channel);
    expect(pc.main?.closes.count).toBe(0);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an impolite peer still ignores a colliding offer on a transport that has a remote description", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api, dispatched } = fakeApi(
      LOWER_PUBLIC_KEY,
      IMPOLITE_SELF_PEER_ID,
    );

    const { disconnects } = await applyDescription(
      pc.epc,
      description("offer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.epc.ignoreOffer).toBe(true);
    expect(pc.localCalls).toEqual([]);
    expect(pc.appliedRemote).toEqual([]);
    expect(dispatched).toEqual([]);
    expect(disconnects).toEqual([]);
    expect(pc.main?.closes.count).toBe(0);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an answer from a retired remote transport is discarded and leaves the first offer pending", async () => {
    // The poisoning shape: our fresh transport holds an unanswered first offer
    // and the peer's answer was produced on the transport we already retired
    // (its queued ICE-restart offer was answered after a thaw). Nothing on
    // this PC could detect it — there is no remote description to compare a
    // fingerprint against — so the retirement set is the only guard.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "new",
      pendingMain: true,
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));
    freshTransports();

    const { peerConnections, disconnects } = await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    // Nothing was applied and nothing was torn down or rebuilt.
    expect(pc.appliedRemote).toEqual([]);
    expect(pc.localCalls).toEqual([]);
    expect(pc.epc.remoteDescription).toBeNull();
    expect(pc.epc.signalingState).toBe("have-local-offer");
    expect(disconnects).toEqual([]);
    expect(peerConnections).toEqual([pc.epc]);
    expect(freshTransports()).toEqual([]);
    expect(pc.closes.count).toBe(0);
    expect(dispatched).toEqual([]);
    // The pending main survives; no duplicate is opened on this transport.
    expect(pc.createdLabels).toEqual([]);
    expect(pc.main?.closes.count).toBe(0);
    // The first offer is still unanswered, so its watchdog stays armed and
    // the edge is re-dialed instead of sitting on a poisoned transport.
    expect(hasUnansweredFirstOffer(pc.epc)).toBe(true);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a fingerprint retired for another edge does not block this one", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connecting",
    });
    const { api } = fakeApi(LOWER_PUBLIC_KEY);
    retireRemoteTransport(ROOM_ID, OTHER_PEER_ID, fingerprintSdp("aa"));

    await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    expect(pc.createdLabels).toEqual(["main"]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an offer from a live remote transport is applied while another of the peer's transports is retired", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "new",
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("cc"));

    const { disconnects } = await applyDescription(
      pc.epc,
      description("offer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    expect(pc.epc.localDescription?.type).toBe("answer");
    expect(thunks(dispatched)).toHaveLength(1);
    expect(pc.createdLabels).toEqual(["main"]);
    // The other transport stays retired: nothing bound to it.
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("cc")),
    ).toBe(true);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an offer from a retired remote transport is answered and un-retires it", async () => {
    // The peer we gave up on is demonstrably negotiating again: it offers on
    // the very transport we retired. An offer is not a reply to anything we
    // hold, so answering it binds this transport to a live remote — and a
    // transport we are bound to is not retired any more, or the answer to our
    // own next ICE restart would be discarded.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "new",
    });
    const { api, dispatched } = fakeApi(LOWER_PUBLIC_KEY);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));

    const { disconnects } = await applyDescription(
      pc.epc,
      description("offer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([]);
    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["offer"]);
    expect(pc.epc.localDescription?.type).toBe("answer");
    expect(thunks(dispatched)).toHaveLength(1);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("an answer applied from a retired-elsewhere transport clears only its own retirement", async () => {
    // The normal path: an answer whose fingerprint was never retired is
    // applied and leaves every other retirement of the edge in place.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "have-local-offer",
      connectionState: "connecting",
    });
    const { api } = fakeApi(LOWER_PUBLIC_KEY);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("cc"));

    await applyDescription(
      pc.epc,
      description("answer", "aa"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(pc.appliedRemote.map((d) => d.type)).toEqual(["answer"]);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("cc")),
    ).toBe(true);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("replacing an authenticated transport retires the certificate it was bound to", async () => {
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api } = fakeApi(LOWER_PUBLIC_KEY);
    freshTransports();

    const { disconnects } = await applyDescription(
      pc.epc,
      description("offer", "bb"),
      api,
      HIGHER_PUBLIC_KEY,
    );

    expect(disconnects).toEqual([{ roomId: ROOM_ID, peerId: PEER_ID }]);
    // The peer's old certificate can never bind another transport of ours...
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
    // ...while the certificate that replaced it stays usable.
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(false);
    expect(freshTransports()).toHaveLength(1);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("tearing an edge down retires the remote transport of every connection it closes", async () => {
    // The grace-timer / ICE-failure teardown that closed the transport whose
    // queued answer poisons the fresh one later.
    const pc = fakePeerConnection({
      peerPublicKey: HIGHER_PUBLIC_KEY,
      signalingState: "stable",
      connectionState: "connected",
      remoteFingerprint: "aa",
      authenticated: true,
    });
    const { api } = fakeApi(LOWER_PUBLIC_KEY);
    const peerConnections: IRTCPeerConnection[] = [pc.epc];

    webrtcDisconnectPeerQuery(
      {
        peerId: PEER_ID,
        roomId: ROOM_ID,
        peerConnections,
        dataChannels: [],
        iceCandidates: [],
      },
      api,
      {},
    );

    expect(peerConnections).toEqual([]);
    expect(pc.closes.count).toBe(1);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(false);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});
