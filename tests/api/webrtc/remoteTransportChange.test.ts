import { beforeAll, describe, expect, test } from "bun:test";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCIceCandidate,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
} from "../../../src/api/webrtc/interfaces";
import type { RebindDeadlineScheduler } from "../../../src/api/webrtc/rebindDeadline";

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
type RebindDeadline = typeof import("../../../src/api/webrtc/rebindDeadline");
type DisconnectFromPeerQuery =
  typeof import("../../../src/api/webrtc/disconnectFromPeerQuery");
type RatchetGate = typeof import("../../../src/handlers/ratchetGate");
type HandleHandshake = typeof import("../../../src/handlers/handleHandshake");
type RoomSlice = typeof import("../../../src/reducers/roomSlice");

let detectRemoteTransportChange: RemoteTransportChange["detectRemoteTransportChange"];
let resetEdgeAuthenticationForNewRemoteTransport: RemoteTransportChange["resetEdgeAuthenticationForNewRemoteTransport"];
let isEdgeAuthenticatedOnTransport: RemoteTransportChange["isEdgeAuthenticatedOnTransport"];
let decideRemoteTransportChangeResponse: RemoteTransportChange["decideRemoteTransportChangeResponse"];
let clearRebindAuthenticationDeadline: RebindDeadline["clearRebindAuthenticationDeadline"];
let webrtcDisconnectPeerQuery: DisconnectFromPeerQuery["default"];
let claimRatchetGate: RatchetGate["claimRatchetGate"];
let getRatchetGate: RatchetGate["getRatchetGate"];
let isCurrentRatchetGateLease: RatchetGate["isCurrentRatchetGateLease"];
let openRatchetGate: RatchetGate["openRatchetGate"];
let resetRatchetGate: RatchetGate["resetRatchetGate"];
let setHandshakeChannel: HandleHandshake["setHandshakeChannel"];
let clearHandshakeChannel: HandleHandshake["clearHandshakeChannel"];
let setPeerHandshakeStatus: RoomSlice["setPeerHandshakeStatus"];
let setConnectingToPeers: RoomSlice["setConnectingToPeers"];
let REBIND_AUTHENTICATION_DEADLINE_MS: number;

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the WebRTC query modules load.
  await import("../../../src/store");
  ({
    detectRemoteTransportChange,
    resetEdgeAuthenticationForNewRemoteTransport,
    isEdgeAuthenticatedOnTransport,
    decideRemoteTransportChangeResponse,
  } = await import("../../../src/api/webrtc/remoteTransportChange"));
  ({ clearRebindAuthenticationDeadline } =
    await import("../../../src/api/webrtc/rebindDeadline"));
  ({ default: webrtcDisconnectPeerQuery } =
    await import("../../../src/api/webrtc/disconnectFromPeerQuery"));
  ({
    claimRatchetGate,
    getRatchetGate,
    isCurrentRatchetGateLease,
    openRatchetGate,
    resetRatchetGate,
  } = await import("../../../src/handlers/ratchetGate"));
  ({ setHandshakeChannel, clearHandshakeChannel } =
    await import("../../../src/handlers/handleHandshake"));
  ({ setPeerHandshakeStatus, setConnectingToPeers } =
    await import("../../../src/reducers/roomSlice"));
  ({ REBIND_AUTHENTICATION_DEADLINE_MS } =
    await import("../../../src/utils/constants"));
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
const OTHER_PEER_ID = "00000000-0000-4000-8000-00000000000e";
const PEER_PUBLIC_KEY = "cd".repeat(32);

const fakeApi = (): {
  api: Pick<BaseQueryApi, "dispatch" | "getState">;
  dispatched: unknown[];
} => {
  const dispatched: unknown[] = [];
  const api = {
    dispatch: (action: unknown) => {
      dispatched.push(action);
      return action;
    },
    // A connected, verified socket: requestPeersAfterEdgeTeardown reads it
    // when a missed re-bind deadline rebuilds the edge.
    getState: () => ({
      signalingServer: { isConnected: true, isVerified: true },
      rooms: [],
    }),
  } as unknown as Pick<BaseQueryApi, "dispatch" | "getState">;
  return { api, dispatched };
};

/** A teardown transport that records what the deadline asked it to tear down. */
const fakeDisconnectPeer = (): {
  disconnectPeer: (params: RTCDisconnectFromPeerParams) => Promise<void>;
  disconnects: RTCDisconnectFromPeerParams[];
} => {
  const disconnects: RTCDisconnectFromPeerParams[] = [];
  return {
    disconnectPeer: (params) => {
      disconnects.push(params);
      return Promise.resolve();
    },
    disconnects,
  };
};

/**
 * A scheduler the test drives by hand: nothing waits in real time, and every
 * arm/clear the deadline performs is observable.
 */
const fakeScheduler = (): {
  schedule: RebindDeadlineScheduler;
  arms: () => number;
  clears: () => number;
  delay: () => number | undefined;
  pending: () => boolean;
  fire: () => void;
} => {
  let arms = 0;
  let clears = 0;
  let delay: number | undefined;
  let callback: (() => void) | undefined;
  const schedule: RebindDeadlineScheduler = {
    setTimeout: (fn, delayMs) => {
      arms += 1;
      delay = delayMs;
      callback = fn;
      return arms as unknown as ReturnType<typeof setTimeout>;
    },
    clearTimeout: () => {
      clears += 1;
      callback = undefined;
    },
  };
  return {
    schedule,
    arms: () => arms,
    clears: () => clears,
    delay: () => delay,
    pending: () => callback !== undefined,
    fire: () => {
      const fn = callback;
      callback = undefined;
      fn?.();
    },
  };
};

/** Let the deadline's teardown-then-re-dial promise chain run to completion. */
const settle = async (): Promise<void> => {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
};

/**
 * The re-bind tests below are not about the deadline: they arm nothing real,
 * so no stray timer of theirs can fire into a later test's registries.
 */
const inertSchedule: RebindDeadlineScheduler = {
  setTimeout: () => 0 as unknown as ReturnType<typeof setTimeout>,
  clearTimeout: () => undefined,
};

interface ChannelFake {
  channel: IRTCDataChannel;
  closes: () => number;
  releases: () => number;
}

/**
 * The slice of an IRTCDataChannel the retirement sweep touches: a readyState
 * that follows close(), the protocol-accounting hook, and every handler
 * property it is expected to detach.
 */
const fakeChannel = (
  label: string,
  readyState: RTCDataChannelState,
  {
    peerId = PEER_ID,
    roomId = ROOM_ID,
  }: { peerId?: string; roomId?: string } = {},
): ChannelFake => {
  let state = readyState;
  let closes = 0;
  let releases = 0;
  const channel = {
    label,
    withPeerId: peerId,
    roomIds: [roomId],
    get readyState() {
      return state;
    },
    close: () => {
      closes += 1;
      state = "closed";
    },
    releaseProtocolResources: () => {
      releases += 1;
    },
    onopen: () => undefined,
    onclose: () => undefined,
    onerror: () => undefined,
    onclosing: () => undefined,
    onmessage: () => undefined,
    onbufferedamountlow: () => undefined,
  } as unknown as IRTCDataChannel;
  return { channel, closes: () => closes, releases: () => releases };
};

describe("resetEdgeAuthenticationForNewRemoteTransport", () => {
  test("wipes the authenticated edge state and reopens the gate for a fresh handshake", async () => {
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    expect(claimRatchetGate(ROOM_ID, PEER_ID)).toBe(oldLease);
    const oldGate = getRatchetGate(ROOM_ID, PEER_ID);
    setHandshakeChannel(ROOM_ID, PEER_ID, { send: () => undefined });

    const mainFake = fakeChannel("main", "open");
    const main = mainFake.channel;
    const messageFake = fakeChannel("message", "open");
    const messageChannel = messageFake.channel;
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
      coverRuntime: {
        destroy: () => {
          coverDestroyed += 1;
        },
      },
    } as unknown as IRTCPeerConnection;
    const dataChannels = [main, messageChannel];
    const { api, dispatched } = fakeApi();

    resetEdgeAuthenticationForNewRemoteTransport({
      epc,
      roomId: ROOM_ID,
      peerId: PEER_ID,
      api,
      dataChannels,
      disconnectPeer: () => Promise.resolve(),
      schedule: inertSchedule,
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

    // Main channel closed and detached, and the retired generation's
    // per-message channels went with it.
    expect(mainFake.closes()).toBe(1);
    expect(epc.mainChannel).toBeUndefined();
    expect(messageFake.closes()).toBe(1);
    expect(epc.messageChannels?.has(messageChannel)).toBe(false);
    expect(dataChannels).toEqual([]);

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
    expect(coverDestroyed).toBe(1);
    expect(epc.coverRuntime).toBeUndefined();

    // The app sees the edge as re-authenticating, never as still authenticated.
    expect(dispatched).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerPublicKey: PEER_PUBLIC_KEY,
        status: "authenticating",
      }),
    ]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("a bare edge with no main or crypto state still gets a fresh gate and status", () => {
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    const closedMainFake = fakeChannel("main", "closed");
    const closedMain = closedMainFake.channel;
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
        dataChannels: [],
        disconnectPeer: () => Promise.resolve(),
        schedule: inertSchedule,
        reason: new Error("Remote DTLS certificate changed"),
      }),
    ).not.toThrow();

    expect(closedMainFake.closes()).toBe(0);
    expect(epc.mainChannel).toBeUndefined();
    expect(isCurrentRatchetGateLease(ROOM_ID, PEER_ID, oldLease)).toBe(false);
    expect(
      isCurrentRatchetGateLease(ROOM_ID, PEER_ID, epc.ratchetGateLease),
    ).toBe(true);
    expect(dispatched).toEqual([
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerPublicKey: PEER_PUBLIC_KEY,
        status: "authenticating",
      }),
    ]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("releases every channel bound to the generation it retires", () => {
    // A per-message channel belongs to the ratchet generation that opened it.
    // One that survives the re-bind can only ever be rejected as unauthenticated
    // application data, and that rejection closes `main` with it — which tears
    // the whole edge down. Retire the generation's channels with its keys.
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    const main = fakeChannel("main", "open");
    const transfer = fakeChannel("file~aa", "open");
    // Registered in the shared array by its onopen but no longer in
    // messageChannels (its own accounting already released it).
    const registered = fakeChannel("file~bb", "open");
    const alreadyClosed = fakeChannel("file~cc", "closed");
    const otherEdge = fakeChannel("file~dd", "open", { peerId: OTHER_PEER_ID });
    const dataChannels = [
      main.channel,
      transfer.channel,
      registered.channel,
      alreadyClosed.channel,
      otherEdge.channel,
    ];
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: oldLease,
      mainChannel: main.channel,
      messageChannels: new Set([transfer.channel, alreadyClosed.channel]),
    } as unknown as IRTCPeerConnection;
    const { api } = fakeApi();

    resetEdgeAuthenticationForNewRemoteTransport({
      epc,
      roomId: ROOM_ID,
      peerId: PEER_ID,
      api,
      dataChannels,
      disconnectPeer: () => Promise.resolve(),
      schedule: inertSchedule,
      reason: new Error("Remote DTLS certificate changed"),
    });

    // Every channel of this edge is released, detached and closed exactly once.
    for (const retired of [transfer, registered, alreadyClosed]) {
      expect(retired.releases()).toBe(1);
      expect(retired.channel.onopen).toBeNull();
      expect(retired.channel.onclose).toBeNull();
      expect(retired.channel.onerror).toBeNull();
      expect(retired.channel.onmessage).toBeNull();
      expect(retired.channel.onbufferedamountlow).toBeNull();
    }
    expect(transfer.closes()).toBe(1);
    expect(registered.closes()).toBe(1);
    // An already-closed channel is released and unregistered, never re-closed.
    expect(alreadyClosed.closes()).toBe(0);

    // Main keeps the treatment it always had — closed once, detached from the
    // connection, its own onclose left to observe the stale lease and return.
    expect(main.closes()).toBe(1);
    expect(epc.mainChannel).toBeUndefined();
    expect(main.channel.onclose).not.toBeNull();

    // Both registries hold nothing of this edge's retired generation, and the
    // peer's other edge is untouched.
    expect(epc.messageChannels?.size ?? 0).toBe(0);
    expect(dataChannels).toEqual([otherEdge.channel]);
    expect(otherEdge.closes()).toBe(0);
    expect(otherEdge.releases()).toBe(0);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("leaves a cover lane to teardownCoverEdge and its own close listener", () => {
    // Cover lanes are NOT the sweep's business: teardownCoverEdge closes each
    // one and the close listener registerCoverChannelUntilClose installed
    // unregisters it from both registries. Releasing them here as well would
    // skip that owner's own close bookkeeping.
    const oldLease = resetRatchetGate(ROOM_ID, PEER_ID);
    const lane = fakeChannel("cover~aa", "open");
    const dataChannels = [lane.channel];
    let coverDestroyed = 0;
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: oldLease,
      coverChannels: new Set([lane.channel]),
      coverRuntime: {
        destroy: () => {
          coverDestroyed += 1;
        },
      },
    } as unknown as IRTCPeerConnection;
    const { api } = fakeApi();

    resetEdgeAuthenticationForNewRemoteTransport({
      epc,
      roomId: ROOM_ID,
      peerId: PEER_ID,
      api,
      dataChannels,
      disconnectPeer: () => Promise.resolve(),
      schedule: inertSchedule,
      reason: new Error("Remote DTLS certificate changed"),
    });

    expect(coverDestroyed).toBe(1);
    expect(epc.coverChannels).toBeUndefined();
    // Closed by teardownCoverEdge, exactly once, and otherwise untouched: its
    // own close listener owns the unregistration.
    expect(lane.closes()).toBe(1);
    expect(lane.releases()).toBe(0);
    expect(lane.channel.onclose).not.toBeNull();
    expect(dataChannels).toEqual([lane.channel]);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });

  test("counts every in-place re-bind of this transport", () => {
    const epc = {
      roomId: ROOM_ID,
      withPeerId: PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: resetRatchetGate(ROOM_ID, PEER_ID),
      remoteTransportRebinds: 0,
    } as unknown as IRTCPeerConnection;
    const { api } = fakeApi();
    const reset = (): void => {
      resetEdgeAuthenticationForNewRemoteTransport({
        epc,
        roomId: ROOM_ID,
        peerId: PEER_ID,
        api,
        dataChannels: [],
        disconnectPeer: () => Promise.resolve(),
        schedule: inertSchedule,
        reason: new Error("Remote DTLS certificate changed"),
      });
    };

    reset();
    expect(epc.remoteTransportRebinds).toBe(1);
    reset();
    expect(epc.remoteTransportRebinds).toBe(2);

    resetRatchetGate(ROOM_ID, PEER_ID);
  });
});

const AUTH_ROOM_ID = "00000000-0000-4000-8000-00000000000c";
const AUTH_PEER_ID = "00000000-0000-4000-8000-00000000000d";

const ratchetState = (): NonNullable<IRTCPeerConnection["ratchetState"]> => ({
  rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
  rootKey: new Uint8Array(32),
  sendingChainKey: null,
  receivingChainKey: null,
  dhSelfPub: new Uint8Array(32),
  dhSelfSec: new Uint8Array(32),
  dhRemotePub: null,
  Ns: 0,
  Nr: 0,
  PN: 0,
  skipped: new Map<string, Uint8Array>(),
});

const mainChannel = (readyState: RTCDataChannelState): IRTCDataChannel =>
  ({ label: "main", readyState }) as unknown as IRTCDataChannel;

describe("isEdgeAuthenticatedOnTransport", () => {
  test("a fresh transport with a pending gate, no ratchet and no main is not authenticated", () => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    const epc = {
      ratchetGateLease: lease,
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(false);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });

  test("a still-connecting main does not make the transport authenticated", () => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    const epc = {
      ratchetGateLease: lease,
      mainChannel: mainChannel("connecting"),
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(false);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });

  test("a live ratchet means the edge was authenticated on this transport", () => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    const epc = {
      ratchetGateLease: lease,
      ratchetState: ratchetState(),
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(true);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });

  test("an open gate held by this transport's lease means authenticated", () => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    expect(openRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID, lease)).toBe(true);
    const epc = {
      ratchetGateLease: lease,
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(true);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });

  test("an open gate under another transport's lease does not authenticate this one", () => {
    const oldLease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    expect(openRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID, oldLease)).toBe(true);
    const epc = {
      ratchetGateLease: { token: Symbol("stale") },
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(false);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });

  test("an open main (handshake in flight over a live SCTP association) means authenticated", () => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    const epc = {
      ratchetGateLease: lease,
      mainChannel: mainChannel("open"),
    } as unknown as IRTCPeerConnection;
    expect(
      isEdgeAuthenticatedOnTransport(epc, AUTH_ROOM_ID, AUTH_PEER_ID),
    ).toBe(true);
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
  });
});

describe("decideRemoteTransportChangeResponse", () => {
  const decide = (
    authenticated: boolean,
    descriptionType: RTCSdpType,
    isInitiator: boolean,
    remoteTransportRebinds = 0,
  ) => {
    const lease = resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    const epc = {
      ratchetGateLease: lease,
      ratchetState: authenticated ? ratchetState() : undefined,
      remoteTransportRebinds,
    } as unknown as IRTCPeerConnection;
    const response = decideRemoteTransportChangeResponse({
      epc,
      roomId: AUTH_ROOM_ID,
      peerId: AUTH_PEER_ID,
      descriptionType,
      isInitiator,
    });
    resetRatchetGate(AUTH_ROOM_ID, AUTH_PEER_ID);
    return response;
  };

  test("a never-authenticated transport is re-bound in place for either role and either description", () => {
    expect(decide(false, "offer", true)).toBe("reset-in-place");
    expect(decide(false, "answer", true)).toBe("reset-in-place");
    expect(decide(false, "offer", false)).toBe("reset-in-place");
    expect(decide(false, "answer", false)).toBe("reset-in-place");
  });

  test("an authenticated transport is replaced when the peer's fresh transport offers, for either role", () => {
    expect(decide(true, "offer", true)).toBe("replace");
    expect(decide(true, "offer", false)).toBe("replace");
  });

  test("the identity initiator replaces its authenticated transport on an answer from a fresh peer transport", () => {
    expect(decide(true, "answer", true)).toBe("replace");
  });

  test("the responder keeps its authenticated transport on such an answer: the peer's fresh main opens over the re-run DTLS", () => {
    expect(decide(true, "answer", false)).toBe("reset-in-place");
  });

  test("a transport already re-bound once, still unauthenticated, is replaced whatever the role or description", () => {
    // At most ONE in-place re-bind per unauthenticated transport. Without this
    // bound a peer that keeps minting certificates loops forever: our remote
    // fingerprint changes every round while our local one never does, because
    // a PC whose ICE stays connected never fails and is never replaced, so we
    // keep answering with a certificate the peer has already retired.
    expect(decide(false, "offer", true, 1)).toBe("replace");
    expect(decide(false, "answer", true, 1)).toBe("replace");
    expect(decide(false, "offer", false, 1)).toBe("replace");
    // Even the ratified responder+answer case, which is what re-bound it.
    expect(decide(false, "answer", false, 1)).toBe("replace");
  });

  test("a transport that authenticated after its re-bind is judged on its role again", () => {
    // The handshake success path clears the counter, so a long-lived edge that
    // legitimately re-binds once per reconnect is never penalised.
    expect(decide(true, "answer", false, 0)).toBe("reset-in-place");
    // A live ratchet proves the re-bind converged even if the counter stands.
    expect(decide(true, "answer", false, 1)).toBe("reset-in-place");
    expect(decide(true, "offer", false, 1)).toBe("replace");
  });
});

const DEADLINE_ROOM_ID = "00000000-0000-4000-8000-00000000000f";
const DEADLINE_PEER_ID = "00000000-0000-4000-8000-000000000010";

interface ArmedRebind {
  epc: IRTCPeerConnection;
  scheduler: ReturnType<typeof fakeScheduler>;
  disconnects: RTCDisconnectFromPeerParams[];
  dispatched: unknown[];
}

/**
 * One in-place re-bind of a bare transport, with its deadline armed on a
 * hand-driven scheduler.
 */
const armRebind = (): ArmedRebind => {
  const scheduler = fakeScheduler();
  const { disconnectPeer, disconnects } = fakeDisconnectPeer();
  const { api, dispatched } = fakeApi();
  const epc = {
    roomId: DEADLINE_ROOM_ID,
    withPeerId: DEADLINE_PEER_ID,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    connectionState: "connected",
    ratchetGateLease: resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID),
    remoteTransportRebinds: 0,
    close: () => undefined,
  } as unknown as IRTCPeerConnection;

  resetEdgeAuthenticationForNewRemoteTransport({
    epc,
    roomId: DEADLINE_ROOM_ID,
    peerId: DEADLINE_PEER_ID,
    api,
    dataChannels: [],
    disconnectPeer,
    schedule: scheduler.schedule,
    reason: new Error("Remote DTLS certificate changed"),
  });

  return { epc, scheduler, disconnects, dispatched };
};

const REDIAL = () =>
  setConnectingToPeers({
    roomId: DEADLINE_ROOM_ID,
    connectingToPeers: true,
    reason: "redial",
    peerId: DEADLINE_PEER_ID,
  });

const redials = (dispatched: unknown[]): unknown[] =>
  dispatched.filter(
    (action) =>
      (action as { type?: string }).type === setConnectingToPeers.type,
  );

describe("the in-place re-bind authentication deadline", () => {
  test("every in-place re-bind arms one, shorter than the handshake step timeout", () => {
    const { epc, scheduler } = armRebind();

    expect(scheduler.arms()).toBe(1);
    expect(scheduler.clears()).toBe(0);
    expect(scheduler.delay()).toBe(REBIND_AUTHENTICATION_DEADLINE_MS);
    expect(epc.rebindDeadline).not.toBeUndefined();
    // Shorter than handleHandshake's HANDSHAKE_STEP_TIMEOUT_MS (30 s): the
    // edge is rebuilt rather than waited out. Longer than a healthy re-bind,
    // which the process-freeze harness measures at about 2 s.
    expect(REBIND_AUTHENTICATION_DEADLINE_MS).toBeLessThan(30_000);
    expect(REBIND_AUTHENTICATION_DEADLINE_MS).toBeGreaterThan(2_000);

    clearRebindAuthenticationDeadline(epc);
    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("a re-bind that authenticates in time clears the deadline and tears nothing down", async () => {
    const { epc, scheduler, disconnects, dispatched } = armRebind();

    // The handshake succeeded on this transport: the same place that refunds
    // the re-bind budget releases the deadline.
    epc.ratchetState = ratchetState();
    expect(
      openRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID, epc.ratchetGateLease),
    ).toBe(true);
    clearRebindAuthenticationDeadline(epc);

    expect(scheduler.clears()).toBe(1);
    expect(scheduler.pending()).toBe(false);
    expect(epc.rebindDeadline).toBeUndefined();

    // Idempotent: a second clear (teardown after a success) does nothing.
    clearRebindAuthenticationDeadline(epc);
    expect(scheduler.clears()).toBe(1);

    scheduler.fire();
    await settle();
    expect(disconnects).toEqual([]);
    expect(redials(dispatched)).toEqual([]);

    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("a re-bind that never authenticates rebuilds the edge exactly once", async () => {
    const { epc, disconnects, dispatched, scheduler } = armRebind();

    scheduler.fire();
    await settle();

    expect(disconnects).toEqual([
      { roomId: DEADLINE_ROOM_ID, peerId: DEADLINE_PEER_ID },
    ]);
    // The room re-introduces the pair so a fresh transport is built.
    expect(redials(dispatched)).toEqual([REDIAL()]);
    expect(epc.rebindDeadline).toBeUndefined();

    // Nothing re-arms behind it: the deadline fires at most once.
    scheduler.fire();
    await settle();
    expect(disconnects.length).toBe(1);
    expect(redials(dispatched).length).toBe(1);

    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("a deadline whose transport was replaced meanwhile does nothing", async () => {
    const { disconnects, dispatched, scheduler } = armRebind();

    // A replacement transport for this edge claims a fresh gate lease, so the
    // connection this deadline belongs to is no longer the current one.
    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);

    scheduler.fire();
    await settle();

    expect(disconnects).toEqual([]);
    expect(redials(dispatched)).toEqual([]);

    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("a deadline that fires on an edge which authenticated meanwhile does nothing", async () => {
    const { epc, disconnects, dispatched, scheduler } = armRebind();

    epc.ratchetState = ratchetState();

    scheduler.fire();
    await settle();

    expect(disconnects).toEqual([]);
    expect(redials(dispatched)).toEqual([]);

    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("a later re-bind of the same transport clears the old deadline and arms a new one", () => {
    const scheduler = fakeScheduler();
    const { disconnectPeer } = fakeDisconnectPeer();
    const { api } = fakeApi();
    const epc = {
      roomId: DEADLINE_ROOM_ID,
      withPeerId: DEADLINE_PEER_ID,
      withPeerPublicKey: PEER_PUBLIC_KEY,
      ratchetGateLease: resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID),
      remoteTransportRebinds: 0,
    } as unknown as IRTCPeerConnection;
    const reset = (): void => {
      resetEdgeAuthenticationForNewRemoteTransport({
        epc,
        roomId: DEADLINE_ROOM_ID,
        peerId: DEADLINE_PEER_ID,
        api,
        dataChannels: [],
        disconnectPeer,
        schedule: scheduler.schedule,
        reason: new Error("Remote DTLS certificate changed"),
      });
    };

    reset();
    reset();

    expect(scheduler.arms()).toBe(2);
    expect(scheduler.clears()).toBe(1);
    expect(scheduler.pending()).toBe(true);

    clearRebindAuthenticationDeadline(epc);
    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });

  test("the peer teardown path clears a pending deadline", async () => {
    const { epc, scheduler, disconnects, dispatched } = armRebind();
    const peerConnections = [epc];
    const dataChannels: IRTCDataChannel[] = [];
    const iceCandidates: IRTCIceCandidate[] = [];
    const { api } = fakeApi();

    await webrtcDisconnectPeerQuery(
      {
        peerId: DEADLINE_PEER_ID,
        roomId: DEADLINE_ROOM_ID,
        peerConnections,
        dataChannels,
        iceCandidates,
      },
      api as BaseQueryApi,
      {},
    );

    expect(scheduler.clears()).toBe(1);
    expect(scheduler.pending()).toBe(false);
    expect(epc.rebindDeadline).toBeUndefined();

    // A torn-down connection never fires it.
    scheduler.fire();
    await settle();
    expect(disconnects).toEqual([]);
    expect(redials(dispatched)).toEqual([]);

    resetRatchetGate(DEADLINE_ROOM_ID, DEADLINE_PEER_ID);
  });
});
