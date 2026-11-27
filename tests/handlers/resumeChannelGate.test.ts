import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import {
  claimRatchetGate,
  isRatchetGateOpen,
  isRatchetGatePending,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";
import {
  admitPreAuthenticatedFrame,
  waitForRatchetGateSettled,
} from "../../src/handlers/ratchetGateWait";
import { hasImmediateRemoteCancel } from "../../src/handlers/immediateDisposition";
import {
  markChannelClosedLocally,
  wasChannelClosedLocally,
} from "../../src/api/webrtc/localChannelClose";
import { MAX_PARKED_PRE_AUTH_BYTES } from "../../src/utils/constants";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { RatchetGateLease } from "../../src/handlers/ratchetGate";

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation: a STATIC import of it from a Bun test
// throws `ReferenceError: localStorage is not defined` before any test runs.
// Shim storage, then enter the store through its application root, exactly as
// tests/handlers/handleSendMessage.test.ts does.
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

let isAuthenticatedPeerCancel: (typeof import("../../src/handlers/handleSendMessage"))["isAuthenticatedPeerCancel"];
let isResumableAuthenticatedTransport: (typeof import("../../src/handlers/handleSendMessage"))["isResumableAuthenticatedTransport"];
let closeTransferChannel: (typeof import("../../src/handlers/handleSendMessage"))["closeTransferChannel"];
let handleOpenChannel: (typeof import("../../src/handlers/handleOpenChannel"))["handleOpenChannel"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];
let DEFAULT_ROOM_POLICY_V1: (typeof import("../../src/roomPolicy"))["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  await import("../../src/store");
  ({
    closeTransferChannel,
    isAuthenticatedPeerCancel,
    isResumableAuthenticatedTransport,
  } = await import("../../src/handlers/handleSendMessage"));
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000a1";
const PEER_ID = "00000000-0000-4000-8000-0000000000a2";

const fakeChannel = (): IRTCDataChannel => {
  let readyState: RTCDataChannelState = "open";
  return {
    label: "m~r",
    withPeerId: PEER_ID,
    roomIds: [ROOM_ID],
    get readyState() {
      return readyState;
    },
    close() {
      readyState = "closed";
    },
  } as unknown as IRTCDataChannel;
};

const fakeEpc = (lease: RatchetGateLease): IRTCPeerConnection =>
  ({
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    connectionState: "connected",
    ratchetGateLease: lease,
  }) as unknown as IRTCPeerConnection;

afterEach(() => {
  resetRatchetGate(ROOM_ID, PEER_ID);
});

describe("a pending gate is not a rejected gate", () => {
  test("a fresh lease is pending, not open", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    expect(isRatchetGateOpen(ROOM_ID, PEER_ID, lease)).toBe(false);
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, lease)).toBe(true);
  });

  test("an opened gate is no longer pending", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, lease)).toBe(false);
  });

  test("a rejected gate is not pending", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    rejectRatchetGate(ROOM_ID, PEER_ID, new Error("nope"), lease);
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, lease)).toBe(false);
  });

  test("a stale lease is never pending", () => {
    const stale = claimRatchetGate(ROOM_ID, PEER_ID);
    resetRatchetGate(ROOM_ID, PEER_ID, new Error("replaced"));
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, stale)).toBe(false);
  });

  test("no lease at all is never pending", () => {
    expect(isRatchetGatePending(ROOM_ID, PEER_ID, undefined)).toBe(false);
  });
});

describe("bounded park for a frame that beat its own gate", () => {
  test("resolves true when the gate opens inside the budget", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const settled = waitForRatchetGateSettled(ROOM_ID, PEER_ID, 2_000);
    setTimeout(() => openRatchetGate(ROOM_ID, PEER_ID, lease), 20);
    expect(await settled).toBe(true);
  });

  test("resolves false when the gate is rejected", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const settled = waitForRatchetGateSettled(ROOM_ID, PEER_ID, 2_000);
    setTimeout(
      () => rejectRatchetGate(ROOM_ID, PEER_ID, new Error("nope"), lease),
      20,
    );
    expect(await settled).toBe(false);
  });

  test("resolves false on timeout without throwing", async () => {
    claimRatchetGate(ROOM_ID, PEER_ID);
    expect(await waitForRatchetGateSettled(ROOM_ID, PEER_ID, 30)).toBe(false);
  });
});

describe("the pre-authentication frame guard admits only what it should", () => {
  test("an already-open gate admits with no park at all", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    // Zero park budget: the live, already-authenticated path must not depend
    // on the park in any way, so an ordinary frame's handling is unchanged.
    expect(
      await admitPreAuthenticatedFrame(ROOM_ID, PEER_ID, lease, 0, 0),
    ).toBe("admit");
  });

  test("a rejected gate closes immediately instead of burning the budget", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    rejectRatchetGate(ROOM_ID, PEER_ID, new Error("dead"), lease);
    const started = Date.now();
    expect(
      await admitPreAuthenticatedFrame(ROOM_ID, PEER_ID, lease, 60_000, 0),
    ).toBe("close");
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  test("a stale lease closes immediately instead of parking", async () => {
    const stale = claimRatchetGate(ROOM_ID, PEER_ID);
    resetRatchetGate(ROOM_ID, PEER_ID, new Error("replaced"));
    const started = Date.now();
    expect(
      await admitPreAuthenticatedFrame(ROOM_ID, PEER_ID, stale, 60_000, 0),
    ).toBe("close");
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  test("the park is bounded in bytes, not only in time — and the bound DROPS", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    // A pending gate would otherwise park every arriving frame for the whole
    // budget: an unauthenticated peer must not be able to pin arbitrary memory
    // on this channel for ten seconds. The bound must not CLOSE, though — a
    // close on a healthy authenticating edge is read by the peer as a cancel
    // and deletes its partial file, which is C7 by another route (C-1).
    expect(
      await admitPreAuthenticatedFrame(
        ROOM_ID,
        PEER_ID,
        lease,
        60_000,
        MAX_PARKED_PRE_AUTH_BYTES + 1,
      ),
    ).toBe("drop");
  });

  test("a gate that never settles closes when the park runs out", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    expect(
      await admitPreAuthenticatedFrame(ROOM_ID, PEER_ID, lease, 30, 0),
    ).toBe("close");
  });
});

describe("a channel this side closed is never a peer cancel", () => {
  test("a bare close on a current authenticated edge remains an interruption", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const epc = fakeEpc(lease);
    const channel = fakeChannel();
    expect(
      isAuthenticatedPeerCancel(epc, [epc], ROOM_ID, PEER_ID, lease, channel),
    ).toBe(false);
  });

  // C7: this is the whole bug. The sender's own pre-authentication guard closed
  // the channel; every other check then legitimately passed and the sender
  // reported a cancel the peer never sent, deleting both sides' data.
  test("a locally-closed channel is not a peer cancel", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const epc = fakeEpc(lease);
    const channel = fakeChannel();
    markChannelClosedLocally(channel);
    expect(wasChannelClosedLocally(channel)).toBe(true);
    expect(
      isAuthenticatedPeerCancel(epc, [epc], ROOM_ID, PEER_ID, lease, channel),
    ).toBe(false);
  });

  test("an absent channel does not turn a non-cancel into a cancel", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const epc = fakeEpc(lease);
    expect(
      isAuthenticatedPeerCancel(epc, [epc], ROOM_ID, PEER_ID, lease, undefined),
    ).toBe(false);
  });

  // sendWithReconcile re-reads the very channel it retired on its next loop
  // iteration (the resumable-rebind-failure path closes it and `continue`s),
  // so the production close routine must record itself.
  test("the transfer's own terminal close is not later read as a peer cancel", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const epc = fakeEpc(lease);
    const channel = fakeChannel();

    closeTransferChannel(channel);

    expect(channel.readyState).toBe("closed");
    expect(
      isAuthenticatedPeerCancel(epc, [epc], ROOM_ID, PEER_ID, lease, channel),
    ).toBe(false);
  });

  test("an unmarked channel is unaffected by the marker helper", () => {
    expect(wasChannelClosedLocally(fakeChannel())).toBe(false);
    expect(wasChannelClosedLocally(undefined)).toBe(false);
  });
});

describe("a resume opens its channel only on an authenticated transport", () => {
  test("a DTLS-connected transport whose handshake has not finished is not resumable", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    // Exactly the state resumeChannel used to accept: connected, registered,
    // correct room and peer — and no authenticated ratchet behind it, so the
    // per-message channel it opens invites the peer's replay burst ahead of
    // this side's gate.
    expect(
      isResumableAuthenticatedTransport(fakeEpc(lease), ROOM_ID, PEER_ID),
    ).toBe(false);
  });

  test("the same transport becomes resumable once its gate opens", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const epc = fakeEpc(lease);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    expect(isResumableAuthenticatedTransport(epc, ROOM_ID, PEER_ID)).toBe(true);
  });

  test("an authenticated transport for a different peer is not resumable", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const other = {
      ...fakeEpc(lease),
      withPeerId: "00000000-0000-4000-8000-0000000000a3",
    } as unknown as IRTCPeerConnection;
    expect(isResumableAuthenticatedTransport(other, ROOM_ID, PEER_ID)).toBe(
      false,
    );
  });

  test("a disconnected transport is not resumable however open its gate", () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    const dead = {
      ...fakeEpc(lease),
      connectionState: "failed",
    } as unknown as IRTCPeerConnection;
    expect(isResumableAuthenticatedTransport(dead, ROOM_ID, PEER_ID)).toBe(
      false,
    );
  });
});

// The lexicographically lower canonical identity is the one that opens `main`;
// a per-message channel is opened by whichever side sends, and arrives at the
// other side as an RTCDataChannel object.
const SELF_PUBLIC_KEY = `${"00".repeat(31)}01`;
const PEER_PUBLIC_KEY = "ff".repeat(32);
const MERKLE_ROOT_HEX = "ab".repeat(64);

interface FakeMessageChannel {
  channel: IRTCDataChannel;
  closes: { count: number };
}

const fakeMessageChannel = (label: string): FakeMessageChannel => {
  const closes = { count: 0 };
  let state: RTCDataChannelState = "open";
  const channel = {
    label,
    binaryType: "blob",
    get readyState() {
      return state;
    },
    send: () => undefined,
    close: () => {
      closes.count += 1;
      state = "closed";
    },
  } as unknown as IRTCDataChannel;
  return { channel, closes };
};

const fakeApi = (roomId: string) =>
  ({
    dispatch: () => ({ unwrap: async () => undefined }),
    getState: () => ({
      keyPair: {
        peerId: "00000000-0000-4000-8000-000000000001",
        publicKey: SELF_PUBLIC_KEY,
        secretKey: "",
        challengeId: "",
        challenge: "",
        signature: "",
      },
      rooms: [
        {
          id: roomId,
          url: "cc".repeat(32),
          rtcConfig: { iceServers: [] },
          signalingActive: true,
          policy: DEFAULT_ROOM_POLICY_V1,
          peers: [{ peerId: PEER_ID, peerPublicKey: PEER_PUBLIC_KEY }],
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
    }),
  }) as unknown as Parameters<typeof handleOpenChannel>[1];

const flush = async (): Promise<void> => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
};

/**
 * Wire a real per-message channel through the real handleOpenChannel, then
 * hand it one application frame while its ratchet gate is still pending.
 */
const openPerMessageChannel = async (
  lease: RatchetGateLease,
): Promise<{
  fake: FakeMessageChannel;
  deliverFrame: () => Promise<void>;
}> => {
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    connectionState: "connected",
    ratchetGateLease: lease,
    close: () => undefined,
  } as unknown as IRTCPeerConnection;
  const label = await compileChannelMessageLabel("chat", MERKLE_ROOT_HEX);
  const fake = fakeMessageChannel(label);
  const opened = await handleOpenChannel(
    { channel: fake.channel, epc, roomId: ROOM_ID, dataChannels: [] },
    fakeApi(ROOM_ID),
  );
  return {
    fake,
    // An unrecognised 1-byte frame: it clears the pre-authentication guard and
    // is then dropped ("Wrong data length received"), so this test observes the
    // GUARD's decision and nothing else.
    deliverFrame: () =>
      (opened.onmessage as (event: MessageEvent) => Promise<void>)({
        data: new Uint8Array([0x7f]).buffer,
      } as MessageEvent),
  };
};

describe("the real guard parks an early frame instead of closing its channel", () => {
  test("a frame that beat this side's gate leaves the channel open", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, deliverFrame } = await openPerMessageChannel(lease);

    // The peer's replayed receipt arrives while our persist is still running.
    const delivered = deliverFrame();
    await flush();
    // Nothing has been closed yet: the frame is parked, not rejected. Before
    // this fix the channel was already closed at this point, and that close is
    // what the peer reads as CANCEL and acts on by deleting its partial file.
    expect(fake.closes.count).toBe(0);
    expect(fake.channel.readyState).toBe("open");

    openRatchetGate(ROOM_ID, PEER_ID, lease);
    await delivered;

    expect(fake.closes.count).toBe(0);
    expect(fake.channel.readyState).toBe("open");
    expect(fake.channel.closedLocally).toBeUndefined();
  });

  test("a frame on a genuinely unauthenticated edge still closes, and marks the close as ours", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, deliverFrame } = await openPerMessageChannel(lease);
    rejectRatchetGate(ROOM_ID, PEER_ID, new Error("handshake failed"), lease);

    await deliverFrame();

    // The DoS guard this fix relaxes is intact: an edge that will never
    // authenticate is still closed on its first application frame.
    expect(fake.closes.count).toBe(1);
    expect(fake.channel.readyState).toBe("closed");
    // ...and even that close must not be reported back to us as a peer cancel.
    expect(wasChannelClosedLocally(fake.channel)).toBe(true);
  });
});

interface C7Outcome {
  /** Did our OWN pre-authentication guard close the resumed channel? */
  guardClosedTheChannel: boolean;
  /** Chunks the sender still holds staged for retransmission. */
  senderStagedChunks: number;
  /** Chunks the receiver still holds of its partial file. */
  receiverStoredChunks: number;
}

/**
 * Replay the exact C7 sequence over the three REAL decision functions that
 * production uses, and report what data each side is left holding.
 *
 * The edge is healthy throughout: DTLS is complete, the connection is
 * registered and both sides authenticate. The only asymmetry is the one the
 * desync hunt measured — the identity RESPONDER completes the handshake on
 * SENDING finish and replays its receipts, while this side (the initiator)
 * completes on RECEIVING it and only after an IndexedDB persist, so a replayed
 * receipt can land on a gate that has not settled yet.
 */
const replayResumedEarlyReceipt = async (
  parkMs: number,
): Promise<C7Outcome> => {
  const lease = claimRatchetGate(ROOM_ID, PEER_ID);
  const epc = fakeEpc(lease);
  const channel = fakeChannel();

  // What the two sides stand to lose.
  const senderStaging = new Set([0, 1, 2]);
  let receiverStoredChunks = 4;

  // This side's persist lands 20 ms after the peer's replayed receipt arrives.
  const persist = setTimeout(
    () => openRatchetGate(ROOM_ID, PEER_ID, lease),
    20,
  );

  // 1. handleOpenChannel's pre-authentication frame guard, on that receipt.
  let guardClosedTheChannel = false;
  if (!isRatchetGateOpen(ROOM_ID, PEER_ID, lease)) {
    const decision = await admitPreAuthenticatedFrame(
      ROOM_ID,
      PEER_ID,
      lease,
      parkMs,
      0,
    );
    if (decision === "close") {
      markChannelClosedLocally(channel);
      channel.close();
      guardClosedTheChannel = true;
    }
  }

  // 2. sendWithReconcile finds its channel closed and asks whether that was
  //    the peer cancelling. "Yes" throws "Message transfer cancelled by peer",
  //    which drops the staged chunks.
  if (
    channel.readyState === "closed" &&
    isAuthenticatedPeerCancel(epc, [epc], ROOM_ID, PEER_ID, lease, channel)
  )
    senderStaging.clear();

  // Receiver cleanup requires an explicit in-band CANCEL for this channel.
  if (guardClosedTheChannel && hasImmediateRemoteCancel(channel))
    receiverStoredChunks = 0;

  clearTimeout(persist);
  return {
    guardClosedTheChannel,
    senderStagedChunks: senderStaging.size,
    receiverStoredChunks,
  };
};

describe("C7: a resumed channel's own pre-auth close must not destroy data", () => {
  test("both sides keep every byte when the receipt merely beat the gate", async () => {
    const outcome = await replayResumedEarlyReceipt(2_000);

    // No close at all: the frame was parked until the gate settled, so the
    // peer never observes a close and neither deletion path is even reached.
    expect(outcome.guardClosedTheChannel).toBe(false);
    expect(outcome.senderStagedChunks).toBe(3);
    expect(outcome.receiverStoredChunks).toBe(4);
  });

  test("park expiry closes the channel and preserves the partial", async () => {
    const outcome = await replayResumedEarlyReceipt(0);

    expect(outcome.guardClosedTheChannel).toBe(true);
    expect(outcome.senderStagedChunks).toBe(3);
    expect(outcome.receiverStoredChunks).toBe(4);
  });
});
