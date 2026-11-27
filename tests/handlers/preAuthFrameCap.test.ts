import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import {
  claimRatchetGate,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";
import { hasImmediateRemoteCancel } from "../../src/handlers/immediateDisposition";
import { wasChannelClosedLocally } from "../../src/api/webrtc/localChannelClose";
import {
  MAX_QUEUED_FRAMES_PER_CHANNEL,
  MAX_QUEUED_RECEIPTS_PER_CHANNEL,
} from "../../src/handlers/handleMessageQueueing";
import {
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
  MAX_PARKED_PRE_AUTH_BYTES,
  MAX_PARKED_PRE_AUTH_FRAMES,
  PARKED_PRE_AUTH_FRAME_OVERHEAD_BYTES,
  WIRE_CHUNK_FRAME_LEN,
  WIRE_RECEIPT_FRAME_LEN,
} from "../../src/utils/constants";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { RatchetGateLease } from "../../src/handlers/ratchetGate";

// handleOpenChannel reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation: a STATIC import of it from a Bun test
// throws `ReferenceError: localStorage is not defined` before any test runs.
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

let handleOpenChannel: (typeof import("../../src/handlers/handleOpenChannel"))["handleOpenChannel"];
let isAuthenticatedPeerCancel: (typeof import("../../src/handlers/handleSendMessage"))["isAuthenticatedPeerCancel"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];
let DEFAULT_ROOM_POLICY_V1: (typeof import("../../src/roomPolicy"))["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ isAuthenticatedPeerCancel } =
    await import("../../src/handlers/handleSendMessage"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
});

// Distinct from every other suite's ids: the ratchet gate, the receipt budget
// and the receive-queue budget are all process-global maps keyed by room/peer.
const ROOM_ID = "00000000-0000-4000-8000-0000000000b1";
const PEER_ID = "00000000-0000-4000-8000-0000000000b2";
const SELF_PUBLIC_KEY = `${"00".repeat(31)}01`;
const PEER_PUBLIC_KEY = "ff".repeat(32);
const MERKLE_ROOT_HEX = "ab".repeat(64);

afterEach(() => {
  resetRatchetGate(ROOM_ID, PEER_ID);
});

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
    withPeerId: PEER_ID,
    roomIds: [ROOM_ID],
    bufferedAmount: 0,
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

const fakeEpc = (lease: RatchetGateLease): IRTCPeerConnection =>
  ({
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    connectionState: "connected",
    ratchetGateLease: lease,
    close: () => undefined,
  }) as unknown as IRTCPeerConnection;

const fakeApi = () =>
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
          id: ROOM_ID,
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
  for (let i = 0; i < 50; i++) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
};

/** Capture the guard's logging so a burst of rejected frames stays readable. */
const withCapturedErrors = async <T>(
  body: (logged: unknown[][]) => Promise<T>,
): Promise<T> => {
  const logged: unknown[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => {
    logged.push(args);
  };
  try {
    return await body(logged);
  } finally {
    console.error = original;
  }
};

interface OpenedChannel {
  fake: FakeMessageChannel;
  epc: IRTCPeerConnection;
  deliver: (frame: Uint8Array) => Promise<void>;
}

/** Wire a real per-message channel through the real handleOpenChannel. */
const openPerMessageChannel = async (
  lease: RatchetGateLease,
): Promise<OpenedChannel> => {
  const epc = fakeEpc(lease);
  const label = await compileChannelMessageLabel("chat", MERKLE_ROOT_HEX);
  const fake = fakeMessageChannel(label);
  const opened = await handleOpenChannel(
    { channel: fake.channel, epc, roomId: ROOM_ID, dataChannels: [] },
    fakeApi(),
  );
  return {
    fake,
    epc,
    deliver: (frame: Uint8Array) =>
      (opened.onmessage as (event: MessageEvent) => Promise<void>)({
        data: frame.buffer.slice(
          frame.byteOffset,
          frame.byteOffset + frame.byteLength,
        ),
      } as MessageEvent),
  };
};

/**
 * One full-size wire cell of the given type, distinct from every other index.
 *
 * Full size on purpose: the park ceiling exists to bound how much memory an
 * unauthenticated peer can pin, and a 65,490-byte cell is the worst case it is
 * sized against.
 */
const wireCell = (type: number, index: number): Uint8Array => {
  const frame = new Uint8Array(WIRE_CHUNK_FRAME_LEN);
  frame[0] = type;
  new DataView(frame.buffer).setUint32(1, index, false);
  new DataView(frame.buffer).setUint32(WIRE_CHUNK_FRAME_LEN - 4, index, false);
  return frame;
};

/** A receipt-sized wire frame: all bookkeeping, almost no payload. */
const smallCell = (type: number, index: number): Uint8Array => {
  const frame = new Uint8Array(WIRE_RECEIPT_FRAME_LEN);
  frame[0] = type;
  new DataView(frame.buffer).setUint32(1, index, false);
  return frame;
};

const receiptCell = (index: number): Uint8Array => {
  const frame = new Uint8Array(WIRE_RECEIPT_FRAME_LEN);
  frame[0] = FRAME_TYPE_RECEIPT;
  new DataView(frame.buffer).setUint32(1, index, false);
  new DataView(frame.buffer).setUint32(
    WIRE_RECEIPT_FRAME_LEN - 4,
    index,
    false,
  );
  return frame;
};

// An unrecognised type byte: such a frame clears the pre-authentication guard
// and is then dropped ("Wrong data length received"), so these tests observe
// the GUARD's decision and nothing else.
const UNROUTED_FRAME_TYPE = 0x7f;

// More cells than the ceiling can hold, whatever unit the ceiling counts in:
// one more than MAX_PARKED_PRE_AUTH_FRAMES full-size cells overruns both a
// 64-frame bound and a bound of 64 full-size frames' worth of bytes.
const CELLS_OVER_THE_CEILING = MAX_PARKED_PRE_AUTH_FRAMES + 1;

interface CeilingOutcome {
  /** Did our OWN pre-authentication guard close the resumed channel? */
  guardClosedTheChannel: boolean;
  /** Chunks the peer still holds of its partial file. */
  peerStoredChunks: number;
  /** Chunks the sender still holds staged for retransmission. */
  senderStagedChunks: number;
}

/**
 * Overrun the pre-authentication park ceiling on a resumed per-message channel
 * and report what data each side is left holding.
 *
 * This is the reconnect receipt replay (handleOpenChannel's onopen burst, one
 * receipt per stored chunk, 32 every 10 ms) landing on a gate that has not
 * settled: on a partial of more than a few megabytes the burst crosses the
 * ceiling in about twenty milliseconds. The edge is healthy throughout.
 */
const burstAcrossTheCeiling = async (
  gate: "pending" | "rejected",
): Promise<CeilingOutcome> => {
  const lease = claimRatchetGate(ROOM_ID, PEER_ID);
  const { fake, epc, deliver } = await openPerMessageChannel(lease);
  if (gate === "rejected")
    rejectRatchetGate(ROOM_ID, PEER_ID, new Error("handshake failed"), lease);

  // What the two sides stand to lose.
  const senderStaging = new Set([0, 1, 2]);
  let peerStoredChunks = 4;

  const outcome = await withCapturedErrors(async () => {
    const inFlight: Promise<void>[] = [];
    for (let i = 0; i < CELLS_OVER_THE_CEILING; i++)
      inFlight.push(deliver(wireCell(UNROUTED_FRAME_TYPE, i)));
    await flush();

    const guardClosedTheChannel = fake.channel.readyState === "closed";

    // Model the matching receive disposition. Bytes can be discarded only
    // after a valid CANCEL on the authenticated channel.
    if (guardClosedTheChannel && hasImmediateRemoteCancel(fake.channel))
      peerStoredChunks = 0;

    // ...and sendWithReconcile finds its own channel closed and asks whether
    // that was the peer cancelling.
    if (
      guardClosedTheChannel &&
      isAuthenticatedPeerCancel(
        epc,
        [epc],
        ROOM_ID,
        PEER_ID,
        lease,
        fake.channel,
      )
    )
      senderStaging.clear();

    // Release every parked frame before the test ends.
    openRatchetGate(ROOM_ID, PEER_ID, lease);
    await Promise.all(inFlight);

    return {
      guardClosedTheChannel,
      peerStoredChunks,
      senderStagedChunks: senderStaging.size,
    };
  });

  return outcome;
};

describe("C-1: overrunning the park ceiling must not destroy the peer's partial", () => {
  test("a burst past the ceiling on a healthy edge closes nothing and deletes nothing", async () => {
    const outcome = await burstAcrossTheCeiling("pending");

    expect(outcome.peerStoredChunks).toBe(4);
    expect(outcome.senderStagedChunks).toBe(3);
    expect(outcome.guardClosedTheChannel).toBe(false);
  });

  test("a failed gate closes the channel and preserves the partial", async () => {
    const outcome = await burstAcrossTheCeiling("rejected");

    expect(outcome.guardClosedTheChannel).toBe(true);
    expect(outcome.peerStoredChunks).toBe(4);
    // The local-close marker still saves the SENDER's staging, because that
    // decision is made in this process.
    expect(outcome.senderStagedChunks).toBe(3);
  });
});

describe("I-2: the park ceiling is computed from the frames actually parked", () => {
  test("frames under the ceiling park; the frame that overruns it is dropped at once", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, deliver } = await openPerMessageChannel(lease);

    await withCapturedErrors(async () => {
      const settled: boolean[] = [];
      const inFlight: Promise<void>[] = [];
      for (let i = 0; i < CELLS_OVER_THE_CEILING; i++) {
        const index = i;
        inFlight.push(
          deliver(wireCell(UNROUTED_FRAME_TYPE, index)).then(() => {
            settled[index] = true;
          }),
        );
      }
      await flush();

      // Everything inside the ceiling is still parked on the pending gate...
      expect(settled[0]).toBeUndefined();
      expect(settled[CELLS_OVER_THE_CEILING - 2]).toBeUndefined();
      // ...and the one that overruns it has already returned, without closing.
      // A call site that passed a constant instead of the running total would
      // either park this frame too, or drop every frame above.
      expect(settled[CELLS_OVER_THE_CEILING - 1]).toBe(true);
      expect(fake.closes.count).toBe(0);
      expect(fake.channel.readyState).toBe("open");

      openRatchetGate(ROOM_ID, PEER_ID, lease);
      await Promise.all(inFlight);
    });
  });

  test("the ceiling charges each parked frame its bookkeeping, not only its payload", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, deliver } = await openPerMessageChannel(lease);
    // Receipt-sized frames: 65 bytes of payload each, and everything else a
    // park costs — the suspended handler, its promise chain, its timer. Charged
    // on payload alone a flooder could pin ~64k of those continuations where
    // the frame ceiling this replaces allowed 64.
    const tinyFramesToTheCeiling =
      Math.floor(
        MAX_PARKED_PRE_AUTH_BYTES / PARKED_PRE_AUTH_FRAME_OVERHEAD_BYTES,
      ) + 1;

    await withCapturedErrors(async () => {
      const settled: boolean[] = [];
      const inFlight: Promise<void>[] = [];
      for (let i = 0; i < tinyFramesToTheCeiling; i++) {
        const index = i;
        inFlight.push(
          deliver(smallCell(UNROUTED_FRAME_TYPE, index)).then(() => {
            settled[index] = true;
          }),
        );
      }
      await flush();

      expect(settled[0]).toBeUndefined();
      expect(settled[tinyFramesToTheCeiling - 1]).toBe(true);
      expect(fake.closes.count).toBe(0);

      openRatchetGate(ROOM_ID, PEER_ID, lease);
      await Promise.all(inFlight);
    });
  });

  test("a dropped frame frees its budget again: the channel keeps serving after the burst", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, deliver } = await openPerMessageChannel(lease);

    await withCapturedErrors(async () => {
      const inFlight: Promise<void>[] = [];
      for (let i = 0; i < CELLS_OVER_THE_CEILING * 2; i++)
        inFlight.push(deliver(wireCell(UNROUTED_FRAME_TYPE, i)));
      await flush();

      expect(fake.closes.count).toBe(0);

      openRatchetGate(ROOM_ID, PEER_ID, lease);
      await Promise.all(inFlight);

      // Nothing pinned, nothing closed, and the next frame is served normally.
      expect(fake.channel.readyState).toBe("open");
      await deliver(wireCell(UNROUTED_FRAME_TYPE, 0));
      expect(fake.closes.count).toBe(0);
    });
  });
});

describe("I-3: a budget-exceeded close is marked as ours, so no peer reads it as a cancel", () => {
  test("the receipt-queue budget close cannot be reported back as a peer cancel", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, epc, deliver } = await openPerMessageChannel(lease);
    openRatchetGate(ROOM_ID, PEER_ID, lease);

    await withCapturedErrors(async () => {
      for (
        let i = 0;
        i < MAX_QUEUED_RECEIPTS_PER_CHANNEL + 8 && fake.closes.count === 0;
        i++
      )
        void deliver(receiptCell(i));
    });

    expect(fake.closes.count).toBe(1);
    expect(fake.channel.readyState).toBe("closed");
    expect(
      isAuthenticatedPeerCancel(
        epc,
        [epc],
        ROOM_ID,
        PEER_ID,
        lease,
        fake.channel,
      ),
    ).toBe(false);
    expect(wasChannelClosedLocally(fake.channel)).toBe(true);
  });

  test("the receive-queue budget close cannot be reported back as a peer cancel", async () => {
    const lease = claimRatchetGate(ROOM_ID, PEER_ID);
    const { fake, epc, deliver } = await openPerMessageChannel(lease);
    openRatchetGate(ROOM_ID, PEER_ID, lease);

    await withCapturedErrors(async () => {
      for (
        let i = 0;
        i < MAX_QUEUED_FRAMES_PER_CHANNEL + 8 && fake.closes.count === 0;
        i++
      )
        void deliver(wireCell(FRAME_TYPE_CHUNK, i));
    });

    expect(fake.closes.count).toBe(1);
    expect(fake.channel.readyState).toBe("closed");
    expect(
      isAuthenticatedPeerCancel(
        epc,
        [epc],
        ROOM_ID,
        PEER_ID,
        lease,
        fake.channel,
      ),
    ).toBe(false);
    expect(wasChannelClosedLocally(fake.channel)).toBe(true);
  });
});
