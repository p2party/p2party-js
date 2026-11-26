import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  WebRtcCandidateProvider,
  WebRtcProviderError,
  dataChannelTransport,
} from "../../../src/blindRendezvous/prototype/webrtcProvider";
import {
  SEND_BUFFER_LOW_THRESHOLD,
  MAX_BUFFERED_AMOUNT,
  PROTOTYPE_APP_LANE_HIGH_WATER_BYTES,
  PROTOTYPE_APP_LANE_MAX_FRAMES,
  PROTOTYPE_CONTROL_LANE_HIGH_WATER_BYTES,
  PROTOTYPE_CONTROL_LANE_MAX_FRAMES,
} from "../../../src/utils/constants";
import {
  createSession,
  generateSessionIdentity,
  type P2PartySession,
} from "../../../src/session";

const wasmFile = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const cryptoOptions = {
  wasmBinary: wasmFile.buffer.slice(
    wasmFile.byteOffset,
    wasmFile.byteOffset + wasmFile.byteLength,
  ) as ArrayBuffer,
};

const TAG_CONTROL = 0;
const TAG_APP = 1;

/**
 * The parts of `RTCDataChannel` the transport touches. `close()` is the
 * channel reporting an orderly close: whichever side started it, the other end
 * sees `close` after every frame it had already been delivered.
 */
class FakeChannel extends EventTarget {
  binaryType = "arraybuffer";
  readyState: RTCDataChannelState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  peer: FakeChannel | null = null;
  onSend: (() => void) | null = null;
  /** Every frame handed to `send`, in order. */
  readonly sent: Uint8Array[] = [];
  /** The next `send` throws, as Chromium's does when it refuses a frame. */
  refuseNextSend = false;
  /** Runs at the start of every `send`, before the frame is taken. */
  beforeSend: (() => void) | null = null;

  send(bytes: Uint8Array): void {
    this.beforeSend?.();
    if (this.refuseNextSend) {
      this.refuseNextSend = false;
      throw new DOMException(
        "RTCDataChannel send queue is full",
        "OperationError",
      );
    }
    this.sent.push(Uint8Array.from(bytes));
    // EventTarget, like RTCDataChannel, does not retain an event for a future
    // listener. This reproduces a HELLO arriving during async getStats().
    this.peer?.dispatchEvent(
      new MessageEvent("message", { data: Uint8Array.from(bytes).buffer }),
    );
    this.onSend?.();
  }

  /** One frame arriving from the peer. */
  deliver(bytes: ArrayLike<number>): void {
    this.dispatchEvent(
      new MessageEvent("message", { data: Uint8Array.from(bytes).buffer }),
    );
  }

  /** The browser's send buffer draining to `amount`, as the spec fires it. */
  drainTo(amount: number): void {
    const before = this.bufferedAmount;
    this.bufferedAmount = amount;
    if (
      before > this.bufferedAmountLowThreshold &&
      amount <= this.bufferedAmountLowThreshold
    )
      this.dispatchEvent(new Event("bufferedamountlow"));
  }

  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
    this.peer?.close();
  }

  asRtc(): RTCDataChannel {
    return this as unknown as RTCDataChannel;
  }
}

/** One frame of `length` payload bytes on `tag`'s lane, every byte `fill`. */
const laneFrame = (tag: number, length: number, fill: number): Uint8Array => {
  const frame = new Uint8Array(1 + length).fill(fill);
  frame[0] = tag;
  return frame;
};

/**
 * How a provider promise settled: `"resolved"`, or the `reason` it rejected
 * with. A synchronous throw counts as a rejection, so a call that throws
 * instead of rejecting is still told apart.
 */
const reasonOf = async (call: () => Promise<unknown>): Promise<string> => {
  try {
    await call();
    return "resolved";
  } catch (error) {
    return error instanceof WebRtcProviderError
      ? error.reason
      : `not a WebRtcProviderError: ${String(error)}`;
  }
};

/** Let every pending promise reaction run: one macrotask turn. */
const turn = (): Promise<void> =>
  new Promise((resolve) => {
    setImmediate(resolve);
  });

/** `promise`'s value if it settles within one turn, else "still pending". */
const withinOneTurn = (promise: Promise<string>): Promise<string> =>
  Promise.race([promise, turn().then(() => "still pending")]);

const fingerprintA = new Uint8Array(32).fill(0xa1);
const fingerprintB = new Uint8Array(32).fill(0xb2);
const stats = (local: Uint8Array, remote: Uint8Array): RTCStatsReport =>
  new Map([
    [
      "transport",
      {
        type: "transport",
        localCertificateId: "local",
        remoteCertificateId: "remote",
      },
    ],
    [
      "local",
      { type: "certificate", fingerprint: Buffer.from(local).toString("hex") },
    ],
    [
      "remote",
      { type: "certificate", fingerprint: Buffer.from(remote).toString("hex") },
    ],
  ]) as unknown as RTCStatsReport;

const originalPeerConnection = globalThis.RTCPeerConnection;
afterEach(() => {
  globalThis.RTCPeerConnection = originalPeerConnection;
});

const makeProviders = () => {
  const connections: FakePeerConnection[] = [];
  class FakePeerConnection extends EventTarget {
    ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
    readonly channel = new FakeChannel();
    statsResult: Promise<RTCStatsReport> = Promise.resolve(
      stats(fingerprintA, fingerprintB),
    );
    constructor() {
      super();
      connections.push(this);
    }
    createDataChannel(): RTCDataChannel {
      return this.channel.asRtc();
    }
    getStats(): Promise<RTCStatsReport> {
      return this.statsResult;
    }
    close(): void {
      this.channel.close();
    }
  }
  globalThis.RTCPeerConnection =
    FakePeerConnection as unknown as typeof RTCPeerConnection;
  const alice = new WebRtcCandidateProvider({
    role: "initiator",
    rtcConfig: {},
  });
  const bob = new WebRtcCandidateProvider({ role: "responder", rtcConfig: {} });
  const [a, b] = connections;
  a.channel.peer = b.channel;
  b.channel.peer = a.channel;
  b.ondatachannel?.({ channel: b.channel.asRtc() } as RTCDataChannelEvent);
  return { alice, bob, a, b };
};

describe("prototype WebRTC bootstrap transport", () => {
  test("channel adoption retains both lanes, and repeated access does not duplicate messages", async () => {
    const { alice, bob, a } = makeProviders();
    try {
      a.channel.send(new Uint8Array([0, 11]));
      a.channel.send(new Uint8Array([1, 22]));
      a.channel.send(new Uint8Array([0, 33]));
      const transport = dataChannelTransport(await bob.channel());
      expect(dataChannelTransport(await bob.channel())).toBe(transport);
      expect(await transport.recv()).toEqual(new Uint8Array([11]));
      expect(await transport.recv()).toEqual(new Uint8Array([33]));
      expect(await transport.recvApp()).toEqual(new Uint8Array([22]));
      const pending = transport.recv();
      bob.close();
      expect(await reasonOf(() => pending)).toBe("aborted");
      expect(await reasonOf(() => bob.channel())).toBe("aborted");
    } finally {
      alice.close();
      bob.close();
    }
  });

  test("the provider's close discards what the peer's graceful close kept", async () => {
    const { alice, bob, a } = makeProviders();
    try {
      // Alice speaks before Bob reads anything, then closes in order.
      a.channel.send(new Uint8Array([TAG_CONTROL, 99]));
      a.channel.send(new Uint8Array([TAG_APP, 7]));
      alice.close();
      const transport = dataChannelTransport(await bob.channel());
      // The orderly close kept what had arrived ...
      expect(await transport.recvApp()).toEqual(new Uint8Array([7]));
      // ... and Bob's own close, which a run reaches on any teardown, is a
      // local abort of the transport, not a second close of the channel: it
      // discards the rest, so no later reader starts a handshake from it.
      bob.close();
      expect(await reasonOf(() => transport.recv())).toBe("closed");
    } finally {
      alice.close();
      bob.close();
    }
  });

  test.each([
    ["control", TAG_CONTROL, PROTOTYPE_CONTROL_LANE_MAX_FRAMES],
    ["app", TAG_APP, PROTOTYPE_APP_LANE_MAX_FRAMES],
  ] as const)(
    "tiny-frame overflow of the %s lane rejects pending receives and clears both queues",
    async (lane, tag, maxFrames) => {
      const channel = new FakeChannel();
      const transport = dataChannelTransport(channel.asRtc());
      // A reader waits on the other lane while this one fills.
      const other = tag === TAG_APP ? transport.recv() : transport.recvApp();
      for (let i = 0; i < maxFrames; i += 1) channel.deliver([tag]);
      expect(channel.readyState).toBe("open");
      channel.deliver([tag]);
      expect(channel.readyState).toBe("closed");
      await expect(other).rejects.toThrow(`${lane} lane`);
      expect(await reasonOf(() => transport.recv())).toBe("overflow");
      expect(await reasonOf(() => transport.recvApp())).toBe("overflow");
    },
  );

  test("each lane's high-water mark is its own, and reading releases it", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // The control lane holding all the frames it may ...
    for (let i = 0; i < PROTOTYPE_CONTROL_LANE_MAX_FRAMES; i += 1)
      channel.deliver([TAG_CONTROL, i]);
    // ... takes nothing from the app lane, which fills to exactly its mark.
    const appFrames = 16;
    const appFrameBytes = PROTOTYPE_APP_LANE_HIGH_WATER_BYTES / appFrames;
    for (let i = 0; i < appFrames; i += 1)
      channel.deliver(laneFrame(TAG_APP, appFrameBytes, i));
    expect(channel.readyState).toBe("open");

    // Reading one app frame frees exactly its bytes: one more frame of the
    // same size fits ...
    expect((await transport.recvApp())[0]).toBe(0);
    channel.deliver(laneFrame(TAG_APP, appFrameBytes, appFrames));
    expect(channel.readyState).toBe("open");
    // ... and one byte past the mark does not.
    channel.deliver([TAG_APP, 0xff]);
    expect(channel.readyState).toBe("closed");
    await expect(transport.recvApp()).rejects.toThrow("app lane");
    expect(await reasonOf(() => transport.recv())).toBe("overflow");
  });

  test("a frame larger than its lane's high-water mark ends the transport even with a reader waiting", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const waiting = transport.recv();
    channel.deliver(
      laneFrame(TAG_CONTROL, PROTOTYPE_CONTROL_LANE_HIGH_WATER_BYTES + 1, 1),
    );
    expect(await reasonOf(() => waiting)).toBe("protocol");
    expect(channel.readyState).toBe("closed");
  });

  test("a transport created on an already closed channel rejects immediately", async () => {
    const channel = new FakeChannel();
    channel.close();
    const transport = dataChannelTransport(channel.asRtc());
    expect(await reasonOf(() => transport.recv())).toBe("closed");
    expect(await reasonOf(() => transport.recvApp())).toBe("closed");
  });

  test("frames delivered before a graceful close are still read", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // A reader mid-message: the first frame goes straight to it, the rest
    // queue, and only then does the peer's close arrive.
    const first = transport.recvApp();
    for (const value of [1, 2, 3]) channel.deliver([TAG_APP, value]);
    channel.deliver([TAG_CONTROL, 9]);
    channel.close();

    expect(await first).toEqual(new Uint8Array([1]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([2]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([3]));
    expect(await transport.recv()).toEqual(new Uint8Array([9]));
    // Drained, each lane then reports the close.
    expect(await reasonOf(() => transport.recvApp())).toBe("closed");
    expect(await reasonOf(() => transport.recv())).toBe("closed");
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([4])))).toBe(
      "closed",
    );
  });

  test("a reader blocked on an empty lane observes a remote graceful close", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const blockedApp = reasonOf(() => transport.recvApp());
    const blockedControl = reasonOf(() => transport.recv());
    channel.close();
    // Bounded: a reader the close does not reach fails here, by assertion.
    expect(await withinOneTurn(blockedApp)).toBe("closed");
    expect(await withinOneTurn(blockedControl)).toBe("closed");
  });

  test("a send before the channel opens is refused as connecting", async () => {
    const channel = new FakeChannel();
    channel.readyState = "connecting";
    const transport = dataChannelTransport(channel.asRtc());
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([1])))).toBe(
      "connecting",
    );
    expect(channel.sent).toHaveLength(0);
  });

  test("frames delivered before a channel error are still read", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.deliver([TAG_APP, 5]);
    channel.deliver([TAG_APP, 6]);
    // An SCTP abort: the browser fires `error`, then `close`.
    channel.dispatchEvent(new Event("error"));
    channel.close();

    expect(await transport.recvApp()).toEqual(new Uint8Array([5]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([6]));
    expect(await reasonOf(() => transport.recvApp())).toBe("errored");
  });

  test("local abort clears the queues", async () => {
    // On an open channel: both lanes go at once, and the channel is closed.
    const open = new FakeChannel();
    const live = dataChannelTransport(open.asRtc());
    open.deliver([TAG_CONTROL, 1]);
    open.deliver([TAG_APP, 2]);
    live.close();
    expect(await reasonOf(() => live.recv())).toBe("aborted");
    expect(await reasonOf(() => live.recvApp())).toBe("aborted");
    expect(open.readyState).toBe("closed");

    // After a graceful close: what the close kept, a later local abort
    // discards.
    const closed = new FakeChannel();
    const ended = dataChannelTransport(closed.asRtc());
    closed.deliver([TAG_APP, 3]);
    closed.deliver([TAG_APP, 4]);
    closed.deliver([TAG_CONTROL, 5]);
    closed.close();
    expect(await ended.recvApp()).toEqual(new Uint8Array([3]));
    ended.close();
    expect(await reasonOf(() => ended.recvApp())).toBe("closed");
    expect(await reasonOf(() => ended.recv())).toBe("closed");
  });

  test("a withdrawn receive does not take the next frame", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const withdrawal = new AbortController();
    const abandoned = reasonOf(() => transport.recvApp(withdrawal.signal));
    withdrawal.abort();
    expect(await abandoned).toBe("cancelled");
    channel.deliver([TAG_APP, 0xaa]);
    channel.deliver([TAG_APP, 0xbb]);
    expect(await transport.recvApp()).toEqual(new Uint8Array([0xaa]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([0xbb]));

    // Withdrawn before it starts, a receive takes nothing that is queued.
    channel.deliver([TAG_APP, 0xcc]);
    expect(await reasonOf(() => transport.recvApp(withdrawal.signal))).toBe(
      "cancelled",
    );
    expect(await transport.recvApp()).toEqual(new Uint8Array([0xcc]));
  });

  test("sender waits when the lane is above its high-water mark", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // At the mark, a frame still leaves at once.
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    await transport.sendApp(new Uint8Array([1]));
    expect(channel.sent).toHaveLength(1);

    // Above it, frames wait: app and control alike, since both lanes share
    // the channel's one buffer.
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT + 1;
    const order: string[] = [];
    const app = Promise.resolve(transport.sendApp(new Uint8Array([2]))).then(
      () => order.push("app"),
    );
    const control = Promise.resolve(transport.send(new Uint8Array([3]))).then(
      () => order.push("control"),
    );
    await turn();
    expect(channel.sent).toHaveLength(1);
    expect(order).toEqual([]);

    // The event is a hint; the buffer is the truth. A stale event that finds
    // the buffer still above the mark releases nothing.
    channel.dispatchEvent(new Event("bufferedamountlow"));
    await turn();
    expect(channel.sent).toHaveLength(1);

    // The drain the transport asked to hear about releases both, in order.
    expect(channel.bufferedAmountLowThreshold).toBe(SEND_BUFFER_LOW_THRESHOLD);
    channel.drainTo(SEND_BUFFER_LOW_THRESHOLD);
    await Promise.all([app, control]);
    expect(order).toEqual(["app", "control"]);
    expect(channel.sent).toEqual([
      new Uint8Array([TAG_APP, 1]),
      new Uint8Array([TAG_APP, 2]),
      new Uint8Array([TAG_CONTROL, 3]),
    ]);
  });

  test.each([
    ["the channel closes", "closed"],
    ["the transport is closed locally", "aborted"],
  ] as const)(
    "a send waiting for a drain fails with the provider's error when %s",
    async (how, reason) => {
      const channel = new FakeChannel();
      const transport = dataChannelTransport(channel.asRtc());
      channel.bufferedAmount = MAX_BUFFERED_AMOUNT + 1;
      const waiting = reasonOf(() => transport.sendApp(new Uint8Array([7])));
      await turn();
      if (how === "the channel closes") channel.close();
      else transport.close();

      expect(await waiting).toBe(reason);
      // The waiting frame never reaches the channel, even once it drains.
      channel.drainTo(0);
      await turn();
      expect(channel.sent).toHaveLength(0);
    },
  );

  test("a frame the channel refuses stops every later frame and leaves receiving alone", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.refuseNextSend = true;
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([1])))).toBe(
      "refused",
    );
    // The lane's framing is positional, so nothing may follow a lost frame.
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([2])))).toBe(
      "refused",
    );
    expect(channel.sent).toHaveLength(0);

    channel.deliver([TAG_APP, 9]);
    expect(await transport.recvApp()).toEqual(new Uint8Array([9]));
  });

  test("a send that throws because the channel is closing reports the close, not a refusal", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // The peer's close begins as this frame goes out.
    channel.beforeSend = () => {
      channel.readyState = "closing";
    };
    channel.refuseNextSend = true;
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([1])))).toBe(
      "closed",
    );
  });

  test("a drain reported from inside send() does not reorder frames", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT + 1;
    const sends = [1, 2, 3].map((value) =>
      transport.sendApp(new Uint8Array([value])),
    );
    // A browser queues `bufferedamountlow` as a task; this channel fires it
    // synchronously, before it takes each frame.
    channel.beforeSend = () =>
      channel.dispatchEvent(new Event("bufferedamountlow"));
    channel.drainTo(0);
    await Promise.all(sends);
    expect(channel.sent).toEqual([
      new Uint8Array([TAG_APP, 1]),
      new Uint8Array([TAG_APP, 2]),
      new Uint8Array([TAG_APP, 3]),
    ]);
  });

  test("closing after sending waits for the buffer to empty, then closes", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.deliver([TAG_APP, 9]);
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT + 1;
    const queued = transport.sendApp(new Uint8Array([1]));
    const pendingRecv = reasonOf(() => transport.recv());
    let closed = false;
    const closing = transport.closeAfterSending().then(() => {
      closed = true;
    });

    // Receiving ends at once, as on a local abort, and new sends are refused.
    expect(await pendingRecv).toBe("aborted");
    expect(await reasonOf(() => transport.recvApp())).toBe("aborted");
    expect(await reasonOf(() => transport.sendApp(new Uint8Array([2])))).toBe(
      "aborted",
    );

    // The frame already queued still leaves ...
    channel.drainTo(SEND_BUFFER_LOW_THRESHOLD);
    await queued;
    expect(channel.sent).toEqual([new Uint8Array([TAG_APP, 1])]);
    // ... and the channel stays open while the buffer is not yet empty.
    await turn();
    expect(closed).toBe(false);
    expect(channel.readyState).toBe("open");

    channel.drainTo(0);
    await turn();
    expect(closed).toBe(true);
    expect(channel.readyState).toBe("closed");
    await closing;
  });

  test("closing after sending fails when the peer closes before the buffer empties", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.bufferedAmount = 100;
    const closing = reasonOf(() => transport.closeAfterSending());
    channel.close();
    expect(await closing).toBe("undrained");
  });

  test("a local abort does not wait for the buffer", async () => {
    // With no orderly close asked for: the channel closes at once over a
    // buffer that still holds bytes.
    const busy = new FakeChannel();
    const aborted = dataChannelTransport(busy.asRtc());
    busy.bufferedAmount = 100;
    aborted.close();
    expect(busy.readyState).toBe("closed");

    // With one under way, the abort ends it too, and nothing queued survives.
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.deliver([TAG_APP, 9]);
    channel.bufferedAmount = MAX_BUFFERED_AMOUNT + 1;
    const waiting = reasonOf(() => transport.sendApp(new Uint8Array([1])));
    const closing = reasonOf(() => transport.closeAfterSending());
    transport.close();
    expect(channel.readyState).toBe("closed");
    expect(await waiting).toBe("aborted");
    expect(await closing).toBe("undrained");
    expect(await reasonOf(() => transport.recvApp())).toBe("aborted");
    channel.drainTo(0);
    await turn();
    expect(channel.sent).toHaveLength(0);
  });

  test("real session retains an early HELLO while the responder awaits certificate verification", async () => {
    const { alice, bob, a, b } = makeProviders();
    const [aliceIdentity, bobIdentity] = await Promise.all([
      generateSessionIdentity(cryptoOptions),
      generateSessionIdentity(cryptoOptions),
    ]);
    let releaseStats!: (report: RTCStatsReport) => void;
    b.statsResult = new Promise((resolve) => {
      releaseStats = resolve;
    });
    let firstHello!: () => void;
    const helloSent = new Promise<void>((resolve) => {
      firstHello = resolve;
    });
    a.channel.onSend = firstHello;
    const bobVerdict = bob.verifyCertificates(fingerprintB, fingerprintA);
    await alice.verifyCertificates(fingerprintA, fingerprintB);
    const transportA = dataChannelTransport(await alice.channel());
    const common = { mode: "nopin" as const, crypto: cryptoOptions };
    const aliceSession = createSession({
      ...common,
      role: "initiator",
      identity: aliceIdentity,
      peerIdentityEd25519PublicKey: bobIdentity.ed25519PublicKey,
      channel: {
        channelId: new Uint8Array([1]),
        localFingerprint: fingerprintA,
        remoteFingerprint: fingerprintB,
      },
      transport: transportA,
    });
    void aliceSession.catch(() => undefined);
    const sessions: P2PartySession[] = [];
    // Bound a failing regression and unblock both real handshake receivers.
    const deadline = setTimeout(() => {
      alice.close();
      bob.close();
    }, 1000);
    try {
      await helloSent;
      expect(a.channel.sent).toHaveLength(1);
      expect(b.channel.sent).toHaveLength(0);
      releaseStats(stats(fingerprintB, fingerprintA));
      expect(await bobVerdict).toBe("verified");
      const bobSession = createSession({
        ...common,
        role: "responder",
        identity: bobIdentity,
        peerIdentityEd25519PublicKey: aliceIdentity.ed25519PublicKey,
        channel: {
          channelId: new Uint8Array([1]),
          localFingerprint: fingerprintB,
          remoteFingerprint: fingerprintA,
        },
        transport: dataChannelTransport(await bob.channel()),
      });
      sessions.push(...(await Promise.all([aliceSession, bobSession])));
      expect(sessions).toHaveLength(2);
      const plaintext = new TextEncoder().encode("early HELLO preserved");
      expect(
        await sessions[1].decrypt(await sessions[0].encrypt(plaintext)),
      ).toEqual(plaintext);
    } finally {
      clearTimeout(deadline);
      alice.close();
      bob.close();
      await Promise.all(sessions.map((session) => session.destroy()));
      for (const identity of [aliceIdentity, bobIdentity]) {
        identity.ed25519SecretKey.fill(0);
        identity.x25519SecretKey.fill(0);
      }
    }
  });
});
