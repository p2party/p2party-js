import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  APP_LANE_HIGH_WATER_BYTES,
  APP_LANE_MAX_FRAMES,
  CONTROL_LANE_HIGH_WATER_BYTES,
  CONTROL_LANE_MAX_FRAMES,
  SEND_HIGH_WATER_BYTES,
  SEND_LOW_WATER_BYTES,
  WebRtcCandidateProvider,
  WebRtcProviderError,
  dataChannelTransport,
} from "../../../src/blindRendezvous/prototype/webrtcProvider";
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

/** Every outcome of a promise as a value, so a rejection can be inspected. */
const settled = <T>(promise: Promise<T>): Promise<T | Error> =>
  promise.then(
    (value) => value,
    (error: unknown) =>
      error instanceof Error ? error : new Error(String(error)),
  );

/** Let every pending promise reaction run: one macrotask turn. */
const turn = (): Promise<void> =>
  new Promise((resolve) => {
    setImmediate(resolve);
  });

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
      await expect(pending).rejects.toThrow("closed");
      await expect(bob.channel()).rejects.toThrow("closed");
    } finally {
      alice.close();
      bob.close();
    }
  });

  test("certificate mismatch discards bytes a graceful close kept", async () => {
    const { alice, bob, a, b } = makeProviders();
    try {
      // Alice speaks before Bob has verified anything, then closes in order.
      a.channel.send(new Uint8Array([TAG_CONTROL, 99]));
      a.channel.send(new Uint8Array([TAG_APP, 7]));
      alice.close();
      expect(b.channel.readyState).toBe("closed");
      const transport = dataChannelTransport(await bob.channel());
      // The orderly close kept what had arrived ...
      expect(await transport.recvApp()).toEqual(new Uint8Array([7]));

      b.statsResult = Promise.resolve(stats(fingerprintB, new Uint8Array(32)));
      await expect(
        bob.verifyCertificates(fingerprintB, fingerprintA),
      ).rejects.toThrow("DTLS fingerprint mismatch");
      // ... and the local close a mismatch ends in discards the rest of it,
      // so no later reader can start a handshake from Alice's early HELLO.
      bob.close();
      await expect(transport.recv()).rejects.toThrow(WebRtcProviderError);
      await expect(transport.sendApp(new Uint8Array([8]))).rejects.toThrow(
        WebRtcProviderError,
      );
    } finally {
      alice.close();
      bob.close();
    }
  });

  test.each([
    ["control", TAG_CONTROL, CONTROL_LANE_MAX_FRAMES],
    ["app", TAG_APP, APP_LANE_MAX_FRAMES],
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
      await expect(transport.recv()).rejects.toThrow("high-water mark");
      await expect(transport.recvApp()).rejects.toThrow("high-water mark");
    },
  );

  test("each lane's high-water mark is its own, and reading releases it", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // The control lane holding all the frames it may ...
    for (let i = 0; i < CONTROL_LANE_MAX_FRAMES; i += 1)
      channel.deliver([TAG_CONTROL, i]);
    // ... takes nothing from the app lane, which fills to exactly its mark.
    const appFrames = 16;
    const appFrameBytes = APP_LANE_HIGH_WATER_BYTES / appFrames;
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
    await expect(transport.recv()).rejects.toThrow("app lane");
  });

  test("a frame larger than its lane's high-water mark ends the transport even with a reader waiting", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const waiting = transport.recv();
    channel.deliver(
      laneFrame(TAG_CONTROL, CONTROL_LANE_HIGH_WATER_BYTES + 1, 1),
    );
    await expect(waiting).rejects.toThrow("high-water mark");
    expect(channel.readyState).toBe("closed");
  });

  test("a transport created on an already closed channel rejects immediately", async () => {
    const channel = new FakeChannel();
    channel.close();
    const transport = dataChannelTransport(channel.asRtc());
    await expect(transport.recv()).rejects.toThrow("already closed");
    await expect(transport.recvApp()).rejects.toThrow("already closed");
  });

  test("frames delivered before a graceful close are still read", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // A reader mid-message: the first frame goes straight to it, the rest
    // queue, and only then does the peer's close arrive — the order
    // RTCDataChannel guarantees for a peer that sends and then closes.
    const first = transport.recvApp();
    for (const value of [1, 2, 3]) channel.deliver([TAG_APP, value]);
    channel.deliver([TAG_CONTROL, 9]);
    channel.close();

    expect(await first).toEqual(new Uint8Array([1]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([2]));
    expect(await transport.recvApp()).toEqual(new Uint8Array([3]));
    expect(await transport.recv()).toEqual(new Uint8Array([9]));
    // Drained, each lane then reports the close.
    await expect(transport.recvApp()).rejects.toThrow("data channel closed");
    await expect(transport.recv()).rejects.toThrow("data channel closed");
    await expect(transport.sendApp(new Uint8Array([4]))).rejects.toThrow(
      "data channel closed",
    );
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
    await expect(transport.recvApp()).rejects.toThrow("data channel errored");
  });

  test("local abort clears the queues", async () => {
    // On an open channel: both lanes go at once, and the channel is closed.
    const open = new FakeChannel();
    const live = dataChannelTransport(open.asRtc());
    open.deliver([TAG_CONTROL, 1]);
    open.deliver([TAG_APP, 2]);
    live.close();
    await expect(live.recv()).rejects.toThrow("transport closed");
    await expect(live.recvApp()).rejects.toThrow("transport closed");
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
    await expect(ended.recvApp()).rejects.toThrow("data channel closed");
    await expect(ended.recv()).rejects.toThrow("data channel closed");
  });

  test("sender waits when the lane is above its high-water mark", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    // At the mark, a frame still leaves at once.
    channel.bufferedAmount = SEND_HIGH_WATER_BYTES;
    await transport.sendApp(new Uint8Array([1]));
    expect(channel.sent).toHaveLength(1);

    // Above it, frames wait: app and control alike, since both lanes share
    // the channel's one buffer.
    channel.bufferedAmount = SEND_HIGH_WATER_BYTES + 1;
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
    expect(channel.bufferedAmountLowThreshold).toBe(SEND_LOW_WATER_BYTES);
    channel.drainTo(SEND_LOW_WATER_BYTES);
    await Promise.all([app, control]);
    expect(order).toEqual(["app", "control"]);
    expect(channel.sent).toEqual([
      new Uint8Array([TAG_APP, 1]),
      new Uint8Array([TAG_APP, 2]),
      new Uint8Array([TAG_CONTROL, 3]),
    ]);
  });

  test.each(["the channel closes", "the transport is closed locally"] as const)(
    "a send waiting for a drain fails with the provider's error when %s",
    async (how) => {
      const channel = new FakeChannel();
      const transport = dataChannelTransport(channel.asRtc());
      channel.bufferedAmount = SEND_HIGH_WATER_BYTES + 1;
      const waiting = settled(
        Promise.resolve(transport.sendApp(new Uint8Array([7]))),
      );
      await turn();
      if (how === "the channel closes") channel.close();
      else transport.close();

      const outcome = await waiting;
      expect(outcome).toBeInstanceOf(WebRtcProviderError);
      expect(String(outcome)).toContain(
        how === "the channel closes"
          ? "data channel closed"
          : "transport closed",
      );
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
    const refused = await settled(
      Promise.resolve().then(() => transport.sendApp(new Uint8Array([1]))),
    );
    expect(refused).toBeInstanceOf(WebRtcProviderError);
    expect(String(refused)).toContain("send queue is full");
    // The lane's framing is positional, so nothing may follow a lost frame.
    const after = await settled(
      Promise.resolve().then(() => transport.sendApp(new Uint8Array([2]))),
    );
    expect(after).toBeInstanceOf(WebRtcProviderError);
    expect(channel.sent).toHaveLength(0);

    channel.deliver([TAG_APP, 9]);
    expect(await transport.recvApp()).toEqual(new Uint8Array([9]));
  });

  test("a drain reported from inside send() does not reorder frames", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    channel.bufferedAmount = SEND_HIGH_WATER_BYTES + 1;
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
