import { readFileSync } from "node:fs";

import { afterEach, describe, expect, test } from "bun:test";

import {
  BlindRendezvousRun,
  PrototypeRunTimeoutError,
  PrototypeSessionEndedError,
} from "../../../src/blindRendezvous/prototype/index";
import {
  WebRtcCandidateProvider,
  WebRtcProviderError,
  dataChannelTransport,
} from "../../../src/blindRendezvous/prototype/webrtcProvider";
import { generateSessionIdentity } from "../../../src/session";
import {
  FRAME_TYPE_COVER,
  MAX_BUFFERED_AMOUNT,
  PROTOTYPE_STOP_DRAIN_TIMEOUT_MS,
} from "../../../src/utils/constants";

import type {
  CarrierRuntime,
  CarrierTimers,
} from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type {
  HandoffFacts,
  PairDriver,
} from "../../../src/blindRendezvous/prototype/pairDriver";
import type { GeneratedSessionIdentity } from "../../../src/session";

/*
 * The session half of a run — handoff to `createSession`, `sendMessage`,
 * `recvMessage`, `stop` — on the real `BlindRendezvousRun`, the real
 * `WebRtcCandidateProvider` and real protocol-v4 sessions. Only the browser
 * objects (`RTCPeerConnection`, `RTCDataChannel`) and the clock are fakes.
 */

const wasmFileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(wasmFileBytes.byteLength);
new Uint8Array(wasmBinary).set(wasmFileBytes);

const TAG_CONTROL = 0;
const TAG_APP = 1;
/** Plaintext bytes one uniform protocol-v4 chunk frame carries. */
const CHUNK_PLAINTEXT_BYTES = 65_405;

const FINGERPRINT_INITIATOR = new Uint8Array(32).fill(0x32);
const FINGERPRINT_RESPONDER = new Uint8Array(32).fill(0x33);

/* ------------------------------------------------------------------ *
 * Fakes
 * ------------------------------------------------------------------ */

/** A clock and timers that move only when the test moves them. */
class FakeTime {
  nowMs = 1_800_000_000_000n;
  readonly clock = { nowMs: (): bigint => this.nowMs };
  readonly #pending = new Map<
    number,
    { readonly dueMs: bigint; readonly callback: () => void }
  >();
  #nextId = 1;

  readonly timers: CarrierTimers = {
    setTimeout: (callback, delayMs) => {
      const id = this.#nextId++;
      this.#pending.set(id, {
        dueMs: this.nowMs + BigInt(Math.max(0, Math.trunc(delayMs))),
        callback,
      });
      return id;
    },
    clearTimeout: (handle) => {
      this.#pending.delete(handle as number);
    },
  };

  /** Move to `toMs`, firing each timer due by then, earliest first. */
  advanceTo(toMs: bigint): void {
    for (;;) {
      let due: [number, { dueMs: bigint; callback: () => void }] | null = null;
      for (const entry of this.#pending)
        if (
          entry[1].dueMs <= toMs &&
          (due === null || entry[1].dueMs < due[1].dueMs)
        )
          due = entry;
      if (due === null) break;
      this.#pending.delete(due[0]);
      this.nowMs = due[1].dueMs;
      due[1].callback();
    }
    this.nowMs = toMs;
  }
}

/**
 * One end of an in-memory `RTCDataChannel`. A frame normally reaches the peer
 * inside `send`; with `holding` set it waits in `bufferedAmount` until the
 * test calls `drain` or `release`, which is how a slow path looks to the
 * sender. `close()` is orderly: the peer sees `close` after every frame that
 * had already left, and frames still held are dropped, as
 * `RTCPeerConnection.close()` drops them.
 */
class LinkedChannel extends EventTarget {
  binaryType = "arraybuffer";
  readyState: RTCDataChannelState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  peer: LinkedChannel | null = null;
  /** Every frame this end handed to `send`, in order. */
  readonly sent: Uint8Array[] = [];
  holding = false;
  /** The next `send` throws while the channel stays open, as a refusal does. */
  refuseNextSend = false;
  /** Called with each frame this end is handed, before it travels. */
  onSend: ((frame: Uint8Array) => void) | null = null;
  /** Called with each frame after it has been delivered to this end. */
  onReceive: ((frame: Uint8Array) => void) | null = null;
  readonly #held: Uint8Array[] = [];

  send(bytes: Uint8Array): void {
    if (this.readyState !== "open")
      throw new DOMException("channel is not open", "InvalidStateError");
    if (this.refuseNextSend) {
      this.refuseNextSend = false;
      throw new DOMException("send queue is full", "OperationError");
    }
    const frame = Uint8Array.from(bytes);
    this.sent.push(frame);
    this.onSend?.(frame);
    if (this.holding) {
      this.#held.push(frame);
      this.bufferedAmount += frame.length;
    } else this.peer?.receive(frame);
  }

  receive(frame: Uint8Array): void {
    if (this.readyState !== "open") return;
    this.dispatchEvent(
      new MessageEvent("message", { data: Uint8Array.from(frame).buffer }),
    );
    this.onReceive?.(frame);
  }

  /** Deliver the first `count` held frames, leaving the rest buffered. */
  release(count: number): void {
    for (const frame of this.#held.splice(0, count)) {
      this.bufferedAmount -= frame.length;
      this.peer?.receive(frame);
    }
  }

  /** Deliver every held frame; the emptied buffer fires its event. */
  drain(): void {
    const before = this.bufferedAmount;
    this.release(this.#held.length);
    if (
      before > this.bufferedAmountLowThreshold &&
      this.bufferedAmount <= this.bufferedAmountLowThreshold
    )
      this.dispatchEvent(new Event("bufferedamountlow"));
  }

  /**
   * Held frames never leave once the channel closes; `bufferedAmount` keeps
   * its value, as the specification has it.
   */
  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.#held.length = 0;
    this.dispatchEvent(new Event("close"));
    this.peer?.close();
  }
}

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

interface FakeConnection {
  readonly channel: LinkedChannel;
  statsResult: Promise<RTCStatsReport>;
  ondatachannel: ((event: RTCDataChannelEvent) => void) | null;
  /** As `RTCPeerConnection.close()`: the channel goes with it, at once. */
  close(): void;
}

const originalPeerConnection = globalThis.RTCPeerConnection;
afterEach(() => {
  globalThis.RTCPeerConnection = originalPeerConnection;
});

/* ------------------------------------------------------------------ *
 * Endpoints
 * ------------------------------------------------------------------ */

interface Endpoint {
  readonly run: BlindRendezvousRun;
  readonly connection: FakeConnection;
  readonly channel: LinkedChannel;
  readonly events: { readonly kind: string; readonly detail?: string }[];
  readonly reached: (kind: string) => Promise<string | undefined>;
}

const endpoint = (
  time: FakeTime,
  role: "initiator" | "responder",
  provider: WebRtcCandidateProvider,
  connection: FakeConnection,
  identity: GeneratedSessionIdentity,
  peer: GeneratedSessionIdentity,
): Endpoint => {
  const events: { readonly kind: string; readonly detail?: string }[] = [];
  const waiters: {
    readonly kind: string;
    readonly resolve: (detail: string | undefined) => void;
  }[] = [];
  const handoff: HandoffFacts = {
    rendezvousChannelId: new Uint8Array(32).fill(0x31),
    localFingerprint:
      role === "initiator" ? FINGERPRINT_INITIATOR : FINGERPRINT_RESPONDER,
    remoteFingerprint:
      role === "initiator" ? FINGERPRINT_RESPONDER : FINGERPRINT_INITIATOR,
    sessionRole: role,
    rendezvousRole: role,
    peerStableEd25519PublicKey: peer.ed25519PublicKey,
    stableEdgeId: new Uint8Array(32).fill(0x34),
  };
  const run = new BlindRendezvousRun({
    // The run reads only `handoff`; the pair exchange is not under test.
    driver: { handoff } as unknown as PairDriver,
    // The run calls only `stop()`; the carrier schedule is not under test.
    runtime: { stop: () => undefined } as unknown as CarrierRuntime,
    transport: { provider, close: () => provider.close() },
    identity,
    pqMode: "hybrid-mlkem768",
    wasmBinary,
    handshakeTimeoutMs: 60_000,
    clock: time.clock,
    timers: time.timers,
    emit: (kind, detail) => {
      events.push({ kind, detail });
      for (const waiter of waiters.splice(0))
        if (waiter.kind === kind) waiter.resolve(detail);
        else waiters.push(waiter);
    },
  });
  return {
    run,
    connection,
    channel: connection.channel,
    events,
    reached: (kind) => {
      const seen = events.find((event) => event.kind === kind);
      if (seen !== undefined) return Promise.resolve(seen.detail);
      return new Promise((resolve) => waiters.push({ kind, resolve }));
    },
  };
};

interface Pair {
  readonly initiator: Endpoint;
  readonly responder: Endpoint;
  stop(): void;
}

/** Two endpoints whose providers share one in-memory data channel. */
const pair = async (time: FakeTime): Promise<Pair> => {
  const [initiatorIdentity, responderIdentity] = await Promise.all([
    generateSessionIdentity({ wasmBinary }),
    generateSessionIdentity({ wasmBinary }),
  ]);
  const connections: FakeConnection[] = [];
  class FakePeerConnection extends EventTarget implements FakeConnection {
    readonly connectionState: RTCPeerConnectionState = "connected";
    ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
    readonly channel = new LinkedChannel();
    statsResult: Promise<RTCStatsReport> = Promise.reject(
      new Error("no stats configured"),
    );
    constructor() {
      super();
      void this.statsResult.catch(() => undefined);
      connections.push(this);
    }
    createDataChannel(): RTCDataChannel {
      return this.channel as unknown as RTCDataChannel;
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
  const initiatorProvider = new WebRtcCandidateProvider({
    role: "initiator",
    rtcConfig: {},
  });
  const responderProvider = new WebRtcCandidateProvider({
    role: "responder",
    rtcConfig: {},
  });
  const [forInitiator, forResponder] = connections;
  forInitiator.channel.peer = forResponder.channel;
  forResponder.channel.peer = forInitiator.channel;
  forResponder.ondatachannel?.({
    channel: forResponder.channel as unknown as RTCDataChannel,
  } as RTCDataChannelEvent);
  forInitiator.statsResult = Promise.resolve(
    stats(FINGERPRINT_INITIATOR, FINGERPRINT_RESPONDER),
  );
  forResponder.statsResult = Promise.resolve(
    stats(FINGERPRINT_RESPONDER, FINGERPRINT_INITIATOR),
  );
  const initiator = endpoint(
    time,
    "initiator",
    initiatorProvider,
    forInitiator,
    initiatorIdentity,
    responderIdentity,
  );
  const responder = endpoint(
    time,
    "responder",
    responderProvider,
    forResponder,
    responderIdentity,
    initiatorIdentity,
  );
  return {
    initiator,
    responder,
    stop: () => {
      initiator.run.stop();
      responder.run.stop();
    },
  };
};

/** A pair that has reached `session-authenticated` on both ends. */
const connected = async (time: FakeTime): Promise<Pair> => {
  const both = await pair(time);
  both.initiator.run.handlePhase("handoff");
  both.responder.run.handlePhase("handoff");
  await both.initiator.reached("session-authenticated");
  await both.responder.reached("session-authenticated");
  return both;
};

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

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

const kinds = (subject: Endpoint): string[] =>
  subject.events.map((event) => event.kind);

/** The provider reason an error carries, or "none". */
const reasonOf = (error: unknown): string =>
  error instanceof WebRtcProviderError ? error.reason : "none";

/**
 * How the endpoint's session attempt ended, whichever way it went, so a test
 * that expects one outcome fails on the other instead of waiting for ever.
 */
const sessionOutcome = (
  subject: Endpoint,
): Promise<{ readonly kind: string; readonly detail?: string }> =>
  Promise.race(
    ["session-failed", "session-authenticated"].map((kind) =>
      subject.reached(kind).then((detail) => ({ kind, detail })),
    ),
  );

const appFrames = (channel: LinkedChannel): Uint8Array[] =>
  channel.sent.filter((frame) => frame[0] === TAG_APP);

/**
 * Settles once `channel` has been handed its first app frame and the hand-off
 * that frame belongs to has returned: encryption takes several turns, so a
 * fixed number of turns is not a wait for it.
 */
/**
 * How `promise` stands after one macrotask turn: settled, or "still pending".
 * A receive that should fail at once is read this way, so a regression that
 * leaves it waiting fails the test instead of hanging it.
 */
const afterOneTurn = async <T>(
  promise: Promise<T>,
): Promise<T | Error | "still pending"> => {
  let outcome: T | Error | "still pending" = "still pending";
  void settled(promise).then((value) => {
    outcome = value;
  });
  await turn();
  return outcome;
};

/** An app-lane header `[u32be rootLength][root][u32be frameCount]`, plus `extra` bytes. */
const headerBytes = (
  rootLength: number,
  frameCount: number,
  extra = 0,
): Uint8Array => {
  const header = new Uint8Array(4 + rootLength + 4 + extra);
  const view = new DataView(header.buffer);
  view.setUint32(0, rootLength, false);
  view.setUint32(4 + rootLength, frameCount, false);
  return header;
};

const firstAppFrame = (channel: LinkedChannel): Promise<void> =>
  new Promise((resolve) => {
    channel.onSend = (frame) => {
      if (frame[0] !== TAG_APP) return;
      channel.onSend = null;
      resolve();
    };
  });

const text = (value: string): Uint8Array => new TextEncoder().encode(value);

/** `length` bytes that differ from frame to frame. */
const pattern = (length: number): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => (index * 31 + 7) & 0xff);

/* ------------------------------------------------------------------ *
 * Tests
 * ------------------------------------------------------------------ */

describe("prototype run session", () => {
  test("a send that misses its deadline after encryption is not sent and the next message still decrypts", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      // The session exists, so the wait for it settles without any timer
      // firing; the one clock read left in sendMessage is the check after
      // encryption. A clock moved past the deadline now is past it then.
      const missed = settled(
        initiator.run.sendMessage(text("missed its deadline"), 10),
      );
      time.nowMs += 11n;
      const outcome = await missed;
      expect(outcome).toBeInstanceOf(PrototypeRunTimeoutError);
      expect(String(outcome)).toContain(
        "sendMessage did not complete within 10ms",
      );
      expect(appFrames(initiator.channel)).toHaveLength(0);
      expect(kinds(initiator)).not.toContain("message-sent");

      // Encryption advanced the sending chain for a message that never left;
      // the receiver must take the next one anyway.
      await initiator.run.sendMessage(text("the next message"), 1_000);
      expect(
        new TextDecoder().decode(await responder.run.recvMessage(1_000)),
      ).toBe("the next message");
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a message the peer sent before stopping its run is still received", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      const payload = pattern(3 * CHUNK_PLAINTEXT_BYTES + 7);
      await initiator.run.sendMessage(payload, 1_000);
      // A header and four chunk frames, all delivered, then an orderly close.
      expect(appFrames(initiator.channel)).toHaveLength(5);
      initiator.run.stop();
      expect(responder.channel.readyState).toBe("closed");

      // A send that meets the closed channel reports the close and ends
      // nothing here: what the peer delivered stays readable.
      const reply = await settled(
        responder.run.sendMessage(text("too late"), 1_000),
      );
      expect(reasonOf(reply)).toBe("closed");
      expect(kinds(responder)).not.toContain("session-failed");

      expect(await responder.run.recvMessage(1_000)).toEqual(payload);
      const after = await settled(responder.run.recvMessage(1_000));
      expect(reasonOf(after)).toBe("closed");
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a graceful stop delivers frames still in the send buffer", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      const payload = pattern(2 * CHUNK_PLAINTEXT_BYTES + 1);
      initiator.channel.holding = true;
      // sendMessage resolves at the hand-off: the frames are in the buffer.
      await initiator.run.sendMessage(payload, 1_000);
      expect(initiator.channel.bufferedAmount).toBeGreaterThan(0);

      let outcome: unknown = "still pending";
      const stopping = Promise.resolve(initiator.run.stop()).then((value) => {
        outcome = value;
      });
      await turn();
      // The run is stopped; its channel waits for the buffer to empty.
      expect(kinds(initiator)).toContain("run-stopped");
      expect(outcome).toBe("still pending");
      expect(initiator.channel.readyState).toBe("open");

      initiator.channel.drain();
      await stopping;
      expect(outcome).toBe("drained");
      expect(initiator.channel.readyState).toBe("closed");
      expect(await responder.run.recvMessage(1_000)).toEqual(payload);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a stop whose buffer never drains closes after the timeout and reports it", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      initiator.channel.holding = true;
      await initiator.run.sendMessage(text("never leaves"), 1_000);

      let outcome: unknown = "still pending";
      void Promise.resolve(initiator.run.stop()).then((value) => {
        outcome = value;
      });
      const stoppedAt = time.nowMs;
      const timeoutMs = BigInt(PROTOTYPE_STOP_DRAIN_TIMEOUT_MS);
      time.advanceTo(stoppedAt + timeoutMs - 1n);
      await turn();
      expect(outcome).toBe("still pending");
      expect(initiator.channel.readyState).toBe("open");

      time.advanceTo(stoppedAt + timeoutMs);
      await turn();
      expect(outcome).toBe("undrained");
      expect(initiator.channel.readyState).toBe("closed");
      expect(
        initiator.events.find((event) => event.kind === "stop-undrained")
          ?.detail,
      ).toContain(`within ${String(PROTOTYPE_STOP_DRAIN_TIMEOUT_MS)}ms`);
      // The peer never gets the message: the close reaches it instead.
      const received = await settled(responder.run.recvMessage(1_000));
      expect(reasonOf(received)).toBe("closed");
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a read that times out does not consume the next frame", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      // Nothing has been sent: the read waits on the header, and its deadline
      // passes with nothing taken.
      const early = settled(responder.run.recvMessage(100));
      await turn();
      time.advanceTo(time.nowMs + 100n);
      const outcome = await early;
      expect(outcome).toBeInstanceOf(PrototypeRunTimeoutError);
      expect(String(outcome)).toContain("application message header");
      expect(kinds(responder)).not.toContain("session-failed");

      // The message sent next is read whole, header first, by the next call.
      const payload = pattern(CHUNK_PLAINTEXT_BYTES + 1);
      await initiator.run.sendMessage(payload, 1_000);
      expect(await responder.run.recvMessage(1_000)).toEqual(payload);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a read that times out mid-message ends the session", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      initiator.channel.holding = true;
      await initiator.run.sendMessage(
        pattern(2 * CHUNK_PLAINTEXT_BYTES + 1),
        1_000,
      );
      expect(appFrames(initiator.channel)).toHaveLength(4);
      // The header and one chunk arrive; the rest is still on the way when
      // the reader's deadline passes.
      initiator.channel.release(2);
      const reading = settled(responder.run.recvMessage(100));
      await turn();
      time.advanceTo(time.nowMs + 100n);
      const outcome = await reading;

      expect(outcome).toBeInstanceOf(PrototypeSessionEndedError);
      expect((outcome as Error).cause).toBeInstanceOf(PrototypeRunTimeoutError);
      expect(await responder.reached("session-failed")).toContain(
        "2 of the message's 4 frames taken",
      );
      expect(responder.channel.readyState).toBe("closed");
      // Every later call on that session reports the same end.
      expect(await settled(responder.run.recvMessage(1_000))).toBe(
        outcome as Error,
      );
      expect(
        await settled(responder.run.sendMessage(text("after"), 1_000)),
      ).toBe(outcome as Error);
    } finally {
      both.stop();
    }
  }, 30_000);

  test.each([
    ["shorter than its two length fields", () => new Uint8Array(7)],
    [
      "whose length disagrees with its root length",
      () => headerBytes(64, 1, 1),
    ],
    ["whose root is not a SHA-512 digest", () => headerBytes(32, 1)],
    ["that announces no frames", () => headerBytes(64, 0)],
    ["that announces too many frames", () => headerBytes(64, 0xffff_ffff)],
  ] as const)(
    "a malformed header ends the session with a protocol-violation reason (one %s)",
    async (_shape, header) => {
      const time = new FakeTime();
      const both = await connected(time);
      const { responder } = both;
      try {
        // Where the next message's header belongs, the lane carries this.
        responder.channel.receive(Uint8Array.of(TAG_APP, ...header()));
        const outcome = await afterOneTurn(responder.run.recvMessage(1_000));

        expect(outcome).toBeInstanceOf(PrototypeSessionEndedError);
        expect((outcome as PrototypeSessionEndedError).reason).toBe("protocol");
        expect(await responder.reached("session-failed")).toContain(
          "the app lane cannot be framed past it",
        );
        expect(responder.channel.readyState).toBe("closed");
        expect(await settled(responder.run.recvMessage(1_000))).toBe(
          outcome as Error,
        );
      } finally {
        both.stop();
      }
    },
    30_000,
  );

  test.each([
    ["a frame shorter than a chunk frame", "truncated"],
    ["a frame that is not a chunk frame", "cover"],
    ["a chunk frame of another message", "foreign"],
  ] as const)(
    "%s in a message's place ends the session with a protocol-violation reason",
    async (_label, kind) => {
      const time = new FakeTime();
      const both = await connected(time);
      const { initiator, responder } = both;
      try {
        initiator.channel.holding = true;
        await initiator.run.sendMessage(
          pattern(2 * CHUNK_PLAINTEXT_BYTES + 1),
          1_000,
        );
        await initiator.run.sendMessage(text("the next message"), 1_000);
        // [header, chunk 0, 1, 2] of the first message, [header, chunk 0] of
        // the second; each still carries its one-byte lane tag.
        const [header, first, , , , nextChunk] = appFrames(initiator.channel);
        responder.channel.receive(header);
        responder.channel.receive(first);
        // Where the first message's chunk 1 belongs, the lane carries this:
        // a chunk frame cut short, one whose type is not a chunk's, or the
        // second message's chunk, whole and valid but under another header.
        const wrong = Uint8Array.from(
          kind === "truncated"
            ? first.subarray(0, 1 + 100)
            : kind === "foreign"
              ? nextChunk
              : first,
        );
        if (kind === "cover") wrong[1] = FRAME_TYPE_COVER;
        responder.channel.receive(wrong);
        const outcome = await afterOneTurn(responder.run.recvMessage(1_000));

        expect(outcome).toBeInstanceOf(PrototypeSessionEndedError);
        expect((outcome as PrototypeSessionEndedError).reason).toBe("protocol");
        expect(await responder.reached("session-failed")).toContain("frame 1 ");
        expect(responder.channel.readyState).toBe("closed");
        expect(kinds(responder)).not.toContain("message-verified");
      } finally {
        both.stop();
      }
    },
    30_000,
  );

  test("a frame the channel refuses ends the session", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator } = both;
    try {
      initiator.channel.refuseNextSend = true;
      const outcome = await settled(
        initiator.run.sendMessage(text("refused"), 1_000),
      );
      expect(outcome).toBeInstanceOf(PrototypeSessionEndedError);
      expect(reasonOf((outcome as Error).cause)).toBe("refused");
      expect(await initiator.reached("session-failed")).toContain("refused");
      // The edge is closed rather than left open with its lane misframed.
      expect(initiator.channel.readyState).toBe("closed");
      expect(
        await settled(initiator.run.sendMessage(text("after"), 1_000)),
      ).toBe(outcome as Error);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a stop during certificate verification starts no handshake", async () => {
    const time = new FakeTime();
    const both = await pair(time);
    const { initiator } = both;
    let releaseStats!: (report: RTCStatsReport) => void;
    initiator.connection.statsResult = new Promise((resolve) => {
      releaseStats = resolve;
    });
    try {
      initiator.run.handlePhase("handoff");
      // From here verifyCertificates waits on getStats().
      await initiator.reached("webrtc-connected");
      initiator.run.stop();
      releaseStats(stats(FINGERPRINT_INITIATOR, FINGERPRINT_RESPONDER));

      expect(await initiator.reached("session-failed")).toContain(
        "the run stopped during certificate verification",
      );
      expect(kinds(initiator)).not.toContain("dtls-verified");
      expect(initiator.channel.sent).toHaveLength(0);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a stop during session authentication publishes no session", async () => {
    const time = new FakeTime();
    const both = await pair(time);
    const { initiator, responder } = both;
    // The initiator's last handshake input is the responder's FINISH, its
    // third control frame. Stopping as it lands leaves the handshake to finish
    // its cryptography after the teardown.
    let controlFrames = 0;
    initiator.channel.onReceive = (frame) => {
      if (frame[0] === TAG_CONTROL && (controlFrames += 1) === 3)
        initiator.run.stop();
    };
    try {
      initiator.run.handlePhase("handoff");
      responder.run.handlePhase("handoff");

      const outcome = await sessionOutcome(initiator);
      expect(outcome.kind).toBe("session-failed");
      expect(outcome.detail).toContain(
        "the run stopped during session authentication",
      );
      expect(controlFrames).toBe(3);
      const send = await settled(
        initiator.run.sendMessage(text("late"), 1_000),
      );
      expect(String(send)).toContain(
        "the run stopped during session authentication",
      );
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a data channel that closed before the handoff fails the session at once", async () => {
    const time = new FakeTime();
    const both = await pair(time);
    const { initiator, responder } = both;
    try {
      responder.channel.close();
      expect(initiator.channel.readyState).toBe("closed");
      initiator.run.handlePhase("handoff");
      // No timer fires: the clock never moves in this test.
      await turn();
      const failed = initiator.events.find(
        (event) => event.kind === "session-failed",
      );
      expect(failed?.detail).toContain(
        "the bootstrap data channel closed before it opened",
      );
    } finally {
      both.stop();
    }
  }, 30_000);

  test.each(["verified", "mismatched"] as const)(
    "a certificate mismatch ends the session before any protocol byte is sent (%s)",
    async (verdict) => {
      const time = new FakeTime();
      const both = await pair(time);
      const { initiator, responder } = both;
      if (verdict === "mismatched")
        responder.connection.statsResult = Promise.resolve(
          stats(FINGERPRINT_RESPONDER, new Uint8Array(32)),
        );
      const helloArrived = new Promise<void>((resolve) => {
        responder.channel.onReceive = () => resolve();
      });
      try {
        // The initiator speaks first; its HELLO is buffered for a responder
        // that has not reached its own handoff yet.
        initiator.run.handlePhase("handoff");
        await helloArrived;
        responder.run.handlePhase("handoff");

        const outcome = await sessionOutcome(responder);
        if (verdict === "verified") {
          // The control: this observation does see a responder that speaks.
          expect(outcome.kind).toBe("session-authenticated");
          expect(responder.channel.sent.length).toBeGreaterThan(0);
          return;
        }
        expect(outcome.kind).toBe("session-failed");
        expect(outcome.detail).toContain("DTLS fingerprint mismatch");
        expect(responder.channel.sent).toHaveLength(0);
        // The buffered HELLO went with the session.
        const leftover = await settled(
          dataChannelTransport(
            responder.channel as unknown as RTCDataChannel,
          ).recv(),
        );
        expect(leftover).toBeInstanceOf(WebRtcProviderError);
      } finally {
        both.stop();
      }
    },
    30_000,
  );

  test("a message above the send high-water mark leaves as the channel drains and arrives whole", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      const payload = pattern(20 * CHUNK_PLAINTEXT_BYTES);
      initiator.channel.holding = true;
      const leaving = firstAppFrame(initiator.channel);
      let done = false;
      const sending = initiator.run.sendMessage(payload, 60_000).then(() => {
        done = true;
      });
      await leaving;
      await turn();
      // The channel took frames until its buffer passed the mark, then no more.
      const firstBatch = appFrames(initiator.channel);
      const last = firstBatch[firstBatch.length - 1];
      expect(initiator.channel.bufferedAmount).toBeGreaterThan(
        MAX_BUFFERED_AMOUNT,
      );
      expect(
        initiator.channel.bufferedAmount - last.length,
      ).toBeLessThanOrEqual(MAX_BUFFERED_AMOUNT);
      expect(done).toBe(false);

      let drains = 0;
      while (!done && drains < 64) {
        initiator.channel.drain();
        drains += 1;
        await turn();
      }
      await sending;
      expect(drains).toBeGreaterThan(0);
      expect(firstBatch.length).toBeLessThan(
        appFrames(initiator.channel).length,
      );
      initiator.channel.drain();
      expect(await responder.run.recvMessage(1_000)).toEqual(payload);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("two overlapping sends arrive as two whole messages, in order", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator, responder } = both;
    try {
      // The first message is large enough to wait on the channel, so the
      // second call's frames queue while the first's are still leaving.
      const first = pattern(20 * CHUNK_PLAINTEXT_BYTES);
      const second = pattern(CHUNK_PLAINTEXT_BYTES + 1).reverse();
      initiator.channel.holding = true;
      // The run's own transport, watched: a header is the one short app
      // frame, so the second header means both messages are queued.
      const transport = dataChannelTransport(
        initiator.channel as unknown as RTCDataChannel,
      );
      const sendApp = transport.sendApp;
      let headers = 0;
      const bothQueued = new Promise<void>((resolve) => {
        transport.sendApp = (bytes) => {
          const leaving = sendApp(bytes);
          if (bytes.length < 1_024 && (headers += 1) === 2) resolve();
          return leaving;
        };
      });
      let done = false;
      const sending = Promise.all([
        initiator.run.sendMessage(first, 60_000),
        initiator.run.sendMessage(second, 60_000),
      ]).then(() => {
        done = true;
      });
      await bothQueued;
      await turn();
      expect(done).toBe(false);
      for (let drains = 0; !done && drains < 64; drains += 1) {
        initiator.channel.drain();
        await turn();
      }
      await sending;
      initiator.channel.drain();
      expect(await responder.run.recvMessage(1_000)).toEqual(first);
      expect(await responder.run.recvMessage(1_000)).toEqual(second);
    } finally {
      both.stop();
    }
  }, 30_000);

  test("a deadline that passes while a message is leaving ends the session", async () => {
    const time = new FakeTime();
    const both = await connected(time);
    const { initiator } = both;
    try {
      initiator.channel.holding = true;
      // The run's own transport, watched: the second header queued means the
      // overlapping call's whole message is waiting behind the first.
      const transport = dataChannelTransport(
        initiator.channel as unknown as RTCDataChannel,
      );
      const sendApp = transport.sendApp;
      let headers = 0;
      const bothQueued = new Promise<void>((resolve) => {
        transport.sendApp = (bytes) => {
          const queued = sendApp(bytes);
          if (bytes.length < 1_024 && (headers += 1) === 2) resolve();
          return queued;
        };
      });
      const sending = settled(
        initiator.run.sendMessage(pattern(20 * CHUNK_PLAINTEXT_BYTES), 50),
      );
      const overlapping = settled(
        initiator.run.sendMessage(text("queued behind"), 60_000),
      );
      await bothQueued;
      await turn();
      // The hand-off stopped at the mark with the rest of both messages
      // waiting; none of the second call's frames has left.
      const handedOff = initiator.channel.sent.length;
      const batch = appFrames(initiator.channel);
      expect(
        initiator.channel.bufferedAmount - batch[batch.length - 1].length,
      ).toBeLessThanOrEqual(MAX_BUFFERED_AMOUNT);
      expect(batch.filter((frame) => frame.length < 1_024 + 1).length).toBe(1);

      // The channel never drains, and the first deadline passes.
      let outcome: unknown = "still pending";
      void sending.then((value) => {
        outcome = value;
      });
      time.advanceTo(time.nowMs + 50n);
      await turn();
      expect(outcome).toBeInstanceOf(PrototypeSessionEndedError);
      expect((outcome as Error).cause).toBeInstanceOf(PrototypeRunTimeoutError);
      expect(await initiator.reached("session-failed")).toContain(
        "the session was ended",
      );
      // The overlapping call fails with the same typed end, not a raw error
      // from the transport its frames were waiting on.
      expect(await overlapping).toBe(outcome as Error);
      // What had not left never leaves, and the edge is closed.
      expect(initiator.channel.readyState).toBe("closed");
      expect(initiator.channel.sent).toHaveLength(handedOff);
      expect(
        await settled(initiator.run.sendMessage(text("next"), 1_000)),
      ).toBe(outcome as Error);
    } finally {
      both.stop();
    }
  }, 30_000);
});
