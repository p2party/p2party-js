import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  WebRtcCandidateProvider,
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

class FakeChannel extends EventTarget {
  binaryType = "arraybuffer";
  readyState = "open";
  peer: FakeChannel | null = null;
  onSend: (() => void) | null = null;
  sent = 0;

  send(bytes: Uint8Array): void {
    this.sent += 1;
    // EventTarget, like RTCDataChannel, does not retain an event for a future
    // listener. This reproduces a HELLO arriving during async getStats().
    this.peer?.dispatchEvent(
      new MessageEvent("message", { data: Uint8Array.from(bytes).buffer }),
    );
    this.onSend?.();
  }

  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }

  asRtc(): RTCDataChannel {
    return this as unknown as RTCDataChannel;
  }
}

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

  test("certificate mismatch sends no protocol data and teardown discards captured bytes", async () => {
    const { alice, bob, a, b } = makeProviders();
    try {
      a.channel.send(new Uint8Array([0, 99]));
      b.statsResult = Promise.resolve(stats(fingerprintB, new Uint8Array(32)));
      await expect(
        bob.verifyCertificates(fingerprintB, fingerprintA),
      ).rejects.toThrow("DTLS fingerprint mismatch");
      expect(b.channel.sent).toBe(0);
      const transport = dataChannelTransport(await bob.channel());
      bob.close();
      await expect(transport.recv()).rejects.toThrow("closed");
      expect(() => transport.sendApp(new Uint8Array([7]))).toThrow("closed");
    } finally {
      alice.close();
      bob.close();
    }
  });

  test("tiny-frame overflow rejects pending receives and clears both bounded queues", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const pending = transport.recvApp();
    for (let i = 0; i < 1025; i += 1)
      channel.dispatchEvent(
        new MessageEvent("message", { data: new Uint8Array([0]).buffer }),
      );
    await expect(pending).rejects.toThrow("queue budget exceeded");
    await expect(transport.recv()).rejects.toThrow("queue budget exceeded");
    expect(channel.readyState).toBe("closed");
  });

  test("aggregate bytes are bounded across lanes", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    const frame = new Uint8Array(8 * 1024 * 1024 + 1);
    channel.dispatchEvent(new MessageEvent("message", { data: frame.buffer }));
    frame[0] = 1;
    channel.dispatchEvent(new MessageEvent("message", { data: frame.buffer }));
    channel.dispatchEvent(
      new MessageEvent("message", { data: new Uint8Array([0, 1]).buffer }),
    );
    await expect(transport.recv()).rejects.toThrow("queue budget exceeded");
    await expect(transport.recvApp()).rejects.toThrow("queue budget exceeded");
    expect(channel.readyState).toBe("closed");
  });

  test("consuming frames releases the queue budget", async () => {
    const channel = new FakeChannel();
    const transport = dataChannelTransport(channel.asRtc());
    for (let i = 0; i < 2050; i += 1) {
      channel.dispatchEvent(
        new MessageEvent("message", {
          data: new Uint8Array([0, i & 0xff]).buffer,
        }),
      );
      const received = await transport.recv();
      if (received[0] !== (i & 0xff))
        throw new Error("FIFO receive changed payload");
    }
    expect(channel.readyState).toBe("open");
    transport.close();
    await expect(transport.recv()).rejects.toThrow("transport closed");
  });

  test("a transport created on an already closed channel rejects immediately", async () => {
    const channel = new FakeChannel();
    channel.close();
    const transport = dataChannelTransport(channel.asRtc());
    await expect(transport.recv()).rejects.toThrow("already closed");
    await expect(transport.recvApp()).rejects.toThrow("already closed");
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
      expect(a.channel.sent).toBe(1);
      expect(b.channel.sent).toBe(0);
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
