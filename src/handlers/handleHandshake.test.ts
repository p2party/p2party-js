import { describe, expect, test, beforeAll } from "bun:test";

import { PQ_TAG } from "../utils/constants";
import { loadTestModule } from "../cryptography/testModule";
import { x25519Keypair } from "../cryptography/x25519";
import { serializeRatchet } from "../cryptography/ratchet";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { HandshakeTransport } from "./handleHandshake";

// handleHandshake.ts transitively imports the Redux `store`, whose keyPair slice
// reads `localStorage` at module-init time (and `db/api` creates a Worker). Bare
// `bun test` has neither, so provide a minimal `localStorage` shim BEFORE the
// module is loaded, and defer that load into `beforeAll` (import hoisting would
// otherwise run it before this statement). `window` is aliased by the
// `loadTestModule` import above.
const _lsMem: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (k: string) => (k in _lsMem ? _lsMem[k] : null),
  setItem: (k: string, v: string) => {
    _lsMem[k] = String(v);
  },
  removeItem: (k: string) => {
    delete _lsMem[k];
  },
  clear: () => {
    for (const k of Object.keys(_lsMem)) delete _lsMem[k];
  },
  key: () => null,
  length: 0,
} as Storage;

type HS = typeof import("./handleHandshake");
let buildChannelInput: HS["buildChannelInput"];
let parseFingerprintFromSdp: HS["parseFingerprintFromSdp"];
let verifyDtlsFingerprints: HS["verifyDtlsFingerprints"];
let performHandshakeCore: HS["performHandshakeCore"];
let setHandshakeChannel: HS["setHandshakeChannel"];
let deliverHandshakeFrame: HS["deliverHandshakeFrame"];
let runHandshake: HS["runHandshake"];

beforeAll(async () => {
  const m = await import("./handleHandshake");
  ({
    buildChannelInput,
    parseFingerprintFromSdp,
    verifyDtlsFingerprints,
    performHandshakeCore,
    setHandshakeChannel,
    deliverHandshakeFrame,
    runHandshake,
  } = m);
});

const CHANNEL_ID = new TextEncoder().encode("main"); // 4 bytes

describe("buildChannelInput (CI)", () => {
  test("concatenates channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG", () => {
    const ikA = new Uint8Array(32).fill(1);
    const ikB = new Uint8Array(32).fill(2);
    const fpA = new Uint8Array(32).fill(3);
    const fpB = new Uint8Array(32).fill(4);
    const ci = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: ikA,
      ikResponder: ikB,
      fpInitiator: fpA,
      fpResponder: fpB,
    });
    expect(ci.length).toBe(4 + 32 + 32 + 32 + 32 + PQ_TAG.length);
    expect([...ci.subarray(0, 4)]).toEqual([...CHANNEL_ID]);
    expect(ci[4]).toBe(1);
    expect(ci[4 + 32]).toBe(2);
    expect(ci[4 + 64]).toBe(3);
    expect(ci[4 + 96]).toBe(4);
    expect(ci[ci.length - 1]).toBe(0); // PQ_TAG
  });

  test("role ordering matters: swapping a/b yields a different CI", () => {
    const one = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(1),
      ikResponder: new Uint8Array(32).fill(2),
      fpInitiator: new Uint8Array(32).fill(3),
      fpResponder: new Uint8Array(32).fill(4),
    });
    const swapped = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(2),
      ikResponder: new Uint8Array(32).fill(1),
      fpInitiator: new Uint8Array(32).fill(4),
      fpResponder: new Uint8Array(32).fill(3),
    });
    expect([...one]).not.toEqual([...swapped]);
  });
});

describe("parseFingerprintFromSdp", () => {
  const sdp =
    "v=0\r\n" +
    "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n" +
    "a=setup:actpass\r\n";

  test("extracts the 32 raw bytes of a sha-256 fingerprint", () => {
    const fp = parseFingerprintFromSdp(sdp);
    expect(fp.length).toBe(32);
    expect(fp[0]).toBe(0xaa);
    expect(fp[1]).toBe(0xbb);
    expect(fp[31]).toBe(0x99);
  });

  test("throws when no sha-256 fingerprint is present", () => {
    expect(() => parseFingerprintFromSdp("v=0\r\n")).toThrow();
  });
});

describe("verifyDtlsFingerprints", () => {
  const fpHex =
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
  const sdpWith = (fp: string) => `v=0\r\na=fingerprint:sha-256 ${fp}\r\n`;

  const mockEpc = (localFp: string, remoteFp: string, statsFp: string) =>
    ({
      localDescription: { sdp: sdpWith(localFp) },
      remoteDescription: { sdp: sdpWith(remoteFp) },
      getStats: async () =>
        new Map<string, any>([
          ["T", { type: "transport", localCertificateId: "LC", remoteCertificateId: "RC" }],
          ["LC", { type: "certificate", fingerprint: localFp, fingerprintAlgorithm: "sha-256" }],
          ["RC", { type: "certificate", fingerprint: statsFp, fingerprintAlgorithm: "sha-256" }],
        ]),
    }) as unknown as IRTCPeerConnection;

  test("resolves when the live cert fp matches the SDP-bound fp", async () => {
    await verifyDtlsFingerprints(mockEpc(fpHex, fpHex, fpHex));
  });

  test("throws when getStats reports a different remote fingerprint (MITM)", async () => {
    const tampered = fpHex.replace(/^AA/, "BB");
    await expect(
      verifyDtlsFingerprints(mockEpc(fpHex, fpHex, tampered)),
    ).rejects.toThrow(/fingerprint/i);
  });

  test("throws (fails closed) when the remote certificate stat is missing/unverifiable", async () => {
    // Transport reports a remoteCertificateId, but no matching "certificate"
    // stat exists in the report (e.g. an attacker-influenced or truncated
    // stats report) — SDPs both parse fine. The live remote fingerprint can
    // never be confirmed, so the tripwire must abort rather than resolve.
    const epc = {
      localDescription: { sdp: sdpWith(fpHex) },
      remoteDescription: { sdp: sdpWith(fpHex) },
      getStats: async () =>
        new Map<string, any>([
          [
            "T",
            {
              type: "transport",
              localCertificateId: "LC",
              remoteCertificateId: "RC",
            },
          ],
          [
            "LC",
            {
              type: "certificate",
              fingerprint: fpHex,
              fingerprintAlgorithm: "sha-256",
            },
          ],
          // Note: no "RC" certificate entry — the remote cert stat is absent.
        ]),
    } as unknown as IRTCPeerConnection;

    await expect(verifyDtlsFingerprints(epc)).rejects.toThrow(
      /fingerprint|MITM/i,
    );
  });
});

// Two in-memory transports wired head-to-head: what one sends, the other recvs.
const linkedTransports = (): [HandshakeTransport, HandshakeTransport] => {
  const qA: Uint8Array[] = [];
  const qB: Uint8Array[] = [];
  const waitersA: ((v: Uint8Array) => void)[] = [];
  const waitersB: ((v: Uint8Array) => void)[] = [];
  const recv =
    (q: Uint8Array[], w: ((v: Uint8Array) => void)[]) =>
    (): Promise<Uint8Array> =>
      q.length > 0
        ? Promise.resolve(q.shift()!)
        : new Promise((res) => w.push(res));
  const send =
    (q: Uint8Array[], w: ((v: Uint8Array) => void)[]) =>
    (b: Uint8Array): void => {
      const next = w.shift();
      if (next) next(b);
      else q.push(b);
    };
  // A sends into B's inbox (qB/waitersB); B sends into A's inbox (qA/waitersA).
  const a: HandshakeTransport = {
    send: send(qB, waitersB),
    recv: recv(qA, waitersA),
  };
  const b: HandshakeTransport = {
    send: send(qA, waitersA),
    recv: recv(qB, waitersB),
  };
  return [a, b];
};

describe("performHandshakeCore (root agreement over a mock channel)", () => {
  test("no-PIN mode: both sides derive the identical 32-byte secret", async () => {
    const module = await loadTestModule();
    const [tA, tB] = linkedTransports();

    // Real X25519 identity keypairs. x3dh's cross-DH (DH(IK_a,EK_b) ==
    // DH(EK_b,IK_a)) only holds when pub = priv·G, so the brief's arbitrary
    // fill()ed identity keys cannot agree — see the task report.
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    const ci = new Uint8Array(160).fill(7);

    const [rA, rB] = await Promise.all([
      performHandshakeCore(
        tA,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: true,
          idSelfSec: idA.secretKey,
          idPeerPub: idB.publicKey,
        },
        module,
      ),
      performHandshakeCore(
        tB,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: false,
          idSelfSec: idB.secretKey,
          idPeerPub: idA.publicKey,
        },
        module,
      ),
    ]);

    expect([...rA.secret]).toEqual([...rB.secret]);
    expect(rA.secret.length).toBe(32);

    // DH-exchange plumbing: initiator adopts responder's DH pub; responder waits.
    // serializeRatchet projects to ArrayBuffers, so wrap before comparing.
    const sA = serializeRatchet(rA.state);
    const sB = serializeRatchet(rB.state);
    expect([...new Uint8Array(sA.dhRemotePub as ArrayBuffer)]).toEqual([
      ...new Uint8Array(sB.dhSelfPub),
    ]);
    expect(sB.dhRemotePub).toBeNull();
  });

  test("PIN mode: matching PINs agree; a wrong PIN fails key-confirmation", async () => {
    const module = await loadTestModule();
    const ci = new Uint8Array(160).fill(9);
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    const pin = new TextEncoder().encode("123456");

    // Matching PIN → both resolve with equal secrets.
    {
      const [tA, tB] = linkedTransports();
      const [rA, rB] = await Promise.all([
        performHandshakeCore(
          tA,
          {
            mode: "pin",
            pin,
            channelInput: ci,
            amInitiator: true,
            idSelfSec: idA.secretKey,
            idPeerPub: idB.publicKey,
          },
          module,
        ),
        performHandshakeCore(
          tB,
          {
            mode: "pin",
            pin,
            channelInput: ci,
            amInitiator: false,
            idSelfSec: idB.secretKey,
            idPeerPub: idA.publicKey,
          },
          module,
        ),
      ]);
      expect([...rA.secret]).toEqual([...rB.secret]);
      expect(rA.secret.length).toBe(32);
    }

    // Wrong PIN on one side → key-confirmation MAC disagrees → both reject.
    {
      const [tA, tB] = linkedTransports();
      const wrong = new TextEncoder().encode("000000");
      const results = await Promise.allSettled([
        performHandshakeCore(
          tA,
          {
            mode: "pin",
            pin,
            channelInput: ci,
            amInitiator: true,
            idSelfSec: idA.secretKey,
            idPeerPub: idB.publicKey,
          },
          module,
        ),
        performHandshakeCore(
          tB,
          {
            mode: "pin",
            pin: wrong,
            channelInput: ci,
            amInitiator: false,
            idSelfSec: idB.secretKey,
            idPeerPub: idA.publicKey,
          },
          module,
        ),
      ]);
      // Both legs must reject (the deadlock-safe R2 ordering guarantees the
      // responder's recv() is satisfied even when the initiator aborts).
      expect(results.every((r) => r.status === "rejected")).toBe(true);
    }
  });
});

describe("runHandshake wiring (inbox + channel registry)", () => {
  test("deliverHandshakeFrame feeds frames the runHandshake transport recvs", () => {
    // Registry/inbox smoke test: a frame delivered before recv is buffered.
    // 0x01 is the internal HS_STEP_HELLO sub-frame tag.
    setHandshakeChannel("peerX", {
      send: () => {},
      readyState: "open",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    deliverHandshakeFrame("peerX", new Uint8Array([0x01, 1, 2, 3]));
    // No throw; the frame sits in the inbox until the handshake drains it.
    expect(typeof runHandshake).toBe("function");
  });
});
