import { describe, expect, test, beforeAll } from "bun:test";

import { PQ_TAG } from "../../src/utils/constants";
import { loadTestModule } from "../../src/cryptography/testModule";
import { x25519Keypair } from "../../src/cryptography/x25519";
import { newKeyPair } from "../../src/cryptography/ed25519";
import { crossSignIdentityX25519 } from "../../src/cryptography/identityCrossSig";
import {
  ML_KEM_512_CIPHERTEXT_BYTES,
  ML_KEM_512_PUBLIC_KEY_BYTES,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
} from "../../src/cryptography/mlkem";
import {
  ratchetDecrypt,
  ratchetEncrypt,
  serializeRatchet,
  wipeRatchet,
} from "../../src/cryptography/ratchet";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import {
  buildChannelInput,
  performHandshakeCore,
  type HandshakeCoreParams,
  type HandshakeTransport,
} from "../../src/handlers/handshakeCore";

// Only the WebRTC orchestration module imports the Redux store/db worker. Bare
// `bun test` has no localStorage, so shim it before dynamically importing that
// module. The store-free handshake core above loads without this browser glue.
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

type HS = typeof import("../../src/handlers/handleHandshake");
type RP = typeof import("../../src/handlers/ratchetPersist");
let parseFingerprintFromSdp: HS["parseFingerprintFromSdp"];
let verifyDtlsFingerprints: HS["verifyDtlsFingerprints"];
let setHandshakeChannel: HS["setHandshakeChannel"];
let clearHandshakeChannel: HS["clearHandshakeChannel"];
let deliverHandshakeFrame: HS["deliverHandshakeFrame"];
let runHandshake: HS["runHandshake"];
let createHandshakePqRuntime: HS["createHandshakePqRuntime"];
let persistAndActivateEdgeCrypto: HS["persistAndActivateEdgeCrypto"];
let claimRatchetPersistence: RP["claimRatchetPersistence"];

beforeAll(async () => {
  const m = await import("../../src/handlers/handleHandshake");
  ({
    parseFingerprintFromSdp,
    verifyDtlsFingerprints,
    setHandshakeChannel,
    clearHandshakeChannel,
    deliverHandshakeFrame,
    runHandshake,
    createHandshakePqRuntime,
    persistAndActivateEdgeCrypto,
  } = m);
  ({ claimRatchetPersistence } =
    await import("../../src/handlers/ratchetPersist"));
});

const CHANNEL_ID = new TextEncoder().encode("main"); // 4 bytes
const HS_STEP_HELLO = 0x01;
const HS_STEP_CONFIRM = 0x02;
const HS_STEP_FINISH = 0x03;
const HELLO_CLASSICAL_FIELDS_LEN = 1 + 32 + 32 + 32 + 32 + 64;
const HELLO_ML_KEM_PUBLIC_KEY_OFF = HELLO_CLASSICAL_FIELDS_LEN;
const HELLO_ML_KEM_CIPHERTEXT_OFF =
  HELLO_ML_KEM_PUBLIC_KEY_OFF + ML_KEM_768_PUBLIC_KEY_BYTES;
const HELLO_PAYLOAD_LEN =
  HELLO_ML_KEM_CIPHERTEXT_OFF + ML_KEM_768_CIPHERTEXT_BYTES;
const HELLO_512_PAYLOAD_LEN =
  HELLO_CLASSICAL_FIELDS_LEN +
  ML_KEM_512_PUBLIC_KEY_BYTES +
  ML_KEM_512_CIPHERTEXT_BYTES;
const HELLO_1024_PAYLOAD_LEN =
  HELLO_CLASSICAL_FIELDS_LEN +
  ML_KEM_1024_PUBLIC_KEY_BYTES +
  ML_KEM_1024_CIPHERTEXT_BYTES;
const CONFIRM_PAYLOAD_LEN = 1 + 32 + 64;
const FINISH_PAYLOAD_LEN = 1 + 64;

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
    expect(ci[ci.length - 1]).toBe(1); // ML-KEM-768 hybrid PQ_TAG
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

  test("the exact room-selected ML-KEM suite has a distinct transcript tag", () => {
    const common = {
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(1),
      ikResponder: new Uint8Array(32).fill(2),
      fpInitiator: new Uint8Array(32).fill(3),
      fpResponder: new Uint8Array(32).fill(4),
    };
    const tags = [
      buildChannelInput({ ...common, pqMode: "hybrid-mlkem512" }).at(-1),
      buildChannelInput({ ...common, pqMode: "hybrid-mlkem768" }).at(-1),
      buildChannelInput({ ...common, pqMode: "hybrid-mlkem1024" }).at(-1),
    ];
    expect(tags).toEqual([2, 1, 3]);
    expect(new Set(tags).size).toBe(3);
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
        new Map<string, Record<string, string>>([
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
              fingerprint: localFp,
              fingerprintAlgorithm: "sha-256",
            },
          ],
          [
            "RC",
            {
              type: "certificate",
              fingerprint: statsFp,
              fingerprintAlgorithm: "sha-256",
            },
          ],
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
        new Map<string, Record<string, string>>([
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
    (): Promise<Uint8Array> => {
      if (q.length > 0) return Promise.resolve(q.shift()!);
      return new Promise((resolve, reject) => {
        const waiter = (value: Uint8Array): void => {
          clearTimeout(timer);
          resolve(value);
        };
        const timer = setTimeout(() => {
          const index = w.indexOf(waiter);
          if (index >= 0) w.splice(index, 1);
          reject(new Error("test handshake transport timed out"));
        }, 250);
        w.push(waiter);
      });
    };
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

const makeNoPinHandshakeParams = async (
  module: LibCrypto,
  channelInput: Uint8Array,
): Promise<[HandshakeCoreParams, HandshakeCoreParams]> => {
  const idA = x25519Keypair(module);
  const idB = x25519Keypair(module);
  const edA = await newKeyPair(module);
  const edB = await newKeyPair(module);
  const crossA = await crossSignIdentityX25519(
    idA.publicKey,
    edA.secretKey,
    module,
  );
  const crossB = await crossSignIdentityX25519(
    idB.publicKey,
    edB.secretKey,
    module,
  );

  return [
    {
      mode: "nopin",
      pin: null,
      channelInput,
      amInitiator: true,
      idSelfSec: idA.secretKey,
      selfIdentityX25519Pub: idA.publicKey,
      selfIdentityCrossSignature: crossA,
      peerIdentityEd25519Pub: edB.publicKey,
    },
    {
      mode: "nopin",
      pin: null,
      channelInput,
      amInitiator: false,
      idSelfSec: idB.secretKey,
      selfIdentityX25519Pub: idB.publicKey,
      selfIdentityCrossSignature: crossB,
      peerIdentityEd25519Pub: edA.publicKey,
    },
  ];
};

const establishNoPinHandshake = async (
  module: LibCrypto,
  channelInput: Uint8Array,
) => {
  const [initiatorTransport, responderTransport] = linkedTransports();
  const [initiatorParams, responderParams] = await makeNoPinHandshakeParams(
    module,
    channelInput,
  );
  const [initiator, responder] = await Promise.all([
    performHandshakeCore(initiatorTransport, initiatorParams, module),
    performHandshakeCore(responderTransport, responderParams, module),
  ]);
  return { initiator, responder };
};

describe("performHandshakeCore (root agreement over a mock channel)", () => {
  test("fails closed before sending when mandatory ML-KEM exports are absent", async () => {
    const module = await loadTestModule();
    let sent = false;
    const withoutMlKem = new Proxy(module, {
      get(target, property, receiver) {
        if (
          property === "_mlkem768_keypair" ||
          property === "_mlkem768_encaps" ||
          property === "_mlkem768_decaps"
        )
          return undefined;
        return Reflect.get(target, property, receiver);
      },
    });

    await expect(
      performHandshakeCore(
        {
          send: () => {
            sent = true;
          },
          recv: async () => new Uint8Array(),
        },
        {
          mode: "nopin",
          pin: null,
          channelInput: new Uint8Array(160),
          amInitiator: true,
          idSelfSec: new Uint8Array(32),
          selfIdentityX25519Pub: new Uint8Array(32),
          selfIdentityCrossSignature: new Uint8Array(64),
          peerIdentityEd25519Pub: new Uint8Array(32),
        },
        withoutMlKem,
      ),
    ).rejects.toThrow(/ML-KEM-768 WASM exports are unavailable/);
    expect(sent).toBe(false);
  });

  test("no-PIN mode: both sides derive the identical 32-byte secret", async () => {
    const module = await loadTestModule();
    const [tA, tB] = linkedTransports();

    // Real X25519 identity keypairs. x3dh's cross-DH (DH(IK_a,EK_b) ==
    // DH(EK_b,IK_a)) only holds when pub = priv·G, so the brief's arbitrary
    // fill()ed identity keys cannot agree — see the task report.
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    // Ed25519 identities + X25519 cross-sigs, exactly as runHandshake supplies
    // them: each side presents its X25519 pub cross-signed by its Ed25519 secret,
    // and pins the peer's Ed25519 pub as the anchor to verify against.
    const edA = await newKeyPair(module);
    const edB = await newKeyPair(module);
    const crossA = await crossSignIdentityX25519(
      idA.publicKey,
      edA.secretKey,
      module,
    );
    const crossB = await crossSignIdentityX25519(
      idB.publicKey,
      edB.secretKey,
      module,
    );
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
          selfIdentityX25519Pub: idA.publicKey,
          selfIdentityCrossSignature: crossA,
          peerIdentityEd25519Pub: edB.publicKey,
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
          selfIdentityX25519Pub: idB.publicKey,
          selfIdentityCrossSignature: crossB,
          peerIdentityEd25519Pub: edA.publicKey,
        },
        module,
      ),
    ]);

    expect([...rA.secret]).toEqual([...rB.secret]);
    expect(rA.secret.length).toBe(32);

    // Handshake bootstrap: the responder has authenticated/adopted the
    // initiator's initial DH pub and opened both chains. Its own DH key has
    // already rotated, so the initiator learns that new pub on responder msg 0.
    const sA = serializeRatchet(rA.state);
    const sB = serializeRatchet(rB.state);
    expect([...new Uint8Array(sB.dhRemotePub as ArrayBuffer)]).toEqual([
      ...new Uint8Array(sA.dhSelfPub),
    ]);
    expect(sA.sendingChainKey).not.toBeNull();
    expect(sB.sendingChainKey).not.toBeNull();
    expect(sB.receivingChainKey).not.toBeNull();
  });

  test("honest establishment uses HELLO plus three chained confirmation flights", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const [initiatorParams, responderParams] = await makeNoPinHandshakeParams(
      module,
      new Uint8Array(160).fill(0x71),
    );
    const sentByInitiator: number[] = [];
    const sentByResponder: number[] = [];
    const capture = (
      transport: HandshakeTransport,
      tags: number[],
    ): HandshakeTransport => ({
      recv: transport.recv,
      send(bytes): void {
        tags.push(bytes[0]);
        transport.send(bytes);
      },
    });

    const [initiator, responder] = await Promise.all([
      performHandshakeCore(
        capture(initiatorTransport, sentByInitiator),
        initiatorParams,
        module,
      ),
      performHandshakeCore(
        capture(responderTransport, sentByResponder),
        responderParams,
        module,
      ),
    ]);

    expect(sentByInitiator).toEqual([HS_STEP_HELLO, HS_STEP_CONFIRM]);
    expect(sentByResponder).toEqual([
      HS_STEP_HELLO,
      HS_STEP_CONFIRM,
      HS_STEP_FINISH,
    ]);
    wipeRatchet(initiator.state);
    wipeRatchet(responder.state);
    initiator.secret.fill(0);
    responder.secret.fill(0);
  });

  test("tampering responder confirmation poisons initiator confirmation so both reject", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const [initiatorParams, responderParams] = await makeNoPinHandshakeParams(
      module,
      new Uint8Array(160).fill(0x72),
    );
    let tampered = false;
    const tamperingResponderTransport: HandshakeTransport = {
      recv: responderTransport.recv,
      send(bytes): void {
        const forwarded = Uint8Array.from(bytes);
        if (
          !tampered &&
          forwarded.length === CONFIRM_PAYLOAD_LEN &&
          forwarded[0] === HS_STEP_CONFIRM
        ) {
          forwarded[forwarded.length - 1] ^= 0x80;
          tampered = true;
        }
        responderTransport.send(forwarded);
      },
    };

    const results = await Promise.allSettled([
      performHandshakeCore(initiatorTransport, initiatorParams, module),
      performHandshakeCore(
        tamperingResponderTransport,
        responderParams,
        module,
      ),
    ]);
    expect(tampered).toBe(true);
    expect(results.map((result) => result.status)).toEqual([
      "rejected",
      "rejected",
    ]);
  });

  test("initiator rejects a tampered third FINISH proof", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const [initiatorParams, responderParams] = await makeNoPinHandshakeParams(
      module,
      new Uint8Array(160).fill(0x73),
    );
    let tampered = false;
    const tamperingResponderTransport: HandshakeTransport = {
      recv: responderTransport.recv,
      send(bytes): void {
        const forwarded = Uint8Array.from(bytes);
        if (
          !tampered &&
          forwarded.length === FINISH_PAYLOAD_LEN &&
          forwarded[0] === HS_STEP_FINISH
        ) {
          forwarded[forwarded.length - 1] ^= 0x80;
          tampered = true;
        }
        responderTransport.send(forwarded);
      },
    };

    const results = await Promise.allSettled([
      performHandshakeCore(initiatorTransport, initiatorParams, module),
      performHandshakeCore(
        tamperingResponderTransport,
        responderParams,
        module,
      ),
    ]);
    expect(tampered).toBe(true);
    expect(results[0].status).toBe("rejected");
    expect(String((results[0] as PromiseRejectedResult).reason)).toMatch(
      /final confirmation/i,
    );
    expect(results[1].status).toBe("fulfilled");
    if (results[1].status === "fulfilled") {
      wipeRatchet(results[1].value.state);
      results[1].value.secret.fill(0);
    }
  });

  test("responder can encrypt first immediately after handshake return", async () => {
    const module = await loadTestModule();
    const { initiator, responder } = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(0x31),
    );

    const firstFromResponder = ratchetEncrypt(responder.state, module);
    const receivedByInitiator = ratchetDecrypt(
      initiator.state,
      firstFromResponder.header,
      module,
    );

    expect(Buffer.from(receivedByInitiator)).toEqual(
      Buffer.from(firstFromResponder.messageKey),
    );
  });

  test("simultaneous first outbound messages decrypt on both sides", async () => {
    const module = await loadTestModule();
    const { initiator, responder } = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(0x32),
    );

    // Derive both outbound message-0 keys before either peer processes inbound
    // traffic. This is the simultaneous-first-message case that previously
    // failed because the responder had no sending chain.
    const firstFromInitiator = ratchetEncrypt(initiator.state, module);
    const firstFromResponder = ratchetEncrypt(responder.state, module);

    const receivedByInitiator = ratchetDecrypt(
      initiator.state,
      firstFromResponder.header,
      module,
    );
    const receivedByResponder = ratchetDecrypt(
      responder.state,
      firstFromInitiator.header,
      module,
    );

    expect(Buffer.from(receivedByInitiator)).toEqual(
      Buffer.from(firstFromResponder.messageKey),
    );
    expect(Buffer.from(receivedByResponder)).toEqual(
      Buffer.from(firstFromInitiator.messageKey),
    );
  });

  test("tampered initiator ratchet DH public key prevents both endpoints from completing", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const [initiatorParams, responderParams] = await makeNoPinHandshakeParams(
      module,
      new Uint8Array(160).fill(0x33),
    );
    let changedInitiatorDhPub = false;
    const tamperingInitiatorTransport: HandshakeTransport = {
      recv: initiatorTransport.recv,
      send(bytes): void {
        const forwarded = Uint8Array.from(bytes);
        if (
          !changedInitiatorDhPub &&
          forwarded.length === CONFIRM_PAYLOAD_LEN &&
          forwarded[0] === HS_STEP_CONFIRM
        ) {
          // CONFIRM's existing 32-byte field now carries the initiator's actual
          // ratchet pub. The MAC was computed over the untampered value.
          forwarded[1 + 11] ^= 0x80;
          changedInitiatorDhPub = true;
        }
        initiatorTransport.send(forwarded);
      },
    };

    const results = await Promise.allSettled([
      performHandshakeCore(
        tamperingInitiatorTransport,
        initiatorParams,
        module,
      ),
      performHandshakeCore(responderTransport, responderParams, module),
    ]);

    expect(changedInitiatorDhPub).toBe(true);
    expect(results[0].status).toBe("rejected");
    expect(results[1].status).toBe("rejected");
    expect(String((results[1] as PromiseRejectedResult).reason)).toMatch(
      /key-confirmation/i,
    );
  });

  test("PIN mode: matching PINs agree; a wrong PIN fails key-confirmation", async () => {
    const module = await loadTestModule();
    const ci = new Uint8Array(160).fill(9);
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    const edA = await newKeyPair(module);
    const edB = await newKeyPair(module);
    const crossA = await crossSignIdentityX25519(
      idA.publicKey,
      edA.secretKey,
      module,
    );
    const crossB = await crossSignIdentityX25519(
      idB.publicKey,
      edB.secretKey,
      module,
    );
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
            selfIdentityX25519Pub: idA.publicKey,
            selfIdentityCrossSignature: crossA,
            peerIdentityEd25519Pub: edB.publicKey,
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
            selfIdentityX25519Pub: idB.publicKey,
            selfIdentityCrossSignature: crossB,
            peerIdentityEd25519Pub: edA.publicKey,
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
            selfIdentityX25519Pub: idA.publicKey,
            selfIdentityCrossSignature: crossA,
            peerIdentityEd25519Pub: edB.publicKey,
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
            selfIdentityX25519Pub: idB.publicKey,
            selfIdentityCrossSignature: crossB,
            peerIdentityEd25519Pub: edA.publicKey,
          },
          module,
        ),
      ]);
      // Both legs must reject (the deadlock-safe R2 ordering guarantees the
      // responder's recv() is satisfied even when the initiator aborts).
      expect(results.every((r) => r.status === "rejected")).toBe(true);
    }
  });

  test("PIN mode rejects a replayed cross-signed identity whose presenter does not possess its X25519 secret", async () => {
    const module = await loadTestModule();
    const ci = new Uint8Array(160).fill(0x59);
    const pin = new TextEncoder().encode("correct-room-pin");

    // Mallory recorded Victim's public credential. It verifies perfectly
    // against Victim's pinned Ed25519 identity, but Mallory has only an unrelated
    // X25519 secret. CPace alone would authenticate this replay whenever Mallory
    // also knew the room PIN; the mandatory X3DH contribution must make both
    // confirmation MACs disagree.
    const victimX25519 = x25519Keypair(module);
    const attackerX25519 = x25519Keypair(module);
    const responderX25519 = x25519Keypair(module);
    const victimEd25519 = await newKeyPair(module);
    const responderEd25519 = await newKeyPair(module);
    const victimCrossSignature = await crossSignIdentityX25519(
      victimX25519.publicKey,
      victimEd25519.secretKey,
      module,
    );
    const responderCrossSignature = await crossSignIdentityX25519(
      responderX25519.publicKey,
      responderEd25519.secretKey,
      module,
    );
    const [attackerTransport, responderTransport] = linkedTransports();

    const results = await Promise.allSettled([
      performHandshakeCore(
        attackerTransport,
        {
          mode: "pin",
          pin,
          channelInput: ci,
          amInitiator: true,
          // Deliberately does NOT correspond to the replayed public credential.
          idSelfSec: attackerX25519.secretKey,
          selfIdentityX25519Pub: victimX25519.publicKey,
          selfIdentityCrossSignature: victimCrossSignature,
          peerIdentityEd25519Pub: responderEd25519.publicKey,
        },
        module,
      ),
      performHandshakeCore(
        responderTransport,
        {
          mode: "pin",
          pin,
          channelInput: ci,
          amInitiator: false,
          idSelfSec: responderX25519.secretKey,
          selfIdentityX25519Pub: responderX25519.publicKey,
          selfIdentityCrossSignature: responderCrossSignature,
          peerIdentityEd25519Pub: victimEd25519.publicKey,
        },
        module,
      ),
    ]);

    expect(results.every((result) => result.status === "rejected")).toBe(true);
    for (const result of results) {
      if (result.status === "rejected")
        expect(String(result.reason)).toMatch(/key-confirmation/i);
    }
  });

  test("tampering with the ML-KEM ciphertext makes both legs fail key confirmation", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    const edA = await newKeyPair(module);
    const edB = await newKeyPair(module);
    const crossA = await crossSignIdentityX25519(
      idA.publicKey,
      edA.secretKey,
      module,
    );
    const crossB = await crossSignIdentityX25519(
      idB.publicKey,
      edB.secretKey,
      module,
    );
    const ci = new Uint8Array(160).fill(0x6a);
    let changedResponderHello = false;
    const tamperingResponderTransport: HandshakeTransport = {
      recv: responderTransport.recv,
      send(bytes): void {
        const forwarded = Uint8Array.from(bytes);
        if (
          !changedResponderHello &&
          forwarded.length === HELLO_PAYLOAD_LEN &&
          forwarded[0] === HS_STEP_HELLO
        ) {
          forwarded[HELLO_ML_KEM_CIPHERTEXT_OFF + 17] ^= 0x80;
          changedResponderHello = true;
        }
        responderTransport.send(forwarded);
      },
    };

    const results = await Promise.allSettled([
      performHandshakeCore(
        initiatorTransport,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: true,
          idSelfSec: idA.secretKey,
          selfIdentityX25519Pub: idA.publicKey,
          selfIdentityCrossSignature: crossA,
          peerIdentityEd25519Pub: edB.publicKey,
        },
        module,
      ),
      performHandshakeCore(
        tamperingResponderTransport,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: false,
          idSelfSec: idB.secretKey,
          selfIdentityX25519Pub: idB.publicKey,
          selfIdentityCrossSignature: crossB,
          peerIdentityEd25519Pub: edA.publicKey,
        },
        module,
      ),
    ]);

    expect(changedResponderHello).toBe(true);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    for (const result of results) {
      if (result.status === "rejected")
        expect(String(result.reason)).toMatch(/key-confirmation/i);
    }
  });

  test("tampering with the initiator ML-KEM public key makes both legs fail key confirmation", async () => {
    const module = await loadTestModule();
    const [initiatorTransport, responderTransport] = linkedTransports();
    const idA = x25519Keypair(module);
    const idB = x25519Keypair(module);
    const edA = await newKeyPair(module);
    const edB = await newKeyPair(module);
    const crossA = await crossSignIdentityX25519(
      idA.publicKey,
      edA.secretKey,
      module,
    );
    const crossB = await crossSignIdentityX25519(
      idB.publicKey,
      edB.secretKey,
      module,
    );
    const ci = new Uint8Array(160).fill(0x6b);
    let changedInitiatorHello = false;
    const tamperingInitiatorTransport: HandshakeTransport = {
      recv: initiatorTransport.recv,
      send(bytes): void {
        const forwarded = Uint8Array.from(bytes);
        if (
          !changedInitiatorHello &&
          forwarded.length === HELLO_PAYLOAD_LEN &&
          forwarded[0] === HS_STEP_HELLO
        ) {
          // Change rho, the final 32-byte public seed, so the key remains
          // syntactically valid while no longer matching the initiator's secret.
          forwarded[
            HELLO_ML_KEM_PUBLIC_KEY_OFF + ML_KEM_768_PUBLIC_KEY_BYTES - 1
          ] ^= 0x80;
          changedInitiatorHello = true;
        }
        initiatorTransport.send(forwarded);
      },
    };

    const results = await Promise.allSettled([
      performHandshakeCore(
        tamperingInitiatorTransport,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: true,
          idSelfSec: idA.secretKey,
          selfIdentityX25519Pub: idA.publicKey,
          selfIdentityCrossSignature: crossA,
          peerIdentityEd25519Pub: edB.publicKey,
        },
        module,
      ),
      performHandshakeCore(
        responderTransport,
        {
          mode: "nopin",
          pin: null,
          channelInput: ci,
          amInitiator: false,
          idSelfSec: idB.secretKey,
          selfIdentityX25519Pub: idB.publicKey,
          selfIdentityCrossSignature: crossB,
          peerIdentityEd25519Pub: edA.publicKey,
        },
        module,
      ),
    ]);

    expect(changedInitiatorHello).toBe(true);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    for (const result of results) {
      if (result.status === "rejected")
        expect(String(result.reason)).toMatch(/key-confirmation/i);
    }
  });

  test("rejects non-canonical or absent role-specific ML-KEM fields instead of downgrading", async () => {
    const module = await loadTestModule();
    const common = {
      mode: "nopin" as const,
      pin: null,
      channelInput: new Uint8Array(160),
      idSelfSec: new Uint8Array(32),
      selfIdentityX25519Pub: new Uint8Array(32),
      selfIdentityCrossSignature: new Uint8Array(64),
      peerIdentityEd25519Pub: new Uint8Array(32),
    };
    const oneShot = (hello: Uint8Array): HandshakeTransport => ({
      send: () => {},
      recv: async () => hello,
    });
    const hello = (): Uint8Array => {
      const bytes = new Uint8Array(HELLO_PAYLOAD_LEN);
      bytes[0] = HS_STEP_HELLO;
      return bytes;
    };

    const initiatorWithCiphertext = hello();
    initiatorWithCiphertext[HELLO_ML_KEM_PUBLIC_KEY_OFF] = 1;
    initiatorWithCiphertext[HELLO_ML_KEM_CIPHERTEXT_OFF] = 1;
    await expect(
      performHandshakeCore(
        oneShot(initiatorWithCiphertext),
        { ...common, amInitiator: false },
        module,
      ),
    ).rejects.toThrow(/initiator ML-KEM ciphertext field must be zero/);

    await expect(
      performHandshakeCore(
        oneShot(hello()),
        { ...common, amInitiator: false },
        module,
      ),
    ).rejects.toThrow(/initiator ML-KEM public key is required/);

    const responderWithPublicKey = hello();
    responderWithPublicKey[HELLO_ML_KEM_PUBLIC_KEY_OFF] = 1;
    responderWithPublicKey[HELLO_ML_KEM_CIPHERTEXT_OFF] = 1;
    await expect(
      performHandshakeCore(
        oneShot(responderWithPublicKey),
        { ...common, amInitiator: true },
        module,
      ),
    ).rejects.toThrow(/responder ML-KEM public-key field must be zero/);

    await expect(
      performHandshakeCore(
        oneShot(hello()),
        { ...common, amInitiator: true },
        module,
      ),
    ).rejects.toThrow(/responder ML-KEM ciphertext is required/);
  });

  test("no-PIN mode: a peer HELLO whose X25519 cross-sig does not verify against the pinned peer Ed25519 rejects (fail-closed, before any DH/secret)", async () => {
    const module = await loadTestModule();

    // Our (initiator) identity, correctly cross-signed.
    const idSelf = x25519Keypair(module);
    const edSelf = await newKeyPair(module);
    const crossSelf = await crossSignIdentityX25519(
      idSelf.publicKey,
      edSelf.secretKey,
      module,
    );

    // The peer presents its real X25519 pub, but its cross-sig is produced by a
    // DIFFERENT (attacker) Ed25519 key — NOT the peer Ed25519 identity we pin —
    // so verifyIdentityCrossSig must return false and abort before any DH.
    const idPeer = x25519Keypair(module);
    const edPeerPinned = await newKeyPair(module); // what the initiator trusts
    const edAttacker = await newKeyPair(module); // what actually signed
    const badCrossSig = await crossSignIdentityX25519(
      idPeer.publicKey,
      edAttacker.secretKey,
      module,
    );

    // Assemble the peer responder HELLO exactly as packHello would. Its
    // role-unused ML-KEM public-key field stays zero and its ciphertext field is
    // nonzero; identity verification fails before decapsulation reads it.
    const peerHello = new Uint8Array(HELLO_PAYLOAD_LEN);
    peerHello[0] = HS_STEP_HELLO;
    peerHello.set(crypto.getRandomValues(new Uint8Array(32)), 1);
    peerHello.set(idPeer.publicKey, 1 + 32);
    // Y (offset 1+32+32) stays zeros.
    peerHello.set(idPeer.publicKey, 1 + 32 + 32 + 32);
    peerHello.set(badCrossSig, 1 + 32 + 32 + 32 + 32);
    peerHello.set(
      crypto.getRandomValues(new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES)),
      HELLO_ML_KEM_CIPHERTEXT_OFF,
    );

    // Scripted one-shot transport: swallow our HELLO, hand back the crafted one.
    // (A two-sided linkedTransports run would leave the honest peer's recv()
    // hanging once the verifying side throws mid-protocol, so drive one leg.)
    const transport: HandshakeTransport = {
      send: () => {},
      recv: async () => peerHello,
    };

    const results = await Promise.allSettled([
      performHandshakeCore(
        transport,
        {
          mode: "nopin",
          pin: null,
          channelInput: new Uint8Array(160).fill(5),
          amInitiator: true,
          idSelfSec: idSelf.secretKey,
          selfIdentityX25519Pub: idSelf.publicKey,
          selfIdentityCrossSignature: crossSelf,
          peerIdentityEd25519Pub: edPeerPinned.publicKey,
        },
        module,
      ),
    ]);

    expect(results[0].status).toBe("rejected");
    expect(String((results[0] as PromiseRejectedResult).reason)).toMatch(
      /cross-signature/i,
    );
  });
});

describe("runHandshake wiring (inbox + channel registry)", () => {
  test("pre-auth framing uses the exact room suite and rejects cross-suite lengths", () => {
    const suites = [
      ["hybrid-mlkem512", HELLO_512_PAYLOAD_LEN],
      ["hybrid-mlkem768", HELLO_PAYLOAD_LEN],
      ["hybrid-mlkem1024", HELLO_1024_PAYLOAD_LEN],
    ] as const;

    for (const [pqMode, expectedLength] of suites) {
      const roomId = `room-${pqMode}`;
      const peerId = `peer-${pqMode}`;
      const lease = setHandshakeChannel(
        roomId,
        peerId,
        { send: () => {} },
        pqMode,
      );
      const hello = new Uint8Array(expectedLength);
      hello[0] = HS_STEP_HELLO;
      expect(deliverHandshakeFrame(roomId, peerId, hello, lease)).toBe(true);
      clearHandshakeChannel(roomId, peerId, undefined, lease);
    }

    const mismatchLease = setHandshakeChannel(
      "room-suite-mismatch",
      "peer-suite-mismatch",
      { send: () => {} },
      "hybrid-mlkem512",
    );
    const wrongHello = new Uint8Array(HELLO_1024_PAYLOAD_LEN);
    wrongHello[0] = HS_STEP_HELLO;
    expect(
      deliverHandshakeFrame(
        "room-suite-mismatch",
        "peer-suite-mismatch",
        wrongHello,
        mismatchLease,
      ),
    ).toBe(false);
  });

  test("only the initiator inbox admits the ordered third FINISH flight", () => {
    const hello = new Uint8Array(HELLO_PAYLOAD_LEN);
    hello[0] = HS_STEP_HELLO;
    const confirm = new Uint8Array(CONFIRM_PAYLOAD_LEN);
    confirm[0] = HS_STEP_CONFIRM;
    const finish = new Uint8Array(FINISH_PAYLOAD_LEN);
    finish[0] = HS_STEP_FINISH;

    const initiatorLease = setHandshakeChannel(
      "room-finish-i",
      "peer-finish-i",
      { send: () => {} },
      "hybrid-mlkem768",
      true,
    );
    expect(
      deliverHandshakeFrame(
        "room-finish-i",
        "peer-finish-i",
        hello,
        initiatorLease,
      ),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-finish-i",
        "peer-finish-i",
        confirm,
        initiatorLease,
      ),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-finish-i",
        "peer-finish-i",
        finish,
        initiatorLease,
      ),
    ).toBe(true);
    clearHandshakeChannel(
      "room-finish-i",
      "peer-finish-i",
      undefined,
      initiatorLease,
    );

    const responderLease = setHandshakeChannel(
      "room-finish-r",
      "peer-finish-r",
      { send: () => {} },
      "hybrid-mlkem768",
      false,
    );
    expect(
      deliverHandshakeFrame(
        "room-finish-r",
        "peer-finish-r",
        hello,
        responderLease,
      ),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-finish-r",
        "peer-finish-r",
        confirm,
        responderLease,
      ),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-finish-r",
        "peer-finish-r",
        finish,
        responderLease,
      ),
    ).toBe(false);
  });

  test("deliverHandshakeFrame feeds frames the runHandshake transport recvs", () => {
    // Registry/inbox smoke test: a frame delivered before recv is buffered.
    // 0x01 is the internal HS_STEP_HELLO sub-frame tag.
    const lease = setHandshakeChannel("roomX", "peerX", {
      send: () => {},
      readyState: "open",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(
      deliverHandshakeFrame(
        "roomX",
        "peerX",
        (() => {
          const hello = new Uint8Array(HELLO_PAYLOAD_LEN);
          hello[0] = HS_STEP_HELLO;
          return hello;
        })(),
        lease,
      ),
    ).toBe(true);
    // No throw; the frame sits in the inbox until the handshake drains it.
    expect(typeof runHandshake).toBe("function");
    clearHandshakeChannel("roomX", "peerX", undefined, lease);
  });

  test("rejects malformed, out-of-order, and surplus pre-auth frames", () => {
    const malformedLease = setHandshakeChannel("room-bounds", "peer-bounds", {
      send: () => {},
    });
    expect(
      deliverHandshakeFrame(
        "room-bounds",
        "peer-bounds",
        new Uint8Array([HS_STEP_HELLO]),
        malformedLease,
      ),
    ).toBe(false);

    const lease = setHandshakeChannel("room-bounds", "peer-bounds", {
      send: () => {},
    });
    const hello = new Uint8Array(HELLO_PAYLOAD_LEN);
    hello[0] = HS_STEP_HELLO;
    const confirm = new Uint8Array(1 + 32 + 64);
    confirm[0] = 2;
    expect(
      deliverHandshakeFrame("room-bounds", "peer-bounds", confirm, lease),
    ).toBe(false);

    const orderedLease = setHandshakeChannel("room-bounds", "peer-bounds", {
      send: () => {},
    });
    expect(
      deliverHandshakeFrame("room-bounds", "peer-bounds", hello, orderedLease),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-bounds",
        "peer-bounds",
        confirm,
        orderedLease,
      ),
    ).toBe(true);
    expect(
      deliverHandshakeFrame(
        "room-bounds",
        "peer-bounds",
        confirm,
        orderedLease,
      ),
    ).toBe(false);
  });

  test("stale inbox completion cannot clear or receive frames for a replacement main channel", () => {
    const oldLease = setHandshakeChannel("room-lease", "peer-lease", {
      send: () => {},
    });
    const freshLease = setHandshakeChannel("room-lease", "peer-lease", {
      send: () => {},
    });

    expect(
      deliverHandshakeFrame(
        "room-lease",
        "peer-lease",
        new Uint8Array([0x01]),
        oldLease,
      ),
    ).toBe(false);
    expect(
      clearHandshakeChannel(
        "room-lease",
        "peer-lease",
        new Error("stale finally"),
        oldLease,
      ),
    ).toBe(false);
    expect(
      deliverHandshakeFrame(
        "room-lease",
        "peer-lease",
        (() => {
          const hello = new Uint8Array(HELLO_PAYLOAD_LEN);
          hello[0] = HS_STEP_HELLO;
          return hello;
        })(),
        freshLease,
      ),
    ).toBe(true);
    expect(
      clearHandshakeChannel(
        "room-lease",
        "peer-lease",
        new Error("fresh finished"),
        freshLease,
      ),
    ).toBe(true);
  });
});

describe("atomic edge-crypto activation (ratchet + initial PQ checkpoint)", () => {
  const EDGE_MAGIC = [0x50, 0x32, 0x45, 0x44, 0x47, 0x45, 0x34, 0x00];

  const fakeEpc = (peerId: string, peerPublicKey: string): IRTCPeerConnection =>
    ({
      withPeerId: peerId,
      withPeerPublicKey: peerPublicKey,
    }) as unknown as IRTCPeerConnection;

  test("the very first persisted row carries a non-null PQ edge checkpoint and installs both states", async () => {
    const module = await loadTestModule();
    const { initiator } = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(7),
    );
    initiator.secret.fill(0);

    const bootstrapRoot = initiator.pqHealing.rootKey;
    const bootstrapBinding = initiator.pqHealing.binding;
    const runtime = createHandshakePqRuntime(
      module,
      "hybrid-mlkem768",
      initiator.state.rootSuite,
      true,
      initiator.pqHealing,
    );
    // The bootstrap buffers are consumed: the runtime is the only holder now.
    expect(bootstrapRoot.every((byte) => byte === 0)).toBe(true);
    expect(bootstrapBinding.every((byte) => byte === 0)).toBe(true);

    const epc = fakeEpc("pq-peer-a", "aa".repeat(32));
    claimRatchetPersistence(epc, "pq-room-a");
    let persistedEdge: Uint8Array | null = null;
    let beforeInstallRan = false;
    await persistAndActivateEdgeCrypto(
      epc,
      "pq-room-a",
      { state: initiator.state, pqRuntime: runtime },
      () => {
        beforeInstallRan = true;
        expect(epc.ratchetState).toBeUndefined();
        expect(epc.pqHealingState).toBeUndefined();
      },
      async (_state, _roomId, _peerPublicKey, _peerId, edgeCryptoState) => {
        expect(edgeCryptoState).toBeInstanceOf(Uint8Array);
        persistedEdge = Uint8Array.from(edgeCryptoState!);
      },
      async () => {
        throw new Error("rollback must not run on the success path");
      },
    );

    expect(beforeInstallRan).toBe(true);
    expect(epc.ratchetState).toBe(initiator.state);
    expect(epc.pqHealingState).toBe(runtime);
    expect(persistedEdge).not.toBeNull();
    expect(Array.from(persistedEdge!.subarray(0, 8))).toEqual(EDGE_MAGIC);
    // The installed hook serializes the SAME live runtime the row was
    // committed with, byte-exactly.
    expect(Buffer.from(epc.serializeEdgeCryptoState!())).toEqual(
      Buffer.from(persistedEdge!),
    );

    epc.pqHealingState!.destroy();
    wipeRatchet(epc.ratchetState!);
  });

  test("an injected persistence failure installs nothing and leaves no live PQ secret", async () => {
    const module = await loadTestModule();
    const { responder } = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(8),
    );
    responder.secret.fill(0);
    const runtime = createHandshakePqRuntime(
      module,
      "hybrid-mlkem768",
      responder.state.rootSuite,
      false,
      responder.pqHealing,
    );

    const epc = fakeEpc("pq-peer-b", "bb".repeat(32));
    claimRatchetPersistence(epc, "pq-room-b");
    let rollbackCalls = 0;
    await expect(
      persistAndActivateEdgeCrypto(
        epc,
        "pq-room-b",
        { state: responder.state, pqRuntime: runtime },
        () => {
          throw new Error("beforeInstall must not run when the write fails");
        },
        async () => {
          throw new Error("injected persistence failure");
        },
        async () => {
          rollbackCalls += 1;
        },
      ),
    ).rejects.toThrow(/injected persistence failure/);

    expect(rollbackCalls).toBe(1);
    expect(epc.ratchetState).toBeUndefined();
    expect(epc.pqHealingState).toBeUndefined();
    expect(epc.serializeEdgeCryptoState).toBeUndefined();

    // Ownership stayed with the caller; runHandshake's finally destroys it,
    // after which no serializable PQ state exists anywhere.
    runtime.destroy();
    expect(() => runtime.serialize()).toThrow(/destroyed/);
    wipeRatchet(responder.state);
  });

  test("an open-gate failure after a successful write rolls the seed row back and installs nothing", async () => {
    const module = await loadTestModule();
    const { initiator } = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(9),
    );
    initiator.secret.fill(0);
    const runtime = createHandshakePqRuntime(
      module,
      "hybrid-mlkem768",
      initiator.state.rootSuite,
      true,
      initiator.pqHealing,
    );

    const epc = fakeEpc("pq-peer-c", "cc".repeat(32));
    claimRatchetPersistence(epc, "pq-room-c");
    let writes = 0;
    let rollbackCalls = 0;
    await expect(
      persistAndActivateEdgeCrypto(
        epc,
        "pq-room-c",
        { state: initiator.state, pqRuntime: runtime },
        () => {
          throw new Error("Handshake transport gate is already settled");
        },
        async () => {
          writes += 1;
        },
        async () => {
          rollbackCalls += 1;
        },
      ),
    ).rejects.toThrow(/already settled/);

    expect(writes).toBe(1);
    expect(rollbackCalls).toBe(1);
    expect(epc.ratchetState).toBeUndefined();
    expect(epc.pqHealingState).toBeUndefined();
    expect(epc.serializeEdgeCryptoState).toBeUndefined();

    runtime.destroy();
    wipeRatchet(initiator.state);
  });

  test("a replacement handshake destroys the previous runtime and wipes the previous ratchet", async () => {
    const module = await loadTestModule();
    const epc = fakeEpc("pq-peer-d", "dd".repeat(32));
    claimRatchetPersistence(epc, "pq-room-d");
    const persistNothing = async (): Promise<void> => {};
    const rollbackNothing = async (): Promise<void> => {};

    const first = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(10),
    );
    first.initiator.secret.fill(0);
    first.responder.secret.fill(0);
    const firstRuntime = createHandshakePqRuntime(
      module,
      "hybrid-mlkem768",
      first.initiator.state.rootSuite,
      true,
      first.initiator.pqHealing,
    );
    await persistAndActivateEdgeCrypto(
      epc,
      "pq-room-d",
      { state: first.initiator.state, pqRuntime: firstRuntime },
      () => {},
      persistNothing,
      rollbackNothing,
    );
    const firstRootKey = first.initiator.state.rootKey;
    expect(firstRootKey.some((byte) => byte !== 0)).toBe(true);

    const second = await establishNoPinHandshake(
      module,
      new Uint8Array(160).fill(11),
    );
    second.initiator.secret.fill(0);
    second.responder.secret.fill(0);
    const secondRuntime = createHandshakePqRuntime(
      module,
      "hybrid-mlkem768",
      second.initiator.state.rootSuite,
      true,
      second.initiator.pqHealing,
    );
    await persistAndActivateEdgeCrypto(
      epc,
      "pq-room-d",
      { state: second.initiator.state, pqRuntime: secondRuntime },
      () => {},
      persistNothing,
      rollbackNothing,
    );

    expect(epc.ratchetState).toBe(second.initiator.state);
    expect(epc.pqHealingState).toBe(secondRuntime);
    // The replaced runtime is destroyed and the replaced ratchet is wiped.
    expect(() => firstRuntime.serialize()).toThrow(/destroyed/);
    expect(firstRootKey.every((byte) => byte === 0)).toBe(true);

    epc.pqHealingState!.destroy();
    wipeRatchet(epc.ratchetState!);
    if (first.responder.state) wipeRatchet(first.responder.state);
    if (second.responder.state) wipeRatchet(second.responder.state);
  });
});

describe("verifyDtlsFingerprints across browser stat support", () => {
  const fpHex =
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
  const otherHex =
    "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:" +
    "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
  const sdpWith = (fp: string) => `v=0\r\na=fingerprint:sha-256 ${fp}\r\n`;

  const epcWithStats = (rows: [string, Record<string, string>][]) =>
    ({
      localDescription: { sdp: sdpWith(fpHex) },
      remoteDescription: { sdp: sdpWith(fpHex) },
      getStats: async () => new Map(rows),
    }) as unknown as IRTCPeerConnection;

  // Firefox implements neither the transport stat nor certificate rows, so the
  // live-certificate check has nothing to read. Failing closed there rejected
  // every handshake and made the library unusable in that browser, while
  // catching no attacker: rewritten SDP still breaks the transcript.
  test("a browser that reports no certificate statistics is allowed through", async () => {
    const firefoxLike = epcWithStats([
      ["CP", { type: "candidate-pair", state: "succeeded" }],
      ["DC", { type: "data-channel", state: "open" }],
    ]);
    await verifyDtlsFingerprints(firefoxLike);
  });

  // Where the browser can answer, a disagreement is still fatal.
  test("a browser that reports a mismatching certificate still fails closed", async () => {
    const chromiumLike = epcWithStats([
      [
        "T",
        {
          type: "transport",
          localCertificateId: "LC",
          remoteCertificateId: "RC",
        },
      ],
      ["LC", { type: "certificate", fingerprint: otherHex }],
      ["RC", { type: "certificate", fingerprint: fpHex }],
    ]);
    await expect(verifyDtlsFingerprints(chromiumLike)).rejects.toThrow(
      /local certificate/u,
    );
  });

  // A transport stat naming a certificate that is absent is a truncated or
  // tampered report, not a browser that cannot answer.
  test("a certificate id that resolves to nothing still fails closed", async () => {
    const truncated = epcWithStats([
      [
        "T",
        {
          type: "transport",
          localCertificateId: "LC",
          remoteCertificateId: "RC",
        },
      ],
      ["RC", { type: "certificate", fingerprint: fpHex }],
    ]);
    await expect(verifyDtlsFingerprints(truncated)).rejects.toThrow(
      /local certificate/u,
    );
  });
});
