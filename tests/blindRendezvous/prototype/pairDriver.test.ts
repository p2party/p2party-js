import { readFileSync } from "node:fs";

import { describe, expect, test } from "bun:test";

import { newKeyPair } from "../../../src/cryptography/ed25519";
import { loadTestModule } from "../../../src/cryptography/testModule";
import { validateAndIdentifyOperationCandidate } from "../../../src/blindRendezvous/coreReduce";
import { pairSemanticSlot } from "../../../src/blindRendezvous/derivations";
import {
  operationPaddingFor,
  signOperation,
} from "../../../src/blindRendezvous/operation";
import {
  decodePairStepEnvelopeV1,
  encodePairStepEnvelopeV1,
} from "../../../src/blindRendezvous/pairStepEnvelope";
import { copyBlindDefaultPolicy } from "../../../src/blindRendezvous/roomPolicyV4";
import { PairDriver } from "../../../src/blindRendezvous/prototype/pairDriver";
import {
  buildOfferCandidates,
  selectWebRtcCandidate,
  validateWebRtcSdp,
} from "../../../src/blindRendezvous/prototype/transportCandidates";
import { operationServiceRole } from "../../../src/blindRendezvous/prototype/workKinds";
import { generateSessionIdentity } from "../../../src/session";

import type { OuterValidatedIdentifiedOperationV1 } from "../../../src/blindRendezvous/coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  UnsignedRoomOperationV1,
} from "../../../src/blindRendezvous/operation";
import type { PairTransportCandidateV1 } from "../../../src/blindRendezvous/pairPlaintext";
import type {
  PairDriverPhase,
  TransportCandidateProvider,
} from "../../../src/blindRendezvous/prototype/pairDriver";
import type { ServiceWorkKindV1 } from "../../../src/blindRendezvous/prototype/workKinds";

const module = await loadTestModule();

const wasmFileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(wasmFileBytes.byteLength);
new Uint8Array(wasmBinary).set(wasmFileBytes);

const NOW_MS = 1_800_000_000_000n;
const LOGICAL_WINDOW =
  NOW_MS / copyBlindDefaultPolicy().protocolLimits.logicalWindowMs;

const clock = { nowMs: (): bigint => NOW_MS };

const random = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fingerprintText = (byte: number): string =>
  Array.from({ length: 32 }, () =>
    byte.toString(16).padStart(2, "0").toUpperCase(),
  ).join(":");

const sdpBytes = (tag: string, fingerprintByte: number): Uint8Array =>
  new TextEncoder().encode(
    [
      "v=0",
      "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
      "s=-",
      "t=0 0",
      "a=group:BUNDLE 0",
      "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
      "c=IN IP4 0.0.0.0",
      "a=ice-ufrag:" + tag,
      "a=ice-pwd:" + tag + tag + tag,
      "a=ice-options:trickle",
      "a=fingerprint:sha-256 " + fingerprintText(fingerprintByte),
      "a=setup:actpass",
      "a=mid:0",
      "a=sctp-port:5000",
      "",
    ].join("\r\n"),
  );

/**
 * One canned complete-ICE endpoint. `createOffer` and `acceptOffer` return the
 * same local SDP because a real endpoint has exactly one local description.
 */
class FakeTransport implements TransportCandidateProvider {
  remoteOffer: Uint8Array | null = null;
  remoteAnswer: Uint8Array | null = null;

  constructor(private readonly localSdp: Uint8Array) {}

  createOffer(): Promise<Uint8Array> {
    return Promise.resolve(Uint8Array.from(this.localSdp));
  }

  acceptOffer(remoteSdp: Uint8Array): Promise<Uint8Array> {
    this.remoteOffer = Uint8Array.from(remoteSdp);
    return Promise.resolve(Uint8Array.from(this.localSdp));
  }

  acceptAnswer(remoteSdp: Uint8Array): Promise<void> {
    this.remoteAnswer = Uint8Array.from(remoteSdp);
    return Promise.resolve();
  }
}

interface CarrierEntry {
  readonly operation: AuthenticatedRoomOperationV1;
  readonly workKind: ServiceWorkKindV1;
}

interface CarrierMember {
  readonly name: string;
  readonly driver: PairDriver;
}

/**
 * A two-store carrier stand-in: one append-only log, and every operation is
 * delivered to every driver twice so idempotence is proven on every run.
 */
class FakeCarrier {
  readonly log: CarrierEntry[] = [];
  private readonly members: CarrierMember[] = [];
  private readonly cursor = new Map<string, number>();

  publishFor(): (
    operation: AuthenticatedRoomOperationV1,
    workKind: ServiceWorkKindV1,
  ) => void {
    return (operation, workKind) => {
      this.log.push({ operation, workKind });
    };
  }

  register(name: string, driver: PairDriver): void {
    this.members.push({ name, driver });
    this.cursor.set(name, 0);
  }

  async pump(maxRounds = 24): Promise<void> {
    for (let round = 0; round < maxRounds; round += 1) {
      const to = this.log.length;
      let progressed = false;
      for (const { name, driver } of this.members) {
        const from = this.cursor.get(name) ?? 0;
        if (from >= to) continue;
        this.cursor.set(name, to);
        progressed = true;
        const batch = this.log.slice(from, to).map((entry) => entry.operation);
        for (let copy = 0; copy < 2; copy += 1)
          await driver.ingest(await this.identify(driver, batch));
      }
      if (!progressed) return;
    }
  }

  private async identify(
    driver: PairDriver,
    operations: readonly AuthenticatedRoomOperationV1[],
  ): Promise<OuterValidatedIdentifiedOperationV1[]> {
    const identified: OuterValidatedIdentifiedOperationV1[] = [];
    for (const operation of operations) {
      try {
        identified.push(
          await validateAndIdentifyOperationCandidate(
            operation,
            driver.validationContextAt(LOGICAL_WINDOW),
            module,
          ),
        );
      } catch {
        /* An operation from another room never enters this driver's view. */
      }
    }
    return identified;
  }
}

interface PhaseRecord {
  readonly phase: PairDriverPhase;
  readonly detail: string | undefined;
}

interface Party {
  readonly name: string;
  readonly driver: PairDriver;
  readonly transport: FakeTransport;
  readonly phases: PairDriverPhase[];
  readonly phaseRecords: PhaseRecord[];
}

/**
 * The reason the driver gave for failing this edge, so a test cannot stay green
 * on an unrelated failure.
 */
const failureDetail = (party: Party): string =>
  party.phaseRecords.find((record) => record.phase === "failed")?.detail ?? "";

const createParty = async (options: {
  readonly carrier: FakeCarrier;
  readonly name: string;
  readonly capability: Uint8Array;
  readonly sdp: Uint8Array;
  readonly forgeOwnership?: boolean;
}): Promise<Party> => {
  const identity = await generateSessionIdentity({ wasmBinary });
  identity.x25519SecretKey.fill(0);
  const transport = new FakeTransport(options.sdp);
  const phases: PairDriverPhase[] = [];
  const phaseRecords: PhaseRecord[] = [];
  const driver = new PairDriver({
    module,
    capability: options.capability,
    identity: {
      ed25519PublicKey: identity.ed25519PublicKey,
      ed25519SecretKey: identity.ed25519SecretKey,
      x25519PublicKey: identity.x25519PublicKey,
      x25519CrossSignature: identity.x25519CrossSignature,
    },
    publish: options.carrier.publishFor(),
    transport,
    clock,
    random,
    onPhase: (phase, detail) => {
      phases.push(phase);
      phaseRecords.push({ phase, detail });
    },
    forgePresenceOwnershipForPrototypeTests: options.forgeOwnership,
  });
  options.carrier.register(options.name, driver);
  return { name: options.name, driver, transport, phases, phaseRecords };
};

const runPairedRoom = async (options: {
  readonly capability: Uint8Array;
  readonly sdpA?: Uint8Array;
  readonly sdpB?: Uint8Array;
}): Promise<{
  readonly carrier: FakeCarrier;
  readonly a: Party;
  readonly b: Party;
}> => {
  const carrier = new FakeCarrier();
  const a = await createParty({
    carrier,
    name: "a",
    capability: options.capability,
    sdp: options.sdpA ?? sdpBytes("aaaa", 0xaa),
  });
  const b = await createParty({
    carrier,
    name: "b",
    capability: options.capability,
    sdp: options.sdpB ?? sdpBytes("bbbb", 0xbb),
  });
  await a.driver.start();
  await b.driver.start();
  return { carrier, a, b };
};

describe("prototype pair driver", () => {
  test("reports the payload class its transport flights were published in", async () => {
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x51),
    });
    await carrier.pump();

    // `padPairPlaintextV1` picks the class from the SDP's size and says
    // nothing. In the pinned delivery profile class 1's safety-control slot is
    // 200 ms *earlier* than class 0's, so a flight that quietly changed class
    // would take a different append slot with a smaller budget and every
    // recorded flight timing would be measuring something else. The E2E
    // asserts the value; this asserts that there is a value to assert.
    // Which side offers is decided by the protocol, not by this test, so the
    // record is looked up across both parties rather than assumed.
    const recordFor = (phase: PairDriverPhase): PhaseRecord | undefined =>
      [...a.phaseRecords, ...b.phaseRecords].find(
        (record) => record.phase === phase,
      );
    for (const phase of ["offer-sent", "answered"] as const) {
      const record = recordFor(phase);
      expect(record).toBeDefined();
      expect(record?.detail).toBe("operationPayloadClass 0");
    }
  });

  test("drives presence, HELLO/ACCEPT and OFFER/ANSWER to a shared handoff", async () => {
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x42),
    });
    await carrier.pump();

    expect(a.driver.phase).toBe("handoff");
    expect(b.driver.phase).toBe("handoff");
    const handoffA = a.driver.handoff;
    const handoffB = b.driver.handoff;
    expect(handoffA).not.toBeNull();
    expect(handoffB).not.toBeNull();
    if (handoffA === null || handoffB === null) return;

    expect(hex(handoffA.rendezvousChannelId)).toBe(
      hex(handoffB.rendezvousChannelId),
    );
    expect(hex(handoffA.stableEdgeId)).toBe(hex(handoffB.stableEdgeId));
    expect(hex(handoffA.localFingerprint)).toBe(
      hex(handoffB.remoteFingerprint),
    );
    expect(hex(handoffB.localFingerprint)).toBe(
      hex(handoffA.remoteFingerprint),
    );
    expect(handoffA.sessionRole).not.toBe(handoffB.sessionRole);
    expect(handoffA.rendezvousRole).not.toBe(handoffB.rendezvousRole);

    // Two presences plus one HELLO/ACCEPT/OFFER/ANSWER: every operation was
    // delivered twice and nothing was authored twice.
    expect(carrier.log).toHaveLength(6);
    const workKinds = carrier.log.map((entry) => entry.workKind);
    expect(workKinds).toContain("IDENTITY_HELLO");
    expect(workKinds).toContain("IDENTITY_ACCEPT");
    expect(workKinds).toContain("TRANSPORT_OFFER");
    expect(workKinds).toContain("TRANSPORT_ANSWER");
    expect(a.phases).not.toContain("failed");
    expect(b.phases).not.toContain("failed");

    // The harness privacy audit needs both exact SDPs and the room ids it
    // must never find in a store's wire log.
    const audit = a.driver.auditSecrets();
    expect(audit.capabilityHex).toBe(hex(new Uint8Array(32).fill(0x42)));
    expect(audit.roomContextIdHex).toBe(hex(a.driver.roomContextId));
    expect(audit.sdpLocal).toContain("a=fingerprint:sha-256");
    expect(audit.sdpRemote).toContain("a=fingerprint:sha-256");
    expect(audit.sdpLocal).not.toBe(audit.sdpRemote);
  }, 120_000);

  test("leaves a capability holder for another room at presence-published", async () => {
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x42),
    });
    const c = await createParty({
      carrier,
      name: "c",
      capability: new Uint8Array(32).fill(0x77),
      sdp: sdpBytes("cccc", 0xcc),
    });
    await c.driver.start();
    await carrier.pump();

    expect(c.driver.phase).toBe("presence-published");
    expect(c.driver.handoff).toBeNull();
    expect(a.driver.phase).toBe("handoff");
    expect(b.driver.phase).toBe("handoff");
  }, 120_000);

  test("ignores a re-delivered HELLO whose pair ciphertext was flipped", async () => {
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x42),
    });
    await carrier.pump();
    expect(a.driver.phase).toBe("handoff");
    expect(b.driver.phase).toBe("handoff");

    const helloEntry = carrier.log.find(
      (entry) => entry.workKind === "IDENTITY_HELLO",
    );
    expect(helloEntry).toBeDefined();
    if (helloEntry === undefined) return;
    const responder = a.driver.handoff?.rendezvousRole === "responder" ? a : b;
    const before = responder.driver.phase;

    const original = helloEntry.operation;
    const envelope = decodePairStepEnvelopeV1(
      original.fixedPayload,
      original.operationPayloadClass,
    );
    const pairCiphertextAndTag = Uint8Array.from(envelope.pairCiphertextAndTag);
    pairCiphertextAndTag[0] ^= 0xff;
    const fixedPayload = encodePairStepEnvelopeV1(
      { ...envelope, pairCiphertextAndTag },
      original.operationPayloadClass,
    );
    const author = await newKeyPair(module);
    const unsigned: UnsignedRoomOperationV1 = {
      version: 1,
      roomContextConfirmation: original.roomContextConfirmation,
      logicalWindow: original.logicalWindow,
      expiresAfterWindow: original.expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: author.publicKey,
      authorSequence: 0n,
      previousAuthorOperationId: null,
      kind: "PAIR_STEP",
      semanticSlot: await pairSemanticSlot(envelope.pairRoutingTag),
      dependencies: [],
      operationPayloadClass: original.operationPayloadClass,
      fixedPayload,
      operationPadding: operationPaddingFor(
        original.operationPayloadClass,
        fixedPayload.length,
      ),
    };
    const tampered = await signOperation(unsigned, author.secretKey, module);
    author.secretKey.fill(0);
    const candidate = await validateAndIdentifyOperationCandidate(
      tampered,
      responder.driver.validationContextAt(LOGICAL_WINDOW),
      module,
    );
    await responder.driver.ingest([candidate]);
    await responder.driver.ingest([candidate]);

    expect(responder.driver.phase).toBe(before);
    expect(responder.phases).not.toContain("failed");
  }, 120_000);

  test("fails the edge when a second distinct HELLO claims the same slot", async () => {
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x42),
    });
    // One round delivers both presences; the initiator's first HELLO is
    // published but still undelivered.
    await carrier.pump(1);
    const initiator = a.driver.phase === "hello-sent" ? a : b;
    const responder = initiator === a ? b : a;
    expect(initiator.driver.phase).toBe("hello-sent");

    await initiator.driver.sendHello();
    await carrier.pump();

    expect(responder.driver.phase).toBe("failed");
    expect(responder.phases).toContain("failed");
    expect(failureDetail(responder)).toContain("fork");
  }, 120_000);

  /*
   * Place the forged presence in an exact rendezvous role. The role follows the
   * bytewise order of two hashed presence operation IDs, so the only way to
   * choose it is to build rooms until it lands.
   */
  const runForgedOwnership = async (
    forgedRole: "initiator" | "responder",
  ): Promise<{ readonly forger: Party; readonly honest: Party }> => {
    for (let attempt = 0; attempt < 24; attempt += 1) {
      const carrier = new FakeCarrier();
      const capability = new Uint8Array(32).fill(0x42);
      const forger = await createParty({
        carrier,
        name: "forger",
        capability,
        sdp: sdpBytes("aaaa", 0xaa),
        forgeOwnership: true,
      });
      const honest = await createParty({
        carrier,
        name: "honest",
        capability,
        sdp: sdpBytes("bbbb", 0xbb),
      });
      await forger.driver.start();
      await honest.driver.start();
      await carrier.pump(1);
      const forgerIsInitiator = forger.driver.phase === "hello-sent";
      if (forgerIsInitiator !== (forgedRole === "initiator")) continue;
      await carrier.pump();
      return { forger, honest };
    }
    throw new Error("could not place the forged presence in its role");
  };

  test("rejects a HELLO whose sender presence carries a forged ownership proof", async () => {
    const { honest } = await runForgedOwnership("initiator");
    expect(honest.driver.phase).toBe("failed");
    expect(failureDetail(honest)).toContain("HELLO rejected");
    expect(failureDetail(honest)).toContain("roomOperation payload:");
    expect(honest.driver.handoff).toBeNull();
  }, 120_000);

  test("rejects an ACCEPT whose responder presence carries a forged ownership proof", async () => {
    const { forger, honest } = await runForgedOwnership("responder");
    // The forger opened the honest HELLO and answered it; the honest initiator
    // is the side that must refuse.
    expect(forger.driver.phase).toBe("accepted");
    expect(honest.driver.phase).toBe("failed");
    expect(failureDetail(honest)).toContain("ACCEPT rejected");
    expect(failureDetail(honest)).toContain("roomOperation payload:");
    expect(honest.driver.handoff).toBeNull();
  }, 120_000);

  test("fails before publishing an offer whose SDP exceeds the profile ceiling", async () => {
    const oversized = new TextEncoder().encode(
      "v=0\r\na=fingerprint:sha-256 " +
        fingerprintText(0xdd) +
        "\r\na=x:" +
        "y".repeat(40_000) +
        "\r\n",
    );
    const { carrier, a, b } = await runPairedRoom({
      capability: new Uint8Array(32).fill(0x42),
      sdpA: oversized,
      sdpB: oversized,
    });
    await carrier.pump();

    const failed = [a, b].filter((party) => party.driver.phase === "failed");
    const accepted = [a, b].filter(
      (party) => party.driver.phase === "accepted",
    );
    expect(failed).toHaveLength(1);
    expect(accepted).toHaveLength(1);
    expect(
      carrier.log.some((entry) => entry.workKind === "TRANSPORT_OFFER"),
    ).toBe(false);
    expect(a.driver.handoff).toBeNull();
    expect(b.driver.handoff).toBeNull();
  }, 120_000);
});

describe("prototype transport candidates", () => {
  test("accepts one complete-ICE SDP and rejects malformed ones", async () => {
    const sdp = sdpBytes("aaaa", 0xaa);
    expect(validateWebRtcSdp(sdp).fingerprint).toHaveLength(32);
    expect(() => validateWebRtcSdp(new Uint8Array(0))).toThrow(
      "transportCandidates:",
    );
    expect(() => validateWebRtcSdp(new Uint8Array(32_769).fill(0x61))).toThrow(
      "transportCandidates:",
    );
    const twoFingerprints = new TextEncoder().encode(
      new TextDecoder().decode(sdp) +
        "a=fingerprint:sha-256 " +
        fingerprintText(0xbb) +
        "\r\n",
    );
    expect(() => validateWebRtcSdp(twoFingerprints)).toThrow(
      "transportCandidates:",
    );
  });

  test("counts only the sha-256 line beside another hash algorithm", () => {
    const sdp = sdpBytes("aaaa", 0xaa);
    const expected = hex(validateWebRtcSdp(sdp).fingerprint);
    const withSha384 = new TextEncoder().encode(
      new TextDecoder().decode(sdp) +
        "a=fingerprint:sha-384 " +
        Array.from({ length: 48 }, () => "CD").join(":") +
        "\r\n",
    );
    expect(hex(validateWebRtcSdp(withSha384).fingerprint)).toBe(expected);

    // A mid-line occurrence is not a fingerprint attribute and must not count.
    const midLine = new TextEncoder().encode(
      "a=note:x a=fingerprint:sha-256 " +
        fingerprintText(0xee) +
        "\r\n" +
        new TextDecoder().decode(sdp),
    );
    expect(hex(validateWebRtcSdp(midLine).fingerprint)).toBe(expected);
  });

  test("selects the webrtc candidate from a well-formed offer", async () => {
    const sdp = sdpBytes("aaaa", 0xaa);
    const candidates = await buildOfferCandidates(sdp);
    expect(candidates).toHaveLength(2);
    const selected = await selectWebRtcCandidate(candidates);
    expect(selected.id).toHaveLength(32);
    expect(hex(selected.sdp)).toBe(hex(sdp));
  });

  test("rejects duplicate carriers and unsorted candidate ids", async () => {
    const carriers: readonly PairTransportCandidateV1[] = [
      { version: 1, kind: "operation-carrier" },
      { version: 1, kind: "operation-carrier" },
    ];
    await expect(selectWebRtcCandidate(carriers)).rejects.toThrow(
      "transportCandidates:",
    );

    const sorted = await buildOfferCandidates(sdpBytes("aaaa", 0xaa));
    const unsorted = [...sorted].reverse();
    await expect(selectWebRtcCandidate(unsorted)).rejects.toThrow(
      "transportCandidates:",
    );

    await expect(selectWebRtcCandidate([])).rejects.toThrow(
      "transportCandidates:",
    );
  });
});

describe("prototype outbox work kinds", () => {
  test("classifies every work kind by its Section 4.3 service role", () => {
    expect(operationServiceRole("REPLICATION_OR_BACKFILL")).toBe(
      "state-replication",
    );
    expect(operationServiceRole("PRESENCE")).toBe("state-replication");
    expect(operationServiceRole("STORE_HINT")).toBe("state-replication");
    expect(operationServiceRole("IDENTITY_HELLO")).toBe("identity-bootstrap");
    expect(operationServiceRole("IDENTITY_ACCEPT")).toBe("identity-bootstrap");
    expect(operationServiceRole("LEAVE")).toBe("safety-control");
    expect(operationServiceRole("ADMISSION_REVOKE")).toBe("safety-control");
    expect(operationServiceRole("TRANSPORT_OFFER")).toBe("safety-control");
    expect(operationServiceRole("TRANSPORT_ANSWER")).toBe("safety-control");
    expect(operationServiceRole("PAIR_CHECKPOINT")).toBe("safety-control");
  });
});
