import { describe, expect, test } from "bun:test";

import { encodeCanonical } from "../../src/blindRendezvous/canonicalSchema";
import { transportOfferCandidateId } from "../../src/blindRendezvous/derivations";
import {
  decodePairPlaintextV1 as decodePairPlaintextV1ForMode,
  encodePairPlaintextV1 as encodePairPlaintextV1ForMode,
  padPairPlaintextV1 as padPairPlaintextV1ForMode,
  pairIdentityUnsignedProjectionV1,
  pairOperationPayloadClassForV1,
  validatePairBootstrapInfoV1,
  validatePairFlightSlotV1,
} from "../../src/blindRendezvous/pairPlaintext";
import { pairPlaintextTargetBytesV1 } from "../../src/blindRendezvous/pairStepEnvelope";
import { pairPlaintextV1Schema } from "../../src/blindRendezvous/schemas";
import {
  HANDSHAKE_STEP,
  handshakePayloadLengthForStep,
} from "../../src/handlers/handshakeFrame";
import { WIRE_CHUNK_FRAME_LEN } from "../../src/utils/constants";

import type {
  PairIdentityAcceptV1,
  PairBootstrapInfoV1,
  PairIdentityHelloV1,
  PairPlaintextV1,
  PairStepBodyV1,
  PairTransportCandidateV1,
  StableEdgeAttemptClaimV1,
} from "../../src/blindRendezvous/pairPlaintext";
import type { RoomPqMode } from "../../src/roomPolicy";

const TEST_ROOM_PQ_MODE: RoomPqMode = "hybrid-mlkem768";

const padPairPlaintextV1 = (
  plaintext: PairPlaintextV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode = TEST_ROOM_PQ_MODE,
) => padPairPlaintextV1ForMode(plaintext, bootstrapHeaderPresent, roomPqMode);

const encodePairPlaintextV1 = (
  plaintext: PairPlaintextV1,
  operationPayloadClass: 0 | 1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode = TEST_ROOM_PQ_MODE,
) =>
  encodePairPlaintextV1ForMode(
    plaintext,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );

const decodePairPlaintextV1 = (
  encoded: Uint8Array,
  operationPayloadClass: 0 | 1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode = TEST_ROOM_PQ_MODE,
) =>
  decodePairPlaintextV1ForMode(
    encoded,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
};

const orderedCandidates = async (
  ...candidates: readonly PairTransportCandidateV1[]
): Promise<PairTransportCandidateV1[]> => {
  const withIds = await Promise.all(
    candidates.map(async (candidate) => ({
      candidate,
      id: await transportOfferCandidateId(candidate),
    })),
  );
  withIds.sort((left, right) => compareBytes(left.id, right.id));
  return withIds.map(({ candidate }) => candidate);
};

const claim = (): StableEdgeAttemptClaimV1 => ({
  version: 1,
  stableEdgeId: bytes(0x31),
  pairEdgeId: bytes(0x32),
  confirmedPairTranscriptId: bytes(0x33),
  claimantStableEd25519PublicKey: bytes(0x34),
  claimNotBeforeLogicalWindow: 50n,
  claimNotAfterLogicalWindow: 60n,
  claimantSignature: bytes(0x35, 64),
});

const helloBody = (): PairIdentityHelloV1 => ({
  version: 1,
  attemptMode: "planner",
  senderIdentity: {
    ed25519PublicKey: bytes(0x41),
    x25519PublicKey: bytes(0x42),
    x25519CrossSignature: bytes(0x43, 64),
  },
  senderPresenceCommitment: bytes(0x44),
  senderAdmissionGrant: null,
  responseHybridKemPublicKey: bytes(0x45, 1216),
  identityTranscriptSignature: bytes(0x46, 64),
});

const acceptBody = (): PairIdentityAcceptV1 => ({
  version: 1,
  responderIdentity: {
    ed25519PublicKey: bytes(0x51),
    x25519PublicKey: bytes(0x52),
    x25519CrossSignature: bytes(0x53, 64),
  },
  responderPresenceCommitment: bytes(0x54),
  responderAdmissionGrant: null,
  identityTranscriptSignature: bytes(0x55, 64),
});

const handshakePayload = (): Uint8Array => {
  const payload = new Uint8Array(
    handshakePayloadLengthForStep(HANDSHAKE_STEP.CONFIRM, "hybrid-mlkem768"),
  );
  payload[0] = HANDSHAKE_STEP.CONFIRM;
  return payload;
};

const plaintext = (
  body: PairStepBodyV1,
  direction: 0 | 1,
  pairSequence: bigint,
  previousPairOperationId: Uint8Array | null,
  pairDependencies: readonly Uint8Array[],
): PairPlaintextV1 => ({
  version: 1,
  kind: body.kind,
  pairEdgeId: bytes(0x21),
  endpointPresenceOperationIds: [bytes(0x10), bytes(0x20)],
  direction,
  pairSequence,
  previousPairOperationId,
  pairDependencies,
  body,
  pairPadding: new Uint8Array(0),
});

const allBodies = async (): Promise<
  Array<{
    readonly plaintext: PairPlaintextV1;
    readonly bootstrap: boolean;
    readonly expectedClass: 0 | 1;
  }>
> => {
  const operationCarrier = {
    version: 1,
    kind: "operation-carrier",
  } as const;
  return [
    {
      plaintext: plaintext(
        { kind: "IDENTITY_HELLO", value: helloBody() },
        0,
        0n,
        null,
        [],
      ),
      bootstrap: true,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        { kind: "IDENTITY_ACCEPT", value: acceptBody() },
        1,
        0n,
        null,
        [bytes(0x61)],
      ),
      bootstrap: true,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        {
          kind: "TRANSPORT_OFFER",
          value: {
            version: 1,
            initiatorStableEdgeClaim: claim(),
            candidates: [operationCarrier],
          },
        },
        0,
        1n,
        bytes(0x61),
        [bytes(0x62)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        {
          kind: "TRANSPORT_ANSWER",
          value: {
            version: 1,
            responderStableEdgeClaim: claim(),
            selectedOfferCandidateId:
              await transportOfferCandidateId(operationCarrier),
            answer: operationCarrier,
          },
        },
        1,
        1n,
        bytes(0x62),
        [bytes(0x63)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        { kind: "V4_HANDSHAKE", value: handshakePayload() },
        0,
        2n,
        bytes(0x63),
        [bytes(0x64)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        {
          kind: "PQ_CONTROL",
          value: new Uint8Array(WIRE_CHUNK_FRAME_LEN),
        },
        0,
        3n,
        bytes(0x64),
        [bytes(0x65)],
      ),
      bootstrap: false,
      expectedClass: 1,
    },
    {
      plaintext: plaintext(
        { kind: "QUIESCE_PROPOSE", value: { version: 1, pqEpoch: 7n } },
        0,
        3n,
        bytes(0x64),
        [],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        { kind: "QUIESCE_ACK", value: { version: 1, pqEpoch: 7n } },
        1,
        2n,
        bytes(0x63),
        [bytes(0x65)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        { kind: "HEAL_COMPLETE", value: { version: 1, newPqEpoch: 8n } },
        1,
        3n,
        bytes(0x65),
        [bytes(0x66)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
    {
      plaintext: plaintext(
        { kind: "PAIR_CHECKPOINT", value: { version: 1, pqEpoch: 8n } },
        0,
        4n,
        bytes(0x66),
        [bytes(0x67)],
      ),
      bootstrap: false,
      expectedClass: 0,
    },
  ];
};

describe("PairPlaintextV1 closed body codec", () => {
  test("all ten bodies select, fill, and round-trip their exact target", async () => {
    for (const fixture of await allBodies()) {
      const padded = await padPairPlaintextV1(
        fixture.plaintext,
        fixture.bootstrap,
      );
      expect(padded.operationPayloadClass).toBe(fixture.expectedClass);
      const encoded = await encodePairPlaintextV1(
        padded.plaintext,
        padded.operationPayloadClass,
        fixture.bootstrap,
      );
      expect(encoded.length).toBe(
        pairPlaintextTargetBytesV1(
          padded.operationPayloadClass,
          fixture.bootstrap,
        ),
      );
      expect(
        await decodePairPlaintextV1(
          encoded,
          padded.operationPayloadClass,
          fixture.bootstrap,
        ),
      ).toEqual(padded.plaintext);
    }
  });

  test("the class-1 threshold derives the exact 65,535-byte maximum padding", async () => {
    const carrier = {
      version: 1,
      kind: "operation-carrier",
    } as const;
    const initialWebrtc = {
      version: 1,
      kind: "webrtc-complete",
      exactSdpUtf8: new Uint8Array([0x61]),
    } as const;
    const initial = plaintext(
      {
        kind: "TRANSPORT_OFFER",
        value: {
          version: 1,
          initiatorStableEdgeClaim: claim(),
          candidates: await orderedCandidates(carrier, initialWebrtc),
        },
      },
      0,
      1n,
      bytes(0x71),
      [bytes(0x72)],
    );
    const initialLength = encodeCanonical(
      pairPlaintextV1Schema,
      initial,
    ).length;
    const sdpLength = 1 + (4_018 - initialLength);
    expect(sdpLength).toBeGreaterThan(0);
    const boundaryWebrtc = {
      ...initialWebrtc,
      exactSdpUtf8: bytes(0x61, sdpLength),
    };
    const boundary = {
      ...initial,
      body: {
        ...initial.body,
        value: {
          ...initial.body.value,
          candidates: await orderedCandidates(carrier, boundaryWebrtc),
        },
      },
    } as PairPlaintextV1;
    expect(encodeCanonical(pairPlaintextV1Schema, boundary).length).toBe(4_018);
    expect(pairOperationPayloadClassForV1(boundary, false)).toBe(1);

    const padded = await padPairPlaintextV1(boundary, false);
    expect(padded.operationPayloadClass).toBe(1);
    expect(padded.plaintext.pairPadding.length).toBe(65_535);
    expect(
      (await encodePairPlaintextV1(padded.plaintext, 1, false)).length,
    ).toBe(69_553);
  });

  test("identity projection removes only the nested signature", async () => {
    const fixture = (await allBodies())[0];
    const padded = await padPairPlaintextV1(
      fixture.plaintext,
      fixture.bootstrap,
    );
    const projection = pairIdentityUnsignedProjectionV1(padded.plaintext);
    expect(projection.kind).toBe("IDENTITY_HELLO");
    expect(projection.body.kind).toBe("IDENTITY_HELLO");
    expect("identityTranscriptSignature" in projection.body.value).toBe(false);
    expect(projection.pairPadding).toEqual(padded.plaintext.pairPadding);
  });
});

describe("PairPlaintextV1 rejects alternate inner meanings", () => {
  test("closes flight-slot and bootstrap-info values beyond broad field enums", () => {
    expect(() =>
      validatePairFlightSlotV1({
        kind: "V4_HANDSHAKE",
        direction: 2,
        pairSequence: 2n,
      } as unknown as Parameters<typeof validatePairFlightSlotV1>[0]),
    ).toThrow("direction must be 0 or 1");

    const bootstrapInfo: PairBootstrapInfoV1 = {
      version: 1,
      pairBootstrapSuite: 1,
      roomContextConfirmation: bytes(0xa1),
      policyHash: bytes(0xa2),
      stepKind: "IDENTITY_HELLO",
      logicalWindow: 10n,
      expiresAfterWindow: 20n,
      authorEpochEd25519Key: bytes(0xa3),
      authorSequence: 0n,
      previousAuthorOperationId: null,
      operationPayloadClass: 0,
      recipientBinding: {
        kind: "presence",
        presenceOperationId: bytes(0xa4),
      },
    };
    expect(() => validatePairBootstrapInfoV1(bootstrapInfo)).not.toThrow();
    expect(() =>
      validatePairBootstrapInfoV1({
        ...bootstrapInfo,
        stepKind: "PQ_CONTROL",
      } as unknown as PairBootstrapInfoV1),
    ).toThrow("step must be IDENTITY_HELLO or IDENTITY_ACCEPT");
    expect(() =>
      validatePairBootstrapInfoV1({
        ...bootstrapInfo,
        operationPayloadClass: 1,
      }),
    ).toThrow("payload class 0");
    expect(() =>
      validatePairBootstrapInfoV1({
        ...bootstrapInfo,
        recipientBinding: {
          kind: "hello-response",
          helloOperationId: bytes(0xa5),
        },
      }),
    ).toThrow("step and recipient binding disagree");
  });

  test("rejects body-kind/header disagreements and invalid initial slots", async () => {
    const hello = (await allBodies())[0].plaintext;
    await expect(
      padPairPlaintextV1(
        {
          ...hello,
          kind: "IDENTITY_ACCEPT",
        } as PairPlaintextV1,
        true,
      ),
    ).rejects.toThrow("kind and body discriminator disagree");
    await expect(padPairPlaintextV1(hello, false)).rejects.toThrow(
      "identity flights require a bootstrap header",
    );
    await expect(
      padPairPlaintextV1(
        { ...hello, pairSequence: 1n } as PairPlaintextV1,
        true,
      ),
    ).rejects.toThrow("non-zero pair sequence must name its predecessor");
    await expect(
      padPairPlaintextV1(
        {
          ...hello,
          endpointPresenceOperationIds: [
            hello.endpointPresenceOperationIds[1],
            hello.endpointPresenceOperationIds[0],
          ],
        },
        true,
      ),
    ).rejects.toThrow("strictly role-ordered");

    const accept = (await allBodies())[1].plaintext;
    await expect(
      padPairPlaintextV1(
        { ...accept, pairDependencies: [] } as PairPlaintextV1,
        true,
      ),
    ).rejects.toThrow("must carry 1 pair dependencies");
  });

  test("rejects nonzero, short, and outer-class-mismatched padding", async () => {
    const fixture = (await allBodies())[0];
    const { plaintext: padded } = await padPairPlaintextV1(
      fixture.plaintext,
      true,
    );
    const nonzeroPadding = Uint8Array.from(padded.pairPadding);
    nonzeroPadding[0] = 1;
    await expect(
      encodePairPlaintextV1(
        { ...padded, pairPadding: nonzeroPadding },
        0,
        true,
      ),
    ).rejects.toThrow("all-zero");
    await expect(
      encodePairPlaintextV1(
        { ...padded, pairPadding: padded.pairPadding.subarray(1) },
        0,
        true,
      ),
    ).rejects.toThrow("pairPadding must be exactly");
    await expect(encodePairPlaintextV1(padded, 1, true)).rejects.toThrow(
      "bootstrap header is permitted only in payload class 0",
    );
  });

  test("rejects candidate hash misordering and missing mandatory carrier", async () => {
    const carrier = {
      version: 1,
      kind: "operation-carrier",
    } as const;
    const webrtc = {
      version: 1,
      kind: "webrtc-complete",
      exactSdpUtf8: new TextEncoder().encode("v=0\r\n"),
    } as const;
    const ordered = await orderedCandidates(carrier, webrtc);
    const offer = plaintext(
      {
        kind: "TRANSPORT_OFFER",
        value: {
          version: 1,
          initiatorStableEdgeClaim: claim(),
          candidates: [...ordered].reverse(),
        },
      },
      0,
      1n,
      bytes(0x81),
      [bytes(0x82)],
    );
    await expect(padPairPlaintextV1(offer, false)).rejects.toThrow(
      "sorted by candidate ID",
    );
    await expect(
      padPairPlaintextV1(
        {
          ...offer,
          body: {
            ...offer.body,
            value: {
              ...offer.body.value,
              candidates: [webrtc],
            },
          },
        } as PairPlaintextV1,
        false,
      ),
    ).rejects.toThrow("exactly one operation carrier");
  });

  test("rejects empty, malformed, repeated, and over-bound candidates", async () => {
    const carrier = {
      version: 1,
      kind: "operation-carrier",
    } as const;
    const offerWith = (
      candidates: readonly PairTransportCandidateV1[],
    ): PairPlaintextV1 =>
      plaintext(
        {
          kind: "TRANSPORT_OFFER",
          value: {
            version: 1,
            initiatorStableEdgeClaim: claim(),
            candidates,
          },
        },
        0,
        1n,
        bytes(0x85),
        [bytes(0x86)],
      );

    await expect(
      padPairPlaintextV1(
        offerWith([
          carrier,
          {
            version: 1,
            kind: "webrtc-complete",
            exactSdpUtf8: new Uint8Array(0),
          },
        ]),
        false,
      ),
    ).rejects.toThrow("SDP must not be empty");
    await expect(
      padPairPlaintextV1(
        offerWith([
          carrier,
          {
            version: 1,
            kind: "webrtc-complete",
            exactSdpUtf8: Uint8Array.of(0xc3, 0x28),
          },
        ]),
        false,
      ),
    ).rejects.toThrow("well-formed UTF-8");
    await expect(
      padPairPlaintextV1(
        offerWith([
          carrier,
          {
            version: 1,
            kind: "registered-local-link",
            adapterProtocolId: 1,
            fixedCanonicalCandidate: new Uint8Array(0),
          },
        ]),
        false,
      ),
    ).rejects.toThrow("local candidate must not be empty");
    await expect(
      padPairPlaintextV1(offerWith([carrier, carrier]), false),
    ).rejects.toThrow("exactly one operation carrier");
    await expect(
      padPairPlaintextV1(
        offerWith([carrier, carrier, carrier, carrier]),
        false,
      ),
    ).rejects.toThrow("3-entry collection bound");
    await expect(
      padPairPlaintextV1(
        offerWith([
          carrier,
          {
            version: 1,
            kind: "webrtc-complete",
            exactSdpUtf8: bytes(0x61, 32_769),
          },
        ]),
        false,
      ),
    ).rejects.toThrow("32768-byte bound");
  });

  test("snapshots candidates before asynchronous encode validation", async () => {
    const carrier = {
      version: 1,
      kind: "operation-carrier",
    } as const;
    const webrtc = {
      version: 1,
      kind: "webrtc-complete",
      exactSdpUtf8: new TextEncoder().encode("v=0\r\n"),
    } as const;
    const offer = plaintext(
      {
        kind: "TRANSPORT_OFFER",
        value: {
          version: 1,
          initiatorStableEdgeClaim: claim(),
          candidates: await orderedCandidates(carrier, webrtc),
        },
      },
      0,
      1n,
      bytes(0x91),
      [bytes(0x92)],
    );
    const padded = await padPairPlaintextV1(offer, false);
    expect(padded.plaintext.body.kind).toBe("TRANSPORT_OFFER");
    if (padded.plaintext.body.kind !== "TRANSPORT_OFFER")
      throw new Error("test fixture body narrowed incorrectly");

    const callerCandidates = padded.plaintext.body.value
      .candidates as PairTransportCandidateV1[];
    const pending = encodePairPlaintextV1(
      padded.plaintext,
      padded.operationPayloadClass,
      false,
    );
    callerCandidates.reverse();

    // encodePairPlaintextV1 snapshots synchronously before its first await, so
    // the in-flight validation observes the original canonical ordering.
    expect((await pending).length).toBe(4_017);
    await expect(
      encodePairPlaintextV1(
        padded.plaintext,
        padded.operationPayloadClass,
        false,
      ),
    ).rejects.toThrow("sorted by candidate ID");
  });

  test("binds v4 handshake framing to the room-selected PQ suite", async () => {
    const fixture = (await allBodies())[4].plaintext;
    const invalid = Uint8Array.from(handshakePayload());
    invalid[0] = 0xff;
    await expect(
      padPairPlaintextV1(
        {
          ...fixture,
          body: { kind: "V4_HANDSHAKE", value: invalid },
        },
        false,
      ),
    ).rejects.toThrow("room-selected PQ suite");

    const mlKem512Hello = new Uint8Array(
      handshakePayloadLengthForStep(HANDSHAKE_STEP.HELLO, "hybrid-mlkem512"),
    );
    mlKem512Hello[0] = HANDSHAKE_STEP.HELLO;
    const crossSuite = {
      ...fixture,
      body: { kind: "V4_HANDSHAKE", value: mlKem512Hello },
    } as PairPlaintextV1;
    await expect(
      padPairPlaintextV1(crossSuite, false, "hybrid-mlkem768"),
    ).rejects.toThrow("room-selected PQ suite");
    await expect(
      padPairPlaintextV1(crossSuite, false, "hybrid-mlkem512"),
    ).resolves.toMatchObject({ operationPayloadClass: 0 });
  });
});
