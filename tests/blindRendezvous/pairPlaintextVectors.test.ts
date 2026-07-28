import { describe, expect, test } from "bun:test";

import { encodeCanonical } from "../../src/blindRendezvous/canonicalSchema";
import {
  bindPairOuter,
  confirmedPairTranscriptId,
  pairAad,
  pairEdgeId,
  pairIdentitySignatureHash,
  pairIdentitySignedMessage,
  pairStepKindByte,
  sha256,
  stableEdgeAttemptClaimSignedMessage,
  stableEdgeId,
  transportOfferCandidateId,
  transportNegotiationTranscriptId,
} from "../../src/blindRendezvous/derivations";
import {
  encodePairPlaintextV1,
  padPairPlaintextV1,
  pairIdentityUnsignedProjectionV1,
} from "../../src/blindRendezvous/pairPlaintext";
import { pairPlaintextTargetBytesV1 } from "../../src/blindRendezvous/pairStepEnvelope";
import {
  pairIdentityUnsignedProjectionV1Schema,
  pairPlaintextV1Schema,
  pairTransportCandidateV1Schema,
} from "../../src/blindRendezvous/schemas";

import type {
  PairIdentityAcceptV1,
  PairOuterPrebindingV1,
  PairPlaintextV1,
  PairStepKindV1,
  PairTransportCandidateV1,
  StableEdgeAttemptClaimUnsignedV1,
} from "../../src/blindRendezvous/pairPlaintext";

/**
 * Partial candidate Phase-0 pair-plaintext known-answer vectors.
 *
 * The expected bytes and digests below were generated once by a standalone
 * Python standard-library reference encoder. It knew only the declared field
 * order, primitive U8/U16BE/U32BE/U64BE/optional/union framing, ASCII domains,
 * and SHA-256; it imported no SDK schema, codec, derivation, or fixture.
 */

const filled = (value: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(value);

const hex = (value: Uint8Array): string =>
  [...value].map((octet) => octet.toString(16).padStart(2, "0")).join("");

const SMALL_PAIR_PLAINTEXT_HEX =
  "0109111111111111111111111111111111111111111111111111111111111111111100022222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333300000000000000000201444444444444444444444444444444444444444444444444444444444444444400015555555555555555555555555555555555555555555555555555555555555555090901000000000000000300000000";

const SMALL_PAIR_PLAINTEXT_SHA256 =
  "b2cc9df64266ed85fa92d755078b02af34fb3594874c0df3c6b67144a632d9ef";

const PADDED_SMALL_PAIR_SHA256 =
  "69a1aa91be6bea5a5050ab9101ea117eed57ef1de96fbeb7f4a2692fbe962a8c";

const OPERATION_CARRIER_CANONICAL_HEX = "010101";
const OPERATION_CARRIER_CANDIDATE_ID =
  "395b09979e17e3c2a43b566e9eff5f871cf67f9634cf9327266f25d63f2ddb55";
const PAIR_EDGE_ID =
  "bc33efa2230d563b2e7814ac1a4c8c035945dbb11573299fde95e7aaae625dc3";
const STABLE_EDGE_ID =
  "76a86c806214f7338479ff5d891579ad7314279a17359ed84ced82855c3d628b";
const CONFIRMED_PAIR_TRANSCRIPT_ID =
  "a3301303c0afc2ff29d426f5a71884bba6607eeaf86fd03fb9c1e611ccba07f2";
const TRANSPORT_NEGOTIATION_TRANSCRIPT_ID =
  "7fba1186f4da27ec9f25441a8b7866ddf95d5765361b0f77f5eb872d6923479e";
const STABLE_EDGE_CLAIM_SIGNED_MESSAGE =
  "703270617274792f737461626c652d656467652d617474656d70742d636c61696d" +
  "2d7369676e61747572652f7631" +
  "91e3d5db7ed12161dbde1b4faa6889495133918c09e72b06481afac643cda4c3";

const IDENTITY_ACCEPT_PROJECTION_HEX =
  "01011010101010101010101010101010101010101010101010101010101010101010" +
  "00022020202020202020202020202020202020202020202020202020202020202020" +
  "3030303030303030303030303030303030303030303030303030303030303030" +
  "010000000000000000000001" +
  "4040404040404040404040404040404040404040404040404040404040404040" +
  "010101" +
  "5050505050505050505050505050505050505050505050505050505050505050" +
  "5151515151515151515151515151515151515151515151515151515151515151" +
  "5252525252525252525252525252525252525252525252525252525252525252" +
  "5252525252525252525252525252525252525252525252525252525252525252" +
  "5353535353535353535353535353535353535353535353535353535353535353" +
  "0000000000";

const IDENTITY_ACCEPT_PROJECTION_SHA256 =
  "688dc8ff0677947decfdbf4cbb285fac225a69ce6afe86adeeca2f5e50cade58";
const PAIR_SEMANTIC_SLOT =
  "4aa6c0fd91425d02308de04823eff6e74e7baf43c258910e0534fb38dab55eca";
const PAIR_AAD_SHA256 =
  "2712d3d63985d23ce236a979b5cc47522cb86badcafa469245a25f6332980e8c";
const IDENTITY_TRANSCRIPT_HASH =
  "51c3af9463e2a484449ea1e31d4894915622e7e0c099d522a79b635aab3cc9de";
const IDENTITY_SIGNED_MESSAGE =
  "703270617274792f706169722d6964656e746974792d7369676e61747572652f" +
  "763101" +
  "51c3af9463e2a484449ea1e31d4894915622e7e0c099d522a79b635aab3cc9de";

const smallPairPlaintext: PairPlaintextV1 = {
  version: 1,
  kind: "PAIR_CHECKPOINT",
  pairEdgeId: filled(0x11),
  endpointPresenceOperationIds: [filled(0x22), filled(0x33)],
  direction: 0,
  pairSequence: 2n,
  previousPairOperationId: filled(0x44),
  pairDependencies: [filled(0x55)],
  body: {
    kind: "PAIR_CHECKPOINT",
    value: { version: 1, pqEpoch: 3n },
  },
  pairPadding: new Uint8Array(0),
};

const identityAccept: PairIdentityAcceptV1 = {
  version: 1,
  responderIdentity: {
    ed25519PublicKey: filled(0x50),
    x25519PublicKey: filled(0x51),
    x25519CrossSignature: filled(0x52, 64),
  },
  responderPresenceCommitment: filled(0x53),
  responderAdmissionGrant: null,
  identityTranscriptSignature: filled(0x54, 64),
};

const identityPlaintext: PairPlaintextV1 = {
  version: 1,
  kind: "IDENTITY_ACCEPT",
  pairEdgeId: filled(0x10),
  endpointPresenceOperationIds: [filled(0x20), filled(0x30)],
  direction: 1,
  pairSequence: 0n,
  previousPairOperationId: null,
  pairDependencies: [filled(0x40)],
  body: { kind: "IDENTITY_ACCEPT", value: identityAccept },
  pairPadding: new Uint8Array(0),
};

const prebinding: PairOuterPrebindingV1 = {
  version: 1,
  roomContextConfirmation: filled(0x60),
  policyHash: filled(0x61),
  logicalWindow: 0x0102030405060708n,
  expiresAfterWindow: 0x1112131415161718n,
  lifetime: "PAIR_CAUSAL",
  authorEpochEd25519Key: filled(0x62),
  authorSequence: 0n,
  previousAuthorOperationId: null,
  kind: "PAIR_STEP",
  dependencies: [],
  operationPayloadClass: 0,
  bootstrapHeaderHash: filled(0x63),
  nonce: null,
};

const unsignedClaim: StableEdgeAttemptClaimUnsignedV1 = {
  version: 1,
  stableEdgeId: filled(0xa1),
  pairEdgeId: filled(0xa2),
  confirmedPairTranscriptId: filled(0xa3),
  claimantStableEd25519PublicKey: filled(0xa4),
  claimNotBeforeLogicalWindow: 0x0102030405060708n,
  claimNotAfterLogicalWindow: 0x1112131415161718n,
};

describe("PairPlaintextV1 independent known-answer vectors", () => {
  test("pins all three schema-derived plaintext targets", () => {
    expect(pairPlaintextTargetBytesV1(0, true)).toBe(2_919);
    expect(pairPlaintextTargetBytesV1(0, false)).toBe(4_017);
    expect(pairPlaintextTargetBytesV1(1, false)).toBe(69_553);
  });

  test("pins one complete small plaintext and its target-padded encoding", async () => {
    const unpadded = encodeCanonical(pairPlaintextV1Schema, smallPairPlaintext);
    expect(hex(unpadded)).toBe(SMALL_PAIR_PLAINTEXT_HEX);
    expect(hex(await sha256(unpadded))).toBe(SMALL_PAIR_PLAINTEXT_SHA256);

    const padded = await padPairPlaintextV1(
      smallPairPlaintext,
      false,
      "hybrid-mlkem768",
    );
    expect(padded.operationPayloadClass).toBe(0);
    expect(padded.plaintext.pairPadding.length).toBe(3_826);
    const complete = await encodePairPlaintextV1(
      padded.plaintext,
      padded.operationPayloadClass,
      false,
      "hybrid-mlkem768",
    );
    expect(complete.length).toBe(4_017);
    expect(hex(await sha256(complete))).toBe(PADDED_SMALL_PAIR_SHA256);
  });

  test("pins candidate framing, CandidateId, and symmetric PairEdgeId", async () => {
    const carrier: PairTransportCandidateV1 = {
      version: 1,
      kind: "operation-carrier",
    };
    expect(hex(encodeCanonical(pairTransportCandidateV1Schema, carrier))).toBe(
      OPERATION_CARRIER_CANONICAL_HEX,
    );
    expect(hex(await transportOfferCandidateId(carrier))).toBe(
      OPERATION_CARRIER_CANDIDATE_ID,
    );

    const roomContextId = filled(0x01);
    const firstPresence = filled(0x02);
    const secondPresence = filled(0x03);
    expect(
      hex(await pairEdgeId(roomContextId, firstPresence, secondPresence)),
    ).toBe(PAIR_EDGE_ID);
    expect(
      hex(await pairEdgeId(roomContextId, secondPresence, firstPresence)),
    ).toBe(PAIR_EDGE_ID);
  });

  test("pins selected pair identity and transport transcript derivations", async () => {
    const pairKinds: readonly PairStepKindV1[] = [
      "IDENTITY_HELLO",
      "IDENTITY_ACCEPT",
      "TRANSPORT_OFFER",
      "TRANSPORT_ANSWER",
      "V4_HANDSHAKE",
      "PQ_CONTROL",
      "QUIESCE_PROPOSE",
      "QUIESCE_ACK",
      "HEAL_COMPLETE",
      "PAIR_CHECKPOINT",
    ];
    expect(pairKinds.map((kind) => hex(pairStepKindByte(kind)))).toEqual([
      "00",
      "01",
      "02",
      "03",
      "04",
      "05",
      "06",
      "07",
      "08",
      "09",
    ]);
    expect(
      hex(await stableEdgeId(filled(0x01), filled(0x04), filled(0x05))),
    ).toBe(STABLE_EDGE_ID);
    expect(
      hex(await confirmedPairTranscriptId(filled(0x06), filled(0x07))),
    ).toBe(CONFIRMED_PAIR_TRANSCRIPT_ID);
    expect(
      hex(await transportNegotiationTranscriptId(filled(0x08), filled(0x09))),
    ).toBe(TRANSPORT_NEGOTIATION_TRANSCRIPT_ID);
    expect(hex(await stableEdgeAttemptClaimSignedMessage(unsignedClaim))).toBe(
      STABLE_EDGE_CLAIM_SIGNED_MESSAGE,
    );
  });

  test("pins identity projection bytes, transcript hash, and signed message", async () => {
    const projection = pairIdentityUnsignedProjectionV1(identityPlaintext);
    const projectionBytes = encodeCanonical(
      pairIdentityUnsignedProjectionV1Schema,
      projection,
    );
    expect(hex(projectionBytes)).toBe(IDENTITY_ACCEPT_PROJECTION_HEX);
    expect(hex(await sha256(projectionBytes))).toBe(
      IDENTITY_ACCEPT_PROJECTION_SHA256,
    );

    const binding = await bindPairOuter(prebinding, filled(0x64));
    expect(hex(binding.semanticSlot)).toBe(PAIR_SEMANTIC_SLOT);
    const aad = await pairAad(binding);
    expect(aad.length).toBe(243);
    expect(hex(await sha256(aad))).toBe(PAIR_AAD_SHA256);
    expect(hex(await pairIdentitySignatureHash(binding, projection))).toBe(
      IDENTITY_TRANSCRIPT_HASH,
    );
    expect(hex(await pairIdentitySignedMessage(binding, projection))).toBe(
      IDENTITY_SIGNED_MESSAGE,
    );

    await expect(
      pairIdentitySignatureHash(binding, {
        ...projection,
        kind: "IDENTITY_HELLO",
      }),
    ).rejects.toThrow("kind and body discriminator disagree");
  });

  test("rejects protocol-impossible outer transcript values", async () => {
    const routingTag = filled(0x64);
    for (const invalid of [
      { ...prebinding, lifetime: "WINDOW_TRANSIENT" },
      { ...prebinding, kind: "PRESENCE" },
      { ...prebinding, dependencies: [filled(0x70)] },
      { ...prebinding, operationPayloadClass: 255 },
      {
        ...prebinding,
        operationPayloadClass: 1,
        nonce: null,
      },
      {
        ...prebinding,
        bootstrapHeaderHash: filled(0x63),
        nonce: filled(0x71, 24),
      },
    ])
      await expect(bindPairOuter(invalid, routingTag)).rejects.toThrow();

    const binding = await bindPairOuter(prebinding, routingTag);
    await expect(
      pairAad({ ...binding, semanticSlot: filled(0xff) }),
    ).rejects.toThrow("semantic slot does not match");
  });
});
