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
import {
  encodePairStepEnvelopeV1,
  pairPlaintextTargetBytesV1,
} from "../../src/blindRendezvous/pairStepEnvelope";
import {
  pairIdentityUnsignedProjectionV1Schema,
  pairPlaintextV1Schema,
  pairTransportCandidateV1Schema,
} from "../../src/blindRendezvous/schemas";

import type {
  PairIdentityAcceptV1,
  PairOuterPrebindingV1,
  PairPlaintextV1,
  PairStepBodyV1,
  PairStepKindV1,
  PairTransportCandidateV1,
  StableEdgeAttemptClaimV1,
  StableEdgeAttemptClaimUnsignedV1,
} from "../../src/blindRendezvous/pairPlaintext";
import type { PairStepEnvelopeV1 } from "../../src/blindRendezvous/pairStepEnvelope";

/**
 * Candidate Phase-0 pair-codec known-answer vectors.
 *
 * The expected bytes and digests below are emitted by the checked-in,
 * standalone Python standard-library reference encoder at
 * `tests/blindRendezvous/reference/pair_plaintext_vectors.py`. It knows only
 * the declared field order, primitive framing, ASCII domains, and SHA-256; it
 * imports no SDK schema, codec, derivation, or fixture.
 *
 * This closes the every-pair-body vector sub-gate. It does not by itself claim
 * whole-AC-035 conformance, which also requires the separately tracked outer
 * operation, store-hint, layer-boundary, and state-predecessor gates.
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

const IDENTITY_ACCEPT_PADDING_LENGTH = 2_543;
const IDENTITY_ACCEPT_PROJECTION_LENGTH = 2_855;
const IDENTITY_ACCEPT_PROJECTION_PREFIX_HEX =
  "010110101010101010101010101010101010101010101010101010101010101010100002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030";
const IDENTITY_ACCEPT_PROJECTION_SUFFIX_HEX = "00".repeat(96);
const IDENTITY_ACCEPT_PROJECTION_SHA256 =
  "7aa44eb31c7b7fae039cbe631ea14dcbd8c53ee1996011809f7ddd772920d778";
const PAIR_SEMANTIC_SLOT =
  "4aa6c0fd91425d02308de04823eff6e74e7baf43c258910e0534fb38dab55eca";
const PAIR_AAD_SHA256 =
  "2712d3d63985d23ce236a979b5cc47522cb86badcafa469245a25f6332980e8c";
const IDENTITY_TRANSCRIPT_HASH =
  "b1b26454f89ea86ee853b421c390c1c7c82dd06c4a672b7f37a5de5ec2aa28ee";
const IDENTITY_SIGNED_MESSAGE =
  "703270617274792f706169722d6964656e746974792d7369676e61747572652f" +
  "763101" +
  "b1b26454f89ea86ee853b421c390c1c7c82dd06c4a672b7f37a5de5ec2aa28ee";

interface PairBodyVector {
  readonly kind: PairStepKindV1;
  readonly bootstrap: boolean;
  readonly operationClass: 0 | 1;
  readonly unpaddedLength: number;
  readonly unpaddedSha256: string;
  readonly unpaddedPrefixHex: string;
  readonly unpaddedSuffixHex: string;
  readonly paddingLength: number;
  readonly paddedSha256: string;
}

/**
 * Full independent matrix for PairStepBodyV1. SHA-256 pins every canonical
 * octet; the 94–96-byte edges make the outer framing and terminal body/padding
 * framing directly reviewable without embedding 131 KiB of repetitive hex.
 */
const PAIR_BODY_VECTORS: readonly PairBodyVector[] = [
  {
    kind: "IDENTITY_HELLO",
    bootstrap: true,
    operationClass: 0,
    unpaddedLength: 1_561,
    unpaddedSha256:
      "0ef181b060551d8ea586efe16a210b124b8aa9a58431ac422d10f5167e5b425f",
    unpaddedPrefixHex:
      "010010101010101010101010101010101010101010101010101010101010101010100002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "747474747474747474747474747474747474747474747474747474747575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757500000000",
    paddingLength: 1_358,
    paddedSha256:
      "75659dc3d3343a082e2403f6158867c2785865d669ef743dc220adf95554af74",
  },
  {
    kind: "IDENTITY_ACCEPT",
    bootstrap: true,
    operationClass: 0,
    unpaddedLength: 376,
    unpaddedSha256:
      "13a466d6778195492f541501a736232fbb19de5c6369ab802a24724c40237abc",
    unpaddedPrefixHex:
      "010111111111111111111111111111111111111111111111111111111111111111110002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "797979797979797979797979797979797979797979797979797979007a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a00000000",
    paddingLength: IDENTITY_ACCEPT_PADDING_LENGTH,
    paddedSha256:
      "fc5d3d1d9b1949b9fe5b3dec4d865a4fcfaf128f51f12db6e71b6e384a58f078",
  },
  {
    kind: "TRANSPORT_OFFER",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 397,
    unpaddedSha256:
      "527d65afe9d6cbd3272b4e3229313e4fdebe03214ccb1d8b30d7a2ad61cc376f",
    unpaddedPrefixHex:
      "010212121212121212121212121212121212121212121212121212121212121212120002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "838383838383830102030405060708111213141516171884848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484000101010100000000",
    paddingLength: 3_620,
    paddedSha256:
      "953fae4664c29f20c71bd7e2c1b516e3ec351e7c9e65e1dacf8ad85294b822cf",
  },
  {
    kind: "TRANSPORT_ANSWER",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 447,
    unpaddedSha256:
      "9038fe399e50589fc504bbf0b337a12393ec09008191b967426a4d896188ecb3",
    unpaddedPrefixHex:
      "010313131313131313131313131313131313131313131313131313131313131313130002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b00010000000010763d300d0a733d703270617274790d0a00000000",
    paddingLength: 3_570,
    paddedSha256:
      "58fb9271af5e5ac4b496285b2582a41e96efdf64da3e1eba80d3bb17f404ae8d",
  },
  {
    kind: "V4_HANDSHAKE",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 2_651,
    unpaddedSha256:
      "0601285605d8ccd44b70394ab8051d69dc01876dfb32681def3a9af15896f8fb",
    unpaddedPrefixHex:
      "010414141414141414141414141414141414141414141414141414141414141414140002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c00000000",
    paddingLength: 1_366,
    paddedSha256:
      "a58dfbdd966a1a4b450e2b34f552cb236126add144b912d3590183fb07521f64",
  },
  {
    kind: "PQ_CONTROL",
    bootstrap: false,
    operationClass: 1,
    unpaddedLength: 65_672,
    unpaddedSha256:
      "3eabfae65480115ec15e59381dbd963d3bbc4dfad35023bcf41120dd956ac931",
    unpaddedPrefixHex:
      "010515151515151515151515151515151515151515151515151515151515151515150002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d00000000",
    paddingLength: 3_881,
    paddedSha256:
      "a1439c03a6cad67ac5ac319b178f7e47aa9b0748f974fc945d9c1da76005c06a",
  },
  {
    kind: "QUIESCE_PROPOSE",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 159,
    unpaddedSha256:
      "e1daf596d5adf12d901a9dd7ff4aa6a32e3a920c3a526ab6f58d5f24d01c10b5",
    unpaddedPrefixHex:
      "010616161616161616161616161616161616161616161616161616161616161616160002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "202020202030303030303030303030303030303030303030303030303030303030303030300000000000000000030146464646464646464646464646464646464646464646464646464646464646460000060601212223242526272800000000",
    paddingLength: 3_858,
    paddedSha256:
      "0dbe54cb8b2033e84a4f65a8e02b9fe4ba1df9fa7e902de287889ecad33ce0a4",
  },
  {
    kind: "QUIESCE_ACK",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 191,
    unpaddedSha256:
      "da5b077b2ac867e8cfd9a5093b1ddbf4fe5a4a63abe359f05363551e7ce451dc",
    unpaddedPrefixHex:
      "010717171717171717171717171717171717171717171717171717171717171717170002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "303030303001000000000000000301474747474747474747474747474747474747474747474747474747474747474700016767676767676767676767676767676767676767676767676767676767676767070701313233343536373800000000",
    paddingLength: 3_826,
    paddedSha256:
      "1fa3471047493bffb9231d31701b81ffd521d6f7ba3bdead4d5d6b391e2ce604",
  },
  {
    kind: "HEAL_COMPLETE",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 191,
    unpaddedSha256:
      "914180909e0a212c6a70160a69a7c09662ae47f3a4cf5f31027a690e4adb6f7d",
    unpaddedPrefixHex:
      "010818181818181818181818181818181818181818181818181818181818181818180002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "303030303000000000000000000401484848484848484848484848484848484848484848484848484848484848484800016868686868686868686868686868686868686868686868686868686868686868080801414243444546474800000000",
    paddingLength: 3_826,
    paddedSha256:
      "5a3d4e3e92aa020c9919058c7e089935f8cdaf19ed4879fa87cf0533d1bd4418",
  },
  {
    kind: "PAIR_CHECKPOINT",
    bootstrap: false,
    operationClass: 0,
    unpaddedLength: 191,
    unpaddedSha256:
      "1123b05307af3135b87dde395d76fe06f43934eae5d236098887b888093674a4",
    unpaddedPrefixHex:
      "010919191919191919191919191919191919191919191919191919191919191919190002202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030",
    unpaddedSuffixHex:
      "303030303001000000000000000401494949494949494949494949494949494949494949494949494949494949494900016969696969696969696969696969696969696969696969696969696969696969090901515253545556575800000000",
    paddingLength: 3_826,
    paddedSha256:
      "976d47a3968ed125a0f4a75a85fcececc97852ba2bfd400c9961df88a4528f14",
  },
];

interface PairEnvelopeVector {
  readonly operationClass: 0 | 1;
  readonly bootstrap: boolean;
  readonly ciphertextLength: number;
  readonly encodedLength: number;
  readonly sha256: string;
  readonly prefixHex: string;
  readonly suffixHex: string;
}

const PAIR_ENVELOPE_VECTORS: readonly PairEnvelopeVector[] = [
  {
    operationClass: 0,
    bootstrap: true,
    ciphertextLength: 2_935,
    encodedLength: 4_096,
    sha256: "59cb7535aef5d71a188adda0ac87a0ee136ef87029474ff2f7328530046b56d5",
    prefixHex:
      "01a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    suffixHex:
      "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
  },
  {
    operationClass: 0,
    bootstrap: false,
    ciphertextLength: 4_033,
    encodedLength: 4_096,
    sha256: "4a1edb07876b034ad6728cf67579c07af63238f53936b5670fab28cb04ef921a",
    prefixHex:
      "01b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b100000fc1b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    suffixHex:
      "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
  },
  {
    operationClass: 1,
    bootstrap: false,
    ciphertextLength: 69_569,
    encodedLength: 69_632,
    sha256: "a49ce2925874ba27084ba156333f0551f00e51d0ff53a710023507aae06935bb",
    prefixHex:
      "01b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b100010fc1b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    suffixHex:
      "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
  },
];

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
  pairPadding: new Uint8Array(IDENTITY_ACCEPT_PADDING_LENGTH),
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

const vectorClaim = (start: number): StableEdgeAttemptClaimV1 => ({
  version: 1,
  stableEdgeId: filled(start),
  pairEdgeId: filled(start + 1),
  confirmedPairTranscriptId: filled(start + 2),
  claimantStableEd25519PublicKey: filled(start + 3),
  claimNotBeforeLogicalWindow: 0x0102030405060708n,
  claimNotAfterLogicalWindow: 0x1112131415161718n,
  claimantSignature: filled(start + 4, 64),
});

const vectorBody = (kind: PairStepKindV1): PairStepBodyV1 => {
  switch (kind) {
    case "IDENTITY_HELLO":
      return {
        kind,
        value: {
          version: 1,
          attemptMode: "planner",
          senderIdentity: {
            ed25519PublicKey: filled(0x70),
            x25519PublicKey: filled(0x71),
            x25519CrossSignature: filled(0x72, 64),
          },
          senderPresenceCommitment: filled(0x73),
          senderAdmissionGrant: null,
          responseHybridKemPublicKey: filled(0x74, 1_216),
          identityTranscriptSignature: filled(0x75, 64),
        },
      };
    case "IDENTITY_ACCEPT":
      return {
        kind,
        value: {
          version: 1,
          responderIdentity: {
            ed25519PublicKey: filled(0x76),
            x25519PublicKey: filled(0x77),
            x25519CrossSignature: filled(0x78, 64),
          },
          responderPresenceCommitment: filled(0x79),
          responderAdmissionGrant: null,
          identityTranscriptSignature: filled(0x7a, 64),
        },
      };
    case "TRANSPORT_OFFER":
      return {
        kind,
        value: {
          version: 1,
          initiatorStableEdgeClaim: vectorClaim(0x80),
          candidates: [{ version: 1, kind: "operation-carrier" }],
        },
      };
    case "TRANSPORT_ANSWER":
      return {
        kind,
        value: {
          version: 1,
          responderStableEdgeClaim: vectorClaim(0x86),
          selectedOfferCandidateId: filled(0x8b),
          answer: {
            version: 1,
            kind: "webrtc-complete",
            exactSdpUtf8: new TextEncoder().encode("v=0\r\ns=p2party\r\n"),
          },
        },
      };
    case "V4_HANDSHAKE": {
      const frame = filled(0x8c, 2_465);
      frame[0] = 0x01;
      return { kind, value: frame };
    }
    case "PQ_CONTROL":
      return { kind, value: filled(0x8d, 65_490) };
    case "QUIESCE_PROPOSE":
      return {
        kind,
        value: { version: 1, pqEpoch: 0x2122232425262728n },
      };
    case "QUIESCE_ACK":
      return {
        kind,
        value: { version: 1, pqEpoch: 0x3132333435363738n },
      };
    case "HEAL_COMPLETE":
      return {
        kind,
        value: { version: 1, newPqEpoch: 0x4142434445464748n },
      };
    case "PAIR_CHECKPOINT":
      return {
        kind,
        value: { version: 1, pqEpoch: 0x5152535455565758n },
      };
  }
};

const vectorSlot = (
  kind: PairStepKindV1,
): readonly [
  direction: 0 | 1,
  pairSequence: bigint,
  previousPairOperationId: Uint8Array | null,
  pairDependencies: readonly Uint8Array[],
] => {
  switch (kind) {
    case "IDENTITY_HELLO":
      return [0, 0n, null, []];
    case "IDENTITY_ACCEPT":
      return [1, 0n, null, [filled(0x61)]];
    case "TRANSPORT_OFFER":
      return [0, 1n, filled(0x42), [filled(0x62)]];
    case "TRANSPORT_ANSWER":
      return [1, 1n, filled(0x43), [filled(0x63)]];
    case "V4_HANDSHAKE":
      return [0, 2n, filled(0x44), [filled(0x64)]];
    case "PQ_CONTROL":
      return [1, 2n, filled(0x45), [filled(0x65)]];
    case "QUIESCE_PROPOSE":
      return [0, 3n, filled(0x46), []];
    case "QUIESCE_ACK":
      return [1, 3n, filled(0x47), [filled(0x67)]];
    case "HEAL_COMPLETE":
      return [0, 4n, filled(0x48), [filled(0x68)]];
    case "PAIR_CHECKPOINT":
      return [1, 4n, filled(0x49), [filled(0x69)]];
  }
};

const vectorPlaintext = (
  kind: PairStepKindV1,
  kindIndex: number,
): PairPlaintextV1 => {
  const [direction, pairSequence, previousPairOperationId, pairDependencies] =
    vectorSlot(kind);
  return {
    version: 1,
    kind,
    pairEdgeId: filled(0x10 + kindIndex),
    endpointPresenceOperationIds: [filled(0x20), filled(0x30)],
    direction,
    pairSequence,
    previousPairOperationId,
    pairDependencies,
    body: vectorBody(kind),
    pairPadding: new Uint8Array(0),
  };
};

const vectorEnvelope = (vector: PairEnvelopeVector): PairStepEnvelopeV1 => ({
  version: 1,
  pairRoutingTag: filled(vector.bootstrap ? 0xa0 : 0xb0),
  bootstrapHeader: vector.bootstrap
    ? {
        version: 1,
        suiteId: 1,
        hybridKemCiphertext: filled(0xa1, 1_120),
      }
    : null,
  nonce: vector.bootstrap ? null : filled(0xb1, 24),
  pairCiphertextAndTag: filled(
    vector.bootstrap ? 0xa2 : 0xb2,
    vector.ciphertextLength,
  ),
});

describe("PairPlaintextV1 independent known-answer vectors", () => {
  test("pins all three schema-derived plaintext targets", () => {
    expect(pairPlaintextTargetBytesV1(0, true)).toBe(2_919);
    expect(pairPlaintextTargetBytesV1(0, false)).toBe(4_017);
    expect(pairPlaintextTargetBytesV1(1, false)).toBe(69_553);
  });

  test("pins every complete body before and after unique target padding", async () => {
    for (const [kindIndex, vector] of PAIR_BODY_VECTORS.entries()) {
      const plaintext = vectorPlaintext(vector.kind, kindIndex);
      const unpadded = encodeCanonical(pairPlaintextV1Schema, plaintext);
      expect(unpadded.length, `${vector.kind} unpadded length`).toBe(
        vector.unpaddedLength,
      );
      expect(
        hex(await sha256(unpadded)),
        `${vector.kind} unpadded digest`,
      ).toBe(vector.unpaddedSha256);
      expect(hex(unpadded.subarray(0, 96)), `${vector.kind} prefix`).toBe(
        vector.unpaddedPrefixHex,
      );
      const suffixBytes = vector.unpaddedSuffixHex.length / 2;
      expect(
        hex(unpadded.subarray(-suffixBytes)),
        `${vector.kind} suffix`,
      ).toBe(vector.unpaddedSuffixHex);

      const padded = await padPairPlaintextV1(
        plaintext,
        vector.bootstrap,
        "hybrid-mlkem768",
      );
      expect(padded.operationPayloadClass, `${vector.kind} class`).toBe(
        vector.operationClass,
      );
      expect(
        padded.plaintext.pairPadding.length,
        `${vector.kind} padding`,
      ).toBe(vector.paddingLength);
      const complete = await encodePairPlaintextV1(
        padded.plaintext,
        vector.operationClass,
        vector.bootstrap,
        "hybrid-mlkem768",
      );
      expect(complete.length, `${vector.kind} target`).toBe(
        pairPlaintextTargetBytesV1(vector.operationClass, vector.bootstrap),
      );
      expect(hex(await sha256(complete)), `${vector.kind} padded digest`).toBe(
        vector.paddedSha256,
      );
    }
  });

  test("rejects a small established body forced into class 1", async () => {
    const vector = PAIR_BODY_VECTORS[9];
    const plaintext = vectorPlaintext(vector.kind, 9);
    const padded = await padPairPlaintextV1(
      plaintext,
      false,
      "hybrid-mlkem768",
    );

    await expect(
      encodePairPlaintextV1(padded.plaintext, 1, false, "hybrid-mlkem768"),
    ).rejects.toThrow("smallest permitted payload class");
  });

  test("rejects a padding suffix one byte longer than the unique target", async () => {
    const vector = PAIR_BODY_VECTORS[9];
    const plaintext = vectorPlaintext(vector.kind, 9);
    const padded = await padPairPlaintextV1(
      plaintext,
      false,
      "hybrid-mlkem768",
    );
    await expect(
      encodePairPlaintextV1(
        {
          ...padded.plaintext,
          pairPadding: new Uint8Array(vector.paddingLength + 1),
        },
        0,
        false,
        "hybrid-mlkem768",
      ),
    ).rejects.toThrow("pairPadding must be exactly");
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
    expect(projectionBytes.length).toBe(IDENTITY_ACCEPT_PROJECTION_LENGTH);
    expect(hex(projectionBytes.subarray(0, 96))).toBe(
      IDENTITY_ACCEPT_PROJECTION_PREFIX_HEX,
    );
    expect(hex(projectionBytes.subarray(-96))).toBe(
      IDENTITY_ACCEPT_PROJECTION_SUFFIX_HEX,
    );
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

describe("PairStepEnvelopeV1 independent known-answer vectors", () => {
  test("pins every legal suite-1 header/class form", async () => {
    for (const vector of PAIR_ENVELOPE_VECTORS) {
      const encoded = encodePairStepEnvelopeV1(
        vectorEnvelope(vector),
        vector.operationClass,
      );
      const label = `class ${String(vector.operationClass)} ${
        vector.bootstrap ? "bootstrap" : "established"
      }`;
      expect(encoded.length, `${label} length`).toBe(vector.encodedLength);
      expect(hex(await sha256(encoded)), `${label} digest`).toBe(vector.sha256);
      expect(hex(encoded.subarray(0, 96)), `${label} prefix`).toBe(
        vector.prefixHex,
      );
      const suffixBytes = vector.suffixHex.length / 2;
      expect(hex(encoded.subarray(-suffixBytes)), `${label} suffix`).toBe(
        vector.suffixHex,
      );
    }
  });
});
