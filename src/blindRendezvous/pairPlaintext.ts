/**
 * Canonical pair-private plaintext codec (Sections 4.11–4.13).
 *
 * This module begins only after pair AEAD has authenticated a candidate. It
 * owns the closed body union, initial direction/sequence/predecessor shapes,
 * candidate-ID ordering, and the unique class-sized all-zero padding suffix.
 * Pair secrets, HPKE, AEAD, admission, exact predecessor IDs, and durable fork
 * state deliberately remain outside this codec.
 *
 * Status: PROPOSED, NOT FROZEN. Release use still requires the Phase-0
 * canonical vectors and registry freeze named by the specification.
 */

import { decodeCanonicalStrict, encodeCanonical } from "./canonicalSchema";
import { transportOfferCandidateId } from "./derivations";
import { pairPlaintextTargetBytesV1 } from "./pairStepEnvelope";
import {
  MAX_PAIR_TRANSPORT_CANDIDATES_V1,
  pairBootstrapInfoV1Schema,
  pairFlightSlotV1Schema,
  pairIdentityUnsignedProjectionV1Schema,
  pairPlaintextV1Schema,
} from "./schemas";
import {
  HANDSHAKE_STEP,
  isHandshakePayloadForStep,
} from "../handlers/handshakeFrame";

import type { AdmissionGrantV1 } from "./operationPayload";
import type { OperationPayloadClassV1 } from "./operation";
import type { RoomPqMode } from "../roomPolicy";
import type { HandshakeStep } from "../handlers/handshakeFrame";

export type PairStepKindV1 =
  | "IDENTITY_HELLO"
  | "IDENTITY_ACCEPT"
  | "TRANSPORT_OFFER"
  | "TRANSPORT_ANSWER"
  | "V4_HANDSHAKE"
  | "PQ_CONTROL"
  | "QUIESCE_PROPOSE"
  | "QUIESCE_ACK"
  | "HEAL_COMPLETE"
  | "PAIR_CHECKPOINT";

export type PairAttemptModeV1 = "planner" | "explicit";

export interface StableIdentityBundleV1 {
  readonly ed25519PublicKey: Uint8Array;
  readonly x25519PublicKey: Uint8Array;
  readonly x25519CrossSignature: Uint8Array;
}

export interface PairIdentityHelloUnsignedV1 {
  readonly version: 1;
  readonly attemptMode: PairAttemptModeV1;
  readonly senderIdentity: StableIdentityBundleV1;
  readonly senderPresenceCommitment: Uint8Array;
  readonly senderAdmissionGrant: AdmissionGrantV1 | null;
  readonly responseHybridKemPublicKey: Uint8Array;
}

export interface PairIdentityHelloV1 extends PairIdentityHelloUnsignedV1 {
  readonly identityTranscriptSignature: Uint8Array;
}

export interface PairIdentityAcceptUnsignedV1 {
  readonly version: 1;
  readonly responderIdentity: StableIdentityBundleV1;
  readonly responderPresenceCommitment: Uint8Array;
  readonly responderAdmissionGrant: AdmissionGrantV1 | null;
}

export interface PairIdentityAcceptV1 extends PairIdentityAcceptUnsignedV1 {
  readonly identityTranscriptSignature: Uint8Array;
}

export interface StableEdgeAttemptClaimUnsignedV1 {
  readonly version: 1;
  readonly stableEdgeId: Uint8Array;
  readonly pairEdgeId: Uint8Array;
  readonly confirmedPairTranscriptId: Uint8Array;
  readonly claimantStableEd25519PublicKey: Uint8Array;
  readonly claimNotBeforeLogicalWindow: bigint;
  readonly claimNotAfterLogicalWindow: bigint;
}

export interface StableEdgeAttemptClaimV1 extends StableEdgeAttemptClaimUnsignedV1 {
  readonly claimantSignature: Uint8Array;
}

export type PairTransportCandidateV1 =
  | {
      readonly version: 1;
      readonly kind: "webrtc-complete";
      readonly exactSdpUtf8: Uint8Array;
    }
  | {
      readonly version: 1;
      readonly kind: "operation-carrier";
    }
  | {
      readonly version: 1;
      readonly kind: "registered-local-link";
      readonly adapterProtocolId: number;
      readonly fixedCanonicalCandidate: Uint8Array;
    };

export interface PairTransportOfferV1 {
  readonly version: 1;
  readonly initiatorStableEdgeClaim: StableEdgeAttemptClaimV1;
  readonly candidates: readonly PairTransportCandidateV1[];
}

export interface PairTransportAnswerV1 {
  readonly version: 1;
  readonly responderStableEdgeClaim: StableEdgeAttemptClaimV1;
  readonly selectedOfferCandidateId: Uint8Array;
  readonly answer: PairTransportCandidateV1;
}

export interface QuiesceProposeV1 {
  readonly version: 1;
  readonly pqEpoch: bigint;
}

export interface QuiesceAckV1 {
  readonly version: 1;
  readonly pqEpoch: bigint;
}

export interface HealCompleteV1 {
  readonly version: 1;
  readonly newPqEpoch: bigint;
}

export interface PairCheckpointV1 {
  readonly version: 1;
  readonly pqEpoch: bigint;
}

export type PairStepBodyV1 =
  | { readonly kind: "IDENTITY_HELLO"; readonly value: PairIdentityHelloV1 }
  | { readonly kind: "IDENTITY_ACCEPT"; readonly value: PairIdentityAcceptV1 }
  | { readonly kind: "TRANSPORT_OFFER"; readonly value: PairTransportOfferV1 }
  | { readonly kind: "TRANSPORT_ANSWER"; readonly value: PairTransportAnswerV1 }
  | { readonly kind: "V4_HANDSHAKE"; readonly value: Uint8Array }
  | { readonly kind: "PQ_CONTROL"; readonly value: Uint8Array }
  | { readonly kind: "QUIESCE_PROPOSE"; readonly value: QuiesceProposeV1 }
  | { readonly kind: "QUIESCE_ACK"; readonly value: QuiesceAckV1 }
  | { readonly kind: "HEAL_COMPLETE"; readonly value: HealCompleteV1 }
  | { readonly kind: "PAIR_CHECKPOINT"; readonly value: PairCheckpointV1 };

export interface PairPlaintextV1 {
  readonly version: 1;
  readonly kind: PairStepKindV1;
  readonly pairEdgeId: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
  readonly direction: 0 | 1;
  readonly pairSequence: bigint;
  readonly previousPairOperationId: Uint8Array | null;
  readonly pairDependencies: readonly Uint8Array[];
  readonly body: PairStepBodyV1;
  readonly pairPadding: Uint8Array;
}

export type PairIdentityUnsignedBodyV1 =
  | {
      readonly kind: "IDENTITY_HELLO";
      readonly value: PairIdentityHelloUnsignedV1;
    }
  | {
      readonly kind: "IDENTITY_ACCEPT";
      readonly value: PairIdentityAcceptUnsignedV1;
    };

export interface PairIdentityUnsignedProjectionV1 {
  readonly version: 1;
  readonly kind: "IDENTITY_HELLO" | "IDENTITY_ACCEPT";
  readonly pairEdgeId: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
  readonly direction: 0 | 1;
  readonly pairSequence: bigint;
  readonly previousPairOperationId: Uint8Array | null;
  readonly pairDependencies: readonly Uint8Array[];
  readonly body: PairIdentityUnsignedBodyV1;
  readonly pairPadding: Uint8Array;
}

export interface PairOuterPrebindingV1 {
  readonly version: 1;
  readonly roomContextConfirmation: Uint8Array;
  readonly policyHash: Uint8Array;
  readonly logicalWindow: bigint;
  readonly expiresAfterWindow: bigint;
  readonly lifetime: "PAIR_CAUSAL";
  readonly authorEpochEd25519Key: Uint8Array;
  readonly authorSequence: bigint;
  readonly previousAuthorOperationId: Uint8Array | null;
  readonly kind: "PAIR_STEP";
  readonly dependencies: readonly [];
  readonly operationPayloadClass: OperationPayloadClassV1;
  readonly bootstrapHeaderHash: Uint8Array;
  readonly nonce: Uint8Array | null;
}

export interface PairOuterBindingV1 {
  readonly prebinding: PairOuterPrebindingV1;
  readonly pairRoutingTag: Uint8Array;
  readonly semanticSlot: Uint8Array;
}

export interface PairFlightSlotV1 {
  readonly kind: PairStepKindV1;
  readonly direction: 0 | 1;
  readonly pairSequence: bigint;
}

export type PairBootstrapRecipientBindingV1 =
  | {
      readonly kind: "presence";
      readonly presenceOperationId: Uint8Array;
    }
  | {
      readonly kind: "hello-response";
      readonly helloOperationId: Uint8Array;
    };

export interface PairBootstrapInfoV1 {
  readonly version: 1;
  readonly pairBootstrapSuite: 1;
  readonly roomContextConfirmation: Uint8Array;
  readonly policyHash: Uint8Array;
  readonly stepKind: "IDENTITY_HELLO" | "IDENTITY_ACCEPT";
  readonly logicalWindow: bigint;
  readonly expiresAfterWindow: bigint;
  readonly authorEpochEd25519Key: Uint8Array;
  readonly authorSequence: bigint;
  readonly previousAuthorOperationId: Uint8Array | null;
  readonly operationPayloadClass: OperationPayloadClassV1;
  readonly recipientBinding: PairBootstrapRecipientBindingV1;
}

export class PairPlaintextError extends Error {
  override readonly name = "PairPlaintextError";

  constructor(message: string) {
    super(`pairPlaintext: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairPlaintextError(message);
};

export const validatePairFlightSlotV1 = (value: PairFlightSlotV1): void => {
  const encoded = encodeCanonical(pairFlightSlotV1Schema, value);
  const snapshot = decodeCanonicalStrict(
    pairFlightSlotV1Schema,
    encoded,
  ) as PairFlightSlotV1;
  if (snapshot.direction !== 0 && snapshot.direction !== 1)
    fail("pair flight slot direction must be 0 or 1");
};

export const validatePairBootstrapInfoV1 = (
  value: PairBootstrapInfoV1,
): void => {
  const encoded = encodeCanonical(pairBootstrapInfoV1Schema, value);
  const snapshot = decodeCanonicalStrict(
    pairBootstrapInfoV1Schema,
    encoded,
  ) as PairBootstrapInfoV1;
  if (snapshot.version !== 1) fail("unsupported PairBootstrapInfoV1 version");
  if (snapshot.pairBootstrapSuite !== 1)
    fail("unsupported pair bootstrap suite");
  if (
    snapshot.stepKind !== "IDENTITY_HELLO" &&
    snapshot.stepKind !== "IDENTITY_ACCEPT"
  )
    fail("pair bootstrap info step must be IDENTITY_HELLO or IDENTITY_ACCEPT");
  if (snapshot.operationPayloadClass !== 0)
    fail("pair bootstrap info must use payload class 0");
  if (snapshot.logicalWindow > snapshot.expiresAfterWindow)
    fail("pair bootstrap info expires before its logical window");
  if (
    (snapshot.authorSequence === 0n) !==
    (snapshot.previousAuthorOperationId === null)
  )
    fail("pair bootstrap info has an invalid author predecessor");
  if (
    (snapshot.stepKind === "IDENTITY_HELLO" &&
      snapshot.recipientBinding.kind !== "presence") ||
    (snapshot.stepKind === "IDENTITY_ACCEPT" &&
      snapshot.recipientBinding.kind !== "hello-response")
  )
    fail("pair bootstrap step and recipient binding disagree");
};

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
};

const snapshotPairPlaintext = (plaintext: PairPlaintextV1): PairPlaintextV1 => {
  const encoded = encodeCanonical(pairPlaintextV1Schema, plaintext);
  return decodeCanonicalStrict(
    pairPlaintextV1Schema,
    encoded,
  ) as PairPlaintextV1;
};

const validateClaim = (claim: StableEdgeAttemptClaimV1): void => {
  if (claim.version !== 1) fail("unsupported stable-edge claim version");
  if (claim.claimNotBeforeLogicalWindow > claim.claimNotAfterLogicalWindow)
    fail("stable-edge claim interval is reversed");
};

const validateCandidate = (candidate: PairTransportCandidateV1): void => {
  if (candidate.version !== 1) fail("unsupported transport candidate version");
  if (candidate.kind === "webrtc-complete") {
    if (candidate.exactSdpUtf8.length === 0)
      fail("WebRTC SDP must not be empty");
    try {
      utf8Decoder.decode(candidate.exactSdpUtf8);
    } catch {
      fail("WebRTC SDP must be well-formed UTF-8");
    }
  } else if (
    candidate.kind === "registered-local-link" &&
    candidate.fixedCanonicalCandidate.length === 0
  ) {
    fail("registered local candidate must not be empty");
  }
};

const validateTransportOffer = async (
  offer: PairTransportOfferV1,
): Promise<void> => {
  if (offer.version !== 1) fail("unsupported transport offer version");
  validateClaim(offer.initiatorStableEdgeClaim);
  if (
    offer.candidates.length < 1 ||
    offer.candidates.length > MAX_PAIR_TRANSPORT_CANDIDATES_V1
  )
    fail("transport offer must contain one through three candidates");

  let operationCarriers = 0;
  let webrtcCandidates = 0;
  let localCandidates = 0;
  for (const candidate of offer.candidates) {
    validateCandidate(candidate);
    if (candidate.kind === "operation-carrier") operationCarriers++;
    else if (candidate.kind === "webrtc-complete") webrtcCandidates++;
    else localCandidates++;
  }
  if (operationCarriers !== 1)
    fail("transport offer must contain exactly one operation carrier");
  if (webrtcCandidates > 1 || localCandidates > 1)
    fail("transport offer repeats a candidate kind");

  const candidateIds = await Promise.all(
    offer.candidates.map((candidate) => transportOfferCandidateId(candidate)),
  );
  for (let index = 1; index < candidateIds.length; index++) {
    const order = compareBytes(candidateIds[index - 1], candidateIds[index]);
    if (order >= 0)
      fail(
        order === 0
          ? "transport candidate IDs must be duplicate-free"
          : "transport candidates must be sorted by candidate ID",
      );
  }
};

const validateTransportAnswer = (answer: PairTransportAnswerV1): void => {
  if (answer.version !== 1) fail("unsupported transport answer version");
  validateClaim(answer.responderStableEdgeClaim);
  validateCandidate(answer.answer);
};

const handshakeSteps = Object.values(
  HANDSHAKE_STEP,
) as readonly HandshakeStep[];

const validateV4HandshakePayload = (
  payload: Uint8Array,
  roomPqMode: RoomPqMode,
): void => {
  const valid = handshakeSteps.some((step) =>
    isHandshakePayloadForStep(payload, step, roomPqMode),
  );
  if (!valid)
    fail("V4_HANDSHAKE is not an exact step for the room-selected PQ suite");
};

const validateBody = async (
  body: PairStepBodyV1,
  roomPqMode: RoomPqMode,
): Promise<void> => {
  switch (body.kind) {
    case "IDENTITY_HELLO":
      if (body.value.version !== 1) fail("unsupported identity HELLO version");
      if (
        body.value.senderAdmissionGrant !== null &&
        body.value.senderAdmissionGrant.version !== 1
      )
        fail("unsupported HELLO admission-grant version");
      return;
    case "IDENTITY_ACCEPT":
      if (body.value.version !== 1) fail("unsupported identity ACCEPT version");
      if (
        body.value.responderAdmissionGrant !== null &&
        body.value.responderAdmissionGrant.version !== 1
      )
        fail("unsupported ACCEPT admission-grant version");
      return;
    case "TRANSPORT_OFFER":
      await validateTransportOffer(body.value);
      return;
    case "TRANSPORT_ANSWER":
      validateTransportAnswer(body.value);
      return;
    case "V4_HANDSHAKE":
      validateV4HandshakePayload(body.value, roomPqMode);
      return;
    case "PQ_CONTROL":
      // This intrinsic codec gate owns only the complete fixed byte width.
      // Slot-selected suite/record/epoch checks remain in the PQ state machine.
      return;
    case "QUIESCE_PROPOSE":
    case "QUIESCE_ACK":
    case "PAIR_CHECKPOINT":
      if (body.value.version !== 1) fail(`unsupported ${body.kind} version`);
      return;
    case "HEAL_COMPLETE":
      if (body.value.version !== 1) fail("unsupported HEAL_COMPLETE version");
      return;
  }
};

const requireDependencyCount = (
  plaintext: PairPlaintextV1,
  count: 0 | 1,
): void => {
  if (plaintext.pairDependencies.length !== count)
    fail(`${plaintext.kind} must carry ${String(count)} pair dependencies`);
};

const validateInitialSlotStructure = (plaintext: PairPlaintextV1): void => {
  if (plaintext.pairSequence === 0n) {
    if (plaintext.previousPairOperationId !== null)
      fail("pair sequence zero must have a null predecessor");
  } else if (plaintext.previousPairOperationId === null) {
    fail("a non-zero pair sequence must name its predecessor");
  }

  switch (plaintext.kind) {
    case "IDENTITY_HELLO":
      if (plaintext.direction !== 0 || plaintext.pairSequence !== 0n)
        fail("IDENTITY_HELLO must use pair slot direction 0, sequence 0");
      requireDependencyCount(plaintext, 0);
      return;
    case "IDENTITY_ACCEPT":
      if (plaintext.direction !== 1 || plaintext.pairSequence !== 0n)
        fail("IDENTITY_ACCEPT must use pair slot direction 1, sequence 0");
      requireDependencyCount(plaintext, 1);
      return;
    case "TRANSPORT_OFFER":
      if (plaintext.direction !== 0 || plaintext.pairSequence !== 1n)
        fail("TRANSPORT_OFFER must use pair slot direction 0, sequence 1");
      requireDependencyCount(plaintext, 1);
      return;
    case "TRANSPORT_ANSWER":
      if (plaintext.direction !== 1 || plaintext.pairSequence !== 1n)
        fail("TRANSPORT_ANSWER must use pair slot direction 1, sequence 1");
      requireDependencyCount(plaintext, 1);
      return;
    case "QUIESCE_PROPOSE":
      if (plaintext.pairSequence < 2n)
        fail("post-transport pair steps must use sequence two or later");
      requireDependencyCount(plaintext, 0);
      return;
    case "V4_HANDSHAKE":
    case "PQ_CONTROL":
    case "QUIESCE_ACK":
    case "HEAL_COMPLETE":
    case "PAIR_CHECKPOINT":
      if (plaintext.pairSequence < 2n)
        fail("post-transport pair steps must use sequence two or later");
      requireDependencyCount(plaintext, 1);
      return;
  }
};

const validateCore = async (
  plaintext: PairPlaintextV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<void> => {
  validateClassifiableShape(plaintext, bootstrapHeaderPresent);
  await validateBody(plaintext.body, roomPqMode);
};

/**
 * Synchronous invariants needed by payload-class selection.
 *
 * Candidate-ID ordering and the remaining body-specific gates are async, but
 * they cannot change the encoded size. Keeping these framing checks here means
 * the exported classifier cannot assign a class to a kind/body/header shape
 * that the pair codec would later reject.
 */
const validateClassifiableShape = (
  plaintext: PairPlaintextV1,
  bootstrapHeaderPresent: boolean,
): void => {
  if (plaintext.version !== 1) fail("unsupported pair plaintext version");
  if (plaintext.direction !== 0 && plaintext.direction !== 1)
    fail("pair direction must be 0 or 1");
  if (plaintext.endpointPresenceOperationIds.length !== 2)
    fail("endpoint presence tuple must contain exactly two operation IDs");
  if (
    compareBytes(
      plaintext.endpointPresenceOperationIds[0],
      plaintext.endpointPresenceOperationIds[1],
    ) >= 0
  )
    fail("endpoint presence tuple must be strictly role-ordered");
  if (plaintext.kind !== plaintext.body.kind)
    fail("pair plaintext kind and body discriminator disagree");

  const isIdentity =
    plaintext.kind === "IDENTITY_HELLO" || plaintext.kind === "IDENTITY_ACCEPT";
  if (bootstrapHeaderPresent !== isIdentity)
    fail(
      isIdentity
        ? "identity flights require a bootstrap header"
        : "only identity flights may carry a bootstrap header",
    );
  validateInitialSlotStructure(plaintext);
};

const requirePayloadClass = (
  operationPayloadClass: OperationPayloadClassV1,
): OperationPayloadClassV1 => {
  if (operationPayloadClass !== 0 && operationPayloadClass !== 1)
    fail("operation payload class must be 0 or 1");
  return operationPayloadClass;
};

/**
 * Select the numerically smallest class for an empty-padding plaintext.
 *
 * This calculation is intentionally available before encryption. A receiver
 * invokes the same rule only after AEAD opening exposes the plaintext.
 */
export const pairOperationPayloadClassForV1 = (
  plaintextWithEmptyPadding: PairPlaintextV1,
  bootstrapHeaderPresent: boolean,
): OperationPayloadClassV1 => {
  const plaintext = snapshotPairPlaintext(plaintextWithEmptyPadding);
  if (plaintext.pairPadding.length !== 0)
    fail("minimal-class input must have empty pairPadding");
  validateClassifiableShape(plaintext, bootstrapHeaderPresent);
  const encodedLength = encodeCanonical(
    pairPlaintextV1Schema,
    plaintext,
  ).length;
  const permitted: readonly OperationPayloadClassV1[] = bootstrapHeaderPresent
    ? [0]
    : [0, 1];
  for (const candidate of permitted) {
    if (
      encodedLength <=
      pairPlaintextTargetBytesV1(candidate, bootstrapHeaderPresent)
    )
      return candidate;
  }
  return fail("pair plaintext fits no permitted operation payload class");
};

const validateOwnedPairPlaintext = async (
  plaintext: PairPlaintextV1,
  operationPayloadClass: OperationPayloadClassV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<void> => {
  const payloadClass = requirePayloadClass(operationPayloadClass);
  // Validate the signed outer class/header combination before reporting any
  // inner minimal-class mismatch.
  pairPlaintextTargetBytesV1(payloadClass, bootstrapHeaderPresent);
  await validateCore(plaintext, bootstrapHeaderPresent, roomPqMode);

  for (const byte of plaintext.pairPadding) {
    if (byte !== 0) fail("pairPadding must be the all-zero suffix");
  }

  const unpadded: PairPlaintextV1 = {
    ...plaintext,
    pairPadding: new Uint8Array(0),
  };
  const minimalClass = pairOperationPayloadClassForV1(
    unpadded,
    bootstrapHeaderPresent,
  );
  if (minimalClass !== payloadClass)
    fail("pair plaintext does not use its smallest permitted payload class");

  const target = pairPlaintextTargetBytesV1(
    payloadClass,
    bootstrapHeaderPresent,
  );
  const unpaddedLength = encodeCanonical(
    pairPlaintextV1Schema,
    unpadded,
  ).length;
  const expectedPaddingLength = target - unpaddedLength;
  if (plaintext.pairPadding.length !== expectedPaddingLength)
    fail(
      `pairPadding must be exactly ${String(expectedPaddingLength)} bytes for this plaintext and class`,
    );
  if (encodeCanonical(pairPlaintextV1Schema, plaintext).length !== target)
    fail("canonical pair plaintext does not consume its complete target");
};

/** Validate an already decoded pair plaintext without mutating caller bytes. */
export const validatePairPlaintextV1 = async (
  plaintext: PairPlaintextV1,
  operationPayloadClass: OperationPayloadClassV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<void> => {
  const privatePlaintext = snapshotPairPlaintext(plaintext);
  await validateOwnedPairPlaintext(
    privatePlaintext,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );
};

/**
 * Fill the unique authenticated zero suffix and return the selected outer
 * class together with an independently owned plaintext.
 */
export const padPairPlaintextV1 = async (
  plaintextWithEmptyPadding: PairPlaintextV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<{
  readonly operationPayloadClass: OperationPayloadClassV1;
  readonly plaintext: PairPlaintextV1;
}> => {
  const unpadded = snapshotPairPlaintext(plaintextWithEmptyPadding);
  if (unpadded.pairPadding.length !== 0)
    fail("padding constructor requires empty pairPadding");
  await validateCore(unpadded, bootstrapHeaderPresent, roomPqMode);
  const operationPayloadClass = pairOperationPayloadClassForV1(
    unpadded,
    bootstrapHeaderPresent,
  );
  const target = pairPlaintextTargetBytesV1(
    operationPayloadClass,
    bootstrapHeaderPresent,
  );
  const unpaddedLength = encodeCanonical(
    pairPlaintextV1Schema,
    unpadded,
  ).length;
  const padded = snapshotPairPlaintext({
    ...unpadded,
    pairPadding: new Uint8Array(target - unpaddedLength),
  });
  await validateOwnedPairPlaintext(
    padded,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );
  return { operationPayloadClass, plaintext: padded };
};

/** Encode only the one canonical, minimally classified, target-sized value. */
export const encodePairPlaintextV1 = async (
  plaintext: PairPlaintextV1,
  operationPayloadClass: OperationPayloadClassV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<Uint8Array> => {
  const encoded = encodeCanonical(pairPlaintextV1Schema, plaintext);
  const privatePlaintext = decodeCanonicalStrict(
    pairPlaintextV1Schema,
    encoded,
  ) as PairPlaintextV1;
  await validateOwnedPairPlaintext(
    privatePlaintext,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );
  return encoded;
};

/** Strictly decode and validate the signed outer class/header state. */
export const decodePairPlaintextV1 = async (
  encoded: Uint8Array,
  operationPayloadClass: OperationPayloadClassV1,
  bootstrapHeaderPresent: boolean,
  roomPqMode: RoomPqMode,
): Promise<PairPlaintextV1> => {
  const plaintext = decodeCanonicalStrict(
    pairPlaintextV1Schema,
    encoded,
  ) as PairPlaintextV1;
  await validateOwnedPairPlaintext(
    plaintext,
    operationPayloadClass,
    bootstrapHeaderPresent,
    roomPqMode,
  );
  return plaintext;
};

/**
 * Remove exactly the nested stable-identity transcript signature.
 *
 * The result uses a record descriptor rather than a new top-level union tag;
 * every outer field and the exact pair padding remain in the projection.
 */
export const pairIdentityUnsignedProjectionV1 = (
  plaintext: PairPlaintextV1,
): PairIdentityUnsignedProjectionV1 => {
  const privatePlaintext = snapshotPairPlaintext(plaintext);
  let body: PairIdentityUnsignedBodyV1;
  if (
    privatePlaintext.kind === "IDENTITY_HELLO" &&
    privatePlaintext.body.kind === "IDENTITY_HELLO"
  ) {
    const { identityTranscriptSignature: _signature, ...value } =
      privatePlaintext.body.value;
    body = { kind: "IDENTITY_HELLO", value };
  } else if (
    privatePlaintext.kind === "IDENTITY_ACCEPT" &&
    privatePlaintext.body.kind === "IDENTITY_ACCEPT"
  ) {
    const { identityTranscriptSignature: _signature, ...value } =
      privatePlaintext.body.value;
    body = { kind: "IDENTITY_ACCEPT", value };
  } else {
    return fail("unsigned identity projection requires HELLO or ACCEPT");
  }

  const projection = {
    version: privatePlaintext.version,
    kind: privatePlaintext.kind,
    pairEdgeId: privatePlaintext.pairEdgeId,
    endpointPresenceOperationIds: privatePlaintext.endpointPresenceOperationIds,
    direction: privatePlaintext.direction,
    pairSequence: privatePlaintext.pairSequence,
    previousPairOperationId: privatePlaintext.previousPairOperationId,
    pairDependencies: privatePlaintext.pairDependencies,
    body,
    pairPadding: privatePlaintext.pairPadding,
  };
  const encoded = encodeCanonical(
    pairIdentityUnsignedProjectionV1Schema,
    projection,
  );
  return decodeCanonicalStrict(
    pairIdentityUnsignedProjectionV1Schema,
    encoded,
  ) as PairIdentityUnsignedProjectionV1;
};
