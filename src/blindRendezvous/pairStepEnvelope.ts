/**
 * Canonical room-visible pair envelope framing (Section 4.11).
 *
 * This is deliberately only the endpoint-independent outer boundary. It
 * validates routing-tag framing, bootstrap-header/nonce state, and exact
 * class-sized ciphertext framing without opening pair AEAD or interpreting a
 * `PairPlaintextV1`. Tag expectation/one-use, admission, and the edge-local
 * pair state machine remain outside this module.
 *
 * Status: PROPOSED, NOT FROZEN. This implements the Phase-0 outer boundary,
 * but does not by itself publish a release-registry vector or interoperability
 * claim.
 *
 * The schema and operation class table are the size SSOTs. Framing overhead is
 * measured from a canonical empty-ciphertext encoding, then the exact
 * ciphertext and plaintext targets are derived from it. No second target table
 * is maintained here.
 */

import { decodeCanonicalStrict, encodeCanonical } from "./canonicalSchema";
import {
  OPERATION_PAYLOAD_CLASS_BYTES,
  PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1,
  pairStepEnvelopeV1Schema,
} from "./schemas";

import type { OperationPayloadClassV1 } from "./operation";

export const PAIR_STEP_ENVELOPE_VERSION_V1 = 1;
export const PAIR_BOOTSTRAP_HEADER_VERSION_V1 = 1;
export const PAIR_BOOTSTRAP_SUITE_ID_V1 = 1;
export const PAIR_AEAD_TAG_BYTES_V1 = 16;

export interface PairBootstrapHeaderV1 {
  version: 1;
  suiteId: 1;
  hybridKemCiphertext: Uint8Array;
}

export interface PairStepEnvelopeV1 {
  version: 1;
  pairRoutingTag: Uint8Array;
  bootstrapHeader: PairBootstrapHeaderV1 | null;
  nonce: Uint8Array | null;
  pairCiphertextAndTag: Uint8Array;
}

export class PairStepEnvelopeError extends Error {
  override readonly name = "PairStepEnvelopeError";

  constructor(message: string) {
    super(`pairStepEnvelope: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairStepEnvelopeError(message);
};

const emptyCiphertextEnvelope = (bootstrap: boolean): PairStepEnvelopeV1 => ({
  version: 1,
  pairRoutingTag: new Uint8Array(32),
  bootstrapHeader: bootstrap
    ? {
        version: 1,
        suiteId: 1,
        hybridKemCiphertext: new Uint8Array(
          PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1,
        ),
      }
    : null,
  nonce: bootstrap ? null : new Uint8Array(24),
  pairCiphertextAndTag: new Uint8Array(0),
});

const deriveEnvelopeOverhead = (bootstrap: boolean): number =>
  encodeCanonical(pairStepEnvelopeV1Schema, emptyCiphertextEnvelope(bootstrap))
    .length;

/**
 * These exported values are projections of the schema above, not literals.
 * Changing an optional tag, fixed field, or length prefix changes them
 * automatically and therefore changes every derived target/vector.
 */
export const PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1 =
  deriveEnvelopeOverhead(true);
export const PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1 =
  deriveEnvelopeOverhead(false);

const requirePayloadClass = (
  operationPayloadClass: OperationPayloadClassV1,
): OperationPayloadClassV1 => {
  if (operationPayloadClass !== 0 && operationPayloadClass !== 1)
    fail("operation payload class must be 0 or 1");
  return operationPayloadClass;
};

/**
 * Exact `pairCiphertextAndTag` bytes for one permitted outer envelope form.
 * Suite 1 deliberately has no class-1 bootstrap form.
 */
export const pairCiphertextAndTagTargetBytesV1 = (
  operationPayloadClass: OperationPayloadClassV1,
  bootstrap: boolean,
): number => {
  const payloadClass = requirePayloadClass(operationPayloadClass);
  if (bootstrap && payloadClass !== 0)
    fail("a bootstrap header is permitted only in payload class 0");
  const overhead = bootstrap
    ? PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1
    : PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1;
  const target = OPERATION_PAYLOAD_CLASS_BYTES[payloadClass] - overhead;
  if (target < PAIR_AEAD_TAG_BYTES_V1)
    fail("operation payload class cannot hold the pair AEAD tag");
  return target;
};

/** Exact authenticated pair-plaintext target after removing the AEAD tag. */
export const pairPlaintextTargetBytesV1 = (
  operationPayloadClass: OperationPayloadClassV1,
  bootstrap: boolean,
): number =>
  pairCiphertextAndTagTargetBytesV1(operationPayloadClass, bootstrap) -
  PAIR_AEAD_TAG_BYTES_V1;

const validatedCanonicalBytes = (
  envelope: PairStepEnvelopeV1,
  operationPayloadClass: OperationPayloadClassV1,
): Uint8Array => {
  const payloadClass = requirePayloadClass(operationPayloadClass);
  const encoded = encodeCanonical(pairStepEnvelopeV1Schema, envelope);

  if (envelope.version !== PAIR_STEP_ENVELOPE_VERSION_V1)
    fail("unsupported envelope version");

  const hasBootstrap = envelope.bootstrapHeader !== null;
  const hasNonce = envelope.nonce !== null;
  if (hasBootstrap === hasNonce)
    fail(
      "exactly one of bootstrapHeader and nonce must be present for suite 1",
    );

  if (envelope.bootstrapHeader !== null) {
    if (envelope.bootstrapHeader.version !== PAIR_BOOTSTRAP_HEADER_VERSION_V1)
      fail("unsupported bootstrap header version");
    if (envelope.bootstrapHeader.suiteId !== PAIR_BOOTSTRAP_SUITE_ID_V1)
      fail("unsupported bootstrap suite");
  }

  const expectedCiphertextBytes = pairCiphertextAndTagTargetBytesV1(
    payloadClass,
    hasBootstrap,
  );
  if (envelope.pairCiphertextAndTag.length !== expectedCiphertextBytes)
    fail(
      `pairCiphertextAndTag must be exactly ${String(expectedCiphertextBytes)} bytes for this class and header state`,
    );

  if (encoded.length !== OPERATION_PAYLOAD_CLASS_BYTES[payloadClass])
    fail("canonical envelope does not consume its complete operation class");
  return encoded;
};

/** Validate a decoded envelope against its signed outer payload class. */
export const validatePairStepEnvelopeV1 = (
  envelope: PairStepEnvelopeV1,
  operationPayloadClass: OperationPayloadClassV1,
): void => {
  validatedCanonicalBytes(envelope, operationPayloadClass);
};

/** Encode only after all class-dependent outer invariants hold. */
export const encodePairStepEnvelopeV1 = (
  envelope: PairStepEnvelopeV1,
  operationPayloadClass: OperationPayloadClassV1,
): Uint8Array => validatedCanonicalBytes(envelope, operationPayloadClass);

/** Decode uniquely, then enforce the signed class-dependent invariants. */
export const decodePairStepEnvelopeV1 = (
  encoded: Uint8Array,
  operationPayloadClass: OperationPayloadClassV1,
): PairStepEnvelopeV1 => {
  const envelope = decodeCanonicalStrict(
    pairStepEnvelopeV1Schema,
    encoded,
  ) as PairStepEnvelopeV1;
  validatePairStepEnvelopeV1(envelope, operationPayloadClass);
  return envelope;
};
