/**
 * The canonical authenticated room operation (Section 4.4).
 *
 * Outer validity is deliberately endpoint-independent: every room member can
 * validate the canonical framing, author chain, lifetime, payload class, slot,
 * and signature of any operation — including a `PAIR_STEP` addressed to two
 * other members — so the same delivered bytes enter every member's core set.
 * Pair AEAD and inner ledger rules are a separate edge-local step that can
 * fail one edge without removing the operation from `CoreRoomState`. That
 * split is what keeps another pair's private plaintext out of room convergence.
 */

import { sign, verify } from "../cryptography/ed25519";
import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  operationId,
  operationSignatureMessage,
  pairSemanticSlot,
  policyHash,
  roomContextConfirmation,
  roomContextId,
} from "./derivations";
import { decodeAndValidateNonPairOperationPayload } from "./operationPayload";
import { decodePairStepEnvelopeV1 } from "./pairStepEnvelope";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";
import {
  OPERATION_PAYLOAD_CLASS_BYTES,
  authenticatedRoomOperationUnsignedV1Schema,
  authenticatedRoomOperationV1Schema,
} from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { DecodedNonPairOperationPayloadV1 } from "./operationPayload";
import type { PairStepEnvelopeV1 } from "./pairStepEnvelope";
import type { RoomPolicyV4 } from "./roomPolicyV4";

export type OperationKindV1 =
  "PRESENCE" | "LEAVE" | "PAIR_STEP" | "STORE_HINT" | "ADMISSION_REVOKE";

export type OperationLifetimeV1 =
  "WINDOW_TRANSIENT" | "GRANT_HORIZON" | "PAIR_CAUSAL";

export type OperationPayloadClassV1 = 0 | 1;

export interface AuthenticatedRoomOperationV1 {
  version: 1;
  roomContextConfirmation: Uint8Array;
  logicalWindow: bigint;
  expiresAfterWindow: bigint;
  lifetime: OperationLifetimeV1;
  authorEpochEd25519Key: Uint8Array;
  authorSequence: bigint;
  previousAuthorOperationId: Uint8Array | null;
  kind: OperationKindV1;
  semanticSlot: Uint8Array;
  dependencies: readonly Uint8Array[];
  operationPayloadClass: OperationPayloadClassV1;
  fixedPayload: Uint8Array;
  operationPadding: Uint8Array;
  authorSignature: Uint8Array;
}

export type UnsignedRoomOperationV1 = Omit<
  AuthenticatedRoomOperationV1,
  "authorSignature"
>;

export class OperationValidationError extends Error {
  override readonly name = "OperationValidationError";

  constructor(message: string) {
    super(`roomOperation: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new OperationValidationError(message);
};

/**
 * Closed kind → lifetime, payload-class, and dependency table (Section 4.4).
 *
 * `PAIR_STEP` is the only kind permitting the large class, and the only kind
 * whose minimal class is recomputed after pair AEAD opening rather than from
 * the outer bytes.
 */
const OPERATION_KIND_RULES: Readonly<
  Record<
    OperationKindV1,
    {
      readonly lifetime: OperationLifetimeV1;
      readonly payloadClasses: readonly OperationPayloadClassV1[];
      readonly dependencies: "empty" | "exactly-one" | "any";
    }
  >
> = Object.freeze({
  PRESENCE: {
    lifetime: "WINDOW_TRANSIENT",
    payloadClasses: [0],
    dependencies: "empty",
  },
  LEAVE: {
    lifetime: "WINDOW_TRANSIENT",
    payloadClasses: [0],
    dependencies: "exactly-one",
  },
  STORE_HINT: {
    lifetime: "WINDOW_TRANSIENT",
    payloadClasses: [0],
    dependencies: "empty",
  },
  ADMISSION_REVOKE: {
    lifetime: "GRANT_HORIZON",
    payloadClasses: [0],
    dependencies: "empty",
  },
  PAIR_STEP: {
    lifetime: "PAIR_CAUSAL",
    payloadClasses: [0, 1],
    dependencies: "empty",
  },
});

const checkedAdd = (left: bigint, right: bigint): bigint => {
  const sum = left + right;
  if (left < 0n || right < 0n || sum > 0xffffffffffffffffn)
    fail("checked addition overflowed");
  return sum;
};

/**
 * Longest period for which exact signed bytes can still be needed as inert
 * author/dependency evidence.
 *
 * A LEAVE can be created at the end of a presence's transient lifetime and
 * itself remain transient for one full retention interval, hence the checked
 * two-interval dependency bound. Pair-causal and authority horizons may be
 * longer and share this one SSOT.
 */
export const requiredRoomRetentionWindows = (
  roomPolicy: RoomPolicyV4,
): bigint => {
  const limits = roomPolicy.protocolLimits;
  const dependencyEvidenceWindows =
    BigInt(limits.operationRetentionWindows) * 2n;
  const pairWindows = BigInt(limits.pairControlRetentionWindows);
  const authorityWindows =
    roomPolicy.admissionFloor.mode === "authority-grant"
      ? BigInt(limits.maxFutureLogicalWindows) +
        BigInt(roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows)
      : 0n;
  return [dependencyEvidenceWindows, pairWindows, authorityWindows].reduce(
    (maximum, value) => (value > maximum ? value : maximum),
    0n,
  );
};

/**
 * The numerically smallest permitted class whose frozen codec fits the payload
 * (`OperationPayloadClassFor`). The sender must use it and the receiver
 * recomputes it, so a larger-than-necessary class is noncanonical rather than
 * merely wasteful — otherwise class choice would leak a sender-selectable
 * signal into a fixed-size traffic model.
 */
export const operationPayloadClassFor = (
  kind: OperationKindV1,
  payloadBytes: number,
): OperationPayloadClassV1 => {
  const permitted = OPERATION_KIND_RULES[kind].payloadClasses;
  for (const candidate of permitted) {
    if (payloadBytes <= OPERATION_PAYLOAD_CLASS_BYTES[candidate])
      return candidate;
  }
  return fail(
    `payload of ${String(payloadBytes)} bytes fits no permitted class for ${kind}`,
  );
};

declare const operationValidationContextBrand: unique symbol;

/**
 * A process-local proof that one exact capability and one exact policy were
 * used to derive this room context.
 *
 * The brand is backed by a private WeakMap, not by a caller-constructible
 * property. This prevents a caller from pairing a real RoomContextId with a
 * different policy and thereby changing admission semantics.
 */
export interface OperationValidationContext {
  readonly [operationValidationContextBrand]: true;
  /** Canonical local `RoomContextId`; never supplied by a carrier. */
  readonly roomContextId: Uint8Array;
  /** `RoomContextConfirmation` derived from the local room context. */
  readonly roomContextConfirmation: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  /** The explicit reference window; never ambient wall-clock time. */
  readonly referenceWindow: bigint;
}

interface PrivateOperationValidationContext {
  readonly roomContextId: Uint8Array;
  readonly roomContextConfirmation: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly roomPolicyBytes: Uint8Array;
  readonly referenceWindow: bigint;
}

const operationValidationContexts = new WeakMap<
  object,
  PrivateOperationValidationContext
>();

const requireReferenceWindow = (referenceWindow: bigint): void => {
  if (
    typeof referenceWindow !== "bigint" ||
    referenceWindow < 0n ||
    referenceWindow > 0xffffffffffffffffn
  )
    fail("referenceWindow must be an unsigned 64-bit integer");
};

const exposeOperationValidationContext = (
  privateContext: PrivateOperationValidationContext,
): OperationValidationContext => {
  const exposed = Object.freeze({
    roomContextId: Uint8Array.from(privateContext.roomContextId),
    roomContextConfirmation: Uint8Array.from(
      privateContext.roomContextConfirmation,
    ),
    roomPolicy: decodeRoomPolicyV4(privateContext.roomPolicyBytes),
    referenceWindow: privateContext.referenceWindow,
  } as OperationValidationContext);
  operationValidationContexts.set(exposed, {
    roomContextId: Uint8Array.from(privateContext.roomContextId),
    roomContextConfirmation: Uint8Array.from(
      privateContext.roomContextConfirmation,
    ),
    roomPolicy: decodeRoomPolicyV4(privateContext.roomPolicyBytes),
    roomPolicyBytes: Uint8Array.from(privateContext.roomPolicyBytes),
    referenceWindow: privateContext.referenceWindow,
  });
  return exposed;
};

const privateOperationValidationContextFor = (
  context: OperationValidationContext,
): PrivateOperationValidationContext => {
  const stored =
    typeof context === "object" && context !== null
      ? operationValidationContexts.get(context)
      : undefined;
  if (stored === undefined)
    fail(
      "validation context must be created by createOperationValidationContext",
    );

  let exposedPolicyBytes: Uint8Array;
  try {
    exposedPolicyBytes = encodeRoomPolicyV4(context.roomPolicy);
  } catch {
    fail("validation context was mutated after initialization");
  }
  if (
    !bytesEqual(context.roomContextId, stored.roomContextId) ||
    !bytesEqual(
      context.roomContextConfirmation,
      stored.roomContextConfirmation,
    ) ||
    !bytesEqual(exposedPolicyBytes, stored.roomPolicyBytes) ||
    context.referenceWindow !== stored.referenceWindow
  )
    fail("validation context was mutated after initialization");

  return {
    roomContextId: Uint8Array.from(stored.roomContextId),
    roomContextConfirmation: Uint8Array.from(stored.roomContextConfirmation),
    roomPolicy: decodeRoomPolicyV4(stored.roomPolicyBytes),
    roomPolicyBytes: Uint8Array.from(stored.roomPolicyBytes),
    referenceWindow: stored.referenceWindow,
  };
};

/**
 * Initialize the sole trusted operation-validation context from room secret
 * material. Neither the capability nor PolicyHash is retained or exposed.
 */
export const createOperationValidationContext = async (
  capability: Uint8Array,
  roomPolicy: RoomPolicyV4,
  referenceWindow: bigint,
): Promise<OperationValidationContext> => {
  const privateCapability = Uint8Array.from(capability);
  if (privateCapability.length !== 32)
    fail("room capability must be exactly 32 bytes");
  requireReferenceWindow(referenceWindow);
  const roomPolicyBytes = encodeRoomPolicyV4(roomPolicy);
  const privatePolicy = decodeRoomPolicyV4(roomPolicyBytes);
  const policyDigest = await policyHash(privatePolicy);
  const contextId = await roomContextId(privateCapability, policyDigest);
  const confirmation = await roomContextConfirmation(contextId);
  return exposeOperationValidationContext({
    roomContextId: contextId,
    roomContextConfirmation: confirmation,
    roomPolicy: privatePolicy,
    roomPolicyBytes,
    referenceWindow,
  });
};

/**
 * Rebind an initialized room to an explicit reference window without needing
 * to expose or reload its capability.
 */
export const operationValidationContextAt = (
  context: OperationValidationContext,
  referenceWindow: bigint,
): OperationValidationContext => {
  requireReferenceWindow(referenceWindow);
  const stored = privateOperationValidationContextFor(context);
  return exposeOperationValidationContext({
    ...stored,
    referenceWindow,
  });
};

/** Return an independently owned, still-branded copy for an async boundary. */
export const snapshotOperationValidationContext = (
  context: OperationValidationContext,
): OperationValidationContext =>
  exposeOperationValidationContext(
    privateOperationValidationContextFor(context),
  );

const snapshotValidationInputs = (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
): {
  readonly operation: AuthenticatedRoomOperationV1;
  readonly context: OperationValidationContext;
} => {
  const operationBytes = encodeCanonical(
    authenticatedRoomOperationV1Schema,
    operation,
  );
  const privateContext = privateOperationValidationContextFor(context);
  return {
    operation: decodeCanonicalStrict(
      authenticatedRoomOperationV1Schema,
      operationBytes,
    ) as AuthenticatedRoomOperationV1,
    context: exposeOperationValidationContext(privateContext),
  };
};

const decodeValidatedPairEnvelope = (
  operation: AuthenticatedRoomOperationV1,
): PairStepEnvelopeV1 => {
  try {
    return decodePairStepEnvelopeV1(
      operation.fixedPayload,
      operation.operationPayloadClass,
    );
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "unknown pair-envelope error";
    return fail(`PAIR_STEP payload is invalid: ${reason}`);
  }
};

interface OperationStructuralValidationResult {
  /**
   * The one canonical outer pair decode, retained for the asynchronous
   * semantic-slot check. Null means this is not a PAIR_STEP operation.
   */
  readonly pairEnvelope: PairStepEnvelopeV1 | null;
}

type OperationReferenceMode = "active-or-future" | "candidate-evidence";

/**
 * Structural and bound validation that needs no signature check.
 *
 * Separated from signature verification so a caller can reject cheap garbage
 * before spending an Ed25519 verification on it, which is what keeps the
 * per-author work bound in SEC-021 meaningful.
 */
const validateOperationStructureInternal = (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  referenceMode: OperationReferenceMode,
): OperationStructuralValidationResult => {
  // Encoding is the shape gate: unknown or missing fields, accessor-backed
  // properties, wrong widths, unsorted dependencies, and unregistered enum
  // members all fail here.
  encodeCanonical(authenticatedRoomOperationV1Schema, operation);

  if (operation.version !== 1) fail("unsupported operation version");
  if (
    !bytesEqual(
      operation.roomContextConfirmation,
      context.roomContextConfirmation,
    )
  )
    fail("operation does not confirm this room context");

  const rules = OPERATION_KIND_RULES[operation.kind];
  if (operation.lifetime !== rules.lifetime)
    fail(`${operation.kind} must use lifetime ${rules.lifetime}`);
  if (!rules.payloadClasses.includes(operation.operationPayloadClass))
    fail(
      `${operation.kind} does not permit payload class ${String(operation.operationPayloadClass)}`,
    );

  const classBytes =
    OPERATION_PAYLOAD_CLASS_BYTES[operation.operationPayloadClass];
  if (
    operation.fixedPayload.length + operation.operationPadding.length !==
    classBytes
  )
    fail("payload plus padding must equal the exact class length");
  for (const byte of operation.operationPadding) {
    if (byte !== 0) fail("operationPadding must be the all-zero suffix");
  }
  let pairEnvelope: PairStepEnvelopeV1 | null = null;
  if (operation.kind === "PAIR_STEP") {
    if (operation.operationPadding.length !== 0)
      fail("PAIR_STEP operationPadding must be empty");
    // Endpoint-independent framing only. Pair AEAD and plaintext minimality
    // remain edge-local, but every room member can prove the signed envelope
    // consumes exactly this operation class.
    pairEnvelope = decodeValidatedPairEnvelope(operation);
  } else if (
    operationPayloadClassFor(operation.kind, operation.fixedPayload.length) !==
    operation.operationPayloadClass
  ) {
    fail("operation does not use its smallest permitted payload class");
  }

  if (rules.dependencies === "empty" && operation.dependencies.length !== 0)
    fail(`${operation.kind} must carry no outer dependencies`);
  if (
    rules.dependencies === "exactly-one" &&
    operation.dependencies.length !== 1
  )
    fail(`${operation.kind} must name exactly one outer dependency`);

  const limits = context.roomPolicy.protocolLimits;
  if (operation.dependencies.length > limits.maxDependenciesPerOperation)
    fail("operation exceeds maxDependenciesPerOperation");

  const skew = BigInt(limits.maxClockSkewWindows);
  const future = BigInt(limits.maxFutureLogicalWindows);
  if (
    operation.logicalWindow > context.referenceWindow &&
    operation.logicalWindow - context.referenceWindow > future
  )
    fail("operation is further in the future than maxFutureLogicalWindows");
  if (operation.logicalWindow > operation.expiresAfterWindow)
    fail("operation expires before its logical window");

  const expiredBeyondSkew =
    context.referenceWindow > operation.expiresAfterWindow &&
    context.referenceWindow - operation.expiresAfterWindow > skew;
  if (referenceMode === "active-or-future" && expiredBeyondSkew)
    fail("operation is expired at this reference window");
  if (referenceMode === "candidate-evidence") {
    // Compute this for every candidate, not only an already-expired one. An
    // overflow is candidate-local invalidity at ingress and can never abort a
    // later room reduction containing unrelated honest operations.
    const evidenceValidThrough = checkedAdd(
      checkedAdd(
        operation.logicalWindow,
        requiredRoomRetentionWindows(context.roomPolicy),
      ),
      skew,
    );
    if (context.referenceWindow > evidenceValidThrough)
      fail("operation is beyond its retained-evidence horizon");
  }

  const lifetimeSpan = operation.expiresAfterWindow - operation.logicalWindow;
  if (
    operation.lifetime === "WINDOW_TRANSIENT" &&
    lifetimeSpan > BigInt(limits.operationRetentionWindows)
  )
    fail("WINDOW_TRANSIENT lifetime exceeds operationRetentionWindows");
  if (
    operation.lifetime === "PAIR_CAUSAL" &&
    lifetimeSpan > BigInt(limits.pairControlRetentionWindows)
  )
    fail("PAIR_CAUSAL lifetime exceeds pairControlRetentionWindows");
  if (
    operation.lifetime === "GRANT_HORIZON" &&
    operation.kind !== "ADMISSION_REVOKE"
  )
    fail("GRANT_HORIZON is reserved for ADMISSION_REVOKE");

  // Sequence zero has a null predecessor; every later sequence in the same
  // window names its exact predecessor. Chains never cross a window.
  if (operation.authorSequence === 0n) {
    if (operation.previousAuthorOperationId !== null)
      fail("author sequence zero must have a null predecessor");
  } else if (operation.previousAuthorOperationId === null) {
    fail("a non-zero author sequence must name its predecessor");
  }

  // The pinned authority is the sole stable author binding: a relay author
  // must not be able to suppress a revoke by rewrapping it under another key.
  if (operation.kind === "ADMISSION_REVOKE") {
    const floor = context.roomPolicy.admissionFloor;
    if (floor.mode !== "authority-grant")
      fail("ADMISSION_REVOKE requires an authority-grant room policy");
    const expectedExpiry = checkedAdd(
      checkedAdd(operation.logicalWindow, future),
      BigInt(floor.maxAuthorityCredentialLifetimeWindows),
    );
    if (operation.expiresAfterWindow !== expectedExpiry)
      fail("ADMISSION_REVOKE outer expiry must use its exact grant horizon");
    if (
      !bytesEqual(
        operation.authorEpochEd25519Key,
        floor.authorityEd25519PublicKey,
      )
    )
      fail("ADMISSION_REVOKE must be authored by the pinned authority key");
  }

  return { pairEnvelope };
};

/**
 * Public cheap structural gate.
 *
 * Its return type intentionally remains void: the decoded pair envelope is an
 * internal validation artifact, not a value callers may treat as trusted
 * without the semantic-slot and author-signature checks below.
 */
export const validateOperationStructure = (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
): void => {
  validateOperationStructureInternal(
    operation,
    snapshotOperationValidationContext(context),
    "active-or-future",
  );
};

/** Verify the author signature over the exact domain-separated transcript. */
export const verifyOperationSignature = async (
  operation: AuthenticatedRoomOperationV1,
  module?: LibCrypto,
): Promise<boolean> => {
  const { authorSignature, ...unsigned } = operation;
  const signature = Uint8Array.from(authorSignature);
  const publicKey = Uint8Array.from(operation.authorEpochEd25519Key);
  const message = operationSignatureMessage(unsigned);
  return verify(message, signature, publicKey, module);
};

export type DecodedOperationPayloadV1 =
  | DecodedNonPairOperationPayloadV1
  | { readonly kind: "PAIR_STEP"; readonly value: PairStepEnvelopeV1 };

/**
 * Validate the room-wide outer candidate without non-pair payload work.
 *
 * CoreReduce uses this stage to count authenticated candidates and classify an
 * entire author/window as forked or overquota before spending work on nested
 * authority/store signatures. The returned pair envelope is already part of
 * endpoint-independent outer framing; null means the signed kind is non-pair.
 */
const validateOperationOuterOwned = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  referenceMode: OperationReferenceMode,
  module?: LibCrypto,
): Promise<PairStepEnvelopeV1 | null> => {
  const { pairEnvelope } = validateOperationStructureInternal(
    operation,
    context,
    referenceMode,
  );

  const derivedConfirmation = await roomContextConfirmation(
    context.roomContextId,
  );
  if (!bytesEqual(derivedConfirmation, context.roomContextConfirmation))
    fail("validation context has an inconsistent RoomContextId confirmation");

  if (pairEnvelope !== null) {
    const expectedSemanticSlot = await pairSemanticSlot(
      pairEnvelope.pairRoutingTag,
    );
    if (!bytesEqual(operation.semanticSlot, expectedSemanticSlot))
      fail("PAIR_STEP semanticSlot does not match pairRoutingTag");
  }
  if (!(await verifyOperationSignature(operation, module)))
    fail("author signature does not verify");
  return pairEnvelope;
};

export const validateOperationOuter = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<PairStepEnvelopeV1 | null> => {
  const snapshot = snapshotValidationInputs(operation, context);
  return validateOperationOuterOwned(
    snapshot.operation,
    snapshot.context,
    "active-or-future",
    module,
  );
};

/**
 * Authenticate a bounded reducer candidate.
 *
 * Unlike `validateOperationOuter`, this accepts exact outer-expired bytes only
 * through the policy-derived inert evidence horizon. It still performs no
 * nested payload signature work, so author quota/fork classification remains
 * the first expensive-work boundary.
 */
export const validateOperationCandidateOuter = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<PairStepEnvelopeV1 | null> => {
  const snapshot = snapshotValidationInputs(operation, context);
  return validateOperationOuterOwned(
    snapshot.operation,
    snapshot.context,
    "candidate-evidence",
    module,
  );
};

/**
 * Full intrinsic validation: authenticated outer candidate followed by the
 * one nested payload codec selected by its signed kind.
 *
 * LEAVE's referenced-presence rule remains set-dependent and is completed by
 * CoreReduce after the dependency is available.
 */
export const validateOperationAndDecodePayload = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<DecodedOperationPayloadV1> => {
  const snapshot = snapshotValidationInputs(operation, context);
  const pairEnvelope = await validateOperationOuterOwned(
    snapshot.operation,
    snapshot.context,
    "active-or-future",
    module,
  );

  if (pairEnvelope !== null) return { kind: "PAIR_STEP", value: pairEnvelope };

  return decodeAndValidateNonPairOperationPayload(
    snapshot.operation,
    {
      roomContextId: snapshot.context.roomContextId,
      roomPolicy: snapshot.context.roomPolicy,
    },
    module,
  );
};

/** Validate an operation without exposing its decoded payload artifact. */
export const validateOperation = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  await validateOperationAndDecodePayload(operation, context, module);
};

/** Sign an operation over the exact transcript and return the signed form. */
export const signOperation = async (
  unsigned: UnsignedRoomOperationV1,
  authorSecretKey: Uint8Array,
  module?: LibCrypto,
): Promise<AuthenticatedRoomOperationV1> => {
  const unsignedBytes = encodeCanonical(
    authenticatedRoomOperationUnsignedV1Schema,
    unsigned,
  );
  const privateUnsigned = decodeCanonicalStrict(
    authenticatedRoomOperationUnsignedV1Schema,
    unsignedBytes,
  ) as UnsignedRoomOperationV1;
  return {
    ...privateUnsigned,
    authorSignature: await sign(
      operationSignatureMessage(privateUnsigned),
      Uint8Array.from(authorSecretKey),
      module,
    ),
  };
};

/** The unique canonical encoding of a signed operation. */
export const encodeOperation = (
  operation: AuthenticatedRoomOperationV1,
): Uint8Array => encodeCanonical(authenticatedRoomOperationV1Schema, operation);

/** Decode and prove the bytes are the unique encoding of the result. */
export const decodeOperation = (
  encoded: Uint8Array,
): AuthenticatedRoomOperationV1 =>
  decodeCanonicalStrict(
    authenticatedRoomOperationV1Schema,
    encoded,
  ) as AuthenticatedRoomOperationV1;

/**
 * `OperationId`, derived only after carrier decryption and validation. It is
 * never sent to a store as a logical identifier.
 */
export const deriveOperationId = (
  operation: AuthenticatedRoomOperationV1,
): Promise<Uint8Array> => operationId(operation);

/** Build the all-zero padding a payload needs to reach its class length. */
export const operationPaddingFor = (
  operationPayloadClass: OperationPayloadClassV1,
  payloadBytes: number,
): Uint8Array => {
  const classBytes = OPERATION_PAYLOAD_CLASS_BYTES[operationPayloadClass];
  if (payloadBytes > classBytes)
    fail("payload exceeds its declared operation payload class");
  return new Uint8Array(classBytes - payloadBytes);
};
