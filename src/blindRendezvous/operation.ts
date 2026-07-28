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
import { operationId, operationSignatureMessage } from "./derivations";
import {
  OPERATION_PAYLOAD_CLASS_BYTES,
  authenticatedRoomOperationV1Schema,
} from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";
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
  if (sum > 0xffffffffffffffffn) fail("checked addition overflowed");
  return sum;
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

export interface OperationValidationContext {
  /** `RoomContextConfirmation` derived from the local room context. */
  readonly roomContextConfirmation: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  /** The explicit reference window; never ambient wall-clock time. */
  readonly referenceWindow: bigint;
}

/**
 * Structural and bound validation that needs no signature check.
 *
 * Separated from signature verification so a caller can reject cheap garbage
 * before spending an Ed25519 verification on it, which is what keeps the
 * per-author work bound in SEC-021 meaningful.
 */
export const validateOperationStructure = (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
): void => {
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
  if (
    operation.kind !== "PAIR_STEP" &&
    operationPayloadClassFor(operation.kind, operation.fixedPayload.length) !==
      operation.operationPayloadClass
  )
    fail("operation does not use its smallest permitted payload class");

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
  if (operation.logicalWindow > checkedAdd(context.referenceWindow, future))
    fail("operation is further in the future than maxFutureLogicalWindows");
  if (context.referenceWindow > checkedAdd(operation.expiresAfterWindow, skew))
    fail("operation is expired at this reference window");
  if (operation.logicalWindow > operation.expiresAfterWindow)
    fail("operation expires before its logical window");

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
    if (
      !bytesEqual(
        operation.authorEpochEd25519Key,
        floor.authorityEd25519PublicKey,
      )
    )
      fail("ADMISSION_REVOKE must be authored by the pinned authority key");
  }
};

/** Verify the author signature over the exact domain-separated transcript. */
export const verifyOperationSignature = async (
  operation: AuthenticatedRoomOperationV1,
  module?: LibCrypto,
): Promise<boolean> => {
  const { authorSignature, ...unsigned } = operation;
  return verify(
    operationSignatureMessage(unsigned),
    authorSignature,
    operation.authorEpochEd25519Key,
    module,
  );
};

/**
 * Full outer validation: structure, bounds, then signature.
 *
 * Order matters — an operation that fails a bound never reaches the
 * verification, and an operation that fails verification never reaches any
 * set, roster, admission view, catalog, or pair ledger (SEC-003).
 */
export const validateOperation = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  validateOperationStructure(operation, context);
  if (!(await verifyOperationSignature(operation, module)))
    fail("author signature does not verify");
};

/** Sign an operation over the exact transcript and return the signed form. */
export const signOperation = async (
  unsigned: UnsignedRoomOperationV1,
  authorSecretKey: Uint8Array,
  module?: LibCrypto,
): Promise<AuthenticatedRoomOperationV1> => ({
  ...unsigned,
  authorSignature: await sign(
    operationSignatureMessage(unsigned),
    authorSecretKey,
    module,
  ),
});

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
