/**
 * Pure durable pair-open work-budget reducer.
 *
 * The effectful transaction layer derives one charge from a genuine active
 * PAIR_STEP, calls this reducer, compare-and-swaps the returned row together
 * with the exact Core/pair-state revisions, and only then mints a one-use
 * cryptographic trial capability. This module deliberately cannot authorize
 * crypto work by itself.
 */

import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { base64urlNoPad, base64urlNoPadDecode } from "./derivations";
import {
  OPERATION_PAYLOAD_CLASS_BYTES,
  pairOpenBudgetChargeV1Schema,
  pairOpenBudgetSnapshotV1Schema,
} from "./schemas";

import type { TypeDescriptor } from "./canonicalSchema";

const U64_MAX = 0xffffffffffffffffn;
const U32_MAX = 0xffffffff;

export interface PairOpenBudgetCoordinateV1 {
  readonly localRoomId: string;
  readonly localPresenceOperationId: Uint8Array;
  readonly budgetLogicalWindow: bigint;
}

export interface PairOpenBudgetSnapshotV1 {
  readonly version: 1;
  readonly coordinate: PairOpenBudgetCoordinateV1;
  readonly budgetRevision: bigint;
  readonly reservedTrialCount: number;
  readonly reservedEnvelopeBytes: bigint;
  readonly saturated: boolean;
}

/**
 * Higher layers derive this from an opaque active-operation handle. In
 * particular, `completeEnvelopeBytes` is the exact validated fixed payload
 * length and is never a transport- or caller-reported estimate.
 */
export interface PairOpenBudgetChargeV1 {
  readonly localRoomId: string;
  readonly localPresenceOperationId: Uint8Array;
  readonly capturedReferenceWindow: bigint;
  readonly completeEnvelopeBytes: number;
}

export interface PairOpenBudgetLimitsV1 {
  readonly maxPairOpenTrialsPerPresenceWindow: number;
  readonly maxPairOpenBytesPerPresenceWindow: number;
}

export type PairOpenBudgetTransitionV1 =
  | {
      readonly result: "prepared";
      /** Must be durably committed before any cryptographic work begins. */
      readonly next: PairOpenBudgetSnapshotV1;
    }
  | {
      readonly result: "saturated";
      /**
       * Non-null on the first saturation (or a new-window reset) and must be
       * committed. Null means the persisted row was already sticky-saturated.
       */
      readonly next: PairOpenBudgetSnapshotV1 | null;
    };

export class PairOpenBudgetError extends Error {
  override readonly name = "PairOpenBudgetError";

  constructor(message: string) {
    super(`pairOpenBudget: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairOpenBudgetError(message);
};

const canonicalOwned = <Value>(
  descriptor: TypeDescriptor,
  value: unknown,
): Value => {
  try {
    const bytes = encodeCanonical(descriptor, value);
    return decodeCanonicalStrict(descriptor, bytes) as Value;
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("canonical validation failed");
  }
};

const validateLocalRoomId = (value: string): void => {
  let decoded: Uint8Array;
  try {
    decoded = base64urlNoPadDecode(value);
  } catch {
    return fail(
      "localRoomId must be the canonical base64url digest of 32 bytes",
    );
  }
  if (decoded.length !== 32 || base64urlNoPad(decoded) !== value)
    fail("localRoomId must be the canonical base64url digest of 32 bytes");
};

const ownSnapshot = (value: unknown): PairOpenBudgetSnapshotV1 => {
  const snapshot = canonicalOwned<PairOpenBudgetSnapshotV1>(
    pairOpenBudgetSnapshotV1Schema,
    value,
  );
  if (snapshot.version !== 1) fail("snapshot.version must be 1");
  validateLocalRoomId(snapshot.coordinate.localRoomId);
  if (snapshot.budgetRevision < 1n) fail("budgetRevision must be at least one");

  const countIsZero = snapshot.reservedTrialCount === 0;
  const bytesAreZero = snapshot.reservedEnvelopeBytes === 0n;
  if (countIsZero !== bytesAreZero)
    fail("persisted counters are not a reachable pair-open budget state");

  if (countIsZero) {
    if (!snapshot.saturated)
      fail("an unsaturated durable row must contain a prepared trial");
  } else {
    const count = BigInt(snapshot.reservedTrialCount);
    const smallClassBytes = BigInt(OPERATION_PAYLOAD_CLASS_BYTES[0]);
    const classDeltaBytes = BigInt(
      OPERATION_PAYLOAD_CLASS_BYTES[1] - OPERATION_PAYLOAD_CLASS_BYTES[0],
    );
    const minimumBytes = count * smallClassBytes;
    const excessBytes = snapshot.reservedEnvelopeBytes - minimumBytes;
    if (
      excessBytes < 0n ||
      excessBytes % classDeltaBytes !== 0n ||
      excessBytes / classDeltaBytes > count
    )
      fail("persisted counters are not a reachable pair-open budget state");
  }

  const minimumRevision =
    BigInt(snapshot.reservedTrialCount) + (snapshot.saturated ? 1n : 0n);
  if (snapshot.budgetRevision < minimumRevision)
    fail("budgetRevision is not reachable from the persisted budget state");
  return snapshot;
};

const ownCharge = (value: unknown): PairOpenBudgetChargeV1 => {
  const charge = canonicalOwned<PairOpenBudgetChargeV1>(
    pairOpenBudgetChargeV1Schema,
    value,
  );
  validateLocalRoomId(charge.localRoomId);
  if (
    charge.completeEnvelopeBytes !== OPERATION_PAYLOAD_CLASS_BYTES[0] &&
    charge.completeEnvelopeBytes !== OPERATION_PAYLOAD_CLASS_BYTES[1]
  )
    fail("completeEnvelopeBytes must equal an operation payload class");
  return charge;
};

const ownLimits = (value: PairOpenBudgetLimitsV1): PairOpenBudgetLimitsV1 => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return fail("limits must be a plain record");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    return fail("limits must be a plain record");
  const expected = [
    "maxPairOpenTrialsPerPresenceWindow",
    "maxPairOpenBytesPerPresenceWindow",
  ] as const;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !expected.some((expectedKey) => expectedKey === key),
    )
  )
    return fail("limits must contain exactly its declared fields");

  const readNumber = (name: (typeof expected)[number]): number => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor === undefined || !("value" in descriptor))
      return fail(`limits.${name} must be an own data property`);
    const number = descriptor.value;
    if (
      typeof number !== "number" ||
      !Number.isSafeInteger(number) ||
      number < 1
    )
      return fail(`limits.${name} must be a positive safe integer`);
    return number;
  };

  const maxTrials = readNumber("maxPairOpenTrialsPerPresenceWindow");
  if (maxTrials > U32_MAX)
    fail("maxPairOpenTrialsPerPresenceWindow exceeds u32");
  return {
    maxPairOpenTrialsPerPresenceWindow: maxTrials,
    maxPairOpenBytesPerPresenceWindow: readNumber(
      "maxPairOpenBytesPerPresenceWindow",
    ),
  };
};

const nextRevision = (previous: PairOpenBudgetSnapshotV1 | null): bigint => {
  if (previous === null) return 1n;
  if (previous.budgetRevision === U64_MAX)
    return fail("budgetRevision overflow");
  return previous.budgetRevision + 1n;
};

const sameSubject = (
  snapshot: PairOpenBudgetSnapshotV1,
  charge: PairOpenBudgetChargeV1,
): boolean =>
  snapshot.coordinate.localRoomId === charge.localRoomId &&
  bytesEqual(
    snapshot.coordinate.localPresenceOperationId,
    charge.localPresenceOperationId,
  );

const makeSnapshot = (value: {
  readonly charge: PairOpenBudgetChargeV1;
  readonly budgetLogicalWindow: bigint;
  readonly budgetRevision: bigint;
  readonly reservedTrialCount: number;
  readonly reservedEnvelopeBytes: bigint;
  readonly saturated: boolean;
}): PairOpenBudgetSnapshotV1 =>
  ownSnapshot({
    version: 1,
    coordinate: {
      localRoomId: value.charge.localRoomId,
      localPresenceOperationId: value.charge.localPresenceOperationId,
      budgetLogicalWindow: value.budgetLogicalWindow,
    },
    budgetRevision: value.budgetRevision,
    reservedTrialCount: value.reservedTrialCount,
    reservedEnvelopeBytes: value.reservedEnvelopeBytes,
    saturated: value.saturated,
  });

/**
 * Apply one actual expensive-trial charge.
 *
 * Equal/older captured windows reuse the durable counters. Only a strictly
 * newer captured Core reference window resets them, and reset plus charge is
 * represented by one replacement row. Repeating crypto work repeats charge.
 */
export const reducePairOpenBudgetV1 = (
  previousValue: PairOpenBudgetSnapshotV1 | null,
  chargeValue: PairOpenBudgetChargeV1,
  limitsValue: PairOpenBudgetLimitsV1,
): PairOpenBudgetTransitionV1 => {
  const previous = previousValue === null ? null : ownSnapshot(previousValue);
  const charge = ownCharge(chargeValue);
  const limits = ownLimits(limitsValue);
  if (previous !== null && !sameSubject(previous, charge))
    fail("persisted budget row belongs to another room or local presence");

  const reset =
    previous === null ||
    charge.capturedReferenceWindow > previous.coordinate.budgetLogicalWindow;
  const budgetLogicalWindow = reset
    ? charge.capturedReferenceWindow
    : (previous?.coordinate.budgetLogicalWindow ??
      charge.capturedReferenceWindow);
  const reservedTrialCount = reset ? 0 : (previous?.reservedTrialCount ?? 0);
  const reservedEnvelopeBytes = reset
    ? 0n
    : (previous?.reservedEnvelopeBytes ?? 0n);

  if (previous?.saturated === true && !reset)
    return { result: "saturated", next: null };

  const chargeBytes = BigInt(charge.completeEnvelopeBytes);
  const countWouldExceed =
    reservedTrialCount >= limits.maxPairOpenTrialsPerPresenceWindow;
  const byteLimit = BigInt(limits.maxPairOpenBytesPerPresenceWindow);
  const bytesWouldOverflow = reservedEnvelopeBytes > U64_MAX - chargeBytes;
  const bytesWouldExceed =
    bytesWouldOverflow || reservedEnvelopeBytes + chargeBytes > byteLimit;

  if (countWouldExceed || bytesWouldExceed)
    return {
      result: "saturated",
      next: makeSnapshot({
        charge,
        budgetLogicalWindow,
        budgetRevision: nextRevision(previous),
        reservedTrialCount,
        reservedEnvelopeBytes,
        saturated: true,
      }),
    };

  return {
    result: "prepared",
    next: makeSnapshot({
      charge,
      budgetLogicalWindow,
      budgetRevision: nextRevision(previous),
      reservedTrialCount: reservedTrialCount + 1,
      reservedEnvelopeBytes: reservedEnvelopeBytes + chargeBytes,
      saturated: false,
    }),
  };
};

/** Strictly own and validate one row read from durable storage. */
export const validatePairOpenBudgetSnapshotV1 = (
  value: unknown,
): PairOpenBudgetSnapshotV1 => ownSnapshot(value);
