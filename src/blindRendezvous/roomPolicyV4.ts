/**
 * `RoomPolicyV4`: the immutable security semantics of a blind room.
 *
 * Section 4.1 keeps delivery profiles, stores, routes, planner preferences,
 * and local frontend controls out of this object: it is hashed into
 * `RoomContextId`, so anything that can change without creating a different
 * room must live elsewhere.
 *
 * The existing 32-byte `RoomPolicyV1` session policy is nested by value, not
 * copied field by field, so `authMode`, `pqMode`, `rendezvousMode`, and the
 * cover schedule keep exactly one encoder and one source of truth.
 */

import { decodeRoomPolicyV1, encodeRoomPolicyV1 } from "../roomPolicy";
import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { roomPolicyV4Schema } from "./schemas";

import type { RoomPolicyV1 } from "../roomPolicy";

export type AdmissionFloorV4 =
  | { mode: "capability" }
  | {
      mode: "authority-grant";
      authorityEd25519PublicKey: Uint8Array;
      maxAuthorityCredentialLifetimeWindows: number;
    };

export interface RoomProtocolLimitsV1 {
  logicalWindowMs: bigint;
  maxClockSkewWindows: number;
  operationRetentionWindows: number;
  pairControlRetentionWindows: number;
  receiverKeyOverlapWindows: number;
  maxFutureLogicalWindows: number;
  maxDependenciesPerOperation: number;
  maxOperationsPerAuthorWindow: number;
}

export interface RoomPolicyV4 {
  version: 4;
  /** Exact `encodeRoomPolicyV1(...)` bytes. */
  sessionPolicyV1: Uint8Array;
  roomCryptoSuite: 1;
  operationCodec: 1;
  pairBootstrapSuite: 1;
  protocolLimits: RoomProtocolLimitsV1;
  admissionFloor: AdmissionFloorV4;
  maxRoomMembers: number;
}

export class RoomPolicyV4Error extends Error {
  override readonly name = "RoomPolicyV4Error";

  constructor(message: string) {
    super(`roomPolicyV4: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new RoomPolicyV4Error(message);
};

const checkedAdd = (left: number, right: number): number => {
  const sum = left + right;
  if (!Number.isSafeInteger(sum)) fail("checked addition overflowed");
  return sum;
};

/**
 * Semantic validation beyond the canonical encoding's width checks.
 *
 * The schema already rejects out-of-range widths, unknown enum values, and
 * noncanonical encodings. This adds the Section 4.1 cross-field inequalities
 * and the nested-session-policy requirement, which no width check can express.
 */
export const validateRoomPolicyV4 = (policy: RoomPolicyV4): void => {
  // Encoding is the shape gate: it rejects unknown/missing fields, accessor
  // properties, wrong widths, and unregistered enum members.
  encodeCanonical(roomPolicyV4Schema, policy);

  if (policy.version !== 4) fail("unsupported policy version");
  if (policy.roomCryptoSuite !== 1) fail("unsupported room crypto suite");
  if (policy.operationCodec !== 1) fail("unsupported operation codec");
  if (policy.pairBootstrapSuite !== 1) fail("unsupported pair bootstrap suite");

  const limits = policy.protocolLimits;
  if (limits.logicalWindowMs <= 0n) fail("logicalWindowMs must be positive");
  if (limits.operationRetentionWindows <= 0)
    fail("operationRetentionWindows must be positive");
  if (limits.pairControlRetentionWindows < limits.operationRetentionWindows)
    fail("pairControlRetentionWindows must cover operationRetentionWindows");
  if (
    checkedAdd(
      limits.operationRetentionWindows,
      limits.receiverKeyOverlapWindows,
    ) > limits.pairControlRetentionWindows
  )
    fail(
      "operationRetentionWindows + receiverKeyOverlapWindows must fit pairControlRetentionWindows",
    );
  if (limits.maxFutureLogicalWindows > limits.maxClockSkewWindows)
    fail("maxFutureLogicalWindows must not exceed maxClockSkewWindows");
  if (limits.maxDependenciesPerOperation < 1)
    fail("maxDependenciesPerOperation must be at least one");
  if (limits.maxOperationsPerAuthorWindow < 1)
    fail("maxOperationsPerAuthorWindow must be at least one");
  if (policy.maxRoomMembers < 2) fail("maxRoomMembers must be at least two");

  // The nested policy is the SSOT for PIN/PQ/cover; only its rendezvous mode
  // is constrained here, and blind mode is not inferable from anything else.
  const sessionPolicy = decodeRoomPolicyV1(policy.sessionPolicyV1);
  if (sessionPolicy.rendezvousMode !== "blind-meeting-point")
    fail("nested session policy does not select blind-meeting-point");
};

/** The unique canonical encoding of a validated policy. */
export const encodeRoomPolicyV4 = (policy: RoomPolicyV4): Uint8Array => {
  validateRoomPolicyV4(policy);
  return encodeCanonical(roomPolicyV4Schema, policy);
};

/** Decode, prove the bytes are the unique encoding, then validate semantics. */
export const decodeRoomPolicyV4 = (encoded: Uint8Array): RoomPolicyV4 => {
  const policy = decodeCanonicalStrict(
    roomPolicyV4Schema,
    encoded,
  ) as RoomPolicyV4;
  validateRoomPolicyV4(policy);
  return policy;
};

export const roomPoliciesEqualV4 = (
  left: RoomPolicyV4,
  right: RoomPolicyV4,
): boolean => bytesEqual(encodeRoomPolicyV4(left), encodeRoomPolicyV4(right));

/**
 * The nested session policy of the byte-frozen blind default: the existing
 * canonical v1 default (revision 0, no PIN, ML-KEM-768, immediate cover) with
 * only `rendezvousMode` changed to `blind-meeting-point`.
 *
 * Section 4.1 publishes these exact 32 bytes; `tests/blindRendezvous`
 * re-derives them from `encodeRoomPolicyV1` rather than trusting the literal.
 */
export const DEFAULT_BLIND_SESSION_POLICY_V1: Readonly<RoomPolicyV1> =
  Object.freeze({
    version: 1,
    revision: 0,
    wireVersion: 4,
    authMode: "nopin",
    pqMode: "hybrid-mlkem768",
    rendezvousMode: "blind-meeting-point",
    coverMode: "immediate",
    coverCadenceMs: 0,
    coverLanes: 0,
    coverFramesPerCell: 0,
    coverDurationEpochs: 0,
  } as const);

/**
 * The room policy a capability-only `v2.` invitation resolves to.
 *
 * Fixing this here rather than reading a mutable application default is the
 * point: a later default change must not reinterpret an already shared bare v2
 * invitation.
 *
 * Status: the field values are transcribed from Section 4.1, but the object's
 * canonical bytes and therefore its `PolicyHash` depend on the unfrozen
 * `canonicalSchema`. Neither is a published v0.4 release artifact yet.
 */
export const DEFAULT_BLIND_POLICY_V4_0: Readonly<RoomPolicyV4> = Object.freeze({
  version: 4,
  sessionPolicyV1: encodeRoomPolicyV1(DEFAULT_BLIND_SESSION_POLICY_V1),
  roomCryptoSuite: 1,
  operationCodec: 1,
  pairBootstrapSuite: 1,
  protocolLimits: Object.freeze({
    logicalWindowMs: 60_000n,
    maxClockSkewWindows: 5,
    operationRetentionWindows: 1440,
    pairControlRetentionWindows: 10_080,
    receiverKeyOverlapWindows: 5,
    maxFutureLogicalWindows: 5,
    maxDependenciesPerOperation: 8,
    maxOperationsPerAuthorWindow: 16,
  }),
  admissionFloor: Object.freeze({ mode: "capability" }),
  maxRoomMembers: 64,
} as const) as Readonly<RoomPolicyV4>;

/**
 * A fresh, independently owned copy of the blind default policy.
 *
 * `Object.freeze` does not protect the elements of a `Uint8Array`, and
 * `Object.freeze` on a non-empty typed array throws, so the only way to keep
 * `DEFAULT_BLIND_POLICY_V4_0` byte-frozen in practice is to never hand out a
 * reference to its `sessionPolicyV1` storage. Callers that resolve a bare v2
 * invitation get this copy.
 */
export const copyBlindDefaultPolicy = (): RoomPolicyV4 => ({
  ...DEFAULT_BLIND_POLICY_V4_0,
  sessionPolicyV1: Uint8Array.from(DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1),
  protocolLimits: { ...DEFAULT_BLIND_POLICY_V4_0.protocolLimits },
  admissionFloor: { ...DEFAULT_BLIND_POLICY_V4_0.admissionFloor },
});
