/**
 * Internal, pure Section 4.8 admission-policy semantics.
 *
 * This module deliberately does not implement `Admit()`, trusted snapshot or
 * custody capture, provenance brands, pair opening/binding, persistence,
 * serialization, outbound-intent atomicity, or the pre-SDP runtime gate. Its
 * structural inputs are useful only after a future trusted constructor has
 * obtained the same facts atomically. Nothing here may turn a caller-supplied
 * authority availability bit, digest, or revocation list into trusted state.
 *
 * The helpers do own the deterministic policy order and lease arithmetic once
 * those facts are available. This file is not exported from the package barrel.
 */

import { bytesEqual } from "./canonicalSchema";
import {
  admissionGrantId,
  stableIdentityCommitment as deriveStableIdentityCommitment,
} from "./derivations";
import {
  decodeAdmissionGrantV1,
  encodeAdmissionGrantV1,
  OperationPayloadValidationError,
  validateAdmissionGrantV1,
} from "./operationPayload";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { CoreFaultV1, CoreRevocationFloorV1 } from "./coreReduce";
import type { AdmissionGrantV1 } from "./operationPayload";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U64_MAX = 0xffffffffffffffffn;
const MAX_LOCAL_SET_ENTRIES = 0xffff;

export type CanonicalBytes32SetV1 = readonly Uint8Array[];

export interface FrontendRoomControlsV1 {
  readonly version: 1;
  readonly policyGeneration: bigint;
  readonly onlyConnectWithKnownPeers: boolean;
  readonly allowedStableIdentityKeys: CanonicalBytes32SetV1;
  readonly deniedStableIdentityKeys: CanonicalBytes32SetV1;
  readonly deniedRoomIdentityCommitments: CanonicalBytes32SetV1;
}

export interface AuthorityWindowFaultV1 {
  readonly logicalWindow: bigint;
  readonly proofOperationIds: readonly Uint8Array[];
}

/**
 * Structural policy projection only. A future private authority-view
 * constructor must derive this from a branded atomic snapshot. This interface
 * and its digest field do not establish provenance.
 */
export interface AuthorityAdmissionPolicyViewV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly referenceWindow: bigint;
  readonly status: "available" | "unavailable";
  readonly revocationFacts: readonly CoreRevocationFloorV1[];
  readonly authorityAdmissionStateDigest: Uint8Array;
}

export interface PairAttemptLeaseV1 {
  readonly version: 1;
  readonly helloOperationId: Uint8Array;
  readonly pairEdgeId: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
  readonly attemptMode: "planner" | "explicit";
  readonly helloLogicalWindow: bigint;
  readonly validThroughLogicalWindow: bigint;
}

export interface BootstrapAdmissionDecisionLeaseV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly stableEd25519PublicKey: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly grantId: Uint8Array | null;
  readonly grantGeneration: bigint | null;
  readonly localPolicyGeneration: bigint;
  readonly authorityAdmissionStateDigest: Uint8Array | null;
  readonly admittedPresenceOperationId: Uint8Array;
  readonly admittedIdentityOperationId: Uint8Array;
  readonly decidedAtLogicalWindow: bigint;
  readonly validThroughLogicalWindow: bigint;
}

export interface StableEdgeAdmissionLeaseV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly stableEdgeId: Uint8Array;
  readonly confirmedPairTranscriptId: Uint8Array;
  readonly rendezvousChannelId: Uint8Array;
  readonly v4WireBinding: Uint8Array;
  readonly remoteStableEd25519PublicKey: Uint8Array;
  readonly remoteStableIdentityCommitment: Uint8Array;
  readonly grantId: Uint8Array | null;
  readonly grantGeneration: bigint | null;
  readonly localPolicyGeneration: bigint;
  readonly authorityAdmissionStateDigest: Uint8Array | null;
  readonly decidedAtLogicalWindow: bigint;
  readonly validThroughLogicalWindow: bigint | null;
}

export type AdmissionAllowReason = "open" | "address-book" | "authority-grant";

export type AdmissionDenyReason =
  | "blacklisted"
  | "not-in-address-book"
  | "missing-grant"
  | "invalid-grant"
  | "revoked"
  | "policy-unavailable";

export interface AllowedPeerAdmissionPolicyV1 {
  readonly result: "allow";
  readonly reason: AdmissionAllowReason;
  readonly localPolicyGeneration: bigint;
  readonly grantId: Uint8Array | null;
  readonly grantGeneration: bigint | null;
  readonly authorityAdmissionStateDigest: Uint8Array | null;
  readonly grantValidThroughLogicalWindow: bigint | null;
}

export interface DeniedPeerAdmissionPolicyV1 {
  readonly result: "deny";
  readonly reason: AdmissionDenyReason;
}

export type PeerAdmissionPolicyDecisionV1 =
  AllowedPeerAdmissionPolicyV1 | DeniedPeerAdmissionPolicyV1;

export type PairAdmissionDecision =
  | {
      readonly result: "allow";
      readonly reason: AdmissionAllowReason;
      readonly bootstrapLease: BootstrapAdmissionDecisionLeaseV1;
      readonly pairAttemptLease: PairAttemptLeaseV1;
    }
  | DeniedPeerAdmissionPolicyV1;

export type StableEdgeAdmissionDecision =
  | {
      readonly result: "allow";
      readonly reason: AdmissionAllowReason;
      readonly lease: StableEdgeAdmissionLeaseV1;
    }
  | DeniedPeerAdmissionPolicyV1;

/**
 * Unbranded facts consumed by the semantic policy helper. Production code must
 * obtain the corresponding values from `TrustedAdmissionSnapshotV1`; this type
 * is intentionally not named or presented as that trusted snapshot.
 */
export interface PeerAdmissionPolicySemanticInputV1 {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly frontendControls: FrontendRoomControlsV1 | null;
  readonly authorityView: AuthorityAdmissionPolicyViewV1 | null;
  readonly stableEd25519PublicKey: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly optionalGrant: AdmissionGrantV1 | null;
  readonly grantCarriedAtLogicalWindow: bigint | null;
}

export interface BootstrapAdmissionLeaseSemanticInputV1 {
  readonly policy: AllowedPeerAdmissionPolicyV1;
  readonly roomContextId: Uint8Array;
  readonly stableEd25519PublicKey: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly admittedPresenceOperationId: Uint8Array;
  readonly admittedIdentityOperationId: Uint8Array;
  readonly admittedIdentityOperationLogicalWindow: bigint;
  readonly admittedIdentityOperationValidThroughLogicalWindow: bigint;
  readonly admittedPresenceEvidenceRetainThroughLogicalWindow: bigint;
  readonly basePairAttemptLease: PairAttemptLeaseV1;
  readonly referenceWindow: bigint;
}

export interface StableEdgeAdmissionLeaseSemanticInputV1 {
  readonly policy: AllowedPeerAdmissionPolicyV1;
  readonly roomContextId: Uint8Array;
  readonly stableEdgeId: Uint8Array;
  readonly confirmedPairTranscriptId: Uint8Array;
  readonly rendezvousChannelId: Uint8Array;
  readonly v4WireBinding: Uint8Array;
  readonly remoteStableEd25519PublicKey: Uint8Array;
  readonly remoteStableIdentityCommitment: Uint8Array;
  readonly referenceWindow: bigint;
}

export class AdmissionPolicySemanticError extends Error {
  override readonly name = "AdmissionPolicySemanticError";

  constructor(message: string) {
    super(`admissionPolicy: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new AdmissionPolicySemanticError(message);
};

const requireU64 = (name: string, value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${name} must be an unsigned 64-bit integer`);
  return value;
};

const checkedAddU64 = (name: string, left: bigint, right: bigint): bigint => {
  requireU64(`${name} left operand`, left);
  requireU64(`${name} right operand`, right);
  if (right > U64_MAX - left)
    return fail(`${name} overflowed unsigned 64-bit arithmetic`);
  return left + right;
};

const copyBytes32 = (name: string, value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32)
    return fail(`${name} must be exactly 32 bytes`);
  return Uint8Array.from(value);
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const compareU64 = (left: bigint, right: bigint): number =>
  left < right ? -1 : left > right ? 1 : 0;

const hasExactOwnDataFields = (
  value: unknown,
  expectedFields: readonly string[],
): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedFields.length ||
    keys.some((key) => typeof key !== "string" || !expectedFields.includes(key))
  )
    return false;
  return expectedFields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return descriptor !== undefined && "value" in descriptor;
  });
};

const copyCanonicalBytes32Set = (
  name: string,
  value: unknown,
): CanonicalBytes32SetV1 => {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    return fail(`${name} must be a dense array`);
  if (value.length > MAX_LOCAL_SET_ENTRIES)
    return fail(`${name} exceeds the local collection bound`);

  const result: Uint8Array[] = [];
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !("value" in descriptor))
      return fail(`${name} must be a dense data-property array`);
    const current = copyBytes32(`${name}[${String(index)}]`, descriptor.value);
    if (index > 0) {
      const order = compareBytes(result[index - 1], current);
      if (order > 0) return fail(`${name} must be bytewise sorted`);
      if (order === 0) return fail(`${name} must be duplicate-free`);
    }
    result.push(current);
  }
  return result;
};

export const validateAndCopyFrontendRoomControlsV1 = (
  value: unknown,
): FrontendRoomControlsV1 => {
  const fields = [
    "version",
    "policyGeneration",
    "onlyConnectWithKnownPeers",
    "allowedStableIdentityKeys",
    "deniedStableIdentityKeys",
    "deniedRoomIdentityCommitments",
  ] as const;
  if (!hasExactOwnDataFields(value, fields))
    return fail(
      "FrontendRoomControlsV1 must contain exactly its declared fields",
    );
  if (value.version !== 1)
    return fail("unsupported FrontendRoomControlsV1 version");
  if (typeof value.onlyConnectWithKnownPeers !== "boolean")
    return fail("onlyConnectWithKnownPeers must be boolean");

  return {
    version: 1,
    policyGeneration: requireU64(
      "FrontendRoomControlsV1.policyGeneration",
      value.policyGeneration,
    ),
    onlyConnectWithKnownPeers: value.onlyConnectWithKnownPeers,
    allowedStableIdentityKeys: copyCanonicalBytes32Set(
      "allowedStableIdentityKeys",
      value.allowedStableIdentityKeys,
    ),
    deniedStableIdentityKeys: copyCanonicalBytes32Set(
      "deniedStableIdentityKeys",
      value.deniedStableIdentityKeys,
    ),
    deniedRoomIdentityCommitments: copyCanonicalBytes32Set(
      "deniedRoomIdentityCommitments",
      value.deniedRoomIdentityCommitments,
    ),
  };
};

/** Membership over an already validated canonical byte set. */
export const canonicalBytes32SetHas = (
  values: CanonicalBytes32SetV1,
  candidate: Uint8Array,
): boolean => {
  const target = copyBytes32("canonical set candidate", candidate);
  let lower = 0;
  let upper = values.length;
  while (lower < upper) {
    const middle = lower + Math.floor((upper - lower) / 2);
    const current = values[middle];
    if (!(current instanceof Uint8Array) || current.length !== 32)
      return fail("canonical set contains a non-Bytes32 value");
    const order = compareBytes(current, target);
    if (order < 0) lower = middle + 1;
    else upper = middle;
  }
  return lower < values.length && bytesEqual(values[lower], target);
};

const copyRevocationFact = (
  fact: CoreRevocationFloorV1,
): CoreRevocationFloorV1 => ({
  stableIdentityCommitment: copyBytes32(
    "revocation stableIdentityCommitment",
    fact.stableIdentityCommitment,
  ),
  minimumAcceptedGeneration: requireU64(
    "revocation minimumAcceptedGeneration",
    fact.minimumAcceptedGeneration,
  ),
  effectiveLogicalWindow: requireU64(
    "revocation effectiveLogicalWindow",
    fact.effectiveLogicalWindow,
  ),
  validThroughLogicalWindow: requireU64(
    "revocation validThroughLogicalWindow",
    fact.validThroughLogicalWindow,
  ),
  revokeOperationId: copyBytes32(
    "revocation revokeOperationId",
    fact.revokeOperationId,
  ),
});

const compareRevocationFacts = (
  left: CoreRevocationFloorV1,
  right: CoreRevocationFloorV1,
): number =>
  compareBytes(left.stableIdentityCommitment, right.stableIdentityCommitment) ||
  compareU64(left.minimumAcceptedGeneration, right.minimumAcceptedGeneration) ||
  compareU64(left.effectiveLogicalWindow, right.effectiveLogicalWindow) ||
  compareU64(left.validThroughLogicalWindow, right.validThroughLogicalWindow) ||
  compareBytes(left.revokeOperationId, right.revokeOperationId);

const revocationFactsEqual = (
  left: CoreRevocationFloorV1,
  right: CoreRevocationFloorV1,
): boolean => compareRevocationFacts(left, right) === 0;

/**
 * `ApplicableRevocationFacts(commitment, referenceWindow)` from Section 4.8.
 * Input order and exact duplicate delivery do not affect the result.
 */
export const selectApplicableRevocationFacts = (
  facts: readonly CoreRevocationFloorV1[],
  stableIdentityCommitment: Uint8Array,
  referenceWindow: bigint,
): readonly CoreRevocationFloorV1[] => {
  const commitment = copyBytes32(
    "stableIdentityCommitment",
    stableIdentityCommitment,
  );
  const reference = requireU64("referenceWindow", referenceWindow);
  const selected = facts
    .map(copyRevocationFact)
    .filter(
      (fact) =>
        bytesEqual(fact.stableIdentityCommitment, commitment) &&
        fact.effectiveLogicalWindow <= reference &&
        reference <= fact.validThroughLogicalWindow,
    )
    .sort(compareRevocationFacts);

  return selected.filter(
    (fact, index) =>
      index === 0 || !revocationFactsEqual(selected[index - 1], fact),
  );
};

const snapshotRoomPolicy = (roomPolicy: RoomPolicyV4): RoomPolicyV4 =>
  decodeRoomPolicyV4(encodeRoomPolicyV4(roomPolicy));

export const authorityFaultValidThrough = (
  roomPolicy: RoomPolicyV4,
  faultWindow: bigint,
): bigint => {
  const policy = snapshotRoomPolicy(roomPolicy);
  if (policy.admissionFloor.mode !== "authority-grant")
    return fail("authority fault horizon requires authority-grant mode");
  let result = requireU64("faultWindow", faultWindow);
  result = checkedAddU64(
    "authority fault max-future horizon",
    result,
    BigInt(policy.protocolLimits.maxFutureLogicalWindows),
  );
  result = checkedAddU64(
    "authority fault credential horizon",
    result,
    BigInt(policy.admissionFloor.maxAuthorityCredentialLifetimeWindows),
  );
  return checkedAddU64(
    "authority fault clock-skew horizon",
    result,
    BigInt(policy.protocolLimits.maxClockSkewWindows),
  );
};

const copyAndNormalizeProofIds = (
  proofOperationIds: readonly Uint8Array[],
): readonly Uint8Array[] => {
  if (proofOperationIds.length === 0)
    return fail("authority fault requires at least one proof operation");
  const sorted = proofOperationIds
    .map((operationId, index) =>
      copyBytes32(
        `authority fault proofOperationIds[${String(index)}]`,
        operationId,
      ),
    )
    .sort(compareBytes);
  return sorted.filter(
    (operationId, index) =>
      index === 0 || !bytesEqual(sorted[index - 1], operationId),
  );
};

const compareAuthorityWindowFaults = (
  left: AuthorityWindowFaultV1,
  right: AuthorityWindowFaultV1,
): number => {
  const windowOrder = compareU64(left.logicalWindow, right.logicalWindow);
  if (windowOrder !== 0) return windowOrder;
  const sharedLength = Math.min(
    left.proofOperationIds.length,
    right.proofOperationIds.length,
  );
  for (let index = 0; index < sharedLength; index++) {
    const proofOrder = compareBytes(
      left.proofOperationIds[index],
      right.proofOperationIds[index],
    );
    if (proofOrder !== 0) return proofOrder;
  }
  return left.proofOperationIds.length - right.proofOperationIds.length;
};

const authorityWindowFaultsEqual = (
  left: AuthorityWindowFaultV1,
  right: AuthorityWindowFaultV1,
): boolean => compareAuthorityWindowFaults(left, right) === 0;

export interface BlockingAuthorityWindowFaultSelectionV1 {
  readonly blockingAuthorityWindowFaults: readonly AuthorityWindowFaultV1[];
  readonly unavailableThroughLogicalWindow: bigint | null;
}

/**
 * Select every still-blocking pinned-authority author-window fault. Custody
 * saturation is intentionally absent; the future trusted view constructor must
 * combine this selection with its protected custody projection.
 */
export const selectBlockingAuthorityWindowFaults = (
  faults: readonly CoreFaultV1[],
  roomPolicy: RoomPolicyV4,
  referenceWindow: bigint,
): BlockingAuthorityWindowFaultSelectionV1 => {
  const policy = snapshotRoomPolicy(roomPolicy);
  if (policy.admissionFloor.mode !== "authority-grant")
    return fail("authority fault selection requires authority-grant mode");
  const reference = requireU64("referenceWindow", referenceWindow);

  const selected: AuthorityWindowFaultV1[] = [];
  for (const fault of faults) {
    if (
      fault.kind !== "author-fork-or-overquota" ||
      !bytesEqual(
        fault.authorEpochEd25519Key,
        policy.admissionFloor.authorityEd25519PublicKey,
      )
    )
      continue;
    const logicalWindow = requireU64(
      "authority fault logicalWindow",
      fault.logicalWindow,
    );
    const validThrough = authorityFaultValidThrough(policy, logicalWindow);
    if (logicalWindow > reference || reference > validThrough) continue;
    selected.push({
      logicalWindow,
      proofOperationIds: copyAndNormalizeProofIds(fault.proofOperationIds),
    });
  }
  selected.sort(compareAuthorityWindowFaults);
  const unique = selected.filter(
    (fault, index) =>
      index === 0 || !authorityWindowFaultsEqual(selected[index - 1], fault),
  );

  let unavailableThroughLogicalWindow: bigint | null = null;
  for (const fault of unique) {
    const horizon = authorityFaultValidThrough(policy, fault.logicalWindow);
    if (
      unavailableThroughLogicalWindow === null ||
      horizon > unavailableThroughLogicalWindow
    )
      unavailableThroughLogicalWindow = horizon;
  }
  return {
    blockingAuthorityWindowFaults: unique,
    unavailableThroughLogicalWindow,
  };
};

export const authorityGenerationAllowed = (
  generation: bigint,
  authorityView: Pick<
    AuthorityAdmissionPolicyViewV1,
    "status" | "revocationFacts"
  >,
): boolean => {
  const candidateGeneration = requireU64("generation", generation);
  if (authorityView.status !== "available") return false;
  let minimumAcceptedGeneration = 0n;
  for (const sourceFact of authorityView.revocationFacts) {
    const fact = copyRevocationFact(sourceFact);
    if (fact.minimumAcceptedGeneration > minimumAcceptedGeneration)
      minimumAcceptedGeneration = fact.minimumAcceptedGeneration;
  }
  return candidateGeneration >= minimumAcceptedGeneration;
};

const snapshotAuthorityView = (
  value: AuthorityAdmissionPolicyViewV1,
): AuthorityAdmissionPolicyViewV1 => {
  if (value.version !== 1)
    return fail("unsupported authority admission view version");
  if (value.status !== "available" && value.status !== "unavailable")
    return fail("authority admission view has an unknown status");
  const roomContextId = copyBytes32(
    "authority view roomContextId",
    value.roomContextId,
  );
  const commitment = copyBytes32(
    "authority view stableIdentityCommitment",
    value.stableIdentityCommitment,
  );
  const referenceWindow = requireU64(
    "authority view referenceWindow",
    value.referenceWindow,
  );
  const revocationFacts = selectApplicableRevocationFacts(
    value.revocationFacts,
    commitment,
    referenceWindow,
  );
  return {
    version: 1,
    roomContextId,
    stableIdentityCommitment: commitment,
    referenceWindow,
    status: value.status,
    revocationFacts,
    authorityAdmissionStateDigest: copyBytes32(
      "authorityAdmissionStateDigest",
      value.authorityAdmissionStateDigest,
    ),
  };
};

const deny = (reason: AdmissionDenyReason): DeniedPeerAdmissionPolicyV1 => ({
  result: "deny",
  reason,
});

interface SnapshottedPolicyInput {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly frontendControls: FrontendRoomControlsV1 | null;
  readonly authorityView: AuthorityAdmissionPolicyViewV1 | null;
  readonly authorityViewInvalid: boolean;
  readonly stableEd25519PublicKey: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly optionalGrant: AdmissionGrantV1 | null;
  readonly optionalGrantPresent: boolean;
  readonly optionalGrantInvalid: boolean;
  readonly grantCarriedAtLogicalWindow: bigint | null;
  readonly grantCarriedAtInvalid: boolean;
}

const snapshotPolicyInput = (
  input: PeerAdmissionPolicySemanticInputV1,
): SnapshottedPolicyInput => {
  const roomContextId = copyBytes32("roomContextId", input.roomContextId);
  const roomPolicy = snapshotRoomPolicy(input.roomPolicy);
  const referenceWindow = requireU64("referenceWindow", input.referenceWindow);
  const frontendControls =
    input.frontendControls === null
      ? null
      : validateAndCopyFrontendRoomControlsV1(input.frontendControls);

  let authorityView: AuthorityAdmissionPolicyViewV1 | null = null;
  let authorityViewInvalid = false;
  if (input.authorityView !== null) {
    try {
      authorityView = snapshotAuthorityView(input.authorityView);
    } catch (error) {
      if (!(error instanceof AdmissionPolicySemanticError)) throw error;
      authorityViewInvalid = true;
    }
  }

  const optionalGrantPresent = input.optionalGrant !== null;
  let optionalGrant: AdmissionGrantV1 | null = null;
  let optionalGrantInvalid = false;
  if (input.optionalGrant !== null) {
    try {
      optionalGrant = decodeAdmissionGrantV1(
        encodeAdmissionGrantV1(input.optionalGrant),
      );
    } catch {
      optionalGrantInvalid = true;
    }
  }

  let grantCarriedAtLogicalWindow: bigint | null = null;
  let grantCarriedAtInvalid = false;
  if (input.grantCarriedAtLogicalWindow !== null) {
    try {
      grantCarriedAtLogicalWindow = requireU64(
        "grantCarriedAtLogicalWindow",
        input.grantCarriedAtLogicalWindow,
      );
    } catch (error) {
      if (!(error instanceof AdmissionPolicySemanticError)) throw error;
      grantCarriedAtInvalid = true;
    }
  }

  return {
    roomContextId,
    roomPolicy,
    referenceWindow,
    frontendControls,
    authorityView,
    authorityViewInvalid,
    stableEd25519PublicKey: copyBytes32(
      "stableEd25519PublicKey",
      input.stableEd25519PublicKey,
    ),
    stableIdentityCommitment: copyBytes32(
      "stableIdentityCommitment",
      input.stableIdentityCommitment,
    ),
    optionalGrant,
    optionalGrantPresent,
    optionalGrantInvalid,
    grantCarriedAtLogicalWindow,
    grantCarriedAtInvalid,
  };
};

/**
 * The one semantic policy order shared by future bootstrap and stable-edge
 * wrappers. It intentionally does not verify trusted snapshot/view provenance.
 */
export const evaluatePeerAdmissionPolicySemantics = async (
  input: PeerAdmissionPolicySemanticInputV1,
  module?: LibCrypto,
): Promise<PeerAdmissionPolicyDecisionV1> => {
  const value = snapshotPolicyInput(input);
  const frontendControls = value.frontendControls;
  if (frontendControls === null) return deny("policy-unavailable");

  const expectedCommitment = await deriveStableIdentityCommitment(
    value.roomContextId,
    value.stableEd25519PublicKey,
  );
  if (!bytesEqual(expectedCommitment, value.stableIdentityCommitment))
    return fail("stable key does not match the claimed room commitment");

  if (
    canonicalBytes32SetHas(
      frontendControls.deniedStableIdentityKeys,
      value.stableEd25519PublicKey,
    ) ||
    canonicalBytes32SetHas(
      frontendControls.deniedRoomIdentityCommitments,
      value.stableIdentityCommitment,
    )
  )
    return deny("blacklisted");

  let grantId: Uint8Array | null = null;
  let grantGeneration: bigint | null = null;
  let authorityAdmissionStateDigest: Uint8Array | null = null;
  let grantValidThroughLogicalWindow: bigint | null = null;

  if (value.roomPolicy.admissionFloor.mode === "authority-grant") {
    const authorityView = value.authorityView;
    if (
      value.authorityViewInvalid ||
      authorityView === null ||
      !bytesEqual(authorityView.roomContextId, value.roomContextId) ||
      !bytesEqual(
        authorityView.stableIdentityCommitment,
        value.stableIdentityCommitment,
      ) ||
      authorityView.referenceWindow !== value.referenceWindow ||
      authorityView.status !== "available"
    )
      return deny("policy-unavailable");

    if (!value.optionalGrantPresent) return deny("missing-grant");
    const grant = value.optionalGrant;
    if (
      value.optionalGrantInvalid ||
      grant === null ||
      value.grantCarriedAtInvalid ||
      value.grantCarriedAtLogicalWindow === null ||
      !bytesEqual(grant.stableEd25519PublicKey, value.stableEd25519PublicKey)
    )
      return deny("invalid-grant");

    try {
      await validateAdmissionGrantV1(
        grant,
        {
          roomContextId: value.roomContextId,
          roomPolicy: value.roomPolicy,
          carriedAtLogicalWindow: value.grantCarriedAtLogicalWindow,
          referenceWindow: value.referenceWindow,
        },
        module,
      );
    } catch (error) {
      if (error instanceof OperationPayloadValidationError)
        return deny("invalid-grant");
      throw error;
    }
    if (!authorityGenerationAllowed(grant.generation, authorityView))
      return deny("revoked");

    grantId = await admissionGrantId(grant);
    grantGeneration = grant.generation;
    authorityAdmissionStateDigest = Uint8Array.from(
      authorityView.authorityAdmissionStateDigest,
    );
    grantValidThroughLogicalWindow = grant.notAfterLogicalWindow;
  } else {
    if (value.authorityView !== null || value.authorityViewInvalid)
      return fail("capability mode forbids an authority admission view");
    if (
      value.optionalGrantPresent ||
      value.grantCarriedAtLogicalWindow !== null ||
      value.grantCarriedAtInvalid
    )
      return deny("invalid-grant");
  }

  if (
    frontendControls.onlyConnectWithKnownPeers &&
    !canonicalBytes32SetHas(
      frontendControls.allowedStableIdentityKeys,
      value.stableEd25519PublicKey,
    )
  )
    return deny("not-in-address-book");

  return {
    result: "allow",
    reason:
      value.roomPolicy.admissionFloor.mode === "authority-grant"
        ? "authority-grant"
        : frontendControls.onlyConnectWithKnownPeers
          ? "address-book"
          : "open",
    localPolicyGeneration: frontendControls.policyGeneration,
    grantId,
    grantGeneration,
    authorityAdmissionStateDigest,
    grantValidThroughLogicalWindow,
  };
};

export const validateAndCopyPairAttemptLeaseV1 = (
  value: unknown,
): PairAttemptLeaseV1 => {
  const fields = [
    "version",
    "helloOperationId",
    "pairEdgeId",
    "endpointPresenceOperationIds",
    "attemptMode",
    "helloLogicalWindow",
    "validThroughLogicalWindow",
  ] as const;
  if (!hasExactOwnDataFields(value, fields))
    return fail("PairAttemptLeaseV1 must contain exactly its declared fields");
  if (value.version !== 1)
    return fail("unsupported PairAttemptLeaseV1 version");
  if (value.attemptMode !== "planner" && value.attemptMode !== "explicit")
    return fail("PairAttemptLeaseV1 has an unknown attempt mode");
  if (
    !Array.isArray(value.endpointPresenceOperationIds) ||
    Object.getPrototypeOf(value.endpointPresenceOperationIds) !==
      Array.prototype ||
    value.endpointPresenceOperationIds.length !== 2 ||
    Reflect.ownKeys(value.endpointPresenceOperationIds).length !== 3 ||
    !["0", "1"].every((index) => {
      const descriptor = Object.getOwnPropertyDescriptor(
        value.endpointPresenceOperationIds,
        index,
      );
      return descriptor !== undefined && "value" in descriptor;
    })
  )
    return fail(
      "PairAttemptLeaseV1 endpoint tuple must contain exactly two data-property IDs",
    );

  const helloLogicalWindow = requireU64(
    "PairAttemptLeaseV1.helloLogicalWindow",
    value.helloLogicalWindow,
  );
  const validThroughLogicalWindow = requireU64(
    "PairAttemptLeaseV1.validThroughLogicalWindow",
    value.validThroughLogicalWindow,
  );
  if (helloLogicalWindow > validThroughLogicalWindow)
    return fail("PairAttemptLeaseV1 has an impossible interval");

  return {
    version: 1,
    helloOperationId: copyBytes32(
      "PairAttemptLeaseV1.helloOperationId",
      value.helloOperationId,
    ),
    pairEdgeId: copyBytes32("PairAttemptLeaseV1.pairEdgeId", value.pairEdgeId),
    endpointPresenceOperationIds: [
      copyBytes32(
        "PairAttemptLeaseV1.endpointPresenceOperationIds[0]",
        value.endpointPresenceOperationIds[0],
      ),
      copyBytes32(
        "PairAttemptLeaseV1.endpointPresenceOperationIds[1]",
        value.endpointPresenceOperationIds[1],
      ),
    ],
    attemptMode: value.attemptMode,
    helloLogicalWindow,
    validThroughLogicalWindow,
  };
};

const copyAllowedPolicy = (
  policy: AllowedPeerAdmissionPolicyV1,
): AllowedPeerAdmissionPolicyV1 => {
  if (policy.result !== "allow")
    return fail("lease construction requires an allowed policy result");
  if (
    policy.reason !== "open" &&
    policy.reason !== "address-book" &&
    policy.reason !== "authority-grant"
  )
    return fail("allowed policy has an unknown reason");
  const localPolicyGeneration = requireU64(
    "localPolicyGeneration",
    policy.localPolicyGeneration,
  );

  if (policy.reason === "authority-grant") {
    if (
      policy.grantId === null ||
      policy.grantGeneration === null ||
      policy.authorityAdmissionStateDigest === null ||
      policy.grantValidThroughLogicalWindow === null
    )
      return fail("authority-grant policy is missing authority bindings");
    return {
      result: "allow",
      reason: policy.reason,
      localPolicyGeneration,
      grantId: copyBytes32("grantId", policy.grantId),
      grantGeneration: requireU64("grantGeneration", policy.grantGeneration),
      authorityAdmissionStateDigest: copyBytes32(
        "authorityAdmissionStateDigest",
        policy.authorityAdmissionStateDigest,
      ),
      grantValidThroughLogicalWindow: requireU64(
        "grantValidThroughLogicalWindow",
        policy.grantValidThroughLogicalWindow,
      ),
    };
  }

  if (
    policy.grantId !== null ||
    policy.grantGeneration !== null ||
    policy.authorityAdmissionStateDigest !== null ||
    policy.grantValidThroughLogicalWindow !== null
  )
    return fail("capability policy carries authority bindings");
  return {
    result: "allow",
    reason: policy.reason,
    localPolicyGeneration,
    grantId: null,
    grantGeneration: null,
    authorityAdmissionStateDigest: null,
    grantValidThroughLogicalWindow: null,
  };
};

/**
 * Narrow the authenticated base pair-attempt horizon by the admitted grant,
 * then construct both immutable bootstrap leases. A future trusted wrapper
 * must verify every pair/presence coordinate before calling this semantic
 * helper and must persist only this returned pair-attempt lease.
 */
export const constructBootstrapAdmissionDecisionLease = (
  input: BootstrapAdmissionLeaseSemanticInputV1,
): PairAdmissionDecision => {
  const policy = copyAllowedPolicy(input.policy);
  const basePairAttemptLease = validateAndCopyPairAttemptLeaseV1(
    input.basePairAttemptLease,
  );
  const referenceWindow = requireU64("referenceWindow", input.referenceWindow);
  const identityLogicalWindow = requireU64(
    "admittedIdentityOperationLogicalWindow",
    input.admittedIdentityOperationLogicalWindow,
  );
  const identityValidThrough = requireU64(
    "admittedIdentityOperationValidThroughLogicalWindow",
    input.admittedIdentityOperationValidThroughLogicalWindow,
  );
  const presenceEvidenceRetainThrough = requireU64(
    "admittedPresenceEvidenceRetainThroughLogicalWindow",
    input.admittedPresenceEvidenceRetainThroughLogicalWindow,
  );
  if (
    identityLogicalWindow > referenceWindow ||
    referenceWindow > identityValidThrough ||
    basePairAttemptLease.helloLogicalWindow > referenceWindow
  )
    return fail("bootstrap lease inputs have an impossible interval");

  const pairAttemptValidThroughLogicalWindow =
    policy.grantValidThroughLogicalWindow === null ||
    basePairAttemptLease.validThroughLogicalWindow <=
      policy.grantValidThroughLogicalWindow
      ? basePairAttemptLease.validThroughLogicalWindow
      : policy.grantValidThroughLogicalWindow;
  const pairAttemptLease: PairAttemptLeaseV1 = {
    ...basePairAttemptLease,
    validThroughLogicalWindow: pairAttemptValidThroughLogicalWindow,
  };
  const horizons = [
    pairAttemptLease.validThroughLogicalWindow,
    presenceEvidenceRetainThrough,
    identityValidThrough,
  ];
  let validThroughLogicalWindow = horizons[0];
  for (let index = 1; index < horizons.length; index++)
    if (horizons[index] < validThroughLogicalWindow)
      validThroughLogicalWindow = horizons[index];
  if (referenceWindow > validThroughLogicalWindow)
    return deny("policy-unavailable");

  return {
    result: "allow",
    reason: policy.reason,
    bootstrapLease: {
      version: 1,
      roomContextId: copyBytes32("roomContextId", input.roomContextId),
      stableEd25519PublicKey: copyBytes32(
        "stableEd25519PublicKey",
        input.stableEd25519PublicKey,
      ),
      stableIdentityCommitment: copyBytes32(
        "stableIdentityCommitment",
        input.stableIdentityCommitment,
      ),
      grantId: policy.grantId === null ? null : Uint8Array.from(policy.grantId),
      grantGeneration: policy.grantGeneration,
      localPolicyGeneration: policy.localPolicyGeneration,
      authorityAdmissionStateDigest:
        policy.authorityAdmissionStateDigest === null
          ? null
          : Uint8Array.from(policy.authorityAdmissionStateDigest),
      admittedPresenceOperationId: copyBytes32(
        "admittedPresenceOperationId",
        input.admittedPresenceOperationId,
      ),
      admittedIdentityOperationId: copyBytes32(
        "admittedIdentityOperationId",
        input.admittedIdentityOperationId,
      ),
      decidedAtLogicalWindow: referenceWindow,
      validThroughLogicalWindow,
    },
    pairAttemptLease,
  };
};

/**
 * Construct only the stable-edge lease/result after a future branded stable
 * context and fresh trusted snapshot have passed the shared policy helper.
 */
export const constructStableEdgeAdmissionLease = (
  input: StableEdgeAdmissionLeaseSemanticInputV1,
): StableEdgeAdmissionDecision => {
  const policy = copyAllowedPolicy(input.policy);
  const referenceWindow = requireU64("referenceWindow", input.referenceWindow);
  if (
    policy.grantValidThroughLogicalWindow !== null &&
    referenceWindow > policy.grantValidThroughLogicalWindow
  )
    return deny("policy-unavailable");

  return {
    result: "allow",
    reason: policy.reason,
    lease: {
      version: 1,
      roomContextId: copyBytes32("roomContextId", input.roomContextId),
      stableEdgeId: copyBytes32("stableEdgeId", input.stableEdgeId),
      confirmedPairTranscriptId: copyBytes32(
        "confirmedPairTranscriptId",
        input.confirmedPairTranscriptId,
      ),
      rendezvousChannelId: copyBytes32(
        "rendezvousChannelId",
        input.rendezvousChannelId,
      ),
      v4WireBinding: copyBytes32("v4WireBinding", input.v4WireBinding),
      remoteStableEd25519PublicKey: copyBytes32(
        "remoteStableEd25519PublicKey",
        input.remoteStableEd25519PublicKey,
      ),
      remoteStableIdentityCommitment: copyBytes32(
        "remoteStableIdentityCommitment",
        input.remoteStableIdentityCommitment,
      ),
      grantId: policy.grantId === null ? null : Uint8Array.from(policy.grantId),
      grantGeneration: policy.grantGeneration,
      localPolicyGeneration: policy.localPolicyGeneration,
      authorityAdmissionStateDigest:
        policy.authorityAdmissionStateDigest === null
          ? null
          : Uint8Array.from(policy.authorityAdmissionStateDigest),
      decidedAtLogicalWindow: referenceWindow,
      validThroughLogicalWindow: policy.grantValidThroughLogicalWindow,
    },
  };
};
