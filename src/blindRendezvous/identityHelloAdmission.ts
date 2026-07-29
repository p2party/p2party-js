/**
 * HELLO-responder admission preparation boundary.
 *
 * A service factory captures the initialized room and one storage port.
 * Per-HELLO callers supply only a genuine one-use authenticated claim; they
 * cannot assemble trusted rows, policy views, admission decisions, or lease
 * coordinates. An allow remains an opaque pre-topology policy result with
 * private HelloRoot custody. It is not a prepared persistence mutation or send
 * authority: planner/replay/resource checks, exact response construction,
 * compare-and-swap persistence, and publication remain later transitions.
 *
 * This source-internal module is intentionally absent from the package barrel.
 */

import {
  CanonicalSchemaError,
  MAX_CANONICAL_ENCODING_BYTES,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { snapshotByteInput } from "../cryptography/byteInput";
import {
  AdmissionPolicySemanticError,
  constructBootstrapAdmissionDecisionLease,
  decodeFrontendRoomControlsV1,
  evaluatePeerAdmissionPolicySemantics,
  selectApplicableRevocationFacts,
  selectBlockingAuthorityWindowFaults,
  validateAndCopyBootstrapAdmissionDecisionLeaseV1,
  validateAndCopyPairAttemptLeaseV1,
} from "./admissionPolicy";
import {
  destroyConsumedIdentityHelloAdmissionClaimV1,
  snapshotConsumedIdentityHelloAdmissionClaimV1,
  takeIdentityHelloAdmissionClaimForVerificationV1,
} from "./identityHelloOpen";
import { invalidAdmissionInput } from "./admissionInput";
import { authorityAdmissionStateDigest } from "./derivations";
import { decodeCoreRoomStateV1 } from "./coreReduce";
import {
  IdentityHelloHistoricalEvidenceError,
  decodeAndVerifyIdentityHelloHistoricalEvidenceBundleV1,
} from "./identityHelloHistoricalEvidence";
import { snapshotOperationValidationContext } from "./operation";
import { encodeRoomPolicyV4 } from "./roomPolicyV4";
import {
  authorityCustodyProjectionV1Schema,
  initializedRoomAdmissionFenceV1Schema,
  localPresenceOwnershipV1Schema,
} from "./schemas";
import {
  IdentityHelloAdmissionPersistenceError,
  validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1,
} from "./identityHelloAdmissionPersistence";

import type { LibCrypto } from "../cryptography/libcrypto";
import type {
  AuthorityAdmissionPolicyViewV1,
  FrontendRoomControlsV1,
  PairAdmissionDecision,
} from "./admissionPolicy";
import type { CoreRoomStateV1 } from "./coreReduce";
import type {
  ConsumedIdentityHelloAdmissionClaimV1,
  IdentityHelloAdmissionClaimSnapshotV1,
  IdentityHelloAdmissionClaimV1,
} from "./identityHelloOpen";
import type { OperationValidationContext } from "./operation";
import type { RoomPolicyV4 } from "./roomPolicyV4";
import type {
  IdentityHelloAdmissionExactCaptureRowsV1,
  IdentityHelloAdmissionPersistencePortV1,
  IdentityHelloAdmissionReadLocatorV1,
} from "./identityHelloAdmissionPersistence";

const U64_MAX = 0xffffffffffffffffn;

declare const trustedAdmissionSnapshotBrand: unique symbol;
declare const verifiedAdmissionContextBrand: unique symbol;
declare const preparedIdentityHelloAdmissionBrand: unique symbol;

interface TrustedAdmissionSnapshotV1 {
  readonly [trustedAdmissionSnapshotBrand]: true;
}

interface VerifiedAdmissionContextV1 {
  readonly [verifiedAdmissionContextBrand]: true;
}

/**
 * Opaque policy allow before topology, replay/fork, key, and resource checks.
 * Its private state owns the claim and exact capture; spreading, persistence,
 * or a type assertion cannot reproduce its process-local provenance.
 */
export interface PreparedIdentityHelloAdmissionV1 {
  readonly [preparedIdentityHelloAdmissionBrand]: true;
}

export interface InitializedRoomAdmissionFenceV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
}

export interface LocalPresenceOwnershipV1 {
  readonly version: 1;
  readonly localPresenceOperationIds: readonly Uint8Array[];
  readonly localStableIdentityKeys: readonly Uint8Array[];
}

export type AuthorityCustodyProjectionV1 =
  | {
      readonly version: 1;
      readonly status: "complete";
      readonly authorityCustodyStateDigest: Uint8Array;
      readonly firstSaturatedRequiredWorkId: null;
    }
  | {
      readonly version: 1;
      readonly status: "saturated";
      readonly authorityCustodyStateDigest: Uint8Array;
      readonly firstSaturatedRequiredWorkId: Uint8Array;
    };

export type IdentityHelloAdmissionCapturePortV1 = Pick<
  IdentityHelloAdmissionPersistencePortV1,
  "readExactCapture"
>;

export type PrepareIdentityHelloAdmissionResultV1 =
  | {
      readonly kind: "prepared";
      readonly value: PreparedIdentityHelloAdmissionV1;
    }
  | {
      readonly kind: "denied";
      readonly reason:
        | "blacklisted"
        | "not-in-address-book"
        | "missing-grant"
        | "invalid-grant"
        | "revoked"
        | "policy-unavailable";
    }
  | {
      readonly kind: "stale";
      readonly reason:
        | "initialized-room-changed"
        | "core-changed"
        | "historical-evidence-changed"
        | "receiver-key-changed"
        | "local-presence-ownership-changed";
    };

export interface IdentityHelloAdmissionPreparationServiceV1 {
  prepareIdentityHelloAdmission(
    claim: IdentityHelloAdmissionClaimV1,
  ): Promise<PrepareIdentityHelloAdmissionResultV1>;
}

export interface PreparedIdentityHelloAdmissionSnapshotV1 {
  readonly version: 1;
  readonly stage: "policy-allowed-pre-topology";
  readonly decision: Extract<
    PairAdmissionDecision,
    { readonly result: "allow" }
  >;
}

type VerifyIdentityHelloAdmissionCaptureResultV1 =
  | {
      readonly kind: "verified";
      readonly snapshot: TrustedAdmissionSnapshotV1;
      readonly context: VerifiedAdmissionContextV1;
    }
  | {
      readonly kind: "stale";
      readonly reason:
        | "initialized-room-changed"
        | "core-changed"
        | "historical-evidence-changed"
        | "receiver-key-changed"
        | "local-presence-ownership-changed";
    };

interface PrivateTrustedAdmissionSnapshot {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly coreRoomState: CoreRoomStateV1;
  readonly frontendControls: FrontendRoomControlsV1 | null;
  readonly authorityCustody: AuthorityCustodyProjectionV1 | null;
  readonly localPresenceOwnership: LocalPresenceOwnershipV1;
  readonly exactCapture: IdentityHelloAdmissionExactCaptureRowsV1;
}

interface PrivateVerifiedAdmissionContext {
  readonly claim: ConsumedIdentityHelloAdmissionClaimV1;
  readonly facts: IdentityHelloAdmissionClaimSnapshotV1;
  readonly snapshot: TrustedAdmissionSnapshotV1;
}

interface PrivatePreparedIdentityHelloAdmission {
  readonly snapshot: TrustedAdmissionSnapshotV1;
  readonly context: VerifiedAdmissionContextV1;
  readonly decision: Extract<
    PairAdmissionDecision,
    { readonly result: "allow" }
  >;
}

const trustedSnapshotStates = new WeakMap<
  object,
  PrivateTrustedAdmissionSnapshot
>();
const genuineTrustedSnapshots = new WeakSet<object>();
const verifiedContextStates = new WeakMap<
  object,
  PrivateVerifiedAdmissionContext
>();
const genuineVerifiedContexts = new WeakSet<object>();
const preparedAdmissionStates = new WeakMap<
  object,
  PrivatePreparedIdentityHelloAdmission
>();
const genuinePreparedAdmissions = new WeakSet<object>();

const ownBytes = (
  value: unknown,
  label: string,
  exactLength?: number,
): Uint8Array =>
  snapshotByteInput(
    value,
    `identityHelloAdmission: ${label}`,
    exactLength === undefined
      ? { maximumLength: MAX_CANONICAL_ENCODING_BYTES }
      : { exactLength },
  );

const copyBytes32 = (value: Uint8Array): Uint8Array =>
  ownBytes(value, "Bytes32", 32);

const copyReadLocator = (
  value: IdentityHelloAdmissionReadLocatorV1,
): IdentityHelloAdmissionReadLocatorV1 => ({
  version: 1,
  roomContextId: copyBytes32(value.roomContextId),
  helloOperationId: copyBytes32(value.helloOperationId),
  pairEdgeId: copyBytes32(value.pairEdgeId),
  localPresenceOperationId: copyBytes32(value.localPresenceOperationId),
  exactHistoricalEvidenceCoreStateBytes: ownBytes(
    value.exactHistoricalEvidenceCoreStateBytes,
    "historical evidence Core locator",
  ),
});

const requireU64 = (value: unknown, label: string): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return invalidAdmissionInput(`${label} must be an unsigned 64-bit integer`);
  return value;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const canonicalBytes32SetHas = (
  values: readonly Uint8Array[],
  candidate: Uint8Array,
): boolean => {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (compareBytes(values[middle], candidate) < 0) low = middle + 1;
    else high = middle;
  }
  return low < values.length && bytesEqual(values[low], candidate);
};

const ownInitializedRoomFence = (
  exactBytes: Uint8Array,
): InitializedRoomAdmissionFenceV1 => {
  try {
    return decodeCanonicalStrict(
      initializedRoomAdmissionFenceV1Schema,
      exactBytes,
    ) as InitializedRoomAdmissionFenceV1;
  } catch (error) {
    if (error instanceof Error)
      return invalidAdmissionInput(
        `invalid initialized-room row: ${error.message}`,
      );
    return invalidAdmissionInput("invalid initialized-room row");
  }
};

const ownLocalPresenceOwnership = (
  exactBytes: Uint8Array,
): LocalPresenceOwnershipV1 => {
  let value: LocalPresenceOwnershipV1;
  try {
    value = decodeCanonicalStrict(
      localPresenceOwnershipV1Schema,
      exactBytes,
    ) as LocalPresenceOwnershipV1;
  } catch (error) {
    if (error instanceof Error)
      return invalidAdmissionInput(
        `invalid local-presence-ownership row: ${error.message}`,
      );
    return invalidAdmissionInput("invalid local-presence-ownership row");
  }
  if (value.version !== 1)
    return invalidAdmissionInput(
      "unsupported local-presence-ownership version",
    );
  return value;
};

const ownAuthorityCustody = (
  exactBytes: Uint8Array,
): AuthorityCustodyProjectionV1 => {
  let value: AuthorityCustodyProjectionV1;
  try {
    value = decodeCanonicalStrict(
      authorityCustodyProjectionV1Schema,
      exactBytes,
    ) as AuthorityCustodyProjectionV1;
  } catch (error) {
    if (error instanceof Error)
      return invalidAdmissionInput(
        `invalid authority-custody row: ${error.message}`,
      );
    return invalidAdmissionInput("invalid authority-custody row");
  }
  if (value.version !== 1)
    return invalidAdmissionInput("unsupported authority-custody version");
  if (
    (value.status === "complete" &&
      value.firstSaturatedRequiredWorkId !== null) ||
    (value.status === "saturated" &&
      value.firstSaturatedRequiredWorkId === null)
  )
    return invalidAdmissionInput(
      "authority-custody status and saturation witness disagree",
    );
  return value;
};

const requireTrustedSnapshotState = (
  value: TrustedAdmissionSnapshotV1,
): PrivateTrustedAdmissionSnapshot => {
  const state =
    typeof value === "object" && value !== null
      ? trustedSnapshotStates.get(value)
      : undefined;
  if (state === undefined)
    return invalidAdmissionInput(
      "trusted admission snapshot must be a genuine live process-local handle",
    );
  return state;
};

const requireVerifiedContextState = (
  value: VerifiedAdmissionContextV1,
): PrivateVerifiedAdmissionContext => {
  const state =
    typeof value === "object" && value !== null
      ? verifiedContextStates.get(value)
      : undefined;
  if (state === undefined)
    return invalidAdmissionInput(
      "verified admission context must be a genuine live process-local handle",
    );
  return state;
};

export const encodeInitializedRoomAdmissionFenceV1 = (
  initializedRoom: OperationValidationContext,
): Uint8Array => {
  const context = snapshotOperationValidationContext(initializedRoom);
  return encodeCanonical(initializedRoomAdmissionFenceV1Schema, {
    version: 1,
    roomContextId: context.roomContextId,
    roomPolicy: context.roomPolicy,
  });
};

export const encodeLocalPresenceOwnershipV1 = (
  value: LocalPresenceOwnershipV1,
): Uint8Array => encodeCanonical(localPresenceOwnershipV1Schema, value);

export const encodeAuthorityCustodyProjectionV1 = (
  value: AuthorityCustodyProjectionV1,
): Uint8Array => {
  const encoded = encodeCanonical(authorityCustodyProjectionV1Schema, value);
  ownAuthorityCustody(encoded);
  return encoded;
};

const createTrustedHandle = (
  state: PrivateTrustedAdmissionSnapshot,
): TrustedAdmissionSnapshotV1 => {
  const handle = Object.freeze({}) as TrustedAdmissionSnapshotV1;
  genuineTrustedSnapshots.add(handle);
  trustedSnapshotStates.set(handle, state);
  return handle;
};

const createVerifiedContextHandle = (
  claim: ConsumedIdentityHelloAdmissionClaimV1,
  facts: IdentityHelloAdmissionClaimSnapshotV1,
  snapshot: TrustedAdmissionSnapshotV1,
): VerifiedAdmissionContextV1 => {
  const handle = Object.freeze({}) as VerifiedAdmissionContextV1;
  genuineVerifiedContexts.add(handle);
  verifiedContextStates.set(handle, { claim, facts, snapshot });
  return handle;
};

/** Correlate one factory-owned exact capture with one consumed HELLO claim. */
const verifyIdentityHelloAdmissionCaptureV1 = async (
  consumedClaim: ConsumedIdentityHelloAdmissionClaimV1,
  facts: IdentityHelloAdmissionClaimSnapshotV1,
  initializedRoomHandle: OperationValidationContext,
  capture: IdentityHelloAdmissionExactCaptureRowsV1,
): Promise<VerifyIdentityHelloAdmissionCaptureResultV1> => {
  let transferred = false;
  try {
    let captured: IdentityHelloAdmissionExactCaptureRowsV1;
    try {
      captured =
        validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(capture);
    } catch (error) {
      if (error instanceof IdentityHelloAdmissionPersistenceError)
        return invalidAdmissionInput(error.message);
      throw error;
    }
    const initializedRoom = snapshotOperationValidationContext(
      initializedRoomHandle,
    );
    if (captured.initializedRoom.kind === "absent")
      return { kind: "stale", reason: "initialized-room-changed" };
    if (captured.currentCore.kind === "absent")
      return { kind: "stale", reason: "core-changed" };
    if (captured.historicalEvidence.kind === "absent")
      return { kind: "stale", reason: "historical-evidence-changed" };
    if (captured.receiverKey.kind === "absent")
      return { kind: "stale", reason: "receiver-key-changed" };
    if (captured.localPresenceOwnership.kind === "absent")
      return {
        kind: "stale",
        reason: "local-presence-ownership-changed",
      };

    const exactInitializedRoomBytes = captured.initializedRoom.exactBytes;
    const exactCurrentCoreStateBytes = captured.currentCore.exactBytes;
    const exactHistoricalEvidenceBytes = captured.historicalEvidence.exactBytes;
    const receiverKeyRecordRevision = requireU64(
      captured.receiverKey.recordRevision,
      "receiver-key record revision",
    );
    const exactLocalPresenceOwnershipBytes =
      captured.localPresenceOwnership.exactBytes;
    const exactFrontendControlsBytes =
      captured.frontendControls.kind === "absent"
        ? null
        : captured.frontendControls.exactBytes;
    const exactAuthorityCustodyBytes =
      captured.authorityCustody.kind === "absent"
        ? null
        : captured.authorityCustody.exactBytes;

    const initializedFence = ownInitializedRoomFence(exactInitializedRoomBytes);
    const expectedInitializedBytes =
      encodeInitializedRoomAdmissionFenceV1(initializedRoom);
    if (
      !bytesEqual(exactInitializedRoomBytes, expectedInitializedBytes) ||
      !bytesEqual(
        initializedFence.roomContextId,
        initializedRoom.roomContextId,
      ) ||
      !bytesEqual(facts.roomContextId, initializedRoom.roomContextId) ||
      !bytesEqual(
        encodeRoomPolicyV4(initializedFence.roomPolicy),
        encodeRoomPolicyV4(initializedRoom.roomPolicy),
      ) ||
      !bytesEqual(
        encodeRoomPolicyV4(facts.roomPolicy),
        encodeRoomPolicyV4(initializedRoom.roomPolicy),
      )
    )
      return { kind: "stale", reason: "initialized-room-changed" };

    let coreRoomState: CoreRoomStateV1;
    try {
      coreRoomState = await decodeCoreRoomStateV1(exactCurrentCoreStateBytes);
    } catch (error) {
      if (
        error instanceof CanonicalSchemaError ||
        (error instanceof Error && error.message.startsWith("coreReduce:"))
      )
        return invalidAdmissionInput(
          `invalid current Core row: ${error.message}`,
        );
      throw error;
    }
    if (
      coreRoomState.referenceWindow !== initializedRoom.referenceWindow ||
      coreRoomState.referenceWindow < facts.openedAtReferenceWindow ||
      !coreRoomState.activePairOuterOperationIds.some((operationId) =>
        bytesEqual(operationId, facts.operationId),
      ) ||
      initializedRoom.referenceWindow < facts.logicalWindow ||
      initializedRoom.referenceWindow > facts.validThroughLogicalWindow
    )
      return { kind: "stale", reason: "core-changed" };

    if (
      !bytesEqual(
        exactHistoricalEvidenceBytes,
        facts.exactHistoricalEvidenceBundleBytes,
      )
    )
      return { kind: "stale", reason: "historical-evidence-changed" };

    let historicalEvidence;
    try {
      historicalEvidence =
        await decodeAndVerifyIdentityHelloHistoricalEvidenceBundleV1(
          exactHistoricalEvidenceBytes,
          {
            roomContextId: facts.roomContextId,
            roomPolicy: facts.roomPolicy,
            exactCoreStateBytes: facts.exactHistoricalEvidenceCoreStateBytes,
            endpointPresenceOperationIds: facts.endpointPresenceOperationIds,
          },
        );
    } catch (error) {
      if (error instanceof IdentityHelloHistoricalEvidenceError)
        return invalidAdmissionInput(error.message);
      throw error;
    }

    let historicalCoreRoomState: CoreRoomStateV1;
    try {
      historicalCoreRoomState = await decodeCoreRoomStateV1(
        historicalEvidence.exactCoreStateBytes,
      );
    } catch (error) {
      if (
        error instanceof CanonicalSchemaError ||
        (error instanceof Error && error.message.startsWith("coreReduce:"))
      )
        return invalidAdmissionInput(
          `invalid historical Core row: ${error.message}`,
        );
      throw error;
    }
    if (
      historicalCoreRoomState.referenceWindow !== facts.logicalWindow ||
      facts.endpointPresenceOperationIds.some(
        (expectedPresenceOperationId) =>
          !historicalCoreRoomState.observedPresences.some((presence) =>
            bytesEqual(
              presence.presenceOperationId,
              expectedPresenceOperationId,
            ),
          ),
      ) ||
      historicalEvidence.endpointPresenceEvidence.some(
        (evidence) =>
          evidence.retainThroughLogicalWindow < initializedRoom.referenceWindow,
      )
    )
      return { kind: "stale", reason: "historical-evidence-changed" };

    if (receiverKeyRecordRevision !== facts.receiverKeyRecordRevision)
      return { kind: "stale", reason: "receiver-key-changed" };

    const localPresenceOwnership = ownLocalPresenceOwnership(
      exactLocalPresenceOwnershipBytes,
    );
    if (
      !canonicalBytes32SetHas(
        localPresenceOwnership.localPresenceOperationIds,
        facts.endpointPresenceOperationIds[1],
      )
    )
      return {
        kind: "stale",
        reason: "local-presence-ownership-changed",
      };

    let frontendControls: FrontendRoomControlsV1 | null = null;
    if (exactFrontendControlsBytes !== null) {
      try {
        frontendControls = decodeFrontendRoomControlsV1(
          exactFrontendControlsBytes,
        );
      } catch (error) {
        if (error instanceof AdmissionPolicySemanticError)
          return invalidAdmissionInput(
            `invalid frontend-controls row: ${error.message}`,
          );
        throw error;
      }
    }

    const authorityCustody =
      exactAuthorityCustodyBytes === null
        ? null
        : ownAuthorityCustody(exactAuthorityCustodyBytes);
    if (
      initializedRoom.roomPolicy.admissionFloor.mode === "capability" &&
      authorityCustody !== null
    )
      return invalidAdmissionInput(
        "capability room captured non-null authority custody",
      );

    const snapshot = createTrustedHandle({
      roomContextId: copyBytes32(initializedRoom.roomContextId),
      roomPolicy: initializedRoom.roomPolicy,
      referenceWindow: initializedRoom.referenceWindow,
      coreRoomState,
      frontendControls,
      authorityCustody,
      localPresenceOwnership,
      exactCapture: captured,
    });
    const context = createVerifiedContextHandle(consumedClaim, facts, snapshot);
    transferred = true;
    return { kind: "verified", snapshot, context };
  } finally {
    if (!transferred)
      destroyConsumedIdentityHelloAdmissionClaimV1(consumedClaim);
  }
};

const deriveAuthorityView = async (
  snapshot: PrivateTrustedAdmissionSnapshot,
  stableIdentityCommitment: Uint8Array,
): Promise<AuthorityAdmissionPolicyViewV1 | null> => {
  if (snapshot.roomPolicy.admissionFloor.mode !== "authority-grant")
    return null;
  const custody = snapshot.authorityCustody;
  if (custody === null) return null;

  const revocationFacts = selectApplicableRevocationFacts(
    snapshot.coreRoomState.revocationFloors,
    stableIdentityCommitment,
    snapshot.referenceWindow,
  );
  const faultSelection = selectBlockingAuthorityWindowFaults(
    snapshot.coreRoomState.faults,
    snapshot.roomPolicy,
    snapshot.referenceWindow,
  );
  /*
   * Phase 0 deliberately remains fail-closed here. Exact custody bytes are a
   * CAS fence, not proof of non-omission. `available` may be enabled only by a
   * constructor that revalidates the complete retained pinned-authority
   * operation bundle through the Core author-chain/fork/quota rules and exact-
   * matches its derived projection to this captured Core.
   */
  const status = "unavailable";
  const digest = await authorityAdmissionStateDigest({
    roomContextId: snapshot.roomContextId,
    stableIdentityCommitment,
    status,
    revocationFacts,
    blockingAuthorityWindowFaults: faultSelection.blockingAuthorityWindowFaults,
    authorityCustodyStatus: custody.status,
    firstSaturatedRequiredWorkId: custody.firstSaturatedRequiredWorkId,
  });

  return {
    version: 1,
    roomContextId: Uint8Array.from(snapshot.roomContextId),
    stableIdentityCommitment: Uint8Array.from(stableIdentityCommitment),
    referenceWindow: snapshot.referenceWindow,
    status,
    revocationFacts,
    authorityAdmissionStateDigest: digest,
  };
};

/**
 * Sole pure bootstrap admission policy call over genuine captured facts.
 *
 * It returns leases only; callers still lack ACCEPT/root access and must
 * commit those leases with the response/outbox in the effectful boundary.
 */
const admitVerifiedIdentityHelloV1 = async (
  snapshotHandle: TrustedAdmissionSnapshotV1,
  contextHandle: VerifiedAdmissionContextV1,
  module?: LibCrypto,
): Promise<PairAdmissionDecision> => {
  const snapshot = requireTrustedSnapshotState(snapshotHandle);
  const context = requireVerifiedContextState(contextHandle);
  const facts = context.facts;
  if (
    context.snapshot !== snapshotHandle ||
    !bytesEqual(snapshot.roomContextId, facts.roomContextId) ||
    facts.decisionRole !== "hello-responder" ||
    facts.kind !== "IDENTITY_HELLO" ||
    facts.logicalWindow > snapshot.referenceWindow ||
    snapshot.referenceWindow > facts.validThroughLogicalWindow
  )
    return invalidAdmissionInput(
      "trusted snapshot and verified HELLO context disagree",
    );

  const authorityView = await deriveAuthorityView(
    snapshot,
    facts.claimedStableIdentityCommitment,
  );
  const policy = await evaluatePeerAdmissionPolicySemantics(
    {
      roomContextId: snapshot.roomContextId,
      roomPolicy: snapshot.roomPolicy,
      referenceWindow: snapshot.referenceWindow,
      frontendControls: snapshot.frontendControls,
      authorityView,
      stableEd25519PublicKey: facts.stableEd25519PublicKey,
      stableIdentityCommitment: facts.claimedStableIdentityCommitment,
      optionalGrant: facts.optionalGrant,
      grantCarriedAtLogicalWindow:
        facts.optionalGrant === null ? null : facts.logicalWindow,
    },
    module,
  );
  if (policy.result === "deny") return policy;

  try {
    return constructBootstrapAdmissionDecisionLease({
      policy,
      roomContextId: snapshot.roomContextId,
      stableEd25519PublicKey: facts.stableEd25519PublicKey,
      stableIdentityCommitment: facts.claimedStableIdentityCommitment,
      admittedPresenceOperationId: facts.admittedPresenceOperationId,
      admittedIdentityOperationId: facts.operationId,
      admittedIdentityOperationLogicalWindow: facts.logicalWindow,
      admittedIdentityOperationValidThroughLogicalWindow:
        facts.validThroughLogicalWindow,
      admittedPresenceEvidenceRetainThroughLogicalWindow:
        facts.admittedPresenceEvidenceRetainThroughLogicalWindow,
      basePairAttemptLease: facts.basePairAttemptLease,
      referenceWindow: snapshot.referenceWindow,
    });
  } catch (error) {
    if (error instanceof AdmissionPolicySemanticError)
      return invalidAdmissionInput(error.message);
    throw error;
  }
};

/** Drop an ephemeral trusted snapshot. Idempotent for a genuine handle. */
const destroyTrustedAdmissionSnapshotV1 = (
  value: TrustedAdmissionSnapshotV1,
): void => {
  if (
    typeof value !== "object" ||
    value === null ||
    !genuineTrustedSnapshots.has(value)
  )
    return invalidAdmissionInput(
      "trusted admission snapshot must be a genuine process-local handle",
    );
  trustedSnapshotStates.delete(value);
};

/** Wipe the context-owned HelloRoot. Idempotent for a genuine handle. */
const destroyVerifiedAdmissionContextV1 = (
  value: VerifiedAdmissionContextV1,
): void => {
  if (
    typeof value !== "object" ||
    value === null ||
    !genuineVerifiedContexts.has(value)
  )
    return invalidAdmissionInput(
      "verified admission context must be a genuine process-local handle",
    );
  const state = verifiedContextStates.get(value);
  if (state === undefined) return;
  verifiedContextStates.delete(value);
  destroyConsumedIdentityHelloAdmissionClaimV1(state.claim);
};

const mintPreparedIdentityHelloAdmission = (
  snapshot: TrustedAdmissionSnapshotV1,
  context: VerifiedAdmissionContextV1,
  decision: Extract<PairAdmissionDecision, { readonly result: "allow" }>,
): PreparedIdentityHelloAdmissionV1 => {
  const prepared = Object.freeze({}) as PreparedIdentityHelloAdmissionV1;
  genuinePreparedAdmissions.add(prepared);
  preparedAdmissionStates.set(prepared, {
    snapshot,
    context,
    decision,
  });
  return prepared;
};

const copyAllowedDecision = (
  value: Extract<PairAdmissionDecision, { readonly result: "allow" }>,
): Extract<PairAdmissionDecision, { readonly result: "allow" }> => ({
  result: "allow",
  reason: value.reason,
  bootstrapLease: validateAndCopyBootstrapAdmissionDecisionLeaseV1(
    value.bootstrapLease,
  ),
  pairAttemptLease: validateAndCopyPairAttemptLeaseV1(value.pairAttemptLease),
});

/**
 * Capture one storage adapter and initialized-room provenance boundary.
 *
 * A test may supply an in-memory port; production must construct this service
 * only inside the trusted room worker with its concrete transaction adapter.
 * Per-attempt callers cannot replace the port, initialized room, or crypto
 * module.
 */
export const createIdentityHelloAdmissionPreparationServiceV1 = (
  port: IdentityHelloAdmissionCapturePortV1,
  initializedRoom: OperationValidationContext,
  module?: LibCrypto,
): IdentityHelloAdmissionPreparationServiceV1 => {
  if (
    port === null ||
    typeof port !== "object" ||
    typeof port.readExactCapture !== "function"
  )
    return invalidAdmissionInput(
      "capture port must implement readExactCapture",
    );

  const room = snapshotOperationValidationContext(initializedRoom);
  const readExactCapture = port.readExactCapture.bind(port);

  return Object.freeze({
    prepareIdentityHelloAdmission: async (
      claim: IdentityHelloAdmissionClaimV1,
    ): Promise<PrepareIdentityHelloAdmissionResultV1> => {
      const consumed = takeIdentityHelloAdmissionClaimForVerificationV1(claim);
      let verificationStarted = false;
      let verified:
        | Extract<
            VerifyIdentityHelloAdmissionCaptureResultV1,
            { readonly kind: "verified" }
          >
        | undefined;
      try {
        const facts = snapshotConsumedIdentityHelloAdmissionClaimV1(consumed);
        const locator: IdentityHelloAdmissionReadLocatorV1 = {
          version: 1,
          roomContextId: copyBytes32(facts.roomContextId),
          helloOperationId: copyBytes32(facts.operationId),
          pairEdgeId: copyBytes32(facts.pairEdgeId),
          localPresenceOperationId: copyBytes32(
            facts.endpointPresenceOperationIds[1],
          ),
          exactHistoricalEvidenceCoreStateBytes: ownBytes(
            facts.exactHistoricalEvidenceCoreStateBytes,
            "historical evidence Core locator",
          ),
        };
        const capture = await readExactCapture(copyReadLocator(locator));
        verificationStarted = true;
        const verification = await verifyIdentityHelloAdmissionCaptureV1(
          consumed,
          facts,
          room,
          capture,
        );
        if (verification.kind === "stale") return verification;
        verified = verification;

        const decision = await admitVerifiedIdentityHelloV1(
          verification.snapshot,
          verification.context,
          module,
        );
        if (decision.result === "deny")
          return {
            kind: "denied",
            reason: decision.reason,
          };

        const prepared = mintPreparedIdentityHelloAdmission(
          verification.snapshot,
          verification.context,
          decision,
        );
        verified = undefined;
        return { kind: "prepared", value: prepared };
      } finally {
        if (!verificationStarted)
          destroyConsumedIdentityHelloAdmissionClaimV1(consumed);
        if (verified !== undefined) {
          destroyVerifiedAdmissionContextV1(verified.context);
          destroyTrustedAdmissionSnapshotV1(verified.snapshot);
        }
      }
    },
  });
};

/**
 * Non-secret diagnostic/test projection. It conveys no HelloRoot, response,
 * outbox, CAS capability, or permission to publish.
 */
export const snapshotPreparedIdentityHelloAdmissionV1 = (
  value: PreparedIdentityHelloAdmissionV1,
): PreparedIdentityHelloAdmissionSnapshotV1 => {
  const state =
    typeof value === "object" && value !== null
      ? preparedAdmissionStates.get(value)
      : undefined;
  if (state === undefined)
    return invalidAdmissionInput(
      "prepared admission must be a genuine live process-local handle",
    );
  return {
    version: 1,
    stage: "policy-allowed-pre-topology",
    decision: copyAllowedDecision(state.decision),
  };
};

/** Wipe private HELLO-root custody. Idempotent for a genuine handle. */
export const destroyPreparedIdentityHelloAdmissionV1 = (
  value: PreparedIdentityHelloAdmissionV1,
): void => {
  if (
    typeof value !== "object" ||
    value === null ||
    !genuinePreparedAdmissions.has(value)
  )
    return invalidAdmissionInput(
      "prepared admission must be a genuine process-local handle",
    );
  const state = preparedAdmissionStates.get(value);
  if (state === undefined) return;
  preparedAdmissionStates.delete(value);
  destroyVerifiedAdmissionContextV1(state.context);
  destroyTrustedAdmissionSnapshotV1(state.snapshot);
};
