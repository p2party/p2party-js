/**
 * Deterministic outer-layer reduction (Section 4.7).
 *
 * `Merge` is set union and `CoreReduce` is a pure function of the validated
 * operation set, the immutable room policy, and an explicit reference window.
 * It reads no arrival timestamp, server identity, fetch order, frontend
 * allow/deny state, planner preference, wall clock, "first response" state,
 * pair secret, or inner pair validity — that exclusion list is the whole
 * reason two honest clients with the same delivered set derive byte-identical
 * state no matter which carrier delivered what, in which order.
 *
 * The reducer consumes only process-private results of the validation ingress.
 * It integrates payload facts only after arrival-independent author
 * fork/quota classification, then applies semantic-slot/dependency rules and
 * emits the exact CoreRoomStateV1 projections. Frontend admission, route
 * activation, planner preference, and pair plaintext remain outside this
 * room-wide state.
 */

import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  coreOperationSetDigest,
  presenceSemanticSlot,
  roomContextConfirmation,
} from "./derivations";
import {
  decodeOperation,
  deriveOperationId,
  encodeOperation,
  requiredRoomRetentionWindows,
  snapshotOperationValidationContext,
  validateOperationCandidateOuter,
} from "./operation";
import {
  OperationPayloadValidationError,
  decodeAndValidateNonPairOperationPayload,
  decodePresenceV1,
  decodeStoreHintOperationV1,
  encodePresenceV1,
  encodeStoreHintOperationV1,
} from "./operationPayload";
import { decodePairStepEnvelopeV1 } from "./pairStepEnvelope";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";
import { coreFaultV1Schema, coreRoomStateV1Schema } from "./schemas";
import { descriptorHash, routeId, storeId } from "./storeDescriptor";

import type { LibCrypto } from "../cryptography/libcrypto";
import type {
  AuthenticatedRoomOperationV1,
  DecodedOperationPayloadV1,
  OperationValidationContext,
} from "./operation";
import type {
  AdmissionRevokeV1,
  PresenceV1,
  StoreHintOperationV1,
} from "./operationPayload";
import type { PairStepEnvelopeV1 } from "./pairStepEnvelope";
import type { RoomPolicyV4 } from "./roomPolicyV4";
import type { StoreDescriptorV1, StoreRouteV1 } from "./storeDescriptor";

/*
 * Compile-time nominal marker. It is deliberately private: consumers may
 * receive the branded interface but cannot structurally construct it.
 */
declare const outerValidatedIdentifiedOperationBrand: unique symbol;

/*
 * Runtime provenance and immutable validation snapshot. WeakMap membership is
 * process-local and is lost across JSON, structured clone, IndexedDB, workers,
 * and process restart. Persisted bytes must therefore be decoded and pass the
 * one validation entrypoint again before CoreReduce accepts them.
 */
interface ValidatedOperationSnapshot {
  /** Canonical signed bytes captured synchronously before the first await. */
  readonly operationBytes: Uint8Array;
  /** Private copy; never returned directly to a caller. */
  readonly operationId: Uint8Array;
  /** Private decoded copy; reducer logic consumes this, not the wrapper. */
  readonly operation: AuthenticatedRoomOperationV1;
  /** Canonical pair framing, or null until non-pair payload reduction. */
  readonly pairEnvelope: PairStepEnvelopeV1 | null;
  /** Exact initialized-room binding used at validation ingress. */
  readonly roomContextId: Uint8Array;
  readonly roomContextConfirmation: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  /** Checked, inclusive inert-evidence horizon for this exact candidate. */
  readonly evidenceValidThroughWindow: bigint;
}

const outerValidatedIdentifiedOperations = new WeakMap<
  object,
  ValidatedOperationSnapshot
>();

interface ReducedRoomStateSnapshot {
  /** Canonical state bytes captured before the result is exposed. */
  readonly stateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  /** Exact active PAIR_STEP provenance, keyed by OperationId hex. */
  readonly activePairOperations: ReadonlyMap<
    string,
    ActivePairReductionSnapshot
  >;
}

interface PairAuthorChainPrefixSnapshot {
  readonly operationId: Uint8Array;
  readonly operationBytes: Uint8Array;
}

interface ActivePairReductionSnapshot {
  readonly operationId: Uint8Array;
  readonly operationBytes: Uint8Array;
  readonly evidenceValidThroughWindow: bigint;
  /**
   * Exact authenticated sequence-zero-through-candidate author prefix that
   * made the PAIR_STEP eligible for CoreReduce. These bytes are later retained
   * by the pair ledger so a newly delivered fork can stall only this edge.
   */
  readonly authorChainPrefix: readonly PairAuthorChainPrefixSnapshot[];
}

/*
 * A decoded or persisted CoreRoomStateV1 is data, not trusted provenance.
 * Pair opening accepts only the live result of coreReduce(), after verifying
 * that neither the exposed state nor its selected candidate was mutated.
 */
const reducedRoomStates = new WeakMap<object, ReducedRoomStateSnapshot>();

declare const activePairOperationCandidateBrand: unique symbol;

/**
 * Process-local proof that one exact PAIR_STEP was active in one genuine
 * CoreReduce result. It intentionally exposes no structural fields.
 */
export interface ActivePairOperationCandidateV1 {
  readonly [activePairOperationCandidateBrand]: true;
}

export interface PairAuthorChainPrefixEvidenceV1 {
  readonly operationId: Uint8Array;
  readonly exactOperationBytes: Uint8Array;
}

export interface ActivePairOperationCandidateSnapshotV1 {
  readonly exactOperationBytes: Uint8Array;
  readonly operationId: Uint8Array;
  readonly operation: AuthenticatedRoomOperationV1;
  readonly envelope: PairStepEnvelopeV1;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly evidenceValidThroughWindow: bigint;
  readonly exactCoreStateBytes: Uint8Array;
  readonly authorChainPrefix: readonly PairAuthorChainPrefixEvidenceV1[];
}

interface PrivateActivePairOperationCandidateSnapshot {
  readonly operationBytes: Uint8Array;
  readonly operationId: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  readonly referenceWindow: bigint;
  readonly evidenceValidThroughWindow: bigint;
  readonly coreStateBytes: Uint8Array;
  readonly authorChainPrefix: readonly PairAuthorChainPrefixSnapshot[];
}

const activePairOperationCandidates = new WeakMap<
  object,
  PrivateActivePairOperationCandidateSnapshot
>();

/** One outer-authenticated candidate together with its private candidate ID. */
export interface OuterValidatedIdentifiedOperationV1 {
  readonly [outerValidatedIdentifiedOperationBrand]: true;
  readonly operationId: Uint8Array;
  readonly operation: AuthenticatedRoomOperationV1;
}

const freezeOperationContainers = (
  operation: AuthenticatedRoomOperationV1,
): AuthenticatedRoomOperationV1 => {
  Object.freeze(operation.dependencies);
  return Object.freeze(operation);
};

/**
 * The sole ingress from untrusted decoded bytes into the reducer domain.
 *
 * The caller-owned object is canonically snapshotted before the first await;
 * all validation and ID derivation use that private copy. OperationId is
 * derived only after complete outer validation, including PAIR_STEP slot
 * binding and the author signature. Non-pair nested signature work is
 * deliberately deferred until CoreReduce has classified author quota/forks.
 * The returned provenance brand is process-local and never persisted.
 */
export const validateAndIdentifyOperationCandidate = async (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<OuterValidatedIdentifiedOperationV1> => {
  // Both calls are synchronous. Decoding gives validation an owned copy of
  // every typed array before signature/slot hashing yields to another task.
  const operationBytes = encodeOperation(operation);
  const privateOperation = freezeOperationContainers(
    decodeOperation(operationBytes),
  );
  const privateContext = snapshotOperationValidationContext(context);
  const roomPolicyBytes = encodeRoomPolicyV4(privateContext.roomPolicy);

  const pairEnvelope = await validateOperationCandidateOuter(
    privateOperation,
    privateContext,
    module,
  );
  const evidenceValidThroughWindow = checkedAddU64(
    checkedAddU64(
      privateOperation.logicalWindow,
      requiredRoomRetentionWindows(privateContext.roomPolicy),
    ),
    BigInt(privateContext.roomPolicy.protocolLimits.maxClockSkewWindows),
  );
  const privateOperationId = await deriveOperationId(privateOperation);

  // Expose a separate copy. Typed-array elements cannot be frozen in
  // JavaScript, so reducer ingress compares it with the private canonical
  // snapshot and then consumes only the private operation below.
  const exposedOperation = freezeOperationContainers(
    decodeOperation(operationBytes),
  );
  const identified = Object.freeze({
    operationId: Uint8Array.from(privateOperationId),
    operation: exposedOperation,
  } as OuterValidatedIdentifiedOperationV1);
  outerValidatedIdentifiedOperations.set(identified, {
    operationBytes,
    operationId: Uint8Array.from(privateOperationId),
    operation: privateOperation,
    pairEnvelope,
    roomContextId: Uint8Array.from(privateContext.roomContextId),
    roomContextConfirmation: Uint8Array.from(
      privateContext.roomContextConfirmation,
    ),
    roomPolicyBytes,
    evidenceValidThroughWindow,
  });
  return identified;
};

interface ReducerOperationSnapshot extends ValidatedOperationSnapshot {
  readonly source: OuterValidatedIdentifiedOperationV1;
}

interface PayloadValidatedReducerSnapshot extends ReducerOperationSnapshot {
  readonly payload: DecodedOperationPayloadV1;
}

const reducerSnapshotFor = (value: unknown): ReducerOperationSnapshot => {
  const snapshot =
    typeof value === "object" && value !== null
      ? outerValidatedIdentifiedOperations.get(value)
      : undefined;
  if (snapshot === undefined)
    throw new Error(
      "coreReduce: input must be a live result of validateAndIdentifyOperationCandidate",
    );

  const source = value as OuterValidatedIdentifiedOperationV1;
  let exposedOperationBytes: Uint8Array;
  try {
    exposedOperationBytes = encodeOperation(source.operation);
  } catch {
    throw new Error("coreReduce: validated input was mutated after validation");
  }
  if (
    !bytesEqual(source.operationId, snapshot.operationId) ||
    !bytesEqual(exposedOperationBytes, snapshot.operationBytes)
  )
    throw new Error("coreReduce: validated input was mutated after validation");

  return { source, ...snapshot };
};

/**
 * Capture one active, provenance-checked PAIR_STEP ingress.
 *
 * This is the only bridge from room-wide outer validation into pair opening.
 * It requires both the candidate and the room state to be live results of
 * their private validation/reduction entrypoints and rechecks their canonical
 * bytes on every call. Persisted bytes must therefore pass validation and
 * CoreReduce again after restart; a merely outer-valid future, forked,
 * overquota, expired, or dependency-inert candidate cannot spend pair-open
 * work or reach admission.
 *
 * The returned value is an opaque process-local capability. Pair-kernel code
 * accepts that capability, never a caller-assembled snapshot or prebinding.
 */
export const captureActivePairOperationCandidate = async (
  candidate: OuterValidatedIdentifiedOperationV1,
  roomState: CoreRoomStateV1,
): Promise<ActivePairOperationCandidateV1> => {
  const candidateSnapshot = reducerSnapshotFor(candidate);
  const roomStateSnapshot =
    typeof roomState === "object" && roomState !== null
      ? reducedRoomStates.get(roomState)
      : undefined;
  if (roomStateSnapshot === undefined)
    throw new Error(
      "coreReduce: pair opening requires a live result of coreReduce",
    );

  let exposedStateBytes: Uint8Array;
  try {
    exposedStateBytes = await encodeCoreRoomStateV1(roomState);
  } catch {
    throw new Error(
      "coreReduce: reduced room state was mutated after reduction",
    );
  }
  if (!bytesEqual(exposedStateBytes, roomStateSnapshot.stateBytes))
    throw new Error(
      "coreReduce: reduced room state was mutated after reduction",
    );

  if (
    !bytesEqual(
      candidateSnapshot.roomContextId,
      roomStateSnapshot.roomContextId,
    ) ||
    !bytesEqual(
      candidateSnapshot.roomPolicyBytes,
      roomStateSnapshot.roomPolicyBytes,
    )
  )
    throw new Error(
      "coreReduce: pair candidate belongs to another reduced room or policy",
    );
  const active = roomStateSnapshot.activePairOperations.get(
    hex(candidateSnapshot.operationId),
  );
  if (
    active === undefined ||
    !bytesEqual(active.operationId, candidateSnapshot.operationId) ||
    !bytesEqual(active.operationBytes, candidateSnapshot.operationBytes)
  )
    throw new Error(
      "coreReduce: pair candidate is not active in the supplied room state",
    );
  if (candidateSnapshot.pairEnvelope === null)
    throw new Error("coreReduce: validated candidate is not a PAIR_STEP");

  const privateState = decodeCoreRoomStateCanonical(
    roomStateSnapshot.stateBytes,
  );
  const handle = Object.freeze({} as ActivePairOperationCandidateV1);
  activePairOperationCandidates.set(handle, {
    operationBytes: Uint8Array.from(active.operationBytes),
    operationId: Uint8Array.from(active.operationId),
    roomContextId: Uint8Array.from(roomStateSnapshot.roomContextId),
    roomPolicyBytes: Uint8Array.from(roomStateSnapshot.roomPolicyBytes),
    referenceWindow: privateState.referenceWindow,
    evidenceValidThroughWindow: active.evidenceValidThroughWindow,
    coreStateBytes: Uint8Array.from(roomStateSnapshot.stateBytes),
    authorChainPrefix: active.authorChainPrefix.map((member) => ({
      operationId: Uint8Array.from(member.operationId),
      operationBytes: Uint8Array.from(member.operationBytes),
    })),
  });
  return handle;
};

/**
 * Take an owned pair-kernel snapshot from a genuine active-operation handle.
 *
 * The returned bytes are data, not provenance: downstream state machines must
 * continue accepting the opaque `ActivePairOperationCandidateV1` and call this
 * accessor themselves. Exact Core bytes are included for the later durable
 * compare-and-swap that prevents an asynchronous open from committing against
 * a superseded room view.
 */
export const snapshotActivePairOperationCandidate = (
  candidate: ActivePairOperationCandidateV1,
): ActivePairOperationCandidateSnapshotV1 => {
  const snapshot =
    typeof candidate === "object" && candidate !== null
      ? activePairOperationCandidates.get(candidate)
      : undefined;
  if (snapshot === undefined)
    throw new Error(
      "coreReduce: pair candidate must be a live result of captureActivePairOperationCandidate",
    );

  const operation = decodeOperation(snapshot.operationBytes);
  return {
    exactOperationBytes: Uint8Array.from(snapshot.operationBytes),
    operationId: Uint8Array.from(snapshot.operationId),
    operation,
    envelope: decodePairStepEnvelopeV1(
      operation.fixedPayload,
      operation.operationPayloadClass,
    ),
    roomContextId: Uint8Array.from(snapshot.roomContextId),
    roomPolicy: decodeRoomPolicyV4(snapshot.roomPolicyBytes),
    referenceWindow: snapshot.referenceWindow,
    evidenceValidThroughWindow: snapshot.evidenceValidThroughWindow,
    exactCoreStateBytes: Uint8Array.from(snapshot.coreStateBytes),
    authorChainPrefix: snapshot.authorChainPrefix.map((member) => ({
      operationId: Uint8Array.from(member.operationId),
      exactOperationBytes: Uint8Array.from(member.operationBytes),
    })),
  };
};

export type CoreFaultV1 =
  | {
      readonly kind: "author-fork-or-overquota";
      readonly authorEpochEd25519Key: Uint8Array;
      readonly logicalWindow: bigint;
      readonly proofOperationIds: readonly Uint8Array[];
    }
  | {
      readonly kind: "presence-or-leave-fork";
      readonly semanticSlot: Uint8Array;
      readonly proofOperationIds: readonly Uint8Array[];
    }
  | {
      readonly kind: "store-generation-fork";
      readonly storeId: Uint8Array;
      readonly descriptorGeneration: bigint;
      readonly descriptorHashes: readonly [Uint8Array, Uint8Array];
    };

export interface CorePresenceFactV1 {
  readonly presenceOperationId: Uint8Array;
  readonly authorEpochEd25519Key: Uint8Array;
  readonly logicalWindow: bigint;
  readonly presence: PresenceV1;
}

export interface CoreStoreFactV1 {
  readonly storeId: Uint8Array;
  readonly descriptorGeneration: bigint;
  readonly descriptorHash: Uint8Array;
  readonly sourceOperationId: Uint8Array;
  readonly descriptor: StoreDescriptorV1;
  readonly routes: readonly StoreRouteV1[];
  readonly hintValidThroughLogicalWindow: bigint;
}

export interface CoreRevocationFloorV1 {
  readonly stableIdentityCommitment: Uint8Array;
  readonly minimumAcceptedGeneration: bigint;
  readonly effectiveLogicalWindow: bigint;
  readonly validThroughLogicalWindow: bigint;
  readonly revokeOperationId: Uint8Array;
}

export interface CoreRoomStateV1 {
  readonly version: 1;
  readonly referenceWindow: bigint;
  readonly roomCapacityState: "within-policy" | "overcapacity";
  readonly activeOperationIds: readonly Uint8Array[];
  readonly observedPresences: readonly CorePresenceFactV1[];
  readonly effectiveLeaveOperationIds: readonly Uint8Array[];
  readonly storeCatalogFacts: readonly CoreStoreFactV1[];
  readonly revocationFloors: readonly CoreRevocationFloorV1[];
  readonly activePairOuterOperationIds: readonly Uint8Array[];
  readonly faults: readonly CoreFaultV1[];
  readonly operationsDigest: Uint8Array;
}

const coreFaultKindOrder = (() => {
  if (coreFaultV1Schema.kind !== "union")
    throw new Error("coreReduce: CoreFaultV1 schema must remain a union");
  return new Map(
    coreFaultV1Schema.variants.map((variant, index) => [
      variant.tag as CoreFaultV1["kind"],
      index,
    ]),
  );
})();

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
};

const hex = (bytes: Uint8Array): string => {
  let output = "";
  for (const byte of bytes) output += byte.toString(16).padStart(2, "0");
  return output;
};

const sortBytes = (values: readonly Uint8Array[]): Uint8Array[] =>
  [...values].sort(compareBytes);

const decodeCoreRoomStateCanonical = (bytes: Uint8Array): CoreRoomStateV1 =>
  decodeCanonicalStrict(coreRoomStateV1Schema, bytes) as CoreRoomStateV1;

/**
 * Canonical rules the generic schema cannot express live here: fixed
 * cardinality for fault proofs and RouteId order for sequence-encoded routes.
 * Keeping this beside the exported Core codec prevents a second notion of
 * canonical Core bytes.
 */
const validateCoreRoomStateCanonicalSemantics = async (
  state: CoreRoomStateV1,
): Promise<void> => {
  if (state.version !== 1)
    throw new Error("coreReduce: unsupported CoreRoomStateV1 version");
  for (const fault of state.faults) {
    if (
      fault.kind === "author-fork-or-overquota" &&
      fault.proofOperationIds.length === 0
    )
      throw new Error(
        "coreReduce: author fault requires at least one proof operation",
      );
    if (
      fault.kind === "presence-or-leave-fork" &&
      fault.proofOperationIds.length !== 2
    )
      throw new Error(
        "coreReduce: semantic fault requires exactly two proof operations",
      );
    if (
      fault.kind === "store-generation-fork" &&
      fault.descriptorHashes.length !== 2
    )
      throw new Error(
        "coreReduce: store fault requires exactly two descriptor hashes",
      );
  }

  for (const fact of state.storeCatalogFacts) {
    const routeIds = await Promise.all(fact.routes.map(routeId));
    for (let index = 1; index < routeIds.length; index++) {
      const order = compareBytes(routeIds[index - 1], routeIds[index]);
      if (order > 0)
        throw new Error(
          "coreReduce: store fact routes must be sorted by RouteId",
        );
      if (order === 0)
        throw new Error(
          "coreReduce: store fact routes must be duplicate-free by RouteId",
        );
    }
  }
};

/** The unique canonical encoding of a reduced room state. */
export const encodeCoreRoomStateV1 = async (
  state: CoreRoomStateV1,
): Promise<Uint8Array> => {
  // Encode and decode synchronously before the first await so subsequent route
  // hashing sees one private snapshot even if the caller mutates its object.
  const encoded = encodeCanonical(coreRoomStateV1Schema, state);
  const snapshot = decodeCoreRoomStateCanonical(encoded);
  await validateCoreRoomStateCanonicalSemantics(snapshot);
  return encoded;
};

/** Strictly decode one canonical reduced room state. */
export const decodeCoreRoomStateV1 = async (
  bytes: Uint8Array,
): Promise<CoreRoomStateV1> => {
  // The strict decoder may return byte views, so first detach caller storage.
  const snapshot = decodeCoreRoomStateCanonical(Uint8Array.from(bytes));
  await validateCoreRoomStateCanonicalSemantics(snapshot);
  return snapshot;
};

const checkedAddU64 = (left: bigint, right: bigint): bigint => {
  const sum = left + right;
  if (left < 0n || right < 0n || sum > 0xffffffffffffffffn)
    throw new Error("coreReduce: checked unsigned-64 addition overflowed");
  return sum;
};

const outerActiveAt = (
  operation: AuthenticatedRoomOperationV1,
  referenceWindow: bigint,
  skew: bigint,
): boolean =>
  operation.logicalWindow <= referenceWindow &&
  (referenceWindow <= operation.expiresAfterWindow ||
    referenceWindow - operation.expiresAfterWindow <= skew);

/**
 * Set union with an exact-duplicate no-op.
 *
 * Associativity, commutativity, and idempotence are the properties the whole
 * convergence argument rests on, so union is deliberately keyed by the private
 * `OperationId` and nothing else — not arrival order, not carrier, not a
 * server-assigned identifier. The canonical byte comparison remains
 * load-bearing even though, absent a real OperationId hash collision, mutated
 * wrappers fail the private-snapshot check before reaching it.
 */
const mergeReducerSnapshots = (
  left: readonly OuterValidatedIdentifiedOperationV1[],
  right: readonly OuterValidatedIdentifiedOperationV1[],
): ReducerOperationSnapshot[] => {
  const byId = new Map<string, ReducerOperationSnapshot>();
  for (const value of [...left, ...right]) {
    const entry = reducerSnapshotFor(value);
    const key = hex(entry.operationId);
    const existing = byId.get(key);
    if (existing === undefined) {
      byId.set(key, entry);
      continue;
    }
    // Two entries with one OperationId must be the same operation; the ID is a
    // hash of the complete canonical encoding.
    if (!bytesEqual(existing.operationBytes, entry.operationBytes))
      throw new Error(
        "coreReduce: two different operations share one OperationId",
      );
  }
  return [...byId.values()].sort((a, b) =>
    compareBytes(a.operationId, b.operationId),
  );
};

export const mergeOperationCandidateSets = (
  left: readonly OuterValidatedIdentifiedOperationV1[],
  right: readonly OuterValidatedIdentifiedOperationV1[],
): OuterValidatedIdentifiedOperationV1[] =>
  mergeReducerSnapshots(left, right).map((entry) => entry.source);

const authorWindowKey = (operation: AuthenticatedRoomOperationV1): string =>
  `${hex(operation.authorEpochEd25519Key)}:${operation.logicalWindow.toString()}`;

interface AuthorWindowClassification {
  readonly faults: CoreFaultV1[];
  readonly faultedAuthorWindows: ReadonlySet<string>;
}

/**
 * One deterministic author fault classifier shared by current and
 * dependency-evidence groups. Nested payload bytes are intentionally absent
 * from this decision.
 */
const classifyAuthorWindows = (
  byAuthorWindow: ReadonlyMap<string, readonly ReducerOperationSnapshot[]>,
  roomPolicy: OperationValidationContext["roomPolicy"],
): AuthorWindowClassification => {
  const maxPerAuthorWindow =
    roomPolicy.protocolLimits.maxOperationsPerAuthorWindow;
  const faults: CoreFaultV1[] = [];
  const faultedAuthorWindows = new Set<string>();

  for (const [key, group] of byAuthorWindow) {
    if (group.length === 0) continue;
    const bySequence = new Map<string, ReducerOperationSnapshot[]>();
    for (const entry of group) {
      const sequenceKey = entry.operation.authorSequence.toString();
      const slot = bySequence.get(sequenceKey);
      if (slot === undefined) bySequence.set(sequenceKey, [entry]);
      else slot.push(entry);
    }

    const forkProofs: {
      readonly sequence: bigint;
      readonly operationIds: readonly [Uint8Array, Uint8Array];
    }[] = [];
    for (const [sequence, slot] of bySequence) {
      if (slot.length < 2) continue;
      const ids = sortBytes(slot.map((entry) => entry.operationId));
      forkProofs.push({
        sequence: BigInt(sequence),
        operationIds: [ids[0], ids[1]],
      });
    }
    forkProofs.sort((left, right) =>
      left.sequence < right.sequence
        ? -1
        : left.sequence > right.sequence
          ? 1
          : 0,
    );

    const overquota = group.length > maxPerAuthorWindow;
    const authorityFloor = roomPolicy.admissionFloor;
    const authoredByAuthority =
      authorityFloor.mode === "authority-grant" &&
      bytesEqual(
        group[0].operation.authorEpochEd25519Key,
        authorityFloor.authorityEd25519PublicKey,
      );
    const nonRevocationInAuthorityChain =
      authoredByAuthority &&
      group.some((entry) => entry.operation.kind !== "ADMISSION_REVOKE");

    if (forkProofs.length === 0 && !overquota && !nonRevocationInAuthorityChain)
      continue;

    faultedAuthorWindows.add(key);
    /*
     * Exact combined-fault proof precedence:
     *   1. overquota: canonical lowest quota+1 IDs;
     *   2. fork: lowest sequence's two lowest IDs;
     *   3. authority-chain violation: lowest offending ID.
     * This both freezes byte output and keeps every proof within its u16 bound.
     */
    const proofOperationIds = overquota
      ? sortBytes(group.map((entry) => entry.operationId)).slice(
          0,
          maxPerAuthorWindow + 1,
        )
      : forkProofs.length > 0
        ? sortBytes(forkProofs[0].operationIds)
        : sortBytes(
            group
              .filter((entry) => entry.operation.kind !== "ADMISSION_REVOKE")
              .map((entry) => entry.operationId),
          ).slice(0, 1);

    faults.push({
      kind: "author-fork-or-overquota",
      authorEpochEd25519Key: Uint8Array.from(
        group[0].operation.authorEpochEd25519Key,
      ),
      logicalWindow: group[0].operation.logicalWindow,
      proofOperationIds: proofOperationIds.map((operationId) =>
        Uint8Array.from(operationId),
      ),
    });
  }

  return { faults, faultedAuthorWindows };
};

const validatePayloadsInAuthorWindows = async (
  byAuthorWindow: ReadonlyMap<string, readonly ReducerOperationSnapshot[]>,
  faultedAuthorWindows: ReadonlySet<string>,
  roomContextId: Uint8Array,
  roomPolicy: OperationValidationContext["roomPolicy"],
  module?: LibCrypto,
): Promise<PayloadValidatedReducerSnapshot[]> => {
  const payloadValidated: PayloadValidatedReducerSnapshot[] = [];
  for (const [key, group] of byAuthorWindow) {
    if (faultedAuthorWindows.has(key)) continue;
    for (const entry of group) {
      let payload: DecodedOperationPayloadV1;
      if (entry.operation.kind === "PAIR_STEP") {
        if (entry.pairEnvelope === null)
          throw new Error(
            "coreReduce: outer-validated PAIR_STEP lost its envelope",
          );
        payload = { kind: "PAIR_STEP", value: entry.pairEnvelope };
      } else {
        if (entry.pairEnvelope !== null)
          throw new Error(
            "coreReduce: non-pair candidate carried a pair envelope",
          );
        try {
          payload = await decodeAndValidateNonPairOperationPayload(
            entry.operation,
            { roomContextId, roomPolicy },
            module,
          );
        } catch (error) {
          if (error instanceof OperationPayloadValidationError) continue;
          throw error;
        }
      }
      payloadValidated.push({ ...entry, payload });
    }
  }
  return payloadValidated.sort((left, right) =>
    compareBytes(left.operationId, right.operationId),
  );
};

const payloadsByAuthorWindow = (
  entries: readonly PayloadValidatedReducerSnapshot[],
): Map<string, PayloadValidatedReducerSnapshot[]> => {
  const groups = new Map<string, PayloadValidatedReducerSnapshot[]>();
  for (const entry of entries) {
    const key = authorWindowKey(entry.operation);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [entry]);
    else group.push(entry);
  }
  return groups;
};

const proveAuthorChains = (
  groups: ReadonlyMap<string, readonly PayloadValidatedReducerSnapshot[]>,
  provenChainMembers: Set<string> = new Set<string>(),
): Set<string> => {
  for (const group of groups.values()) {
    const bySequence = new Map<string, PayloadValidatedReducerSnapshot>();
    for (const entry of group)
      bySequence.set(entry.operation.authorSequence.toString(), entry);

    let expectedPredecessor: Uint8Array | null = null;
    for (let sequence = 0n; ; sequence++) {
      const entry = bySequence.get(sequence.toString());
      if (entry === undefined) break;
      const declared = entry.operation.previousAuthorOperationId;
      if (expectedPredecessor === null) {
        if (declared !== null) break;
      } else if (
        declared === null ||
        !bytesEqual(declared, expectedPredecessor)
      )
        break;
      provenChainMembers.add(hex(entry.operationId));
      expectedPredecessor = entry.operationId;
    }
  }
  return provenChainMembers;
};

/**
 * Recover the exact authenticated prefix that made one active pair candidate
 * chain-proven. This is derived from the reducer's sole author-window
 * partition; the pair layer never reconstructs or guesses it from public
 * state projections.
 */
const exactAuthorChainPrefixThrough = (
  candidate: PayloadValidatedReducerSnapshot,
  groups: ReadonlyMap<string, readonly PayloadValidatedReducerSnapshot[]>,
  provenChainMembers: ReadonlySet<string>,
): PairAuthorChainPrefixSnapshot[] => {
  const group = groups.get(authorWindowKey(candidate.operation));
  if (group === undefined)
    throw new Error(
      "coreReduce: active pair candidate lost its author-window evidence",
    );

  const ordered = [...group]
    .filter(
      (entry) =>
        entry.operation.authorSequence <= candidate.operation.authorSequence,
    )
    .sort((left, right) =>
      left.operation.authorSequence < right.operation.authorSequence
        ? -1
        : left.operation.authorSequence > right.operation.authorSequence
          ? 1
          : compareBytes(left.operationId, right.operationId),
    );

  const prefix: PairAuthorChainPrefixSnapshot[] = [];
  let expectedSequence = 0n;
  let expectedPredecessor: Uint8Array | null = null;
  for (const entry of ordered) {
    if (
      entry.operation.authorSequence !== expectedSequence ||
      !provenChainMembers.has(hex(entry.operationId))
    )
      throw new Error(
        "coreReduce: active pair candidate has an incomplete author prefix",
      );
    const declaredPredecessor = entry.operation.previousAuthorOperationId;
    if (
      (expectedPredecessor === null && declaredPredecessor !== null) ||
      (expectedPredecessor !== null &&
        (declaredPredecessor === null ||
          !bytesEqual(declaredPredecessor, expectedPredecessor)))
    )
      throw new Error(
        "coreReduce: active pair candidate has an inconsistent author prefix",
      );

    prefix.push({
      operationId: Uint8Array.from(entry.operationId),
      operationBytes: Uint8Array.from(entry.operationBytes),
    });
    expectedPredecessor = entry.operationId;
    expectedSequence += 1n;
  }

  if (
    prefix.length === 0 ||
    expectedSequence !== candidate.operation.authorSequence + 1n ||
    !bytesEqual(prefix[prefix.length - 1].operationId, candidate.operationId)
  )
    throw new Error(
      "coreReduce: active pair candidate author prefix does not end at candidate",
    );
  return prefix;
};

const activePayloadCandidatesAt = (
  entries: readonly PayloadValidatedReducerSnapshot[],
  provenChainMembers: ReadonlySet<string>,
  referenceWindow: bigint,
  skew: bigint,
): PayloadValidatedReducerSnapshot[] =>
  entries.filter(
    (entry) =>
      provenChainMembers.has(hex(entry.operationId)) &&
      outerActiveAt(entry.operation, referenceWindow, skew),
  );

/**
 * Exact deterministic `CoreReduce`.
 *
 * Every decision is a function of privately snapshotted operation bytes and
 * one immutable room context/reference window. Fork and overquota
 * classification precedes payload reduction and is arrival-independent.
 */
export const coreReduce = async (
  operations: readonly OuterValidatedIdentifiedOperationV1[],
  context: OperationValidationContext,
  module?: LibCrypto,
): Promise<CoreRoomStateV1> => {
  // Snapshot every caller-owned container synchronously before the first
  // await. A caller cannot change set membership while confirmation hashing
  // yields to WebCrypto.
  const operationInputs = [...operations];
  const privateContext = snapshotOperationValidationContext(context);
  const roomContextIdBytes = Uint8Array.from(privateContext.roomContextId);
  const confirmationBytes = Uint8Array.from(
    privateContext.roomContextConfirmation,
  );
  const roomPolicyBytes = encodeRoomPolicyV4(privateContext.roomPolicy);
  const roomPolicy = decodeRoomPolicyV4(roomPolicyBytes);
  const referenceWindow = privateContext.referenceWindow;
  if (
    !bytesEqual(
      await roomContextConfirmation(roomContextIdBytes),
      confirmationBytes,
    )
  )
    throw new Error(
      "coreReduce: context has an inconsistent RoomContextId confirmation",
    );

  // Deduplicate first. The author quota counts *distinct* candidates, so a
  // carrier that redelivers one operation must not be able to manufacture an
  // overquota fault against an honest author — at-least-once delivery is part
  // of the carrier contract, not evidence of misbehavior.
  const sorted = mergeReducerSnapshots(operationInputs, []);
  for (const entry of sorted) {
    if (
      !bytesEqual(entry.roomContextId, roomContextIdBytes) ||
      !bytesEqual(entry.roomContextConfirmation, confirmationBytes) ||
      !bytesEqual(entry.roomPolicyBytes, roomPolicyBytes)
    )
      throw new Error(
        "coreReduce: validated operation belongs to another room or policy",
      );
  }

  const skew = BigInt(roomPolicy.protocolLimits.maxClockSkewWindows);
  /*
   * Future custody cannot affect current core state. Expired operations enter
   * the author partition only as bounded prefix evidence for a currently live
   * later sequence, or as retained pinned-authority fault evidence through the
   * exact credential horizon.
   */
  const rawByAuthorWindow = new Map<string, ReducerOperationSnapshot[]>();
  for (const entry of sorted) {
    if (entry.operation.logicalWindow > referenceWindow) continue;
    const key = authorWindowKey(entry.operation);
    const group = rawByAuthorWindow.get(key);
    if (group === undefined) rawByAuthorWindow.set(key, [entry]);
    else group.push(entry);
  }

  const byAuthorWindow = new Map<string, ReducerOperationSnapshot[]>();
  for (const [key, group] of rawByAuthorWindow) {
    const live = group.filter((entry) =>
      outerActiveAt(entry.operation, referenceWindow, skew),
    );
    let maximumLiveSequence: bigint | null = null;
    for (const entry of live)
      if (
        maximumLiveSequence === null ||
        entry.operation.authorSequence > maximumLiveSequence
      )
        maximumLiveSequence = entry.operation.authorSequence;

    const authority = roomPolicy.admissionFloor;
    const authoredByAuthority =
      authority.mode === "authority-grant" &&
      bytesEqual(
        group[0].operation.authorEpochEd25519Key,
        authority.authorityEd25519PublicKey,
      );
    const authorityFaultHorizon =
      authority.mode === "authority-grant"
        ? checkedAddU64(
            checkedAddU64(
              checkedAddU64(
                group[0].operation.logicalWindow,
                BigInt(roomPolicy.protocolLimits.maxFutureLogicalWindows),
              ),
              BigInt(authority.maxAuthorityCredentialLifetimeWindows),
            ),
            skew,
          )
        : null;

    const current = group.filter((entry) => {
      if (outerActiveAt(entry.operation, referenceWindow, skew)) return true;
      if (
        maximumLiveSequence !== null &&
        entry.operation.authorSequence <= maximumLiveSequence &&
        referenceWindow <= entry.evidenceValidThroughWindow
      )
        return true;
      return (
        authoredByAuthority &&
        authorityFaultHorizon !== null &&
        referenceWindow <= authorityFaultHorizon
      );
    });
    if (current.length !== 0) byAuthorWindow.set(key, current);
  }

  // Every distinct current outer candidate counts toward author quota,
  // including one whose nested payload will fail below.
  const initialAuthorClassification = classifyAuthorWindows(
    byAuthorWindow,
    roomPolicy,
  );
  let faults: CoreFaultV1[] = [...initialAuthorClassification.faults];
  let faultedAuthorWindows = new Set(
    initialAuthorClassification.faultedAuthorWindows,
  );

  /*
   * Only now perform nested payload work. Faulted/overquota author windows are
   * excluded without verifying a permit, revoke, descriptor, or route
   * signature, which bounds attacker-selected expensive work per author.
   */
  let payloadValidated = await validatePayloadsInAuthorWindows(
    byAuthorWindow,
    faultedAuthorWindows,
    roomContextIdBytes,
    roomPolicy,
    module,
  );

  let payloadValidatedByAuthorWindow = payloadsByAuthorWindow(payloadValidated);

  // An operation is eligible only when its author chain is proven contiguous
  // back to sequence zero of its window, each link naming its exact
  // predecessor. Without this, an author could publish sequence 5 alone and
  // have it reduce as though 0..4 existed.
  let provenChainMembers = proveAuthorChains(payloadValidatedByAuthorWindow);

  let candidateActive = activePayloadCandidatesAt(
    payloadValidated,
    provenChainMembers,
    referenceWindow,
    skew,
  );

  /*
   * A live, intrinsically valid LEAVE may depend on a presence from another
   * author window whose outer lifetime has ended. Promote the exact referenced
   * presence's complete semantic slot plus the prefixes needed to prove those
   * branches, then rerun the same author/payload/chain pipeline. Invalid LEAVE
   * payloads never enter `candidateActive`, so they cannot make unrelated
   * historical evidence affect current state.
   *
   * The loop is monotone over the finite validated candidate set. It matters
   * only when adding one dependency prefix proves another already-present
   * LEAVE chain; ordinary cases complete in one pass.
   */
  const sortedByOperationId = new Map(
    sorted.map((entry) => [hex(entry.operationId), entry] as const),
  );
  const requestedPresenceSlots = new Set<string>();
  const canonicalHistoricalPresenceCandidates = new Map<string, boolean>();
  const isCanonicalHistoricalPresenceCandidate = async (
    entry: ReducerOperationSnapshot,
  ): Promise<boolean> => {
    const id = hex(entry.operationId);
    const cached = canonicalHistoricalPresenceCandidates.get(id);
    if (cached !== undefined) return cached;

    let valid = false;
    if (
      entry.operation.kind === "PRESENCE" &&
      referenceWindow <= entry.evidenceValidThroughWindow
    ) {
      try {
        const presence = decodePresenceV1(entry.operation.fixedPayload);
        valid =
          presence.core.version === 1 &&
          entry.operation.logicalWindow <=
            presence.core.validThroughLogicalWindow &&
          presence.core.validThroughLogicalWindow <=
            presence.core.receiverKeyValidThroughLogicalWindow &&
          presence.core.receiverKeyValidThroughLogicalWindow <=
            entry.operation.expiresAfterWindow &&
          bytesEqual(
            entry.operation.semanticSlot,
            await presenceSemanticSlot(
              entry.operation.authorEpochEd25519Key,
              entry.operation.logicalWindow,
              presence.core.presenceNonce,
            ),
          );
      } catch {
        valid = false;
      }
    }
    canonicalHistoricalPresenceCandidates.set(id, valid);
    return valid;
  };
  for (;;) {
    let learnedSlot = false;
    for (const entry of candidateActive) {
      if (entry.payload.kind !== "LEAVE") continue;
      const referenced = sortedByOperationId.get(
        hex(entry.payload.value.presenceOperationId),
      );
      if (
        referenced === undefined ||
        referenced.operation.kind !== "PRESENCE" ||
        !bytesEqual(
          entry.operation.authorEpochEd25519Key,
          referenced.operation.authorEpochEd25519Key,
        ) ||
        referenced.operation.logicalWindow > referenceWindow ||
        referenceWindow > referenced.evidenceValidThroughWindow
      )
        continue;
      let referencedPresence: PresenceV1;
      try {
        referencedPresence = decodePresenceV1(
          referenced.operation.fixedPayload,
        );
      } catch {
        continue;
      }
      if (
        referenced.operation.logicalWindow >
          entry.payload.value.effectiveLogicalWindow ||
        entry.payload.value.effectiveLogicalWindow >
          referencedPresence.core.validThroughLogicalWindow ||
        entry.operation.expiresAfterWindow <
          referencedPresence.core.validThroughLogicalWindow ||
        referencedPresence.core.validThroughLogicalWindow >
          referencedPresence.core.receiverKeyValidThroughLogicalWindow ||
        referencedPresence.core.receiverKeyValidThroughLogicalWindow >
          referenced.operation.expiresAfterWindow ||
        !bytesEqual(
          referenced.operation.semanticSlot,
          await presenceSemanticSlot(
            referenced.operation.authorEpochEd25519Key,
            referenced.operation.logicalWindow,
            referencedPresence.core.presenceNonce,
          ),
        )
      )
        continue;
      const slot = hex(referenced.operation.semanticSlot);
      if (!requestedPresenceSlots.has(slot)) {
        requestedPresenceSlots.add(slot);
        learnedSlot = true;
      }
    }

    let addedCandidate = false;
    for (const [key, group] of rawByAuthorWindow) {
      const direct: ReducerOperationSnapshot[] = [];
      for (const entry of group) {
        if (
          entry.operation.kind === "PRESENCE" &&
          requestedPresenceSlots.has(hex(entry.operation.semanticSlot)) &&
          (await isCanonicalHistoricalPresenceCandidate(entry))
        )
          direct.push(entry);
      }
      if (direct.length === 0) continue;

      let maximumDirectSequence = direct[0].operation.authorSequence;
      for (const entry of direct)
        if (entry.operation.authorSequence > maximumDirectSequence)
          maximumDirectSequence = entry.operation.authorSequence;
      const directOperationIds = new Set(
        direct.map((entry) => hex(entry.operationId)),
      );

      const existing = byAuthorWindow.get(key) ?? [];
      const byId = new Map(
        existing.map((entry) => [hex(entry.operationId), entry] as const),
      );
      for (const entry of group) {
        const id = hex(entry.operationId);
        const isDirect = directOperationIds.has(id);
        const isRequiredPrefix =
          entry.operation.authorSequence <= maximumDirectSequence;
        if (
          !isDirect &&
          (!isRequiredPrefix ||
            referenceWindow > entry.evidenceValidThroughWindow)
        )
          continue;
        if (!byId.has(id)) {
          byId.set(id, entry);
          addedCandidate = true;
        }
      }
      byAuthorWindow.set(
        key,
        [...byId.values()].sort((left, right) =>
          compareBytes(left.operationId, right.operationId),
        ),
      );
    }

    if (!addedCandidate) {
      if (!learnedSlot) break;
      // A newly learned slot may already have been fully present in the
      // current groups; one more scan proves the fixed point.
      continue;
    }

    const classification = classifyAuthorWindows(byAuthorWindow, roomPolicy);
    faults = [...classification.faults];
    faultedAuthorWindows = new Set(classification.faultedAuthorWindows);
    payloadValidated = await validatePayloadsInAuthorWindows(
      byAuthorWindow,
      faultedAuthorWindows,
      roomContextIdBytes,
      roomPolicy,
      module,
    );
    payloadValidatedByAuthorWindow = payloadsByAuthorWindow(payloadValidated);
    provenChainMembers = proveAuthorChains(payloadValidatedByAuthorWindow);
    candidateActive = activePayloadCandidatesAt(
      payloadValidated,
      provenChainMembers,
      referenceWindow,
      skew,
    );
  }

  const semanticForkedOperationIds = new Set<string>();
  const recordSemanticSlotForks = (
    groups: ReadonlyMap<string, readonly PayloadValidatedReducerSnapshot[]>,
  ): void => {
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      const operationIds = sortBytes(group.map((entry) => entry.operationId));
      for (const operationId of operationIds)
        semanticForkedOperationIds.add(hex(operationId));
      faults.push({
        kind: "presence-or-leave-fork",
        semanticSlot: Uint8Array.from(group[0].operation.semanticSlot),
        proofOperationIds: operationIds
          .slice(0, 2)
          .map((operationId) => Uint8Array.from(operationId)),
      });
    }
  };

  /*
   * Presence subjects fork before leaves are evaluated. Include current roster
   * candidates and exact presences referenced by a current LEAVE; unrelated
   * expired prefix evidence cannot manufacture a current semantic fault.
   */
  const candidateActiveIds = new Set(
    candidateActive.map((entry) => hex(entry.operationId)),
  );
  const byOperationId = new Map(
    payloadValidated.map((entry) => [hex(entry.operationId), entry] as const),
  );
  /*
   * Prequalify exact LEAVE dependencies before they can make an otherwise
   * inert historical presence slot relevant to semantic-fork detection. The
   * fork result itself is necessarily checked later, after those slots have
   * been grouped.
   */
  const prequalifiedLeaveDependencies = new Map<
    string,
    PayloadValidatedReducerSnapshot
  >();
  const referencedPresenceSlots = new Set<string>();
  for (const entry of candidateActive) {
    if (entry.payload.kind !== "LEAVE") continue;
    const referenced = byOperationId.get(
      hex(entry.payload.value.presenceOperationId),
    );
    if (
      referenced === undefined ||
      referenced.payload.kind !== "PRESENCE" ||
      !provenChainMembers.has(hex(referenced.operationId)) ||
      !bytesEqual(
        entry.operation.authorEpochEd25519Key,
        referenced.operation.authorEpochEd25519Key,
      ) ||
      referenced.operation.logicalWindow >
        entry.payload.value.effectiveLogicalWindow ||
      entry.payload.value.effectiveLogicalWindow >
        referenced.payload.value.core.validThroughLogicalWindow ||
      entry.operation.expiresAfterWindow <
        referenced.payload.value.core.validThroughLogicalWindow
    )
      continue;
    prequalifiedLeaveDependencies.set(hex(entry.operationId), referenced);
    referencedPresenceSlots.add(hex(referenced.operation.semanticSlot));
  }

  const byPresenceSlot = new Map<string, PayloadValidatedReducerSnapshot[]>();
  for (const entry of payloadValidated) {
    if (
      entry.payload.kind !== "PRESENCE" ||
      !provenChainMembers.has(hex(entry.operationId)) ||
      (!candidateActiveIds.has(hex(entry.operationId)) &&
        !referencedPresenceSlots.has(hex(entry.operation.semanticSlot)))
    )
      continue;
    const key = hex(entry.operation.semanticSlot);
    const group = byPresenceSlot.get(key);
    if (group === undefined) byPresenceSlot.set(key, [entry]);
    else group.push(entry);
  }
  recordSemanticSlotForks(byPresenceSlot);

  /*
   * Resolve LEAVE's exact dependency before grouping leave semantic slots. A
   * missing, wrong-kind, wrong-author, invalid-at-effective, or forked
   * presence suspends only that leave and cannot poison a valid leave slot.
   */
  const validLeaveIds = new Set<string>();
  const byLeaveSlot = new Map<string, PayloadValidatedReducerSnapshot[]>();
  for (const entry of candidateActive) {
    if (entry.payload.kind !== "LEAVE") continue;
    const referenced = prequalifiedLeaveDependencies.get(
      hex(entry.operationId),
    );
    if (
      referenced === undefined ||
      semanticForkedOperationIds.has(hex(referenced.operationId))
    )
      continue;
    validLeaveIds.add(hex(entry.operationId));
    const slot = hex(entry.operation.semanticSlot);
    const group = byLeaveSlot.get(slot);
    if (group === undefined) byLeaveSlot.set(slot, [entry]);
    else group.push(entry);
  }
  recordSemanticSlotForks(byLeaveSlot);

  /*
   * A semantic-forked operation cannot remain the author-chain proof for a
   * later sequence. Propagate exclusion through that same contiguous chain;
   * explicit LEAVE dependencies were handled above.
   */
  for (const group of payloadValidatedByAuthorWindow.values()) {
    let forkedPrefixSeen = false;
    const ordered = [...group].sort((left, right) =>
      left.operation.authorSequence < right.operation.authorSequence
        ? -1
        : left.operation.authorSequence > right.operation.authorSequence
          ? 1
          : 0,
    );
    for (const entry of ordered) {
      const id = hex(entry.operationId);
      if (semanticForkedOperationIds.has(id)) forkedPrefixSeen = true;
      else if (forkedPrefixSeen) semanticForkedOperationIds.add(id);
    }
  }

  const active: PayloadValidatedReducerSnapshot[] = candidateActive
    .filter((entry) => {
      const id = hex(entry.operationId);
      if (semanticForkedOperationIds.has(id)) return false;
      if (entry.payload.kind !== "LEAVE") return true;
      const referenced = byOperationId.get(
        hex(entry.payload.value.presenceOperationId),
      );
      return (
        validLeaveIds.has(id) &&
        referenced !== undefined &&
        !semanticForkedOperationIds.has(hex(referenced.operationId))
      );
    })
    .sort((left, right) => compareBytes(left.operationId, right.operationId));

  const privateActiveOperationIds = active.map((entry) => entry.operationId);
  const privateActivePairOuterOperationIds = active
    .filter((entry) => entry.operation.kind === "PAIR_STEP")
    .map((entry) => entry.operationId);

  const operationsDigest = await coreOperationSetDigest(
    privateActiveOperationIds,
  );

  const effectiveLeaveEntries = active.filter(
    (entry) =>
      entry.payload.kind === "LEAVE" &&
      entry.payload.value.effectiveLogicalWindow <= referenceWindow,
  );
  const leftPresenceOperationIds = new Set(
    effectiveLeaveEntries.map((entry) => {
      if (entry.payload.kind !== "LEAVE")
        throw new Error("coreReduce: impossible LEAVE narrowing failure");
      return hex(entry.payload.value.presenceOperationId);
    }),
  );

  const observedPresences: CorePresenceFactV1[] = [];
  for (const entry of active) {
    if (entry.payload.kind !== "PRESENCE") continue;
    if (
      referenceWindow > entry.payload.value.core.validThroughLogicalWindow ||
      leftPresenceOperationIds.has(hex(entry.operationId))
    )
      continue;
    observedPresences.push({
      presenceOperationId: Uint8Array.from(entry.operationId),
      authorEpochEd25519Key: Uint8Array.from(
        entry.operation.authorEpochEd25519Key,
      ),
      logicalWindow: entry.operation.logicalWindow,
      presence: decodePresenceV1(encodePresenceV1(entry.payload.value)),
    });
  }

  const storeCatalogFacts: CoreStoreFactV1[] = [];
  for (const entry of active) {
    if (entry.payload.kind !== "STORE_HINT") continue;
    const hint: StoreHintOperationV1 = entry.payload.value;
    if (referenceWindow > hint.hintExpiresAfterLogicalWindow) continue;
    const hintCopy = decodeStoreHintOperationV1(
      encodeStoreHintOperationV1(hint),
    );
    storeCatalogFacts.push({
      storeId: await storeId(hint.descriptor.storeIdentityEd25519Key),
      descriptorGeneration: hint.descriptor.descriptorGeneration,
      descriptorHash: await descriptorHash(hint.descriptor),
      sourceOperationId: Uint8Array.from(entry.operationId),
      descriptor: hintCopy.descriptor,
      routes: hintCopy.routes,
      hintValidThroughLogicalWindow: hint.hintExpiresAfterLogicalWindow,
    });
  }
  storeCatalogFacts.sort(
    (left, right) =>
      compareBytes(left.storeId, right.storeId) ||
      (left.descriptorGeneration < right.descriptorGeneration
        ? -1
        : left.descriptorGeneration > right.descriptorGeneration
          ? 1
          : 0) ||
      compareBytes(left.descriptorHash, right.descriptorHash) ||
      compareBytes(left.sourceOperationId, right.sourceOperationId),
  );

  /*
   * Only the greatest live generation for one store can activate. Preserve
   * every exact source fact, but emit one deterministic fault when that
   * generation has multiple descriptor hashes.
   */
  const storeFactsById = new Map<string, CoreStoreFactV1[]>();
  for (const fact of storeCatalogFacts) {
    const key = hex(fact.storeId);
    const group = storeFactsById.get(key);
    if (group === undefined) storeFactsById.set(key, [fact]);
    else group.push(fact);
  }
  for (const group of storeFactsById.values()) {
    let maximumGeneration = group[0].descriptorGeneration;
    for (const fact of group)
      if (fact.descriptorGeneration > maximumGeneration)
        maximumGeneration = fact.descriptorGeneration;
    const hashesByHex = new Map<string, Uint8Array>();
    for (const fact of group) {
      if (fact.descriptorGeneration !== maximumGeneration) continue;
      hashesByHex.set(hex(fact.descriptorHash), fact.descriptorHash);
    }
    if (hashesByHex.size < 2) continue;
    const hashes = sortBytes([...hashesByHex.values()]);
    faults.push({
      kind: "store-generation-fork",
      storeId: Uint8Array.from(group[0].storeId),
      descriptorGeneration: maximumGeneration,
      descriptorHashes: [
        Uint8Array.from(hashes[0]),
        Uint8Array.from(hashes[1]),
      ],
    });
  }

  const revocationFloors: CoreRevocationFloorV1[] = [];
  for (const entry of active) {
    if (entry.payload.kind !== "ADMISSION_REVOKE") continue;
    const revoke: AdmissionRevokeV1 = entry.payload.value;
    if (
      revoke.effectiveLogicalWindow > referenceWindow ||
      referenceWindow > revoke.expiresAfterLogicalWindow
    )
      continue;
    revocationFloors.push({
      stableIdentityCommitment: Uint8Array.from(
        revoke.stableIdentityCommitment,
      ),
      minimumAcceptedGeneration: revoke.minimumAcceptedGeneration,
      effectiveLogicalWindow: revoke.effectiveLogicalWindow,
      validThroughLogicalWindow: revoke.expiresAfterLogicalWindow,
      revokeOperationId: Uint8Array.from(entry.operationId),
    });
  }
  revocationFloors.sort(
    (left, right) =>
      compareBytes(
        left.stableIdentityCommitment,
        right.stableIdentityCommitment,
      ) ||
      (left.minimumAcceptedGeneration < right.minimumAcceptedGeneration
        ? -1
        : left.minimumAcceptedGeneration > right.minimumAcceptedGeneration
          ? 1
          : 0) ||
      (left.effectiveLogicalWindow < right.effectiveLogicalWindow
        ? -1
        : left.effectiveLogicalWindow > right.effectiveLogicalWindow
          ? 1
          : 0) ||
      (left.validThroughLogicalWindow < right.validThroughLogicalWindow
        ? -1
        : left.validThroughLogicalWindow > right.validThroughLogicalWindow
          ? 1
          : 0) ||
      compareBytes(left.revokeOperationId, right.revokeOperationId),
  );

  faults.sort((left, right) => {
    const leftKindOrder = coreFaultKindOrder.get(left.kind);
    const rightKindOrder = coreFaultKindOrder.get(right.kind);
    if (leftKindOrder === undefined || rightKindOrder === undefined)
      throw new Error("coreReduce: fault kind is absent from its schema");
    const kindOrder = leftKindOrder - rightKindOrder;
    if (kindOrder !== 0) return kindOrder;
    if (
      left.kind === "author-fork-or-overquota" &&
      right.kind === "author-fork-or-overquota"
    )
      return (
        compareBytes(left.authorEpochEd25519Key, right.authorEpochEd25519Key) ||
        (left.logicalWindow < right.logicalWindow
          ? -1
          : left.logicalWindow > right.logicalWindow
            ? 1
            : 0)
      );
    if (
      left.kind === "presence-or-leave-fork" &&
      right.kind === "presence-or-leave-fork"
    )
      return compareBytes(left.semanticSlot, right.semanticSlot);
    if (
      left.kind === "store-generation-fork" &&
      right.kind === "store-generation-fork"
    )
      return (
        compareBytes(left.storeId, right.storeId) ||
        (left.descriptorGeneration < right.descriptorGeneration
          ? -1
          : left.descriptorGeneration > right.descriptorGeneration
            ? 1
            : 0)
      );
    throw new Error("coreReduce: impossible fault-kind comparison");
  });

  const state: CoreRoomStateV1 = {
    version: 1,
    referenceWindow,
    roomCapacityState:
      observedPresences.length > roomPolicy.maxRoomMembers
        ? "overcapacity"
        : "within-policy",
    activeOperationIds: privateActiveOperationIds.map((operationId) =>
      Uint8Array.from(operationId),
    ),
    observedPresences,
    effectiveLeaveOperationIds: effectiveLeaveEntries.map((entry) =>
      Uint8Array.from(entry.operationId),
    ),
    storeCatalogFacts,
    revocationFloors,
    activePairOuterOperationIds: privateActivePairOuterOperationIds.map(
      (operationId) => Uint8Array.from(operationId),
    ),
    faults,
    operationsDigest,
  };
  // The output codec is a final executable assertion that every projection is
  // in its one schema-defined order and has no duplicate canonical values.
  const stateBytes = await encodeCoreRoomStateV1(state);
  const reducedState = decodeCoreRoomStateCanonical(stateBytes);
  reducedRoomStates.set(reducedState, {
    stateBytes: Uint8Array.from(stateBytes),
    roomContextId: Uint8Array.from(roomContextIdBytes),
    roomPolicyBytes: Uint8Array.from(roomPolicyBytes),
    activePairOperations: new Map(
      active
        .filter((entry) => entry.operation.kind === "PAIR_STEP")
        .map(
          (entry) =>
            [
              hex(entry.operationId),
              {
                operationId: Uint8Array.from(entry.operationId),
                operationBytes: Uint8Array.from(entry.operationBytes),
                evidenceValidThroughWindow: entry.evidenceValidThroughWindow,
                authorChainPrefix: exactAuthorChainPrefixThrough(
                  entry,
                  payloadValidatedByAuthorWindow,
                  provenChainMembers,
                ),
              },
            ] as const,
        ),
    ),
  });
  return reducedState;
};
