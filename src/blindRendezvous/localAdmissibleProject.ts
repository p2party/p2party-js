/**
 * Pure local-admissible projection semantics.
 *
 * This module computes the diagnostic `LocalAdmissibleStateV1` from complete,
 * deeply owned inputs. It deliberately does not mint topology, reservation,
 * admission, persistence, or publication authority. The effectful HELLO path
 * must later wrap this kernel behind an opaque handle tied by object identity
 * to one genuine `TrustedAdmissionSnapshotV1` and its exact planner/CAS row.
 *
 * Authority-mode projection remains unavailable until the protected
 * non-omission custody constructor is implemented. There is no fallback to
 * address-book or open eligibility.
 */

import { snapshotByteInput } from "../cryptography/byteInput";
import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { validateAndCopyFrontendRoomControlsV1 } from "./admissionPolicy";
import {
  coreOperationSetDigest,
  localPeerId,
  observedRosterHash,
  openPresenceRank,
  addressBookPresenceRank,
  stableIdentityCommitment,
} from "./derivations";
import { decodeCoreRoomStateV1, encodeCoreRoomStateV1 } from "./coreReduce";
import {
  OperationPayloadValidationError,
  validateCorePresenceFactOwnershipV1,
} from "./operationPayload";
import {
  assertPlannerStateRoomBindingV1,
  validateAndCopyPlannerAndExplicitStateV1,
} from "./plannerState";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";
import { localPresenceOwnershipV1Schema } from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { FrontendRoomControlsV1 } from "./admissionPolicy";
import type { CorePresenceFactV1, CoreRoomStateV1 } from "./coreReduce";
import type { PlannerAndExplicitStateV1 } from "./plannerState";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U64_MAX = 0xffffffffffffffffn;

export type LocalPresenceEligibilityV1 =
  "open" | "local-address-book-proved" | "authority-permit-proved";

export interface LocalAdmissiblePeerV1 {
  readonly localPeerId: string;
  readonly presenceOperationId: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly rank: Uint8Array;
  readonly eligibility: LocalPresenceEligibilityV1;
  readonly desiredEdge: boolean;
}

export interface LocalAdmissibleStateV1 {
  readonly version: 1;
  readonly referenceWindow: bigint;
  readonly coreOperationsDigest: Uint8Array;
  readonly localPresenceOperationId: Uint8Array | null;
  readonly localPresenceRank: Uint8Array | null;
  readonly peers: readonly LocalAdmissiblePeerV1[];
  readonly requestedExplicitPeerIds: readonly string[];
}

export type LocalAdmissibleProjectStatusV1 =
  | "ready"
  | "policy-unavailable"
  | "projection-resource-overcapacity"
  | "no-unambiguous-local-presence";

export type LocalAdmissiblePlannerStatusV1 =
  "ready" | "unavailable" | "full-mesh-overcapacity";

/**
 * Structural inputs for the pure semantic kernel.
 *
 * `maxPairLedgerEntriesPerRoom` is needed only to validate the captured
 * planner row. A future trusted wrapper pins it from the room resource policy;
 * accepting this structural object does not establish that provenance.
 */
export interface LocalAdmissibleProjectSemanticInputV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly coreRoomState: CoreRoomStateV1;
  readonly frontendControls: FrontendRoomControlsV1 | null;
  /**
   * Structural premise only. The trusted wrapper must replace this with a
   * process-local brand that binds every exact owned Core fact and OperationId
   * to one of these stable keys, a verified stable-ownership signature, and
   * current local author, identity, and receiver-key custody.
   */
  readonly localPresenceOwnership: {
    readonly version: 1;
    readonly localPresenceOperationIds: readonly Uint8Array[];
    readonly localStableIdentityKeys: readonly Uint8Array[];
  };
  readonly plannerAndExplicitState: PlannerAndExplicitStateV1;
  readonly maxRetainedValidOperationsPerRoom: number;
  readonly maxPairLedgerEntriesPerRoom: number;
}

export interface LocalAdmissibleProjectSemanticResultV1 {
  readonly version: 1;
  readonly projectionStatus: LocalAdmissibleProjectStatusV1;
  readonly plannerStatus: LocalAdmissiblePlannerStatusV1;
  readonly observedRosterHash: Uint8Array;
  readonly state: LocalAdmissibleStateV1;
  /**
   * SSOT for the two distinct attempt origins. `state.peers[].desiredEdge` is
   * only their UI-friendly OR and must never be used to enforce attemptMode.
   */
  readonly topologySelections: readonly LocalTopologySelectionFactV1[];
}

export interface LocalTopologySelectionFactV1 {
  readonly presenceOperationId: Uint8Array;
  readonly plannerSelected: boolean;
  /**
   * Local outbound intent only. An incoming signed `attemptMode="explicit"`
   * does not require this bit; it requires the separately captured receiver
   * `allowOnDemandEdges` gate.
   */
  readonly locallyRequestedExplicit: boolean;
}

export class LocalAdmissibleProjectError extends Error {
  override readonly name = "LocalAdmissibleProjectError";

  constructor(message: string) {
    super(`localAdmissibleProject: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new LocalAdmissibleProjectError(message);
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const hex = (value: Uint8Array): string => {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
};

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
    return (
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor
    );
  });
};

const requireU64 = (value: unknown, label: string): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${label} must be an unsigned 64-bit integer`);
  return value;
};

const requirePositiveSafeInteger = (value: unknown, label: string): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    return fail(`${label} must be a positive safe integer`);
  return value;
};

interface OwnedProjectInput {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly referenceWindow: bigint;
  readonly coreBytesPromise: Promise<Uint8Array>;
  readonly frontendControls: FrontendRoomControlsV1 | null;
  readonly localPresenceOperationIds: readonly Uint8Array[];
  readonly localStableIdentityKeys: readonly Uint8Array[];
  readonly plannerAndExplicitState: PlannerAndExplicitStateV1;
  readonly maxRetainedValidOperationsPerRoom: number;
  readonly maxPairLedgerEntriesPerRoom: number;
}

const ownInputBeforeAwait = (input: unknown): OwnedProjectInput => {
  const fields = [
    "version",
    "roomContextId",
    "roomPolicy",
    "referenceWindow",
    "coreRoomState",
    "frontendControls",
    "localPresenceOwnership",
    "plannerAndExplicitState",
    "maxRetainedValidOperationsPerRoom",
    "maxPairLedgerEntriesPerRoom",
  ] as const;
  if (!hasExactOwnDataFields(input, fields))
    return fail("input must contain exactly its declared fields");
  if (input.version !== 1) return fail("unsupported input version");

  let roomContextId: Uint8Array;
  try {
    roomContextId = snapshotByteInput(
      input.roomContextId,
      "localAdmissibleProject: roomContextId",
      { exactLength: 32 },
    );
  } catch {
    return fail("roomContextId must be exactly 32 bytes");
  }

  let roomPolicy: RoomPolicyV4;
  try {
    roomPolicy = decodeRoomPolicyV4(
      encodeRoomPolicyV4(input.roomPolicy as RoomPolicyV4),
    );
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("roomPolicy is invalid");
  }

  const referenceWindow = requireU64(input.referenceWindow, "referenceWindow");
  const maxPairLedgerEntriesPerRoom = requirePositiveSafeInteger(
    input.maxPairLedgerEntriesPerRoom,
    "maxPairLedgerEntriesPerRoom",
  );
  const maxRetainedValidOperationsPerRoom = requirePositiveSafeInteger(
    input.maxRetainedValidOperationsPerRoom,
    "maxRetainedValidOperationsPerRoom",
  );

  let frontendControls: FrontendRoomControlsV1 | null;
  try {
    frontendControls =
      input.frontendControls === null
        ? null
        : validateAndCopyFrontendRoomControlsV1(input.frontendControls);
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("frontendControls is invalid");
  }

  let localPresenceOperationIds: readonly Uint8Array[];
  let localStableIdentityKeys: readonly Uint8Array[];
  try {
    const ownership = decodeCanonicalStrict(
      localPresenceOwnershipV1Schema,
      encodeCanonical(
        localPresenceOwnershipV1Schema,
        input.localPresenceOwnership,
      ),
    ) as {
      readonly version: number;
      readonly localPresenceOperationIds: readonly Uint8Array[];
      readonly localStableIdentityKeys: readonly Uint8Array[];
    };
    if (ownership.version !== 1)
      return fail("unsupported localPresenceOwnership version");
    localPresenceOperationIds = ownership.localPresenceOperationIds;
    localStableIdentityKeys = ownership.localStableIdentityKeys;
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("localPresenceOwnership is invalid");
  }

  let plannerAndExplicitState: PlannerAndExplicitStateV1;
  try {
    plannerAndExplicitState = validateAndCopyPlannerAndExplicitStateV1(
      input.plannerAndExplicitState,
      {
        maxRoomMembers: roomPolicy.maxRoomMembers,
        maxPairLedgerEntriesPerRoom,
      },
    );
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("plannerAndExplicitState is invalid");
  }

  let coreBytesPromise: Promise<Uint8Array>;
  try {
    coreBytesPromise = encodeCoreRoomStateV1(
      input.coreRoomState as CoreRoomStateV1,
    );
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("coreRoomState is invalid");
  }

  return {
    roomContextId,
    roomPolicy,
    referenceWindow,
    coreBytesPromise,
    frontendControls,
    localPresenceOperationIds,
    localStableIdentityKeys,
    plannerAndExplicitState,
    maxRetainedValidOperationsPerRoom,
    maxPairLedgerEntriesPerRoom,
  };
};

const validateCoreProjection = async (
  core: CoreRoomStateV1,
  roomPolicy: RoomPolicyV4,
  referenceWindow: bigint,
): Promise<void> => {
  if (core.referenceWindow !== referenceWindow)
    return fail("Core reference window does not match Project");
  const expectedCapacityState =
    core.observedPresences.length > roomPolicy.maxRoomMembers
      ? "overcapacity"
      : "within-policy";
  if (core.roomCapacityState !== expectedCapacityState)
    return fail("Core room capacity state is inconsistent");
  if (
    !bytesEqual(
      core.operationsDigest,
      await coreOperationSetDigest(core.activeOperationIds),
    )
  )
    return fail("Core operations digest is inconsistent");

  const activeOperationIds = new Set(core.activeOperationIds.map(hex));
  for (const fact of core.observedPresences) {
    if (!activeOperationIds.has(hex(fact.presenceOperationId)))
      return fail("Core presence is absent from activeOperationIds");
    if (
      fact.logicalWindow > referenceWindow ||
      referenceWindow > fact.presence.core.validThroughLogicalWindow
    )
      return fail("Core contains a presence inactive at referenceWindow");
    const hasPermit = fact.presence.authorityPermit !== null;
    if ((roomPolicy.admissionFloor.mode === "authority-grant") !== hasPermit)
      return fail("Core presence permit mode disagrees with room policy");
  }
};

interface ProjectedVertex {
  readonly fact: CorePresenceFactV1;
  readonly localPeerId: string;
  readonly rank: Uint8Array;
  readonly eligibility: LocalPresenceEligibilityV1;
}

const copyState = (state: LocalAdmissibleStateV1): LocalAdmissibleStateV1 => ({
  version: 1,
  referenceWindow: state.referenceWindow,
  coreOperationsDigest: Uint8Array.from(state.coreOperationsDigest),
  localPresenceOperationId:
    state.localPresenceOperationId === null
      ? null
      : Uint8Array.from(state.localPresenceOperationId),
  localPresenceRank:
    state.localPresenceRank === null
      ? null
      : Uint8Array.from(state.localPresenceRank),
  peers: state.peers.map((peer) => ({
    localPeerId: peer.localPeerId,
    presenceOperationId: Uint8Array.from(peer.presenceOperationId),
    stableIdentityCommitment: Uint8Array.from(peer.stableIdentityCommitment),
    rank: Uint8Array.from(peer.rank),
    eligibility: peer.eligibility,
    desiredEdge: peer.desiredEdge,
  })),
  requestedExplicitPeerIds: [...state.requestedExplicitPeerIds],
});

const emptyState = (
  input: OwnedProjectInput,
  core: CoreRoomStateV1,
): LocalAdmissibleStateV1 => ({
  version: 1,
  referenceWindow: input.referenceWindow,
  coreOperationsDigest: Uint8Array.from(core.operationsDigest),
  localPresenceOperationId: null,
  localPresenceRank: null,
  peers: [],
  requestedExplicitPeerIds: [
    ...input.plannerAndExplicitState.requestedExplicitPeerIds,
  ],
});

interface FrontendCommitmentIndexes {
  readonly deniedCommitments: ReadonlySet<string>;
  /** Null records an infeasible-but-fail-closed hash collision. */
  readonly eligibleStableKeyByCommitment: ReadonlyMap<
    string,
    Uint8Array | null
  >;
}

const deriveFrontendCommitmentIndexes = async (
  roomContextId: Uint8Array,
  frontendControls: FrontendRoomControlsV1,
  localStableIdentityKeys: readonly Uint8Array[],
): Promise<FrontendCommitmentIndexes> => {
  const deniedCommitments = new Set(
    frontendControls.deniedRoomIdentityCommitments.map(hex),
  );
  const commitmentByStableKey = new Map<string, Uint8Array>();
  const deriveOnce = async (stableKey: Uint8Array): Promise<Uint8Array> => {
    const key = hex(stableKey);
    const existing = commitmentByStableKey.get(key);
    if (existing !== undefined) return existing;
    const commitment = await stableIdentityCommitment(roomContextId, stableKey);
    commitmentByStableKey.set(key, commitment);
    return commitment;
  };

  // Deliberately sequential: the canonical set can contain 65,535 entries.
  // Project must not enqueue one promise per frontend row.
  for (const stableKey of frontendControls.deniedStableIdentityKeys)
    deniedCommitments.add(hex(await deriveOnce(stableKey)));

  const eligibleStableKeyByCommitment = new Map<string, Uint8Array | null>();
  const addEligibleStableKey = async (stableKey: Uint8Array): Promise<void> => {
    const commitmentKey = hex(await deriveOnce(stableKey));
    const existing = eligibleStableKeyByCommitment.get(commitmentKey);
    if (existing === null) return;
    if (existing === undefined) {
      eligibleStableKeyByCommitment.set(
        commitmentKey,
        Uint8Array.from(stableKey),
      );
    } else if (!bytesEqual(existing, stableKey)) {
      eligibleStableKeyByCommitment.set(commitmentKey, null);
    }
  };
  for (const stableKey of frontendControls.allowedStableIdentityKeys)
    await addEligibleStableKey(stableKey);
  /*
   * Strict self eligibility is stable-identity-wide. Union the locally held
   * public keys before candidate verification so a lower valid presence for
   * the same key wins even when that exact operation is not locally owned.
   */
  for (const stableKey of localStableIdentityKeys)
    await addEligibleStableKey(stableKey);

  return { deniedCommitments, eligibleStableKeyByCommitment };
};

const selectCapabilityCandidates = async (
  input: OwnedProjectInput,
  core: CoreRoomStateV1,
  frontendControls: FrontendRoomControlsV1,
  module?: LibCrypto,
): Promise<ProjectedVertex[]> => {
  const indexes = await deriveFrontendCommitmentIndexes(
    input.roomContextId,
    frontendControls,
    input.localStableIdentityKeys,
  );
  const strict = frontendControls.onlyConnectWithKnownPeers;
  const acceptedStrictCommitments = new Set<string>();

  const eligibleFacts: {
    readonly fact: CorePresenceFactV1;
    readonly eligibility: Extract<
      LocalPresenceEligibilityV1,
      "open" | "local-address-book-proved"
    >;
  }[] = [];
  for (const fact of core.observedPresences) {
    const commitmentKey = hex(fact.presence.core.stableIdentityCommitment);
    if (indexes.deniedCommitments.has(commitmentKey)) continue;
    if (!strict) {
      eligibleFacts.push({ fact, eligibility: "open" });
      continue;
    }

    if (acceptedStrictCommitments.has(commitmentKey)) continue;
    const matchingKey =
      indexes.eligibleStableKeyByCommitment.get(commitmentKey);
    if (matchingKey === undefined || matchingKey === null) continue;
    try {
      await validateCorePresenceFactOwnershipV1(
        fact,
        matchingKey,
        {
          roomContextId: input.roomContextId,
          roomPolicy: input.roomPolicy,
        },
        module,
      );
    } catch (cause) {
      if (cause instanceof OperationPayloadValidationError) continue;
      throw cause;
    }
    acceptedStrictCommitments.add(commitmentKey);
    eligibleFacts.push({
      fact,
      eligibility: "local-address-book-proved",
    });
  }

  const projected: ProjectedVertex[] = [];
  // Also sequential for the u16-bounded Core. The future trusted wrapper
  // applies the pinned retained-operation cap before reaching this loop.
  for (const { fact, eligibility } of eligibleFacts) {
    const commitment = fact.presence.core.stableIdentityCommitment;
    projected.push({
      fact,
      localPeerId: await localPeerId(input.roomContextId, commitment),
      rank:
        eligibility === "open"
          ? await openPresenceRank(
              input.roomContextId,
              fact.presenceOperationId,
            )
          : await addressBookPresenceRank(input.roomContextId, commitment),
      eligibility,
    });
  }
  projected.sort(
    (left, right) =>
      compareBytes(left.rank, right.rank) ||
      compareBytes(
        left.fact.presenceOperationId,
        right.fact.presenceOperationId,
      ),
  );
  return projected.slice(0, input.roomPolicy.maxRoomMembers);
};

const desiredPresenceIds = (
  vertices: readonly ProjectedVertex[],
  localIndex: number,
  planner: PlannerAndExplicitStateV1,
): {
  readonly plannerSelected: ReadonlySet<string>;
  readonly locallyRequestedExplicit: ReadonlySet<string>;
  readonly fullMeshOvercapacity: boolean;
} => {
  const plannerSelected = new Set<string>();
  const locallyRequestedExplicit = new Set<string>();
  const policy = planner.plannerPolicy;
  const localVertex = vertices[localIndex];

  if (policy.mode === "sparse-ring") {
    const steps = Math.min(policy.sparseRadius, vertices.length - 1);
    for (let distance = 1; distance <= steps; distance++) {
      const predecessor =
        (localIndex - distance + vertices.length) % vertices.length;
      const successor = (localIndex + distance) % vertices.length;
      if (predecessor !== localIndex)
        plannerSelected.add(
          hex(vertices[predecessor].fact.presenceOperationId),
        );
      if (successor !== localIndex)
        plannerSelected.add(hex(vertices[successor].fact.presenceOperationId));
    }
  }

  const fullMeshOvercapacity =
    policy.mode === "full-mesh-small-room" &&
    vertices.length > policy.fullMeshMaxMembers;
  if (policy.mode === "full-mesh-small-room" && !fullMeshOvercapacity) {
    for (const vertex of vertices) {
      if (vertex !== localVertex)
        plannerSelected.add(hex(vertex.fact.presenceOperationId));
    }
  }

  if (policy.allowOnDemandEdges) {
    const requested = new Set(planner.requestedExplicitPeerIds);
    const resolvedRequestedPeerIds = new Set<string>();
    for (const vertex of vertices) {
      if (
        vertex !== localVertex &&
        requested.has(vertex.localPeerId) &&
        !resolvedRequestedPeerIds.has(vertex.localPeerId)
      ) {
        locallyRequestedExplicit.add(hex(vertex.fact.presenceOperationId));
        resolvedRequestedPeerIds.add(vertex.localPeerId);
      }
    }
  }

  return {
    plannerSelected,
    locallyRequestedExplicit,
    fullMeshOvercapacity,
  };
};

/**
 * Evaluate the local Project rules over one owned structural snapshot.
 *
 * The return value is a diagnostic fact only. It is intentionally cloneable
 * and therefore MUST NOT be accepted by a topology or admission transition as
 * proof that a peer was selected.
 */
export const evaluateLocalAdmissibleProjectionSemanticsV1 = async (
  inputValue: unknown,
  module?: LibCrypto,
): Promise<LocalAdmissibleProjectSemanticResultV1> => {
  const input = ownInputBeforeAwait(inputValue);
  const core = await decodeCoreRoomStateV1(await input.coreBytesPromise);
  await validateCoreProjection(core, input.roomPolicy, input.referenceWindow);
  try {
    await assertPlannerStateRoomBindingV1(
      input.plannerAndExplicitState,
      input.roomContextId,
      {
        maxRoomMembers: input.roomPolicy.maxRoomMembers,
        maxPairLedgerEntriesPerRoom: input.maxPairLedgerEntriesPerRoom,
      },
    );
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("planner state room binding failed");
  }

  const rosterHash = await observedRosterHash(
    input.referenceWindow,
    core.observedPresences.map((fact) => fact.presenceOperationId),
  );
  if (
    core.activeOperationIds.length >= input.maxRetainedValidOperationsPerRoom ||
    core.observedPresences.length >= input.maxRetainedValidOperationsPerRoom
  ) {
    return {
      version: 1,
      projectionStatus: "projection-resource-overcapacity",
      plannerStatus: "unavailable",
      observedRosterHash: rosterHash,
      state: emptyState(input, core),
      topologySelections: [],
    };
  }
  const controls = input.frontendControls;
  if (controls === null) {
    return {
      version: 1,
      projectionStatus: "policy-unavailable",
      plannerStatus: "unavailable",
      observedRosterHash: rosterHash,
      state: emptyState(input, core),
      topologySelections: [],
    };
  }
  if (input.roomPolicy.admissionFloor.mode === "authority-grant") {
    return {
      version: 1,
      projectionStatus: "policy-unavailable",
      plannerStatus: "unavailable",
      observedRosterHash: rosterHash,
      state: emptyState(input, core),
      topologySelections: [],
    };
  }

  const vertices = await selectCapabilityCandidates(
    input,
    core,
    controls,
    module,
  );
  const ownedPresenceIds = new Set(input.localPresenceOperationIds.map(hex));
  const selectedOwnedIndices = vertices.flatMap((vertex, index) =>
    ownedPresenceIds.has(hex(vertex.fact.presenceOperationId)) ? [index] : [],
  );
  const localIndex =
    selectedOwnedIndices.length === 1 ? selectedOwnedIndices[0] : -1;
  const localVertex = localIndex < 0 ? null : vertices[localIndex];
  const selection =
    localVertex === null
      ? {
          plannerSelected: new Set<string>(),
          locallyRequestedExplicit: new Set<string>(),
          fullMeshOvercapacity:
            input.plannerAndExplicitState.plannerPolicy.mode ===
              "full-mesh-small-room" &&
            vertices.length >
              input.plannerAndExplicitState.plannerPolicy.fullMeshMaxMembers,
        }
      : desiredPresenceIds(vertices, localIndex, input.plannerAndExplicitState);

  const selectedOwnedIds = new Set(
    selectedOwnedIndices.map((index) =>
      hex(vertices[index].fact.presenceOperationId),
    ),
  );
  const topologySelections: LocalTopologySelectionFactV1[] = [];
  const state: LocalAdmissibleStateV1 = {
    version: 1,
    referenceWindow: input.referenceWindow,
    coreOperationsDigest: Uint8Array.from(core.operationsDigest),
    localPresenceOperationId:
      localVertex === null
        ? null
        : Uint8Array.from(localVertex.fact.presenceOperationId),
    localPresenceRank:
      localVertex === null ? null : Uint8Array.from(localVertex.rank),
    peers: vertices.flatMap((vertex) => {
      const operationIdKey = hex(vertex.fact.presenceOperationId);
      if (selectedOwnedIds.has(operationIdKey)) return [];
      const plannerSelected =
        localVertex !== null && selection.plannerSelected.has(operationIdKey);
      const locallyRequestedExplicit =
        localVertex !== null &&
        selection.locallyRequestedExplicit.has(operationIdKey);
      topologySelections.push({
        presenceOperationId: Uint8Array.from(vertex.fact.presenceOperationId),
        plannerSelected,
        locallyRequestedExplicit,
      });
      return [
        {
          localPeerId: vertex.localPeerId,
          presenceOperationId: Uint8Array.from(vertex.fact.presenceOperationId),
          stableIdentityCommitment: Uint8Array.from(
            vertex.fact.presence.core.stableIdentityCommitment,
          ),
          rank: Uint8Array.from(vertex.rank),
          eligibility: vertex.eligibility,
          desiredEdge: plannerSelected || locallyRequestedExplicit,
        },
      ];
    }),
    requestedExplicitPeerIds: [
      ...input.plannerAndExplicitState.requestedExplicitPeerIds,
    ],
  };

  const projectionStatus: LocalAdmissibleProjectStatusV1 =
    localVertex === null ? "no-unambiguous-local-presence" : "ready";
  const plannerStatus: LocalAdmissiblePlannerStatusV1 =
    localVertex === null
      ? "unavailable"
      : selection.fullMeshOvercapacity
        ? "full-mesh-overcapacity"
        : "ready";
  return {
    version: 1,
    projectionStatus,
    plannerStatus,
    observedRosterHash: Uint8Array.from(rosterHash),
    state: copyState(state),
    topologySelections: topologySelections.map((fact) => ({
      presenceOperationId: Uint8Array.from(fact.presenceOperationId),
      plannerSelected: fact.plannerSelected,
      locallyRequestedExplicit: fact.locallyRequestedExplicit,
    })),
  };
};
