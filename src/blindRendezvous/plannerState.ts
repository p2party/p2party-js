/**
 * Canonical local planner/topology persistence state.
 *
 * Core room reduction deliberately contains no local topology preference.
 * This module is the one local SSOT for planner policy, explicit requests,
 * provisional pair edges, and active stable edges. Counts are always derived
 * from canonical edge sets; there are no independently mutable counters.
 *
 * This module deliberately exposes no desired-neighbor or reservation
 * authority yet. That transition must consume an opaque result of the trusted
 * local `Project`, then compare-and-swap this exact captured row with every
 * other admission fence. Raw caller-supplied "selected" booleans are not a
 * planner proof.
 */

import {
  MAX_CANONICAL_ENCODING_BYTES,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { snapshotByteInput } from "../cryptography/byteInput";
import {
  base64urlNoPad,
  base64urlNoPadDecode,
  pairEdgeId,
} from "./derivations";
import { plannerAndExplicitStateV1Schema } from "./schemas";

export type ConnectionPlannerModeV1 =
  "explicit" | "sparse-ring" | "full-mesh-small-room";

export interface ConnectionPlannerPolicyV1 {
  readonly version: 1;
  readonly mode: ConnectionPlannerModeV1;
  readonly sparseRadius: number;
  readonly maxProvisionalEdges: number;
  readonly maxActiveStableEdges: number;
  readonly fullMeshMaxMembers: number;
  readonly allowOnDemandEdges: boolean;
}

export interface ProvisionalTopologyEdgeV1 {
  readonly pairEdgeId: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
  readonly remoteLocalPeerId: string;
}

export interface ActiveStableTopologyEdgeV1 {
  readonly stableEdgeId: Uint8Array;
  readonly remoteLocalPeerId: string;
}

export interface PlannerAndExplicitStateV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly plannerPolicy: ConnectionPlannerPolicyV1;
  readonly requestedExplicitPeerIds: readonly string[];
  readonly provisionalEdges: readonly ProvisionalTopologyEdgeV1[];
  readonly activeStableEdges: readonly ActiveStableTopologyEdgeV1[];
}

export interface PlannerStateValidationLimitsV1 {
  readonly maxRoomMembers: number;
  readonly maxPairLedgerEntriesPerRoom: number;
}

export class PlannerStateError extends Error {
  override readonly name = "PlannerStateError";

  constructor(message: string) {
    super(`plannerState: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new PlannerStateError(message);
};

const hex = (value: Uint8Array): string => {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
};

const hasExactOwnDataFields = (
  value: unknown,
  fields: readonly string[],
): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  )
    return false;
  return fields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return (
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor
    );
  });
};

const requirePositiveSafeInteger = (value: unknown, label: string): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    return fail(`${label} must be a positive safe integer`);
  return value;
};

const ownLimits = (
  value: PlannerStateValidationLimitsV1,
): PlannerStateValidationLimitsV1 => {
  if (
    !hasExactOwnDataFields(value, [
      "maxRoomMembers",
      "maxPairLedgerEntriesPerRoom",
    ])
  )
    return fail("validation limits must contain exactly their declared fields");
  return {
    maxRoomMembers: requirePositiveSafeInteger(
      value.maxRoomMembers,
      "maxRoomMembers",
    ),
    maxPairLedgerEntriesPerRoom: requirePositiveSafeInteger(
      value.maxPairLedgerEntriesPerRoom,
      "maxPairLedgerEntriesPerRoom",
    ),
  };
};

const validateLocalPeerId = (value: string, label: string): void => {
  if (
    typeof value !== "string" ||
    value.length !== 51 ||
    !value.startsWith("peer.v1.")
  )
    return fail(`${label} must be a canonical peer.v1 local peer ID`);
  let digest: Uint8Array;
  try {
    digest = base64urlNoPadDecode(value.slice(8));
  } catch {
    return fail(`${label} must be a canonical peer.v1 local peer ID`);
  }
  if (digest.length !== 32 || `peer.v1.${base64urlNoPad(digest)}` !== value)
    fail(`${label} must be a canonical peer.v1 local peer ID`);
};

const canonicalState = (value: unknown): PlannerAndExplicitStateV1 => {
  try {
    return decodeCanonicalStrict(
      plannerAndExplicitStateV1Schema,
      encodeCanonical(plannerAndExplicitStateV1Schema, value),
    ) as PlannerAndExplicitStateV1;
  } catch (cause) {
    if (cause instanceof PlannerStateError) throw cause;
    if (cause instanceof Error) return fail(cause.message);
    return fail("planner state canonical validation failed");
  }
};

const validatePolicy = (
  policy: ConnectionPlannerPolicyV1,
  limits: PlannerStateValidationLimitsV1,
): void => {
  if (policy.version !== 1) fail("plannerPolicy.version must be 1");
  const sparseRadius = requirePositiveSafeInteger(
    policy.sparseRadius,
    "plannerPolicy.sparseRadius",
  );
  const maxProvisionalEdges = requirePositiveSafeInteger(
    policy.maxProvisionalEdges,
    "plannerPolicy.maxProvisionalEdges",
  );
  const maxActiveStableEdges = requirePositiveSafeInteger(
    policy.maxActiveStableEdges,
    "plannerPolicy.maxActiveStableEdges",
  );
  const fullMeshMaxMembers = requirePositiveSafeInteger(
    policy.fullMeshMaxMembers,
    "plannerPolicy.fullMeshMaxMembers",
  );

  if (sparseRadius >= limits.maxRoomMembers)
    fail("plannerPolicy.sparseRadius must be below maxRoomMembers");
  if (maxActiveStableEdges >= limits.maxRoomMembers)
    fail("plannerPolicy.maxActiveStableEdges must be below maxRoomMembers");
  if (
    Math.min(2 * sparseRadius, limits.maxRoomMembers - 1) > maxActiveStableEdges
  )
    fail("plannerPolicy.maxActiveStableEdges cannot realize sparseRadius");
  if (maxActiveStableEdges > maxProvisionalEdges)
    fail(
      "plannerPolicy.maxActiveStableEdges must not exceed maxProvisionalEdges",
    );
  if (maxProvisionalEdges > limits.maxPairLedgerEntriesPerRoom)
    fail(
      "plannerPolicy.maxProvisionalEdges exceeds maxPairLedgerEntriesPerRoom",
    );
  if (
    fullMeshMaxMembers > maxActiveStableEdges + 1 ||
    fullMeshMaxMembers > limits.maxRoomMembers
  )
    fail(
      "plannerPolicy.fullMeshMaxMembers exceeds the stable-edge or room cap",
    );
};

const validateStateSemantics = (
  state: PlannerAndExplicitStateV1,
  limits: PlannerStateValidationLimitsV1,
): void => {
  if (state.version !== 1) fail("state.version must be 1");
  validatePolicy(state.plannerPolicy, limits);
  if (state.provisionalEdges.length > state.plannerPolicy.maxProvisionalEdges)
    fail("provisional edges exceed maxProvisionalEdges");
  if (state.activeStableEdges.length > state.plannerPolicy.maxActiveStableEdges)
    fail("active stable edges exceed maxActiveStableEdges");

  for (let index = 0; index < state.requestedExplicitPeerIds.length; index++)
    validateLocalPeerId(
      state.requestedExplicitPeerIds[index],
      `requestedExplicitPeerIds[${String(index)}]`,
    );

  const pairEdgeIds = new Set<string>();
  const endpointTuples = new Set<string>();
  for (let index = 0; index < state.provisionalEdges.length; index++) {
    const edge = state.provisionalEdges[index];
    if (edge.endpointPresenceOperationIds.length !== 2)
      fail(
        `provisionalEdges[${String(index)}] must name exactly two endpoint presences`,
      );
    const pairKey = hex(edge.pairEdgeId);
    if (pairEdgeIds.has(pairKey))
      fail("provisional edges must have unique pairEdgeId values");
    pairEdgeIds.add(pairKey);
    const endpointKey = `${hex(edge.endpointPresenceOperationIds[0])}:${hex(
      edge.endpointPresenceOperationIds[1],
    )}`;
    if (endpointTuples.has(endpointKey))
      fail("provisional edges must have unique endpoint tuples");
    endpointTuples.add(endpointKey);
    validateLocalPeerId(
      edge.remoteLocalPeerId,
      `provisionalEdges[${String(index)}].remoteLocalPeerId`,
    );
  }

  const stableEdgeIds = new Set<string>();
  const remotePeerIds = new Set<string>();
  for (let index = 0; index < state.activeStableEdges.length; index++) {
    const edge = state.activeStableEdges[index];
    const stableEdgeKey = hex(edge.stableEdgeId);
    if (stableEdgeIds.has(stableEdgeKey))
      fail("active stable edges must have unique stableEdgeId values");
    stableEdgeIds.add(stableEdgeKey);
    validateLocalPeerId(
      edge.remoteLocalPeerId,
      `activeStableEdges[${String(index)}].remoteLocalPeerId`,
    );
    if (remotePeerIds.has(edge.remoteLocalPeerId))
      fail("active stable edges must have unique remote local peer IDs");
    remotePeerIds.add(edge.remoteLocalPeerId);
  }
};

/** Strictly own and validate one complete planner/topology state. */
export const validateAndCopyPlannerAndExplicitStateV1 = (
  value: unknown,
  limitsValue: PlannerStateValidationLimitsV1,
): PlannerAndExplicitStateV1 => {
  const limits = ownLimits(limitsValue);
  const state = canonicalState(value);
  validateStateSemantics(state, limits);
  return state;
};

/** Canonical durable planner/topology bytes. */
export const encodePlannerAndExplicitStateV1 = (
  value: unknown,
  limits: PlannerStateValidationLimitsV1,
): Uint8Array =>
  encodeCanonical(
    plannerAndExplicitStateV1Schema,
    validateAndCopyPlannerAndExplicitStateV1(value, limits),
  );

/** Strictly restore and own one canonical durable planner/topology row. */
export const decodePlannerAndExplicitStateV1 = (
  encoded: Uint8Array,
  limits: PlannerStateValidationLimitsV1,
): PlannerAndExplicitStateV1 => {
  let bytes: Uint8Array;
  try {
    bytes = snapshotByteInput(encoded, "plannerState: encoded state", {
      maximumLength: MAX_CANONICAL_ENCODING_BYTES,
    });
  } catch (cause) {
    if (cause instanceof Error) return fail(cause.message);
    return fail("encoded planner state must be canonical bytes");
  }
  if (bytes.length === 0) fail("encoded planner state must not be empty");
  try {
    return validateAndCopyPlannerAndExplicitStateV1(
      decodeCanonicalStrict(plannerAndExplicitStateV1Schema, bytes),
      limits,
    );
  } catch (cause) {
    if (cause instanceof PlannerStateError) throw cause;
    if (cause instanceof Error) return fail(cause.message);
    return fail("encoded planner state validation failed");
  }
};

const ownRoomContextId = (value: unknown): Uint8Array => {
  try {
    return snapshotByteInput(value, "plannerState: roomContextId", {
      exactLength: 32,
    });
  } catch {
    return fail("roomContextId must be exactly 32 bytes");
  }
};

/**
 * Prove every persisted provisional edge is bound to this exact room.
 *
 * All state and room bytes are owned before the first hash promise begins.
 */
export const assertPlannerStateRoomBindingV1 = async (
  stateValue: unknown,
  roomContextIdValue: Uint8Array,
  limits: PlannerStateValidationLimitsV1,
): Promise<PlannerAndExplicitStateV1> => {
  const state = validateAndCopyPlannerAndExplicitStateV1(stateValue, limits);
  const roomContextId = ownRoomContextId(roomContextIdValue);
  if (!bytesEqual(state.roomContextId, roomContextId))
    fail("planner state belongs to another room context");
  const expectedIds = await Promise.all(
    state.provisionalEdges.map((edge) =>
      pairEdgeId(
        state.roomContextId,
        edge.endpointPresenceOperationIds[0],
        edge.endpointPresenceOperationIds[1],
      ),
    ),
  );
  for (let index = 0; index < state.provisionalEdges.length; index++) {
    if (
      !bytesEqual(expectedIds[index], state.provisionalEdges[index].pairEdgeId)
    )
      fail(`provisionalEdges[${String(index)}] has the wrong room pairEdgeId`);
  }
  return state;
};
