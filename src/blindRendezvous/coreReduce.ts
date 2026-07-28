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
 * Scope: this module implements the outer layer — author-chain and quota
 * faults, the active operation set, the pair-step projection, and
 * `operationsDigest`. The payload-level facts of `CoreRoomStateV1`
 * (`observedPresences`, `effectiveLeaveOperationIds`, `storeCatalogFacts`,
 * `revocationFloors`) require the Section 4.2/4.9 nested payload codecs, which
 * are not implemented yet; `coreReduceOuter` therefore returns exactly the
 * facts it can derive and names the rest as pending rather than emitting an
 * empty array that would read as "no presences observed".
 */

import { bytesEqual } from "./canonicalSchema";
import { coreOperationSetDigest } from "./derivations";
import { encodeOperation } from "./operation";

import type { AuthenticatedRoomOperationV1 } from "./operation";
import type { RoomPolicyV4 } from "./roomPolicyV4";

/** One validated operation together with its derived private identifier. */
export interface IdentifiedOperationV1 {
  readonly operationId: Uint8Array;
  readonly operation: AuthenticatedRoomOperationV1;
}

export type CoreFaultV1 = {
  readonly kind: "author-fork-or-overquota";
  readonly authorEpochEd25519Key: Uint8Array;
  readonly logicalWindow: bigint;
  readonly proofOperationIds: readonly Uint8Array[];
};

export interface CoreOuterStateV1 {
  readonly version: 1;
  readonly referenceWindow: bigint;
  readonly activeOperationIds: readonly Uint8Array[];
  readonly activePairOuterOperationIds: readonly Uint8Array[];
  readonly faults: readonly CoreFaultV1[];
  readonly operationsDigest: Uint8Array;
  /**
   * Payload-level reduction that this increment does not perform. A caller
   * must not present the absence of these facts as an observation.
   */
  readonly pendingPayloadReduction: readonly (
    | "observedPresences"
    | "effectiveLeaveOperationIds"
    | "storeCatalogFacts"
    | "revocationFloors"
    | "roomCapacityState"
  )[];
}

const PENDING_PAYLOAD_REDUCTION = Object.freeze([
  "observedPresences",
  "effectiveLeaveOperationIds",
  "storeCatalogFacts",
  "revocationFloors",
  // Section 4.7 defines this over the active presence count against immutable
  // maxRoomMembers, so it cannot be derived before presence reduction — and it
  // must never be derived from a local storage cap, which is a delivery fact.
  "roomCapacityState",
] as const);

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

/**
 * Set union with an exact-duplicate no-op.
 *
 * Associativity, commutativity, and idempotence are the properties the whole
 * convergence argument rests on, so union is deliberately keyed by the private
 * `OperationId` and nothing else — not arrival order, not carrier, not a
 * server-assigned identifier.
 */
export const mergeOperationSets = (
  left: readonly IdentifiedOperationV1[],
  right: readonly IdentifiedOperationV1[],
): IdentifiedOperationV1[] => {
  const byId = new Map<string, IdentifiedOperationV1>();
  for (const entry of [...left, ...right]) {
    const key = hex(entry.operationId);
    const existing = byId.get(key);
    if (existing === undefined) {
      byId.set(key, entry);
      continue;
    }
    // Two entries with one OperationId must be the same operation; the ID is a
    // hash of the complete canonical encoding.
    if (
      !bytesEqual(
        encodeOperation(existing.operation),
        encodeOperation(entry.operation),
      )
    )
      throw new Error(
        "coreReduce: two different operations share one OperationId",
      );
  }
  return [...byId.values()].sort((a, b) =>
    compareBytes(a.operationId, b.operationId),
  );
};

const authorWindowKey = (operation: AuthenticatedRoomOperationV1): string =>
  `${hex(operation.authorEpochEd25519Key)}:${operation.logicalWindow.toString()}`;

/**
 * `CoreReduce` over the outer layer.
 *
 * Every decision below is a function of the operation bytes and the explicit
 * reference window. In particular, fork and overquota classification precedes
 * any payload work and is arrival-independent: an author that occupies one
 * `(key, window, sequence)` slot with two different byte strings, or that
 * exceeds `maxOperationsPerAuthorWindow` candidates, has its whole window
 * excluded no matter which operation arrived first.
 */
export const coreReduceOuter = async (
  operations: readonly IdentifiedOperationV1[],
  roomPolicy: RoomPolicyV4,
  referenceWindow: bigint,
): Promise<CoreOuterStateV1> => {
  // Deduplicate first. The author quota counts *distinct* candidates, so a
  // carrier that redelivers one operation must not be able to manufacture an
  // overquota fault against an honest author — at-least-once delivery is part
  // of the carrier contract, not evidence of misbehavior.
  const sorted = mergeOperationSets(operations, []);

  const skew = BigInt(roomPolicy.protocolLimits.maxClockSkewWindows);
  const maxPerAuthorWindow =
    roomPolicy.protocolLimits.maxOperationsPerAuthorWindow;

  // Group by (author key, logical window). Every distinct candidate counts
  // toward the author quota, including ones later excluded by a fault: the
  // count must not depend on which of them a client happened to receive.
  const byAuthorWindow = new Map<string, IdentifiedOperationV1[]>();
  for (const entry of sorted) {
    const key = authorWindowKey(entry.operation);
    const group = byAuthorWindow.get(key);
    if (group === undefined) byAuthorWindow.set(key, [entry]);
    else group.push(entry);
  }

  const faults: CoreFaultV1[] = [];
  const faultedAuthorWindows = new Set<string>();

  for (const [key, group] of byAuthorWindow) {
    const bySequence = new Map<string, IdentifiedOperationV1[]>();
    for (const entry of group) {
      const sequenceKey = entry.operation.authorSequence.toString();
      const slot = bySequence.get(sequenceKey);
      if (slot === undefined) bySequence.set(sequenceKey, [entry]);
      else slot.push(entry);
    }

    const forkProofs: Uint8Array[] = [];
    for (const slot of bySequence.values()) {
      if (slot.length > 1) {
        // A fixed-size proof suffices: the two bytewise-lowest IDs in the slot.
        const ids = sortBytes(slot.map((entry) => entry.operationId));
        forkProofs.push(ids[0], ids[1]);
      }
    }

    const overquota = group.length > maxPerAuthorWindow;

    // The pinned authority is the one stable author binding, and its chain may
    // contain only revocations. Anything else under that key is a fault, so a
    // capability holder cannot dilute or displace authority slots.
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
    const proofOperationIds =
      forkProofs.length > 0
        ? sortBytes(forkProofs)
        : nonRevocationInAuthorityChain
          ? sortBytes(
              group
                .filter((entry) => entry.operation.kind !== "ADMISSION_REVOKE")
                .map((entry) => entry.operationId),
            ).slice(0, 1)
          : // Physical proof of overquota needs only the lowest quota+1 IDs.
            sortBytes(group.map((entry) => entry.operationId)).slice(
              0,
              maxPerAuthorWindow + 1,
            );

    faults.push({
      kind: "author-fork-or-overquota",
      authorEpochEd25519Key: group[0].operation.authorEpochEd25519Key,
      logicalWindow: group[0].operation.logicalWindow,
      proofOperationIds,
    });
  }

  // An operation is eligible only when its author chain is proven contiguous
  // back to sequence zero of its window, each link naming its exact
  // predecessor. Without this, an author could publish sequence 5 alone and
  // have it reduce as though 0..4 existed.
  const provenChainMembers = new Set<string>();
  for (const [key, group] of byAuthorWindow) {
    if (faultedAuthorWindows.has(key)) continue;

    const bySequence = new Map<string, IdentifiedOperationV1>();
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

  const active: IdentifiedOperationV1[] = [];
  for (const entry of sorted) {
    if (faultedAuthorWindows.has(authorWindowKey(entry.operation))) continue;
    // A gap or mislinked predecessor leaves the rest of that chain unproven.
    if (!provenChainMembers.has(hex(entry.operationId))) continue;
    // Future operations are held in a bounded candidate partition and cannot
    // affect core state until a later reference window admits them.
    if (entry.operation.logicalWindow > referenceWindow) continue;
    // Semantic expiry: retained bytes may still serve as author-prefix
    // evidence, but the operation contributes no active state.
    if (referenceWindow > entry.operation.expiresAfterWindow + skew) continue;
    active.push(entry);
  }

  const activeOperationIds = active.map((entry) => entry.operationId);
  const activePairOuterOperationIds = active
    .filter((entry) => entry.operation.kind === "PAIR_STEP")
    .map((entry) => entry.operationId);

  return {
    version: 1,
    referenceWindow,
    activeOperationIds,
    activePairOuterOperationIds,
    // Sorted by the complete canonical identifying tuple (author key, then
    // logical window), not by a nested proof ID.
    faults: faults.sort(
      (a, b) =>
        compareBytes(a.authorEpochEd25519Key, b.authorEpochEd25519Key) ||
        (a.logicalWindow < b.logicalWindow
          ? -1
          : a.logicalWindow > b.logicalWindow
            ? 1
            : 0),
    ),
    operationsDigest: await coreOperationSetDigest(activeOperationIds),
    pendingPayloadReduction: PENDING_PAYLOAD_REDUCTION,
  };
};
