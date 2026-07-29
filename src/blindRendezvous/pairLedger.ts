/**
 * Pure accepted-slot ledger for pair-private operations.
 *
 * This boundary starts only after pair opening has authenticated an operation
 * and checked its state-derived inner slot. Invalid tag/AEAD trials therefore
 * never consume a slot or routing tag here. Persistence, budgets, pair-machine
 * state, WebRTC effects, and response publication remain outside this module.
 *
 * The coordinate deliberately excludes `kind`: two authenticated kinds at
 * the same edge/endpoint/direction/sequence coordinate are a fork. Consumed
 * routing tags and retained fork-stall evidence are projections of entries,
 * never separately mutable state. The pair machine separately owns overall
 * edge status, including non-fork failures and causal expiry.
 */

import {
  bytes32,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  pairAcceptedSlotCoordinateV1Schema,
  pairAcceptedSlotLedgerSnapshotV1Schema,
  pairSlotAcceptanceCandidateV1Schema,
} from "./schemas";

import type { TypeDescriptor } from "./canonicalSchema";
import type { PairAuthorChainPrefixEvidenceV1 } from "./coreReduce";
import type { PairStepKindV1 } from "./pairPlaintext";

declare const pairAcceptedSlotLedgerBrand: unique symbol;

/** Process-local immutable ledger handle. Persist only its canonical snapshot. */
export interface PairAcceptedSlotLedgerV1 {
  readonly [pairAcceptedSlotLedgerBrand]: true;
}

export interface PairAcceptedSlotCoordinateV1 {
  readonly pairEdgeId: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
  readonly direction: 0 | 1;
  readonly pairSequence: bigint;
}

/**
 * Structural input for the post-authentication boundary.
 *
 * Production pair ingress must construct this only from its opaque successful
 * open result. This ledger owns and validates the shape but does not itself
 * prove pair AEAD, signatures, bindings, or operation-ID derivation.
 */
export interface PairSlotAcceptanceCandidateV1 {
  readonly coordinate: PairAcceptedSlotCoordinateV1;
  readonly kind: PairStepKindV1;
  readonly acceptedOperationId: Uint8Array;
  readonly exactOperationBytes: Uint8Array;
  readonly acceptedLogicalWindow: bigint;
  readonly retainThroughLogicalWindow: bigint;
  readonly routingTag: Uint8Array;
  readonly authorChainPrefix: readonly PairAuthorChainPrefixEvidenceV1[];
  readonly cachedExactResponse: Uint8Array | null;
}

export interface PairAcceptedSlotEntryV1 extends PairSlotAcceptanceCandidateV1 {
  readonly version: 1;
  /**
   * Bytewise-lowest two distinct authenticated IDs observed at this
   * coordinate. These are a bounded fork-evidence index; the validated outer
   * operation store remains the SSOT for the referenced signed bytes.
   */
  readonly forkProofOperationIds: readonly [Uint8Array, Uint8Array] | null;
}

/** Durable, deeply owned structural representation. */
export interface PairAcceptedSlotLedgerSnapshotV1 {
  readonly version: 1;
  readonly entries: readonly PairAcceptedSlotEntryV1[];
}

export type PairAcceptedSlotTransitionV1 =
  | {
      readonly result: "accepted";
      readonly ledger: PairAcceptedSlotLedgerV1;
    }
  | {
      readonly result: "replay";
      /** Exact cached bytes are freshly owned by this result. */
      readonly cachedExactResponse: Uint8Array | null;
      /** Replay is a no-op and preserves handle identity. */
      readonly ledger: PairAcceptedSlotLedgerV1;
    }
  | {
      readonly result: "fork";
      readonly forkProofOperationIds: readonly [Uint8Array, Uint8Array];
      readonly ledger: PairAcceptedSlotLedgerV1;
    }
  | {
      readonly result: "edge-stalled";
      readonly ledger: PairAcceptedSlotLedgerV1;
    };

/**
 * Read-only classification at the authenticated pair-slot boundary.
 *
 * `unoccupied` is deliberately not called `accepted`: no durable entry or
 * fork proof exists until `recordAcceptedPairSlotV1` succeeds.
 */
export type AuthenticatedPairSlotPreviewV1 =
  | { readonly result: "unoccupied" }
  | {
      readonly result: "replay";
      /** Exact cached bytes are freshly owned by this result. */
      readonly cachedExactResponse: Uint8Array | null;
    }
  | {
      readonly result: "fork";
      readonly forkProofOperationIds: readonly [Uint8Array, Uint8Array];
    }
  | { readonly result: "edge-stalled" };

export class PairLedgerError extends Error {
  override readonly name = "PairLedgerError";

  constructor(message: string) {
    super(`pairLedger: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairLedgerError(message);
};

interface InternalEntry {
  readonly value: PairAcceptedSlotEntryV1;
  /** Canonical coordinate bytes are the sole ordering key. */
  readonly coordinateKey: Uint8Array;
}

interface InternalState {
  readonly entries: readonly InternalEntry[];
}

const ledgerStates = new WeakMap<object, InternalState>();

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const bytesKey = (value: Uint8Array): string => {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
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

const validateCandidateSemantics = (
  candidate: PairSlotAcceptanceCandidateV1,
  name: string,
): void => {
  if (candidate.coordinate.endpointPresenceOperationIds.length !== 2)
    fail(`${name}.coordinate must name exactly two endpoint presences`);
  if (
    candidate.coordinate.direction !== 0 &&
    candidate.coordinate.direction !== 1
  )
    fail(`${name}.coordinate.direction must be 0 or 1`);
  if (candidate.exactOperationBytes.length === 0)
    fail(`${name}.exactOperationBytes must not be empty`);
  if (candidate.retainThroughLogicalWindow < candidate.acceptedLogicalWindow)
    fail(`${name} retention ends before its accepted logical window`);
  if (candidate.cachedExactResponse?.length === 0)
    fail(`${name}.cachedExactResponse must be null or non-empty`);
  if (candidate.authorChainPrefix.length === 0)
    fail(`${name}.authorChainPrefix must not be empty`);

  const prefixOperationIds = new Set<string>();
  for (let index = 0; index < candidate.authorChainPrefix.length; index++) {
    const evidence = candidate.authorChainPrefix[index];
    if (evidence.exactOperationBytes.length === 0)
      fail(
        `${name}.authorChainPrefix[${String(index)}].exactOperationBytes must not be empty`,
      );
    const operationIdKey = bytesKey(evidence.operationId);
    if (prefixOperationIds.has(operationIdKey))
      fail(`${name}.authorChainPrefix must contain unique operation IDs`);
    prefixOperationIds.add(operationIdKey);
  }

  const tail = candidate.authorChainPrefix.at(-1);
  if (
    tail === undefined ||
    !bytesEqual(tail.operationId, candidate.acceptedOperationId) ||
    !bytesEqual(tail.exactOperationBytes, candidate.exactOperationBytes)
  )
    fail(
      `${name}.authorChainPrefix must end with the exact accepted operation`,
    );
};

const ownCandidate = (
  value: unknown,
  name = "candidate",
): PairSlotAcceptanceCandidateV1 => {
  const candidate = canonicalOwned<PairSlotAcceptanceCandidateV1>(
    pairSlotAcceptanceCandidateV1Schema,
    value,
  );
  validateCandidateSemantics(candidate, name);
  return candidate;
};

const validatePersistableCandidateSemantics = (
  candidate: PairSlotAcceptanceCandidateV1,
  name: string,
): void => {
  if (
    candidate.kind === "IDENTITY_HELLO" &&
    candidate.cachedExactResponse === null
  )
    fail(
      `${name}.cachedExactResponse must be non-null for durable IDENTITY_HELLO acceptance`,
    );
};

const validateEntrySemantics = (
  entry: PairAcceptedSlotEntryV1,
  name: string,
): void => {
  if (entry.version !== 1) fail(`${name}.version must be 1`);
  validateCandidateSemantics(entry, name);
  validatePersistableCandidateSemantics(entry, name);
  if (
    entry.forkProofOperationIds !== null &&
    entry.forkProofOperationIds.length !== 2
  )
    fail(`${name}.forkProofOperationIds must contain exactly two IDs`);
};

const coordinateKey = (coordinate: PairAcceptedSlotCoordinateV1): Uint8Array =>
  encodeCanonical(pairAcceptedSlotCoordinateV1Schema, coordinate);

const internalEntry = (value: PairAcceptedSlotEntryV1): InternalEntry =>
  Object.freeze({
    value,
    coordinateKey: coordinateKey(value.coordinate),
  });

const createHandle = (
  entries: readonly InternalEntry[],
): PairAcceptedSlotLedgerV1 => {
  const handle = Object.freeze({}) as PairAcceptedSlotLedgerV1;
  ledgerStates.set(handle, Object.freeze({ entries: Object.freeze(entries) }));
  return handle;
};

const requireState = (ledger: PairAcceptedSlotLedgerV1): InternalState => {
  if (typeof ledger !== "object" || ledger === null)
    return fail("ledger must be a genuine process-local handle");
  const state = ledgerStates.get(ledger);
  if (state === undefined)
    return fail("ledger must be a genuine process-local handle");
  return state;
};

const candidateEntry = (
  candidate: PairSlotAcceptanceCandidateV1,
  forkProofOperationIds: readonly [Uint8Array, Uint8Array] | null,
): PairAcceptedSlotEntryV1 => ({
  version: 1,
  coordinate: candidate.coordinate,
  kind: candidate.kind,
  acceptedOperationId: candidate.acceptedOperationId,
  exactOperationBytes: candidate.exactOperationBytes,
  acceptedLogicalWindow: candidate.acceptedLogicalWindow,
  retainThroughLogicalWindow: candidate.retainThroughLogicalWindow,
  routingTag: candidate.routingTag,
  authorChainPrefix: candidate.authorChainPrefix,
  cachedExactResponse: candidate.cachedExactResponse,
  forkProofOperationIds,
});

const lowerBoundEntry = (
  entries: readonly InternalEntry[],
  key: Uint8Array,
): number => {
  let low = 0;
  let high = entries.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (compareBytes(entries[middle].coordinateKey, key) < 0) low = middle + 1;
    else high = middle;
  }
  return low;
};

const canonicalForkProof = (
  entry: PairAcceptedSlotEntryV1,
  candidateOperationId: Uint8Array,
): readonly [Uint8Array, Uint8Array] => {
  const candidates = [
    entry.acceptedOperationId,
    ...(entry.forkProofOperationIds ?? []),
    candidateOperationId,
  ].sort(compareBytes);
  const unique: Uint8Array[] = [];
  for (const operationId of candidates) {
    if (
      unique.length === 0 ||
      !bytesEqual(unique[unique.length - 1], operationId)
    )
      unique.push(operationId);
  }
  if (unique.length < 2)
    return fail("a fork proof requires two distinct operation IDs");
  return [Uint8Array.from(unique[0]), Uint8Array.from(unique[1])];
};

const proofOut = (
  proof: readonly [Uint8Array, Uint8Array],
): readonly [Uint8Array, Uint8Array] => [
  Uint8Array.from(proof[0]),
  Uint8Array.from(proof[1]),
];

const cachedResponseOut = (
  entry: PairAcceptedSlotEntryV1,
): Uint8Array | null =>
  entry.cachedExactResponse === null
    ? null
    : Uint8Array.from(entry.cachedExactResponse);

const edgeIsStalled = (state: InternalState, pairEdgeId: Uint8Array): boolean =>
  state.entries.some(
    ({ value }) =>
      value.forkProofOperationIds !== null &&
      bytesEqual(value.coordinate.pairEdgeId, pairEdgeId),
  );

const entryOperationIds = (
  entry: PairAcceptedSlotEntryV1,
): readonly Uint8Array[] => [
  entry.acceptedOperationId,
  ...(entry.forkProofOperationIds ?? []),
];

const validateGlobalEntrySemantics = (
  entries: readonly InternalEntry[],
): void => {
  const operationCoordinates = new Map<string, Uint8Array>();
  const routingTagCoordinates = new Map<string, Uint8Array>();

  for (const entry of entries) {
    for (const operationId of entryOperationIds(entry.value)) {
      const key = bytesKey(operationId);
      const priorCoordinate = operationCoordinates.get(key);
      if (
        priorCoordinate !== undefined &&
        compareBytes(priorCoordinate, entry.coordinateKey) !== 0
      )
        fail("one operation ID must not bind two pair-slot coordinates");
      operationCoordinates.set(key, entry.coordinateKey);
    }

    const tagKey = bytesKey(entry.value.routingTag);
    const priorCoordinate = routingTagCoordinates.get(tagKey);
    if (
      priorCoordinate !== undefined &&
      compareBytes(priorCoordinate, entry.coordinateKey) !== 0
    )
      fail("one-use routing tags must be unique across pair-slot coordinates");
    routingTagCoordinates.set(tagKey, entry.coordinateKey);
  }
};

const assertCandidateCoordinateOwnership = (
  state: InternalState,
  candidate: PairSlotAcceptanceCandidateV1,
  candidateCoordinateKey: Uint8Array,
): void => {
  for (const entry of state.entries) {
    if (
      entryOperationIds(entry.value).some((operationId) =>
        bytesEqual(operationId, candidate.acceptedOperationId),
      ) &&
      compareBytes(entry.coordinateKey, candidateCoordinateKey) !== 0
    )
      fail("one operation ID must not bind two pair-slot coordinates");
    if (
      bytesEqual(entry.value.routingTag, candidate.routingTag) &&
      compareBytes(entry.coordinateKey, candidateCoordinateKey) !== 0
    )
      fail("one-use routing tags must be unique across pair-slot coordinates");
  }
};

type InternalAuthenticatedPairSlotClassificationV1 = {
  readonly state: InternalState;
  readonly candidate: PairSlotAcceptanceCandidateV1;
  readonly at: number;
} & (
  | { readonly result: "unoccupied" }
  | {
      readonly result: "replay";
      readonly existing: InternalEntry;
    }
  | {
      readonly result: "fork";
      readonly existing: InternalEntry;
      readonly forkProofOperationIds: readonly [Uint8Array, Uint8Array];
      readonly proofAlreadyRecorded: boolean;
    }
  | { readonly result: "edge-stalled" }
);

/**
 * The single validated lookup path shared by read-only preview and mutation.
 * Preserve the ordering here: coordinate conflicts precede edge-stall checks,
 * while a stalled edge masks cross-coordinate ownership errors as before.
 */
const classifyAuthenticatedPairSlot = (
  ledger: PairAcceptedSlotLedgerV1,
  candidateValue: PairSlotAcceptanceCandidateV1,
): InternalAuthenticatedPairSlotClassificationV1 => {
  const state = requireState(ledger);
  const candidate = ownCandidate(candidateValue);
  const key = coordinateKey(candidate.coordinate);
  const at = lowerBoundEntry(state.entries, key);
  const existing = state.entries[at];
  const common = {
    state,
    candidate,
    at,
  };

  if (
    existing !== undefined &&
    compareBytes(existing.coordinateKey, key) === 0
  ) {
    assertCandidateCoordinateOwnership(state, candidate, key);
    if (
      bytesEqual(
        existing.value.acceptedOperationId,
        candidate.acceptedOperationId,
      )
    )
      return { ...common, result: "replay", existing };

    const proof = canonicalForkProof(
      existing.value,
      candidate.acceptedOperationId,
    );
    return {
      ...common,
      result: "fork",
      existing,
      forkProofOperationIds: proof,
      proofAlreadyRecorded:
        existing.value.forkProofOperationIds !== null &&
        bytesEqual(existing.value.forkProofOperationIds[0], proof[0]) &&
        bytesEqual(existing.value.forkProofOperationIds[1], proof[1]),
    };
  }

  if (edgeIsStalled(state, candidate.coordinate.pairEdgeId))
    return { ...common, result: "edge-stalled" };

  assertCandidateCoordinateOwnership(state, candidate, key);
  return { ...common, result: "unoccupied" };
};

/** Create the unique empty ledger value. */
export const createEmptyPairAcceptedSlotLedgerV1 =
  (): PairAcceptedSlotLedgerV1 => createHandle([]);

/** Deep-copy the complete state for the durable transaction adapter. */
export const snapshotPairAcceptedSlotLedgerV1 = (
  ledger: PairAcceptedSlotLedgerV1,
): PairAcceptedSlotLedgerSnapshotV1 =>
  canonicalOwned<PairAcceptedSlotLedgerSnapshotV1>(
    pairAcceptedSlotLedgerSnapshotV1Schema,
    {
      version: 1,
      entries: requireState(ledger).entries.map(({ value }) => value),
    },
  );

/**
 * Strict structural reconstruction boundary.
 *
 * This restores ledger shape and invariants, not cryptographic provenance.
 * The durable pair transaction must revalidate exact accepted operation bytes
 * and pair state before using a restored ledger for protocol effects.
 */
export const restorePairAcceptedSlotLedgerV1 = (
  snapshotValue: unknown,
): PairAcceptedSlotLedgerV1 => {
  const snapshot = canonicalOwned<PairAcceptedSlotLedgerSnapshotV1>(
    pairAcceptedSlotLedgerSnapshotV1Schema,
    snapshotValue,
  );
  if (snapshot.version !== 1) fail("snapshot.version must be 1");

  const entries = snapshot.entries.map((entry, index) => {
    validateEntrySemantics(entry, `snapshot.entries[${String(index)}]`);
    return internalEntry(entry);
  });
  for (let index = 1; index < entries.length; index++) {
    const order = compareBytes(
      entries[index - 1].coordinateKey,
      entries[index].coordinateKey,
    );
    if (order >= 0)
      fail(
        order === 0
          ? "snapshot entries must have unique coordinates"
          : "snapshot entries must be canonically sorted",
      );
  }
  validateGlobalEntrySemantics(entries);
  return createHandle(entries);
};

/**
 * Classify one fully authenticated candidate without creating any durable
 * entry, fork proof, consumed-tag projection, or replacement ledger handle.
 *
 * A new IDENTITY_HELLO may be previewed with a null cached response so the
 * caller can run admission and construct that response. The subsequent record
 * call revalidates the candidate and requires the exact response atomically.
 */
export const previewAuthenticatedPairSlotV1 = (
  ledger: PairAcceptedSlotLedgerV1,
  candidateValue: PairSlotAcceptanceCandidateV1,
): AuthenticatedPairSlotPreviewV1 => {
  const classification = classifyAuthenticatedPairSlot(ledger, candidateValue);
  switch (classification.result) {
    case "unoccupied":
      return { result: "unoccupied" };
    case "replay":
      return {
        result: "replay",
        cachedExactResponse: cachedResponseOut(classification.existing.value),
      };
    case "fork":
      return {
        result: "fork",
        forkProofOperationIds: proofOut(classification.forkProofOperationIds),
      };
    case "edge-stalled":
      return { result: "edge-stalled" };
  }
};

/**
 * Record one already fully authenticated pair operation.
 *
 * Exact ID replays return the persisted response. A different ID at the same
 * coordinate records a bounded proof and stalls only that retained edge.
 */
export const recordAcceptedPairSlotV1 = (
  ledger: PairAcceptedSlotLedgerV1,
  candidateValue: PairSlotAcceptanceCandidateV1,
): PairAcceptedSlotTransitionV1 => {
  const classification = classifyAuthenticatedPairSlot(ledger, candidateValue);
  switch (classification.result) {
    case "replay":
      return {
        result: "replay",
        cachedExactResponse: cachedResponseOut(classification.existing.value),
        ledger,
      };
    case "fork": {
      if (classification.proofAlreadyRecorded)
        return {
          result: "fork",
          forkProofOperationIds: proofOut(classification.forkProofOperationIds),
          ledger,
        };

      const entries = [...classification.state.entries];
      entries[classification.at] = internalEntry(
        candidateEntry(
          classification.existing.value,
          classification.forkProofOperationIds,
        ),
      );
      const next = createHandle(entries);
      return {
        result: "fork",
        forkProofOperationIds: proofOut(classification.forkProofOperationIds),
        ledger: next,
      };
    }
    case "edge-stalled":
      return { result: "edge-stalled", ledger };
    case "unoccupied": {
      validatePersistableCandidateSemantics(
        classification.candidate,
        "candidate",
      );
      const entries = [...classification.state.entries];
      entries.splice(
        classification.at,
        0,
        internalEntry(candidateEntry(classification.candidate, null)),
      );
      return { result: "accepted", ledger: createHandle(entries) };
    }
  }
};

/** True exactly while retained fork evidence stalls this edge. */
export const pairEdgeIsStalledV1 = (
  ledger: PairAcceptedSlotLedgerV1,
  pairEdgeId: Uint8Array,
): boolean => {
  const ownedEdgeId = canonicalOwned<Uint8Array>(bytes32, pairEdgeId);
  return edgeIsStalled(requireState(ledger), ownedEdgeId);
};

/**
 * Canonical unique routing-tag projection. There is intentionally no
 * separately persisted consumed-tag collection.
 */
export const consumedPairRoutingTagsV1 = (
  ledger: PairAcceptedSlotLedgerV1,
): readonly Uint8Array[] => {
  const tags = requireState(ledger)
    .entries.map(({ value }) => value.routingTag)
    .sort(compareBytes);
  const result: Uint8Array[] = [];
  for (const tag of tags) {
    if (result.length === 0 || !bytesEqual(result[result.length - 1], tag))
      result.push(Uint8Array.from(tag));
  }
  return result;
};
