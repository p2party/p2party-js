/**
 * Effectful pair-open budget reservation boundary.
 *
 * The pure reducer in pairOpenBudget.ts describes the next durable row. This
 * module is the only bridge from that structural transition to permission for
 * one expensive identity-HELLO open: it derives every coordinate and fence
 * from opaque provenance, commits the exact row with one storage CAS, and only
 * then mints an object-identity capability.
 *
 * The storage adapter treats canonical rows as opaque bytes. An IndexedDB
 * implementation performs compare + optional replacement in one readwrite
 * transaction over the Core, receiver-key, and budget stores and resolves
 * "committed" only after `transaction.oncomplete`. No cryptography or other
 * promise is awaited while that transaction is live.
 */

import { bytesEqual } from "./canonicalSchema";
import { localRoomId as deriveLocalRoomId } from "./derivations";
import {
  assertExpectedIdentityHelloTrialReservationLivenessV1,
  snapshotExpectedIdentityHelloTrialReservationProjectionV1,
} from "./identityHelloTrial";
import {
  decodePairOpenBudgetSnapshotV1,
  encodePairOpenBudgetSnapshotV1,
  reducePairOpenBudgetV1,
} from "./pairOpenBudget";
import { snapshotByteInput } from "../cryptography/byteInput";

import type { ActivePairOperationCandidateV1 } from "./coreReduce";
import type { ExpectedIdentityHelloTrialV1 } from "./identityHelloTrial";
import type {
  PairOpenBudgetLimitsV1,
  PairOpenBudgetSnapshotV1,
} from "./pairOpenBudget";

const U64_MAX = 0xffffffffffffffffn;

/** Storage subject shared by the Core, receiver-key, and budget lookups. */
export interface PairOpenBudgetSubjectV1 {
  readonly localRoomId: string;
  readonly localPresenceOperationId: Uint8Array;
}

/**
 * Exact durable budget-row state. `absent` is distinct from malformed, empty,
 * or deleted-and-recreated bytes.
 */
export type ExactPairOpenBudgetRowV1 =
  | {
      readonly kind: "absent";
    }
  | {
      readonly kind: "present";
      readonly exactBytes: Uint8Array;
    };

export interface PairOpenReservationCasRequestV1 {
  readonly subject: PairOpenBudgetSubjectV1;
  /** Exact canonical Core bytes, not only `operationsDigest` or a revision. */
  readonly expectedExactCoreStateBytes: Uint8Array;
  /**
   * Exact canonical HELLO-time Core bytes identifying the complete retained
   * historical evidence view. This may intentionally differ from the current
   * Core fence for a delayed HELLO.
   *
   * The durable row selected by this fence owns the exact presence operations
   * and author prefixes for every observed presence in that Core view. An
   * adapter must conflict if the row or any of that complete evidence is no
   * longer retained.
   */
  readonly expectedExactEvidenceCoreStateBytes: Uint8Array;
  /**
   * Exact revision at the subject's receiver-key row. Revisions must never be
   * reused after replacement or retirement, so deletion cannot create ABA.
   */
  readonly expectedReceiverKeyRecordRevision: bigint;
  /** Exact prior bytes (or exact absence), never revision-only equality. */
  readonly expectedBudgetRow: ExactPairOpenBudgetRowV1;
  readonly budgetMutation:
    | {
        /** A sticky saturated row is still fenced, but needs no rewrite. */
        readonly kind: "keep";
      }
    | {
        /** Canonical prepared or newly saturated replacement bytes. */
        readonly kind: "replace";
        readonly exactNextBytes: Uint8Array;
      };
}

export type PairOpenReservationCasResultV1 =
  | {
      readonly status: "committed";
      /**
       * Exact row visible at commit. For `keep`, this is the prior row; for
       * `replace`, this is the replacement. The service verifies this echo.
       */
      readonly exactBudgetRowBytes: Uint8Array;
    }
  | {
      readonly status: "conflict";
      /**
       * Adapters compare in this order: current Core, historical evidence
       * view, receiver key, then budget row. The first mismatch determines
       * this closed result.
       */
      readonly fence:
        "core" | "historical-evidence" | "receiver-key" | "budget";
    };

/**
 * Minimal byte-store port. Implementations own all input before retaining it
 * and return fresh bytes; this module additionally snapshots every boundary.
 */
export interface PairOpenReservationStorePortV1 {
  /**
   * Read the one current budget row for this room/presence subject. This read
   * need not share a transaction with the later CAS: the exact returned bytes
   * become the CAS fence.
   */
  readExactBudgetRow(
    subject: PairOpenBudgetSubjectV1,
  ): Promise<ExactPairOpenBudgetRowV1>;

  /**
   * In one atomic transaction, compare exact current Core bytes, the complete
   * exact historical-evidence view, receiver-key record revision, and exact
   * budget row/absence, then apply the requested mutation.
   *
   * If physical budget keys include `budgetLogicalWindow`, a replacement that
   * advances the window deletes the old key and writes the new key in this
   * same transaction.
   */
  compareAndSwap(
    request: PairOpenReservationCasRequestV1,
  ): Promise<PairOpenReservationCasResultV1>;
}

declare const reservedIdentityHelloOpenBrand: unique symbol;

/**
 * One process-local permission for one already charged HELLO open.
 *
 * It intentionally exposes no structural fields. Spread, structured clone,
 * persistence, or a type assertion cannot reproduce its WeakMap provenance.
 */
export interface ReservedIdentityHelloOpenV1 {
  readonly [reservedIdentityHelloOpenBrand]: true;
}

export type ReserveIdentityHelloOpenResultV1 =
  | {
      readonly kind: "reserved";
      readonly capability: ReservedIdentityHelloOpenV1;
    }
  | {
      readonly kind: "saturated";
      readonly condition: "pair-control-DoS/stalled";
    }
  | {
      readonly kind: "retry";
      readonly reason: "budget-conflict";
    }
  | {
      readonly kind: "stale";
      readonly reason:
        "core-changed" | "historical-evidence-changed" | "receiver-key-changed";
    };

export interface PairOpenReservationServiceV1 {
  /**
   * Perform one read/reduce/CAS attempt. Budget contention is returned to the
   * deterministic pair scheduler; this method never spins or reorders trials.
   */
  reserveIdentityHelloOpen(
    candidate: ActivePairOperationCandidateV1,
    trial: ExpectedIdentityHelloTrialV1,
  ): Promise<ReserveIdentityHelloOpenResultV1>;
}

export class PairOpenReservationError extends Error {
  override readonly name = "PairOpenReservationError";

  constructor(message: string) {
    super(`pairOpenReservation: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairOpenReservationError(message);
};

interface ReservedIdentityHelloOpenState {
  readonly candidate: ActivePairOperationCandidateV1;
  readonly trial: ExpectedIdentityHelloTrialV1;
}

interface OwnedBudgetRead {
  readonly exact: ExactPairOpenBudgetRowV1;
  readonly snapshot: PairOpenBudgetSnapshotV1 | null;
}

const reservedIdentityHelloOpens = new WeakMap<
  object,
  ReservedIdentityHelloOpenState
>();

const ownBytes = (
  value: unknown,
  label: string,
  exactLength?: number,
): Uint8Array =>
  snapshotByteInput(
    value,
    `pairOpenReservation: ${label}`,
    exactLength === undefined ? {} : { exactLength },
  );

const ownSubject = (
  subject: PairOpenBudgetSubjectV1,
): PairOpenBudgetSubjectV1 => ({
  localRoomId: subject.localRoomId,
  localPresenceOperationId: ownBytes(
    subject.localPresenceOperationId,
    "local presence operation ID",
    32,
  ),
});

const ownExpectedBudgetRow = (
  value: ExactPairOpenBudgetRowV1,
): OwnedBudgetRead => {
  if (value === null || typeof value !== "object")
    return fail("budget read result must be a record");
  if (value.kind === "absent")
    return { exact: { kind: "absent" }, snapshot: null };
  if (value.kind !== "present")
    return fail("budget read result has an unknown kind");

  /*
   * Strict decode owns and proves the borrowed bytes canonical. Re-encoding
   * produces the independently owned exact fence, so later port mutation
   * cannot change either the reducer input or the CAS expectation.
   */
  const snapshot = decodePairOpenBudgetSnapshotV1(value.exactBytes);
  return {
    exact: {
      kind: "present",
      exactBytes: encodePairOpenBudgetSnapshotV1(snapshot),
    },
    snapshot,
  };
};

const copyExactBudgetRow = (
  value: ExactPairOpenBudgetRowV1,
): ExactPairOpenBudgetRowV1 =>
  value.kind === "absent"
    ? { kind: "absent" }
    : {
        kind: "present",
        exactBytes: Uint8Array.from(value.exactBytes),
      };

const classifyConflict = (
  fence: "core" | "historical-evidence" | "receiver-key" | "budget",
): ReserveIdentityHelloOpenResultV1 => {
  switch (fence) {
    case "core":
      return { kind: "stale", reason: "core-changed" };
    case "historical-evidence":
      return { kind: "stale", reason: "historical-evidence-changed" };
    case "receiver-key":
      return { kind: "stale", reason: "receiver-key-changed" };
    case "budget":
      return { kind: "retry", reason: "budget-conflict" };
  }
};

const ownCasResult = (
  value: PairOpenReservationCasResultV1,
  intendedBudgetBytes: Uint8Array,
): PairOpenReservationCasResultV1 => {
  if (value === null || typeof value !== "object")
    return fail("CAS result must be a record");
  if (value.status === "conflict") {
    if (
      value.fence !== "core" &&
      value.fence !== "historical-evidence" &&
      value.fence !== "receiver-key" &&
      value.fence !== "budget"
    )
      return fail("CAS result has an unknown conflict fence");
    return { status: "conflict", fence: value.fence };
  }
  if (value.status !== "committed")
    return fail("CAS result has an unknown status");

  const echo = ownBytes(
    value.exactBudgetRowBytes,
    "committed budget-row echo",
    intendedBudgetBytes.length,
  );
  if (!bytesEqual(echo, intendedBudgetBytes))
    fail("committed budget-row echo does not equal the intended exact bytes");
  return { status: "committed", exactBudgetRowBytes: echo };
};

const mintReservedIdentityHelloOpen = (
  candidate: ActivePairOperationCandidateV1,
  trial: ExpectedIdentityHelloTrialV1,
): ReservedIdentityHelloOpenV1 => {
  const capability = Object.freeze({}) as ReservedIdentityHelloOpenV1;
  reservedIdentityHelloOpens.set(capability, { candidate, trial });
  return capability;
};

/**
 * Create the trusted effectful boundary around one concrete storage adapter.
 *
 * The adapter and validated local resource policy are captured once; callers
 * cannot supply a transition, charge, coordinate, fence, or commit result per
 * trial.
 */
export const createPairOpenReservationServiceV1 = (
  port: PairOpenReservationStorePortV1,
  limits: PairOpenBudgetLimitsV1,
): PairOpenReservationServiceV1 => {
  if (
    port === null ||
    typeof port !== "object" ||
    typeof port.readExactBudgetRow !== "function" ||
    typeof port.compareAndSwap !== "function"
  )
    fail("storage port must implement both reservation methods");

  /*
   * Capture primitive values and bound methods now. Later mutation of the
   * caller's options object or port properties cannot change this service.
   * The pure reducer remains the SSOT that validates the copied limits.
   */
  const ownedLimits: PairOpenBudgetLimitsV1 = {
    maxPairOpenTrialsPerPresenceWindow:
      limits.maxPairOpenTrialsPerPresenceWindow,
    maxPairOpenBytesPerPresenceWindow: limits.maxPairOpenBytesPerPresenceWindow,
  };
  const readExactBudgetRow = port.readExactBudgetRow.bind(port);
  const compareAndSwap = port.compareAndSwap.bind(port);

  return Object.freeze({
    reserveIdentityHelloOpen: async (
      candidate: ActivePairOperationCandidateV1,
      trial: ExpectedIdentityHelloTrialV1,
    ): Promise<ReserveIdentityHelloOpenResultV1> => {
      const projection =
        snapshotExpectedIdentityHelloTrialReservationProjectionV1(
          trial,
          candidate,
        );
      const subject: PairOpenBudgetSubjectV1 = {
        localRoomId: await deriveLocalRoomId(projection.roomContextId),
        localPresenceOperationId: ownBytes(
          projection.localPresenceOperationId,
          "trial local presence operation ID",
          32,
        ),
      };
      const exactCoreStateBytes = ownBytes(
        projection.exactCurrentCoreStateBytes,
        "candidate exact Core state",
      );
      if (exactCoreStateBytes.length === 0)
        fail("candidate exact Core state must not be empty");
      const exactEvidenceCoreStateBytes = ownBytes(
        projection.exactEvidenceCoreStateBytes,
        "historical evidence exact Core state",
      );
      if (exactEvidenceCoreStateBytes.length === 0)
        fail("historical evidence exact Core state must not be empty");
      const receiverKeyRecordRevision = projection.receiverKeyRecordRevision;
      if (
        typeof receiverKeyRecordRevision !== "bigint" ||
        receiverKeyRecordRevision < 0n ||
        receiverKeyRecordRevision > U64_MAX
      )
        fail("receiver-key record revision must be an unsigned 64-bit integer");

      const borrowedBudgetRow = await readExactBudgetRow(ownSubject(subject));
      const previous = ownExpectedBudgetRow(borrowedBudgetRow);
      const transition = reducePairOpenBudgetV1(
        previous.snapshot,
        {
          localRoomId: subject.localRoomId,
          localPresenceOperationId: Uint8Array.from(
            subject.localPresenceOperationId,
          ),
          capturedReferenceWindow: projection.capturedReferenceWindow,
          /*
           * `fixedPayload` is the complete, outer-validated canonical
           * PairStepEnvelopeV1. Whole-operation, ciphertext-only, and carrier
           * byte lengths are deliberately not accepted here.
           */
          completeEnvelopeBytes: projection.completeEnvelopeBytes,
        },
        ownedLimits,
      );

      let budgetMutation: PairOpenReservationCasRequestV1["budgetMutation"];
      let intendedBudgetBytes: Uint8Array;
      if (transition.next === null) {
        if (previous.exact.kind !== "present")
          fail("sticky saturation requires one exact persisted budget row");
        budgetMutation = { kind: "keep" };
        intendedBudgetBytes = Uint8Array.from(previous.exact.exactBytes);
      } else {
        intendedBudgetBytes = encodePairOpenBudgetSnapshotV1(transition.next);
        budgetMutation = {
          kind: "replace",
          exactNextBytes: Uint8Array.from(intendedBudgetBytes),
        };
      }

      const casRequest: PairOpenReservationCasRequestV1 = {
        subject: ownSubject(subject),
        expectedExactCoreStateBytes: Uint8Array.from(exactCoreStateBytes),
        expectedExactEvidenceCoreStateBytes: Uint8Array.from(
          exactEvidenceCoreStateBytes,
        ),
        expectedReceiverKeyRecordRevision: receiverKeyRecordRevision,
        expectedBudgetRow: copyExactBudgetRow(previous.exact),
        budgetMutation,
      };
      const casResult = ownCasResult(
        await compareAndSwap(casRequest),
        intendedBudgetBytes,
      );
      if (casResult.status === "conflict")
        return classifyConflict(casResult.fence);
      if (transition.result === "saturated")
        return {
          kind: "saturated",
          condition: "pair-control-DoS/stalled",
        };

      /*
       * Recheck liveness after the transaction. If another local task consumed
       * the trial or destroyed its receiver custody while storage was pending,
       * budget remains conservatively spent but no unusable crypto capability
       * is minted.
       */
      assertExpectedIdentityHelloTrialReservationLivenessV1(trial, candidate);
      return {
        kind: "reserved",
        capability: mintReservedIdentityHelloOpen(candidate, trial),
      };
    },
  });
};

/**
 * Consume one exact reservation before any trial-secret transfer or KEM work.
 *
 * Deletion is synchronous and precedes return, so reentrancy and a second
 * attempt cannot reuse the capability. The returned value is the opaque
 * candidate privately stored at reservation time; the gated trial-secret
 * transfer compares it to the candidate sealed inside the trial. No
 * structural transition or secret-bearing snapshot is returned.
 *
 * @internal
 */
export const consumeReservedIdentityHelloOpenV1 = (
  capability: ReservedIdentityHelloOpenV1,
  trial: ExpectedIdentityHelloTrialV1,
): ActivePairOperationCandidateV1 => {
  const state =
    typeof capability === "object" && capability !== null
      ? reservedIdentityHelloOpens.get(capability)
      : undefined;
  if (state === undefined)
    fail("open capability must be a genuine unused reservation");
  if (state.trial !== trial) fail("open capability is bound to another trial");
  reservedIdentityHelloOpens.delete(capability);
  return state.candidate;
};
