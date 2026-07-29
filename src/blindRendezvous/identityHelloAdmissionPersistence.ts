/**
 * Exact persistence contract for HELLO-responder admission.
 *
 * This module is deliberately declarative. It defines the one atomic capture,
 * fixed compare-and-swap fence order, and closed write masks that a concrete
 * store adapter must implement. It does not expose an executable claim-to-CAS
 * path: only the trusted admission/response orchestrator may eventually build
 * a mutation from canonical rows and spend its opaque prepared handle.
 *
 * The adapter's read result is untrusted until
 * `validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1` accepts it. This
 * source-internal module is absent from the package barrel.
 */

import { MAX_CANONICAL_ENCODING_BYTES } from "./canonicalSchema";
import { snapshotByteInput } from "../cryptography/byteInput";

const U64_MAX = 0xffffffffffffffffn;

/** Exact absence is a fence and is never represented by empty bytes. */
export type ExactIdentityHelloAdmissionRowV1 =
  | {
      readonly kind: "absent";
    }
  | {
      readonly kind: "present";
      readonly exactBytes: Uint8Array;
    };

/** Revisioned key custody uses a non-reused u64 revision to prevent ABA. */
export type ExactIdentityHelloAdmissionRevisionV1 =
  | {
      readonly kind: "absent";
    }
  | {
      readonly kind: "present";
      readonly recordRevision: bigint;
    };

/**
 * Lookup coordinates derived only from a genuine authenticated HELLO claim.
 * Applications and adapters may not select any of these values.
 */
export interface IdentityHelloAdmissionReadLocatorV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly helloOperationId: Uint8Array;
  readonly pairEdgeId: Uint8Array;
  readonly localPresenceOperationId: Uint8Array;
  readonly exactHistoricalEvidenceCoreStateBytes: Uint8Array;
}

/**
 * Complete read result from one atomic read-only transaction.
 *
 * `historicalEvidence` is the canonical pair-subject evidence bundle selected
 * by the exact HELLO-time Core bytes: that exact Core row plus the remote and
 * local endpoint PRESENCE operations and their required author prefixes.
 */
export interface IdentityHelloAdmissionExactCaptureRowsV1 {
  readonly initializedRoom: ExactIdentityHelloAdmissionRowV1;
  readonly currentCore: ExactIdentityHelloAdmissionRowV1;
  readonly historicalEvidence: ExactIdentityHelloAdmissionRowV1;
  readonly receiverKey: ExactIdentityHelloAdmissionRevisionV1;
  readonly localPresenceOwnership: ExactIdentityHelloAdmissionRowV1;
  readonly frontendControls: ExactIdentityHelloAdmissionRowV1;
  readonly authorityCustody: ExactIdentityHelloAdmissionRowV1;
  readonly plannerAndExplicitState: ExactIdentityHelloAdmissionRowV1;
  readonly localIdentityKey: ExactIdentityHelloAdmissionRevisionV1;
  readonly localAuthorHead: ExactIdentityHelloAdmissionRowV1;
  readonly pairLedger: ExactIdentityHelloAdmissionRowV1;
  readonly provisionalPair: ExactIdentityHelloAdmissionRowV1;
  readonly identityBootstrapOutbox: ExactIdentityHelloAdmissionRowV1;
  readonly resourceState: ExactIdentityHelloAdmissionRowV1;
}

/** Normative first-conflict order for the admission transaction. */
export const IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1 = Object.freeze([
  "initialized-room",
  "current-core",
  "historical-evidence",
  "receiver-key",
  "local-presence-ownership",
  "frontend-controls",
  "authority-custody",
  "planner-and-explicit-state",
  "local-identity-key",
  "local-author-head",
  "pair-ledger",
  "provisional-pair",
  "identity-bootstrap-outbox",
  "resource-state",
] as const);

export type IdentityHelloAdmissionCasConflictFenceV1 =
  (typeof IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1)[number];

interface ExactPresentIdentityHelloAdmissionRowV1 {
  readonly kind: "present";
  readonly exactBytes: Uint8Array;
}

/**
 * Closed write masks for the three legal persistence transitions.
 *
 * These are an adapter contract, not caller input. A later trusted transition
 * must construct every row from canonical codecs and prove that the same
 * ACCEPT operation ID is bound through the author head, pair ledger,
 * provisional pair, outbox, and resource reservation.
 */
export type PreparedIdentityHelloAdmissionMutationV1 =
  | {
      readonly kind: "accept-new";
      readonly nextLocalAuthorHead: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextPairLedger: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextProvisionalPair: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextIdentityBootstrapOutbox: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextResourceState: ExactPresentIdentityHelloAdmissionRowV1;
    }
  | {
      readonly kind: "requeue-replay";
      readonly nextIdentityBootstrapOutbox: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextResourceState: ExactPresentIdentityHelloAdmissionRowV1;
    }
  | {
      readonly kind: "record-fork";
      readonly nextPairLedger: ExactPresentIdentityHelloAdmissionRowV1;
      readonly nextResourceState: ExactPresentIdentityHelloAdmissionRowV1;
    };

export interface IdentityHelloAdmissionCasRequestV1 {
  readonly locator: IdentityHelloAdmissionReadLocatorV1;
  readonly expected: IdentityHelloAdmissionExactCaptureRowsV1;
  readonly mutation: PreparedIdentityHelloAdmissionMutationV1;
}

/** Complete mutable-row echo after a successful durable commit. */
export interface IdentityHelloAdmissionCommittedRowsV1 {
  readonly localAuthorHead: ExactIdentityHelloAdmissionRowV1;
  readonly pairLedger: ExactIdentityHelloAdmissionRowV1;
  readonly provisionalPair: ExactIdentityHelloAdmissionRowV1;
  readonly identityBootstrapOutbox: ExactIdentityHelloAdmissionRowV1;
  readonly resourceState: ExactIdentityHelloAdmissionRowV1;
}

export type IdentityHelloAdmissionPortCasResultV1 =
  | {
      readonly status: "committed";
      readonly committedRows: IdentityHelloAdmissionCommittedRowsV1;
    }
  | {
      readonly status: "conflict";
      readonly fence: IdentityHelloAdmissionCasConflictFenceV1;
    };

/**
 * Minimal byte-store port.
 *
 * `readExactCapture` performs one read-only transaction over every named row,
 * owns all returned bytes, and resolves only from `transaction.oncomplete`.
 *
 * `compareAndSwap` performs one read-write transaction, compares exact bytes,
 * exact absence, and non-reused revisions in the normative order, applies the
 * closed mutation only if every fence matches, and resolves only from
 * `transaction.oncomplete`. It performs no crypto and awaits no promise while
 * the IndexedDB transaction is live.
 */
export interface IdentityHelloAdmissionPersistencePortV1 {
  readExactCapture(
    locator: IdentityHelloAdmissionReadLocatorV1,
  ): Promise<IdentityHelloAdmissionExactCaptureRowsV1>;

  compareAndSwap(
    request: IdentityHelloAdmissionCasRequestV1,
  ): Promise<IdentityHelloAdmissionPortCasResultV1>;
}

export class IdentityHelloAdmissionPersistenceError extends Error {
  override readonly name = "IdentityHelloAdmissionPersistenceError";

  constructor(message: string) {
    super(`identityHelloAdmissionPersistence: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new IdentityHelloAdmissionPersistenceError(message);
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

const ownBytes = (value: unknown, label: string): Uint8Array => {
  const bytes = snapshotByteInput(
    value,
    `identityHelloAdmissionPersistence: ${label}`,
    { maximumLength: MAX_CANONICAL_ENCODING_BYTES },
  );
  if (bytes.length === 0) return fail(`${label} must not be empty`);
  return bytes;
};

const ownExactRow = (
  value: unknown,
  label: string,
): ExactIdentityHelloAdmissionRowV1 => {
  if (hasExactOwnDataFields(value, ["kind"]) && value.kind === "absent")
    return { kind: "absent" };
  if (
    !hasExactOwnDataFields(value, ["kind", "exactBytes"]) ||
    value.kind !== "present"
  )
    return fail(`${label} must be an exact present/absent row`);
  return {
    kind: "present",
    exactBytes: ownBytes(value.exactBytes, `${label} bytes`),
  };
};

const ownExactRevision = (
  value: unknown,
  label: string,
): ExactIdentityHelloAdmissionRevisionV1 => {
  if (hasExactOwnDataFields(value, ["kind"]) && value.kind === "absent")
    return { kind: "absent" };
  if (
    !hasExactOwnDataFields(value, ["kind", "recordRevision"]) ||
    value.kind !== "present" ||
    typeof value.recordRevision !== "bigint" ||
    value.recordRevision < 0n ||
    value.recordRevision > U64_MAX
  )
    return fail(`${label} must be an exact present/absent u64 revision`);
  return { kind: "present", recordRevision: value.recordRevision };
};

const CAPTURE_ROW_FIELDS = [
  "initializedRoom",
  "currentCore",
  "historicalEvidence",
  "receiverKey",
  "localPresenceOwnership",
  "frontendControls",
  "authorityCustody",
  "plannerAndExplicitState",
  "localIdentityKey",
  "localAuthorHead",
  "pairLedger",
  "provisionalPair",
  "identityBootstrapOutbox",
  "resourceState",
] as const;

/**
 * Deeply own and structurally validate one complete adapter capture.
 *
 * This is only the byte/absence/revision boundary. The trusted admission
 * orchestrator must canonical-decode and correlate every required row before
 * it can mint any subsequent opaque capability.
 *
 * @internal
 */
export const validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1 = (
  value: unknown,
): IdentityHelloAdmissionExactCaptureRowsV1 => {
  if (!hasExactOwnDataFields(value, CAPTURE_ROW_FIELDS))
    return fail("capture rows must contain exactly every declared fence");
  return {
    initializedRoom: ownExactRow(value.initializedRoom, "initialized room"),
    currentCore: ownExactRow(value.currentCore, "current Core"),
    historicalEvidence: ownExactRow(
      value.historicalEvidence,
      "historical evidence",
    ),
    receiverKey: ownExactRevision(value.receiverKey, "receiver key"),
    localPresenceOwnership: ownExactRow(
      value.localPresenceOwnership,
      "local presence ownership",
    ),
    frontendControls: ownExactRow(value.frontendControls, "frontend controls"),
    authorityCustody: ownExactRow(value.authorityCustody, "authority custody"),
    plannerAndExplicitState: ownExactRow(
      value.plannerAndExplicitState,
      "planner and explicit state",
    ),
    localIdentityKey: ownExactRevision(
      value.localIdentityKey,
      "local identity key",
    ),
    localAuthorHead: ownExactRow(value.localAuthorHead, "local author head"),
    pairLedger: ownExactRow(value.pairLedger, "pair ledger"),
    provisionalPair: ownExactRow(value.provisionalPair, "provisional pair"),
    identityBootstrapOutbox: ownExactRow(
      value.identityBootstrapOutbox,
      "identity bootstrap outbox",
    ),
    resourceState: ownExactRow(value.resourceState, "resource state"),
  };
};
