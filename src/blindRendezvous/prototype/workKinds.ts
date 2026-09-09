/**
 * Outbox work classification for the flagged two-store prototype.
 *
 * Section 4.3 makes every wrap intent carry exactly one `ServiceWorkKindV1`
 * and classifies it with one total `OperationServiceRole` function that public
 * scheduling, the release simulator, outbox reserves, and L3 all share. The
 * prototype needs the same vocabulary so its carrier runtime can label what it
 * publishes, even though it implements neither the append schedule nor the
 * reserved byte regions those roles govern.
 *
 * This metadata is local: it never crosses a carrier and never affects
 * `CoreRoomState`.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import type { PairStepKindV1 } from "../pairPlaintext";

/** Section 4.3: the exact outer kind for live non-pair work, the authenticated
 * sender-known `PairStepBodyV1.kind` for a locally created `PAIR_STEP`, and
 * `REPLICATION_OR_BACKFILL` for every imported copy, replica, and backfill. */
export type ServiceWorkKindV1 =
  | "REPLICATION_OR_BACKFILL"
  | "PRESENCE"
  | "LEAVE"
  | "STORE_HINT"
  | "ADMISSION_REVOKE"
  | PairStepKindV1;

export type OperationServiceRoleV1 =
  "safety-control" | "identity-bootstrap" | "state-replication";

/**
 * `OperationServiceRole(intent)` exactly as Section 4.3 states it. Every kind
 * the union can hold falls through to `safety-control`, which is the
 * conservative branch: it is the only role that may consume any byte region.
 */
export const operationServiceRole = (
  serviceWorkKind: ServiceWorkKindV1,
): OperationServiceRoleV1 => {
  switch (serviceWorkKind) {
    case "REPLICATION_OR_BACKFILL":
      return "state-replication";
    case "IDENTITY_ACCEPT":
    case "IDENTITY_HELLO":
      return "identity-bootstrap";
    case "PRESENCE":
    case "STORE_HINT":
      return "state-replication";
    default:
      return "safety-control";
  }
};
