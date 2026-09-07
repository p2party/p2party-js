/**
 * Typed encode/decode wrappers for the prototype-v0 store wire.
 *
 * The descriptors in `schemas.ts` are the only authority for these bytes;
 * this module is a projection of them, exactly as `projections.ts` is for the
 * release schemas. It exists so the prototype store server and the client
 * adapter call one encoder each way instead of two hand-rolled ones, and so a
 * caller gets a named type rather than `unknown` back from the codec.
 *
 * Every decoder is `decodeCanonicalStrict`: a store answer is attacker-shaped
 * input, and re-encoding proves the bytes are the unique encoding of the value
 * before a signature is checked over them.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry, and nothing here is a v0.4 release artifact.
 */

import { decodeCanonicalStrict, encodeCanonical } from "../canonicalSchema";
import {
  allocationTokenIssueRequestV1Schema,
  allocationTokenIssueResultBodyV1Schema,
  allocationTokenIssueResultV1Schema,
  prototypeStoreDescriptorDocumentV1Schema,
  publicAllocationLeaseBodyV1Schema,
  publicAllocationLeaseV1Schema,
  publicAllocationRequestV1Schema,
  publicAllocationResultV1Schema,
  publicAllocationStatusBodyV1Schema,
  publicAppendAdmissionV1Schema,
  publicAppendRequestV1Schema,
  publicAppendResultBodyV1Schema,
  publicAppendResultV1Schema,
  publicAppendStatusV1Schema,
  publicChunkReadV1Schema,
  publicChunkStatusBodyV1Schema,
  publicStoreCheckpointReadV1Schema,
  publicStoreCheckpointStatusBodyV1Schema,
  storeWitnessRecordV1Schema,
  storeWitnessRecordsV1Schema,
} from "../schemas";

import type {
  PublicBucketV1,
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../publicWindow";
import type { StoreDescriptorV1, StoreRouteV1 } from "../storeDescriptor";

/* ------------------------------------------------------------------ *
 * Types
 *
 * Interface order is readability order; wire order is the descriptor's.
 * ------------------------------------------------------------------ */

export interface PublicAllocationLeaseBodyV1 {
  version: 1;
  storeId: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  requestHash: Uint8Array;
  allocationOrdinal: number;
  allocationEd25519PublicKey: Uint8Array;
}

export type PublicAllocationLeaseV1 = PublicAllocationLeaseBodyV1 & {
  storeSignature: Uint8Array;
};

export interface PublicAppendAdmissionV1 {
  version: 1;
  lease: PublicAllocationLeaseV1;
  objectOrdinalWithinAllocation: number;
  allocationSignature: Uint8Array;
}

export interface PublicAppendRequestV1 {
  version: 1;
  bucket: PublicBucketV1;
  exactFixedObject: Uint8Array;
  /** `null` is an unallocated cover append: accepted, then discarded. */
  admission: PublicAppendAdmissionV1 | null;
}

export type PublicAppendStatusV1 =
  | "stored"
  | "already-present"
  | "slot-conflict"
  | "unallocated-cover"
  | "window-finalized"
  | "capacity-exhausted";

export interface PublicAppendResultBodyV1 {
  version: 1;
  storeId: Uint8Array;
  descriptorHash: Uint8Array;
  bucket: PublicBucketV1;
  requestHash: Uint8Array;
  status: PublicAppendStatusV1;
  fixedStatusPadding: Uint8Array;
}

export type PublicAppendResultV1 = PublicAppendResultBodyV1 & {
  storeSignature: Uint8Array;
};

export interface AllocationTokenIssueRequestV1 {
  version: 1;
  storeId: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  privacyPassTokenRequest: Uint8Array;
}

export type AllocationTokenIssueStatusKindV1 =
  "quota-denied" | "invalid-request" | "issuer-unavailable";

export type AllocationTokenIssueResultBodyV1 =
  | {
      kind: "issued";
      version: 1;
      requestHash: Uint8Array;
      privacyPassTokenResponse: Uint8Array;
    }
  | {
      kind: "status";
      version: 1;
      requestHash: Uint8Array;
      status: AllocationTokenIssueStatusKindV1;
      fixedErrorPadding: Uint8Array;
    };

/** The signature wraps the union body; `body` is exactly what is signed. */
export interface AllocationTokenIssueResultV1 {
  body: AllocationTokenIssueResultBodyV1;
  storeSignature: Uint8Array;
}

export interface PublicAllocationRequestV1 {
  version: 1;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  allocationEd25519PublicKey: Uint8Array;
  privacyPassToken: Uint8Array;
}

export type PublicAllocationStatusKindV1 =
  "invalid-token" | "token-spent" | "capacity-exhausted" | "window-closed";

export interface PublicAllocationStatusBodyV1 {
  version: 1;
  storeId: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  requestHash: Uint8Array;
  status: PublicAllocationStatusKindV1;
  fixedErrorPadding: Uint8Array;
}

export type PublicAllocationResultV1 =
  | { kind: "allocated"; lease: PublicAllocationLeaseV1 }
  | {
      kind: "status";
      value: PublicAllocationStatusBodyV1;
      storeSignature: Uint8Array;
    };

export type PublicStoreCheckpointStatusKindV1 =
  "not-final" | "out-of-range" | "chain-unavailable";

export interface PublicStoreCheckpointStatusBodyV1 {
  version: 1;
  storeId: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  status: PublicStoreCheckpointStatusKindV1;
}

export type PublicStoreCheckpointReadV1 =
  | {
      kind: "finalized";
      descriptor: StoreDescriptorV1;
      checkpoint: PublicStoreCheckpointV1;
    }
  | {
      kind: "status";
      value: PublicStoreCheckpointStatusBodyV1;
      storeSignature: Uint8Array;
    };

export type PublicChunkStatusKindV1 = "not-final" | "out-of-range";

export interface PublicChunkStatusBodyV1 {
  version: 1;
  bucket: PublicBucketV1;
  chunkIndex: bigint;
  status: PublicChunkStatusKindV1;
}

export type PublicChunkReadV1 =
  | { kind: "finalized"; chunk: PublicChunkV1 }
  | {
      kind: "status";
      value: PublicChunkStatusBodyV1;
      storeSignature: Uint8Array;
    };

export interface PrototypeStoreDescriptorDocumentV1 {
  descriptor: StoreDescriptorV1;
  routes: readonly StoreRouteV1[];
}

export interface StoreWitnessRecordV1 {
  version: 1;
  witnessedStoreId: Uint8Array;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  checkpointHash: Uint8Array;
}

/* ------------------------------------------------------------------ *
 * Codecs
 * ------------------------------------------------------------------ */

export const encodePublicAllocationLeaseBodyV1 = (
  value: PublicAllocationLeaseBodyV1,
): Uint8Array => encodeCanonical(publicAllocationLeaseBodyV1Schema, value);

export const decodePublicAllocationLeaseBodyV1 = (
  bytes: Uint8Array,
): PublicAllocationLeaseBodyV1 =>
  decodeCanonicalStrict(
    publicAllocationLeaseBodyV1Schema,
    bytes,
  ) as PublicAllocationLeaseBodyV1;

export const encodePublicAllocationLeaseV1 = (
  value: PublicAllocationLeaseV1,
): Uint8Array => encodeCanonical(publicAllocationLeaseV1Schema, value);

export const decodePublicAllocationLeaseV1 = (
  bytes: Uint8Array,
): PublicAllocationLeaseV1 =>
  decodeCanonicalStrict(
    publicAllocationLeaseV1Schema,
    bytes,
  ) as PublicAllocationLeaseV1;

export const encodePublicAppendAdmissionV1 = (
  value: PublicAppendAdmissionV1,
): Uint8Array => encodeCanonical(publicAppendAdmissionV1Schema, value);

export const decodePublicAppendAdmissionV1 = (
  bytes: Uint8Array,
): PublicAppendAdmissionV1 =>
  decodeCanonicalStrict(
    publicAppendAdmissionV1Schema,
    bytes,
  ) as PublicAppendAdmissionV1;

export const encodePublicAppendRequestV1 = (
  value: PublicAppendRequestV1,
): Uint8Array => encodeCanonical(publicAppendRequestV1Schema, value);

export const decodePublicAppendRequestV1 = (
  bytes: Uint8Array,
): PublicAppendRequestV1 =>
  decodeCanonicalStrict(
    publicAppendRequestV1Schema,
    bytes,
  ) as PublicAppendRequestV1;

export const encodePublicAppendStatusV1 = (
  value: PublicAppendStatusV1,
): Uint8Array => encodeCanonical(publicAppendStatusV1Schema, value);

export const decodePublicAppendStatusV1 = (
  bytes: Uint8Array,
): PublicAppendStatusV1 =>
  decodeCanonicalStrict(
    publicAppendStatusV1Schema,
    bytes,
  ) as PublicAppendStatusV1;

export const encodePublicAppendResultBodyV1 = (
  value: PublicAppendResultBodyV1,
): Uint8Array => encodeCanonical(publicAppendResultBodyV1Schema, value);

export const decodePublicAppendResultBodyV1 = (
  bytes: Uint8Array,
): PublicAppendResultBodyV1 =>
  decodeCanonicalStrict(
    publicAppendResultBodyV1Schema,
    bytes,
  ) as PublicAppendResultBodyV1;

export const encodePublicAppendResultV1 = (
  value: PublicAppendResultV1,
): Uint8Array => encodeCanonical(publicAppendResultV1Schema, value);

export const decodePublicAppendResultV1 = (
  bytes: Uint8Array,
): PublicAppendResultV1 =>
  decodeCanonicalStrict(
    publicAppendResultV1Schema,
    bytes,
  ) as PublicAppendResultV1;

export const encodeAllocationTokenIssueRequestV1 = (
  value: AllocationTokenIssueRequestV1,
): Uint8Array => encodeCanonical(allocationTokenIssueRequestV1Schema, value);

export const decodeAllocationTokenIssueRequestV1 = (
  bytes: Uint8Array,
): AllocationTokenIssueRequestV1 =>
  decodeCanonicalStrict(
    allocationTokenIssueRequestV1Schema,
    bytes,
  ) as AllocationTokenIssueRequestV1;

export const encodeAllocationTokenIssueResultBodyV1 = (
  value: AllocationTokenIssueResultBodyV1,
): Uint8Array => encodeCanonical(allocationTokenIssueResultBodyV1Schema, value);

export const decodeAllocationTokenIssueResultBodyV1 = (
  bytes: Uint8Array,
): AllocationTokenIssueResultBodyV1 =>
  decodeCanonicalStrict(
    allocationTokenIssueResultBodyV1Schema,
    bytes,
  ) as AllocationTokenIssueResultBodyV1;

export const encodeAllocationTokenIssueResultV1 = (
  value: AllocationTokenIssueResultV1,
): Uint8Array => encodeCanonical(allocationTokenIssueResultV1Schema, value);

export const decodeAllocationTokenIssueResultV1 = (
  bytes: Uint8Array,
): AllocationTokenIssueResultV1 =>
  decodeCanonicalStrict(
    allocationTokenIssueResultV1Schema,
    bytes,
  ) as AllocationTokenIssueResultV1;

export const encodePublicAllocationRequestV1 = (
  value: PublicAllocationRequestV1,
): Uint8Array => encodeCanonical(publicAllocationRequestV1Schema, value);

export const decodePublicAllocationRequestV1 = (
  bytes: Uint8Array,
): PublicAllocationRequestV1 =>
  decodeCanonicalStrict(
    publicAllocationRequestV1Schema,
    bytes,
  ) as PublicAllocationRequestV1;

export const encodePublicAllocationStatusBodyV1 = (
  value: PublicAllocationStatusBodyV1,
): Uint8Array => encodeCanonical(publicAllocationStatusBodyV1Schema, value);

export const decodePublicAllocationStatusBodyV1 = (
  bytes: Uint8Array,
): PublicAllocationStatusBodyV1 =>
  decodeCanonicalStrict(
    publicAllocationStatusBodyV1Schema,
    bytes,
  ) as PublicAllocationStatusBodyV1;

export const encodePublicAllocationResultV1 = (
  value: PublicAllocationResultV1,
): Uint8Array => encodeCanonical(publicAllocationResultV1Schema, value);

export const decodePublicAllocationResultV1 = (
  bytes: Uint8Array,
): PublicAllocationResultV1 =>
  decodeCanonicalStrict(
    publicAllocationResultV1Schema,
    bytes,
  ) as PublicAllocationResultV1;

export const encodePublicStoreCheckpointStatusBodyV1 = (
  value: PublicStoreCheckpointStatusBodyV1,
): Uint8Array =>
  encodeCanonical(publicStoreCheckpointStatusBodyV1Schema, value);

export const decodePublicStoreCheckpointStatusBodyV1 = (
  bytes: Uint8Array,
): PublicStoreCheckpointStatusBodyV1 =>
  decodeCanonicalStrict(
    publicStoreCheckpointStatusBodyV1Schema,
    bytes,
  ) as PublicStoreCheckpointStatusBodyV1;

export const encodePublicStoreCheckpointReadV1 = (
  value: PublicStoreCheckpointReadV1,
): Uint8Array => encodeCanonical(publicStoreCheckpointReadV1Schema, value);

export const decodePublicStoreCheckpointReadV1 = (
  bytes: Uint8Array,
): PublicStoreCheckpointReadV1 =>
  decodeCanonicalStrict(
    publicStoreCheckpointReadV1Schema,
    bytes,
  ) as PublicStoreCheckpointReadV1;

export const encodePublicChunkStatusBodyV1 = (
  value: PublicChunkStatusBodyV1,
): Uint8Array => encodeCanonical(publicChunkStatusBodyV1Schema, value);

export const decodePublicChunkStatusBodyV1 = (
  bytes: Uint8Array,
): PublicChunkStatusBodyV1 =>
  decodeCanonicalStrict(
    publicChunkStatusBodyV1Schema,
    bytes,
  ) as PublicChunkStatusBodyV1;

export const encodePublicChunkReadV1 = (value: PublicChunkReadV1): Uint8Array =>
  encodeCanonical(publicChunkReadV1Schema, value);

export const decodePublicChunkReadV1 = (bytes: Uint8Array): PublicChunkReadV1 =>
  decodeCanonicalStrict(publicChunkReadV1Schema, bytes) as PublicChunkReadV1;

export const encodePrototypeStoreDescriptorDocumentV1 = (
  value: PrototypeStoreDescriptorDocumentV1,
): Uint8Array =>
  encodeCanonical(prototypeStoreDescriptorDocumentV1Schema, value);

export const decodePrototypeStoreDescriptorDocumentV1 = (
  bytes: Uint8Array,
): PrototypeStoreDescriptorDocumentV1 =>
  decodeCanonicalStrict(
    prototypeStoreDescriptorDocumentV1Schema,
    bytes,
  ) as PrototypeStoreDescriptorDocumentV1;

export const encodeStoreWitnessRecordV1 = (
  value: StoreWitnessRecordV1,
): Uint8Array => encodeCanonical(storeWitnessRecordV1Schema, value);

export const decodeStoreWitnessRecordV1 = (
  bytes: Uint8Array,
): StoreWitnessRecordV1 =>
  decodeCanonicalStrict(
    storeWitnessRecordV1Schema,
    bytes,
  ) as StoreWitnessRecordV1;

export const encodeStoreWitnessRecordsV1 = (
  value: readonly StoreWitnessRecordV1[],
): Uint8Array => encodeCanonical(storeWitnessRecordsV1Schema, value);

export const decodeStoreWitnessRecordsV1 = (
  bytes: Uint8Array,
): readonly StoreWitnessRecordV1[] =>
  decodeCanonicalStrict(
    storeWitnessRecordsV1Schema,
    bytes,
  ) as readonly StoreWitnessRecordV1[];
