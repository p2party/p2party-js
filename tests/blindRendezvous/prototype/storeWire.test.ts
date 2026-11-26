import { describe, expect, test } from "bun:test";

import {
  decodeCanonicalStrict,
  encodeCanonical,
} from "../../../src/blindRendezvous/canonicalSchema";
import {
  allocationAppendSignedMessage,
  allocationTokenIssueRequestHash,
  allocationTokenIssueResultSignedMessage,
  domain,
  prototypeStoreCompatibilityHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationRequestHash,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
  sha256,
} from "../../../src/blindRendezvous/derivations";
import {
  publicAllocationResultV1Schema,
  publicAppendRequestV1Schema,
} from "../../../src/blindRendezvous/schemas";
import {
  decodeAllocationTokenIssueRequestV1,
  decodeAllocationTokenIssueResultBodyV1,
  decodeAllocationTokenIssueResultV1,
  decodePrototypeStoreDescriptorDocumentV1,
  decodePublicAllocationLeaseBodyV1,
  decodePublicAllocationLeaseV1,
  decodePublicAllocationRequestV1,
  decodePublicAllocationResultV1,
  decodePublicAllocationStatusBodyV1,
  decodePublicAppendAdmissionV1,
  decodePublicAppendRequestV1,
  decodePublicAppendResultBodyV1,
  decodePublicAppendResultV1,
  decodePublicAppendStatusV1,
  decodePublicChunkReadV1,
  decodePublicChunkStatusBodyV1,
  decodePublicStoreCheckpointReadV1,
  decodePublicStoreCheckpointStatusBodyV1,
  decodeStoreWitnessRecordV1,
  decodeStoreWitnessRecordsV1,
  encodeAllocationTokenIssueRequestV1,
  encodeAllocationTokenIssueResultBodyV1,
  encodeAllocationTokenIssueResultV1,
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationLeaseBodyV1,
  encodePublicAllocationLeaseV1,
  encodePublicAllocationRequestV1,
  encodePublicAllocationResultV1,
  encodePublicAllocationStatusBodyV1,
  encodePublicAppendAdmissionV1,
  encodePublicAppendRequestV1,
  encodePublicAppendResultBodyV1,
  encodePublicAppendResultV1,
  encodePublicAppendStatusV1,
  encodePublicChunkReadV1,
  encodePublicChunkStatusBodyV1,
  encodePublicStoreCheckpointReadV1,
  encodePublicStoreCheckpointStatusBodyV1,
  encodeStoreWitnessRecordV1,
  encodeStoreWitnessRecordsV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type {
  AllocationTokenIssueRequestV1,
  AllocationTokenIssueResultBodyV1,
  AllocationTokenIssueResultV1,
  PrototypeStoreDescriptorDocumentV1,
  PublicAllocationLeaseBodyV1,
  PublicAllocationLeaseV1,
  PublicAllocationRequestV1,
  PublicAllocationResultV1,
  PublicAllocationStatusBodyV1,
  PublicAppendAdmissionV1,
  PublicAppendRequestV1,
  PublicAppendResultBodyV1,
  PublicAppendResultV1,
  PublicChunkReadV1,
  PublicChunkStatusBodyV1,
  PublicStoreCheckpointReadV1,
  PublicStoreCheckpointStatusBodyV1,
  StoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import type {
  PublicBucketV1,
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../../src/blindRendezvous/publicWindow";
import type {
  StoreDescriptorV1,
  StoreRouteV1,
} from "../../../src/blindRendezvous/storeDescriptor";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

const bucket: PublicBucketV1 = {
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  sizeClass: 0,
};

const leaseBody: PublicAllocationLeaseBodyV1 = {
  version: 1,
  storeId: fill(32, 1),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  requestHash: fill(32, 3),
  allocationOrdinal: 5,
  allocationEd25519PublicKey: fill(32, 4),
};

const lease: PublicAllocationLeaseV1 = {
  ...leaseBody,
  storeSignature: fill(64, 5),
};

const admission: PublicAppendAdmissionV1 = {
  version: 1,
  lease,
  objectOrdinalWithinAllocation: 2,
  allocationSignature: fill(64, 6),
};

const appendRequest: PublicAppendRequestV1 = {
  version: 1,
  bucket,
  exactFixedObject: fill(16, 9),
  admission,
};

const appendResultBody: PublicAppendResultBodyV1 = {
  version: 1,
  storeId: fill(32, 1),
  descriptorHash: fill(32, 7),
  bucket,
  requestHash: fill(32, 3),
  status: "stored",
  fixedStatusPadding: fill(16, 0),
};

const appendResult: PublicAppendResultV1 = {
  ...appendResultBody,
  storeSignature: fill(64, 8),
};

const tokenIssueRequest: AllocationTokenIssueRequestV1 = {
  version: 1,
  storeId: fill(32, 1),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  privacyPassTokenRequest: fill(48, 10),
};

const tokenIssueIssuedBody: AllocationTokenIssueResultBodyV1 = {
  kind: "issued",
  version: 1,
  requestHash: fill(32, 11),
  privacyPassTokenResponse: fill(32, 0),
};

const tokenIssueStatusBody: AllocationTokenIssueResultBodyV1 = {
  kind: "status",
  version: 1,
  requestHash: fill(32, 11),
  status: "quota-denied",
  fixedErrorPadding: fill(32, 0),
};

const tokenIssueResult: AllocationTokenIssueResultV1 = {
  body: tokenIssueIssuedBody,
  storeSignature: fill(64, 12),
};

const allocationRequest: PublicAllocationRequestV1 = {
  version: 1,
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  allocationEd25519PublicKey: fill(32, 4),
  privacyPassToken: fill(32, 0),
};

const allocationStatusBody: PublicAllocationStatusBodyV1 = {
  version: 1,
  storeId: fill(32, 1),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  requestHash: fill(32, 13),
  status: "capacity-exhausted",
  fixedErrorPadding: fill(32, 0),
};

const allocatedResult: PublicAllocationResultV1 = { kind: "allocated", lease };

const allocationStatusResult: PublicAllocationResultV1 = {
  kind: "status",
  value: allocationStatusBody,
  storeSignature: fill(64, 14),
};

const checkpointStatusBody: PublicStoreCheckpointStatusBodyV1 = {
  version: 1,
  storeId: fill(32, 1),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  storeIngressWindow: 9n,
  status: "not-final",
};

const descriptor: StoreDescriptorV1 = {
  version: 1,
  storeIdentityEd25519Key: fill(32, 15),
  allocationIssuerPublicKeyDer: fill(8, 16),
  descriptorGeneration: 3n,
  compatibilityHash: fill(32, 17),
  supportedDeliveryProfileHashes: [fill(32, 2)],
  checkpointChainStarts: [
    { deliveryProfileHash: fill(32, 2), chainStartIngressWindow: 4n },
  ],
  retentionWindows: 256,
  notBeforeUnixMs: 1000n,
  notAfterUnixMs: 2000n,
  descriptorSignature: fill(64, 18),
};

const route: StoreRouteV1 = {
  version: 1,
  storeId: fill(32, 1),
  descriptorHash: fill(32, 19),
  routeFamily: 1,
  opaqueLocator: fill(8, 20),
  routePublicParameters: fill(4, 21),
  notBeforeUnixMs: 1000n,
  notAfterUnixMs: 2000n,
  routeSignature: fill(64, 22),
};

const checkpoint: PublicStoreCheckpointV1 = {
  version: 1,
  storeId: fill(32, 1),
  descriptorHash: fill(32, 19),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  chainStartIngressWindow: 4n,
  previousCheckpointHash: fill(32, 23),
  finalizedChunkCount: 3,
  finalizedChunkRoot: fill(32, 24),
  storeSignature: fill(64, 25),
};

const descriptorDocument: PrototypeStoreDescriptorDocumentV1 = {
  descriptor,
  routes: [route],
};

const chunk: PublicChunkV1 = {
  version: 1,
  bucket,
  chunkIndex: 0n,
  previousChunkHash: fill(32, 0),
  fixedObjects: [fill(16, 9), fill(16, 26)],
  storeSignature: fill(64, 27),
};

const chunkStatusBody: PublicChunkStatusBodyV1 = {
  version: 1,
  bucket,
  chunkIndex: 1n,
  storeIngressWindow: 9n,
  status: "out-of-range",
};

const chunkFinalized: PublicChunkReadV1 = { kind: "finalized", chunk };

const chunkStatus: PublicChunkReadV1 = {
  kind: "status",
  value: chunkStatusBody,
  storeSignature: fill(64, 28),
};

const checkpointFinalized: PublicStoreCheckpointReadV1 = {
  kind: "finalized",
  descriptor,
  checkpoint,
};

const checkpointStatus: PublicStoreCheckpointReadV1 = {
  kind: "status",
  value: checkpointStatusBody,
  storeSignature: fill(64, 29),
};

const witness: StoreWitnessRecordV1 = {
  version: 1,
  witnessedStoreId: fill(32, 30),
  deliveryProfileHash: fill(32, 2),
  ingressWindow: 7n,
  checkpointHash: fill(32, 31),
};

const witnesses: readonly StoreWitnessRecordV1[] = [
  witness,
  { ...witness, ingressWindow: 8n },
];

describe("prototype store wire codecs", () => {
  test("allocation lease body round-trips and is pinned", () => {
    const bytes = encodePublicAllocationLeaseBodyV1(leaseBody);
    expect(decodePublicAllocationLeaseBodyV1(bytes)).toEqual(leaseBody);
    expect(hex(bytes)).toBe(
      "010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070303030303030303030303030303030303030303030303030303030303030303000000050404040404040404040404040404040404040404040404040404040404040404",
    );
  });

  test("allocation lease round-trips and is pinned", () => {
    const bytes = encodePublicAllocationLeaseV1(lease);
    expect(decodePublicAllocationLeaseV1(bytes)).toEqual(lease);
    expect(hex(bytes)).toBe(
      "01010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000007030303030303030303030303030303030303030303030303030303030303030300000005040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
    );
  });

  test("append admission round-trips and is pinned", () => {
    const bytes = encodePublicAppendAdmissionV1(admission);
    expect(decodePublicAppendAdmissionV1(bytes)).toEqual(admission);
    expect(hex(bytes)).toBe(
      "01010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070303030303030303030303030303030303030303030303030303030303030303000000050404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050000000206060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606",
    );
  });

  test("append request round-trips and is pinned", () => {
    const bytes = encodePublicAppendRequestV1(appendRequest);
    expect(decodePublicAppendRequestV1(bytes)).toEqual(appendRequest);
    expect(hex(bytes)).toBe(
      "01020202020202020202020202020202020202020202020202020202020202020200000000000000070000000010090909090909090909090909090909090101010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070303030303030303030303030303030303030303030303030303030303030303000000050404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050000000206060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606",
    );
  });

  test("append status round-trips and is pinned", () => {
    const bytes = encodePublicAppendStatusV1("window-finalized");
    expect(decodePublicAppendStatusV1(bytes)).toBe("window-finalized");
    expect(hex(bytes)).toBe("04");
  });

  test("append result body round-trips and is pinned", () => {
    const bytes = encodePublicAppendResultBodyV1(appendResultBody);
    expect(decodePublicAppendResultBodyV1(bytes)).toEqual(appendResultBody);
    expect(hex(bytes)).toBe(
      "0101010101010101010101010101010101010101010101010101010101010101010707070707070707070707070707070707070707070707070707070707070707020202020202020202020202020202020202020202020202020202020202020200000000000000070003030303030303030303030303030303030303030303030303030303030303030000000000000000000000000000000000",
    );
  });

  test("append result round-trips and is pinned", () => {
    const bytes = encodePublicAppendResultV1(appendResult);
    expect(decodePublicAppendResultV1(bytes)).toEqual(appendResult);
    expect(hex(bytes)).toBe(
      "010101010101010101010101010101010101010101010101010101010101010101070707070707070707070707070707070707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020000000000000007000303030303030303030303030303030303030303030303030303030303030303000000000000000000000000000000000008080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808",
    );
  });

  test("allocation token issue request round-trips and is pinned", () => {
    const bytes = encodeAllocationTokenIssueRequestV1(tokenIssueRequest);
    expect(decodeAllocationTokenIssueRequestV1(bytes)).toEqual(
      tokenIssueRequest,
    );
    expect(hex(bytes)).toBe(
      "01010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000007000000300a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    );
  });

  test("allocation token issue result body round-trips both variants", () => {
    const issued = encodeAllocationTokenIssueResultBodyV1(tokenIssueIssuedBody);
    expect(decodeAllocationTokenIssueResultBodyV1(issued)).toEqual(
      tokenIssueIssuedBody,
    );
    expect(hex(issued)).toBe(
      "0000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000200000000000000000000000000000000000000000000000000000000000000000",
    );

    const status = encodeAllocationTokenIssueResultBodyV1(tokenIssueStatusBody);
    expect(decodeAllocationTokenIssueResultBodyV1(status)).toEqual(
      tokenIssueStatusBody,
    );
    expect(hex(status)).toBe(
      "0100010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000000000000000000000000000000000000000000000",
    );
    // The union tag byte, not only the payload, separates the two variants.
    expect(issued[0]).not.toBe(status[0]);
  });

  test("allocation token issue result round-trips and is pinned", () => {
    const bytes = encodeAllocationTokenIssueResultV1(tokenIssueResult);
    expect(decodeAllocationTokenIssueResultV1(bytes)).toEqual(tokenIssueResult);
    expect(hex(bytes)).toBe(
      "0000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000002000000000000000000000000000000000000000000000000000000000000000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
    );
  });

  test("allocation request round-trips and is pinned", () => {
    const bytes = encodePublicAllocationRequestV1(allocationRequest);
    expect(decodePublicAllocationRequestV1(bytes)).toEqual(allocationRequest);
    expect(hex(bytes)).toBe(
      "01020202020202020202020202020202020202020202020202020202020202020200000000000000070404040404040404040404040404040404040404040404040404040404040404000000200000000000000000000000000000000000000000000000000000000000000000",
    );
  });

  test("allocation status body round-trips and is pinned", () => {
    const bytes = encodePublicAllocationStatusBodyV1(allocationStatusBody);
    expect(decodePublicAllocationStatusBodyV1(bytes)).toEqual(
      allocationStatusBody,
    );
    expect(hex(bytes)).toBe(
      "010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d020000000000000000000000000000000000000000000000000000000000000000",
    );
  });

  test("allocation result round-trips both variants and is pinned", () => {
    const allocated = encodePublicAllocationResultV1(allocatedResult);
    expect(decodePublicAllocationResultV1(allocated)).toEqual(allocatedResult);
    expect(hex(allocated)).toBe(
      "000001010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000007030303030303030303030303030303030303030303030303030303030303030300000005040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
    );

    const status = encodePublicAllocationResultV1(allocationStatusResult);
    expect(decodePublicAllocationResultV1(status)).toEqual(
      allocationStatusResult,
    );
    expect(hex(status)).toBe(
      "0100010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0200000000000000000000000000000000000000000000000000000000000000000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
    );
  });

  test("checkpoint status body round-trips and is pinned", () => {
    const bytes = encodePublicStoreCheckpointStatusBodyV1(checkpointStatusBody);
    expect(decodePublicStoreCheckpointStatusBodyV1(bytes)).toEqual(
      checkpointStatusBody,
    );
    expect(hex(bytes)).toBe(
      "01010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000007000000000000000900",
    );
  });

  test("checkpoint read round-trips both variants and is pinned", () => {
    const finalized = encodePublicStoreCheckpointReadV1(checkpointFinalized);
    expect(decodePublicStoreCheckpointReadV1(finalized)).toEqual(
      checkpointFinalized,
    );
    expect(hex(finalized)).toBe(
      "0000010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00000008101010101010101000000000000000031111111111111111111111111111111111111111111111111111111111111111000102020202020202020202020202020202020202020202020202020202020202020001020202020202020202020202020202020202020202020202020202020202020200000000000000040000010000000000000003e800000000000007d0121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212120101010101010101010101010101010101010101010101010101010101010101011313131313131313131313131313131313131313131313131313131313131313020202020202020202020202020202020202020202020202020202020202020200000000000000070000000000000004171717171717171717171717171717171717171717171717171717171717171700000003181818181818181818181818181818181818181818181818181818181818181819191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919",
    );

    const status = encodePublicStoreCheckpointReadV1(checkpointStatus);
    expect(decodePublicStoreCheckpointReadV1(status)).toEqual(checkpointStatus);
    expect(hex(status)).toBe(
      "0100010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000070000000000000009001d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d",
    );
  });

  test("chunk status body round-trips and is pinned", () => {
    const bytes = encodePublicChunkStatusBodyV1(chunkStatusBody);
    expect(decodePublicChunkStatusBodyV1(bytes)).toEqual(chunkStatusBody);
    expect(hex(bytes)).toBe(
      "0102020202020202020202020202020202020202020202020202020202020202020000000000000007000000000000000001000000000000000901",
    );
  });

  test("chunk read round-trips both variants and is pinned", () => {
    const finalized = encodePublicChunkReadV1(chunkFinalized);
    expect(decodePublicChunkReadV1(finalized)).toEqual(chunkFinalized);
    expect(hex(finalized)).toBe(
      "00000102020202020202020202020202020202020202020202020202020202020202020000000000000007000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000001009090909090909090909090909090909000000101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
    );

    const status = encodePublicChunkReadV1(chunkStatus);
    expect(decodePublicChunkReadV1(status)).toEqual(chunkStatus);
    expect(hex(status)).toBe(
      "010001020202020202020202020202020202020202020202020202020202020202020200000000000000070000000000000000010000000000000009011c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c",
    );
  });

  test("descriptor document round-trips and is pinned", () => {
    const bytes = encodePrototypeStoreDescriptorDocumentV1(descriptorDocument);
    expect(decodePrototypeStoreDescriptorDocumentV1(bytes)).toEqual(
      descriptorDocument,
    );
    expect(hex(bytes)).toBe(
      "010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00000008101010101010101000000000000000031111111111111111111111111111111111111111111111111111111111111111000102020202020202020202020202020202020202020202020202020202020202020001020202020202020202020202020202020202020202020202020202020202020200000000000000040000010000000000000003e800000000000007d012121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212000101010101010101010101010101010101010101010101010101010101010101010113131313131313131313131313131313131313131313131313131313131313130001000000081414141414141414000000041515151500000000000003e800000000000007d016161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616",
    );
  });

  test("witness record and record list round-trip and are pinned", () => {
    const one = encodeStoreWitnessRecordV1(witness);
    expect(decodeStoreWitnessRecordV1(one)).toEqual(witness);
    expect(hex(one)).toBe(
      "011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e020202020202020202020202020202020202020202020202020202020202020200000000000000071f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    );

    const many = encodeStoreWitnessRecordsV1(witnesses);
    expect(decodeStoreWitnessRecordsV1(many)).toEqual(witnesses);
    expect(hex(many)).toBe(
      "0002011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e020202020202020202020202020202020202020202020202020202020202020200000000000000071f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e020202020202020202020202020202020202020202020202020202020202020200000000000000081f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    );
  });

  test("cover append has admission null", () => {
    const cover = { ...appendRequest, admission: null };
    const bytes = encodeCanonical(publicAppendRequestV1Schema, cover);
    expect(decodeCanonicalStrict(publicAppendRequestV1Schema, bytes)).toEqual(
      cover,
    );
    // The admission is the only difference: an absent one drops exactly the
    // admission encoding, leaving the one-byte optional tag in place.
    expect(bytes.length).toBe(
      encodePublicAppendRequestV1(appendRequest).length -
        encodePublicAppendAdmissionV1(admission).length,
    );
  });

  test("allocation result union distinguishes variants", () => {
    const bytes = encodeCanonical(publicAllocationResultV1Schema, {
      kind: "allocated",
      lease,
    });
    expect(
      decodeCanonicalStrict(publicAllocationResultV1Schema, bytes),
    ).toEqual(allocatedResult);
    expect(bytes[0]).toBe(0);
    expect(encodePublicAllocationResultV1(allocationStatusResult)[0]).toBe(1);
  });
});

describe("prototype store wire transcripts", () => {
  test("allocation append signed message layout", async () => {
    const message = await allocationAppendSignedMessage(
      leaseBody,
      0,
      2,
      fill(16, 9),
    );
    const prefix = domain("p2party/allocation-append-signature/v1");
    expect(message.length).toBe(prefix.length + 32 + 1 + 4 + 32);
    expect(hex(message.subarray(0, prefix.length))).toBe(hex(prefix));
    expect(hex(message.subarray(prefix.length, prefix.length + 32))).toBe(
      hex(await sha256(encodePublicAllocationLeaseBodyV1(leaseBody))),
    );
    expect(message[prefix.length + 32]).toBe(0);
    expect(hex(message.subarray(prefix.length + 33, prefix.length + 37))).toBe(
      "00000002",
    );
    expect(hex(message.subarray(prefix.length + 37))).toBe(
      hex(await sha256(fill(16, 9))),
    );
  });

  test("changing the object ordinal changes only the four ordinal bytes", async () => {
    const first = await allocationAppendSignedMessage(
      leaseBody,
      0,
      2,
      fill(16, 9),
    );
    const second = await allocationAppendSignedMessage(
      leaseBody,
      0,
      3,
      fill(16, 9),
    );
    expect(first.length).toBe(second.length);
    const differing = [...first]
      .map((byte, index) => (byte === second[index] ? -1 : index))
      .filter((index) => index >= 0);
    const ordinalStart =
      domain("p2party/allocation-append-signature/v1").length + 33;
    expect(differing).toEqual([ordinalStart + 3]);
  });

  test("the append request hash is domain-separated over the canonical request", async () => {
    expect(hex(await publicAppendRequestHash(appendRequest))).toBe(
      "543f23058f09368f8ab9c8679ba9945e1f014a5b75758887a253ad8f5a7faf9d",
    );
  });

  test("the append result transcript is the domain then the body hash", async () => {
    const message = await publicAppendResultSignedMessage(appendResultBody);
    const prefix = domain("p2party/public-append-result/v1");
    expect(message.length).toBe(prefix.length + 32);
    expect(hex(message.subarray(prefix.length))).toBe(
      hex(await sha256(encodePublicAppendResultBodyV1(appendResultBody))),
    );
  });

  test("the allocation request hash is pinned", async () => {
    expect(hex(await publicAllocationRequestHash(allocationRequest))).toBe(
      "b3c779763a323d78cb07c04f00a34316238ab78552582cbc37fd1bc85e139a6e",
    );
  });

  test("the lease transcript is the domain then the lease-body hash", async () => {
    const message = await publicAllocationLeaseSignedMessage(leaseBody);
    const prefix = domain("p2party/public-allocation-lease-signature/v1");
    expect(message.length).toBe(prefix.length + 32);
    expect(hex(message.subarray(prefix.length))).toBe(
      hex(await sha256(encodePublicAllocationLeaseBodyV1(leaseBody))),
    );
  });

  test("the allocation status transcript is the domain then the body hash", async () => {
    const message =
      await publicAllocationStatusSignedMessage(allocationStatusBody);
    const prefix = domain("p2party/public-allocation-status-signature/v1");
    expect(message.length).toBe(prefix.length + 32);
    expect(hex(message.subarray(prefix.length))).toBe(
      hex(
        await sha256(encodePublicAllocationStatusBodyV1(allocationStatusBody)),
      ),
    );
  });

  test("the token issue request hash is pinned", async () => {
    expect(hex(await allocationTokenIssueRequestHash(tokenIssueRequest))).toBe(
      "b113f4e3d2c18e28de4de9c52d7ea0de3bd3be81c8329c365cdc169dbf491753",
    );
  });

  test("the token issue result transcript covers the union body", async () => {
    const message =
      await allocationTokenIssueResultSignedMessage(tokenIssueIssuedBody);
    const prefix = domain("p2party/allocation-token-issue-result-signature/v1");
    expect(message.length).toBe(prefix.length + 32);
    expect(hex(message.subarray(prefix.length))).toBe(
      hex(
        await sha256(
          encodeAllocationTokenIssueResultBodyV1(tokenIssueIssuedBody),
        ),
      ),
    );
    // The two variants must never share a transcript.
    const other =
      await allocationTokenIssueResultSignedMessage(tokenIssueStatusBody);
    expect(hex(other)).not.toBe(hex(message));
  });

  test("the chunk and checkpoint status signing hashes are pinned", async () => {
    expect(hex(await publicChunkStatusSigningHash(chunkStatusBody))).toBe(
      "df6aed2a80180d61f01872b381af920d62036075f505492f109f61280cae4fa8",
    );
    expect(
      hex(await publicCheckpointStatusSigningHash(checkpointStatusBody)),
    ).toBe("746402d9c328914841f135f6c4f3fb39208ae50ee2de2dd8e67c6dcf91acaffb");
  });

  test("the prototype compatibility hash is pinned and requires 32 bytes", async () => {
    expect(hex(await prototypeStoreCompatibilityHash(fill(32, 2)))).toBe(
      "8630e00cd3dcce2e13e5dba8e60991caf7ef26b1d59ebbcddb028f459009aab7",
    );
    await expect(
      prototypeStoreCompatibilityHash(fill(31, 2)),
    ).rejects.toThrow();
  });
});
