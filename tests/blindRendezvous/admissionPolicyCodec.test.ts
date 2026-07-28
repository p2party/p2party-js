import { describe, expect, test } from "bun:test";

import {
  decodeBootstrapAdmissionDecisionLeaseV1,
  decodeFrontendRoomControlsV1,
  decodePairAttemptLeaseV1,
  encodeBootstrapAdmissionDecisionLeaseV1,
  encodeFrontendRoomControlsV1,
  encodePairAttemptLeaseV1,
} from "../../src/blindRendezvous/admissionPolicy";
import { encodeCanonical } from "../../src/blindRendezvous/canonicalSchema";
import {
  bootstrapAdmissionDecisionLeaseV1Schema,
  pairAttemptLeaseV1Schema,
} from "../../src/blindRendezvous/schemas";

import type {
  BootstrapAdmissionDecisionLeaseV1,
  FrontendRoomControlsV1,
  PairAttemptLeaseV1,
} from "../../src/blindRendezvous/admissionPolicy";

const bytes32 = (fill: number): Uint8Array => new Uint8Array(32).fill(fill);

const frontendControls = (): FrontendRoomControlsV1 => ({
  version: 1,
  policyGeneration: 7n,
  onlyConnectWithKnownPeers: true,
  allowedStableIdentityKeys: [bytes32(0x11), bytes32(0x22)],
  deniedStableIdentityKeys: [bytes32(0x33)],
  deniedRoomIdentityCommitments: [bytes32(0x44)],
});

const pairAttemptLease = (
  attemptMode: PairAttemptLeaseV1["attemptMode"] = "planner",
): PairAttemptLeaseV1 => ({
  version: 1,
  helloOperationId: bytes32(0x11),
  pairEdgeId: bytes32(0x22),
  // Sequence order is meaningful and deliberately not bytewise sorted.
  endpointPresenceOperationIds: [bytes32(0x44), bytes32(0x33)],
  attemptMode,
  helloLogicalWindow: 10n,
  validThroughLogicalWindow: 14n,
});

const bootstrapLease = (
  authorityBound: boolean,
): BootstrapAdmissionDecisionLeaseV1 => ({
  version: 1,
  roomContextId: bytes32(0x11),
  stableEd25519PublicKey: bytes32(0x22),
  stableIdentityCommitment: bytes32(0x33),
  grantId: authorityBound ? bytes32(0x44) : null,
  grantGeneration: authorityBound ? 5n : null,
  localPolicyGeneration: 7n,
  authorityAdmissionStateDigest: authorityBound ? bytes32(0x55) : null,
  admittedPresenceOperationId: bytes32(0x66),
  admittedIdentityOperationId: bytes32(0x77),
  decidedAtLogicalWindow: 10n,
  validThroughLogicalWindow: 14n,
});

describe("FrontendRoomControlsV1 canonical codec", () => {
  test("round-trips one field-order-independent canonical encoding", () => {
    const value = frontendControls();
    const encoded = encodeFrontendRoomControlsV1(value);
    const shuffled = {
      deniedRoomIdentityCommitments: value.deniedRoomIdentityCommitments,
      onlyConnectWithKnownPeers: value.onlyConnectWithKnownPeers,
      version: value.version,
      allowedStableIdentityKeys: value.allowedStableIdentityKeys,
      policyGeneration: value.policyGeneration,
      deniedStableIdentityKeys: value.deniedStableIdentityKeys,
    };

    expect(encodeFrontendRoomControlsV1(shuffled)).toEqual(encoded);
    const decoded = decodeFrontendRoomControlsV1(encoded);
    expect(decoded).toEqual(value);
    expect(encodeFrontendRoomControlsV1(decoded)).toEqual(encoded);
  });

  test("owns caller values and encoded input bytes", () => {
    const value = frontendControls();
    const firstAllowedKey = value.allowedStableIdentityKeys[0];
    const encoded = encodeFrontendRoomControlsV1(value);
    const stableEncoding = Uint8Array.from(encoded);

    firstAllowedKey.fill(0xff);
    expect(encoded).toEqual(stableEncoding);

    const decoded = decodeFrontendRoomControlsV1(encoded);
    encoded.fill(0xee);
    expect(decoded.allowedStableIdentityKeys[0]).toEqual(bytes32(0x11));
  });

  test("rejects noncanonical collections, malformed bytes, and accessors", () => {
    const encoded = encodeFrontendRoomControlsV1(frontendControls());

    const unsorted = Uint8Array.from(encoded);
    const firstEntry = Uint8Array.from(unsorted.subarray(12, 44));
    unsorted.copyWithin(12, 44, 76);
    unsorted.set(firstEntry, 44);
    expect(() => decodeFrontendRoomControlsV1(unsorted)).toThrow("sorted");

    const duplicate = Uint8Array.from(encoded);
    duplicate.copyWithin(44, 12, 44);
    expect(() => decodeFrontendRoomControlsV1(duplicate)).toThrow(
      "duplicate-free",
    );

    const invalidBoolean = Uint8Array.from(encoded);
    invalidBoolean[9] = 2;
    expect(() => decodeFrontendRoomControlsV1(invalidBoolean)).toThrow(
      "boolean",
    );
    expect(() =>
      decodeFrontendRoomControlsV1(Uint8Array.from([...encoded, 0])),
    ).toThrow("trailing");
    expect(() =>
      decodeFrontendRoomControlsV1(encoded.subarray(0, encoded.length - 1)),
    ).toThrow("truncated");
    expect(() =>
      decodeFrontendRoomControlsV1(
        new Proxy(encoded, {}) as unknown as Uint8Array,
      ),
    ).toThrow("Uint8Array");

    const accessor = { ...frontendControls() };
    Object.defineProperty(accessor, "policyGeneration", {
      enumerable: true,
      get: () => 7n,
    });
    expect(() => encodeFrontendRoomControlsV1(accessor)).toThrow(
      "exactly its declared fields",
    );
  });
});

describe("PairAttemptLeaseV1 canonical codec", () => {
  test("round-trips both modes and preserves endpoint sequence order", () => {
    for (const mode of ["planner", "explicit"] as const) {
      const value = pairAttemptLease(mode);
      const encoded = encodePairAttemptLeaseV1(value);
      const shuffled = {
        validThroughLogicalWindow: value.validThroughLogicalWindow,
        endpointPresenceOperationIds: value.endpointPresenceOperationIds,
        pairEdgeId: value.pairEdgeId,
        attemptMode: value.attemptMode,
        version: value.version,
        helloLogicalWindow: value.helloLogicalWindow,
        helloOperationId: value.helloOperationId,
      };

      expect(encoded.length).toBe(148);
      expect(encodePairAttemptLeaseV1(shuffled)).toEqual(encoded);
      expect(decodePairAttemptLeaseV1(encoded)).toEqual(value);
    }
  });

  test("owns nested bytes across source and encoded-input mutation", () => {
    const value = pairAttemptLease();
    const sourceEndpoint = value.endpointPresenceOperationIds[0];
    const encoded = encodePairAttemptLeaseV1(value);

    sourceEndpoint.fill(0xff);
    const decoded = decodePairAttemptLeaseV1(encoded);
    encoded.fill(0xee);
    expect(decoded.endpointPresenceOperationIds[0]).toEqual(bytes32(0x44));
  });

  test("rejects unknown modes, impossible intervals, and malformed tuples", () => {
    const value = pairAttemptLease();
    const encoded = encodePairAttemptLeaseV1(value);
    const invalidMode = Uint8Array.from(encoded);
    invalidMode[131] = 2;
    expect(() => decodePairAttemptLeaseV1(invalidMode)).toThrow(
      "PairAttemptModeV1",
    );

    const impossible = encodeCanonical(pairAttemptLeaseV1Schema, {
      ...value,
      helloLogicalWindow: 15n,
      validThroughLogicalWindow: 14n,
    });
    expect(() => decodePairAttemptLeaseV1(impossible)).toThrow(
      "impossible interval",
    );

    const tuple = [...value.endpointPresenceOperationIds] as Uint8Array[] & {
      extra?: boolean;
    };
    tuple.extra = true;
    expect(() =>
      encodePairAttemptLeaseV1({
        ...value,
        endpointPresenceOperationIds: tuple,
      }),
    ).toThrow("exactly two");

    expect(() =>
      decodePairAttemptLeaseV1(Uint8Array.from([...encoded, 0])),
    ).toThrow("exactly 148");
    expect(() =>
      decodePairAttemptLeaseV1(encoded.subarray(0, encoded.length - 1)),
    ).toThrow("exactly 148");
  });
});

describe("BootstrapAdmissionDecisionLeaseV1 canonical codec", () => {
  test("round-trips capability and authority-bound lease forms", () => {
    for (const authorityBound of [false, true]) {
      const value = bootstrapLease(authorityBound);
      const encoded = encodeBootstrapAdmissionDecisionLeaseV1(value);
      const shuffled = {
        validThroughLogicalWindow: value.validThroughLogicalWindow,
        grantGeneration: value.grantGeneration,
        version: value.version,
        stableIdentityCommitment: value.stableIdentityCommitment,
        admittedIdentityOperationId: value.admittedIdentityOperationId,
        roomContextId: value.roomContextId,
        authorityAdmissionStateDigest: value.authorityAdmissionStateDigest,
        localPolicyGeneration: value.localPolicyGeneration,
        decidedAtLogicalWindow: value.decidedAtLogicalWindow,
        grantId: value.grantId,
        admittedPresenceOperationId: value.admittedPresenceOperationId,
        stableEd25519PublicKey: value.stableEd25519PublicKey,
      };

      expect(encodeBootstrapAdmissionDecisionLeaseV1(shuffled)).toEqual(
        encoded,
      );
      const decoded = decodeBootstrapAdmissionDecisionLeaseV1(encoded);
      expect(decoded).toEqual(value);
      expect(encodeBootstrapAdmissionDecisionLeaseV1(decoded)).toEqual(encoded);
    }
  });

  test("owns every optional and mandatory byte string", () => {
    const value = bootstrapLease(true);
    const sourceGrantId = value.grantId;
    if (sourceGrantId === null) throw new Error("expected authority lease");
    const encoded = encodeBootstrapAdmissionDecisionLeaseV1(value);

    sourceGrantId.fill(0xff);
    const decoded = decodeBootstrapAdmissionDecisionLeaseV1(encoded);
    encoded.fill(0xee);
    expect(decoded.grantId).toEqual(bytes32(0x44));
    expect(decoded.roomContextId).toEqual(bytes32(0x11));
    expect(decoded.admittedIdentityOperationId).toEqual(bytes32(0x77));
  });

  test("rejects invalid optional tags and canonical but impossible leases", () => {
    const capability = bootstrapLease(false);
    const encoded = encodeBootstrapAdmissionDecisionLeaseV1(capability);
    const invalidOptionalTag = Uint8Array.from(encoded);
    invalidOptionalTag[97] = 2;
    expect(() =>
      decodeBootstrapAdmissionDecisionLeaseV1(invalidOptionalTag),
    ).toThrow("presence tag");

    const partialAuthorityBinding = encodeCanonical(
      bootstrapAdmissionDecisionLeaseV1Schema,
      {
        ...capability,
        grantId: bytes32(0x44),
      },
    );
    expect(() =>
      decodeBootstrapAdmissionDecisionLeaseV1(partialAuthorityBinding),
    ).toThrow("all present or all absent");

    const impossibleInterval = encodeCanonical(
      bootstrapAdmissionDecisionLeaseV1Schema,
      {
        ...capability,
        decidedAtLogicalWindow: 15n,
        validThroughLogicalWindow: 14n,
      },
    );
    expect(() =>
      decodeBootstrapAdmissionDecisionLeaseV1(impossibleInterval),
    ).toThrow("impossible interval");

    expect(() =>
      decodeBootstrapAdmissionDecisionLeaseV1(Uint8Array.from([...encoded, 0])),
    ).toThrow("trailing");
    expect(() =>
      decodeBootstrapAdmissionDecisionLeaseV1(
        encoded.subarray(0, encoded.length - 1),
      ),
    ).toThrow("truncated");
  });
});
