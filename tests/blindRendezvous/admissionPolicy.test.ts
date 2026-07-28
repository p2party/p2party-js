import { describe, expect, test } from "bun:test";

import { keyPairFromSeed, sign } from "../../src/cryptography/ed25519";
import {
  authorityFaultValidThrough,
  authorityGenerationAllowed,
  canonicalBytes32SetHas,
  constructBootstrapAdmissionDecisionLease,
  constructStableEdgeAdmissionLease,
  evaluatePeerAdmissionPolicySemantics,
  selectApplicableRevocationFacts,
  selectBlockingAuthorityWindowFaults,
  validateAndCopyFrontendRoomControlsV1,
  validateAndCopyPairAttemptLeaseV1,
} from "../../src/blindRendezvous/admissionPolicy";
import {
  admissionGrantSignedMessage,
  stableIdentityCommitment,
} from "../../src/blindRendezvous/derivations";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";

import type {
  AllowedPeerAdmissionPolicyV1,
  AuthorityAdmissionPolicyViewV1,
  BootstrapAdmissionLeaseSemanticInputV1,
  FrontendRoomControlsV1,
  PairAttemptLeaseV1,
  PeerAdmissionPolicySemanticInputV1,
  StableEdgeAdmissionLeaseSemanticInputV1,
} from "../../src/blindRendezvous/admissionPolicy";
import type {
  CoreFaultV1,
  CoreRevocationFloorV1,
} from "../../src/blindRendezvous/coreReduce";
import type { AdmissionGrantV1 } from "../../src/blindRendezvous/operationPayload";
import type { RoomPolicyV4 } from "../../src/blindRendezvous/roomPolicyV4";

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill & 0xff);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const permutations = <T>(values: readonly T[]): T[][] => {
  if (values.length === 0) return [[]];
  const result: T[][] = [];
  for (let index = 0; index < values.length; index++) {
    const head = values[index];
    const tail = [...values.slice(0, index), ...values.slice(index + 1)];
    for (const suffix of permutations(tail)) result.push([head, ...suffix]);
  }
  return result;
};

const authority = await keyPairFromSeed(bytes(0xa1));
const stable = await keyPairFromSeed(bytes(0xb1));
const otherStable = await keyPairFromSeed(bytes(0xc1));
const roomContextId = bytes(0xd1);
const candidateCommitment = await stableIdentityCommitment(
  roomContextId,
  stable.publicKey,
);

const capabilityPolicy = (): RoomPolicyV4 => ({
  ...DEFAULT_BLIND_POLICY_V4_0,
  sessionPolicyV1: Uint8Array.from(DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1),
  protocolLimits: { ...DEFAULT_BLIND_POLICY_V4_0.protocolLimits },
  admissionFloor: { mode: "capability" },
});

const authorityPolicy = (): RoomPolicyV4 => ({
  ...capabilityPolicy(),
  admissionFloor: {
    mode: "authority-grant",
    authorityEd25519PublicKey: Uint8Array.from(authority.publicKey),
    maxAuthorityCredentialLifetimeWindows: 10,
  },
});

const frontendControls = (
  overrides: Partial<FrontendRoomControlsV1> = {},
): FrontendRoomControlsV1 => ({
  version: 1,
  policyGeneration: 7n,
  onlyConnectWithKnownPeers: false,
  allowedStableIdentityKeys: [],
  deniedStableIdentityKeys: [],
  deniedRoomIdentityCommitments: [],
  ...overrides,
});

const authorityView = (
  overrides: Partial<AuthorityAdmissionPolicyViewV1> = {},
): AuthorityAdmissionPolicyViewV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(roomContextId),
  stableIdentityCommitment: Uint8Array.from(candidateCommitment),
  referenceWindow: 100n,
  status: "available",
  revocationFacts: [],
  authorityAdmissionStateDigest: bytes(0xe1),
  ...overrides,
});

const signedGrant = async (
  stableEd25519PublicKey = stable.publicKey,
  generation = 7n,
  overrides: Partial<Omit<AdmissionGrantV1, "authoritySignature">> = {},
): Promise<AdmissionGrantV1> => {
  const unsigned = {
    version: 1 as const,
    roomContextId: Uint8Array.from(roomContextId),
    stableEd25519PublicKey: Uint8Array.from(stableEd25519PublicKey),
    generation,
    issuedAtLogicalWindow: 95n,
    notBeforeLogicalWindow: 96n,
    notAfterLogicalWindow: 105n,
    ...overrides,
  };
  return {
    ...unsigned,
    authoritySignature: await sign(
      await admissionGrantSignedMessage(unsigned),
      authority.secretKey,
    ),
  };
};

const semanticInput = (
  overrides: Partial<PeerAdmissionPolicySemanticInputV1> = {},
): PeerAdmissionPolicySemanticInputV1 => ({
  roomContextId: Uint8Array.from(roomContextId),
  roomPolicy: capabilityPolicy(),
  referenceWindow: 100n,
  frontendControls: frontendControls(),
  authorityView: null,
  stableEd25519PublicKey: Uint8Array.from(stable.publicKey),
  stableIdentityCommitment: Uint8Array.from(candidateCommitment),
  optionalGrant: null,
  grantCarriedAtLogicalWindow: null,
  ...overrides,
});

describe("FrontendRoomControlsV1 in-memory normalization", () => {
  test("validates canonical byte sets, owns its copies, and uses byte membership", () => {
    const low = bytes(0x10);
    const high = bytes(0x20);
    const source = frontendControls({
      allowedStableIdentityKeys: [low, high],
      deniedStableIdentityKeys: [bytes(0x30)],
      deniedRoomIdentityCommitments: [bytes(0x40)],
    });
    const copy = validateAndCopyFrontendRoomControlsV1(source);

    low.fill(0xff);
    high.fill(0xff);
    expect(copy.allowedStableIdentityKeys.map(hex)).toEqual([
      hex(bytes(0x10)),
      hex(bytes(0x20)),
    ]);
    expect(
      canonicalBytes32SetHas(copy.allowedStableIdentityKeys, bytes(0x20)),
    ).toBe(true);
    expect(
      canonicalBytes32SetHas(copy.allowedStableIdentityKeys, bytes(0x21)),
    ).toBe(false);
  });

  test("rejects duplicate, unsorted, malformed, accessor, and extra fields", () => {
    expect(() =>
      validateAndCopyFrontendRoomControlsV1(
        frontendControls({
          allowedStableIdentityKeys: [bytes(0x20), bytes(0x10)],
        }),
      ),
    ).toThrow("bytewise sorted");
    expect(() =>
      validateAndCopyFrontendRoomControlsV1(
        frontendControls({
          allowedStableIdentityKeys: [bytes(0x10), bytes(0x10)],
        }),
      ),
    ).toThrow("duplicate-free");
    expect(() =>
      validateAndCopyFrontendRoomControlsV1(
        frontendControls({
          deniedStableIdentityKeys: [bytes(0x10, 31)],
        }),
      ),
    ).toThrow("exactly 32 bytes");
    expect(() =>
      validateAndCopyFrontendRoomControlsV1({
        ...frontendControls(),
        extra: true,
      }),
    ).toThrow("exactly its declared fields");

    const accessor = frontendControls() as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "policyGeneration", {
      enumerable: true,
      get: () => 7n,
    });
    expect(() => validateAndCopyFrontendRoomControlsV1(accessor)).toThrow(
      "exactly its declared fields",
    );
  });
});

describe("authority fact selection", () => {
  const commitment = bytes(0x51);
  const otherCommitment = bytes(0x52);
  const first: CoreRevocationFloorV1 = {
    stableIdentityCommitment: commitment,
    minimumAcceptedGeneration: 4n,
    effectiveLogicalWindow: 90n,
    validThroughLogicalWindow: 100n,
    revokeOperationId: bytes(0x30),
  };
  const second: CoreRevocationFloorV1 = {
    stableIdentityCommitment: commitment,
    minimumAcceptedGeneration: 8n,
    effectiveLogicalWindow: 95n,
    validThroughLogicalWindow: 105n,
    revokeOperationId: bytes(0x20),
  };
  const equalFloorDifferentHorizon: CoreRevocationFloorV1 = {
    ...second,
    validThroughLogicalWindow: 106n,
    revokeOperationId: bytes(0x21),
  };
  const unrelated: CoreRevocationFloorV1 = {
    ...first,
    stableIdentityCommitment: otherCommitment,
    revokeOperationId: bytes(0x10),
  };

  test("selects one canonical fact set under every delivery permutation", () => {
    const inputs = [
      second,
      equalFloorDifferentHorizon,
      unrelated,
      first,
      { ...first },
    ];
    for (const order of permutations(inputs)) {
      const selected = selectApplicableRevocationFacts(order, commitment, 100n);
      expect(
        selected.map((fact) => [
          fact.minimumAcceptedGeneration,
          fact.validThroughLogicalWindow,
          hex(fact.revokeOperationId),
        ]),
      ).toEqual([
        [4n, 100n, hex(bytes(0x30))],
        [8n, 105n, hex(bytes(0x20))],
        [8n, 106n, hex(bytes(0x21))],
      ]);
    }
  });

  test("applies the maximum generation floor inclusively", () => {
    const revocationFacts = selectApplicableRevocationFacts(
      [first, second],
      commitment,
      100n,
    );
    expect(
      authorityGenerationAllowed(7n, {
        status: "available",
        revocationFacts,
      }),
    ).toBe(false);
    expect(
      authorityGenerationAllowed(8n, {
        status: "available",
        revocationFacts,
      }),
    ).toBe(true);
    expect(
      authorityGenerationAllowed(100n, {
        status: "unavailable",
        revocationFacts,
      }),
    ).toBe(false);
  });

  test("uses the exact inclusive authority-fault horizon and canonical order", () => {
    const policy = authorityPolicy();
    const authorityFaultA: CoreFaultV1 = {
      kind: "author-fork-or-overquota",
      authorEpochEd25519Key: authority.publicKey,
      logicalWindow: 100n,
      proofOperationIds: [bytes(0x22), bytes(0x11)],
    };
    const authorityFaultB: CoreFaultV1 = {
      kind: "author-fork-or-overquota",
      authorEpochEd25519Key: authority.publicKey,
      logicalWindow: 101n,
      proofOperationIds: [bytes(0x44), bytes(0x33)],
    };
    const otherAuthorFault: CoreFaultV1 = {
      ...authorityFaultA,
      authorEpochEd25519Key: otherStable.publicKey,
    };
    const unrelatedFault: CoreFaultV1 = {
      kind: "presence-or-leave-fork",
      semanticSlot: bytes(0x55),
      proofOperationIds: [bytes(0x66), bytes(0x77)],
    };

    expect(authorityFaultValidThrough(policy, 100n)).toBe(120n);
    for (const order of permutations([
      authorityFaultB,
      otherAuthorFault,
      unrelatedFault,
      authorityFaultA,
    ])) {
      const selected = selectBlockingAuthorityWindowFaults(order, policy, 120n);
      expect(selected.unavailableThroughLogicalWindow).toBe(121n);
      expect(
        selected.blockingAuthorityWindowFaults.map((fault) => [
          fault.logicalWindow,
          fault.proofOperationIds.map(hex),
        ]),
      ).toEqual([
        [100n, [hex(bytes(0x11)), hex(bytes(0x22))]],
        [101n, [hex(bytes(0x33)), hex(bytes(0x44))]],
      ]);
    }

    expect(
      selectBlockingAuthorityWindowFaults([authorityFaultA], policy, 120n)
        .blockingAuthorityWindowFaults,
    ).toHaveLength(1);
    expect(
      selectBlockingAuthorityWindowFaults([authorityFaultA], policy, 121n),
    ).toEqual({
      blockingAuthorityWindowFaults: [],
      unavailableThroughLogicalWindow: null,
    });
    expect(() =>
      selectBlockingAuthorityWindowFaults(
        [
          {
            kind: "author-fork-or-overquota",
            authorEpochEd25519Key: authority.publicKey,
            logicalWindow: 100n,
            proofOperationIds: [],
          },
        ],
        policy,
        100n,
      ),
    ).toThrow("requires at least one proof operation");
    expect(() =>
      authorityFaultValidThrough(policy, 0xffffffffffffffffn),
    ).toThrow("overflowed");
  });
});

describe("shared peer-admission policy order", () => {
  test("implements capability open/address-book/deny precedence", async () => {
    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({ frontendControls: null }),
      ),
    ).resolves.toEqual({ result: "deny", reason: "policy-unavailable" });

    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          frontendControls: frontendControls({
            onlyConnectWithKnownPeers: true,
            allowedStableIdentityKeys: [stable.publicKey],
            deniedStableIdentityKeys: [stable.publicKey],
          }),
        }),
      ),
    ).resolves.toEqual({ result: "deny", reason: "blacklisted" });

    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          frontendControls: frontendControls({
            onlyConnectWithKnownPeers: true,
            allowedStableIdentityKeys: [stable.publicKey],
            deniedRoomIdentityCommitments: [candidateCommitment],
          }),
        }),
      ),
    ).resolves.toEqual({ result: "deny", reason: "blacklisted" });

    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          frontendControls: frontendControls({
            onlyConnectWithKnownPeers: true,
          }),
        }),
      ),
    ).resolves.toEqual({
      result: "deny",
      reason: "not-in-address-book",
    });

    const allowed = await evaluatePeerAdmissionPolicySemantics(
      semanticInput({
        frontendControls: frontendControls({
          policyGeneration: 9n,
          onlyConnectWithKnownPeers: true,
          allowedStableIdentityKeys: [stable.publicKey],
        }),
      }),
    );
    expect(allowed).toEqual({
      result: "allow",
      reason: "address-book",
      localPolicyGeneration: 9n,
      grantId: null,
      grantGeneration: null,
      authorityAdmissionStateDigest: null,
      grantValidThroughLogicalWindow: null,
    });
  });

  test("closes capability credential mode and rejects a false commitment", async () => {
    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          optionalGrant: await signedGrant(),
          grantCarriedAtLogicalWindow: 99n,
        }),
      ),
    ).resolves.toEqual({ result: "deny", reason: "invalid-grant" });

    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          stableIdentityCommitment: bytes(0xff),
        }),
      ),
    ).rejects.toThrow("does not match");
    await expect(
      evaluatePeerAdmissionPolicySemantics(
        semanticInput({
          authorityView: authorityView(),
        }),
      ),
    ).rejects.toThrow("capability mode forbids");
  });

  test("orders authority availability, grant validity, revocation, and address book", async () => {
    const grant = await signedGrant();
    const base = semanticInput({
      roomPolicy: authorityPolicy(),
      authorityView: authorityView(),
      optionalGrant: grant,
      grantCarriedAtLogicalWindow: 99n,
    });

    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        authorityView: null,
        optionalGrant: null,
      }),
    ).resolves.toEqual({ result: "deny", reason: "policy-unavailable" });
    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        authorityView: authorityView({ status: "unavailable" }),
      }),
    ).resolves.toEqual({ result: "deny", reason: "policy-unavailable" });
    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        optionalGrant: null,
        grantCarriedAtLogicalWindow: null,
      }),
    ).resolves.toEqual({ result: "deny", reason: "missing-grant" });

    const revocation: CoreRevocationFloorV1 = {
      stableIdentityCommitment: candidateCommitment,
      minimumAcceptedGeneration: 8n,
      effectiveLogicalWindow: 90n,
      validThroughLogicalWindow: 110n,
      revokeOperationId: bytes(0x70),
    };
    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        authorityView: authorityView({ revocationFacts: [revocation] }),
      }),
    ).resolves.toEqual({ result: "deny", reason: "revoked" });

    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        frontendControls: frontendControls({
          onlyConnectWithKnownPeers: true,
        }),
      }),
    ).resolves.toEqual({
      result: "deny",
      reason: "not-in-address-book",
    });

    const allowed = await evaluatePeerAdmissionPolicySemantics({
      ...base,
      frontendControls: frontendControls({
        policyGeneration: 11n,
        onlyConnectWithKnownPeers: true,
        allowedStableIdentityKeys: [stable.publicKey],
      }),
    });
    expect(allowed.result).toBe("allow");
    if (allowed.result !== "allow") throw new Error("expected authority allow");
    expect(allowed.reason).toBe("authority-grant");
    expect(allowed.localPolicyGeneration).toBe(11n);
    expect(allowed.grantGeneration).toBe(7n);
    expect(allowed.grantValidThroughLogicalWindow).toBe(105n);
    expect(hex(allowed.authorityAdmissionStateDigest!)).toBe(hex(bytes(0xe1)));
  });

  test("maps a validly signed wrong-subject or bad-signature grant to invalid-grant", async () => {
    const wrongSubjectGrant = await signedGrant(otherStable.publicKey);
    const badSignatureGrant = {
      ...(await signedGrant()),
      authoritySignature: bytes(0xff, 64),
    };
    const base = semanticInput({
      roomPolicy: authorityPolicy(),
      authorityView: authorityView(),
      grantCarriedAtLogicalWindow: 99n,
    });

    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        optionalGrant: wrongSubjectGrant,
      }),
    ).resolves.toEqual({ result: "deny", reason: "invalid-grant" });
    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        optionalGrant: badSignatureGrant,
      }),
    ).resolves.toEqual({ result: "deny", reason: "invalid-grant" });

    await expect(
      evaluatePeerAdmissionPolicySemantics({
        ...base,
        optionalGrant: wrongSubjectGrant,
        frontendControls: frontendControls({
          deniedStableIdentityKeys: [stable.publicKey],
        }),
      }),
    ).resolves.toEqual({ result: "deny", reason: "blacklisted" });
  });

  test("maps exact grant interval boundaries and adjacent failures", async () => {
    const base = semanticInput({
      roomPolicy: authorityPolicy(),
      authorityView: authorityView(),
      grantCarriedAtLogicalWindow: 99n,
    });
    const allowedGrants = [
      await signedGrant(),
      await signedGrant(stable.publicKey, 7n, {
        notBeforeLogicalWindow: 100n,
      }),
      await signedGrant(stable.publicKey, 7n, {
        notAfterLogicalWindow: 100n,
      }),
    ];
    const allowedHorizons = [105n, 105n, 100n];
    for (let index = 0; index < allowedGrants.length; index++) {
      const decision = await evaluatePeerAdmissionPolicySemantics({
        ...base,
        optionalGrant: allowedGrants[index],
      });
      expect(decision.result).toBe("allow");
      if (decision.result !== "allow")
        throw new Error("expected boundary grant allow");
      expect(decision.reason).toBe("authority-grant");
      expect(decision.grantValidThroughLogicalWindow).toBe(
        allowedHorizons[index],
      );
    }

    const invalidCases: readonly {
      readonly grant: AdmissionGrantV1;
      readonly carriedAtLogicalWindow: bigint;
    }[] = [
      {
        grant: await signedGrant(stable.publicKey, 7n, {
          notAfterLogicalWindow: 106n,
        }),
        carriedAtLogicalWindow: 99n,
      },
      {
        grant: await signedGrant(stable.publicKey, 7n, {
          notBeforeLogicalWindow: 101n,
        }),
        carriedAtLogicalWindow: 99n,
      },
      {
        grant: await signedGrant(stable.publicKey, 7n, {
          notAfterLogicalWindow: 99n,
        }),
        carriedAtLogicalWindow: 99n,
      },
      {
        grant: await signedGrant(stable.publicKey, 7n, {
          roomContextId: bytes(0xd2),
        }),
        carriedAtLogicalWindow: 99n,
      },
      {
        grant: await signedGrant(),
        carriedAtLogicalWindow: 101n,
      },
      {
        grant: await signedGrant(stable.publicKey, 7n, {
          issuedAtLogicalWindow: 100n,
          notBeforeLogicalWindow: 100n,
        }),
        carriedAtLogicalWindow: 99n,
      },
    ];
    for (const invalidCase of invalidCases)
      await expect(
        evaluatePeerAdmissionPolicySemantics({
          ...base,
          optionalGrant: invalidCase.grant,
          grantCarriedAtLogicalWindow: invalidCase.carriedAtLogicalWindow,
        }),
      ).resolves.toEqual({ result: "deny", reason: "invalid-grant" });
  });
});

describe("pair and decision lease semantics", () => {
  const pairAttemptLease = (): PairAttemptLeaseV1 => ({
    version: 1,
    helloOperationId: bytes(0x01),
    pairEdgeId: bytes(0x02),
    endpointPresenceOperationIds: [bytes(0x03), bytes(0x04)],
    attemptMode: "planner",
    helloLogicalWindow: 90n,
    validThroughLogicalWindow: 120n,
  });

  const capabilityAllow = (): AllowedPeerAdmissionPolicyV1 => ({
    result: "allow",
    reason: "open",
    localPolicyGeneration: 7n,
    grantId: null,
    grantGeneration: null,
    authorityAdmissionStateDigest: null,
    grantValidThroughLogicalWindow: null,
  });

  const authorityAllow = (): AllowedPeerAdmissionPolicyV1 => ({
    result: "allow",
    reason: "authority-grant",
    localPolicyGeneration: 8n,
    grantId: bytes(0x05),
    grantGeneration: 9n,
    authorityAdmissionStateDigest: bytes(0x06),
    grantValidThroughLogicalWindow: 112n,
  });

  const bootstrapInput = (
    overrides: Partial<BootstrapAdmissionLeaseSemanticInputV1> = {},
  ): BootstrapAdmissionLeaseSemanticInputV1 => ({
    policy: capabilityAllow(),
    roomContextId: bytes(0x10),
    stableEd25519PublicKey: stable.publicKey,
    stableIdentityCommitment: candidateCommitment,
    admittedPresenceOperationId: bytes(0x11),
    admittedIdentityOperationId: bytes(0x12),
    admittedIdentityOperationLogicalWindow: 95n,
    admittedIdentityOperationValidThroughLogicalWindow: 118n,
    admittedPresenceEvidenceRetainThroughLogicalWindow: 115n,
    basePairAttemptLease: pairAttemptLease(),
    referenceWindow: 100n,
    ...overrides,
  });

  const stableInput = (
    overrides: Partial<StableEdgeAdmissionLeaseSemanticInputV1> = {},
  ): StableEdgeAdmissionLeaseSemanticInputV1 => ({
    policy: capabilityAllow(),
    roomContextId: bytes(0x20),
    stableEdgeId: bytes(0x21),
    confirmedPairTranscriptId: bytes(0x22),
    rendezvousChannelId: bytes(0x23),
    v4WireBinding: bytes(0x24),
    remoteStableEd25519PublicKey: stable.publicKey,
    remoteStableIdentityCommitment: candidateCommitment,
    referenceWindow: 100n,
    ...overrides,
  });

  test("copies a pair-attempt lease and rejects an impossible interval", () => {
    const source = pairAttemptLease();
    const copy = validateAndCopyPairAttemptLeaseV1(source);
    source.helloOperationId.fill(0xff);
    expect(hex(copy.helloOperationId)).toBe(hex(bytes(0x01)));
    expect(() =>
      validateAndCopyPairAttemptLeaseV1({
        ...pairAttemptLease(),
        helloLogicalWindow: 121n,
      }),
    ).toThrow("impossible interval");

    expect(() =>
      validateAndCopyPairAttemptLeaseV1({
        ...pairAttemptLease(),
        unregistered: true,
      }),
    ).toThrow("exactly its declared fields");

    const accessorBacked = pairAttemptLease();
    Object.defineProperty(accessorBacked, "pairEdgeId", {
      enumerable: true,
      get: () => bytes(0x02),
    });
    expect(() => validateAndCopyPairAttemptLeaseV1(accessorBacked)).toThrow(
      "exactly its declared fields",
    );

    const tupleWithExtraProperty = pairAttemptLease();
    Object.assign(tupleWithExtraProperty.endpointPresenceOperationIds, {
      unregistered: true,
    });
    expect(() =>
      validateAndCopyPairAttemptLeaseV1(tupleWithExtraProperty),
    ).toThrow("exactly two data-property IDs");
  });

  test("uses the exact bootstrap minimum, including the authority grant", () => {
    const capabilityDecision =
      constructBootstrapAdmissionDecisionLease(bootstrapInput());
    expect(capabilityDecision.result).toBe("allow");
    if (capabilityDecision.result !== "allow")
      throw new Error("expected bootstrap allow");
    expect(capabilityDecision.bootstrapLease.validThroughLogicalWindow).toBe(
      115n,
    );
    expect(capabilityDecision.bootstrapLease.decidedAtLogicalWindow).toBe(100n);
    expect(capabilityDecision.pairAttemptLease.validThroughLogicalWindow).toBe(
      120n,
    );

    const pairDecision = constructBootstrapAdmissionDecisionLease(
      bootstrapInput({
        basePairAttemptLease: {
          ...pairAttemptLease(),
          validThroughLogicalWindow: 110n,
        },
      }),
    );
    expect(pairDecision.result).toBe("allow");
    if (pairDecision.result !== "allow")
      throw new Error("expected pair-horizon bootstrap allow");
    expect(pairDecision.bootstrapLease.validThroughLogicalWindow).toBe(110n);
    expect(pairDecision.pairAttemptLease.validThroughLogicalWindow).toBe(110n);

    const identityDecision = constructBootstrapAdmissionDecisionLease(
      bootstrapInput({
        admittedIdentityOperationValidThroughLogicalWindow: 111n,
      }),
    );
    expect(identityDecision.result).toBe("allow");
    if (identityDecision.result !== "allow")
      throw new Error("expected identity-horizon bootstrap allow");
    expect(identityDecision.bootstrapLease.validThroughLogicalWindow).toBe(
      111n,
    );
    expect(identityDecision.pairAttemptLease.validThroughLogicalWindow).toBe(
      120n,
    );

    const authorityDecision = constructBootstrapAdmissionDecisionLease(
      bootstrapInput({ policy: authorityAllow() }),
    );
    expect(authorityDecision.result).toBe("allow");
    if (authorityDecision.result !== "allow")
      throw new Error("expected authority bootstrap allow");
    expect(authorityDecision.bootstrapLease.validThroughLogicalWindow).toBe(
      112n,
    );
    expect(authorityDecision.bootstrapLease.grantGeneration).toBe(9n);
    expect(authorityDecision.pairAttemptLease.validThroughLogicalWindow).toBe(
      112n,
    );

    expect(
      constructBootstrapAdmissionDecisionLease(
        bootstrapInput({
          admittedPresenceEvidenceRetainThroughLogicalWindow: 99n,
        }),
      ),
    ).toEqual({ result: "deny", reason: "policy-unavailable" });
  });

  test("constructs capability and finite authority stable-edge leases", () => {
    const capabilityDecision = constructStableEdgeAdmissionLease(stableInput());
    expect(capabilityDecision.result).toBe("allow");
    if (capabilityDecision.result !== "allow")
      throw new Error("expected stable-edge allow");
    expect(capabilityDecision.lease.validThroughLogicalWindow).toBeNull();
    expect(capabilityDecision.lease.localPolicyGeneration).toBe(7n);

    const authorityDecision = constructStableEdgeAdmissionLease(
      stableInput({ policy: authorityAllow() }),
    );
    expect(authorityDecision.result).toBe("allow");
    if (authorityDecision.result !== "allow")
      throw new Error("expected authority stable-edge allow");
    expect(authorityDecision.lease.validThroughLogicalWindow).toBe(112n);
    expect(hex(authorityDecision.lease.v4WireBinding)).toBe(hex(bytes(0x24)));

    expect(
      constructStableEdgeAdmissionLease(
        stableInput({
          policy: authorityAllow(),
          referenceWindow: 113n,
        }),
      ),
    ).toEqual({ result: "deny", reason: "policy-unavailable" });
  });

  test("returns byte-owned policy and lease results", async () => {
    const view = authorityView();
    const policyDecision = await evaluatePeerAdmissionPolicySemantics(
      semanticInput({
        roomPolicy: authorityPolicy(),
        authorityView: view,
        optionalGrant: await signedGrant(),
        grantCarriedAtLogicalWindow: 99n,
      }),
    );
    expect(policyDecision.result).toBe("allow");
    if (policyDecision.result !== "allow")
      throw new Error("expected owned policy allow");
    view.authorityAdmissionStateDigest.fill(0xff);
    expect(hex(policyDecision.authorityAdmissionStateDigest!)).toBe(
      hex(bytes(0xe1)),
    );

    const policy = authorityAllow();
    const bootstrapSource = bootstrapInput({
      policy,
      stableEd25519PublicKey: Uint8Array.from(stable.publicKey),
      stableIdentityCommitment: Uint8Array.from(candidateCommitment),
    });
    const stableSource = stableInput({
      policy,
      remoteStableEd25519PublicKey: Uint8Array.from(stable.publicKey),
      remoteStableIdentityCommitment: Uint8Array.from(candidateCommitment),
    });
    const bootstrapDecision =
      constructBootstrapAdmissionDecisionLease(bootstrapSource);
    const stableDecision = constructStableEdgeAdmissionLease(stableSource);
    expect(bootstrapDecision.result).toBe("allow");
    expect(stableDecision.result).toBe("allow");
    if (
      bootstrapDecision.result !== "allow" ||
      stableDecision.result !== "allow"
    )
      throw new Error("expected owned lease allows");

    bootstrapSource.roomContextId.fill(0xff);
    bootstrapSource.stableEd25519PublicKey.fill(0xff);
    bootstrapSource.admittedPresenceOperationId.fill(0xff);
    bootstrapSource.basePairAttemptLease.pairEdgeId.fill(0xff);
    stableSource.v4WireBinding.fill(0xff);
    stableSource.remoteStableIdentityCommitment.fill(0xff);
    policy.grantId!.fill(0xff);
    policy.authorityAdmissionStateDigest!.fill(0xff);

    expect(hex(bootstrapDecision.bootstrapLease.roomContextId)).toBe(
      hex(bytes(0x10)),
    );
    expect(hex(bootstrapDecision.bootstrapLease.stableEd25519PublicKey)).toBe(
      hex(stable.publicKey),
    );
    expect(
      hex(bootstrapDecision.bootstrapLease.admittedPresenceOperationId),
    ).toBe(hex(bytes(0x11)));
    expect(hex(bootstrapDecision.bootstrapLease.grantId!)).toBe(
      hex(bytes(0x05)),
    );
    expect(
      hex(bootstrapDecision.bootstrapLease.authorityAdmissionStateDigest!),
    ).toBe(hex(bytes(0x06)));
    expect(hex(bootstrapDecision.pairAttemptLease.pairEdgeId)).toBe(
      hex(bytes(0x02)),
    );
    expect(hex(stableDecision.lease.v4WireBinding)).toBe(hex(bytes(0x24)));
    expect(hex(stableDecision.lease.remoteStableIdentityCommitment)).toBe(
      hex(candidateCommitment),
    );
    expect(hex(stableDecision.lease.grantId!)).toBe(hex(bytes(0x05)));
    expect(hex(stableDecision.lease.authorityAdmissionStateDigest!)).toBe(
      hex(bytes(0x06)),
    );
  });
});
