import { describe, expect, test } from "bun:test";

import { authorityAdmissionStateDigest } from "../../src/blindRendezvous/derivations";

interface RevocationFact {
  readonly stableIdentityCommitment: Uint8Array;
  readonly minimumAcceptedGeneration: bigint;
  readonly effectiveLogicalWindow: bigint;
  readonly validThroughLogicalWindow: bigint;
  readonly revokeOperationId: Uint8Array;
}

interface AuthorityWindowFault {
  readonly logicalWindow: bigint;
  readonly proofOperationIds: readonly Uint8Array[];
}

interface DigestInput {
  readonly roomContextId: Uint8Array;
  readonly stableIdentityCommitment: Uint8Array;
  readonly status: "available" | "unavailable";
  readonly revocationFacts: readonly RevocationFact[];
  readonly blockingAuthorityWindowFaults: readonly AuthorityWindowFault[];
  readonly authorityCustodyStatus: "complete" | "saturated";
  readonly firstSaturatedRequiredWorkId: Uint8Array | null;
}

const bytes32 = (fill: number): Uint8Array => new Uint8Array(32).fill(fill);

const revocationFact = (
  minimumAcceptedGeneration: bigint,
  revokeOperationIdFill: number,
  commitmentFill = 0x22,
): RevocationFact => ({
  stableIdentityCommitment: bytes32(commitmentFill),
  minimumAcceptedGeneration,
  effectiveLogicalWindow: 4n,
  validThroughLogicalWindow: 20n,
  revokeOperationId: bytes32(revokeOperationIdFill),
});

const authorityFault = (
  logicalWindow: bigint,
  proofOperationIdFills: readonly number[],
): AuthorityWindowFault => ({
  logicalWindow,
  proofOperationIds: proofOperationIdFills.map(bytes32),
});

const canonicalInput = (): DigestInput => ({
  roomContextId: bytes32(0x11),
  stableIdentityCommitment: bytes32(0x22),
  status: "unavailable",
  revocationFacts: [revocationFact(1n, 0x41), revocationFact(2n, 0x42)],
  blockingAuthorityWindowFaults: [
    authorityFault(7n, [0x51, 0x52]),
    authorityFault(8n, [0x53, 0x54]),
  ],
  authorityCustodyStatus: "saturated",
  firstSaturatedRequiredWorkId: bytes32(0x61),
});

const availableInput = (): DigestInput => ({
  roomContextId: bytes32(0x11),
  stableIdentityCommitment: bytes32(0x22),
  status: "available",
  revocationFacts: [revocationFact(1n, 0x41)],
  blockingAuthorityWindowFaults: [],
  authorityCustodyStatus: "complete",
  firstSaturatedRequiredWorkId: null,
});

const digestHex = async (input: unknown): Promise<string> =>
  [...(await authorityAdmissionStateDigest(input))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

describe("AuthorityAdmissionStateDigest", () => {
  test("is deterministic for the same canonically ordered facts and faults", async () => {
    const input = canonicalInput();
    const reorderedProperties = {
      firstSaturatedRequiredWorkId: Uint8Array.from(
        input.firstSaturatedRequiredWorkId ?? new Uint8Array(32),
      ),
      blockingAuthorityWindowFaults: input.blockingAuthorityWindowFaults.map(
        (fault) => ({
          proofOperationIds: fault.proofOperationIds.map((id) =>
            Uint8Array.from(id),
          ),
          logicalWindow: fault.logicalWindow,
        }),
      ),
      authorityCustodyStatus: input.authorityCustodyStatus,
      status: input.status,
      stableIdentityCommitment: Uint8Array.from(input.stableIdentityCommitment),
      revocationFacts: input.revocationFacts.map((fact) => ({
        revokeOperationId: Uint8Array.from(fact.revokeOperationId),
        validThroughLogicalWindow: fact.validThroughLogicalWindow,
        stableIdentityCommitment: Uint8Array.from(
          fact.stableIdentityCommitment,
        ),
        effectiveLogicalWindow: fact.effectiveLogicalWindow,
        minimumAcceptedGeneration: fact.minimumAcceptedGeneration,
      })),
      roomContextId: Uint8Array.from(input.roomContextId),
    };

    const first = await digestHex(input);
    expect(await digestHex(input)).toBe(first);
    expect(await digestHex(reorderedProperties)).toBe(first);
  });

  test("changes for each decision-relevant status, revocation, fault, and custody witness", async () => {
    const available = availableInput();
    const availableDigest = await digestHex(available);
    expect(
      await digestHex({
        ...available,
        status: "unavailable",
      }),
    ).not.toBe(availableDigest);
    expect(
      await digestHex({
        ...available,
        revocationFacts: [revocationFact(2n, 0x41)],
      }),
    ).not.toBe(availableDigest);

    const faulted: DigestInput = {
      ...available,
      status: "unavailable",
      blockingAuthorityWindowFaults: [authorityFault(7n, [0x51, 0x52])],
    };
    expect(
      await digestHex({
        ...faulted,
        blockingAuthorityWindowFaults: [authorityFault(7n, [0x51, 0x53])],
      }),
    ).not.toBe(await digestHex(faulted));

    const saturated: DigestInput = {
      ...available,
      status: "unavailable",
      authorityCustodyStatus: "saturated",
      firstSaturatedRequiredWorkId: bytes32(0x61),
    };
    expect(
      await digestHex({
        ...saturated,
        firstSaturatedRequiredWorkId: bytes32(0x62),
      }),
    ).not.toBe(await digestHex(saturated));
  });

  test("rejects reordered and duplicate revocation or fault evidence", async () => {
    const input = canonicalInput();
    const firstRevocation = input.revocationFacts[0];
    const firstFault = input.blockingAuthorityWindowFaults[0];

    await expect(
      authorityAdmissionStateDigest({
        ...input,
        revocationFacts: [...input.revocationFacts].reverse(),
      }),
    ).rejects.toThrow("sorted by its complete canonical key");
    await expect(
      authorityAdmissionStateDigest({
        ...input,
        revocationFacts: [firstRevocation, firstRevocation],
      }),
    ).rejects.toThrow("duplicate-free");
    await expect(
      authorityAdmissionStateDigest({
        ...input,
        blockingAuthorityWindowFaults: [
          ...input.blockingAuthorityWindowFaults,
        ].reverse(),
      }),
    ).rejects.toThrow("sorted by its complete canonical key");
    await expect(
      authorityAdmissionStateDigest({
        ...input,
        blockingAuthorityWindowFaults: [firstFault, firstFault],
      }),
    ).rejects.toThrow("duplicate-free");
    await expect(
      authorityAdmissionStateDigest({
        ...input,
        blockingAuthorityWindowFaults: [authorityFault(7n, [0x52, 0x51])],
      }),
    ).rejects.toThrow("sorted by its complete canonical key");
    await expect(
      authorityAdmissionStateDigest({
        ...input,
        blockingAuthorityWindowFaults: [authorityFault(7n, [0x51, 0x51])],
      }),
    ).rejects.toThrow("duplicate-free");
  });

  test("ignores unrelated state only through the deliberate digest projection", async () => {
    interface WiderAuthorityState extends DigestInput {
      readonly referenceWindow: bigint;
      readonly wholeCoreStateDigest: Uint8Array;
      readonly authorityCustodyStateDigest: Uint8Array;
      readonly unrelatedRevocationFacts: readonly RevocationFact[];
    }

    const source: WiderAuthorityState = {
      ...availableInput(),
      referenceWindow: 10n,
      wholeCoreStateDigest: bytes32(0x71),
      authorityCustodyStateDigest: bytes32(0x72),
      unrelatedRevocationFacts: [revocationFact(1n, 0x73, 0x33)],
    };
    const project = ({
      roomContextId,
      stableIdentityCommitment,
      status,
      revocationFacts,
      blockingAuthorityWindowFaults,
      authorityCustodyStatus,
      firstSaturatedRequiredWorkId,
    }: WiderAuthorityState): DigestInput => ({
      roomContextId,
      stableIdentityCommitment,
      status,
      revocationFacts,
      blockingAuthorityWindowFaults,
      authorityCustodyStatus,
      firstSaturatedRequiredWorkId,
    });

    const changedOnlyOutsideProjection: WiderAuthorityState = {
      ...source,
      referenceWindow: 999n,
      wholeCoreStateDigest: bytes32(0x81),
      authorityCustodyStateDigest: bytes32(0x82),
      unrelatedRevocationFacts: [revocationFact(9n, 0x83, 0x44)],
    };
    const projectedDigest = await digestHex(project(source));
    expect(await digestHex(project(changedOnlyOutsideProjection))).toBe(
      projectedDigest,
    );

    expect(
      await digestHex({
        ...project(source),
        revocationFacts: [
          ...source.revocationFacts,
          ...source.unrelatedRevocationFacts,
        ],
      }),
    ).not.toBe(projectedDigest);
    await expect(
      authorityAdmissionStateDigest({
        ...project(source),
        referenceWindow: source.referenceWindow,
      }),
    ).rejects.toThrow("unexpected fields");
  });
});
