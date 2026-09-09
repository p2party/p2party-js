import { describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import {
  coreOperationSetDigest,
  localPeerId,
  openPresenceRank,
  policyHash,
  presenceOwnershipSignedMessage,
  presenceProofTranscriptHash,
  stableIdentityCommitment,
} from "../../src/blindRendezvous/derivations";
import { evaluateLocalAdmissibleProjectionSemanticsV1 } from "../../src/blindRendezvous/localAdmissibleProject";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import { createOperationValidationContext } from "../../src/blindRendezvous/operation";

import type { FrontendRoomControlsV1 } from "../../src/blindRendezvous/admissionPolicy";
import type {
  CorePresenceFactV1,
  CoreRoomStateV1,
} from "../../src/blindRendezvous/coreReduce";
import type { LocalAdmissibleProjectSemanticInputV1 } from "../../src/blindRendezvous/localAdmissibleProject";
import type {
  ConnectionPlannerModeV1,
  PlannerAndExplicitStateV1,
} from "../../src/blindRendezvous/plannerState";
import type {
  PresenceCoreV1,
  PresencePermitV1,
} from "../../src/blindRendezvous/operationPayload";
import type { RoomPolicyV4 } from "../../src/blindRendezvous/roomPolicyV4";

const bytes32 = (value: number): Uint8Array => new Uint8Array(32).fill(value);

const hex = (value: Uint8Array): string => {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  for (let index = 0; index < left.length; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return 0;
};

const capability = bytes32(0x42);
const referenceWindow = 10n;

const room = async (
  maxRoomMembers: number,
  authority = false,
): Promise<{
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
}> => {
  const authorityKey = authority ? await newKeyPair() : null;
  const roomPolicy: RoomPolicyV4 = {
    ...DEFAULT_BLIND_POLICY_V4_0,
    maxRoomMembers,
    admissionFloor:
      authorityKey === null
        ? { mode: "capability" }
        : {
            mode: "authority-grant",
            authorityEd25519PublicKey: authorityKey.publicKey,
            maxAuthorityCredentialLifetimeWindows: 64,
          },
  };
  const context = await createOperationValidationContext(
    capability,
    roomPolicy,
    referenceWindow,
  );
  return {
    roomContextId: context.roomContextId,
    roomPolicy,
  };
};

type KeyPair = Awaited<ReturnType<typeof newKeyPair>>;

const presenceFact = async (
  roomContextId: Uint8Array,
  roomPolicy: RoomPolicyV4,
  stable: KeyPair,
  operationIdByte: number,
  options: {
    readonly author?: KeyPair;
    readonly corruptOwnership?: boolean;
    readonly authorityPermit?: PresencePermitV1 | null;
  } = {},
): Promise<CorePresenceFactV1> => {
  const author = options.author ?? (await newKeyPair());
  const core: PresenceCoreV1 = {
    version: 1,
    stableIdentityCommitment: await stableIdentityCommitment(
      roomContextId,
      stable.publicKey,
    ),
    rendezvousHybridKemPublicKey: new Uint8Array(1216).fill(operationIdByte),
    receiverKeyValidThroughLogicalWindow: referenceWindow + 4n,
    presenceNonce: bytes32(operationIdByte ^ 0x80),
    validThroughLogicalWindow: referenceWindow + 3n,
  };
  const transcriptHash = await presenceProofTranscriptHash({
    roomContextId,
    policyHash: await policyHash(roomPolicy),
    logicalWindow: referenceWindow,
    authorEpochEd25519Key: author.publicKey,
    core,
  });
  const stableOwnershipSignature = await sign(
    presenceOwnershipSignedMessage(transcriptHash),
    stable.secretKey,
  );
  if (options.corruptOwnership === true) stableOwnershipSignature[0] ^= 0xff;
  return {
    presenceOperationId: bytes32(operationIdByte),
    authorEpochEd25519Key: Uint8Array.from(author.publicKey),
    logicalWindow: referenceWindow,
    presence: {
      core,
      stableOwnershipSignature,
      authorityPermit: options.authorityPermit ?? null,
    },
  };
};

const coreState = async (
  facts: readonly CorePresenceFactV1[],
  maxRoomMembers: number,
): Promise<CoreRoomStateV1> => {
  const observedPresences = [...facts].sort((left, right) =>
    compareBytes(left.presenceOperationId, right.presenceOperationId),
  );
  const activeOperationIds = observedPresences.map(
    (fact) => fact.presenceOperationId,
  );
  return {
    version: 1,
    referenceWindow,
    roomCapacityState:
      facts.length > maxRoomMembers ? "overcapacity" : "within-policy",
    activeOperationIds,
    observedPresences,
    effectiveLeaveOperationIds: [],
    storeCatalogFacts: [],
    revocationFloors: [],
    activePairOuterOperationIds: [],
    faults: [],
    operationsDigest: await coreOperationSetDigest(activeOperationIds),
  };
};

const controls = (
  overrides: Partial<FrontendRoomControlsV1> = {},
): FrontendRoomControlsV1 => ({
  version: 1,
  policyGeneration: 1n,
  onlyConnectWithKnownPeers: false,
  allowedStableIdentityKeys: [],
  deniedStableIdentityKeys: [],
  deniedRoomIdentityCommitments: [],
  ...overrides,
});

const planner = (
  roomContextId: Uint8Array,
  maxRoomMembers: number,
  overrides: {
    readonly mode?: ConnectionPlannerModeV1;
    readonly sparseRadius?: number;
    readonly fullMeshMaxMembers?: number;
    readonly allowOnDemandEdges?: boolean;
    readonly requestedExplicitPeerIds?: readonly string[];
  } = {},
): PlannerAndExplicitStateV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(roomContextId),
  plannerPolicy: {
    version: 1,
    mode: overrides.mode ?? "sparse-ring",
    sparseRadius: overrides.sparseRadius ?? 1,
    maxProvisionalEdges: maxRoomMembers,
    maxActiveStableEdges: maxRoomMembers - 1,
    fullMeshMaxMembers: overrides.fullMeshMaxMembers ?? maxRoomMembers,
    allowOnDemandEdges: overrides.allowOnDemandEdges ?? true,
  },
  requestedExplicitPeerIds: overrides.requestedExplicitPeerIds ?? [],
  provisionalEdges: [],
  activeStableEdges: [],
});

const input = (
  roomContextId: Uint8Array,
  roomPolicy: RoomPolicyV4,
  coreRoomState: CoreRoomStateV1,
  localPresenceOperationIds: readonly Uint8Array[],
  overrides: {
    readonly frontendControls?: FrontendRoomControlsV1 | null;
    readonly plannerAndExplicitState?: PlannerAndExplicitStateV1;
    readonly localStableIdentityKeys?: readonly Uint8Array[];
    readonly maxRetainedValidOperationsPerRoom?: number;
  } = {},
): LocalAdmissibleProjectSemanticInputV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(roomContextId),
  roomPolicy,
  referenceWindow,
  coreRoomState,
  frontendControls:
    "frontendControls" in overrides
      ? (overrides.frontendControls ?? null)
      : controls(),
  localPresenceOwnership: {
    version: 1,
    localPresenceOperationIds,
    localStableIdentityKeys: overrides.localStableIdentityKeys ?? [],
  },
  plannerAndExplicitState:
    overrides.plannerAndExplicitState ??
    planner(roomContextId, roomPolicy.maxRoomMembers),
  maxRetainedValidOperationsPerRoom:
    overrides.maxRetainedValidOperationsPerRoom ??
    Math.max(
      roomPolicy.maxRoomMembers + 2,
      coreRoomState.activeOperationIds.length + 1,
    ),
  maxPairLedgerEntriesPerRoom: roomPolicy.maxRoomMembers + 2,
});

const sortedByOpenRank = async (
  roomContextId: Uint8Array,
  facts: readonly CorePresenceFactV1[],
): Promise<CorePresenceFactV1[]> => {
  const ranked = await Promise.all(
    facts.map(async (fact) => ({
      fact,
      rank: await openPresenceRank(roomContextId, fact.presenceOperationId),
    })),
  );
  ranked.sort(
    (left, right) =>
      compareBytes(left.rank, right.rank) ||
      compareBytes(
        left.fact.presenceOperationId,
        right.fact.presenceOperationId,
      ),
  );
  return ranked.map(({ fact }) => fact);
};

describe("local admissible Project semantics", () => {
  test("ranks the complete overcapacity Core and includes the local vertex in the cap", async () => {
    const context = await room(3);
    const stableKeys = await Promise.all(
      [1, 2, 3, 4, 5].map(() => newKeyPair()),
    );
    const facts = await Promise.all(
      stableKeys.map((stable, index) =>
        presenceFact(
          context.roomContextId,
          context.roomPolicy,
          stable,
          index + 1,
        ),
      ),
    );
    const ranked = await sortedByOpenRank(context.roomContextId, facts);
    const source = input(
      context.roomContextId,
      context.roomPolicy,
      await coreState(facts, 3),
      [ranked[0].presenceOperationId],
    );
    const expectedLocalPresenceOperationId = Uint8Array.from(
      ranked[0].presenceOperationId,
    );
    const expectedSelectedPresenceOperationIds = ranked
      .slice(0, 3)
      .map((fact) => hex(fact.presenceOperationId))
      .sort();
    const pending = evaluateLocalAdmissibleProjectionSemanticsV1(source);

    source.roomContextId.fill(0xff);
    source.coreRoomState.operationsDigest.fill(0xff);
    source.coreRoomState.observedPresences[0].presenceOperationId.fill(0xff);
    source.localPresenceOwnership.localPresenceOperationIds[0].fill(0xff);

    const result = await pending;
    expect(result.projectionStatus).toBe("ready");
    expect(result.state.localPresenceOperationId).toEqual(
      expectedLocalPresenceOperationId,
    );
    expect(
      [
        result.state.localPresenceOperationId,
        ...result.state.peers.map((peer) => peer.presenceOperationId),
      ]
        .map((value) => hex(value!))
        .sort(),
    ).toEqual(expectedSelectedPresenceOperationIds);
    expect(result.state.peers.every((peer) => peer.desiredEdge)).toBe(true);
    expect(
      result.state.peers.every((peer) => peer.eligibility === "open"),
    ).toBe(true);
  });

  test("fails closed when local ownership is absent, outside the cap, or ambiguous", async () => {
    const context = await room(3);
    const stableKeys = await Promise.all([1, 2, 3, 4].map(() => newKeyPair()));
    const facts = await Promise.all(
      stableKeys.map((stable, index) =>
        presenceFact(
          context.roomContextId,
          context.roomPolicy,
          stable,
          index + 1,
        ),
      ),
    );
    const ranked = await sortedByOpenRank(context.roomContextId, facts);
    const core = await coreState(facts, 3);

    for (const localIds of [
      [],
      [ranked[3].presenceOperationId],
      [ranked[0].presenceOperationId, ranked[1].presenceOperationId].sort(
        compareBytes,
      ),
    ]) {
      const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
        input(context.roomContextId, context.roomPolicy, core, localIds),
      );
      expect(result.projectionStatus).toBe("no-unambiguous-local-presence");
      expect(result.state.localPresenceOperationId).toBeNull();
      expect(result.state.localPresenceRank).toBeNull();
      expect(result.state.peers.every((peer) => !peer.desiredEdge)).toBe(true);
    }
  });

  test("requires an address-book ownership proof, applies denial first, and deduplicates strict identities", async () => {
    const context = await room(4);
    const localStable = await newKeyPair();
    const denied = await newKeyPair();
    const remoteStable = await newKeyPair();
    const knownFirst = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      1,
    );
    const knownDuplicate = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      2,
    );
    const deniedFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      denied,
      3,
    );
    const invalidRemoteProof = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      4,
      { corruptOwnership: true },
    );
    const remoteFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      5,
    );
    const strictControls = controls({
      onlyConnectWithKnownPeers: true,
      allowedStableIdentityKeys: [
        remoteStable.publicKey,
        denied.publicKey,
      ].sort(compareBytes),
      deniedStableIdentityKeys: [denied.publicKey],
    });
    const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(
          [
            knownFirst,
            knownDuplicate,
            deniedFact,
            invalidRemoteProof,
            remoteFact,
          ],
          4,
        ),
        [knownFirst.presenceOperationId],
        {
          frontendControls: strictControls,
          localStableIdentityKeys: [localStable.publicKey],
        },
      ),
    );

    expect(result.projectionStatus).toBe("ready");
    expect(result.state.localPresenceOperationId).toEqual(
      knownFirst.presenceOperationId,
    );
    expect(result.state.peers).toHaveLength(1);
    expect(result.state.peers[0].presenceOperationId).toEqual(
      remoteFact.presenceOperationId,
    );
    expect(result.state.peers[0].eligibility).toBe("local-address-book-proved");

    const openResult = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([knownFirst, knownDuplicate], 4),
        [knownFirst.presenceOperationId],
        {
          frontendControls: controls({
            allowedStableIdentityKeys: [localStable.publicKey],
          }),
        },
      ),
    );
    expect(openResult.state.peers).toHaveLength(1);
    expect(openResult.state.peers[0].eligibility).toBe("open");

    const corruptOnly = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      6,
      { corruptOwnership: true },
    );
    const corruptResult = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([knownFirst, corruptOnly], 4),
        [knownFirst.presenceOperationId],
        {
          frontendControls: controls({
            onlyConnectWithKnownPeers: true,
            allowedStableIdentityKeys: [remoteStable.publicKey],
          }),
          localStableIdentityKeys: [localStable.publicKey],
        },
      ),
    );
    expect(corruptResult.projectionStatus).toBe("ready");
    expect(corruptResult.state.peers).toEqual([]);

    const mutationSafeRemote = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      7,
    );
    const mutableControls = controls({
      onlyConnectWithKnownPeers: true,
      allowedStableIdentityKeys: [Uint8Array.from(remoteStable.publicKey)],
    });
    const mutableLocalStableKey = Uint8Array.from(localStable.publicKey);
    const mutationInput = input(
      context.roomContextId,
      context.roomPolicy,
      await coreState([knownFirst, mutationSafeRemote], 4),
      [knownFirst.presenceOperationId],
      {
        frontendControls: mutableControls,
        localStableIdentityKeys: [mutableLocalStableKey],
      },
    );
    const mutationPending =
      evaluateLocalAdmissibleProjectionSemanticsV1(mutationInput);
    mutationSafeRemote.presence.stableOwnershipSignature.fill(0);
    mutableControls.allowedStableIdentityKeys[0].fill(0);
    mutableLocalStableKey.fill(0);
    await expect(mutationPending).resolves.toMatchObject({
      projectionStatus: "ready",
      state: { peers: [{ eligibility: "local-address-book-proved" }] },
    });
  });

  test("selects the lowest valid strict presence identity-wide before testing local ownership", async () => {
    const context = await room(3);
    const localStable = await newKeyPair();
    const lowerUnowned = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      1,
    );
    const higherOwned = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      2,
    );
    const strictControls = controls({ onlyConnectWithKnownPeers: true });

    const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([higherOwned, lowerUnowned], 3),
        [higherOwned.presenceOperationId],
        {
          frontendControls: strictControls,
          localStableIdentityKeys: [localStable.publicKey],
        },
      ),
    );

    expect(result.projectionStatus).toBe("no-unambiguous-local-presence");
    expect(result.state.localPresenceOperationId).toBeNull();
    expect(result.state.peers).toHaveLength(1);
    expect(result.state.peers[0].presenceOperationId).toEqual(
      lowerUnowned.presenceOperationId,
    );
    expect(result.state.peers[0].desiredEdge).toBe(false);

    const corruptOwned = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      3,
      { corruptOwnership: true },
    );
    const corruptResult = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([corruptOwned], 3),
        [corruptOwned.presenceOperationId],
        {
          frontendControls: strictControls,
          localStableIdentityKeys: [localStable.publicKey],
        },
      ),
    );
    expect(corruptResult.projectionStatus).toBe(
      "no-unambiguous-local-presence",
    );
    expect(corruptResult.state.peers).toEqual([]);
  });

  test("derives sparse-ring neighbors from rank order including wraparound", async () => {
    const context = await room(5);
    const stableKeys = await Promise.all(
      [1, 2, 3, 4, 5].map(() => newKeyPair()),
    );
    const facts = await Promise.all(
      stableKeys.map((stable, index) =>
        presenceFact(
          context.roomContextId,
          context.roomPolicy,
          stable,
          index + 1,
        ),
      ),
    );
    const ranked = await sortedByOpenRank(context.roomContextId, facts);
    const local = ranked[0];
    const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(facts, 5),
        [local.presenceOperationId],
      ),
    );
    const desired = result.state.peers
      .filter((peer) => peer.desiredEdge)
      .map((peer) => hex(peer.presenceOperationId))
      .sort();
    expect(desired).toEqual(
      [
        hex(ranked[1].presenceOperationId),
        hex(ranked[4].presenceOperationId),
      ].sort(),
    );
    expect(
      result.topologySelections
        .filter((selection) => selection.plannerSelected)
        .map((selection) => hex(selection.presenceOperationId))
        .sort(),
    ).toEqual(desired);
    expect(
      result.topologySelections.every(
        (selection) => !selection.locallyRequestedExplicit,
      ),
    ).toBe(true);

    const radiusTwo = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(facts.slice(0, 3), 5),
        [facts[0].presenceOperationId],
        {
          plannerAndExplicitState: planner(context.roomContextId, 5, {
            sparseRadius: 2,
          }),
        },
      ),
    );
    expect(radiusTwo.state.peers.every((peer) => peer.desiredEdge)).toBe(true);
  });

  test("keeps full-mesh overcapacity separate from an allowed explicit request", async () => {
    const context = await room(4);
    const stableKeys = await Promise.all([1, 2, 3, 4].map(() => newKeyPair()));
    const facts = await Promise.all(
      stableKeys.map((stable, index) =>
        presenceFact(
          context.roomContextId,
          context.roomPolicy,
          stable,
          index + 1,
        ),
      ),
    );
    const ranked = await sortedByOpenRank(context.roomContextId, facts);
    const requestedPeerId = await localPeerId(
      context.roomContextId,
      ranked[2].presence.core.stableIdentityCommitment,
    );
    const overcapacity = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(facts, 4),
        [ranked[0].presenceOperationId],
        {
          plannerAndExplicitState: planner(context.roomContextId, 4, {
            mode: "full-mesh-small-room",
            fullMeshMaxMembers: 3,
            requestedExplicitPeerIds: [requestedPeerId],
          }),
        },
      ),
    );
    expect(overcapacity.projectionStatus).toBe("ready");
    expect(overcapacity.plannerStatus).toBe("full-mesh-overcapacity");
    expect(
      overcapacity.state.peers.filter((peer) => peer.desiredEdge),
    ).toHaveLength(1);
    expect(
      overcapacity.state.peers.find((peer) => peer.desiredEdge)?.localPeerId,
    ).toBe(requestedPeerId);
    const requestedSelection = overcapacity.topologySelections.find(
      (selection) =>
        hex(selection.presenceOperationId) ===
        hex(ranked[2].presenceOperationId),
    );
    expect(requestedSelection).toMatchObject({
      plannerSelected: false,
      locallyRequestedExplicit: true,
    });
    expect(
      overcapacity.topologySelections
        .filter((selection) => selection.locallyRequestedExplicit)
        .map((selection) => hex(selection.presenceOperationId)),
    ).toEqual([hex(ranked[2].presenceOperationId)]);

    const exactCeiling = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(facts.slice(0, 3), 4),
        [facts[0].presenceOperationId],
        {
          plannerAndExplicitState: planner(context.roomContextId, 4, {
            mode: "full-mesh-small-room",
            fullMeshMaxMembers: 3,
          }),
        },
      ),
    );
    expect(exactCeiling.projectionStatus).toBe("ready");
    expect(exactCeiling.state.peers.every((peer) => peer.desiredEdge)).toBe(
      true,
    );
  });

  test("explicit mode obeys the captured request and on-demand gate", async () => {
    const context = await room(3);
    const localStable = await newKeyPair();
    const remoteStable = await newKeyPair();
    const localFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      1,
    );
    const remoteFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      2,
    );
    const remotePeerId = await localPeerId(
      context.roomContextId,
      remoteFact.presence.core.stableIdentityCommitment,
    );
    const core = await coreState([localFact, remoteFact], 3);

    for (const [allowOnDemandEdges, expected] of [
      [true, true],
      [false, false],
    ] as const) {
      const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
        input(
          context.roomContextId,
          context.roomPolicy,
          core,
          [localFact.presenceOperationId],
          {
            plannerAndExplicitState: planner(context.roomContextId, 3, {
              mode: "explicit",
              allowOnDemandEdges,
              requestedExplicitPeerIds: [remotePeerId],
            }),
          },
        ),
      );
      expect(result.state.peers[0].desiredEdge).toBe(expected);
      expect(result.topologySelections[0]).toMatchObject({
        plannerSelected: false,
        locallyRequestedExplicit: expected,
      });
    }
  });

  test("one explicit peer request resolves to one selected presence and never outside the room cap", async () => {
    const context = await room(3);
    const localStable = await newKeyPair();
    const remoteStable = await newKeyPair();
    const localFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      localStable,
      1,
    );
    const remoteFirst = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      2,
    );
    const remoteDuplicate = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      remoteStable,
      3,
    );
    const requestedPeerId = await localPeerId(
      context.roomContextId,
      remoteFirst.presence.core.stableIdentityCommitment,
    );
    const result = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([localFact, remoteFirst, remoteDuplicate], 3),
        [localFact.presenceOperationId],
        {
          plannerAndExplicitState: planner(context.roomContextId, 3, {
            mode: "explicit",
            requestedExplicitPeerIds: [requestedPeerId],
          }),
        },
      ),
    );
    expect(
      result.topologySelections.filter(
        (selection) => selection.locallyRequestedExplicit,
      ),
    ).toHaveLength(1);

    const distinctStableKeys = await Promise.all(
      [1, 2, 3, 4].map(() => newKeyPair()),
    );
    const distinctFacts = await Promise.all(
      distinctStableKeys.map((stable, index) =>
        presenceFact(
          context.roomContextId,
          context.roomPolicy,
          stable,
          index + 10,
        ),
      ),
    );
    const ranked = await sortedByOpenRank(context.roomContextId, distinctFacts);
    const selectedLocal = ranked[0];
    const outsideCap = ranked[3];
    const outsidePeerId = await localPeerId(
      context.roomContextId,
      outsideCap.presence.core.stableIdentityCommitment,
    );
    const outsideResult = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState(distinctFacts, 3),
        [selectedLocal.presenceOperationId],
        {
          plannerAndExplicitState: planner(context.roomContextId, 3, {
            mode: "explicit",
            requestedExplicitPeerIds: [outsidePeerId],
          }),
        },
      ),
    );
    expect(
      outsideResult.topologySelections.some(
        (selection) => selection.locallyRequestedExplicit,
      ),
    ).toBe(false);
  });

  test("missing frontend state and authority mode never fall back to open", async () => {
    const capabilityRoom = await room(3);
    const stable = await newKeyPair();
    const capabilityFact = await presenceFact(
      capabilityRoom.roomContextId,
      capabilityRoom.roomPolicy,
      stable,
      1,
    );
    const missingPolicy = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        capabilityRoom.roomContextId,
        capabilityRoom.roomPolicy,
        await coreState([capabilityFact], 3),
        [capabilityFact.presenceOperationId],
        { frontendControls: null },
      ),
    );
    expect(missingPolicy.projectionStatus).toBe("policy-unavailable");
    expect(missingPolicy.state.peers).toEqual([]);

    const authorityRoom = await room(3, true);
    const authorityStable = await newKeyPair();
    const permit: PresencePermitV1 = {
      version: 1,
      roomContextId: authorityRoom.roomContextId,
      presenceProofTranscriptHash: bytes32(0x21),
      permitSerial: bytes32(0x22),
      generation: 1n,
      issuedAtLogicalWindow: referenceWindow,
      notBeforeLogicalWindow: referenceWindow,
      notAfterLogicalWindow: referenceWindow + 4n,
      authoritySignature: new Uint8Array(64),
    };
    const authorityFact = await presenceFact(
      authorityRoom.roomContextId,
      authorityRoom.roomPolicy,
      authorityStable,
      1,
      { authorityPermit: permit },
    );
    const unavailable = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        authorityRoom.roomContextId,
        authorityRoom.roomPolicy,
        await coreState([authorityFact], 3),
        [authorityFact.presenceOperationId],
      ),
    );
    expect(unavailable.projectionStatus).toBe("policy-unavailable");
    expect(unavailable.state.localPresenceOperationId).toBeNull();
    expect(unavailable.state.peers).toEqual([]);
  });

  test("rejects inconsistent Core, cross-room planner state, and accessor input", async () => {
    const context = await room(3);
    const stable = await newKeyPair();
    const fact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      stable,
      1,
    );
    const core = await coreState([fact], 3);
    const belowResourceLimit =
      await evaluateLocalAdmissibleProjectionSemanticsV1(
        input(
          context.roomContextId,
          context.roomPolicy,
          core,
          [fact.presenceOperationId],
          { maxRetainedValidOperationsPerRoom: 2 },
        ),
      );
    expect(belowResourceLimit.projectionStatus).toBe("ready");

    const atResourceLimit = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        core,
        [fact.presenceOperationId],
        { maxRetainedValidOperationsPerRoom: 1 },
      ),
    );
    expect(atResourceLimit).toMatchObject({
      projectionStatus: "projection-resource-overcapacity",
      plannerStatus: "unavailable",
      topologySelections: [],
    });

    const secondStable = await newKeyPair();
    const secondFact = await presenceFact(
      context.roomContextId,
      context.roomPolicy,
      secondStable,
      2,
    );
    const overResource = await evaluateLocalAdmissibleProjectionSemanticsV1(
      input(
        context.roomContextId,
        context.roomPolicy,
        await coreState([fact, secondFact], 3),
        [fact.presenceOperationId],
        { maxRetainedValidOperationsPerRoom: 1 },
      ),
    );
    expect(overResource).toMatchObject({
      projectionStatus: "projection-resource-overcapacity",
      plannerStatus: "unavailable",
      topologySelections: [],
    });

    core.operationsDigest[0] ^= 0xff;
    await expect(
      evaluateLocalAdmissibleProjectionSemanticsV1(
        input(context.roomContextId, context.roomPolicy, core, [
          fact.presenceOperationId,
        ]),
      ),
    ).rejects.toThrow("operations digest is inconsistent");

    await expect(
      evaluateLocalAdmissibleProjectionSemanticsV1(
        input(
          context.roomContextId,
          context.roomPolicy,
          await coreState([fact], 3),
          [fact.presenceOperationId],
          {
            plannerAndExplicitState: planner(bytes32(0x99), 3),
          },
        ),
      ),
    ).rejects.toThrow("another room context");

    const getter = Object.defineProperty(
      {
        ...input(
          context.roomContextId,
          context.roomPolicy,
          await coreState([fact], 3),
          [fact.presenceOperationId],
        ),
      },
      "frontendControls",
      {
        enumerable: true,
        get: (): never => {
          throw new Error("getter must not run");
        },
      },
    );
    await expect(
      evaluateLocalAdmissibleProjectionSemanticsV1(getter),
    ).rejects.toThrow("exactly its declared fields");
  });
});
