import { describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import {
  admissionRevokeSemanticSlot,
  admissionRevokeSignedMessage,
  leaveSemanticSlot,
  presenceSemanticSlot,
  storeHintSemanticSlot,
} from "../../src/blindRendezvous/derivations";
import {
  coreReduce,
  decodeCoreRoomStateV1,
  encodeCoreRoomStateV1,
  validateAndIdentifyOperationCandidate,
} from "../../src/blindRendezvous/coreReduce";
import {
  createOperationValidationContext,
  operationPaddingFor,
  operationValidationContextAt,
  requiredRoomRetentionWindows,
  signOperation,
} from "../../src/blindRendezvous/operation";
import {
  encodeAdmissionRevokeV1,
  encodeLeaveV1,
  encodePresenceV1,
  encodeStoreHintOperationV1,
} from "../../src/blindRendezvous/operationPayload";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import {
  descriptorHash,
  storeDescriptorSignedMessage,
  storeId,
} from "../../src/blindRendezvous/storeDescriptor";

import type {
  CoreRoomStateV1,
  OuterValidatedIdentifiedOperationV1,
} from "../../src/blindRendezvous/coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  OperationValidationContext,
  UnsignedRoomOperationV1,
} from "../../src/blindRendezvous/operation";
import type {
  AdmissionRevokeV1,
  LeaveV1,
  PresenceV1,
  StoreHintOperationV1,
} from "../../src/blindRendezvous/operationPayload";
import type { RoomPolicyV4 } from "../../src/blindRendezvous/roomPolicyV4";
import type { StoreDescriptorV1 } from "../../src/blindRendezvous/storeDescriptor";

const BASE_WINDOW = 100n;
const CAPABILITY = new Uint8Array(32).fill(0xc1);

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill & 0xff);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const capabilityPolicy = (
  maxRoomMembers = DEFAULT_BLIND_POLICY_V4_0.maxRoomMembers,
): RoomPolicyV4 => ({
  ...DEFAULT_BLIND_POLICY_V4_0,
  sessionPolicyV1: Uint8Array.from(DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1),
  protocolLimits: { ...DEFAULT_BLIND_POLICY_V4_0.protocolLimits },
  admissionFloor: { mode: "capability" },
  maxRoomMembers,
});

const identify = (
  operation: AuthenticatedRoomOperationV1,
  context: OperationValidationContext,
): Promise<OuterValidatedIdentifiedOperationV1> =>
  validateAndIdentifyOperationCandidate(operation, context);

const reduceAt = (
  operations: readonly OuterValidatedIdentifiedOperationV1[],
  context: OperationValidationContext,
  referenceWindow: bigint,
): Promise<CoreRoomStateV1> =>
  coreReduce(
    operations,
    operationValidationContextAt(context, referenceWindow),
  );

const signOuter = (
  unsigned: Omit<UnsignedRoomOperationV1, "operationPadding">,
  secretKey: Uint8Array,
): Promise<AuthenticatedRoomOperationV1> =>
  signOperation(
    {
      ...unsigned,
      operationPadding: operationPaddingFor(
        unsigned.operationPayloadClass,
        unsigned.fixedPayload.length,
      ),
    },
    secretKey,
  );

type SigningKeyPair = Awaited<ReturnType<typeof newKeyPair>>;

interface PresenceOptions {
  readonly context: OperationValidationContext;
  readonly author: SigningKeyPair;
  readonly nonceFill: number;
  readonly commitmentFill: number;
  readonly logicalWindow?: bigint;
  readonly validThroughLogicalWindow?: bigint;
  readonly receiverKeyValidThroughLogicalWindow?: bigint;
  readonly expiresAfterWindow?: bigint;
  readonly authorSequence?: bigint;
  readonly previousAuthorOperationId?: Uint8Array | null;
}

const buildPresence = async (
  options: PresenceOptions,
): Promise<AuthenticatedRoomOperationV1> => {
  const logicalWindow = options.logicalWindow ?? BASE_WINDOW;
  const expiresAfterWindow = options.expiresAfterWindow ?? logicalWindow + 10n;
  const validThroughLogicalWindow =
    options.validThroughLogicalWindow ?? logicalWindow + 5n;
  const receiverKeyValidThroughLogicalWindow =
    options.receiverKeyValidThroughLogicalWindow ?? expiresAfterWindow;
  const presenceNonce = bytes(options.nonceFill);
  const presence: PresenceV1 = {
    core: {
      version: 1,
      stableIdentityCommitment: bytes(options.commitmentFill),
      rendezvousHybridKemPublicKey: bytes(options.commitmentFill ^ 0x5a, 1216),
      receiverKeyValidThroughLogicalWindow,
      presenceNonce,
      validThroughLogicalWindow,
    },
    // The stable key is deliberately hidden in capability mode; ownership is
    // verified only by a trusted local/address-book or pair projection.
    stableOwnershipSignature: bytes(options.commitmentFill ^ 0xa5, 64),
    authorityPermit: null,
  };
  const fixedPayload = encodePresenceV1(presence);
  return signOuter(
    {
      version: 1,
      roomContextConfirmation: options.context.roomContextConfirmation,
      logicalWindow,
      expiresAfterWindow,
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: options.author.publicKey,
      authorSequence: options.authorSequence ?? 0n,
      previousAuthorOperationId: options.previousAuthorOperationId ?? null,
      kind: "PRESENCE",
      semanticSlot: await presenceSemanticSlot(
        options.author.publicKey,
        logicalWindow,
        presenceNonce,
      ),
      dependencies: [],
      operationPayloadClass: 0,
      fixedPayload,
    },
    options.author.secretKey,
  );
};

interface LeaveOptions {
  readonly context: OperationValidationContext;
  readonly author: SigningKeyPair;
  readonly presenceOperationId: Uint8Array;
  readonly effectiveLogicalWindow?: bigint;
  readonly expiresAfterWindow?: bigint;
  readonly authorSequence?: bigint;
  readonly previousAuthorOperationId?: Uint8Array | null;
}

const buildLeave = async (
  options: LeaveOptions,
): Promise<AuthenticatedRoomOperationV1> => {
  const effectiveLogicalWindow = options.effectiveLogicalWindow ?? BASE_WINDOW;
  const leave: LeaveV1 = {
    version: 1,
    presenceOperationId: options.presenceOperationId,
    effectiveLogicalWindow,
  };
  const fixedPayload = encodeLeaveV1(leave);
  return signOuter(
    {
      version: 1,
      roomContextConfirmation: options.context.roomContextConfirmation,
      logicalWindow: effectiveLogicalWindow,
      expiresAfterWindow:
        options.expiresAfterWindow ?? effectiveLogicalWindow + 10n,
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: options.author.publicKey,
      authorSequence: options.authorSequence ?? 0n,
      previousAuthorOperationId: options.previousAuthorOperationId ?? null,
      kind: "LEAVE",
      semanticSlot: await leaveSemanticSlot(
        leave.presenceOperationId,
        leave.effectiveLogicalWindow,
      ),
      dependencies: [leave.presenceOperationId],
      operationPayloadClass: 0,
      fixedPayload,
    },
    options.author.secretKey,
  );
};

interface RawPresenceOptions {
  readonly context: OperationValidationContext;
  readonly author: SigningKeyPair;
  readonly payloadFill: number;
  readonly slotFill: number;
  readonly logicalWindow?: bigint;
  readonly expiresAfterWindow?: bigint;
  readonly authorSequence?: bigint;
  readonly previousAuthorOperationId?: Uint8Array | null;
}

/**
 * Build an outer-valid PRESENCE whose nested payload is intentionally invalid.
 * These are load-bearing quota/fork candidates, not logical presence facts.
 */
const buildOuterOnlyPresence = (
  options: RawPresenceOptions,
): Promise<AuthenticatedRoomOperationV1> => {
  const logicalWindow = options.logicalWindow ?? BASE_WINDOW;
  const fixedPayload = Uint8Array.of(options.payloadFill & 0xff);
  return signOuter(
    {
      version: 1,
      roomContextConfirmation: options.context.roomContextConfirmation,
      logicalWindow,
      expiresAfterWindow: options.expiresAfterWindow ?? logicalWindow + 10n,
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: options.author.publicKey,
      authorSequence: options.authorSequence ?? 0n,
      previousAuthorOperationId: options.previousAuthorOperationId ?? null,
      kind: "PRESENCE",
      semanticSlot: bytes(options.slotFill),
      dependencies: [],
      operationPayloadClass: 0,
      fixedPayload,
    },
    options.author.secretKey,
  );
};

describe("CoreReduce presence and leave semantics", () => {
  test("matches the independently generated empty CoreRoomStateV1 vector", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const state = await coreReduce([], context);

    // Generated independently with Python stdlib SHA-256 plus the normative
    // fixed-width/u16-empty encodings, not by this codec implementation.
    expect(hex(await encodeCoreRoomStateV1(state))).toBe(
      "010000000000000064000000000000000000000000000000" +
        "96d28799bbe76f1a15dcab8cbb117ca954d9b16fc8f9115da9f43b8e5b2b1bfb",
    );
  });

  test("activates at the logical window, expires roster facts exactly, and reports capacity without choosing a winner", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(2),
      BASE_WINDOW,
    );
    const authors = await Promise.all([
      newKeyPair(),
      newKeyPair(),
      newKeyPair(),
    ]);
    const operations = await Promise.all(
      authors.map(async (author, index) =>
        identify(
          await buildPresence({
            context,
            author,
            nonceFill: 0x10 + index,
            commitmentFill: 0x20 + index,
            validThroughLogicalWindow: BASE_WINDOW + 5n,
            expiresAfterWindow: BASE_WINDOW + 10n,
          }),
          context,
        ),
      ),
    );

    const before = await reduceAt(operations, context, BASE_WINDOW - 1n);
    expect(before.activeOperationIds).toEqual([]);
    expect(before.observedPresences).toEqual([]);
    expect(before.roomCapacityState).toBe("within-policy");

    const active = await reduceAt(operations, context, BASE_WINDOW);
    expect(active.activeOperationIds).toHaveLength(3);
    expect(active.activeOperationIds.map(hex)).toEqual(
      active.activeOperationIds.map(hex).sort(),
    );
    expect(active.observedPresences).toHaveLength(3);
    expect(active.roomCapacityState).toBe("overcapacity");
    const activeBytes = await encodeCoreRoomStateV1(active);
    expect(
      await encodeCoreRoomStateV1(await decodeCoreRoomStateV1(activeBytes)),
    ).toEqual(activeBytes);
    expect(
      active.observedPresences.map((fact) => hex(fact.presenceOperationId)),
    ).toEqual(
      [...active.observedPresences]
        .map((fact) => hex(fact.presenceOperationId))
        .sort(),
    );

    const exactEnd = await reduceAt(operations, context, BASE_WINDOW + 5n);
    expect(exactEnd.observedPresences).toHaveLength(3);
    expect(exactEnd.roomCapacityState).toBe("overcapacity");

    const afterRosterExpiry = await reduceAt(
      operations,
      context,
      BASE_WINDOW + 6n,
    );
    // Outer operation retention and roster validity are intentionally distinct.
    expect(afterRosterExpiry.activeOperationIds).toHaveLength(3);
    expect(afterRosterExpiry.observedPresences).toEqual([]);
    expect(afterRosterExpiry.roomCapacityState).toBe("within-policy");
  });

  test("applies one valid LEAVE while wrong-author and missing dependencies cannot poison its slot", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const presenceAuthor = await newKeyPair();
    const wrongAuthor = await newKeyPair();
    const missingAuthor = await newKeyPair();

    const presenceOperation = await buildPresence({
      context,
      author: presenceAuthor,
      nonceFill: 0x31,
      commitmentFill: 0x41,
    });
    const presence = await identify(presenceOperation, context);

    const validLeaveOperation = await buildLeave({
      context,
      author: presenceAuthor,
      presenceOperationId: presence.operationId,
      authorSequence: 1n,
      previousAuthorOperationId: presence.operationId,
    });
    const validLeave = await identify(validLeaveOperation, context);

    // This operation has the exact legitimate LeaveSemanticSlot, but it cannot
    // leave a presence authenticated by a different author key.
    const wrongAuthorLeave = await identify(
      await buildLeave({
        context,
        author: wrongAuthor,
        presenceOperationId: presence.operationId,
      }),
      context,
    );

    const missingLeave = await identify(
      await buildLeave({
        context,
        author: missingAuthor,
        presenceOperationId: bytes(0xee),
      }),
      context,
    );

    const state = await coreReduce(
      [wrongAuthorLeave, missingLeave, validLeave, presence],
      context,
    );
    expect(
      state.faults.filter((fault) => fault.kind === "presence-or-leave-fork"),
    ).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.effectiveLeaveOperationIds.map(hex)).toEqual([
      hex(validLeave.operationId),
    ]);
    expect(state.activeOperationIds.map(hex)).toContain(
      hex(presence.operationId),
    );
    expect(state.activeOperationIds.map(hex)).toContain(
      hex(validLeave.operationId),
    );
    expect(state.activeOperationIds.map(hex)).not.toContain(
      hex(wrongAuthorLeave.operationId),
    );
    expect(state.activeOperationIds.map(hex)).not.toContain(
      hex(missingLeave.operationId),
    );
  });

  test("a LEAVE shorter than the remaining presence lifetime never applies or resurrects", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const presence = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x75,
        commitmentFill: 0x76,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      context,
    );
    const shortLeave = await identify(
      await buildLeave({
        context,
        author,
        presenceOperationId: presence.operationId,
        expiresAfterWindow: BASE_WINDOW + 1n,
        authorSequence: 1n,
        previousAuthorOperationId: presence.operationId,
      }),
      context,
    );

    for (const referenceWindow of [BASE_WINDOW, BASE_WINDOW + 7n]) {
      const state = await reduceAt(
        [shortLeave, presence],
        context,
        referenceWindow,
      );
      expect(state.faults).toEqual([]);
      expect(
        state.observedPresences.map((fact) => hex(fact.presenceOperationId)),
      ).toEqual([hex(presence.operationId)]);
      expect(state.effectiveLeaveOperationIds).toEqual([]);
      expect(state.activeOperationIds.map(hex)).not.toContain(
        hex(shortLeave.operationId),
      );
    }
  });

  test("a wrong-author LEAVE cannot promote a historical presence fork and suppress its successor", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 7n,
    );
    const presenceAuthor = await newKeyPair();
    const wrongAuthor = await newKeyPair();

    const first = await identify(
      await buildPresence({
        context: baseContext,
        author: presenceAuthor,
        nonceFill: 0x81,
        commitmentFill: 0x82,
        validThroughLogicalWindow: BASE_WINDOW + 1n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 1n,
        expiresAfterWindow: BASE_WINDOW + 1n,
      }),
      lateContext,
    );
    const sibling = await identify(
      await buildPresence({
        context: baseContext,
        author: presenceAuthor,
        nonceFill: 0x81,
        commitmentFill: 0x83,
        validThroughLogicalWindow: BASE_WINDOW + 1n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 1n,
        expiresAfterWindow: BASE_WINDOW + 1n,
        authorSequence: 1n,
        previousAuthorOperationId: first.operationId,
      }),
      lateContext,
    );
    const successor = await identify(
      await buildPresence({
        context: baseContext,
        author: presenceAuthor,
        nonceFill: 0x84,
        commitmentFill: 0x85,
        validThroughLogicalWindow: BASE_WINDOW + 9n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
        authorSequence: 2n,
        previousAuthorOperationId: sibling.operationId,
      }),
      lateContext,
    );
    const wrongAuthorLeave = await identify(
      await buildLeave({
        context: baseContext,
        author: wrongAuthor,
        presenceOperationId: first.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 7n,
      }),
      lateContext,
    );

    const state = await coreReduce(
      [wrongAuthorLeave, sibling, successor, first],
      lateContext,
    );
    expect(state.faults).toEqual([]);
    expect(
      state.observedPresences.map((fact) => hex(fact.presenceOperationId)),
    ).toEqual([hex(successor.operationId)]);
    expect(state.activeOperationIds.map(hex)).toContain(
      hex(successor.operationId),
    );
    expect(state.activeOperationIds.map(hex)).not.toContain(
      hex(wrongAuthorLeave.operationId),
    );
  });

  test("a LEAVE outside the presence interval cannot manufacture a historical author fault", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 7n,
    );
    const author = await newKeyPair();
    const first = await identify(
      await buildPresence({
        context: baseContext,
        author,
        nonceFill: 0x91,
        commitmentFill: 0x92,
        validThroughLogicalWindow: BASE_WINDOW + 1n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 1n,
        expiresAfterWindow: BASE_WINDOW + 1n,
      }),
      lateContext,
    );
    const forkedSibling = await identify(
      await buildPresence({
        context: baseContext,
        author,
        nonceFill: 0x91,
        commitmentFill: 0x93,
        validThroughLogicalWindow: BASE_WINDOW + 1n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 1n,
        expiresAfterWindow: BASE_WINDOW + 1n,
      }),
      lateContext,
    );
    const invalidAtEffectiveLeave = await identify(
      await buildLeave({
        context: baseContext,
        author,
        presenceOperationId: first.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 7n,
      }),
      lateContext,
    );

    const state = await coreReduce(
      [forkedSibling, invalidAtEffectiveLeave, first],
      lateContext,
    );
    expect(state.faults).toEqual([]);
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.effectiveLeaveOperationIds).toEqual([]);
  });

  test("a referenced presence with a forged slot cannot promote another author's historical fork", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 16n,
    );
    const victimAuthor = await newKeyPair();
    const attackerAuthor = await newKeyPair();

    const victimFirst = await identify(
      await buildPresence({
        context: baseContext,
        author: victimAuthor,
        nonceFill: 0xa1,
        commitmentFill: 0xa2,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      lateContext,
    );
    const victimSibling = await identify(
      await buildPresence({
        context: baseContext,
        author: victimAuthor,
        nonceFill: 0xa1,
        commitmentFill: 0xa3,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      lateContext,
    );

    const template = await buildPresence({
      context: baseContext,
      author: attackerAuthor,
      nonceFill: 0xa4,
      commitmentFill: 0xa5,
      validThroughLogicalWindow: BASE_WINDOW + 10n,
      receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
      expiresAfterWindow: BASE_WINDOW + 10n,
    });
    const { authorSignature: _signature, ...templateUnsigned } = template;
    const spoofedReference = await identify(
      await signOperation(
        {
          ...templateUnsigned,
          semanticSlot: Uint8Array.from(victimFirst.operation.semanticSlot),
        },
        attackerAuthor.secretKey,
      ),
      lateContext,
    );
    const leave = await identify(
      await buildLeave({
        context: baseContext,
        author: attackerAuthor,
        presenceOperationId: spoofedReference.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 20n,
      }),
      lateContext,
    );

    const state = await coreReduce(
      [victimSibling, leave, spoofedReference, victimFirst],
      lateContext,
    );
    expect(state.faults).toEqual([]);
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
  });

  test("copied historical slots cannot manufacture an unrelated author fault", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 16n,
    );
    const victimAuthor = await newKeyPair();
    const attackerAuthor = await newKeyPair();

    const victim = await identify(
      await buildPresence({
        context: baseContext,
        author: victimAuthor,
        nonceFill: 0xa6,
        commitmentFill: 0xa7,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      lateContext,
    );
    const leave = await identify(
      await buildLeave({
        context: baseContext,
        author: victimAuthor,
        presenceOperationId: victim.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 20n,
      }),
      lateContext,
    );

    const copyVictimSlot = async (
      nonceFill: number,
      commitmentFill: number,
    ): Promise<OuterValidatedIdentifiedOperationV1> => {
      const template = await buildPresence({
        context: baseContext,
        author: attackerAuthor,
        nonceFill,
        commitmentFill,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      });
      const { authorSignature: _signature, ...unsigned } = template;
      return identify(
        await signOperation(
          {
            ...unsigned,
            semanticSlot: Uint8Array.from(victim.operation.semanticSlot),
          },
          attackerAuthor.secretKey,
        ),
        lateContext,
      );
    };

    const attackerForkA = await copyVictimSlot(0xa8, 0xa9);
    const attackerForkB = await copyVictimSlot(0xaa, 0xab);
    const state = await coreReduce(
      [attackerForkB, victim, leave, attackerForkA],
      lateContext,
    );

    expect(state.faults).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.effectiveLeaveOperationIds.map(hex)).toEqual([
      hex(leave.operationId),
    ]);
  });

  test("a chain-unproven historical presence suspends only its dependent LEAVE", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 16n,
    );
    const author = await newKeyPair();
    const unprovenPresence = await identify(
      await buildPresence({
        context: baseContext,
        author,
        nonceFill: 0xb1,
        commitmentFill: 0xb2,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
        authorSequence: 1n,
        previousAuthorOperationId: bytes(0xb3),
      }),
      lateContext,
    );
    const leave = await identify(
      await buildLeave({
        context: baseContext,
        author,
        presenceOperationId: unprovenPresence.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 20n,
      }),
      lateContext,
    );

    const state = await coreReduce([leave, unprovenPresence], lateContext);
    expect(state.faults).toEqual([]);
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.effectiveLeaveOperationIds).toEqual([]);
  });

  test("revalidates an outer-expired cross-window presence as inert LEAVE dependency evidence", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 16n,
    );
    const author = await newKeyPair();
    const signedPresence = await buildPresence({
      context: baseContext,
      author,
      nonceFill: 0x41,
      commitmentFill: 0x42,
      validThroughLogicalWindow: BASE_WINDOW + 10n,
      receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
      expiresAfterWindow: BASE_WINDOW + 10n,
    });
    // This models restart/first late delivery: the exact expired bytes receive
    // a fresh process-local candidate brand at the later reference window.
    const presence = await identify(signedPresence, lateContext);
    const leave = await identify(
      await buildLeave({
        context: baseContext,
        author,
        presenceOperationId: presence.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 20n,
      }),
      lateContext,
    );

    const state = await coreReduce([leave, presence], lateContext);
    expect(state.faults).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.activeOperationIds.map(hex)).toEqual([hex(leave.operationId)]);
    expect(state.effectiveLeaveOperationIds.map(hex)).toEqual([
      hex(leave.operationId),
    ]);
  });

  test("a historical LEAVE dependency promotes every branch in its presence semantic slot", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const lateContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 16n,
    );
    const author = await newKeyPair();
    const first = await identify(
      await buildPresence({
        context: baseContext,
        author,
        nonceFill: 0x51,
        commitmentFill: 0x52,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      lateContext,
    );
    const second = await identify(
      await buildPresence({
        context: baseContext,
        author,
        nonceFill: 0x51,
        commitmentFill: 0x53,
        validThroughLogicalWindow: BASE_WINDOW + 10n,
        receiverKeyValidThroughLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 10n,
        authorSequence: 1n,
        previousAuthorOperationId: first.operationId,
      }),
      lateContext,
    );
    const leave = await identify(
      await buildLeave({
        context: baseContext,
        author,
        presenceOperationId: first.operationId,
        effectiveLogicalWindow: BASE_WINDOW + 10n,
        expiresAfterWindow: BASE_WINDOW + 20n,
      }),
      lateContext,
    );

    const state = await coreReduce([leave, second, first], lateContext);
    const semanticFaults = state.faults.filter(
      (fault) => fault.kind === "presence-or-leave-fork",
    );
    expect(semanticFaults).toHaveLength(1);
    expect(semanticFaults[0].proofOperationIds.map(hex)).toEqual(
      [hex(first.operationId), hex(second.operationId)].sort(),
    );
    expect(state.activeOperationIds).toEqual([]);
    expect(state.effectiveLeaveOperationIds).toEqual([]);
  });

  test("excludes every branch of a presence semantic-slot fork", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const first = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x51,
        commitmentFill: 0x61,
      }),
      context,
    );
    const second = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x51,
        commitmentFill: 0x62,
        authorSequence: 1n,
        previousAuthorOperationId: first.operationId,
      }),
      context,
    );

    const state = await coreReduce([second, first], context);
    const semanticFaults = state.faults.filter(
      (fault) => fault.kind === "presence-or-leave-fork",
    );
    expect(semanticFaults).toHaveLength(1);
    expect(semanticFaults[0].proofOperationIds.map(hex)).toEqual(
      [hex(first.operationId), hex(second.operationId)].sort(),
    );
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
  });

  test("a leave semantic-slot fork applies no representative and leaves the presence active", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const presence = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x71,
        commitmentFill: 0x72,
      }),
      context,
    );
    const firstLeave = await identify(
      await buildLeave({
        context,
        author,
        presenceOperationId: presence.operationId,
        authorSequence: 1n,
        previousAuthorOperationId: presence.operationId,
      }),
      context,
    );
    const secondLeave = await identify(
      await buildLeave({
        context,
        author,
        presenceOperationId: presence.operationId,
        authorSequence: 2n,
        previousAuthorOperationId: firstLeave.operationId,
      }),
      context,
    );

    const state = await coreReduce(
      [secondLeave, presence, firstLeave],
      context,
    );
    expect(
      state.faults.filter((fault) => fault.kind === "presence-or-leave-fork"),
    ).toHaveLength(1);
    expect(state.effectiveLeaveOperationIds).toEqual([]);
    expect(
      state.observedPresences.map((fact) => hex(fact.presenceOperationId)),
    ).toEqual([hex(presence.operationId)]);
    expect(state.activeOperationIds.map(hex)).toEqual([
      hex(presence.operationId),
    ]);
  });
});

describe("CoreReduce store and authority facts", () => {
  test("retains descriptor-only source facts and faults only the maximum live store generation", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const store = await newKeyPair();
    const operationAuthors = await Promise.all([
      newKeyPair(),
      newKeyPair(),
      newKeyPair(),
    ]);

    const makeDescriptor = async (
      descriptorGeneration: bigint,
      compatibilityFill: number,
    ): Promise<StoreDescriptorV1> => {
      const draft: StoreDescriptorV1 = {
        version: 1,
        storeIdentityEd25519Key: store.publicKey,
        allocationIssuerPublicKeyDer: Uint8Array.of(0x30),
        descriptorGeneration,
        compatibilityHash: bytes(compatibilityFill),
        supportedDeliveryProfileHashes: [bytes(0x81)],
        checkpointChainStarts: [
          {
            deliveryProfileHash: bytes(0x81),
            chainStartIngressWindow: 0n,
          },
        ],
        notBeforeUnixMs: 0n,
        notAfterUnixMs: 1_000_000_000n,
        descriptorSignature: bytes(0, 64),
      };
      return {
        ...draft,
        descriptorSignature: await sign(
          await storeDescriptorSignedMessage(draft),
          store.secretKey,
        ),
      };
    };

    const makeHint = async (
      descriptor: StoreDescriptorV1,
      author: SigningKeyPair,
    ): Promise<OuterValidatedIdentifiedOperationV1> => {
      const hint: StoreHintOperationV1 = {
        version: 1,
        descriptor,
        routes: [],
        hintExpiresAfterLogicalWindow: BASE_WINDOW + 5n,
      };
      const fixedPayload = encodeStoreHintOperationV1(hint);
      return identify(
        await signOuter(
          {
            version: 1,
            roomContextConfirmation: context.roomContextConfirmation,
            logicalWindow: BASE_WINDOW,
            expiresAfterWindow: BASE_WINDOW + 10n,
            lifetime: "WINDOW_TRANSIENT",
            authorEpochEd25519Key: author.publicKey,
            authorSequence: 0n,
            previousAuthorOperationId: null,
            kind: "STORE_HINT",
            semanticSlot: await storeHintSemanticSlot(
              await storeId(store.publicKey),
              descriptor.descriptorGeneration,
            ),
            dependencies: [],
            operationPayloadClass: 0,
            fixedPayload,
          },
          author.secretKey,
        ),
        context,
      );
    };

    const generation1 = await makeDescriptor(1n, 0x91);
    const generation2A = await makeDescriptor(2n, 0x92);
    const generation2B = await makeDescriptor(2n, 0x93);
    const operations = await Promise.all([
      makeHint(generation1, operationAuthors[0]),
      makeHint(generation2A, operationAuthors[1]),
      makeHint(generation2B, operationAuthors[2]),
    ]);

    const state = await coreReduce(
      [operations[2], operations[0], operations[1]],
      context,
    );
    expect(state.storeCatalogFacts).toHaveLength(3);
    expect(
      state.storeCatalogFacts.map((fact) => fact.descriptorGeneration),
    ).toEqual([1n, 2n, 2n]);
    expect(
      state.storeCatalogFacts.every((fact) => fact.routes.length === 0),
    ).toBe(true);

    const storeFaults = state.faults.filter(
      (fault) => fault.kind === "store-generation-fork",
    );
    expect(storeFaults).toHaveLength(1);
    const storeFault = storeFaults[0];
    if (storeFault.kind !== "store-generation-fork")
      throw new Error("expected a store-generation-fork");
    expect(storeFault.descriptorGeneration).toBe(2n);
    expect(storeFault.descriptorHashes.map(hex)).toEqual(
      [
        hex(await descriptorHash(generation2A)),
        hex(await descriptorHash(generation2B)),
      ].sort(),
    );
  });

  test("retains distinct revocation facts and sorts their complete identifying tuples", async () => {
    const authority = await newKeyPair();
    const authorityPolicy: RoomPolicyV4 = {
      ...capabilityPolicy(),
      admissionFloor: {
        mode: "authority-grant",
        authorityEd25519PublicKey: authority.publicKey,
        maxAuthorityCredentialLifetimeWindows: 60,
      },
    };
    const context = await createOperationValidationContext(
      CAPABILITY,
      authorityPolicy,
      BASE_WINDOW,
    );
    const expiresAfterLogicalWindow =
      BASE_WINDOW +
      BigInt(authorityPolicy.protocolLimits.maxFutureLogicalWindows) +
      60n;

    const makeRevoke = async (
      stableIdentityCommitment: Uint8Array,
      minimumAcceptedGeneration: bigint,
      authorSequence: bigint,
      previousAuthorOperationId: Uint8Array | null,
    ): Promise<OuterValidatedIdentifiedOperationV1> => {
      const unsignedRevoke = {
        version: 1 as const,
        roomContextId: context.roomContextId,
        stableIdentityCommitment,
        minimumAcceptedGeneration,
        effectiveLogicalWindow: BASE_WINDOW,
        expiresAfterLogicalWindow,
      };
      const revoke: AdmissionRevokeV1 = {
        ...unsignedRevoke,
        authoritySignature: await sign(
          await admissionRevokeSignedMessage(unsignedRevoke),
          authority.secretKey,
        ),
      };
      const fixedPayload = encodeAdmissionRevokeV1(revoke);
      return identify(
        await signOuter(
          {
            version: 1,
            roomContextConfirmation: context.roomContextConfirmation,
            logicalWindow: BASE_WINDOW,
            expiresAfterWindow: expiresAfterLogicalWindow,
            lifetime: "GRANT_HORIZON",
            authorEpochEd25519Key: authority.publicKey,
            authorSequence,
            previousAuthorOperationId,
            kind: "ADMISSION_REVOKE",
            semanticSlot: await admissionRevokeSemanticSlot(
              stableIdentityCommitment,
              minimumAcceptedGeneration,
              BASE_WINDOW,
              expiresAfterLogicalWindow,
            ),
            dependencies: [],
            operationPayloadClass: 0,
            fixedPayload,
          },
          authority.secretKey,
        ),
        context,
      );
    };

    const first = await makeRevoke(bytes(0x20), 9n, 0n, null);
    const second = await makeRevoke(bytes(0x10), 11n, 1n, first.operationId);
    const state = await coreReduce([second, first], context);

    expect(state.faults).toEqual([]);
    expect(state.revocationFloors).toHaveLength(2);
    expect(
      state.revocationFloors.map((fact) => hex(fact.stableIdentityCommitment)),
    ).toEqual([hex(bytes(0x10)), hex(bytes(0x20))]);
    expect(
      state.revocationFloors.map((fact) => fact.minimumAcceptedGeneration),
    ).toEqual([11n, 9n]);
    expect(
      state.revocationFloors.every(
        (fact) => fact.validThroughLogicalWindow === expiresAfterLogicalWindow,
      ),
    ).toBe(true);
  });
});

describe("CoreReduce adversarial outer-candidate ordering", () => {
  test("accepts inert evidence at the exact retention horizon and rejects plus one", async () => {
    const policy = capabilityPolicy();
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      policy,
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const operation = await buildPresence({
      context: baseContext,
      author,
      nonceFill: 0xe1,
      commitmentFill: 0xe2,
      validThroughLogicalWindow: BASE_WINDOW,
      receiverKeyValidThroughLogicalWindow: BASE_WINDOW,
      expiresAfterWindow: BASE_WINDOW,
    });
    const evidenceHorizon =
      BASE_WINDOW +
      requiredRoomRetentionWindows(policy) +
      BigInt(policy.protocolLimits.maxClockSkewWindows);
    const atHorizon = operationValidationContextAt(
      baseContext,
      evidenceHorizon,
    );
    const afterHorizon = operationValidationContextAt(
      baseContext,
      evidenceHorizon + 1n,
    );

    const retained = await identify(operation, atHorizon);
    const state = await coreReduce([retained], atHorizon);
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
    expect(state.faults).toEqual([]);
    await expect(identify(operation, afterHorizon)).rejects.toThrow(
      "beyond its retained-evidence horizon",
    );
  });

  test("snapshots the operation set before its first asynchronous boundary", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const first = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x01,
        commitmentFill: 0x02,
      }),
      context,
    );
    const lateFork = await identify(
      await buildPresence({
        context,
        author,
        nonceFill: 0x03,
        commitmentFill: 0x04,
      }),
      context,
    );
    const mutableInputs = [first];
    const pending = coreReduce(mutableInputs, context);
    mutableInputs.push(lateFork);

    const state = await pending;
    expect(state.faults).toEqual([]);
    expect(state.activeOperationIds.map(hex)).toEqual([hex(first.operationId)]);
  });

  test("rejects an overflowing evidence horizon at candidate ingress without poisoning an honest candidate", async () => {
    const u64Max = 0xffffffffffffffffn;
    const policy = capabilityPolicy();
    policy.protocolLimits = {
      ...policy.protocolLimits,
      maxClockSkewWindows: 0,
      operationRetentionWindows: 1,
      pairControlRetentionWindows: 1,
      receiverKeyOverlapWindows: 0,
      maxFutureLogicalWindows: 0,
    };
    const context = await createOperationValidationContext(
      CAPABILITY,
      policy,
      u64Max - 1n,
    );
    const honestAuthor = await newKeyPair();
    const attacker = await newKeyPair();
    const honest = await identify(
      await buildPresence({
        context,
        author: honestAuthor,
        nonceFill: 0x11,
        commitmentFill: 0x12,
        logicalWindow: u64Max - 2n,
        validThroughLogicalWindow: u64Max - 1n,
        receiverKeyValidThroughLogicalWindow: u64Max - 1n,
        expiresAfterWindow: u64Max - 1n,
      }),
      context,
    );
    const overflowing = await buildPresence({
      context,
      author: attacker,
      nonceFill: 0x13,
      commitmentFill: 0x14,
      logicalWindow: u64Max - 1n,
      validThroughLogicalWindow: u64Max,
      receiverKeyValidThroughLogicalWindow: u64Max,
      expiresAfterWindow: u64Max,
    });

    await expect(identify(overflowing, context)).rejects.toThrow(
      "checked addition overflowed",
    );
    const state = await coreReduce([honest], context);
    expect(state.faults).toEqual([]);
    expect(state.activeOperationIds.map(hex)).toEqual([
      hex(honest.operationId),
    ]);
  });

  test("quota+1 outer-valid but nested-invalid candidates fault before payload work", async () => {
    const policy = capabilityPolicy();
    const context = await createOperationValidationContext(
      CAPABILITY,
      policy,
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const quota = policy.protocolLimits.maxOperationsPerAuthorWindow;
    const candidates: OuterValidatedIdentifiedOperationV1[] = [];
    let previousAuthorOperationId: Uint8Array | null = null;

    for (let sequence = 0; sequence <= quota; sequence++) {
      const candidate = await identify(
        await buildOuterOnlyPresence({
          context,
          author,
          payloadFill: sequence + 1,
          slotFill: sequence + 0x20,
          authorSequence: BigInt(sequence),
          previousAuthorOperationId,
        }),
        context,
      );
      previousAuthorOperationId = Uint8Array.from(candidate.operationId);
      candidates.push(candidate);
    }

    const state = await coreReduce([...candidates].reverse(), context);
    const authorFaults = state.faults.filter(
      (fault) => fault.kind === "author-fork-or-overquota",
    );
    expect(authorFaults).toHaveLength(1);
    expect(authorFaults[0].proofOperationIds).toHaveLength(quota + 1);
    expect(state.activeOperationIds).toEqual([]);
    expect(state.observedPresences).toEqual([]);
  });

  test("a future author-slot conflict remains custody only and cannot fault current core state", async () => {
    const context = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const author = await newKeyPair();
    const logicalWindow = BASE_WINDOW + 3n;
    const futureA = await identify(
      await buildOuterOnlyPresence({
        context,
        author,
        payloadFill: 0xa1,
        slotFill: 0xa2,
        logicalWindow,
        expiresAfterWindow: logicalWindow + 5n,
      }),
      context,
    );
    const futureB = await identify(
      await buildOuterOnlyPresence({
        context,
        author,
        payloadFill: 0xb1,
        slotFill: 0xb2,
        logicalWindow,
        expiresAfterWindow: logicalWindow + 5n,
      }),
      context,
    );

    const current = await coreReduce([futureB, futureA], context);
    expect(current.faults).toEqual([]);
    expect(current.activeOperationIds).toEqual([]);

    const activated = await reduceAt(
      [futureA, futureB],
      context,
      logicalWindow,
    );
    expect(
      activated.faults.filter(
        (fault) => fault.kind === "author-fork-or-overquota",
      ),
    ).toHaveLength(1);
    expect(activated.activeOperationIds).toEqual([]);
  });

  test("an expired branch in the same author sequence still faults its live branch", async () => {
    const baseContext = await createOperationValidationContext(
      CAPABILITY,
      capabilityPolicy(),
      BASE_WINDOW,
    );
    const reductionContext = operationValidationContextAt(
      baseContext,
      BASE_WINDOW + 7n,
    );
    const author = await newKeyPair();
    const expiredBranch = await identify(
      await buildOuterOnlyPresence({
        context: reductionContext,
        author,
        payloadFill: 0xc1,
        slotFill: 0xc2,
        expiresAfterWindow: BASE_WINDOW + 1n,
      }),
      reductionContext,
    );
    const liveBranch = await identify(
      await buildOuterOnlyPresence({
        context: reductionContext,
        author,
        payloadFill: 0xd1,
        slotFill: 0xd2,
        expiresAfterWindow: BASE_WINDOW + 10n,
      }),
      reductionContext,
    );

    const state = await coreReduce(
      [liveBranch, expiredBranch],
      reductionContext,
    );
    const authorFaults = state.faults.filter(
      (fault) => fault.kind === "author-fork-or-overquota",
    );
    expect(authorFaults).toHaveLength(1);
    expect(authorFaults[0].proofOperationIds.map(hex)).toEqual(
      [hex(expiredBranch.operationId), hex(liveBranch.operationId)].sort(),
    );
    expect(state.activeOperationIds).toEqual([]);
  });
});
