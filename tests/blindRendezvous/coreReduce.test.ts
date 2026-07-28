import { describe, expect, test } from "bun:test";

import { newKeyPair } from "../../src/cryptography/ed25519";
import {
  pairSemanticSlot,
  presenceSemanticSlot,
} from "../../src/blindRendezvous/derivations";
import {
  coreReduce,
  mergeOperationCandidateSets as mergeOperationSets,
  validateAndIdentifyOperationCandidate as validateAndIdentifyOperation,
} from "../../src/blindRendezvous/coreReduce";
import {
  decodeOperation,
  encodeOperation,
  createOperationValidationContext,
  operationPaddingFor,
  operationPayloadClassFor,
  operationValidationContextAt,
  signOperation,
  validateOperation,
  validateOperationStructure,
} from "../../src/blindRendezvous/operation";
import { encodePresenceV1 } from "../../src/blindRendezvous/operationPayload";
import {
  encodePairStepEnvelopeV1,
  pairCiphertextAndTagTargetBytesV1,
} from "../../src/blindRendezvous/pairStepEnvelope";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";

import type { OuterValidatedIdentifiedOperationV1 as ValidatedIdentifiedOperationV1 } from "../../src/blindRendezvous/coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  OperationKindV1,
  OperationValidationContext,
  UnsignedRoomOperationV1,
} from "../../src/blindRendezvous/operation";
import type { RoomPolicyV4 } from "../../src/blindRendezvous/roomPolicyV4";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const capability = new Uint8Array(32).fill(0x33);
const roomPolicy = DEFAULT_BLIND_POLICY_V4_0;
const REFERENCE_WINDOW = 1_000n;

const context = await createOperationValidationContext(
  capability,
  roomPolicy,
  REFERENCE_WINDOW,
);

const author = await newKeyPair();
const otherAuthor = await newKeyPair();

interface BuildOptions {
  readonly kind?: OperationKindV1;
  readonly authorSequence?: bigint;
  readonly previousAuthorOperationId?: Uint8Array | null;
  readonly logicalWindow?: bigint;
  readonly expiresAfterWindow?: bigint;
  readonly payload?: Uint8Array;
  readonly semanticSlot?: Uint8Array;
  readonly dependencies?: readonly Uint8Array[];
  readonly signer?: { publicKey: Uint8Array; secretKey: Uint8Array };
  readonly roomContextConfirmation?: Uint8Array;
}

const presencePayload = (
  seed: Uint8Array,
  expiresAfterWindow: bigint,
): { readonly payload: Uint8Array; readonly nonce: Uint8Array } => {
  const material = seed.length === 0 ? Uint8Array.of(0) : seed;
  const expanded = (length: number, tweak: number): Uint8Array =>
    Uint8Array.from(
      { length },
      (_, index) =>
        material[index % material.length] ^ ((index + tweak) & 0xff),
    );
  const nonce = expanded(32, 0x31);
  return {
    nonce,
    payload: encodePresenceV1({
      core: {
        version: 1,
        stableIdentityCommitment: expanded(32, 0x51),
        rendezvousHybridKemPublicKey: expanded(1216, 0x71),
        receiverKeyValidThroughLogicalWindow: expiresAfterWindow,
        presenceNonce: nonce,
        validThroughLogicalWindow: expiresAfterWindow,
      },
      // Capability-mode core validation cannot identify the hidden stable key;
      // address-book/pair projection verifies this fixed-width signature.
      stableOwnershipSignature: expanded(64, 0x91),
      authorityPermit: null,
    }),
  };
};

const unsignedOperation = async (
  options: BuildOptions = {},
  operationContext: OperationValidationContext = context,
): Promise<UnsignedRoomOperationV1> => {
  const kind = options.kind ?? "PRESENCE";
  const logicalWindow = options.logicalWindow ?? REFERENCE_WINDOW;
  const expiresAfterWindow = options.expiresAfterWindow ?? logicalWindow + 10n;
  const signer = options.signer ?? author;
  const rawPayload = options.payload ?? Uint8Array.of(1, 2, 3);
  const presence =
    kind === "PRESENCE"
      ? presencePayload(rawPayload, expiresAfterWindow)
      : null;
  const payload = presence?.payload ?? rawPayload;
  return {
    version: 1,
    roomContextConfirmation:
      options.roomContextConfirmation ??
      operationContext.roomContextConfirmation,
    logicalWindow,
    expiresAfterWindow,
    lifetime:
      kind === "PAIR_STEP"
        ? "PAIR_CAUSAL"
        : kind === "ADMISSION_REVOKE"
          ? "GRANT_HORIZON"
          : "WINDOW_TRANSIENT",
    authorEpochEd25519Key: signer.publicKey,
    authorSequence: options.authorSequence ?? 0n,
    previousAuthorOperationId: options.previousAuthorOperationId ?? null,
    kind,
    semanticSlot:
      options.semanticSlot ??
      (presence === null
        ? new Uint8Array(32).fill(0x77)
        : await presenceSemanticSlot(
            signer.publicKey,
            logicalWindow,
            presence.nonce,
          )),
    dependencies: options.dependencies ?? [],
    operationPayloadClass: 0,
    fixedPayload: payload,
    operationPadding: operationPaddingFor(0, payload.length),
  };
};

const buildSignedOperation = async (
  options: BuildOptions = {},
  operationContext: OperationValidationContext = context,
): Promise<AuthenticatedRoomOperationV1> => {
  const signer = options.signer ?? author;
  return signOperation(
    await unsignedOperation(options, operationContext),
    signer.secretKey,
  );
};

const buildOperation = async (
  options: BuildOptions = {},
  validationContext: OperationValidationContext = context,
): Promise<ValidatedIdentifiedOperationV1> =>
  validateAndIdentifyOperation(
    await buildSignedOperation(options, validationContext),
    validationContext,
  );

const coreReduceOuter = async (
  operations: readonly ValidatedIdentifiedOperationV1[],
  policy: RoomPolicyV4,
  referenceWindow: bigint,
): Promise<
  ReturnType<typeof coreReduce> extends Promise<infer T> ? T : never
> =>
  coreReduce(
    operations,
    await createOperationValidationContext(capability, policy, referenceWindow),
  );

/** Deterministic shuffle so a failure names one exact permutation seed. */
const permute = <T>(values: readonly T[], seed: number): T[] => {
  const output = [...values];
  let state = seed >>> 0;
  for (let index = output.length - 1; index > 0; index--) {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    const swap = state % (index + 1);
    [output[index], output[swap]] = [output[swap], output[index]];
  }
  return output;
};

describe("canonical operation codec", () => {
  test("round-trips through its unique canonical encoding", async () => {
    const { operation } = await buildOperation();
    const encoded = encodeOperation(operation);
    expect(hex(encodeOperation(decodeOperation(encoded)))).toBe(hex(encoded));
  });

  test("verifies a correct signature and rejects a tampered one", async () => {
    const { operation } = await buildOperation();
    await expect(
      validateOperation(operation, context),
    ).resolves.toBeUndefined();

    const tamperedPayload = Uint8Array.from(operation.fixedPayload);
    tamperedPayload[tamperedPayload.length - 1] ^= 0xff;
    const tampered: AuthenticatedRoomOperationV1 = {
      ...operation,
      fixedPayload: tamperedPayload,
    };
    await expect(validateOperation(tampered, context)).rejects.toThrow(
      "author signature does not verify",
    );

    const wrongKey: AuthenticatedRoomOperationV1 = {
      ...operation,
      authorEpochEd25519Key: otherAuthor.publicKey,
    };
    await expect(validateOperation(wrongKey, context)).rejects.toThrow(
      "author signature does not verify",
    );
  });

  test("rejects an operation confirming another room context", async () => {
    const operation = await buildSignedOperation({
      roomContextConfirmation: new Uint8Array(32).fill(0xfe),
    });
    expect(() => validateOperationStructure(operation, context)).toThrow(
      "does not confirm this room context",
    );
  });

  test("enforces the closed kind, lifetime, and dependency table", async () => {
    const { operation } = await buildOperation();
    expect(() =>
      validateOperationStructure(
        { ...operation, lifetime: "PAIR_CAUSAL" },
        context,
      ),
    ).toThrow("must use lifetime WINDOW_TRANSIENT");

    expect(() =>
      validateOperationStructure(
        { ...operation, dependencies: [new Uint8Array(32).fill(1)] },
        context,
      ),
    ).toThrow("must carry no outer dependencies");

    // LEAVE names exactly its referenced presence and nothing else.
    const leave = await buildSignedOperation({ kind: "LEAVE" });
    expect(() => validateOperationStructure(leave, context)).toThrow(
      "must name exactly one outer dependency",
    );
  });

  test("enforces exact class length and all-zero padding", async () => {
    const { operation } = await buildOperation();
    expect(() =>
      validateOperationStructure(
        { ...operation, operationPadding: new Uint8Array(10) },
        context,
      ),
    ).toThrow("must equal the exact class length");

    const nonZeroPadding = Uint8Array.from(operation.operationPadding);
    nonZeroPadding[0] = 1;
    expect(() =>
      validateOperationStructure(
        { ...operation, operationPadding: nonZeroPadding },
        context,
      ),
    ).toThrow("all-zero suffix");
  });

  test("a non-pair kind is confined to the small payload class", async () => {
    const { operation } = await buildOperation();
    // PRESENCE permits only class 0, so the closed-table check fires first;
    // the minimality rule below is what constrains a multi-class kind.
    expect(() =>
      validateOperationStructure(
        {
          ...operation,
          operationPayloadClass: 1,
          operationPadding: operationPaddingFor(
            1,
            operation.fixedPayload.length,
          ),
        },
        context,
      ),
    ).toThrow("does not permit payload class 1");
  });

  test("payload class selection takes the smallest fitting permitted class", () => {
    expect(operationPayloadClassFor("PRESENCE", 4096)).toBe(0);
    expect(operationPayloadClassFor("PAIR_STEP", 4096)).toBe(0);
    // Only PAIR_STEP may reach the large class, and only when it must.
    expect(operationPayloadClassFor("PAIR_STEP", 4097)).toBe(1);
    expect(() => operationPayloadClassFor("PRESENCE", 4097)).toThrow(
      "fits no permitted class",
    );
    expect(() => operationPayloadClassFor("PAIR_STEP", 69_633)).toThrow(
      "fits no permitted class",
    );
  });

  test("enforces the author-chain predecessor rule", async () => {
    const operation = await buildSignedOperation({ authorSequence: 1n });
    expect(() => validateOperationStructure(operation, context)).toThrow(
      "must name its predecessor",
    );

    const zeroWithPredecessor = await buildSignedOperation({
      authorSequence: 0n,
      previousAuthorOperationId: new Uint8Array(32).fill(2),
    });
    expect(() =>
      validateOperationStructure(zeroWithPredecessor, context),
    ).toThrow("sequence zero must have a null predecessor");
  });

  test("rejects windows outside the policy's skew and future bounds", async () => {
    const future = await buildSignedOperation({
      logicalWindow: REFERENCE_WINDOW + 6n,
    });
    expect(() => validateOperationStructure(future, context)).toThrow(
      "maxFutureLogicalWindows",
    );

    const expired = await buildSignedOperation({
      logicalWindow: REFERENCE_WINDOW - 100n,
      expiresAfterWindow: REFERENCE_WINDOW - 90n,
    });
    expect(() => validateOperationStructure(expired, context)).toThrow(
      "expired at this reference window",
    );
  });

  test("rejects ADMISSION_REVOKE outside an authority-grant room", async () => {
    const revoke = await buildSignedOperation({
      kind: "ADMISSION_REVOKE",
      expiresAfterWindow: REFERENCE_WINDOW + 10n,
    });
    expect(() => validateOperationStructure(revoke, context)).toThrow(
      "requires an authority-grant room policy",
    );
  });
});

describe("merge is associative, commutative, and idempotent", () => {
  const identity = (
    entries: readonly ValidatedIdentifiedOperationV1[],
  ): string => entries.map((entry) => hex(entry.operationId)).join(",");

  test("holds for every ordering of three disjoint sets", async () => {
    const a = [await buildOperation({ payload: Uint8Array.of(1) })];
    const b = [await buildOperation({ payload: Uint8Array.of(2) })];
    const c = [await buildOperation({ payload: Uint8Array.of(3) })];

    expect(identity(mergeOperationSets(a, b))).toBe(
      identity(mergeOperationSets(b, a)),
    );
    expect(identity(mergeOperationSets(mergeOperationSets(a, b), c))).toBe(
      identity(mergeOperationSets(a, mergeOperationSets(b, c))),
    );
    expect(identity(mergeOperationSets(a, a))).toBe(identity(a));
  });

  test("an exact duplicate delivery is a no-op", async () => {
    const entry = await buildOperation();
    const merged = mergeOperationSets([entry], [entry, entry]);
    expect(merged.length).toBe(1);
  });

  test("rejects object-spread and structured-cloned reducer entries", async () => {
    const entry = await buildOperation();
    const spread = {
      ...entry,
    } as unknown as ValidatedIdentifiedOperationV1;
    const restored = structuredClone(
      entry,
    ) as unknown as ValidatedIdentifiedOperationV1;

    expect(() => mergeOperationSets([spread], [])).toThrow(
      "live result of validateAndIdentifyOperation",
    );
    expect(() => mergeOperationSets([restored], [])).toThrow(
      "live result of validateAndIdentifyOperation",
    );
    await expect(
      coreReduceOuter([restored], roomPolicy, REFERENCE_WINDOW),
    ).rejects.toThrow("live result of validateAndIdentifyOperation");
  });

  test("rejects post-validation mutation of exposed typed arrays", async () => {
    const bodyMutated = await buildOperation({
      payload: Uint8Array.of(1),
    });
    bodyMutated.operation.fixedPayload[0] ^= 0xff;
    expect(() => mergeOperationSets([bodyMutated], [])).toThrow(
      "mutated after validation",
    );

    const idMutated = await buildOperation({ payload: Uint8Array.of(2) });
    idMutated.operationId[0] ^= 0xff;
    await expect(
      coreReduceOuter([idMutated], roomPolicy, REFERENCE_WINDOW),
    ).rejects.toThrow("mutated after validation");
  });

  test("snapshots caller operation and validation context before its first await", async () => {
    const signed = await buildSignedOperation({
      payload: Uint8Array.of(0x11, 0x22),
    });
    const expectedPayload = Uint8Array.from(signed.fixedPayload);
    const mutableContext = operationValidationContextAt(
      context,
      context.referenceWindow,
    );

    const pending = validateAndIdentifyOperation(signed, mutableContext);
    signed.fixedPayload.fill(0xff);
    signed.authorSignature.fill(0);
    mutableContext.roomContextId.fill(0);
    mutableContext.roomContextConfirmation.fill(0);
    mutableContext.roomPolicy.sessionPolicyV1.fill(0);

    const identified = await pending;
    expect(identified.operation.fixedPayload).toEqual(expectedPayload);
    expect(mergeOperationSets([identified], [])).toHaveLength(1);
  });
});

describe("CoreReduce is independent of delivery order and duplication", () => {
  const buildChain = async (): Promise<ValidatedIdentifiedOperationV1[]> => {
    const first = await buildOperation({
      payload: Uint8Array.of(1),
    });
    const second = await buildOperation({
      payload: Uint8Array.of(2),
      authorSequence: 1n,
      previousAuthorOperationId: first.operationId,
    });
    const remote = await buildOperation({
      payload: Uint8Array.of(3),
      signer: otherAuthor,
    });
    const pairRoutingTag = new Uint8Array(32).fill(0x04);
    const pairPayload = encodePairStepEnvelopeV1(
      {
        version: 1,
        pairRoutingTag,
        bootstrapHeader: null,
        nonce: new Uint8Array(24).fill(0x05),
        pairCiphertextAndTag: new Uint8Array(
          pairCiphertextAndTagTargetBytesV1(0, false),
        ),
      },
      0,
    );
    const pairStep = await buildOperation({
      kind: "PAIR_STEP",
      payload: pairPayload,
      signer: otherAuthor,
      authorSequence: 1n,
      previousAuthorOperationId: remote.operationId,
      semanticSlot: await pairSemanticSlot(pairRoutingTag),
    });
    return [first, second, remote, pairStep];
  };

  test("every permutation and duplication yields one byte-identical state", async () => {
    const operations = await buildChain();
    const baseline = await coreReduceOuter(
      operations,
      roomPolicy,
      REFERENCE_WINDOW,
    );

    for (let seed = 1; seed <= 24; seed++) {
      const shuffled = permute(operations, seed);
      // Duplicate a different element each round: at-least-once delivery must
      // not change the result.
      const withDuplicate = [...shuffled, shuffled[seed % shuffled.length]];
      const state = await coreReduceOuter(
        withDuplicate,
        roomPolicy,
        REFERENCE_WINDOW,
      );
      expect(hex(state.operationsDigest)).toBe(hex(baseline.operationsDigest));
      expect(state.activeOperationIds.map(hex)).toEqual(
        baseline.activeOperationIds.map(hex),
      );
      expect(state.activePairOuterOperationIds.map(hex)).toEqual(
        baseline.activePairOuterOperationIds.map(hex),
      );
    }
  });

  test("an outer-valid pair step enters every member's core set", async () => {
    const operations = await buildChain();
    const state = await coreReduceOuter(
      operations,
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.activePairOuterOperationIds.length).toBe(1);
    expect(state.activeOperationIds.map(hex)).toContain(
      hex(state.activePairOuterOperationIds[0]),
    );
  });

  test("omission changes the observed frontier, not the derivation", async () => {
    const operations = await buildChain();
    const full = await coreReduceOuter(
      operations,
      roomPolicy,
      REFERENCE_WINDOW,
    );
    const partial = await coreReduceOuter(
      operations.slice(0, 2),
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(hex(partial.operationsDigest)).not.toBe(hex(full.operationsDigest));

    // Late delivery of the omitted operations converges to the same state.
    const late = await coreReduceOuter(
      mergeOperationSets(operations.slice(0, 2), operations.slice(2)),
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(hex(late.operationsDigest)).toBe(hex(full.operationsDigest));
  });

  test("future and expired operations are excluded from active state", async () => {
    const live = await buildOperation({ payload: Uint8Array.of(1) });
    const future = await buildOperation({
      payload: Uint8Array.of(2),
      logicalWindow: REFERENCE_WINDOW + 3n,
    });
    const expired = await buildOperation(
      {
        payload: Uint8Array.of(3),
        logicalWindow: REFERENCE_WINDOW - 100n,
        expiresAfterWindow: REFERENCE_WINDOW - 90n,
      },
      operationValidationContextAt(context, REFERENCE_WINDOW - 100n),
    );

    const state = await coreReduceOuter(
      [live, future, expired],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.activeOperationIds.map(hex)).toEqual([hex(live.operationId)]);

    // The future operation becomes active at a later reference window without
    // any new delivery.
    const later = await coreReduceOuter(
      [live, future, expired],
      roomPolicy,
      REFERENCE_WINDOW + 3n,
    );
    expect(later.activeOperationIds.map(hex).sort()).toEqual(
      [hex(live.operationId), hex(future.operationId)].sort(),
    );
  });
});

describe("author fork and overquota are arrival-independent", () => {
  test("two byte-different operations in one slot fork the author window", async () => {
    const first = await buildOperation({ payload: Uint8Array.of(1) });
    const second = await buildOperation({ payload: Uint8Array.of(2) });
    const honest = await buildOperation({
      payload: Uint8Array.of(3),
      signer: otherAuthor,
    });

    for (const ordering of [
      [first, second, honest],
      [second, first, honest],
      [honest, second, first],
    ]) {
      const state = await coreReduceOuter(
        ordering,
        roomPolicy,
        REFERENCE_WINDOW,
      );
      expect(state.faults.length).toBe(1);
      const fault = state.faults[0];
      expect(fault.kind).toBe("author-fork-or-overquota");
      if (fault.kind !== "author-fork-or-overquota")
        throw new Error("unexpected fault kind");
      expect(fault.proofOperationIds.length).toBe(2);
      // The forked author contributes nothing; the honest author is unaffected.
      expect(state.activeOperationIds.map(hex)).toEqual([
        hex(honest.operationId),
      ]);
    }
  });

  test("exceeding maxOperationsPerAuthorWindow excludes the whole window", async () => {
    const quota = roomPolicy.protocolLimits.maxOperationsPerAuthorWindow;
    const operations: ValidatedIdentifiedOperationV1[] = [];
    let previous: Uint8Array | null = null;
    for (let sequence = 0; sequence <= quota; sequence++) {
      const entry = await buildOperation({
        payload: Uint8Array.of(sequence),
        authorSequence: BigInt(sequence),
        previousAuthorOperationId: previous,
      });
      previous = entry.operationId;
      operations.push(entry);
    }
    expect(operations.length).toBe(quota + 1);

    const state = await coreReduceOuter(
      permute(operations, 7),
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.faults.length).toBe(1);
    // Physical proof needs only the lowest quota+1 IDs.
    const fault = state.faults[0];
    if (fault.kind !== "author-fork-or-overquota")
      throw new Error("unexpected fault kind");
    expect(fault.proofOperationIds.length).toBe(quota + 1);
    expect(state.activeOperationIds.length).toBe(0);
  });

  test("overquota proof takes precedence over a simultaneous author-slot fork", async () => {
    const quota = roomPolicy.protocolLimits.maxOperationsPerAuthorWindow;
    const operations: ValidatedIdentifiedOperationV1[] = [];
    let previous: Uint8Array | null = null;
    for (let sequence = 0; sequence <= quota; sequence++) {
      const entry = await buildOperation({
        payload: Uint8Array.of(sequence),
        authorSequence: BigInt(sequence),
        previousAuthorOperationId: previous,
      });
      previous = entry.operationId;
      operations.push(entry);
    }
    const forkedSequenceZero = await buildOperation({
      payload: Uint8Array.of(0xff),
      authorSequence: 0n,
      previousAuthorOperationId: null,
    });
    const combined = [...operations, forkedSequenceZero];

    const state = await coreReduceOuter(
      permute(combined, 11),
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.faults).toHaveLength(1);
    const fault = state.faults[0];
    if (fault.kind !== "author-fork-or-overquota")
      throw new Error("unexpected fault kind");
    expect(fault.proofOperationIds.map(hex)).toEqual(
      combined
        .map((entry) => hex(entry.operationId))
        .sort()
        .slice(0, quota + 1),
    );
  });

  test("a non-revocation under the pinned authority faults that authority window", async () => {
    const authorityPolicy = {
      ...roomPolicy,
      admissionFloor: {
        mode: "authority-grant" as const,
        authorityEd25519PublicKey: author.publicKey,
        maxAuthorityCredentialLifetimeWindows: 60,
      },
    };
    const pairRoutingTag = new Uint8Array(32).fill(0xa7);
    const pairPayload = encodePairStepEnvelopeV1(
      {
        version: 1,
        pairRoutingTag,
        bootstrapHeader: null,
        nonce: new Uint8Array(24).fill(0xa8),
        pairCiphertextAndTag: new Uint8Array(
          pairCiphertextAndTagTargetBytesV1(0, false),
        ),
      },
      0,
    );
    const unauthorizedAuthorityOperation = await buildOperation(
      {
        kind: "PAIR_STEP",
        payload: pairPayload,
        semanticSlot: await pairSemanticSlot(pairRoutingTag),
        signer: author,
      },
      await createOperationValidationContext(
        capability,
        authorityPolicy,
        REFERENCE_WINDOW,
      ),
    );

    const state = await coreReduceOuter(
      [unauthorizedAuthorityOperation],
      authorityPolicy,
      REFERENCE_WINDOW,
    );

    expect(state.activeOperationIds).toEqual([]);
    expect(state.faults).toHaveLength(1);
    expect(state.faults[0]).toMatchObject({
      kind: "author-fork-or-overquota",
      logicalWindow: REFERENCE_WINDOW,
    });
    const fault = state.faults[0];
    if (fault.kind !== "author-fork-or-overquota")
      throw new Error("unexpected fault kind");
    expect(fault.proofOperationIds.map(hex)).toEqual([
      hex(unauthorizedAuthorityOperation.operationId),
    ]);
  });

  test("a fork in one logical window does not fault the author's other window", async () => {
    const forkedA = await buildOperation({ payload: Uint8Array.of(1) });
    const forkedB = await buildOperation({ payload: Uint8Array.of(2) });
    const otherWindow = await buildOperation({
      payload: Uint8Array.of(3),
      logicalWindow: REFERENCE_WINDOW - 1n,
      expiresAfterWindow: REFERENCE_WINDOW + 5n,
    });

    const state = await coreReduceOuter(
      [forkedA, forkedB, otherWindow],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.faults.length).toBe(1);
    expect(state.activeOperationIds.map(hex)).toEqual([
      hex(otherWindow.operationId),
    ]);
  });

  test("an empty validated set reduces to exact empty payload facts", async () => {
    const state = await coreReduceOuter([], roomPolicy, REFERENCE_WINDOW);
    expect(state.observedPresences).toEqual([]);
    expect(state.effectiveLeaveOperationIds).toEqual([]);
    expect(state.storeCatalogFacts).toEqual([]);
    expect(state.revocationFloors).toEqual([]);
    expect(state.roomCapacityState).toBe("within-policy");
  });

  test("an author chain with a gap contributes nothing", async () => {
    const zero = await buildOperation({ payload: Uint8Array.of(1) });
    const one = await buildOperation({
      payload: Uint8Array.of(2),
      authorSequence: 1n,
      previousAuthorOperationId: zero.operationId,
    });
    // Sequence 2 links to 1, but 1 is withheld by the carrier.
    const two = await buildOperation({
      payload: Uint8Array.of(3),
      authorSequence: 2n,
      previousAuthorOperationId: one.operationId,
    });

    const withGap = await coreReduceOuter(
      [zero, two],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(withGap.activeOperationIds.map(hex)).toEqual([
      hex(zero.operationId),
    ]);

    // Late delivery of the missing link admits the rest of the chain.
    const complete = await coreReduceOuter(
      [zero, one, two],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(complete.activeOperationIds.length).toBe(3);
  });

  test("a chain link naming the wrong predecessor is not admitted", async () => {
    const zero = await buildOperation({ payload: Uint8Array.of(1) });
    const mislinked = await buildOperation({
      payload: Uint8Array.of(2),
      authorSequence: 1n,
      previousAuthorOperationId: new Uint8Array(32).fill(0xab),
    });
    const state = await coreReduceOuter(
      [zero, mislinked],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.activeOperationIds.map(hex)).toEqual([hex(zero.operationId)]);
  });

  test("faults sort by author key and window, not by a nested proof id", async () => {
    const forkA = await buildOperation({ payload: Uint8Array.of(1) });
    const forkB = await buildOperation({ payload: Uint8Array.of(2) });
    const otherForkA = await buildOperation({
      payload: Uint8Array.of(3),
      signer: otherAuthor,
    });
    const otherForkB = await buildOperation({
      payload: Uint8Array.of(4),
      signer: otherAuthor,
    });

    const state = await coreReduceOuter(
      permute([forkA, forkB, otherForkA, otherForkB], 3),
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.faults.length).toBe(2);
    const keys = state.faults.map((fault) => {
      if (fault.kind !== "author-fork-or-overquota")
        throw new Error("unexpected fault kind");
      return hex(fault.authorEpochEd25519Key);
    });
    expect([...keys]).toEqual([...keys].sort());
  });
});
