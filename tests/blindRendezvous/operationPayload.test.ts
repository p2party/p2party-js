import { describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import {
  admissionGrantSignedMessage,
  admissionRevokeSemanticSlot,
  admissionRevokeSignedMessage,
  leaveSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presencePermitSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  stableIdentityCommitment,
  storeHintSemanticSlot,
} from "../../src/blindRendezvous/derivations";
import {
  createOperationValidationContext,
  deriveOperationId,
  operationPaddingFor,
  operationValidationContextAt,
  requiredRoomRetentionWindows,
  signOperation,
  validateOperation,
  validateOperationCandidateOuter,
} from "../../src/blindRendezvous/operation";
import {
  decodeAdmissionGrantV1,
  decodeAdmissionRevokeV1,
  decodeLeaveV1,
  decodePresenceV1,
  decodeStoreHintOperationV1,
  encodeAdmissionGrantV1,
  encodeAdmissionRevokeV1,
  encodeLeaveV1,
  encodePresenceV1,
  encodeStoreHintOperationV1,
  validateAdmissionGrantV1,
  validateCorePresenceFactOwnershipV1,
  validatePresenceOwnershipV1,
} from "../../src/blindRendezvous/operationPayload";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import {
  descriptorHash,
  storeDescriptorSignedMessage,
  storeId,
  storeRouteSignedMessage,
} from "../../src/blindRendezvous/storeDescriptor";

import type {
  AuthenticatedRoomOperationV1,
  OperationValidationContext,
  UnsignedRoomOperationV1,
} from "../../src/blindRendezvous/operation";
import type {
  AdmissionGrantV1,
  AdmissionRevokeV1,
  LeaveV1,
  PresenceCoreV1,
  PresencePermitV1,
  PresenceV1,
  StoreHintOperationV1,
} from "../../src/blindRendezvous/operationPayload";
import type {
  StoreDescriptorV1,
  StoreRouteV1,
} from "../../src/blindRendezvous/storeDescriptor";
import type { CorePresenceFactV1 } from "../../src/blindRendezvous/coreReduce";

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const capability = bytes(0x41);
const author = await newKeyPair();
const stable = await newKeyPair();
const otherStable = await newKeyPair();
const authority = await newKeyPair();
const store = await newKeyPair();

const capabilityPolicy = DEFAULT_BLIND_POLICY_V4_0;
const authorityPolicy = {
  ...capabilityPolicy,
  admissionFloor: {
    mode: "authority-grant" as const,
    authorityEd25519PublicKey: authority.publicKey,
    maxAuthorityCredentialLifetimeWindows: 60,
  },
};

const validationContext = async (
  roomPolicy: typeof capabilityPolicy | typeof authorityPolicy,
  referenceWindow = 1_000n,
): Promise<OperationValidationContext> => {
  return createOperationValidationContext(
    capability,
    roomPolicy,
    referenceWindow,
  );
};

const capabilityContext = await validationContext(capabilityPolicy);
const authorityContext = await validationContext(authorityPolicy);

const signOuter = async (
  fields: Omit<UnsignedRoomOperationV1, "operationPadding">,
  secretKey = author.secretKey,
): Promise<AuthenticatedRoomOperationV1> =>
  signOperation(
    {
      ...fields,
      operationPadding: operationPaddingFor(
        fields.operationPayloadClass,
        fields.fixedPayload.length,
      ),
    },
    secretKey,
  );

interface PresenceFixture {
  readonly operation: AuthenticatedRoomOperationV1;
  readonly presence: PresenceV1;
  readonly context: OperationValidationContext;
}

const buildPresence = async (
  context: OperationValidationContext,
  options: {
    readonly logicalWindow?: bigint;
    readonly expiresAfterWindow?: bigint;
    readonly includePermit?: boolean;
    readonly permitSignerSecretKey?: Uint8Array;
    readonly semanticSlot?: Uint8Array;
  } = {},
): Promise<PresenceFixture> => {
  const logicalWindow = options.logicalWindow ?? 1_000n;
  const expiresAfterWindow = options.expiresAfterWindow ?? logicalWindow + 10n;
  const core: PresenceCoreV1 = {
    version: 1,
    stableIdentityCommitment: await stableIdentityCommitment(
      context.roomContextId,
      stable.publicKey,
    ),
    rendezvousHybridKemPublicKey: bytes(0x52, 1216),
    receiverKeyValidThroughLogicalWindow: expiresAfterWindow,
    presenceNonce: bytes(0x53),
    validThroughLogicalWindow: expiresAfterWindow - 1n,
  };
  const transcriptHash = await presenceProofTranscriptHash({
    roomContextId: context.roomContextId,
    policyHash: await policyHash(context.roomPolicy),
    logicalWindow,
    authorEpochEd25519Key: author.publicKey,
    core,
  });
  const ownershipSignature = await sign(
    presenceOwnershipSignedMessage(transcriptHash),
    stable.secretKey,
  );

  let authorityPermit: PresencePermitV1 | null = null;
  if (options.includePermit === true) {
    const unsignedPermit = {
      version: 1 as const,
      roomContextId: context.roomContextId,
      presenceProofTranscriptHash: transcriptHash,
      permitSerial: bytes(0x54),
      generation: 7n,
      issuedAtLogicalWindow: logicalWindow,
      notBeforeLogicalWindow: logicalWindow,
      notAfterLogicalWindow: expiresAfterWindow,
    };
    authorityPermit = {
      ...unsignedPermit,
      authoritySignature: await sign(
        await presencePermitSignedMessage(unsignedPermit),
        options.permitSignerSecretKey ?? authority.secretKey,
      ),
    };
  }

  const presence: PresenceV1 = {
    core,
    stableOwnershipSignature: ownershipSignature,
    authorityPermit,
  };
  const payload = encodePresenceV1(presence);
  const operation = await signOuter({
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    logicalWindow,
    expiresAfterWindow,
    lifetime: "WINDOW_TRANSIENT",
    authorEpochEd25519Key: author.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "PRESENCE",
    semanticSlot:
      options.semanticSlot ??
      (await presenceSemanticSlot(
        author.publicKey,
        logicalWindow,
        core.presenceNonce,
      )),
    dependencies: [],
    operationPayloadClass: 0,
    fixedPayload: payload,
  });
  return { operation, presence, context };
};

const resignPresence = async (
  fixture: PresenceFixture,
  presence: PresenceV1,
): Promise<AuthenticatedRoomOperationV1> => {
  const fixedPayload = encodePresenceV1(presence);
  const {
    authorSignature: _signature,
    operationPadding: _padding,
    ...outer
  } = fixture.operation;
  return signOuter({ ...outer, fixedPayload }, author.secretKey);
};

const unsignedDescriptor = {
  version: 1 as const,
  storeIdentityEd25519Key: store.publicKey,
  allocationIssuerPublicKeyDer: Uint8Array.of(0x30),
  descriptorGeneration: 3n,
  compatibilityHash: bytes(0x61),
  supportedDeliveryProfileHashes: [bytes(0x62)],
  checkpointChainStarts: [
    {
      deliveryProfileHash: bytes(0x62),
      chainStartIngressWindow: 0n,
    },
  ],
  retentionWindows: 256,
  notBeforeUnixMs: 0n,
  notAfterUnixMs: 100_000_000n,
};

const signDescriptor = async (): Promise<StoreDescriptorV1> => {
  const draft: StoreDescriptorV1 = {
    ...unsignedDescriptor,
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

const signRoute = async (
  descriptor: StoreDescriptorV1,
): Promise<StoreRouteV1> => {
  const draft: StoreRouteV1 = {
    version: 1,
    storeId: await storeId(store.publicKey),
    descriptorHash: await descriptorHash(descriptor),
    routeFamily: 1,
    opaqueLocator: new TextEncoder().encode("https://store.example"),
    routePublicParameters: new Uint8Array(0),
    notBeforeUnixMs: 0n,
    notAfterUnixMs: 100_000_000n,
    routeSignature: bytes(0, 64),
  };
  return {
    ...draft,
    routeSignature: await sign(
      await storeRouteSignedMessage(draft),
      store.secretKey,
    ),
  };
};

describe("closed non-pair payload codecs", () => {
  test("round-trips every payload without a second field-order table", async () => {
    const presence = (await buildPresence(capabilityContext)).presence;
    const leave: LeaveV1 = {
      version: 1,
      presenceOperationId: bytes(0x71),
      effectiveLogicalWindow: 1_000n,
    };
    const descriptor = await signDescriptor();
    const hint: StoreHintOperationV1 = {
      version: 1,
      descriptor,
      routes: [],
      hintExpiresAfterLogicalWindow: 1_005n,
    };
    const grant: AdmissionGrantV1 = {
      version: 1,
      roomContextId: authorityContext.roomContextId,
      stableEd25519PublicKey: stable.publicKey,
      generation: 2n,
      issuedAtLogicalWindow: 995n,
      notBeforeLogicalWindow: 996n,
      notAfterLogicalWindow: 1_010n,
      authoritySignature: bytes(0, 64),
    };
    const revoke: AdmissionRevokeV1 = {
      version: 1,
      roomContextId: authorityContext.roomContextId,
      stableIdentityCommitment: bytes(0x72),
      minimumAcceptedGeneration: 9n,
      effectiveLogicalWindow: 1_000n,
      expiresAfterLogicalWindow: 1_065n,
      authoritySignature: bytes(0, 64),
    };

    const vectors = [
      [
        encodePresenceV1(presence),
        encodePresenceV1(decodePresenceV1(encodePresenceV1(presence))),
      ],
      [
        encodeLeaveV1(leave),
        encodeLeaveV1(decodeLeaveV1(encodeLeaveV1(leave))),
      ],
      [
        encodeStoreHintOperationV1(hint),
        encodeStoreHintOperationV1(
          decodeStoreHintOperationV1(encodeStoreHintOperationV1(hint)),
        ),
      ],
      [
        encodeAdmissionGrantV1(grant),
        encodeAdmissionGrantV1(
          decodeAdmissionGrantV1(encodeAdmissionGrantV1(grant)),
        ),
      ],
      [
        encodeAdmissionRevokeV1(revoke),
        encodeAdmissionRevokeV1(
          decodeAdmissionRevokeV1(encodeAdmissionRevokeV1(revoke)),
        ),
      ],
    ];
    for (const [encoded, reencoded] of vectors)
      expect(hex(reencoded)).toBe(hex(encoded));
  });
});

describe("PRESENCE intrinsic and deferred ownership validation", () => {
  test("accepts capability presence and verifies ownership when the key is supplied", async () => {
    const fixture = await buildPresence(capabilityContext);
    await expect(
      validateOperation(fixture.operation, capabilityContext),
    ).resolves.toBeUndefined();
    await expect(
      validatePresenceOwnershipV1(
        fixture.operation,
        fixture.presence,
        stable.publicKey,
        capabilityContext,
      ),
    ).resolves.toBeUndefined();
    await expect(
      validatePresenceOwnershipV1(
        fixture.operation,
        fixture.presence,
        otherStable.publicKey,
        capabilityContext,
      ),
    ).rejects.toThrow("does not match the presence commitment");
  });

  test("binds ownership to the exact operation payload and snapshots mutable inputs", async () => {
    const mismatchFixture = await buildPresence(capabilityContext);
    const mismatchedPresence = decodePresenceV1(
      encodePresenceV1(mismatchFixture.presence),
    );
    mismatchedPresence.stableOwnershipSignature[0] ^= 0xff;
    await expect(
      validatePresenceOwnershipV1(
        mismatchFixture.operation,
        mismatchedPresence,
        stable.publicKey,
        capabilityContext,
      ),
    ).rejects.toThrow("does not match the operation payload");

    const fixture = await buildPresence(capabilityContext);
    const mutableStableKey = Uint8Array.from(stable.publicKey);
    const pending = validatePresenceOwnershipV1(
      fixture.operation,
      fixture.presence,
      mutableStableKey,
      capabilityContext,
    );
    fixture.operation.fixedPayload.fill(0);
    fixture.presence.stableOwnershipSignature.fill(0);
    fixture.presence.core.presenceNonce.fill(0);
    mutableStableKey.fill(0);
    await expect(pending).resolves.toBeUndefined();
  });

  test("verifies a trusted Core fact without fabricating an outer operation", async () => {
    const fixture = await buildPresence(capabilityContext);
    const fact: CorePresenceFactV1 = {
      presenceOperationId: await deriveOperationId(fixture.operation),
      authorEpochEd25519Key: Uint8Array.from(
        fixture.operation.authorEpochEd25519Key,
      ),
      logicalWindow: fixture.operation.logicalWindow,
      presence: decodePresenceV1(encodePresenceV1(fixture.presence)),
    };
    const mutableStableKey = Uint8Array.from(stable.publicKey);
    const pending = validateCorePresenceFactOwnershipV1(
      fact,
      mutableStableKey,
      capabilityContext,
    );
    fact.presenceOperationId.fill(0);
    fact.authorEpochEd25519Key.fill(0);
    fact.presence.stableOwnershipSignature.fill(0);
    mutableStableKey.fill(0);
    await expect(pending).resolves.toBeUndefined();

    const wrongKeyFact: CorePresenceFactV1 = {
      presenceOperationId: await deriveOperationId(fixture.operation),
      authorEpochEd25519Key: Uint8Array.from(
        fixture.operation.authorEpochEd25519Key,
      ),
      logicalWindow: fixture.operation.logicalWindow,
      presence: decodePresenceV1(encodePresenceV1(fixture.presence)),
    };
    await expect(
      validateCorePresenceFactOwnershipV1(
        wrongKeyFact,
        otherStable.publicKey,
        capabilityContext,
      ),
    ).rejects.toThrow("does not match the presence commitment");
  });

  test("does not pretend the hidden stable key is core-verifiable", async () => {
    const fixture = await buildPresence(capabilityContext);
    const tamperedSignature = Uint8Array.from(
      fixture.presence.stableOwnershipSignature,
    );
    tamperedSignature[0] ^= 0xff;
    const tamperedPresence = {
      ...fixture.presence,
      stableOwnershipSignature: tamperedSignature,
    };
    const operation = await resignPresence(fixture, tamperedPresence);

    // Room-wide validation has no raw stable key and therefore cannot test the
    // signature. The trusted address-book/pair projection can and does.
    await expect(
      validateOperation(operation, capabilityContext),
    ).resolves.toBeUndefined();
    await expect(
      validatePresenceOwnershipV1(
        operation,
        tamperedPresence,
        stable.publicKey,
        capabilityContext,
      ),
    ).rejects.toThrow("ownership signature does not verify");
  });

  test("rejects the wrong semantic slot and impossible nested interval", async () => {
    const wrongSlot = await buildPresence(capabilityContext, {
      semanticSlot: bytes(0xff),
    });
    await expect(
      validateOperation(wrongSlot.operation, capabilityContext),
    ).rejects.toThrow("semanticSlot does not match");

    const fixture = await buildPresence(capabilityContext);
    const impossible: PresenceV1 = {
      ...fixture.presence,
      core: {
        ...fixture.presence.core,
        validThroughLogicalWindow:
          fixture.presence.core.receiverKeyValidThroughLogicalWindow + 1n,
      },
    };
    await expect(
      validateOperation(
        await resignPresence(fixture, impossible),
        capabilityContext,
      ),
    ).rejects.toThrow("validity interval");
  });

  test("rejects a presence whose required historical receiver-key horizon overflows", async () => {
    const maximumWindow = 0xffffffffffffffffn;
    const nearMaximumContext = await validationContext(
      capabilityPolicy,
      maximumWindow - 10n,
    );
    const fixture = await buildPresence(nearMaximumContext, {
      logicalWindow: maximumWindow - 10n,
      expiresAfterWindow: maximumWindow,
    });
    await expect(
      validateOperation(fixture.operation, nearMaximumContext),
    ).rejects.toThrow("checked unsigned-64 addition overflowed");
  });

  test("closes capability/authority permit modes and verifies the pinned signer", async () => {
    const capabilityWithPermit = await buildPresence(capabilityContext, {
      includePermit: true,
    });
    await expect(
      validateOperation(capabilityWithPermit.operation, capabilityContext),
    ).rejects.toThrow("forbidden in capability mode");

    const missingAuthorityPermit = await buildPresence(authorityContext);
    await expect(
      validateOperation(missingAuthorityPermit.operation, authorityContext),
    ).rejects.toThrow("requires a presence permit");

    const valid = await buildPresence(authorityContext, {
      includePermit: true,
    });
    await expect(
      validateOperation(valid.operation, authorityContext),
    ).resolves.toBeUndefined();

    const forged = await buildPresence(authorityContext, {
      includePermit: true,
      permitSignerSecretKey: otherStable.secretKey,
    });
    await expect(
      validateOperation(forged.operation, authorityContext),
    ).rejects.toThrow("authority signature does not verify");
  });

  test("retains a bounded future candidate without promoting it early", async () => {
    const futureContext = operationValidationContextAt(
      authorityContext,
      1_000n,
    );
    const future = await buildPresence(futureContext, {
      logicalWindow: 1_003n,
      expiresAfterWindow: 1_010n,
      includePermit: true,
    });
    await expect(
      validateOperation(future.operation, futureContext),
    ).resolves.toBeUndefined();
  });

  test("rejects a structurally forged room-validation context", async () => {
    const fixture = await buildPresence(capabilityContext);
    await expect(
      validateOperation(fixture.operation, {
        ...capabilityContext,
        roomPolicy: authorityPolicy,
      } as unknown as OperationValidationContext),
    ).rejects.toThrow("must be created by createOperationValidationContext");
  });
});

describe("LEAVE, STORE_HINT, and ADMISSION_REVOKE", () => {
  test("binds LEAVE to its exact dependency, window, and semantic slot", async () => {
    const presence = await buildPresence(capabilityContext);
    const presenceOperationId = await deriveOperationId(presence.operation);
    const leave: LeaveV1 = {
      version: 1,
      presenceOperationId,
      effectiveLogicalWindow: 1_000n,
    };
    const payload = encodeLeaveV1(leave);
    const operation = await signOuter({
      version: 1,
      roomContextConfirmation: capabilityContext.roomContextConfirmation,
      logicalWindow: 1_000n,
      expiresAfterWindow: 1_010n,
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: author.publicKey,
      authorSequence: 0n,
      previousAuthorOperationId: null,
      kind: "LEAVE",
      semanticSlot: await leaveSemanticSlot(
        leave.presenceOperationId,
        leave.effectiveLogicalWindow,
      ),
      dependencies: [presenceOperationId],
      operationPayloadClass: 0,
      fixedPayload: payload,
    });
    await expect(
      validateOperation(operation, capabilityContext),
    ).resolves.toBeUndefined();

    const wrongDependency = await signOuter({
      ...(() => {
        const {
          authorSignature: _signature,
          operationPadding: _padding,
          ...unsignedOperation
        } = operation;
        return unsignedOperation;
      })(),
      dependencies: [bytes(0xaa)],
    });
    await expect(
      validateOperation(wrongDependency, capabilityContext),
    ).rejects.toThrow("dependency must equal");
  });

  test("accepts a descriptor-only hint but fails closed on unfrozen route codecs", async () => {
    const descriptor = await signDescriptor();
    const baseHint: StoreHintOperationV1 = {
      version: 1,
      descriptor,
      routes: [],
      hintExpiresAfterLogicalWindow: 1_005n,
    };
    const buildHintOperation = async (
      hint: StoreHintOperationV1,
    ): Promise<AuthenticatedRoomOperationV1> => {
      const payload = encodeStoreHintOperationV1(hint);
      return signOuter({
        version: 1,
        roomContextConfirmation: capabilityContext.roomContextConfirmation,
        logicalWindow: 1_000n,
        expiresAfterWindow: 1_010n,
        lifetime: "WINDOW_TRANSIENT",
        authorEpochEd25519Key: author.publicKey,
        authorSequence: 0n,
        previousAuthorOperationId: null,
        kind: "STORE_HINT",
        semanticSlot: await storeHintSemanticSlot(
          await storeId(descriptor.storeIdentityEd25519Key),
          descriptor.descriptorGeneration,
        ),
        dependencies: [],
        operationPayloadClass: 0,
        fixedPayload: payload,
      });
    };

    await expect(
      validateOperation(await buildHintOperation(baseHint), capabilityContext),
    ).resolves.toBeUndefined();

    const route = await signRoute(descriptor);
    await expect(
      validateOperation(
        await buildHintOperation({ ...baseHint, routes: [route] }),
        capabilityContext,
      ),
    ).rejects.toThrow("route-family registry is not frozen");

    const forgedDescriptor: StoreDescriptorV1 = {
      ...descriptor,
      descriptorSignature: bytes(0xff, 64),
    };
    await expect(
      validateOperation(
        await buildHintOperation({
          ...baseHint,
          descriptor: forgedDescriptor,
        }),
        capabilityContext,
      ),
    ).rejects.toThrow("descriptor is not authentic");
  });

  test("requires the exact authority horizon, slot, inner signer, and outer signer", async () => {
    const effectiveLogicalWindow = 1_000n;
    const expiresAfterLogicalWindow =
      effectiveLogicalWindow +
      BigInt(authorityPolicy.protocolLimits.maxFutureLogicalWindows) +
      BigInt(
        authorityPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows,
      );
    const unsignedRevoke = {
      version: 1 as const,
      roomContextId: authorityContext.roomContextId,
      stableIdentityCommitment: bytes(0x91),
      minimumAcceptedGeneration: 11n,
      effectiveLogicalWindow,
      expiresAfterLogicalWindow,
    };
    const revoke: AdmissionRevokeV1 = {
      ...unsignedRevoke,
      authoritySignature: await sign(
        await admissionRevokeSignedMessage(unsignedRevoke),
        authority.secretKey,
      ),
    };
    const buildRevoke = async (
      value: AdmissionRevokeV1,
      outerExpiry = value.expiresAfterLogicalWindow,
    ): Promise<AuthenticatedRoomOperationV1> => {
      const payload = encodeAdmissionRevokeV1(value);
      return signOuter(
        {
          version: 1,
          roomContextConfirmation: authorityContext.roomContextConfirmation,
          logicalWindow: value.effectiveLogicalWindow,
          expiresAfterWindow: outerExpiry,
          lifetime: "GRANT_HORIZON",
          authorEpochEd25519Key: authority.publicKey,
          authorSequence: 0n,
          previousAuthorOperationId: null,
          kind: "ADMISSION_REVOKE",
          semanticSlot: await admissionRevokeSemanticSlot(
            value.stableIdentityCommitment,
            value.minimumAcceptedGeneration,
            value.effectiveLogicalWindow,
            value.expiresAfterLogicalWindow,
          ),
          dependencies: [],
          operationPayloadClass: 0,
          fixedPayload: payload,
        },
        authority.secretKey,
      );
    };

    await expect(
      validateOperation(await buildRevoke(revoke), authorityContext),
    ).resolves.toBeUndefined();
    await expect(
      validateOperation(
        await buildRevoke(revoke, expiresAfterLogicalWindow - 1n),
        authorityContext,
      ),
    ).rejects.toThrow("exact grant horizon");

    const skew = BigInt(authorityPolicy.protocolLimits.maxClockSkewWindows);
    const evidenceValidThrough =
      effectiveLogicalWindow +
      requiredRoomRetentionWindows(authorityPolicy) +
      skew;
    const lateReference = evidenceValidThrough + 1n;
    const inflatedOuterExpiry = lateReference + 10n;
    const inflatedOuter = await buildRevoke(revoke, inflatedOuterExpiry);
    await expect(
      validateOperationCandidateOuter(inflatedOuter, authorityContext),
    ).rejects.toThrow("outer expiry must use its exact grant horizon");
    await expect(
      validateOperationCandidateOuter(
        inflatedOuter,
        operationValidationContextAt(authorityContext, lateReference),
      ),
    ).rejects.toThrow("beyond its retained-evidence horizon");

    const forged = {
      ...revoke,
      authoritySignature: bytes(0xff, 64),
    };
    await expect(
      validateOperation(await buildRevoke(forged), authorityContext),
    ).rejects.toThrow("authority signature does not verify");
  });
});

describe("pair-private AdmissionGrantV1 validation", () => {
  test("checks the carrying flight, live interval, lifetime, room, and pinned signature", async () => {
    const unsignedGrant = {
      version: 1 as const,
      roomContextId: authorityContext.roomContextId,
      stableEd25519PublicKey: stable.publicKey,
      generation: 12n,
      issuedAtLogicalWindow: 995n,
      notBeforeLogicalWindow: 996n,
      notAfterLogicalWindow: 1_010n,
    };
    const grant: AdmissionGrantV1 = {
      ...unsignedGrant,
      authoritySignature: await sign(
        await admissionGrantSignedMessage(unsignedGrant),
        authority.secretKey,
      ),
    };
    await expect(
      validateAdmissionGrantV1(grant, {
        roomContextId: authorityContext.roomContextId,
        roomPolicy: authorityPolicy,
        carriedAtLogicalWindow: 998n,
        referenceWindow: 1_000n,
      }),
    ).resolves.toBeUndefined();

    await expect(
      validateAdmissionGrantV1(grant, {
        roomContextId: authorityContext.roomContextId,
        roomPolicy: authorityPolicy,
        carriedAtLogicalWindow: 998n,
        referenceWindow: 1_011n,
      }),
    ).rejects.toThrow("not live");

    await expect(
      validateAdmissionGrantV1(grant, {
        roomContextId: authorityContext.roomContextId,
        roomPolicy: authorityPolicy,
        carriedAtLogicalWindow: Number.NaN as unknown as bigint,
        referenceWindow: Number.NaN as unknown as bigint,
      }),
    ).rejects.toThrow("issuance/carrying interval is invalid");

    await expect(
      validateAdmissionGrantV1(
        { ...grant, authoritySignature: bytes(0xff, 64) },
        {
          roomContextId: authorityContext.roomContextId,
          roomPolicy: authorityPolicy,
          carriedAtLogicalWindow: 998n,
          referenceWindow: 1_000n,
        },
      ),
    ).rejects.toThrow("authority signature does not verify");

    const mutableGrant = decodeAdmissionGrantV1(encodeAdmissionGrantV1(grant));
    const mutablePolicy = structuredClone(authorityPolicy);
    const mutableContext = {
      roomContextId: Uint8Array.from(authorityContext.roomContextId),
      roomPolicy: mutablePolicy,
      carriedAtLogicalWindow: 998n,
      referenceWindow: 1_000n,
    };
    const pending = validateAdmissionGrantV1(mutableGrant, mutableContext);
    mutableGrant.authoritySignature.fill(0);
    mutableGrant.roomContextId.fill(0);
    mutableContext.roomContextId.fill(0);
    if (mutablePolicy.admissionFloor.mode === "authority-grant")
      mutablePolicy.admissionFloor.authorityEd25519PublicKey.fill(0);
    await expect(pending).resolves.toBeUndefined();
  });
});
