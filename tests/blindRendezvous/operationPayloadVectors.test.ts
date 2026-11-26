import { describe, expect, test } from "bun:test";

import { encodeCanonical } from "../../src/blindRendezvous/canonicalSchema";
import {
  admissionGrantId,
  admissionRevokeSemanticSlot,
  admissionGrantSignedMessage,
  admissionRevokeSignedMessage,
  leaveSemanticSlot,
  presenceSemanticSlot,
  presenceOwnershipSignedMessage,
  presencePermitSignedMessage,
  presenceProofTranscriptHash,
  sha256,
  storeHintSemanticSlot,
} from "../../src/blindRendezvous/derivations";
import {
  decodeCoreRoomStateV1,
  encodeCoreRoomStateV1,
} from "../../src/blindRendezvous/coreReduce";
import {
  encodeAdmissionGrantV1,
  encodeAdmissionRevokeV1,
  encodeLeaveV1,
  encodePresenceV1,
  encodeStoreHintOperationV1,
} from "../../src/blindRendezvous/operationPayload";
import {
  coreRoomStateV1Schema,
  presenceCoreV1Schema,
  presencePermitV1Schema,
  presenceProofTranscriptV1Schema,
} from "../../src/blindRendezvous/schemas";
import { routeId, storeId } from "../../src/blindRendezvous/storeDescriptor";

import type { CoreRoomStateV1 } from "../../src/blindRendezvous/coreReduce";
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

/**
 * Immutable Phase-0 known-answer vectors.
 *
 * The expected constants were generated once with a standalone Python
 * standard-library reference encoder. It knew only the specified primitive
 * encodings (U8/U16BE/U32BE/U64BE, fixed/variable bytes, optional and sequence
 * framing), declaration order, ASCII domains, and SHA-256. It did not import
 * SDK schemas, codecs, derivations, or fixtures. Keeping the expected bytes
 * hardcoded makes this file an independent alarm for protocol-visible drift.
 */

const filled = (value: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(value);

const incrementing = (length: number): Uint8Array =>
  Uint8Array.from({ length }, (_value, index) => index & 0xff);

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(
    value.match(/../gu)?.map((octet) => Number.parseInt(octet, 16)) ?? [],
  );

const hex = (value: Uint8Array): string =>
  [...value].map((octet) => octet.toString(16).padStart(2, "0")).join("");

const ROOM_CONTEXT_ID = filled(0x11);
const POLICY_HASH = filled(0xaa);
const AUTHOR_EPOCH_KEY = filled(0xbb);
const STABLE_IDENTITY_COMMITMENT = filled(0x33);

const PRESENCE_PROOF_HASH =
  "f134200adf07bb821ea26a6a45233f70afeea226f17d7c5607eae043557e9ce1";

const presenceCore: PresenceCoreV1 = {
  version: 1,
  stableIdentityCommitment: STABLE_IDENTITY_COMMITMENT,
  rendezvousHybridKemPublicKey: incrementing(1216),
  receiverKeyValidThroughLogicalWindow: 0x2122232425262728n,
  presenceNonce: filled(0x66),
  validThroughLogicalWindow: 0x1112131415161718n,
};

const presenceProofTranscript = {
  roomContextId: ROOM_CONTEXT_ID,
  policyHash: POLICY_HASH,
  logicalWindow: 0x0102030405060708n,
  authorEpochEd25519Key: AUTHOR_EPOCH_KEY,
  core: presenceCore,
};

const unsignedPresencePermit = {
  version: 1 as const,
  roomContextId: ROOM_CONTEXT_ID,
  presenceProofTranscriptHash: fromHex(PRESENCE_PROOF_HASH),
  permitSerial: filled(0x77),
  generation: 0x3132333435363738n,
  issuedAtLogicalWindow: 0x0102030405060708n,
  notBeforeLogicalWindow: 0x0102030405060708n,
  notAfterLogicalWindow: 0x2122232425262728n,
};

const presencePermit: PresencePermitV1 = {
  ...unsignedPresencePermit,
  authoritySignature: filled(0x88, 64),
};

const presence: PresenceV1 = {
  core: presenceCore,
  stableOwnershipSignature: filled(0x99, 64),
  authorityPermit: presencePermit,
};

const unsignedAdmissionGrant = {
  version: 1 as const,
  roomContextId: ROOM_CONTEXT_ID,
  stableEd25519PublicKey: filled(0xcc),
  generation: 0x4142434445464748n,
  issuedAtLogicalWindow: 0x5152535455565758n,
  notBeforeLogicalWindow: 0x6162636465666768n,
  notAfterLogicalWindow: 0x7172737475767778n,
};

const admissionGrant: AdmissionGrantV1 = {
  ...unsignedAdmissionGrant,
  authoritySignature: filled(0xdd, 64),
};

const unsignedAdmissionRevoke = {
  version: 1 as const,
  roomContextId: ROOM_CONTEXT_ID,
  stableIdentityCommitment: STABLE_IDENTITY_COMMITMENT,
  minimumAcceptedGeneration: 0x8182838485868788n,
  effectiveLogicalWindow: 0x9192939495969798n,
  expiresAfterLogicalWindow: 0xa1a2a3a4a5a6a7a8n,
};

const admissionRevoke: AdmissionRevokeV1 = {
  ...unsignedAdmissionRevoke,
  authoritySignature: filled(0xee, 64),
};

const leave: LeaveV1 = {
  version: 1,
  presenceOperationId: filled(0xf1),
  effectiveLogicalWindow: 0xb1b2b3b4b5b6b7b8n,
};

const storeDescriptor: StoreDescriptorV1 = {
  version: 1,
  storeIdentityEd25519Key: filled(0xd1),
  allocationIssuerPublicKeyDer: Uint8Array.of(0x30, 0x03, 0x01, 0x02, 0x03),
  descriptorGeneration: 0x0102030405060708n,
  compatibilityHash: filled(0xd2),
  supportedDeliveryProfileHashes: [filled(0xd3)],
  checkpointChainStarts: [
    {
      deliveryProfileHash: filled(0xd3),
      chainStartIngressWindow: 0x1112131415161718n,
    },
  ],
  retentionWindows: 256,
  notBeforeUnixMs: 0x2122232425262728n,
  notAfterUnixMs: 0x3132333435363738n,
  descriptorSignature: filled(0xd4, 64),
};

const storeRoute: StoreRouteV1 = {
  version: 1,
  storeId: filled(0xe1),
  descriptorHash: filled(0xe2),
  routeFamily: 0x1234,
  opaqueLocator: new TextEncoder().encode("https://kat.example/r"),
  routePublicParameters: Uint8Array.of(0x01, 0x02, 0x03, 0x04),
  notBeforeUnixMs: 0x2122232425262728n,
  notAfterUnixMs: 0x3132333435363738n,
  routeSignature: filled(0xe3, 64),
};

const storeHint: StoreHintOperationV1 = {
  version: 1,
  descriptor: storeDescriptor,
  routes: [storeRoute],
  hintExpiresAfterLogicalWindow: 0x4142434445464748n,
};

const coreRoomState: CoreRoomStateV1 = {
  version: 1,
  referenceWindow: 0x0102030405060708n,
  roomCapacityState: "within-policy",
  activeOperationIds: [],
  observedPresences: [],
  effectiveLeaveOperationIds: [],
  storeCatalogFacts: [
    {
      storeId: filled(0xe1),
      descriptorGeneration: 0x0102030405060708n,
      descriptorHash: filled(0xe2),
      sourceOperationId: filled(0xf2),
      descriptor: storeDescriptor,
      routes: [storeRoute],
      hintValidThroughLogicalWindow: 0x4142434445464748n,
    },
  ],
  revocationFloors: [],
  activePairOuterOperationIds: [],
  faults: [],
  operationsDigest: filled(0xf3),
};

const faultedCoreRoomState: CoreRoomStateV1 = {
  version: 1,
  referenceWindow: 0x0102030405060708n,
  roomCapacityState: "within-policy",
  activeOperationIds: [],
  observedPresences: [],
  effectiveLeaveOperationIds: [],
  storeCatalogFacts: [],
  revocationFloors: [],
  activePairOuterOperationIds: [],
  faults: [
    {
      kind: "author-fork-or-overquota",
      authorEpochEd25519Key: filled(0x01),
      logicalWindow: 0x1112131415161718n,
      proofOperationIds: [filled(0x02), filled(0x03)],
    },
    {
      kind: "presence-or-leave-fork",
      semanticSlot: filled(0x04),
      proofOperationIds: [filled(0x05), filled(0x06)],
    },
    {
      kind: "store-generation-fork",
      storeId: filled(0x07),
      descriptorGeneration: 0x2122232425262728n,
      descriptorHashes: [filled(0x08), filled(0x09)],
    },
  ],
  operationsDigest: filled(0x0a),
};

describe("blind-rendezvous Phase-0 operation-payload known-answer vectors", () => {
  test("PresenceProofTranscript, proof hash, and ownership message", async () => {
    const coreBytes = encodeCanonical(presenceCoreV1Schema, presenceCore);
    expect(coreBytes).toHaveLength(1297);
    expect(hex(await sha256(coreBytes))).toBe(
      "8fef116e5a40cb5565c071cb3af3602a761242cc4a8d11dc35f02a8cf40943a9",
    );

    const transcriptBytes = encodeCanonical(
      presenceProofTranscriptV1Schema,
      presenceProofTranscript,
    );
    expect(transcriptBytes).toHaveLength(1401);
    expect(hex(await sha256(transcriptBytes))).toBe(
      "b9bef33415a9fc166a39d74cbf119df72c1671f57ba81703f47c20ba800b8400",
    );
    expect(
      hex(await presenceProofTranscriptHash(presenceProofTranscript)),
    ).toBe(PRESENCE_PROOF_HASH);
    expect(
      hex(
        presenceOwnershipSignedMessage(
          await presenceProofTranscriptHash(presenceProofTranscript),
        ),
      ),
    ).toBe(
      "703270617274792f70726573656e63652d6f776e6572736869702d7369676e61747572652f7631f134200adf07bb821ea26a6a45233f70afeea226f17d7c5607eae043557e9ce1",
    );
  });

  test("PresencePermit and its authority-signed message", async () => {
    expect(hex(encodeCanonical(presencePermitV1Schema, presencePermit))).toBe(
      "011111111111111111111111111111111111111111111111111111111111111111f134200adf07bb821ea26a6a45233f70afeea226f17d7c5607eae043557e9ce17777777777777777777777777777777777777777777777777777777777777777313233343536373801020304050607080102030405060708212223242526272888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888",
    );
    expect(hex(await presencePermitSignedMessage(unsignedPresencePermit))).toBe(
      "703270617274792f70726573656e63652d7065726d69742d7369676e61747572652f76313b7bfd3fb9d5ffe75960ddfa6d94e10f7a079aa78987d2797fd5f320d883ede7",
    );
  });

  test("Presence operation payload", async () => {
    const encoded = encodePresenceV1(presence);
    expect(encoded).toHaveLength(1555);
    expect(hex(await sha256(encoded))).toBe(
      "8c165ba7200f1f836e75d843ea6d07b731179a3eabb8c52cc5e4643ad7aa6412",
    );
  });

  test("AdmissionGrant, GrantId, and authority-signed message", async () => {
    expect(hex(encodeAdmissionGrantV1(admissionGrant))).toBe(
      "011111111111111111111111111111111111111111111111111111111111111111cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc4142434445464748515253545556575861626364656667687172737475767778dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    expect(hex(await admissionGrantId(admissionGrant))).toBe(
      "bd09bd3af40f23403b1977cc1ca69ac34e7221efc2d6097592e220564992d112",
    );
    expect(hex(await admissionGrantSignedMessage(unsignedAdmissionGrant))).toBe(
      "703270617274792f61646d697373696f6e2d6772616e742d7369676e61747572652f7631554accc5912144150592acf85b55f4917fb5d5c7cea2278b0e001e9175c0a218",
    );
  });

  test("AdmissionRevoke and its authority-signed message", async () => {
    expect(hex(encodeAdmissionRevokeV1(admissionRevoke))).toBe(
      "011111111111111111111111111111111111111111111111111111111111111111333333333333333333333333333333333333333333333333333333333333333381828384858687889192939495969798a1a2a3a4a5a6a7a8eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    );
    expect(
      hex(await admissionRevokeSignedMessage(unsignedAdmissionRevoke)),
    ).toBe(
      "703270617274792f61646d697373696f6e2d7265766f6b652d7369676e61747572652f763115235caf1ae7f03d6c9916a782daf9c52ba487d006ff5137e829900db8e90870",
    );
  });

  test("Leave operation payload", () => {
    expect(hex(encodeLeaveV1(leave))).toBe(
      "01f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1b1b2b3b4b5b6b7b8",
    );
  });

  test("StoreHint operation payload", async () => {
    const encoded = encodeStoreHintOperationV1(storeHint);
    expect(encoded).toHaveLength(433);
    expect(hex(await sha256(encoded))).toBe(
      "5e73a9b1d55b169b38b501eb0dd48c96dc9bfd886ff780725393d2e2c72bca5b",
    );
    expect(hex(encoded)).toBe(
      "0101d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d10000000530030102030102030405060708d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d20001d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d30001d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d311121314151617180000010021222324252627283132333435363738d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4000101e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e212340000001568747470733a2f2f6b61742e6578616d706c652f72000000040102030421222324252627283132333435363738e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e34142434445464748",
    );
  });

  test("all four non-pair semantic slots", async () => {
    expect(
      hex(
        await presenceSemanticSlot(
          AUTHOR_EPOCH_KEY,
          presenceProofTranscript.logicalWindow,
          presenceCore.presenceNonce,
        ),
      ),
    ).toBe("dd3cd1148bcd4cb57da4713a0766d02238d74587bdf6ffb72dbcb880e250df1b");
    expect(
      hex(
        await leaveSemanticSlot(
          leave.presenceOperationId,
          leave.effectiveLogicalWindow,
        ),
      ),
    ).toBe("3ab47dc90033c211118c4d72cefe6d2676cde1f2e34180ef85b3ba6e824e6c4f");
    expect(
      hex(
        await storeHintSemanticSlot(
          await storeId(storeDescriptor.storeIdentityEd25519Key),
          storeDescriptor.descriptorGeneration,
        ),
      ),
    ).toBe("737b061a818979e6b7d3622451d91ca5bfc41f9943c1da424485ac7b6cc214ed");
    expect(
      hex(
        await admissionRevokeSemanticSlot(
          admissionRevoke.stableIdentityCommitment,
          admissionRevoke.minimumAcceptedGeneration,
          admissionRevoke.effectiveLogicalWindow,
          admissionRevoke.expiresAfterLogicalWindow,
        ),
      ),
    ).toBe("d4d56e970ed39d0ec1d3f20fbb5b9fd84d1941522c828c80d49ea301d6884084");
  });

  test("nonempty CoreRoomState and RouteId ordering", async () => {
    const encoded = await encodeCoreRoomStateV1(coreRoomState);
    expect(encoded).toHaveLength(592);
    expect(hex(await sha256(encoded))).toBe(
      "3d14bccd39d8439f6a79fb5f713a243bf35a2ddc1343024dccece431d8b0cb02",
    );
    expect(hex(await routeId(storeRoute))).toBe(
      "0532dcd473db53227e1f13b039972be942eec383df89910d1cf664cef2d7dfa8",
    );
    expect(
      await encodeCoreRoomStateV1(await decodeCoreRoomStateV1(encoded)),
    ).toEqual(encoded);
  });

  test("CoreRoomState encodes every fault variant in canonical order", async () => {
    const encoded = await encodeCoreRoomStateV1(faultedCoreRoomState);
    expect(encoded).toHaveLength(372);
    expect(hex(await sha256(encoded))).toBe(
      "828acc888c8214e5d4ad042e1288b6d44e7a50e04e67f8e138697f9289266849",
    );
    expect(
      await encodeCoreRoomStateV1(await decodeCoreRoomStateV1(encoded)),
    ).toEqual(encoded);
  });

  test("CoreRoomState rejects duplicate and RouteId-unsorted routes", async () => {
    const duplicateRoute: StoreRouteV1 = {
      ...storeRoute,
      routeSignature: filled(0xe4, 64),
    };
    const duplicateState: CoreRoomStateV1 = {
      ...coreRoomState,
      storeCatalogFacts: [
        {
          ...coreRoomState.storeCatalogFacts[0],
          routes: [storeRoute, duplicateRoute],
        },
      ],
    };
    await expect(encodeCoreRoomStateV1(duplicateState)).rejects.toThrow(
      "duplicate-free by RouteId",
    );

    const otherRoute: StoreRouteV1 = {
      ...storeRoute,
      opaqueLocator: new TextEncoder().encode("https://kat.example/s"),
      routeSignature: filled(0xe4, 64),
    };
    const routeIds = await Promise.all([
      routeId(storeRoute),
      routeId(otherRoute),
    ]);
    const descendingRoutes =
      hex(routeIds[0]) > hex(routeIds[1])
        ? [storeRoute, otherRoute]
        : [otherRoute, storeRoute];
    const unsortedState: CoreRoomStateV1 = {
      ...coreRoomState,
      storeCatalogFacts: [
        {
          ...coreRoomState.storeCatalogFacts[0],
          routes: descendingRoutes,
        },
      ],
    };
    await expect(encodeCoreRoomStateV1(unsortedState)).rejects.toThrow(
      "sorted by RouteId",
    );
    const rawUnsorted = encodeCanonical(coreRoomStateV1Schema, unsortedState);
    await expect(decodeCoreRoomStateV1(rawUnsorted)).rejects.toThrow(
      "sorted by RouteId",
    );
  });

  test("CoreRoomState closes version and fault-proof cardinalities", async () => {
    const wrongVersion = {
      ...coreRoomState,
      version: 2,
    } as unknown as CoreRoomStateV1;
    await expect(encodeCoreRoomStateV1(wrongVersion)).rejects.toThrow(
      "unsupported CoreRoomStateV1 version",
    );

    const emptyAuthorProof: CoreRoomStateV1 = {
      ...coreRoomState,
      faults: [
        {
          kind: "author-fork-or-overquota",
          authorEpochEd25519Key: filled(0x01),
          logicalWindow: 1n,
          proofOperationIds: [],
        },
      ],
    };
    await expect(encodeCoreRoomStateV1(emptyAuthorProof)).rejects.toThrow(
      "at least one proof operation",
    );

    const shortSemanticProof: CoreRoomStateV1 = {
      ...coreRoomState,
      faults: [
        {
          kind: "presence-or-leave-fork",
          semanticSlot: filled(0x02),
          proofOperationIds: [filled(0x03)],
        },
      ],
    };
    const rawShortSemanticProof = encodeCanonical(
      coreRoomStateV1Schema,
      shortSemanticProof,
    );
    await expect(decodeCoreRoomStateV1(rawShortSemanticProof)).rejects.toThrow(
      "exactly two proof operations",
    );

    const shortStoreProof: CoreRoomStateV1 = {
      ...coreRoomState,
      faults: [
        {
          kind: "store-generation-fork",
          storeId: filled(0x04),
          descriptorGeneration: 1n,
          descriptorHashes: [filled(0x05)] as unknown as readonly [
            Uint8Array,
            Uint8Array,
          ],
        },
      ],
    };
    await expect(encodeCoreRoomStateV1(shortStoreProof)).rejects.toThrow(
      "exactly two descriptor hashes",
    );
  });
});
