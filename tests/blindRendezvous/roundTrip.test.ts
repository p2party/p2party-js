import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import libcrypto from "../../src/cryptography/libcrypto";
import { newKeyPair } from "../../src/cryptography/ed25519";
import {
  buildCarrierPlaintext,
  createCarrierAeadProvider,
  decodeCarrierEnvelope,
  deriveCarrierObjectId,
  encodeCarrierEnvelope,
  openCarrierEnvelope,
  sealCarrierEnvelope,
} from "../../src/blindRendezvous/carrierEnvelope";
import {
  coreReduceOuter,
  mergeOperationSets,
} from "../../src/blindRendezvous/coreReduce";
import {
  deliveryProfileHash,
  policyHash,
  roomContextConfirmation,
  roomContextId,
  roomRoot,
} from "../../src/blindRendezvous/derivations";
import {
  decodeOperation,
  deriveOperationId,
  encodeOperation,
  operationPaddingFor,
  signOperation,
  validateOperation,
} from "../../src/blindRendezvous/operation";
import {
  encodeBlindRoomInviteV2Default,
  parseRoomInvite,
  resolveInviteRoomPolicy,
} from "../../src/blindRendezvous/roomInviteV2";

import type { BlindRoomInviteV2 } from "../../src/blindRendezvous/roomInviteV2";
import type { IdentifiedOperationV1 } from "../../src/blindRendezvous/coreReduce";
import type { LibCrypto } from "../../src/cryptography/libcrypto";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fileBytes = readFileSync(
  new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
new Uint8Array(wasmBinary).set(fileBytes);

const PAGES = 1024;
const cryptoModule = (await libcrypto({
  wasmBinary,
  wasmMemory: new WebAssembly.Memory({ initial: PAGES, maximum: PAGES }),
})) as unknown as LibCrypto;

const provider = createCarrierAeadProvider(cryptoModule);

/**
 * The delivery profile only has to be a valid, hashable public geometry for
 * this test; the release registry freezes the real default separately.
 */
const testProfile = {
  version: 1,
  carrierEnvelopeCodec: 1,
  publicStoreProtocol: 1,
  carrierAeadSuite: 1,
  admissionScheme: 1,
  deliveryWindowMs: 60_000n,
  carrierRetentionWindows: 1440,
  maxFutureIngressWindows: 2,
  roomSlotsPerClient: 4,
  cohortAllocationsPerWindow: 1024,
  publicChunkObjectCount: 64,
  maxScheduleSkewMs: 2_000n,
  tokenIssueOffsetMs: 1_000n,
  tokenIssueResponseBudgetMs: 2_000n,
  allocationRequestOffsetMs: 5_000n,
  allocationResponseBudgetMs: 2_000n,
  chunkFinalizationOffsetMs: 50_000n,
  publicReadLagWindows: 1,
  publicReadOffsetMs: 10_000n,
  maxConsecutiveMissedAppendOpportunities: 3,
  sizeClasses: [
    {
      id: 0,
      fixedCarrierObjectBytes: 8192,
      operationPayloadClass: 0,
      appendSchedule: [{ offsetMs: 20_000n, role: "safety-control" as const }],
      publicChunksPerWindow: 8,
    },
  ],
  minMeasuredSharedCohort: 2,
  maxAssuranceEvidenceAgeMs: 3_600_000n,
};

const REFERENCE_WINDOW = 5_000n;
const INGRESS_WINDOW = 900n;

describe("a room operation survives the full carrier round trip", () => {
  test("invite to sealed object to reduced state, with real AEAD", async () => {
    // 1. One capability, one link — the same user action as today.
    const capability = new Uint8Array(32).fill(0x42);
    const fragment = encodeBlindRoomInviteV2Default(capability);
    const invite = parseRoomInvite(`#${fragment}`) as BlindRoomInviteV2;
    const roomPolicy = resolveInviteRoomPolicy(invite);

    // 2. Room identity is derived locally; none of it crosses a carrier.
    const policyDigest = await policyHash(roomPolicy);
    const contextId = await roomContextId(invite.capability, policyDigest);
    const root = await roomRoot(invite.capability, policyDigest);
    const confirmation = await roomContextConfirmation(contextId);
    const profileDigest = await deliveryProfileHash(testProfile);

    // 3. Author and sign one canonical operation.
    const author = await newKeyPair();
    const payload = Uint8Array.from({ length: 100 }, (_, index) => index);
    const operation = await signOperation(
      {
        version: 1,
        roomContextConfirmation: confirmation,
        logicalWindow: REFERENCE_WINDOW,
        expiresAfterWindow: REFERENCE_WINDOW + 10n,
        lifetime: "WINDOW_TRANSIENT",
        authorEpochEd25519Key: author.publicKey,
        authorSequence: 0n,
        previousAuthorOperationId: null,
        kind: "PRESENCE",
        semanticSlot: new Uint8Array(32).fill(0x5a),
        dependencies: [],
        operationPayloadClass: 0,
        fixedPayload: payload,
        operationPadding: operationPaddingFor(0, payload.length),
      },
      author.secretKey,
    );

    // 4. Seal it for one carrier context and publish the exact bytes.
    const coordinates = {
      deliveryProfileHash: profileDigest,
      carrierContextId: new Uint8Array(32).fill(0x0c),
      ingressWindow: INGRESS_WINDOW,
      sizeClass: 0,
    };
    const nonce = new Uint8Array(24).fill(0x77);
    const envelope = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      buildCarrierPlaintext(
        encodeOperation(operation),
        testProfile.sizeClasses[0].fixedCarrierObjectBytes,
      ),
      provider,
    );
    const published = encodeCarrierEnvelope(envelope);

    // The published object carries no room-derived value a store could join on.
    const publishedHex = hex(published);
    expect(publishedHex).not.toContain(hex(invite.capability));
    expect(publishedHex).not.toContain(hex(contextId));
    expect(publishedHex).not.toContain(hex(confirmation));
    expect(publishedHex).not.toContain(hex(author.publicKey));
    expect(published.length).toBe(
      encodeCarrierEnvelope(
        await sealCarrierEnvelope(
          root,
          coordinates,
          nonce,
          buildCarrierPlaintext(
            new Uint8Array(8),
            testProfile.sizeClasses[0].fixedCarrierObjectBytes,
          ),
          provider,
        ),
      ).length,
    );

    // 5. A receiving member decodes, opens, validates, and reduces.
    const received = decodeCarrierEnvelope(published);
    const opened = await openCarrierEnvelope(root, received, provider);
    expect(opened).not.toBeNull();

    const recovered = decodeOperation(opened!.operationBytes);
    expect(hex(encodeOperation(recovered))).toBe(
      hex(encodeOperation(operation)),
    );

    await validateOperation(recovered, {
      roomContextConfirmation: confirmation,
      roomPolicy,
      referenceWindow: REFERENCE_WINDOW,
    });

    const identified: IdentifiedOperationV1 = {
      operationId: await deriveOperationId(recovered),
      operation: recovered,
    };
    const state = await coreReduceOuter(
      [identified],
      roomPolicy,
      REFERENCE_WINDOW,
    );
    expect(state.activeOperationIds.map(hex)).toEqual([
      hex(identified.operationId),
    ]);
  });

  test("a second room in the same cohort neither opens nor merges", async () => {
    const ours = new Uint8Array(32).fill(0x42);
    const theirs = new Uint8Array(32).fill(0x43);

    const roomPolicy = resolveInviteRoomPolicy(
      parseRoomInvite(
        encodeBlindRoomInviteV2Default(ours),
      ) as BlindRoomInviteV2,
    );
    const policyDigest = await policyHash(roomPolicy);
    const ourRoot = await roomRoot(ours, policyDigest);
    const theirRoot = await roomRoot(theirs, policyDigest);
    const theirConfirmation = await roomContextConfirmation(
      await roomContextId(theirs, policyDigest),
    );

    const author = await newKeyPair();
    const payload = Uint8Array.of(1, 2, 3);
    const theirOperation = await signOperation(
      {
        version: 1,
        roomContextConfirmation: theirConfirmation,
        logicalWindow: REFERENCE_WINDOW,
        expiresAfterWindow: REFERENCE_WINDOW + 10n,
        lifetime: "WINDOW_TRANSIENT",
        authorEpochEd25519Key: author.publicKey,
        authorSequence: 0n,
        previousAuthorOperationId: null,
        kind: "PRESENCE",
        semanticSlot: new Uint8Array(32).fill(0x5b),
        dependencies: [],
        operationPayloadClass: 0,
        fixedPayload: payload,
        operationPadding: operationPaddingFor(0, payload.length),
      },
      author.secretKey,
    );

    const coordinates = {
      deliveryProfileHash: await deliveryProfileHash(testProfile),
      carrierContextId: new Uint8Array(32).fill(0x0c),
      ingressWindow: INGRESS_WINDOW,
      sizeClass: 0,
    };
    const theirEnvelope = await sealCarrierEnvelope(
      theirRoot,
      coordinates,
      new Uint8Array(24).fill(0x78),
      buildCarrierPlaintext(
        encodeOperation(theirOperation),
        testProfile.sizeClasses[0].fixedCarrierObjectBytes,
      ),
      provider,
    );

    // The other room's object is cover, not a member: it simply does not open.
    expect(
      await openCarrierEnvelope(ourRoot, theirEnvelope, provider),
    ).toBeNull();
  });

  test("independently wrapped copies stay carrier-separated", async () => {
    const capability = new Uint8Array(32).fill(0x42);
    const roomPolicy = resolveInviteRoomPolicy(
      parseRoomInvite(
        encodeBlindRoomInviteV2Default(capability),
      ) as BlindRoomInviteV2,
    );
    const policyDigest = await policyHash(roomPolicy);
    const root = await roomRoot(capability, policyDigest);
    const confirmation = await roomContextConfirmation(
      await roomContextId(capability, policyDigest),
    );
    const profileDigest = await deliveryProfileHash(testProfile);

    const author = await newKeyPair();
    const payload = Uint8Array.of(9, 9, 9);
    const operation = await signOperation(
      {
        version: 1,
        roomContextConfirmation: confirmation,
        logicalWindow: REFERENCE_WINDOW,
        expiresAfterWindow: REFERENCE_WINDOW + 10n,
        lifetime: "WINDOW_TRANSIENT",
        authorEpochEd25519Key: author.publicKey,
        authorSequence: 0n,
        previousAuthorOperationId: null,
        kind: "PRESENCE",
        semanticSlot: new Uint8Array(32).fill(0x5c),
        dependencies: [],
        operationPayloadClass: 0,
        fixedPayload: payload,
        operationPadding: operationPaddingFor(0, payload.length),
      },
      author.secretKey,
    );
    const operationBytes = encodeOperation(operation);
    const plaintext = buildCarrierPlaintext(
      operationBytes,
      testProfile.sizeClasses[0].fixedCarrierObjectBytes,
    );

    const first = await sealCarrierEnvelope(
      root,
      {
        deliveryProfileHash: profileDigest,
        carrierContextId: new Uint8Array(32).fill(0x01),
        ingressWindow: INGRESS_WINDOW,
        sizeClass: 0,
      },
      new Uint8Array(24).fill(0x11),
      plaintext,
      provider,
    );
    const second = await sealCarrierEnvelope(
      root,
      {
        deliveryProfileHash: profileDigest,
        carrierContextId: new Uint8Array(32).fill(0x02),
        ingressWindow: INGRESS_WINDOW,
        sizeClass: 0,
      },
      new Uint8Array(24).fill(0x22),
      plaintext,
      provider,
    );

    // Two stores must not be able to join on the bytes or the object id.
    expect(hex(first.ciphertextAndTag)).not.toBe(hex(second.ciphertextAndTag));
    expect(hex(await deriveCarrierObjectId(first))).not.toBe(
      hex(await deriveCarrierObjectId(second)),
    );

    // The client deduplicates them by the private OperationId after opening.
    const openedFirst = await openCarrierEnvelope(root, first, provider);
    const openedSecond = await openCarrierEnvelope(root, second, provider);
    const identify = async (
      bytes: Uint8Array,
    ): Promise<IdentifiedOperationV1> => {
      const decoded = decodeOperation(bytes);
      return {
        operationId: await deriveOperationId(decoded),
        operation: decoded,
      };
    };
    const merged = mergeOperationSets(
      [await identify(openedFirst!.operationBytes)],
      [await identify(openedSecond!.operationBytes)],
    );
    expect(merged.length).toBe(1);
  });
});
