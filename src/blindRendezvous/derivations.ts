/**
 * Domain-separated derivations for blind rendezvous.
 *
 * Section 3.3 fixes the conventions used throughout: `H(x)` is SHA-256, `||`
 * is byte concatenation, a quoted domain string is its exact ASCII octets with
 * no terminator, and `U16BE`/`U32BE`/`U64BE`/`Byte` are exact big-endian
 * encodings that reject out-of-range input before a preimage is formed.
 *
 * Every formula below is transcribed from the specification and carries its
 * source label. A caller must not build one of these preimages by hand: the
 * domain string, argument order, and canonical encoding are protocol-visible.
 *
 * Status: PROPOSED, NOT FROZEN. The formulas are fixed by the specification,
 * but any value derived over a `Canonical(...)` argument inherits the
 * unfrozen status of `canonicalSchema.ts`, so no output here is a published
 * v0.4 release artifact yet.
 */

import { encodeCanonical } from "./canonicalSchema";
import {
  admissionGrantUnsignedV1Schema,
  admissionGrantV1Schema,
  admissionRevokeUnsignedV1Schema,
  authenticatedRoomOperationUnsignedV1Schema,
  authenticatedRoomOperationV1Schema,
  carrierEnvelopeV1Schema,
  claimEvaluationDatasetV1Schema,
  claimEvaluationV1Schema,
  claimRegistryV1Schema,
  claimWordingCatalogV1Schema,
  deliveryProfileV1Schema,
  executableRendezvousKernelManifestV1Schema,
  formalObligationRegistryV1Schema,
  formalProofResultV1Schema,
  kernelModuleSemanticsSchema,
  kernelSourceTreeSchema,
  operationIdSetSchema,
  presencePermitUnsignedV1Schema,
  presenceProofTranscriptV1Schema,
  resolvedAssumptionSetSchema,
  roomPolicyV4Schema,
} from "./schemas";

import type { TypeDescriptor } from "./canonicalSchema";

const textEncoder = new TextEncoder();

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export class DerivationError extends Error {
  override readonly name = "DerivationError";

  constructor(message: string) {
    super(`blindRendezvous derivation: ${message}`);
  }
}

// Annotated so TypeScript narrows control flow after a throwing call.
const fail: (message: string) => never = (message) => {
  throw new DerivationError(message);
};

/* ------------------------------------------------------------------ *
 * Primitive encodings (Section 3.3)
 * ------------------------------------------------------------------ */

/** Exact ASCII octets of a domain-separation string; no terminator. */
export const domain = (value: string): Uint8Array => {
  for (let index = 0; index < value.length; index++) {
    if (value.charCodeAt(index) > 0x7f)
      fail(`domain string "${value}" is not ASCII`);
  }
  return textEncoder.encode(value);
};

export const byteOf = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff)
    fail("Byte(x) input is out of range");
  return Uint8Array.of(value);
};

export const u16be = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff)
    fail("U16BE(x) input is out of range");
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
};

export const u32be = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff)
    fail("U32BE(x) input is out of range");
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
};

export const u64be = (value: bigint): Uint8Array => {
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn)
    fail("U64BE(x) input is out of range");
  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
};

export const concatBytes = (
  ...parts: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> => {
  let total = 0;
  for (const part of parts) {
    if (!(part instanceof Uint8Array))
      fail("concatenation input must be a Uint8Array");
    total += part.length;
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

/** RFC 4648 URL-safe base64 with no padding. No lowercase variant exists. */
export const base64urlNoPad = (bytes: Uint8Array): string => {
  let output = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const remaining = bytes.length - offset;
    const chunk =
      (bytes[offset] << 16) |
      ((remaining > 1 ? bytes[offset + 1] : 0) << 8) |
      (remaining > 2 ? bytes[offset + 2] : 0);
    output += BASE64URL_ALPHABET[(chunk >>> 18) & 0x3f];
    output += BASE64URL_ALPHABET[(chunk >>> 12) & 0x3f];
    if (remaining > 1) output += BASE64URL_ALPHABET[(chunk >>> 6) & 0x3f];
    if (remaining > 2) output += BASE64URL_ALPHABET[chunk & 0x3f];
  }
  return output;
};

export const base64urlNoPadDecode = (encoded: string): Uint8Array => {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]*$/u.test(encoded))
    fail("value is not unpadded base64url");
  if (encoded.length % 4 === 1) fail("value is not unpadded base64url");

  const output = new Uint8Array(Math.floor((encoded.length * 6) / 8));
  let accumulator = 0;
  let availableBits = 0;
  let offset = 0;
  for (const character of encoded) {
    accumulator = (accumulator << 6) | BASE64URL_ALPHABET.indexOf(character);
    availableBits += 6;
    if (availableBits >= 8) {
      availableBits -= 8;
      output[offset] = (accumulator >>> availableBits) & 0xff;
      offset += 1;
      accumulator &= (1 << availableBits) - 1;
    }
  }
  // Reject alternate encodings: leftover bits of a canonical value are zero.
  if (accumulator !== 0) fail("base64url encoding is not canonical");
  return output;
};

/* ------------------------------------------------------------------ *
 * Hash and key-derivation primitives
 * ------------------------------------------------------------------ */

/** `H(x) = SHA-256(x)` (Section 3.3). */
export const sha256 = async (input: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      input as unknown as ArrayBufferView<ArrayBuffer>,
    ),
  );

const hmacSha256 = async (
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> => {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    // An empty HMAC key is legal in RFC 2104 but not accepted by WebCrypto;
    // HKDF-Extract with an empty salt uses a zero-filled block instead.
    (key.length === 0
      ? new Uint8Array(32)
      : key) as unknown as ArrayBufferView<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await globalThis.crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      message as unknown as ArrayBufferView<ArrayBuffer>,
    ),
  );
};

/**
 * RFC 5869 HKDF-Extract with SHA-256, which is exactly
 * `HMAC-SHA-256(key = salt, msg = ikm)`. The HMAC itself comes from WebCrypto;
 * this composes the standard construction and does not implement a primitive.
 */
export const hkdfSha256Extract = async (
  salt: Uint8Array,
  ikm: Uint8Array,
): Promise<Uint8Array> => hmacSha256(salt, ikm);

/** RFC 5869 §2.3 HKDF-Expand with SHA-256. */
export const hkdfSha256Expand = async (
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> => {
  if (!Number.isSafeInteger(length) || length <= 0 || length > 255 * 32)
    fail("HKDF-Expand output length is out of range");
  const output = new Uint8Array(length);
  let previousBlock: Uint8Array = new Uint8Array(0);
  let offset = 0;
  for (let counter = 1; offset < length; counter++) {
    previousBlock = await hmacSha256(
      prk,
      concatBytes(previousBlock, info, byteOf(counter)),
    );
    const take = Math.min(previousBlock.length, length - offset);
    output.set(previousBlock.subarray(0, take), offset);
    offset += take;
  }
  return output;
};

const hashWithDomain = async (
  domainString: string,
  ...parts: readonly Uint8Array[]
): Promise<Uint8Array> => sha256(concatBytes(domain(domainString), ...parts));

const canonical = (descriptor: TypeDescriptor, value: unknown): Uint8Array =>
  encodeCanonical(descriptor, value);

const requireBytes = (
  name: string,
  value: Uint8Array,
  length: number,
): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== length)
    fail(`${name} must be exactly ${String(length)} bytes`);
  return value;
};

/* ------------------------------------------------------------------ *
 * Section 4.1 — room identity
 * ------------------------------------------------------------------ */

/** `PolicyHash = H("p2party/room-policy/v4" || Canonical(RoomPolicyV4))` */
export const policyHash = async (roomPolicy: unknown): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/room-policy/v4",
    canonical(roomPolicyV4Schema, roomPolicy),
  );

/**
 * `RoomRoot = HKDF-Extract(salt = PolicyHash, ikm = capability)`
 *
 * The result is a local secret and never crosses a carrier.
 */
export const roomRoot = async (
  capability: Uint8Array,
  policyHashBytes: Uint8Array,
): Promise<Uint8Array> =>
  hkdfSha256Extract(
    requireBytes("PolicyHash", policyHashBytes, 32),
    requireBytes("capability", capability, 32),
  );

/** `RoomContextId = H("p2party/room-context/v4" || capability || PolicyHash)` */
export const roomContextId = async (
  capability: Uint8Array,
  policyHashBytes: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/room-context/v4",
    requireBytes("capability", capability, 32),
    requireBytes("PolicyHash", policyHashBytes, 32),
  );

/**
 * `DeliveryProfileHash =
 *    H("p2party/delivery-profile/v1" || Canonical(DeliveryProfileV1))`
 */
export const deliveryProfileHash = async (
  profile: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/delivery-profile/v1",
    canonical(deliveryProfileV1Schema, profile),
  );

/**
 * `LocalRoomId = Base64urlNoPad(H("p2party/local-room-id/v1" || RoomContextId))`
 *
 * This replaces the legacy server-assigned room UUID in local state and never
 * crosses a carrier.
 */
export const localRoomId = async (
  roomContextIdBytes: Uint8Array,
): Promise<string> =>
  base64urlNoPad(
    await hashWithDomain(
      "p2party/local-room-id/v1",
      requireBytes("RoomContextId", roomContextIdBytes, 32),
    ),
  );

/**
 * `StableIdentityCommitment =
 *    H("p2party/stable-identity-commitment/v1" ||
 *      RoomContextId || stableEd25519PublicKey)`
 *
 * This is a room-scoped pseudonym, not key hiding: a capability holder that
 * already knows a candidate public key can test it. The raw stable key never
 * needs to enter a room-wide presence payload.
 */
export const stableIdentityCommitment = async (
  roomContextIdBytes: Uint8Array,
  stableEd25519PublicKey: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/stable-identity-commitment/v1",
    requireBytes("RoomContextId", roomContextIdBytes, 32),
    requireBytes("stableEd25519PublicKey", stableEd25519PublicKey, 32),
  );

/**
 * `LocalPeerIdDigest =
 *    H("p2party/local-peer-id/v1" ||
 *      RoomContextId || StableIdentityCommitment)`
 */
export const localPeerIdDigest = async (
  roomContextIdBytes: Uint8Array,
  stableIdentityCommitmentBytes: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/local-peer-id/v1",
    requireBytes("RoomContextId", roomContextIdBytes, 32),
    requireBytes("StableIdentityCommitment", stableIdentityCommitmentBytes, 32),
  );

/** `"peer.v1." || Base64urlNoPad(LocalPeerIdDigest)` */
export const localPeerId = async (
  roomContextIdBytes: Uint8Array,
  stableIdentityCommitmentBytes: Uint8Array,
): Promise<string> =>
  `peer.v1.${base64urlNoPad(
    await localPeerIdDigest(roomContextIdBytes, stableIdentityCommitmentBytes),
  )}`;

/* ------------------------------------------------------------------ *
 * Section 4.4 — operation identity and semantic slots
 * ------------------------------------------------------------------ */

/**
 * `RoomContextConfirmation = H("p2party/room-confirmation/v1" || RoomContextId)`
 */
export const roomContextConfirmation = async (
  roomContextIdBytes: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/room-confirmation/v1",
    requireBytes("RoomContextId", roomContextIdBytes, 32),
  );

/**
 * `OperationId =
 *    H("p2party/room-operation/v1" || Canonical(AuthenticatedRoomOperationV1))`
 *
 * Derived only after carrier AEAD and operation validation; it is never sent
 * to a store as a logical identifier.
 */
export const operationId = async (operation: unknown): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/room-operation/v1",
    canonical(authenticatedRoomOperationV1Schema, operation),
  );

/**
 * The operation signature transcript:
 * `"p2party/room-operation-signature/v1" || Canonical(every preceding field)`.
 * The length-disjoint domain prefix is part of the signed bytes.
 */
export const operationSignatureMessage = (
  unsignedOperation: unknown,
): Uint8Array =>
  concatBytes(
    domain("p2party/room-operation-signature/v1"),
    canonical(authenticatedRoomOperationUnsignedV1Schema, unsignedOperation),
  );

/**
 * `PresenceSemanticSlot = H("p2party/presence-slot/v1" ||
 *    authorEpochEd25519Key || U64BE(logicalWindow) || presenceNonce)`
 */
export const presenceSemanticSlot = async (
  authorEpochEd25519Key: Uint8Array,
  logicalWindow: bigint,
  presenceNonce: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/presence-slot/v1",
    requireBytes("authorEpochEd25519Key", authorEpochEd25519Key, 32),
    u64be(logicalWindow),
    requireBytes("presenceNonce", presenceNonce, 32),
  );

/**
 * `LeaveSemanticSlot = H("p2party/leave-slot/v1" ||
 *    presenceOperationId || U64BE(effectiveLogicalWindow))`
 */
export const leaveSemanticSlot = async (
  presenceOperationId: Uint8Array,
  effectiveLogicalWindow: bigint,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/leave-slot/v1",
    requireBytes("presenceOperationId", presenceOperationId, 32),
    u64be(effectiveLogicalWindow),
  );

/**
 * `StoreHintSemanticSlot = H("p2party/store-hint-slot/v1" ||
 *    StoreId(descriptor) || U64BE(descriptorGeneration))`
 */
export const storeHintSemanticSlot = async (
  storeId: Uint8Array,
  descriptorGeneration: bigint,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/store-hint-slot/v1",
    requireBytes("StoreId", storeId, 32),
    u64be(descriptorGeneration),
  );

/**
 * `AdmissionRevokeSemanticSlot = H("p2party/admission-revoke-slot/v1" ||
 *    stableIdentityCommitment || U64BE(minimumAcceptedGeneration) ||
 *    U64BE(effectiveLogicalWindow) || U64BE(expiresAfterLogicalWindow))`
 */
export const admissionRevokeSemanticSlot = async (
  stableIdentityCommitment: Uint8Array,
  minimumAcceptedGeneration: bigint,
  effectiveLogicalWindow: bigint,
  expiresAfterLogicalWindow: bigint,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/admission-revoke-slot/v1",
    requireBytes("stableIdentityCommitment", stableIdentityCommitment, 32),
    u64be(minimumAcceptedGeneration),
    u64be(effectiveLogicalWindow),
    u64be(expiresAfterLogicalWindow),
  );

/** `H("p2party/pair-slot/v1" || pairRoutingTag)` (Section 4.4 slot table). */
export const pairSemanticSlot = async (
  pairRoutingTag: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/pair-slot/v1",
    requireBytes("pairRoutingTag", pairRoutingTag, 32),
  );

/* ------------------------------------------------------------------ *
 * Sections 4.8/4.9 — admission and presence transcripts
 * ------------------------------------------------------------------ */

/**
 * `PresenceProofTranscriptHash =
 *   H("p2party/presence-proof/v1" || Canonical(PresenceProofTranscript))`
 */
export const presenceProofTranscriptHash = async (
  transcript: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/presence-proof/v1",
    canonical(presenceProofTranscriptV1Schema, transcript),
  );

/**
 * `PresenceOwnershipSignedMessage =
 *   "p2party/presence-ownership-signature/v1" ||
 *   PresenceProofTranscriptHash`
 */
export const presenceOwnershipSignedMessage = (
  transcriptHash: Uint8Array,
): Uint8Array =>
  concatBytes(
    domain("p2party/presence-ownership-signature/v1"),
    requireBytes("PresenceProofTranscriptHash", transcriptHash, 32),
  );

/**
 * `PresencePermitSignedMessage =
 *   "p2party/presence-permit-signature/v1" ||
 *   H(Canonical(PresencePermitV1 without authoritySignature))`
 */
export const presencePermitSignedMessage = async (
  unsignedPermit: unknown,
): Promise<Uint8Array> =>
  concatBytes(
    domain("p2party/presence-permit-signature/v1"),
    await sha256(canonical(presencePermitUnsignedV1Schema, unsignedPermit)),
  );

/**
 * `AdmissionGrantId =
 *   H("p2party/admission-grant/v1" || Canonical(AdmissionGrantV1))`
 */
export const admissionGrantId = async (grant: unknown): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/admission-grant/v1",
    canonical(admissionGrantV1Schema, grant),
  );

/**
 * `AdmissionGrantSignedMessage =
 *   "p2party/admission-grant-signature/v1" ||
 *   H(Canonical(AdmissionGrantV1 without authoritySignature))`
 */
export const admissionGrantSignedMessage = async (
  unsignedGrant: unknown,
): Promise<Uint8Array> =>
  concatBytes(
    domain("p2party/admission-grant-signature/v1"),
    await sha256(canonical(admissionGrantUnsignedV1Schema, unsignedGrant)),
  );

/**
 * `AdmissionRevokeSignedMessage =
 *   "p2party/admission-revoke-signature/v1" ||
 *   H(Canonical(AdmissionRevokeV1 without authoritySignature))`
 */
export const admissionRevokeSignedMessage = async (
  unsignedRevoke: unknown,
): Promise<Uint8Array> =>
  concatBytes(
    domain("p2party/admission-revoke-signature/v1"),
    await sha256(canonical(admissionRevokeUnsignedV1Schema, unsignedRevoke)),
  );

/* ------------------------------------------------------------------ *
 * Section 4.5 — carrier envelope
 * ------------------------------------------------------------------ */

export interface CarrierEnvelopeCoordinates {
  readonly deliveryProfileHash: Uint8Array;
  readonly carrierContextId: Uint8Array;
  readonly ingressWindow: bigint;
  readonly sizeClass: number;
}

/**
 * `CarrierKey = HKDF-Expand(RoomRoot,
 *    "p2party/carrier-envelope-key/v1" || DeliveryProfileHash ||
 *    carrierContextId || U64BE(ingressWindow) || Byte(sizeClass) || nonce, 32)`
 */
export const carrierKey = async (
  roomRootBytes: Uint8Array,
  coordinates: CarrierEnvelopeCoordinates,
  nonce: Uint8Array,
): Promise<Uint8Array> =>
  hkdfSha256Expand(
    requireBytes("RoomRoot", roomRootBytes, 32),
    concatBytes(
      domain("p2party/carrier-envelope-key/v1"),
      requireBytes("DeliveryProfileHash", coordinates.deliveryProfileHash, 32),
      requireBytes("carrierContextId", coordinates.carrierContextId, 32),
      u64be(coordinates.ingressWindow),
      byteOf(coordinates.sizeClass),
      requireBytes("nonce", nonce, 24),
    ),
    32,
  );

/**
 * `CarrierAAD = "p2party/carrier-envelope-aad/v1" || Byte(version) ||
 *    DeliveryProfileHash || U64BE(ingressWindow) || Byte(sizeClass) ||
 *    carrierContextId`
 *
 * The AAD deliberately omits the nonce: the nonce is a key selector, and the
 * key schedule already binds it.
 */
export const carrierAad = (
  version: number,
  coordinates: CarrierEnvelopeCoordinates,
): Uint8Array =>
  concatBytes(
    domain("p2party/carrier-envelope-aad/v1"),
    byteOf(version),
    requireBytes("DeliveryProfileHash", coordinates.deliveryProfileHash, 32),
    u64be(coordinates.ingressWindow),
    byteOf(coordinates.sizeClass),
    requireBytes("carrierContextId", coordinates.carrierContextId, 32),
  );

/**
 * `CarrierObjectId = H("p2party/carrier-object/v1" || Canonical(CarrierEnvelopeV1))`
 *
 * Useful only inside one carrier context; clients deduplicate by the private
 * `OperationId` after decryption.
 */
export const carrierObjectId = async (envelope: unknown): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/carrier-object/v1",
    canonical(carrierEnvelopeV1Schema, envelope),
  );

/* ------------------------------------------------------------------ *
 * Section 4.7 — core reduction
 * ------------------------------------------------------------------ */

/**
 * `operationsDigest =
 *    H("p2party/core-operation-set/v1" || Canonical(activeOperationIds))`
 *
 * The same formula serves the R2 conformance record's required-operation
 * digest.
 */
export const coreOperationSetDigest = async (
  operationIds: readonly Uint8Array[],
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/core-operation-set/v1",
    canonical(operationIdSetSchema, operationIds),
  );

/* ------------------------------------------------------------------ *
 * Section 4.0 — kernel, claim, and formal registry roots
 * ------------------------------------------------------------------ */

export const executableKernelManifestHash = async (
  manifest: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/executable-rendezvous-kernel/v1",
    canonical(executableRendezvousKernelManifestV1Schema, manifest),
  );

/**
 * `KernelModuleSemanticsHash(module) =
 *    H("p2party/executable-kernel-module-semantics/v1" || module.moduleId ||
 *      Canonical(sorted entrypoint tuples))`
 *
 * `moduleId` is a `Uint16` schema field, so it enters the preimage as `U16BE`.
 */
export const kernelModuleSemanticsHash = async (module: {
  readonly moduleId: number;
  readonly entrypoints: readonly unknown[];
}): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/executable-kernel-module-semantics/v1",
    u16be(module.moduleId),
    canonical(kernelModuleSemanticsSchema, module.entrypoints),
  );

/**
 * `KernelSourceTreeHash(files) = H("p2party/executable-kernel-source-tree/v1"
 *    || Canonical(Sort(normalizedRelativePath, H(fileBytes))))`
 *
 * Absolute paths, timestamps, filesystem order, and build-host metadata are
 * excluded by construction.
 */
export const kernelSourceTreeHash = async (
  files: readonly {
    readonly normalizedRelativePath: string;
    readonly fileDigest: Uint8Array;
  }[],
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/executable-kernel-source-tree/v1",
    canonical(kernelSourceTreeSchema, files),
  );

export const claimRegistryHash = async (
  registry: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/rendezvous-claim-registry/v1",
    canonical(claimRegistryV1Schema, registry),
  );

export const claimWordingCatalogHash = async (
  catalog: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/claim-wording-catalog/v1",
    canonical(claimWordingCatalogV1Schema, catalog),
  );

export const formalObligationRegistryHash = async (
  registry: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/formal-obligation-registry/v1",
    canonical(formalObligationRegistryV1Schema, registry),
  );

/**
 * `ClaimScopeDigest = H("p2party/claim-scope/v1" || U16BE(claimId) ||
 *    ClaimScopeKindByte(scopeKind) || scopeSchemaHash || canonicalScope)`
 */
export const claimScopeDigest = async (
  claimId: number,
  scopeKindByte: number,
  scopeSchemaHash: Uint8Array,
  canonicalScope: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/claim-scope/v1",
    u16be(claimId),
    byteOf(scopeKindByte),
    requireBytes("scopeSchemaHash", scopeSchemaHash, 32),
    canonicalScope,
  );

export const claimEvaluationDatasetDigest = async (
  dataset: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/claim-evaluation-dataset/v1",
    canonical(claimEvaluationDatasetV1Schema, dataset),
  );

/**
 * `FormalAssumptionSetHash = H("p2party/formal-assumption-set/v1" ||
 *    claimRegistryHash || Canonical(resolved sorted ClaimAssumptionV1 records))`
 */
export const formalAssumptionSetHash = async (
  claimRegistryHashBytes: Uint8Array,
  resolvedAssumptions: readonly unknown[],
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/formal-assumption-set/v1",
    requireBytes("claimRegistryHash", claimRegistryHashBytes, 32),
    canonical(resolvedAssumptionSetSchema, resolvedAssumptions),
  );

/**
 * `FormalProofScopeDigest = H("p2party/formal-proof-scope/v1" ||
 *    U16BE(obligationId) || proofScopeSchemaHash || canonicalScope)`
 */
export const formalProofScopeDigest = async (
  obligationId: number,
  proofScopeSchemaHash: Uint8Array,
  canonicalScope: Uint8Array,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/formal-proof-scope/v1",
    u16be(obligationId),
    requireBytes("proofScopeSchemaHash", proofScopeSchemaHash, 32),
    canonicalScope,
  );

/**
 * `EmptySchedulerWorkloadDigest = H("p2party/scheduler-workload/v1/none")`
 *
 * Only FPO-002 accepts a nonempty scheduler workload; every other obligation
 * uses this closed sentinel so an unrelated workload cannot alter another
 * property's identity.
 */
export const emptySchedulerWorkloadDigest = async (): Promise<Uint8Array> =>
  sha256(domain("p2party/scheduler-workload/v1/none"));

export const claimEvaluationDigest = async (
  evaluation: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/claim-evaluation/v1",
    canonical(claimEvaluationV1Schema, evaluation),
  );

export const formalProofResultDigest = async (
  result: unknown,
): Promise<Uint8Array> =>
  hashWithDomain(
    "p2party/formal-proof-result/v1",
    canonical(formalProofResultV1Schema, result),
  );
