/**
 * Carrier-separated envelope framing (Section 4.5).
 *
 * The same logical operation is wrapped independently for every carrier
 * context, with carrier-domain-separated keys and nonce material, so two
 * stores never receive byte-identical ciphertext or a common object
 * identifier. A client deduplicates the rewrapped copies by the private
 * `OperationId` after decryption — an identifier a store never sees.
 *
 * ## Unresolved dependency: the sealing primitive
 *
 * `carrierAeadSuite = 1` is the frozen XChaCha20-Poly1305 construction from
 * `draft-irtf-cfrg-xchacha-03` with a 32-byte key, 24-byte nonce, and 16-byte
 * tag. This package's WASM module does not currently export it: it exposes
 * ChaCha20-Poly1305 IETF (12-byte nonce) and XSalsa20-Poly1305, neither of
 * which is the specified construction.
 *
 * Substituting a different AEAD, or composing XChaCha20 out of HChaCha20 in
 * TypeScript, is forbidden by SEC-002 and SEC-019. This module therefore owns
 * the framing, key schedule, AAD, and identifiers — all of which are fully
 * specified — and takes the AEAD as an injected provider. With no provider
 * installed, sealing and opening fail closed rather than falling back.
 *
 * Closing this gap means exposing `crypto_aead_xchacha20poly1305_ietf_*` from
 * the vendored libsodium through `src/cryptography/libcrypto.c` and rebuilding
 * the WASM artifact. That rebuild re-emits an SRI-pinned, provenance-recorded
 * binary that dependents verify, so it is a deliberate release action rather
 * than a side effect of this module.
 */

import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { carrierAad, carrierKey, carrierObjectId } from "./derivations";
import { carrierEnvelopeV1Schema, carrierPlaintextV1Schema } from "./schemas";

import type { CarrierEnvelopeCoordinates } from "./derivations";

export const CARRIER_ENVELOPE_VERSION = 1;
export const CARRIER_AEAD_SUITE_1_KEY_BYTES = 32;
export const CARRIER_AEAD_SUITE_1_NONCE_BYTES = 24;
export const CARRIER_AEAD_SUITE_1_TAG_BYTES = 16;

export interface CarrierEnvelopeV1 {
  version: 1;
  deliveryProfileHash: Uint8Array;
  ingressWindow: bigint;
  sizeClass: number;
  carrierContextId: Uint8Array;
  nonce: Uint8Array;
  ciphertextAndTag: Uint8Array;
}

export interface CarrierPlaintextV1 {
  /** Exact canonical signed operation bytes, identical across carriers. */
  operationBytes: Uint8Array;
  /** Fills this profile's carrier size class. */
  carrierPadding: Uint8Array;
}

/**
 * The exact AEAD required by `carrierAeadSuite = 1`.
 *
 * An implementation must be XChaCha20-Poly1305 with the stated key, nonce, and
 * tag sizes. `open` returns null — never a partial or unauthenticated
 * plaintext — on any tag, length, or associated-data failure.
 */
export interface CarrierAeadProvider {
  readonly suite: 1;
  seal(
    key: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
  open(
    key: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array,
    ciphertextAndTag: Uint8Array,
  ): Promise<Uint8Array | null>;
}

export class CarrierAeadUnavailableError extends Error {
  override readonly name = "CarrierAeadUnavailableError";
  readonly code = "carrier-aead-suite-1-unavailable";
  readonly suite = 1;

  constructor() {
    super(
      "carrierAeadSuite=1 (XChaCha20-Poly1305) is not available in this build; " +
        "no substitute AEAD may be used for a carrier envelope.",
    );
  }
}

export class CarrierEnvelopeError extends Error {
  override readonly name = "CarrierEnvelopeError";

  constructor(message: string) {
    super(`carrierEnvelope: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new CarrierEnvelopeError(message);
};

const requireProvider = (
  provider: CarrierAeadProvider | null,
): CarrierAeadProvider => {
  if (provider === null || provider.suite !== 1)
    throw new CarrierAeadUnavailableError();
  return provider;
};

/**
 * Build the canonical carrier plaintext, padded to the profile's size class.
 *
 * Padding is what makes real and dummy objects the same length; a caller that
 * skipped it would publish a length that varies with the operation.
 */
export const buildCarrierPlaintext = (
  operationBytes: Uint8Array,
  fixedCarrierObjectBytes: number,
): CarrierPlaintextV1 => {
  const framingOverhead =
    encodeCanonical(carrierPlaintextV1Schema, {
      operationBytes: new Uint8Array(0),
      carrierPadding: new Uint8Array(0),
    }).length + CARRIER_AEAD_SUITE_1_TAG_BYTES;
  const available = fixedCarrierObjectBytes - framingOverhead;
  if (operationBytes.length > available)
    fail("operation does not fit this profile's carrier size class");
  return {
    operationBytes,
    carrierPadding: new Uint8Array(available - operationBytes.length),
  };
};

/**
 * Seal one operation for one carrier context.
 *
 * The nonce is sampled by the caller per `(OperationId, profile, context,
 * ingressWindow, sizeClass)` wrap slot and persisted with the envelope before
 * first publication, so an exact retry resends the same bytes rather than
 * re-encrypting under a fresh nonce.
 */
export const sealCarrierEnvelope = async (
  roomRootBytes: Uint8Array,
  coordinates: CarrierEnvelopeCoordinates,
  nonce: Uint8Array,
  plaintext: CarrierPlaintextV1,
  provider: CarrierAeadProvider | null,
): Promise<CarrierEnvelopeV1> => {
  const aead = requireProvider(provider);
  if (nonce.length !== CARRIER_AEAD_SUITE_1_NONCE_BYTES)
    fail(
      `nonce must be exactly ${String(CARRIER_AEAD_SUITE_1_NONCE_BYTES)} bytes`,
    );

  const key = await carrierKey(roomRootBytes, coordinates, nonce);
  const ciphertextAndTag = await aead.seal(
    key,
    nonce,
    carrierAad(CARRIER_ENVELOPE_VERSION, coordinates),
    encodeCanonical(carrierPlaintextV1Schema, plaintext),
  );

  return {
    version: 1,
    deliveryProfileHash: coordinates.deliveryProfileHash,
    ingressWindow: coordinates.ingressWindow,
    sizeClass: coordinates.sizeClass,
    carrierContextId: coordinates.carrierContextId,
    nonce,
    ciphertextAndTag,
  };
};

/**
 * Open an envelope, returning null when it is not for this room.
 *
 * A dummy is indistinguishable from a real object at this layer by
 * construction: it has the same public header and body length and simply fails
 * authentication, so the caller must treat null as "not mine", never as
 * evidence of a fault.
 */
export const openCarrierEnvelope = async (
  roomRootBytes: Uint8Array,
  envelope: CarrierEnvelopeV1,
  provider: CarrierAeadProvider | null,
): Promise<CarrierPlaintextV1 | null> => {
  const aead = requireProvider(provider);
  if (envelope.version !== CARRIER_ENVELOPE_VERSION)
    fail("unsupported carrier envelope version");

  const coordinates: CarrierEnvelopeCoordinates = {
    deliveryProfileHash: envelope.deliveryProfileHash,
    carrierContextId: envelope.carrierContextId,
    ingressWindow: envelope.ingressWindow,
    sizeClass: envelope.sizeClass,
  };
  const key = await carrierKey(roomRootBytes, coordinates, envelope.nonce);
  const opened = await aead.open(
    key,
    envelope.nonce,
    carrierAad(envelope.version, coordinates),
    envelope.ciphertextAndTag,
  );
  if (opened === null) return null;

  // The plaintext must be the unique canonical encoding of itself; an
  // alternate encoding would give one logical operation two carrier forms.
  const plaintext = decodeCanonicalStrict(
    carrierPlaintextV1Schema,
    opened,
  ) as CarrierPlaintextV1;
  for (const byte of plaintext.carrierPadding) {
    if (byte !== 0) fail("carrier padding must be all zero");
  }
  return plaintext;
};

/** The exact canonical encoding of an envelope, as published to a carrier. */
export const encodeCarrierEnvelope = (
  envelope: CarrierEnvelopeV1,
): Uint8Array => encodeCanonical(carrierEnvelopeV1Schema, envelope);

export const decodeCarrierEnvelope = (encoded: Uint8Array): CarrierEnvelopeV1 =>
  decodeCanonicalStrict(carrierEnvelopeV1Schema, encoded) as CarrierEnvelopeV1;

/** `CarrierObjectId`, meaningful only inside one carrier context. */
export const deriveCarrierObjectId = (
  envelope: CarrierEnvelopeV1,
): Promise<Uint8Array> => carrierObjectId(envelope);

/**
 * Two envelopes of the same operation for different carrier contexts must not
 * share ciphertext or object identifier. Exposed so the carrier-separation
 * requirement is testable rather than assumed.
 */
export const envelopesAreCarrierSeparated = (
  left: CarrierEnvelopeV1,
  right: CarrierEnvelopeV1,
): boolean =>
  !bytesEqual(left.ciphertextAndTag, right.ciphertextAndTag) &&
  !bytesEqual(left.nonce, right.nonce);
