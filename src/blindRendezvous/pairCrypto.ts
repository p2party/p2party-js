/**
 * Pair-bootstrap HPKE and established-flight AEAD (Section 4.11).
 *
 * This module owns only cryptographic sealing/opening and exact transcript
 * binding. It deliberately does not own one-use routing-tag consumption,
 * predecessor/dependency state, identity/admission decisions, persistence, or
 * SDP dispatch. Those effectful gates consume this module's authenticated
 * output and must commit their state before exposing it to WebRTC.
 */

import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  bindPairOuter,
  identityAcceptPskId,
  identityHelloPskId,
  pairAad,
  pairBootstrapHeaderHash,
  pairBootstrapTagExporterContext,
  pairFlightAeadKey,
  pairFlightRoot,
  pairFlightRoutingTag,
  pairFlightSecret,
  validatedPairRootExporterContext,
} from "./derivations";
import {
  PAIR_BOOTSTRAP_SUITE_ID_V1,
  PAIR_BOOTSTRAP_SUITE_V1,
} from "./pairBootstrapSuite";
import {
  decodePairPlaintextV1,
  encodePairBootstrapInfoV1,
  encodePairPlaintextV1,
  validatePairFlightSlotV1,
} from "./pairPlaintext";
import {
  PAIR_BOOTSTRAP_HEADER_VERSION_V1,
  PAIR_STEP_ENVELOPE_VERSION_V1,
  decodePairStepEnvelopeV1,
  encodePairStepEnvelopeV1,
} from "./pairStepEnvelope";
import {
  pairBootstrapInfoV1Schema,
  pairFlightSlotV1Schema,
  pairOuterBindingV1Schema,
  pairOuterPrebindingV1Schema,
  pairPlaintextV1Schema,
} from "./schemas";
import {
  setupHpkePskRecipient,
  setupHpkePskSender,
} from "../cryptography/hpke";
import { snapshotByteInput } from "../cryptography/byteInput";
import {
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
} from "../cryptography/xchacha20poly1305";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { RoomPqMode } from "../roomPolicy";
import type { OperationPayloadClassV1 } from "./operation";
import type {
  PairBootstrapInfoV1,
  PairFlightSlotV1,
  PairOuterBindingV1,
  PairOuterPrebindingV1,
  PairPlaintextV1,
} from "./pairPlaintext";
import type {
  PairBootstrapHeaderV1,
  PairStepEnvelopeV1,
} from "./pairStepEnvelope";

const ZERO32 = new Uint8Array(32);

const BOOTSTRAP_TAG_EXPORTER_BYTES = PAIR_BOOTSTRAP_SUITE_V1.routingTagBytes;
const BOOTSTRAP_ROOT_EXPORTER_BYTES = 32;

export class PairCryptoError extends Error {
  override readonly name = "PairCryptoError";

  constructor(message: string) {
    super(`pairCrypto: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new PairCryptoError(message);
};

const snapshotExactBytes = (
  value: unknown,
  name: string,
  length: number,
): Uint8Array =>
  snapshotByteInput(value, `pairCrypto: ${name}`, {
    exactLength: length,
  });

const fixedTimeEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++)
    difference |= left[index] ^ right[index];
  return difference === 0;
};

const isZero32 = (value: Uint8Array): boolean =>
  value.length === ZERO32.length && fixedTimeEqual(value, ZERO32);

const snapshotPrebinding = (
  value: PairOuterPrebindingV1,
): PairOuterPrebindingV1 =>
  decodeCanonicalStrict(
    pairOuterPrebindingV1Schema,
    encodeCanonical(pairOuterPrebindingV1Schema, value),
  ) as PairOuterPrebindingV1;

const snapshotBinding = (value: unknown): PairOuterBindingV1 =>
  decodeCanonicalStrict(
    pairOuterBindingV1Schema,
    encodeCanonical(pairOuterBindingV1Schema, value),
  ) as PairOuterBindingV1;

const snapshotPlaintext = (value: PairPlaintextV1): PairPlaintextV1 =>
  decodeCanonicalStrict(
    pairPlaintextV1Schema,
    encodeCanonical(pairPlaintextV1Schema, value),
  ) as PairPlaintextV1;

const snapshotBootstrapInfo = (
  value: PairBootstrapInfoV1,
): {
  readonly value: PairBootstrapInfoV1;
  readonly encoded: Uint8Array;
} => {
  const encoded = encodePairBootstrapInfoV1(value);
  return {
    value: decodeCanonicalStrict(
      pairBootstrapInfoV1Schema,
      encoded,
    ) as PairBootstrapInfoV1,
    encoded,
  };
};

const snapshotSlot = (value: PairFlightSlotV1): PairFlightSlotV1 => {
  validatePairFlightSlotV1(value);
  return decodeCanonicalStrict(
    pairFlightSlotV1Schema,
    encodeCanonical(pairFlightSlotV1Schema, value),
  ) as PairFlightSlotV1;
};

const snapshotEnvelope = (
  value: PairStepEnvelopeV1,
  operationPayloadClass: OperationPayloadClassV1,
): PairStepEnvelopeV1 =>
  decodePairStepEnvelopeV1(
    encodePairStepEnvelopeV1(value, operationPayloadClass),
    operationPayloadClass,
  );

export type PairBootstrapOuterFieldsV1 = Omit<
  PairOuterPrebindingV1,
  "bootstrapHeaderHash" | "nonce"
>;

const snapshotBootstrapOuterFields = (
  value: PairBootstrapOuterFieldsV1,
): PairBootstrapOuterFieldsV1 => {
  const prebinding = snapshotPrebinding({
    ...value,
    bootstrapHeaderHash: ZERO32,
    nonce: null,
  });
  if (prebinding.operationPayloadClass !== 0)
    fail("bootstrap pair steps must use operation payload class 0");
  const {
    bootstrapHeaderHash: _headerHash,
    nonce: _nonce,
    ...outerFields
  } = prebinding;
  return outerFields;
};

const assertBootstrapInfoMatchesOuter = (
  info: PairBootstrapInfoV1,
  outer: PairBootstrapOuterFieldsV1,
): void => {
  if (
    info.roomContextConfirmation.length !==
      outer.roomContextConfirmation.length ||
    !bytesEqual(info.roomContextConfirmation, outer.roomContextConfirmation) ||
    info.policyHash.length !== outer.policyHash.length ||
    !bytesEqual(info.policyHash, outer.policyHash) ||
    info.logicalWindow !== outer.logicalWindow ||
    info.expiresAfterWindow !== outer.expiresAfterWindow ||
    info.authorEpochEd25519Key.length !== outer.authorEpochEd25519Key.length ||
    !bytesEqual(info.authorEpochEd25519Key, outer.authorEpochEd25519Key) ||
    info.authorSequence !== outer.authorSequence ||
    (info.previousAuthorOperationId === null) !==
      (outer.previousAuthorOperationId === null) ||
    (info.previousAuthorOperationId !== null &&
      outer.previousAuthorOperationId !== null &&
      !bytesEqual(
        info.previousAuthorOperationId,
        outer.previousAuthorOperationId,
      )) ||
    info.operationPayloadClass !== outer.operationPayloadClass
  )
    fail("bootstrap info does not match the exact outer operation fields");
};

const deriveBootstrapPskId = (
  info: PairBootstrapInfoV1,
): Promise<Uint8Array> => {
  if (
    info.stepKind === "IDENTITY_HELLO" &&
    info.recipientBinding.kind === "presence"
  )
    return identityHelloPskId(
      info.policyHash,
      info.recipientBinding.presenceOperationId,
    );
  if (
    info.stepKind === "IDENTITY_ACCEPT" &&
    info.recipientBinding.kind === "hello-response"
  )
    return identityAcceptPskId(
      info.policyHash,
      info.recipientBinding.helloOperationId,
    );
  return fail("bootstrap step and recipient binding disagree");
};

const assertPlaintextSlot = (
  plaintext: PairPlaintextV1,
  slot: PairFlightSlotV1,
): void => {
  if (
    plaintext.kind !== slot.kind ||
    plaintext.direction !== slot.direction ||
    plaintext.pairSequence !== slot.pairSequence
  )
    fail("pair plaintext does not match the expected pair flight slot");
};

const assertBootstrapPlaintextKind = (
  plaintext: PairPlaintextV1,
  info: PairBootstrapInfoV1,
): void => {
  if (plaintext.kind !== info.stepKind)
    fail("bootstrap plaintext kind does not match HPKE info");
};

const assertEstablishedPrebinding = (
  prebinding: PairOuterPrebindingV1,
): Uint8Array => {
  if (!isZero32(prebinding.bootstrapHeaderHash))
    fail("established pair prebinding must use ZERO32 bootstrapHeaderHash");
  if (prebinding.nonce === null)
    fail("established pair prebinding must carry its public nonce");
  return prebinding.nonce;
};

const bootstrapHeader = (
  hybridKemCiphertext: Uint8Array,
): PairBootstrapHeaderV1 => ({
  version: PAIR_BOOTSTRAP_HEADER_VERSION_V1,
  suiteId: PAIR_BOOTSTRAP_SUITE_ID_V1,
  hybridKemCiphertext: Uint8Array.from(hybridKemCiphertext),
});

export interface PairBootstrapSealOptionsV1 {
  readonly module: LibCrypto;
  readonly recipientHybridKemPublicKey: Uint8Array;
  /** RoomRoot for HELLO or the validated HelloRoot for ACCEPT. */
  readonly psk: Uint8Array;
  readonly bootstrapInfo: PairBootstrapInfoV1;
  readonly outerFields: PairBootstrapOuterFieldsV1;
  readonly roomPqMode: RoomPqMode;
  /**
   * Called only after the HPKE header, one-use tag, and exact outer binding
   * exist, allowing the stable identity signature to cover that binding.
   */
  readonly createSignedPlaintext: (
    binding: PairOuterBindingV1,
  ) => PairPlaintextV1 | Promise<PairPlaintextV1>;
}

export interface PairBootstrapSealResultV1 {
  readonly envelope: PairStepEnvelopeV1;
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
  /**
   * HelloRoot or AcceptRoot. The caller owns these bytes and must wipe them
   * after deriving/persisting the next protected state.
   */
  readonly bootstrapRoot: Uint8Array;
}

/**
 * Seal one HELLO or ACCEPT. Normal encapsulation always uses the hybrid KEM's
 * CSPRNG path; deterministic conformance hooks are intentionally unreachable
 * from this protocol API.
 */
export const sealPairBootstrapV1 = async (
  options: PairBootstrapSealOptionsV1,
): Promise<PairBootstrapSealResultV1> => {
  const recipientPublicKey = snapshotExactBytes(
    options.recipientHybridKemPublicKey,
    "recipient hybrid KEM public key",
    PAIR_BOOTSTRAP_SUITE_V1.hybridKem.publicKeyBytes,
  );
  const info = snapshotBootstrapInfo(options.bootstrapInfo);
  const outer = snapshotBootstrapOuterFields(options.outerFields);
  const psk = snapshotExactBytes(
    options.psk,
    "bootstrap PSK",
    PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes,
  );

  let pskId: Uint8Array | undefined;
  let headerHash: Uint8Array | undefined;
  let tagContext: Uint8Array | undefined;
  let routingTag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let encodedPlaintext: Uint8Array | undefined;
  let rootContext: Uint8Array | undefined;
  let setup: Awaited<ReturnType<typeof setupHpkePskSender>> | undefined;
  try {
    assertBootstrapInfoMatchesOuter(info.value, outer);
    pskId = await deriveBootstrapPskId(info.value);
    setup = await setupHpkePskSender({
      module: options.module,
      recipientPublicKey,
      info: info.encoded,
      psk,
      pskId,
    });

    const header = bootstrapHeader(setup.encapsulatedKey);
    headerHash = await pairBootstrapHeaderHash(header);
    const prebinding = snapshotPrebinding({
      ...outer,
      bootstrapHeaderHash: headerHash,
      nonce: null,
    });
    tagContext = pairBootstrapTagExporterContext(prebinding);
    routingTag = await setup.context.exportSecret(
      tagContext,
      BOOTSTRAP_TAG_EXPORTER_BYTES,
    );
    const binding = snapshotBinding(
      await bindPairOuter(prebinding, routingTag),
    );

    const createdPlaintext = await options.createSignedPlaintext(
      snapshotBinding(binding),
    );
    const plaintext = snapshotPlaintext(createdPlaintext);
    assertBootstrapPlaintextKind(plaintext, info.value);
    encodedPlaintext = await encodePairPlaintextV1(
      plaintext,
      outer.operationPayloadClass,
      true,
      options.roomPqMode,
    );
    aad = await pairAad(binding);
    const ciphertext = setup.context.seal(aad, encodedPlaintext);
    rootContext = await validatedPairRootExporterContext(
      info.value.stepKind,
      encodedPlaintext,
    );
    const bootstrapRoot = await setup.context.exportSecret(
      rootContext,
      BOOTSTRAP_ROOT_EXPORTER_BYTES,
    );
    const envelope = snapshotEnvelope(
      {
        version: PAIR_STEP_ENVELOPE_VERSION_V1,
        pairRoutingTag: binding.pairRoutingTag,
        bootstrapHeader: header,
        nonce: null,
        pairCiphertextAndTag: ciphertext,
      },
      outer.operationPayloadClass,
    );

    return {
      envelope,
      binding: snapshotBinding(binding),
      plaintext: await decodePairPlaintextV1(
        encodedPlaintext,
        outer.operationPayloadClass,
        true,
        options.roomPqMode,
      ),
      bootstrapRoot,
    };
  } finally {
    setup?.context.destroy();
    recipientPublicKey.fill(0);
    psk.fill(0);
    info.encoded.fill(0);
    pskId?.fill(0);
    headerHash?.fill(0);
    tagContext?.fill(0);
    routingTag?.fill(0);
    aad?.fill(0);
    encodedPlaintext?.fill(0);
    rootContext?.fill(0);
  }
};

export interface PairBootstrapOpenOptionsV1 {
  readonly module: LibCrypto;
  readonly recipientHybridKemSecretKey: Uint8Array;
  readonly psk: Uint8Array;
  readonly bootstrapInfo: PairBootstrapInfoV1;
  readonly prebinding: PairOuterPrebindingV1;
  readonly envelope: PairStepEnvelopeV1;
  readonly operationPayloadClass: OperationPayloadClassV1;
  readonly roomPqMode: RoomPqMode;
  /**
   * The trusted pair-state layer verifies the stable transcript signature,
   * identity/commitment binding, exact presences, and state-owned slot before
   * the bootstrap root is released.
   */
  readonly validateAuthenticatedPlaintext: (
    binding: PairOuterBindingV1,
    plaintext: PairPlaintextV1,
  ) => void | Promise<void>;
}

export interface PairBootstrapOpenResultV1 {
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
  readonly bootstrapRoot: Uint8Array;
}

/**
 * Try one budgeted HELLO/ACCEPT receiver key and expected info candidate.
 *
 * A routing-tag or HPKE authentication mismatch is `null` (not this
 * candidate). Authenticated noncanonical/invalid pair plaintext throws and
 * must be accounted as a rejected pair attempt by the caller.
 */
export const openPairBootstrapV1 = async (
  options: PairBootstrapOpenOptionsV1,
): Promise<PairBootstrapOpenResultV1 | null> => {
  const info = snapshotBootstrapInfo(options.bootstrapInfo);
  const prebinding = snapshotPrebinding(options.prebinding);
  const envelope = snapshotEnvelope(
    options.envelope,
    options.operationPayloadClass,
  );
  let recipientSecretKey: Uint8Array | undefined;
  let psk: Uint8Array | undefined;
  try {
    recipientSecretKey = snapshotExactBytes(
      options.recipientHybridKemSecretKey,
      "recipient hybrid KEM secret key",
      PAIR_BOOTSTRAP_SUITE_V1.hybridKem.secretKeyBytes,
    );
    psk = snapshotExactBytes(
      options.psk,
      "bootstrap PSK",
      PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes,
    );
  } catch (error) {
    recipientSecretKey?.fill(0);
    throw error;
  }

  let expectedHeaderHash: Uint8Array | undefined;
  let pskId: Uint8Array | undefined;
  let tagContext: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let encodedPlaintext: Uint8Array | undefined;
  let rootContext: Uint8Array | undefined;
  let context: Awaited<ReturnType<typeof setupHpkePskRecipient>> | undefined;
  try {
    if (envelope.bootstrapHeader === null || envelope.nonce !== null)
      return fail("bootstrap open requires an HPKE header and null nonce");
    const {
      bootstrapHeaderHash: _headerHash,
      nonce: _nonce,
      ...outerFields
    } = prebinding;
    assertBootstrapInfoMatchesOuter(info.value, outerFields);
    expectedHeaderHash = await pairBootstrapHeaderHash(
      envelope.bootstrapHeader,
    );
    if (!fixedTimeEqual(expectedHeaderHash, prebinding.bootstrapHeaderHash))
      return null;

    pskId = await deriveBootstrapPskId(info.value);
    context = await setupHpkePskRecipient({
      module: options.module,
      encapsulatedKey: envelope.bootstrapHeader.hybridKemCiphertext,
      recipientSecretKey,
      info: info.encoded,
      psk,
      pskId,
    });
    tagContext = pairBootstrapTagExporterContext(prebinding);
    expectedTag = await context.exportSecret(
      tagContext,
      BOOTSTRAP_TAG_EXPORTER_BYTES,
    );
    if (!fixedTimeEqual(expectedTag, envelope.pairRoutingTag)) return null;

    const binding = snapshotBinding(
      await bindPairOuter(prebinding, expectedTag),
    );
    aad = await pairAad(binding);
    encodedPlaintext =
      context.open(aad, envelope.pairCiphertextAndTag) ?? undefined;
    if (encodedPlaintext === undefined) return null;
    const plaintext = await decodePairPlaintextV1(
      encodedPlaintext,
      options.operationPayloadClass,
      true,
      options.roomPqMode,
    );
    assertBootstrapPlaintextKind(plaintext, info.value);
    await options.validateAuthenticatedPlaintext(
      snapshotBinding(binding),
      snapshotPlaintext(plaintext),
    );

    rootContext = await validatedPairRootExporterContext(
      info.value.stepKind,
      encodedPlaintext,
    );
    return {
      binding: snapshotBinding(binding),
      plaintext,
      bootstrapRoot: await context.exportSecret(
        rootContext,
        BOOTSTRAP_ROOT_EXPORTER_BYTES,
      ),
    };
  } finally {
    context?.destroy();
    recipientSecretKey.fill(0);
    psk.fill(0);
    info.encoded.fill(0);
    expectedHeaderHash?.fill(0);
    pskId?.fill(0);
    tagContext?.fill(0);
    expectedTag?.fill(0);
    aad?.fill(0);
    encodedPlaintext?.fill(0);
    rootContext?.fill(0);
  }
};

export interface SealPairStepOptionsV1 {
  readonly module: LibCrypto;
  /** EstablishedPairRoot before promotion, one-use PqSlotSecret afterwards. */
  readonly baseSecret: Uint8Array;
  readonly expectedSlot: PairFlightSlotV1;
  readonly prebinding: PairOuterPrebindingV1;
  readonly plaintext: PairPlaintextV1;
  readonly roomPqMode: RoomPqMode;
}

export interface SealPairStepResultV1 {
  readonly envelope: PairStepEnvelopeV1;
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
}

/** Seal one non-HPKE pair flight under the exact suite-1 DRY construction. */
export const sealPairStepV1 = async (
  options: SealPairStepOptionsV1,
): Promise<SealPairStepResultV1> => {
  const slot = snapshotSlot(options.expectedSlot);
  const prebinding = snapshotPrebinding(options.prebinding);
  const nonce = Uint8Array.from(assertEstablishedPrebinding(prebinding));
  const plaintext = snapshotPlaintext(options.plaintext);
  assertPlaintextSlot(plaintext, slot);
  const baseSecret = snapshotExactBytes(
    options.baseSecret,
    "pair base secret",
    32,
  );

  let flightRoot: Uint8Array | undefined;
  let flightSecret: Uint8Array | undefined;
  let routingTag: Uint8Array | undefined;
  let aeadKey: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let encodedPlaintext: Uint8Array | undefined;
  try {
    flightRoot = await pairFlightRoot(baseSecret, slot);
    flightSecret = await pairFlightSecret(flightRoot, slot.kind, prebinding);
    routingTag = await pairFlightRoutingTag(flightSecret);
    const binding = snapshotBinding(
      await bindPairOuter(prebinding, routingTag),
    );
    aeadKey = await pairFlightAeadKey(flightSecret, binding);
    aad = await pairAad(binding);
    encodedPlaintext = await encodePairPlaintextV1(
      plaintext,
      prebinding.operationPayloadClass,
      false,
      options.roomPqMode,
    );
    const ciphertext = xchacha20Poly1305Seal(
      options.module,
      aeadKey,
      nonce,
      encodedPlaintext,
      aad,
    );
    const envelope = snapshotEnvelope(
      {
        version: PAIR_STEP_ENVELOPE_VERSION_V1,
        pairRoutingTag: binding.pairRoutingTag,
        bootstrapHeader: null,
        nonce,
        pairCiphertextAndTag: ciphertext,
      },
      prebinding.operationPayloadClass,
    );
    return {
      envelope,
      binding: snapshotBinding(binding),
      plaintext: await decodePairPlaintextV1(
        encodedPlaintext,
        prebinding.operationPayloadClass,
        false,
        options.roomPqMode,
      ),
    };
  } finally {
    baseSecret.fill(0);
    nonce.fill(0);
    flightRoot?.fill(0);
    flightSecret?.fill(0);
    routingTag?.fill(0);
    aeadKey?.fill(0);
    aad?.fill(0);
    encodedPlaintext?.fill(0);
  }
};

export interface OpenPairStepOptionsV1 {
  readonly module: LibCrypto;
  readonly baseSecret: Uint8Array;
  /** One member of the closed candidate-slot set selected by pair state. */
  readonly expectedSlot: PairFlightSlotV1;
  readonly prebinding: PairOuterPrebindingV1;
  readonly envelope: PairStepEnvelopeV1;
  readonly operationPayloadClass: OperationPayloadClassV1;
  readonly roomPqMode: RoomPqMode;
}

export interface OpenPairStepResultV1 {
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
}

/**
 * Try one state-selected established-flight slot. A tag/authentication
 * mismatch is `null`; authenticated slot/body/padding disagreement throws.
 */
export const openPairStepV1 = async (
  options: OpenPairStepOptionsV1,
): Promise<OpenPairStepResultV1 | null> => {
  const slot = snapshotSlot(options.expectedSlot);
  const prebinding = snapshotPrebinding(options.prebinding);
  const nonce = Uint8Array.from(assertEstablishedPrebinding(prebinding));
  const envelope = snapshotEnvelope(
    options.envelope,
    options.operationPayloadClass,
  );
  if (envelope.bootstrapHeader !== null || envelope.nonce === null)
    return fail("established pair open requires null header and a nonce");
  if (!fixedTimeEqual(nonce, envelope.nonce))
    return fail(
      "established envelope nonce does not match its outer prebinding",
    );
  if (prebinding.operationPayloadClass !== options.operationPayloadClass)
    return fail("pair prebinding payload class does not match the operation");
  const baseSecret = snapshotExactBytes(
    options.baseSecret,
    "pair base secret",
    32,
  );

  let flightRoot: Uint8Array | undefined;
  let flightSecret: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  let aeadKey: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let encodedPlaintext: Uint8Array | undefined;
  try {
    flightRoot = await pairFlightRoot(baseSecret, slot);
    flightSecret = await pairFlightSecret(flightRoot, slot.kind, prebinding);
    expectedTag = await pairFlightRoutingTag(flightSecret);
    if (!fixedTimeEqual(expectedTag, envelope.pairRoutingTag)) return null;

    const binding = snapshotBinding(
      await bindPairOuter(prebinding, expectedTag),
    );
    aeadKey = await pairFlightAeadKey(flightSecret, binding);
    aad = await pairAad(binding);
    encodedPlaintext =
      xchacha20Poly1305Open(
        options.module,
        aeadKey,
        nonce,
        envelope.pairCiphertextAndTag,
        aad,
      ) ?? undefined;
    if (encodedPlaintext === undefined) return null;
    const plaintext = await decodePairPlaintextV1(
      encodedPlaintext,
      options.operationPayloadClass,
      false,
      options.roomPqMode,
    );
    assertPlaintextSlot(plaintext, slot);
    return { binding: snapshotBinding(binding), plaintext };
  } finally {
    baseSecret.fill(0);
    nonce.fill(0);
    flightRoot?.fill(0);
    flightSecret?.fill(0);
    expectedTag?.fill(0);
    aeadKey?.fill(0);
    aad?.fill(0);
    encodedPlaintext?.fill(0);
  }
};
