import { chacha20Poly1305Open, chacha20Poly1305Seal } from "./chacha20poly1305";
import { snapshotByteInput } from "./byteInput";
import { shake256 } from "./fips202";
import {
  createMlKem768X25519Backend,
  MLKEM768_X25519_CIPHERTEXT_BYTES,
  MLKEM768_X25519_PUBLIC_KEY_BYTES,
  MLKEM768_X25519_RANDOM_BYTES,
  MLKEM768_X25519_SECRET_KEY_BYTES,
} from "./hybridKem";
import {
  HPKE_CHACHA20POLY1305_AEAD_ID,
  HPKE_HASH_BYTES,
  HPKE_HKDF_SHA256_KDF_ID,
  HPKE_KEY_BYTES,
  HPKE_MAX_APPLICATION_CONTEXT_BYTES,
  HPKE_MAX_EXPORT_BYTES,
  HPKE_MLKEM768_X25519_KEM_ID,
  HPKE_MODE_BASE,
  HPKE_MODE_PSK,
  HPKE_NONCE_BYTES,
  HPKE_PAIR_PSK_BYTES,
  HPKE_PAIR_PSK_ID_BYTES,
} from "./hpkeSuite";
import { hkdfSha256Expand, hkdfSha256Extract } from "./webCryptoSha256";

import type {
  MlKem768X25519Backend,
  MlKem768X25519Decapsulation,
  MlKem768X25519Encapsulation,
  MlKem768X25519KeyPair,
} from "./hybridKem";
import type { LibCrypto } from "./libcrypto";

export {
  HPKE_CHACHA20POLY1305_AEAD_ID,
  HPKE_HASH_BYTES,
  HPKE_HKDF_SHA256_KDF_ID,
  HPKE_KEY_BYTES,
  HPKE_MAX_APPLICATION_CONTEXT_BYTES,
  HPKE_MAX_EXPORT_BYTES,
  HPKE_MLKEM768_X25519_KEM_ID,
  HPKE_MLKEM768_X25519_SUITE,
  HPKE_MODE_BASE,
  HPKE_MODE_PSK,
  HPKE_NONCE_BYTES,
  HPKE_PAIR_PSK_BYTES,
  HPKE_PAIR_PSK_ID_BYTES,
  HPKE_TAG_BYTES,
} from "./hpkeSuite";

const textEncoder = new TextEncoder();
const HPKE_VERSION_LABEL = textEncoder.encode("HPKE-v1");
const DERIVE_KEY_PAIR_LABEL = textEncoder.encode("DeriveKeyPair");
const PSK_ID_HASH_LABEL = textEncoder.encode("psk_id_hash");
const INFO_HASH_LABEL = textEncoder.encode("info_hash");
const SECRET_LABEL = textEncoder.encode("secret");
const KEY_LABEL = textEncoder.encode("key");
const BASE_NONCE_LABEL = textEncoder.encode("base_nonce");
const EXPORTER_SECRET_LABEL = textEncoder.encode("exp");
const EXPORT_LABEL = textEncoder.encode("sec");
const MAX_SEQUENCE = (1n << BigInt(8 * HPKE_NONCE_BYTES)) - 1n;

const requireExactBytes = (
  value: Uint8Array,
  name: string,
  expectedLength: number,
): void => {
  if (value.length !== expectedLength)
    throw new RangeError(
      `HPKE ${name} must be exactly ${String(expectedLength)} bytes`,
    );
};

const requireApplicationContext = (value: Uint8Array, name: string): void => {
  if (value.length > HPKE_MAX_APPLICATION_CONTEXT_BYTES)
    throw new RangeError(
      `HPKE ${name} exceeds ${String(HPKE_MAX_APPLICATION_CONTEXT_BYTES)} bytes`,
    );
};

const requireExportLength = (length: number): void => {
  if (!Number.isSafeInteger(length))
    throw new TypeError("HPKE export length must be a safe integer");
  if (length < 1 || length > HPKE_MAX_EXPORT_BYTES)
    throw new RangeError(
      `HPKE export length must be between 1 and ${String(HPKE_MAX_EXPORT_BYTES)}`,
    );
};

const i2osp16 = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff)
    throw new RangeError("HPKE uint16 value is out of range");
  return Uint8Array.of(value >>> 8, value & 0xff);
};

const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const KEM_SUITE_ID = concatenate(
  textEncoder.encode("KEM"),
  i2osp16(HPKE_MLKEM768_X25519_KEM_ID),
);
const HPKE_SUITE_ID = concatenate(
  textEncoder.encode("HPKE"),
  i2osp16(HPKE_MLKEM768_X25519_KEM_ID),
  i2osp16(HPKE_HKDF_SHA256_KDF_ID),
  i2osp16(HPKE_CHACHA20POLY1305_AEAD_ID),
);

/**
 * The single-stage SHAKE256 LabeledDerive used only by this KEM's HPKE
 * DeriveKeyPair mapping. Its ordering intentionally differs from the
 * two-stage HKDF labels below.
 */
const kemLabeledDeriveKeyPairSeed = (
  ikm: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const transcript = concatenate(
    ikm,
    HPKE_VERSION_LABEL,
    KEM_SUITE_ID,
    i2osp16(DERIVE_KEY_PAIR_LABEL.length),
    DERIVE_KEY_PAIR_LABEL,
    i2osp16(MLKEM768_X25519_SECRET_KEY_BYTES),
  );
  try {
    return shake256(transcript, MLKEM768_X25519_SECRET_KEY_BYTES, module);
  } finally {
    transcript.fill(0);
  }
};

const labeledExtract = async (
  salt: Uint8Array,
  label: Uint8Array,
  ikm: Uint8Array,
): Promise<Uint8Array> => {
  const labeledIkm = concatenate(HPKE_VERSION_LABEL, HPKE_SUITE_ID, label, ikm);
  try {
    return await hkdfSha256Extract(salt, labeledIkm);
  } finally {
    labeledIkm.fill(0);
  }
};

const labeledExpand = async (
  pseudorandomKey: Uint8Array,
  label: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> => {
  const labeledInfo = concatenate(
    i2osp16(length),
    HPKE_VERSION_LABEL,
    HPKE_SUITE_ID,
    label,
    info,
  );
  try {
    return await hkdfSha256Expand(pseudorandomKey, labeledInfo, length);
  } finally {
    labeledInfo.fill(0);
  }
};

interface ContextSecrets {
  readonly key: Uint8Array;
  readonly baseNonce: Uint8Array;
  readonly exporterSecret: Uint8Array;
}

const wipeContextSecrets = (secrets: ContextSecrets | undefined): void => {
  secrets?.key.fill(0);
  secrets?.baseNonce.fill(0);
  secrets?.exporterSecret.fill(0);
};

const keySchedule = async (
  mode: typeof HPKE_MODE_BASE | typeof HPKE_MODE_PSK,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array,
  pskId: Uint8Array,
): Promise<ContextSecrets> => {
  let pskIdHash: Uint8Array | undefined;
  let infoHash: Uint8Array | undefined;
  let keyScheduleContext: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let baseNonce: Uint8Array | undefined;
  let exporterSecret: Uint8Array | undefined;
  let transferred = false;

  try {
    pskIdHash = await labeledExtract(
      new Uint8Array(0),
      PSK_ID_HASH_LABEL,
      pskId,
    );
    infoHash = await labeledExtract(new Uint8Array(0), INFO_HASH_LABEL, info);
    keyScheduleContext = concatenate(Uint8Array.of(mode), pskIdHash, infoHash);
    secret = await labeledExtract(sharedSecret, SECRET_LABEL, psk);
    key = await labeledExpand(
      secret,
      KEY_LABEL,
      keyScheduleContext,
      HPKE_KEY_BYTES,
    );
    baseNonce = await labeledExpand(
      secret,
      BASE_NONCE_LABEL,
      keyScheduleContext,
      HPKE_NONCE_BYTES,
    );
    exporterSecret = await labeledExpand(
      secret,
      EXPORTER_SECRET_LABEL,
      keyScheduleContext,
      HPKE_HASH_BYTES,
    );

    const result = { key, baseNonce, exporterSecret };
    transferred = true;
    return result;
  } finally {
    pskIdHash?.fill(0);
    infoHash?.fill(0);
    keyScheduleContext?.fill(0);
    secret?.fill(0);
    if (!transferred) {
      key?.fill(0);
      baseNonce?.fill(0);
      exporterSecret?.fill(0);
    }
  }
};

export interface HpkeContext {
  readonly sequence: bigint;
  readonly destroyed: boolean;
  /**
   * RFC 9180 Export. It does not consume a nonce and has no replay protection.
   */
  exportSecret(
    exporterContext: Uint8Array,
    length: number,
  ): Promise<Uint8Array>;
  /** Idempotently wipe the AEAD and exporter state. */
  destroy(): void;
}

export interface HpkeSenderContext extends HpkeContext {
  readonly role: "sender";
  seal(associatedData: Uint8Array, plaintext: Uint8Array): Uint8Array;
}

export interface HpkeRecipientContext extends HpkeContext {
  readonly role: "recipient";
  /**
   * Return null on authentication failure. A failed Open does not advance the
   * sequence number.
   */
  open(
    associatedData: Uint8Array,
    ciphertextAndTag: Uint8Array,
  ): Uint8Array | null;
}

abstract class HpkeContextBase implements HpkeContext {
  readonly #module: LibCrypto;
  readonly #key: Uint8Array;
  readonly #baseNonce: Uint8Array;
  readonly #exporterSecret: Uint8Array;
  #sequence = 0n;
  #destroyed = false;

  protected constructor(module: LibCrypto, secrets: ContextSecrets) {
    this.#module = module;
    this.#key = secrets.key;
    this.#baseNonce = secrets.baseNonce;
    this.#exporterSecret = secrets.exporterSecret;
  }

  get sequence(): bigint {
    return this.#sequence;
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  protected get module(): LibCrypto {
    return this.#module;
  }

  protected get key(): Uint8Array {
    return this.#key;
  }

  protected nextNonce(): Uint8Array {
    this.assertUsable();
    // RFC 9180 fails an operation that would overflow during IncrementSeq.
    if (this.#sequence >= MAX_SEQUENCE)
      throw new Error("HPKE message limit reached");

    const nonce = Uint8Array.from(this.#baseNonce);
    let counter = this.#sequence;
    for (let index = nonce.length - 1; index >= 0; index--) {
      nonce[index] ^= Number(counter & 0xffn);
      counter >>= 8n;
    }
    return nonce;
  }

  protected incrementSequence(): void {
    this.#sequence += 1n;
  }

  protected assertUsable(): void {
    if (this.#destroyed) throw new Error("HPKE context is destroyed");
  }

  exportSecret(
    exporterContext: Uint8Array,
    length: number,
  ): Promise<Uint8Array> {
    this.assertUsable();
    requireExportLength(length);
    const privateExporterContext = snapshotByteInput(
      exporterContext,
      "HPKE exporterContext",
      { maximumLength: HPKE_MAX_APPLICATION_CONTEXT_BYTES },
    );
    const privateExporterSecret = Uint8Array.from(this.#exporterSecret);
    return this.exportOwned(
      privateExporterSecret,
      privateExporterContext,
      length,
    );
  }

  private async exportOwned(
    exporterSecret: Uint8Array,
    exporterContext: Uint8Array,
    length: number,
  ): Promise<Uint8Array> {
    try {
      return await labeledExpand(
        exporterSecret,
        EXPORT_LABEL,
        exporterContext,
        length,
      );
    } finally {
      exporterSecret.fill(0);
      exporterContext.fill(0);
    }
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#key.fill(0);
    this.#baseNonce.fill(0);
    this.#exporterSecret.fill(0);
    this.#destroyed = true;
  }
}

class HpkeSenderContextImpl
  extends HpkeContextBase
  implements HpkeSenderContext
{
  readonly role = "sender" as const;

  constructor(module: LibCrypto, secrets: ContextSecrets) {
    super(module, secrets);
  }

  seal(associatedData: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const nonce = this.nextNonce();
    try {
      const ciphertext = chacha20Poly1305Seal(
        this.module,
        this.key,
        nonce,
        plaintext,
        associatedData,
      );
      this.incrementSequence();
      return ciphertext;
    } finally {
      nonce.fill(0);
    }
  }
}

class HpkeRecipientContextImpl
  extends HpkeContextBase
  implements HpkeRecipientContext
{
  readonly role = "recipient" as const;

  constructor(module: LibCrypto, secrets: ContextSecrets) {
    super(module, secrets);
  }

  open(
    associatedData: Uint8Array,
    ciphertextAndTag: Uint8Array,
  ): Uint8Array | null {
    const nonce = this.nextNonce();
    try {
      const plaintext = chacha20Poly1305Open(
        this.module,
        this.key,
        nonce,
        ciphertextAndTag,
        associatedData,
      );
      if (plaintext !== null) this.incrementSequence();
      return plaintext;
    } finally {
      nonce.fill(0);
    }
  }
}

export interface HpkePskSenderSetup {
  readonly encapsulatedKey: Uint8Array;
  readonly context: HpkeSenderContext;
}

export interface HpkePskSenderOptions {
  readonly module: LibCrypto;
  readonly recipientPublicKey: Uint8Array;
  readonly info: Uint8Array;
  /** Pair suite 1 requires the exact 32-byte RoomRoot or HelloRoot. */
  readonly psk: Uint8Array;
  /** Pair suite 1 requires the exact 32-byte transcript-derived PSK ID. */
  readonly pskId: Uint8Array;
}

export interface HpkePskRecipientOptions {
  readonly module: LibCrypto;
  readonly encapsulatedKey: Uint8Array;
  readonly recipientSecretKey: Uint8Array;
  readonly info: Uint8Array;
  readonly psk: Uint8Array;
  readonly pskId: Uint8Array;
}

interface OwnedSenderInputs {
  readonly recipientPublicKey: Uint8Array;
  readonly info: Uint8Array;
  readonly psk: Uint8Array;
  readonly pskId: Uint8Array;
  readonly randomness?: Uint8Array;
}

const validatePskSenderInputs = (
  options: HpkePskSenderOptions,
  randomness?: Uint8Array,
): OwnedSenderInputs => {
  let recipientPublicKey: Uint8Array | undefined;
  let info: Uint8Array | undefined;
  let psk: Uint8Array | undefined;
  let pskId: Uint8Array | undefined;
  let privateRandomness: Uint8Array | undefined;
  let transferred = false;
  try {
    recipientPublicKey = snapshotByteInput(
      options.recipientPublicKey,
      "HPKE recipientPublicKey",
      { exactLength: MLKEM768_X25519_PUBLIC_KEY_BYTES },
    );
    info = snapshotByteInput(options.info, "HPKE info", {
      maximumLength: HPKE_MAX_APPLICATION_CONTEXT_BYTES,
    });
    psk = snapshotByteInput(options.psk, "HPKE psk", {
      exactLength: HPKE_PAIR_PSK_BYTES,
    });
    pskId = snapshotByteInput(options.pskId, "HPKE pskId", {
      exactLength: HPKE_PAIR_PSK_ID_BYTES,
    });
    privateRandomness =
      randomness === undefined
        ? undefined
        : snapshotByteInput(randomness, "HPKE encapsulationRandomness", {
            exactLength: MLKEM768_X25519_RANDOM_BYTES,
          });
    requireExactBytes(
      recipientPublicKey,
      "recipientPublicKey",
      MLKEM768_X25519_PUBLIC_KEY_BYTES,
    );
    requireApplicationContext(info, "info");
    requireExactBytes(psk, "psk", HPKE_PAIR_PSK_BYTES);
    requireExactBytes(pskId, "pskId", HPKE_PAIR_PSK_ID_BYTES);
    if (privateRandomness !== undefined)
      requireExactBytes(
        privateRandomness,
        "encapsulationRandomness",
        MLKEM768_X25519_RANDOM_BYTES,
      );
    const result = {
      recipientPublicKey,
      info,
      psk,
      pskId,
      randomness: privateRandomness,
    };
    transferred = true;
    return result;
  } finally {
    if (!transferred) {
      recipientPublicKey?.fill(0);
      info?.fill(0);
      psk?.fill(0);
      pskId?.fill(0);
      privateRandomness?.fill(0);
    }
  }
};

const setupSenderOwned = async (
  module: LibCrypto,
  mode: typeof HPKE_MODE_BASE | typeof HPKE_MODE_PSK,
  inputs: OwnedSenderInputs,
): Promise<HpkePskSenderSetup> => {
  let kem: MlKem768X25519Backend | undefined;
  let encapsulation: MlKem768X25519Encapsulation | undefined;
  let contextSecrets: ContextSecrets | undefined;
  let transferred = false;

  try {
    kem = createMlKem768X25519Backend(module);
    encapsulation =
      inputs.randomness === undefined
        ? await kem.encapsulate(inputs.recipientPublicKey)
        : await kem.encapsulateDeterministically(
            inputs.recipientPublicKey,
            inputs.randomness,
          );
    contextSecrets = await keySchedule(
      mode,
      encapsulation.sharedSecret,
      inputs.info,
      inputs.psk,
      inputs.pskId,
    );
    const context = new HpkeSenderContextImpl(module, contextSecrets);
    const result = {
      encapsulatedKey: Uint8Array.from(encapsulation.ciphertext),
      context,
    };
    transferred = true;
    return result;
  } finally {
    encapsulation?.destroy();
    inputs.recipientPublicKey.fill(0);
    inputs.info.fill(0);
    inputs.psk.fill(0);
    inputs.pskId.fill(0);
    inputs.randomness?.fill(0);
    if (!transferred) wipeContextSecrets(contextSecrets);
  }
};

/** RFC 9180 SetupPSKS for the fixed pair-bootstrap suite. */
export const setupHpkePskSender = (
  options: HpkePskSenderOptions,
): Promise<HpkePskSenderSetup> =>
  setupSenderOwned(
    options.module,
    HPKE_MODE_PSK,
    validatePskSenderInputs(options),
  );

/**
 * Deterministic SetupPSKS hook for pinned vectors only.
 *
 * Reusing or predicting its 64-byte randomness destroys KEM security. Normal
 * protocol code must call setupHpkePskSender(), which obtains fresh CSPRNG
 * bytes internally.
 *
 * @internal
 */
export const setupHpkePskSenderDeterministically = (
  options: HpkePskSenderOptions & {
    readonly encapsulationRandomness: Uint8Array;
  },
): Promise<HpkePskSenderSetup> =>
  setupSenderOwned(
    options.module,
    HPKE_MODE_PSK,
    validatePskSenderInputs(options, options.encapsulationRandomness),
  );

const validatePskRecipientInputs = (
  options: HpkePskRecipientOptions,
): {
  readonly encapsulatedKey: Uint8Array;
  readonly recipientSecretKey: Uint8Array;
  readonly info: Uint8Array;
  readonly psk: Uint8Array;
  readonly pskId: Uint8Array;
} => {
  let encapsulatedKey: Uint8Array | undefined;
  let recipientSecretKey: Uint8Array | undefined;
  let info: Uint8Array | undefined;
  let psk: Uint8Array | undefined;
  let pskId: Uint8Array | undefined;
  let transferred = false;
  try {
    encapsulatedKey = snapshotByteInput(
      options.encapsulatedKey,
      "HPKE encapsulatedKey",
      { exactLength: MLKEM768_X25519_CIPHERTEXT_BYTES },
    );
    recipientSecretKey = snapshotByteInput(
      options.recipientSecretKey,
      "HPKE recipientSecretKey",
      { exactLength: MLKEM768_X25519_SECRET_KEY_BYTES },
    );
    info = snapshotByteInput(options.info, "HPKE info", {
      maximumLength: HPKE_MAX_APPLICATION_CONTEXT_BYTES,
    });
    psk = snapshotByteInput(options.psk, "HPKE psk", {
      exactLength: HPKE_PAIR_PSK_BYTES,
    });
    pskId = snapshotByteInput(options.pskId, "HPKE pskId", {
      exactLength: HPKE_PAIR_PSK_ID_BYTES,
    });
    requireExactBytes(
      encapsulatedKey,
      "encapsulatedKey",
      MLKEM768_X25519_CIPHERTEXT_BYTES,
    );
    requireExactBytes(
      recipientSecretKey,
      "recipientSecretKey",
      MLKEM768_X25519_SECRET_KEY_BYTES,
    );
    requireApplicationContext(info, "info");
    requireExactBytes(psk, "psk", HPKE_PAIR_PSK_BYTES);
    requireExactBytes(pskId, "pskId", HPKE_PAIR_PSK_ID_BYTES);
    const result = {
      encapsulatedKey,
      recipientSecretKey,
      info,
      psk,
      pskId,
    };
    transferred = true;
    return result;
  } finally {
    if (!transferred) {
      encapsulatedKey?.fill(0);
      recipientSecretKey?.fill(0);
      info?.fill(0);
      psk?.fill(0);
      pskId?.fill(0);
    }
  }
};

const setupRecipientOwned = async (
  module: LibCrypto,
  mode: typeof HPKE_MODE_BASE | typeof HPKE_MODE_PSK,
  inputs: ReturnType<typeof validatePskRecipientInputs>,
): Promise<HpkeRecipientContext> => {
  let kem: MlKem768X25519Backend | undefined;
  let decapsulation: MlKem768X25519Decapsulation | undefined;
  let contextSecrets: ContextSecrets | undefined;
  let transferred = false;

  try {
    kem = createMlKem768X25519Backend(module);
    decapsulation = await kem.decapsulate(
      inputs.encapsulatedKey,
      inputs.recipientSecretKey,
    );
    contextSecrets = await keySchedule(
      mode,
      decapsulation.sharedSecret,
      inputs.info,
      inputs.psk,
      inputs.pskId,
    );
    const context = new HpkeRecipientContextImpl(module, contextSecrets);
    transferred = true;
    return context;
  } finally {
    decapsulation?.destroy();
    inputs.encapsulatedKey.fill(0);
    inputs.recipientSecretKey.fill(0);
    inputs.info.fill(0);
    inputs.psk.fill(0);
    inputs.pskId.fill(0);
    if (!transferred) wipeContextSecrets(contextSecrets);
  }
};

/** RFC 9180 SetupPSKR for the fixed pair-bootstrap suite. */
export const setupHpkePskRecipient = (
  options: HpkePskRecipientOptions,
): Promise<HpkeRecipientContext> =>
  setupRecipientOwned(
    options.module,
    HPKE_MODE_PSK,
    validatePskRecipientInputs(options),
  );

/**
 * Generate a production recipient key pair using the hybrid KEM's CSPRNG path.
 */
export const generateHpkeRecipientKeyPair = (
  module: LibCrypto,
): Promise<MlKem768X25519KeyPair> =>
  createMlKem768X25519Backend(module).generateKeyPair();

/**
 * HPKE KEM DeriveKeyPair mapping used by the official conformance vectors.
 * The pair profile restricts IKM to one exact 32-byte seed.
 */
export const deriveHpkeRecipientKeyPair = (
  ikm: Uint8Array,
  module: LibCrypto,
): Promise<MlKem768X25519KeyPair> => {
  const privateIkm = snapshotByteInput(ikm, "HPKE recipient key IKM", {
    exactLength: MLKEM768_X25519_SECRET_KEY_BYTES,
  });
  requireExactBytes(
    privateIkm,
    "recipient key IKM",
    MLKEM768_X25519_SECRET_KEY_BYTES,
  );
  return deriveRecipientKeyPairOwned(privateIkm, module);
};

const deriveRecipientKeyPairOwned = async (
  ikm: Uint8Array,
  module: LibCrypto,
): Promise<MlKem768X25519KeyPair> => {
  let seed: Uint8Array | undefined;
  try {
    seed = kemLabeledDeriveKeyPairSeed(ikm, module);
    return await createMlKem768X25519Backend(module).deriveKeyPair(seed);
  } finally {
    seed?.fill(0);
    ikm.fill(0);
  }
};

/**
 * Base-mode deterministic setup exists solely to verify the official
 * draft-ietf-hpke-pq vector for this exact KEM/KDF/AEAD tuple. Pair protocol
 * code must never use base mode.
 *
 * @internal
 */
export const setupHpkeBaseSenderForConformance = (options: {
  readonly module: LibCrypto;
  readonly recipientPublicKey: Uint8Array;
  readonly info: Uint8Array;
  readonly encapsulationRandomness: Uint8Array;
}): Promise<HpkePskSenderSetup> => {
  const empty = new Uint8Array(0);
  let recipientPublicKey: Uint8Array | undefined;
  let info: Uint8Array | undefined;
  let randomness: Uint8Array | undefined;
  let transferred = false;
  try {
    recipientPublicKey = snapshotByteInput(
      options.recipientPublicKey,
      "HPKE recipientPublicKey",
      { exactLength: MLKEM768_X25519_PUBLIC_KEY_BYTES },
    );
    info = snapshotByteInput(options.info, "HPKE info", {
      maximumLength: HPKE_MAX_APPLICATION_CONTEXT_BYTES,
    });
    randomness = snapshotByteInput(
      options.encapsulationRandomness,
      "HPKE encapsulationRandomness",
      { exactLength: MLKEM768_X25519_RANDOM_BYTES },
    );
    requireExactBytes(
      recipientPublicKey,
      "recipientPublicKey",
      MLKEM768_X25519_PUBLIC_KEY_BYTES,
    );
    requireApplicationContext(info, "info");
    requireExactBytes(
      randomness,
      "encapsulationRandomness",
      MLKEM768_X25519_RANDOM_BYTES,
    );
    const result = setupSenderOwned(options.module, HPKE_MODE_BASE, {
      recipientPublicKey,
      info,
      psk: empty,
      pskId: new Uint8Array(0),
      randomness,
    });
    transferred = true;
    return result;
  } finally {
    if (!transferred) {
      recipientPublicKey?.fill(0);
      info?.fill(0);
      randomness?.fill(0);
      empty.fill(0);
    }
  }
};
