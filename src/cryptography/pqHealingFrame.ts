import { hkdfExpand, hkdfExtract } from "./hkdf";
import {
  decodePqHealingAck,
  inspectPqHealingRecord,
  PQ_HEALING_ACK_BYTES,
  PQ_HEALING_BINDING_BYTES,
  PQ_HEALING_ROOT_BYTES,
} from "./pqHealing";
import { getMlKemSuite } from "./mlkem";
import {
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";
import {
  FRAME_TYPE_LEN,
  FRAME_TYPE_PQ_CONTROL,
  PQ_EPOCH_LEN,
  RATCHET_DHPUB_LEN,
  RATCHET_N_LEN,
  RATCHET_NONCE_LEN,
  RATCHET_PN_LEN,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";
import type { MlKemParameterSet, MlKemSuiteDescriptor } from "./mlkem";

/**
 * PQ controls reuse the protocol-v4 uniform cell geometry:
 *
 * `type(1) | edge-control-id(32) | counter(8) | reserved(8) | epoch(8) |
 * nonce(12) | encrypted(recordLength(4) | record | zero padding) | tag(16)`.
 *
 * The complete 69-byte public header, including the nonce, is AEAD AAD.
 */
const CONTROL_ID_OFFSET = FRAME_TYPE_LEN;
const COUNTER_OFFSET = CONTROL_ID_OFFSET + RATCHET_DHPUB_LEN;
const RESERVED_OFFSET = COUNTER_OFFSET + RATCHET_N_LEN;
const EPOCH_OFFSET = RESERVED_OFFSET + RATCHET_PN_LEN;
const NONCE_OFFSET = EPOCH_OFFSET + PQ_EPOCH_LEN;

export const PQ_CONTROL_FRAME_HEADER_BYTES =
  FRAME_TYPE_LEN +
  RATCHET_DHPUB_LEN +
  RATCHET_N_LEN +
  RATCHET_PN_LEN +
  PQ_EPOCH_LEN +
  RATCHET_NONCE_LEN;
export const PQ_CONTROL_FRAME_PLAINTEXT_BYTES =
  WIRE_CHUNK_FRAME_LEN -
  PQ_CONTROL_FRAME_HEADER_BYTES -
  crypto_aead_chacha20poly1305_ietf_ABYTES;

const RECORD_LENGTH_BYTES = 4;
const MAX_U64 = (1n << 64n) - 1n;
const KEY_DOMAIN = new TextEncoder().encode(
  "p2party/pq-control-frame/key/v1\u0000",
);

export type PqControlDirection =
  "initiator-to-responder" | "responder-to-initiator";

export type PqControlFrameErrorCode =
  | "authentication-failed"
  | "binding-mismatch"
  | "epoch-mismatch"
  | "invalid-direction"
  | "invalid-frame"
  | "invalid-padding"
  | "record-mismatch";

export class PqControlFrameError extends Error {
  readonly code: PqControlFrameErrorCode;

  constructor(code: PqControlFrameErrorCode, message: string) {
    super(`pqHealingFrame: ${message}`);
    this.name = "PqControlFrameError";
    this.code = code;
  }
}

export interface SealPqControlFrameOptions<
  P extends MlKemParameterSet = MlKemParameterSet,
> {
  readonly module: LibCrypto;
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;
  readonly rootKey: Uint8Array;
  readonly binding: Uint8Array;
  readonly direction: PqControlDirection;
  /** Epoch whose PQ root authenticates this frame. */
  readonly keyEpoch: bigint;
  /** Exact canonical OFFER, ADVANCE, or 64-byte ACK. */
  readonly record: Uint8Array;
}

export interface OpenPqControlFrameOptions<
  P extends MlKemParameterSet = MlKemParameterSet,
> {
  readonly module: LibCrypto;
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;
  readonly rootKey: Uint8Array;
  readonly binding: Uint8Array;
  /** Expected inbound direction; the opposite direction derives another key. */
  readonly direction: PqControlDirection;
  /** Exact expected authentication epoch. */
  readonly keyEpoch: bigint;
  readonly frame: Uint8Array;
}

const fail = (code: PqControlFrameErrorCode, message: string): never => {
  throw new PqControlFrameError(code, message);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= left[index] ^ right[index];
  return difference === 0;
};

const requireBytes = (
  value: unknown,
  name: string,
  length?: number,
): Uint8Array => {
  if (!(value instanceof Uint8Array))
    return fail("invalid-frame", `${name} must be a Uint8Array`);
  if (length !== undefined && value.length !== length)
    fail("invalid-frame", `${name} must be exactly ${String(length)} bytes`);
  return value;
};

const requireU64 = (value: unknown, name: string): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    return fail("invalid-frame", `${name} must be an unsigned 64-bit bigint`);
  return value;
};

const directionTag = (direction: unknown): number => {
  if (direction === "initiator-to-responder") return 1;
  if (direction === "responder-to-initiator") return 2;
  return fail("invalid-direction", "control direction is unknown");
};

const suiteTag = (suite: Readonly<MlKemSuiteDescriptor>): number => {
  const canonical = getMlKemSuite(suite.parameterSet);
  if (
    suite.standardName !== canonical.standardName ||
    suite.publicKeyBytes !== canonical.publicKeyBytes ||
    suite.secretKeyBytes !== canonical.secretKeyBytes ||
    suite.ciphertextBytes !== canonical.ciphertextBytes ||
    suite.sharedSecretBytes !== canonical.sharedSecretBytes ||
    suite.keyPairRandomBytes !== canonical.keyPairRandomBytes ||
    suite.encapsRandomBytes !== canonical.encapsRandomBytes
  )
    return fail("invalid-frame", "ML-KEM suite descriptor is not canonical");
  if (suite.parameterSet === 768) return 1;
  if (suite.parameterSet === 512) return 2;
  if (suite.parameterSet === 1024) return 3;
  return fail("invalid-frame", "ML-KEM suite is unsupported");
};

const encodeU64 = (value: bigint): Uint8Array => {
  const encoded = new Uint8Array(8);
  new DataView(encoded.buffer).setBigUint64(0, value, false);
  return encoded;
};

const deriveFrameKey = (
  module: LibCrypto,
  suite: Readonly<MlKemSuiteDescriptor>,
  rootKey: Uint8Array,
  binding: Uint8Array,
  direction: PqControlDirection,
  keyEpoch: bigint,
): Uint8Array => {
  requireBytes(rootKey, "PQ root", PQ_HEALING_ROOT_BYTES);
  requireBytes(binding, "binding", PQ_HEALING_BINDING_BYTES);
  const epochBytes = encodeU64(requireU64(keyEpoch, "keyEpoch"));
  const info = new Uint8Array(
    KEY_DOMAIN.length + 1 + 1 + binding.length + epochBytes.length,
  );
  info.set(KEY_DOMAIN, 0);
  info[KEY_DOMAIN.length] = suiteTag(suite);
  info[KEY_DOMAIN.length + 1] = directionTag(direction);
  info.set(binding, KEY_DOMAIN.length + 2);
  info.set(epochBytes, KEY_DOMAIN.length + 2 + binding.length);

  const prk = hkdfExtract(rootKey, binding, module);
  try {
    return hkdfExpand(
      prk,
      info,
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
      module,
    );
  } finally {
    prk.fill(0);
    epochBytes.fill(0);
  }
};

interface InspectedControlRecord {
  readonly counter: bigint;
  readonly keyEpoch: bigint;
}

const inspectControlRecord = (
  record: Uint8Array,
  suite: Readonly<MlKemSuiteDescriptor>,
  binding: Uint8Array,
): InspectedControlRecord => {
  requireBytes(record, "control record");
  if (record.length === PQ_HEALING_ACK_BYTES) {
    const ack = decodePqHealingAck(record, suite, binding);
    return { counter: ack.advanceCounter, keyEpoch: ack.epoch };
  }

  const inspected = inspectPqHealingRecord(record, suite);
  if (!bytesEqual(inspected.binding, binding))
    return fail(
      "binding-mismatch",
      "control record belongs to another authenticated edge",
    );
  return {
    counter: inspected.senderCounter,
    keyEpoch: inspected.fromEpoch,
  };
};

const randomNonce = (): Uint8Array => {
  const nonce = new Uint8Array(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  crypto.getRandomValues(nonce);
  return nonce;
};

const aeadSeal = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array => {
  const outputLength =
    plaintext.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const plaintextPtr = module._malloc(plaintext.length);
  const aadPtr = module._malloc(aad.length);
  const outputPtr = module._malloc(outputLength);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(
      module.wasmMemory.buffer,
      plaintextPtr,
      plaintext.length,
    ).set(plaintext);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);
    const result = module._encrypt_chachapoly_symmetric(
      outputPtr,
      plaintextPtr,
      plaintext.length,
      keyPtr,
      noncePtr,
      aadPtr,
      aad.length,
    );
    if (result !== 0)
      return fail("invalid-frame", "control-frame AEAD encryption failed");
    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, plaintextPtr, plaintext.length),
    );
    module._free(aadPtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, outputPtr, outputLength),
    );
  }
};

const aeadOpen = (
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array => {
  const plaintextLength =
    ciphertext.length - crypto_aead_chacha20poly1305_ietf_ABYTES;
  const keyPtr = module._malloc(key.length);
  const noncePtr = module._malloc(nonce.length);
  const ciphertextPtr = module._malloc(ciphertext.length);
  const aadPtr = module._malloc(aad.length);
  const plaintextPtr = module._malloc(plaintextLength);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, noncePtr, nonce.length).set(nonce);
    new Uint8Array(
      module.wasmMemory.buffer,
      ciphertextPtr,
      ciphertext.length,
    ).set(ciphertext);
    new Uint8Array(module.wasmMemory.buffer, aadPtr, aad.length).set(aad);
    const plaintextHeap = new Uint8Array(
      module.wasmMemory.buffer,
      plaintextPtr,
      plaintextLength,
    );
    plaintextHeap.fill(0);
    const result = module._decrypt_chachapoly_symmetric(
      plaintextPtr,
      ciphertextPtr,
      ciphertext.length,
      keyPtr,
      noncePtr,
      aadPtr,
      aad.length,
    );
    if (result !== 0)
      return fail(
        "authentication-failed",
        "control-frame authentication failed",
      );
    return Uint8Array.from(plaintextHeap);
  } finally {
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length),
    );
    module._free(noncePtr);
    module._free(ciphertextPtr);
    module._free(aadPtr);
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, plaintextPtr, plaintextLength),
    );
  }
};

/** Seal one exact canonical control record into a fixed-size v4 cell. */
export const sealPqControlFrame = <P extends MlKemParameterSet>(
  options: SealPqControlFrameOptions<P>,
): Uint8Array => {
  const binding = requireBytes(
    options.binding,
    "binding",
    PQ_HEALING_BINDING_BYTES,
  );
  const keyEpoch = requireU64(options.keyEpoch, "keyEpoch");
  const inspected = inspectControlRecord(
    options.record,
    options.suite,
    binding,
  );
  if (inspected.keyEpoch !== keyEpoch)
    fail(
      "epoch-mismatch",
      "control record is not authenticated under its required epoch",
    );
  if (
    options.record.length >
    PQ_CONTROL_FRAME_PLAINTEXT_BYTES - RECORD_LENGTH_BYTES
  )
    fail("invalid-frame", "control record does not fit the uniform cell");

  const nonce = randomNonce();
  const header = new Uint8Array(PQ_CONTROL_FRAME_HEADER_BYTES);
  header[0] = FRAME_TYPE_PQ_CONTROL;
  header.set(binding, CONTROL_ID_OFFSET);
  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  );
  view.setBigUint64(COUNTER_OFFSET, inspected.counter, false);
  // RESERVED_OFFSET remains canonical zero.
  view.setBigUint64(EPOCH_OFFSET, keyEpoch, false);
  header.set(nonce, NONCE_OFFSET);

  const plaintext = new Uint8Array(PQ_CONTROL_FRAME_PLAINTEXT_BYTES);
  new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  ).setUint32(0, options.record.length, false);
  plaintext.set(options.record, RECORD_LENGTH_BYTES);

  const key = deriveFrameKey(
    options.module,
    options.suite,
    options.rootKey,
    binding,
    options.direction,
    keyEpoch,
  );
  try {
    const ciphertext = aeadSeal(options.module, key, nonce, plaintext, header);
    const frame = new Uint8Array(WIRE_CHUNK_FRAME_LEN);
    frame.set(header, 0);
    frame.set(ciphertext, PQ_CONTROL_FRAME_HEADER_BYTES);
    return frame;
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
};

/**
 * Authenticate a fixed-size cell and return an owned exact canonical record.
 * The caller supplies the expected edge, direction, suite, root, and epoch.
 */
export const openPqControlFrame = <P extends MlKemParameterSet>(
  options: OpenPqControlFrameOptions<P>,
): Uint8Array => {
  const frame = requireBytes(
    options.frame,
    "control frame",
    WIRE_CHUNK_FRAME_LEN,
  );
  const binding = requireBytes(
    options.binding,
    "binding",
    PQ_HEALING_BINDING_BYTES,
  );
  const keyEpoch = requireU64(options.keyEpoch, "keyEpoch");
  if (frame[0] !== FRAME_TYPE_PQ_CONTROL)
    fail("invalid-frame", "frame type is not PQ control");
  if (
    !bytesEqual(
      frame.subarray(CONTROL_ID_OFFSET, CONTROL_ID_OFFSET + RATCHET_DHPUB_LEN),
      binding,
    )
  )
    fail("binding-mismatch", "control frame belongs to another edge");

  const header = frame.subarray(0, PQ_CONTROL_FRAME_HEADER_BYTES);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const headerCounter = view.getBigUint64(COUNTER_OFFSET, false);
  if (view.getBigUint64(RESERVED_OFFSET, false) !== 0n)
    fail("invalid-frame", "control-frame reserved header must be zero");
  if (view.getBigUint64(EPOCH_OFFSET, false) !== keyEpoch)
    fail("epoch-mismatch", "control-frame epoch is not the expected epoch");

  const nonce = frame.subarray(NONCE_OFFSET, NONCE_OFFSET + RATCHET_NONCE_LEN);
  const ciphertext = frame.subarray(PQ_CONTROL_FRAME_HEADER_BYTES);
  const key = deriveFrameKey(
    options.module,
    options.suite,
    options.rootKey,
    binding,
    options.direction,
    keyEpoch,
  );
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = aeadOpen(options.module, key, nonce, ciphertext, header);
    const recordLength = new DataView(
      plaintext.buffer,
      plaintext.byteOffset,
      plaintext.byteLength,
    ).getUint32(0, false);
    if (
      recordLength === 0 ||
      recordLength > PQ_CONTROL_FRAME_PLAINTEXT_BYTES - RECORD_LENGTH_BYTES
    )
      fail("invalid-padding", "encrypted control-record length is invalid");
    const paddingOffset = RECORD_LENGTH_BYTES + recordLength;
    let nonzeroPadding = 0;
    for (let index = paddingOffset; index < plaintext.length; index += 1)
      nonzeroPadding |= plaintext[index];
    if (nonzeroPadding !== 0)
      fail("invalid-padding", "encrypted control padding must be all zero");

    const record = plaintext.slice(RECORD_LENGTH_BYTES, paddingOffset);
    const inspected = inspectControlRecord(record, options.suite, binding);
    if (inspected.keyEpoch !== keyEpoch)
      fail(
        "epoch-mismatch",
        "decrypted control record does not match its frame epoch",
      );
    if (inspected.counter !== headerCounter)
      fail(
        "record-mismatch",
        "decrypted control counter does not match its public header",
      );
    return record;
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
};
