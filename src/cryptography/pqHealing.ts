import { hkdfExpand, hkdfExtract } from "./hkdf";
import {
  getMlKemSuite,
  type MlKemBackend,
  type MlKemKeyPair,
  type MlKemParameterSet,
  type MlKemSuiteDescriptor,
} from "./mlkem";

import type { LibCrypto } from "./libcrypto";

/**
 * Sparse post-quantum healing state machine.
 *
 * This module deliberately does not own transport or persistence. Callers must:
 *
 * 1. authenticate/decrypt every inbound record with the current outer channel
 *    before calling an `acceptAuthenticated*` method;
 * 2. persist prepared state before putting its record on the network;
 * 3. encrypt an ADVANCE under its `fromEpoch` key before committing it; and
 * 4. gate application traffic while `trafficBlocked` is true.
 *
 * There is no classical or lower-parameter fallback. The room-selected suite
 * supplied to the constructor is checked against both FIPS 203 sizes and the
 * backend. Every ADVANCE embeds the complete OFFER it answers. That makes the
 * exact suite, channel binding, epochs, counters, public key, and ciphertext a
 * single deterministic KDF transcript and gives the state machine an exact
 * byte string with which to reject replays and forks.
 */

export const PQ_HEALING_BINDING_BYTES = 32;
export const PQ_HEALING_ROOT_BYTES = 32;
export const PQ_HEALING_RECORD_HEADER_BYTES = 64;

const MAGIC = new Uint8Array([0x50, 0x32, 0x51, 0x48]); // "P2QH"
const FORMAT_VERSION = 1;
const OFFER_TYPE = 1;
const ADVANCE_TYPE = 2;
const RESERVED_FLAGS = 0;
const KDF_DOMAIN = new TextEncoder().encode("p2party/pq-healing/root/v1\u0000");
const MAX_U64 = (1n << 64n) - 1n;

const MAGIC_OFFSET = 0;
const VERSION_OFFSET = 4;
const TYPE_OFFSET = 5;
const SUITE_OFFSET = 6;
const FLAGS_OFFSET = 7;
const BINDING_OFFSET = 8;
const COUNTER_OFFSET = 40;
const FROM_EPOCH_OFFSET = 48;
const TO_EPOCH_OFFSET = 56;

export type PqHealingTurn = "local" | "remote";

export type PqHealingPhase =
  | "idle"
  | "outbound-offer-prepared"
  | "outbound-offer-dispatched"
  | "inbound-offer"
  | "outbound-advance-prepared"
  | "outbound-advance-awaiting-ack"
  | "inbound-advance-prepared"
  | "inbound-advance-awaiting-ack-dispatch"
  | "destroyed";

export type PqHealingErrorCode =
  | "binding-mismatch"
  | "counter-gap"
  | "destroyed"
  | "epoch-gap"
  | "fork"
  | "invalid-record"
  | "invalid-state"
  | "overflow"
  | "replay"
  | "suite-mismatch"
  | "wrong-turn";

export class PqHealingError extends Error {
  readonly code: PqHealingErrorCode;

  constructor(code: PqHealingErrorCode, message: string) {
    super(`pqHealing: ${message}`);
    this.name = "PqHealingError";
    this.code = code;
  }
}

export interface PqHealingAdvanceAcknowledgement {
  /**
   * Integration-facing typed value, NOT a wire encoding. ACK wire encoding
   * and authentication remain integration-owned: the transport must define
   * one canonical byte representation, authenticate it under `epoch`, and
   * only then pass the decoded value to this state machine.
   *
   * The newly committed epoch. The transport acknowledgement must be
   * authenticated under this epoch, proving that the offerer decapsulated.
   */
  readonly epoch: bigint;
  /** Sender counter of the ADVANCE being acknowledged. */
  readonly advanceCounter: bigint;
}

export interface PqHealingOfferRecord {
  readonly type: "offer";
  readonly parameterSet: MlKemParameterSet;
  readonly binding: Uint8Array;
  readonly senderCounter: bigint;
  readonly fromEpoch: bigint;
  readonly toEpoch: bigint;
  readonly publicKey: Uint8Array;
}

export interface PqHealingAdvanceRecord {
  readonly type: "advance";
  readonly parameterSet: MlKemParameterSet;
  readonly binding: Uint8Array;
  readonly senderCounter: bigint;
  readonly fromEpoch: bigint;
  readonly toEpoch: bigint;
  /** The complete, canonical OFFER answered by this record. */
  readonly offerBytes: Uint8Array;
  readonly offer: PqHealingOfferRecord;
  readonly ciphertext: Uint8Array;
}

export type PqHealingRecord = PqHealingOfferRecord | PqHealingAdvanceRecord;

export interface PqHealingMachineOptions<P extends MlKemParameterSet> {
  readonly module: LibCrypto;
  readonly backend: MlKemBackend<P>;
  /**
   * Authenticated room-selected suite. This is an input, never a negotiated
   * result. It must exactly match the backend's parameter set and FIPS sizes.
   */
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;
  /**
   * Non-secret, transcript-derived edge binding (for example a truncation of
   * the authenticated handshake/channel-input hash).
   */
  readonly binding: Uint8Array;
  /** Current, separate PQ root. The constructor takes an owned copy. */
  readonly rootKey: Uint8Array;
  /** Which side is allowed to emit the first/next OFFER. */
  readonly nextOfferer: PqHealingTurn;
  readonly epoch?: bigint;
  readonly localCounter?: bigint;
  readonly remoteCounter?: bigint;
}

interface DecodedHeader {
  readonly senderCounter: bigint;
  readonly fromEpoch: bigint;
  readonly toEpoch: bigint;
}

interface DecodedOffer extends DecodedHeader {
  readonly bytes: Uint8Array;
  readonly publicKey: Uint8Array;
}

interface DecodedAdvance extends DecodedHeader {
  readonly bytes: Uint8Array;
  readonly offer: DecodedOffer;
  readonly ciphertext: Uint8Array;
}

interface IdlePhase {
  readonly kind: "idle";
}

interface OutboundOfferPhase {
  readonly kind: "outbound-offer";
  readonly dispatched: boolean;
  readonly offer: DecodedOffer;
  readonly keyPair: MlKemKeyPair;
}

interface InboundOfferPhase {
  readonly kind: "inbound-offer";
  readonly offer: DecodedOffer;
}

interface OutboundAdvancePreparedPhase {
  readonly kind: "outbound-advance-prepared";
  readonly offer: DecodedOffer;
  readonly advance: DecodedAdvance;
  readonly nextRoot: Uint8Array;
}

interface OutboundAdvanceAwaitingAckPhase {
  readonly kind: "outbound-advance-awaiting-ack";
  readonly offer: DecodedOffer;
  readonly advance: DecodedAdvance;
}

interface InboundAdvancePreparedPhase {
  readonly kind: "inbound-advance-prepared";
  readonly offer: DecodedOffer;
  readonly advance: DecodedAdvance;
  readonly keyPair: MlKemKeyPair;
  readonly nextRoot: Uint8Array;
}

interface InboundAdvanceAwaitingAckDispatchPhase {
  readonly kind: "inbound-advance-awaiting-ack-dispatch";
  readonly advance: DecodedAdvance;
}

type InternalPhase =
  | IdlePhase
  | OutboundOfferPhase
  | InboundOfferPhase
  | OutboundAdvancePreparedPhase
  | OutboundAdvanceAwaitingAckPhase
  | InboundAdvancePreparedPhase
  | InboundAdvanceAwaitingAckDispatchPhase;

const fail = (code: PqHealingErrorCode, message: string): never => {
  throw new PqHealingError(code, message);
};

const requireBytes = (
  value: unknown,
  name: string,
  expectedLength: number,
): Uint8Array => {
  if (!(value instanceof Uint8Array))
    return fail("invalid-record", `${name} must be a Uint8Array`);
  if (value.length !== expectedLength)
    return fail(
      "invalid-record",
      `${name} must be exactly ${String(expectedLength)} bytes`,
    );
  return value;
};

const requireU64 = (value: bigint, name: string): void => {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    fail("overflow", `${name} is outside the unsigned 64-bit range`);
};

const requireIncrementableU64 = (value: bigint, name: string): void => {
  requireU64(value, name);
  if (value === MAX_U64)
    fail("overflow", `${name} cannot advance beyond uint64`);
};

const requireAcknowledgement = (
  value: unknown,
): PqHealingAdvanceAcknowledgement => {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    return fail(
      "invalid-record",
      "advance acknowledgement must be a plain record",
    );
  const record = value as Record<PropertyKey, unknown>;
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== 2 ||
    !keys.includes("epoch") ||
    !keys.includes("advanceCounter")
  )
    fail(
      "invalid-record",
      "advance acknowledgement must contain only epoch and advanceCounter",
    );
  const epochDescriptor = Object.getOwnPropertyDescriptor(record, "epoch");
  const counterDescriptor = Object.getOwnPropertyDescriptor(
    record,
    "advanceCounter",
  );
  if (
    epochDescriptor === undefined ||
    counterDescriptor === undefined ||
    !("value" in epochDescriptor) ||
    !("value" in counterDescriptor) ||
    !epochDescriptor.enumerable ||
    !counterDescriptor.enumerable
  )
    return fail(
      "invalid-record",
      "advance acknowledgement fields must be enumerable data properties",
    );

  const epoch: unknown = epochDescriptor.value;
  const advanceCounter: unknown = counterDescriptor.value;
  if (typeof epoch !== "bigint" || typeof advanceCounter !== "bigint")
    return fail(
      "invalid-record",
      "advance acknowledgement fields must be bigint values",
    );
  requireU64(epoch, "advance acknowledgement epoch");
  requireU64(advanceCounter, "advance acknowledgement counter");
  return { epoch, advanceCounter };
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= left[index] ^ right[index];
  return difference === 0;
};

const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const parameterSetToTag = (parameterSet: number): number => {
  // Byte-match the authenticated room-policy / bootstrap transcript tags.
  if (parameterSet === 768) return 1;
  if (parameterSet === 512) return 2;
  if (parameterSet === 1024) return 3;
  return fail("suite-mismatch", "unsupported ML-KEM parameter set");
};

const tagToParameterSet = (tag: number): MlKemParameterSet => {
  if (tag === 1) return 768;
  if (tag === 2) return 512;
  if (tag === 3) return 1024;
  return fail("invalid-record", "record has an unknown ML-KEM suite tag");
};

const readRuntimeField = (value: object, field: string): unknown =>
  Reflect.get(value, field) as unknown;

const assertCanonicalSuite = <P extends MlKemParameterSet>(
  suite: Readonly<MlKemSuiteDescriptor<P>>,
): void => {
  const canonical = getMlKemSuite(suite.parameterSet);
  if (
    suite.standardName !== canonical.standardName ||
    suite.publicKeyBytes !== canonical.publicKeyBytes ||
    suite.secretKeyBytes !== canonical.secretKeyBytes ||
    suite.ciphertextBytes !== canonical.ciphertextBytes ||
    readRuntimeField(suite, "sharedSecretBytes") !==
      canonical.sharedSecretBytes ||
    readRuntimeField(suite, "keyPairRandomBytes") !==
      canonical.keyPairRandomBytes ||
    readRuntimeField(suite, "encapsRandomBytes") !== canonical.encapsRandomBytes
  )
    fail(
      "suite-mismatch",
      "selected suite does not match its canonical FIPS 203 descriptor",
    );
};

const assertSameSuite = (
  selected: Readonly<MlKemSuiteDescriptor>,
  backend: Readonly<MlKemSuiteDescriptor>,
): void => {
  assertCanonicalSuite(selected);
  assertCanonicalSuite(backend);
  if (
    selected.parameterSet !== backend.parameterSet ||
    selected.publicKeyBytes !== backend.publicKeyBytes ||
    selected.secretKeyBytes !== backend.secretKeyBytes ||
    selected.ciphertextBytes !== backend.ciphertextBytes
  )
    fail(
      "suite-mismatch",
      "room-selected suite does not exactly match the ML-KEM backend",
    );
};

const offerLength = (suite: Readonly<MlKemSuiteDescriptor>): number =>
  PQ_HEALING_RECORD_HEADER_BYTES + suite.publicKeyBytes;

const advanceLength = (suite: Readonly<MlKemSuiteDescriptor>): number =>
  PQ_HEALING_RECORD_HEADER_BYTES + offerLength(suite) + suite.ciphertextBytes;

export const getPqHealingRecordLengths = (
  suite: Readonly<MlKemSuiteDescriptor>,
): { readonly offer: number; readonly advance: number } => {
  assertCanonicalSuite(suite);
  return {
    offer: offerLength(suite),
    advance: advanceLength(suite),
  };
};

const encodeHeader = (
  type: typeof OFFER_TYPE | typeof ADVANCE_TYPE,
  suite: Readonly<MlKemSuiteDescriptor>,
  binding: Uint8Array,
  senderCounter: bigint,
  fromEpoch: bigint,
  toEpoch: bigint,
  totalLength: number,
): Uint8Array => {
  requireBytes(binding, "binding", PQ_HEALING_BINDING_BYTES);
  requireU64(senderCounter, "sender counter");
  requireU64(fromEpoch, "from epoch");
  requireU64(toEpoch, "to epoch");
  if (fromEpoch === MAX_U64 || toEpoch !== fromEpoch + 1n)
    fail("invalid-record", "record must advance exactly one PQ epoch");

  const record = new Uint8Array(totalLength);
  record.set(MAGIC, MAGIC_OFFSET);
  record[VERSION_OFFSET] = FORMAT_VERSION;
  record[TYPE_OFFSET] = type;
  record[SUITE_OFFSET] = parameterSetToTag(suite.parameterSet);
  record[FLAGS_OFFSET] = RESERVED_FLAGS;
  record.set(binding, BINDING_OFFSET);

  const view = new DataView(
    record.buffer,
    record.byteOffset,
    record.byteLength,
  );
  view.setBigUint64(COUNTER_OFFSET, senderCounter, false);
  view.setBigUint64(FROM_EPOCH_OFFSET, fromEpoch, false);
  view.setBigUint64(TO_EPOCH_OFFSET, toEpoch, false);
  return record;
};

const decodeHeader = (
  record: Uint8Array,
  expectedType: typeof OFFER_TYPE | typeof ADVANCE_TYPE,
  suite: Readonly<MlKemSuiteDescriptor>,
  binding: Uint8Array | undefined,
): DecodedHeader => {
  if (!(record instanceof Uint8Array))
    fail("invalid-record", "record must be a Uint8Array");
  if (record.length < PQ_HEALING_RECORD_HEADER_BYTES)
    fail("invalid-record", "record is shorter than its canonical header");
  if (!bytesEqual(record.subarray(MAGIC_OFFSET, VERSION_OFFSET), MAGIC))
    fail("invalid-record", "record magic is invalid");
  if (record[VERSION_OFFSET] !== FORMAT_VERSION)
    fail("invalid-record", "record version is unsupported");
  if (record[TYPE_OFFSET] !== expectedType)
    fail("invalid-record", "record type is unexpected");
  if (record[FLAGS_OFFSET] !== RESERVED_FLAGS)
    fail("invalid-record", "record reserved flags must be zero");

  const recordParameterSet = tagToParameterSet(record[SUITE_OFFSET]);
  if (recordParameterSet !== suite.parameterSet)
    fail(
      "suite-mismatch",
      "record suite differs from the authenticated room suite",
    );

  const recordBinding = record.subarray(
    BINDING_OFFSET,
    BINDING_OFFSET + PQ_HEALING_BINDING_BYTES,
  );
  if (binding !== undefined && !bytesEqual(recordBinding, binding))
    fail(
      "binding-mismatch",
      "record belongs to a different authenticated edge",
    );

  const view = new DataView(
    record.buffer,
    record.byteOffset,
    record.byteLength,
  );
  const senderCounter = view.getBigUint64(COUNTER_OFFSET, false);
  const fromEpoch = view.getBigUint64(FROM_EPOCH_OFFSET, false);
  const toEpoch = view.getBigUint64(TO_EPOCH_OFFSET, false);
  if (fromEpoch === MAX_U64 || toEpoch !== fromEpoch + 1n)
    fail("invalid-record", "record must advance exactly one PQ epoch");

  return { senderCounter, fromEpoch, toEpoch };
};

const decodeOffer = (
  record: Uint8Array,
  suite: Readonly<MlKemSuiteDescriptor>,
  binding?: Uint8Array,
): DecodedOffer => {
  const header = decodeHeader(record, OFFER_TYPE, suite, binding);
  if (record.length !== offerLength(suite))
    fail("invalid-record", "OFFER length is not canonical for its suite");
  return {
    ...header,
    bytes: Uint8Array.from(record),
    publicKey: record.slice(PQ_HEALING_RECORD_HEADER_BYTES),
  };
};

const decodeAdvance = (
  record: Uint8Array,
  suite: Readonly<MlKemSuiteDescriptor>,
  binding?: Uint8Array,
): DecodedAdvance => {
  const header = decodeHeader(record, ADVANCE_TYPE, suite, binding);
  if (record.length !== advanceLength(suite))
    fail("invalid-record", "ADVANCE length is not canonical for its suite");

  const nestedOfferLength = offerLength(suite);
  const offerBytes = record.slice(
    PQ_HEALING_RECORD_HEADER_BYTES,
    PQ_HEALING_RECORD_HEADER_BYTES + nestedOfferLength,
  );
  const offer = decodeOffer(offerBytes, suite, binding);
  if (offer.fromEpoch !== header.fromEpoch || offer.toEpoch !== header.toEpoch)
    fail("fork", "ADVANCE epoch does not exactly match its embedded OFFER");

  return {
    ...header,
    bytes: Uint8Array.from(record),
    offer,
    ciphertext: record.slice(
      PQ_HEALING_RECORD_HEADER_BYTES + nestedOfferLength,
    ),
  };
};

/**
 * Parse a canonical record without changing state. Integration code can use
 * this for routing and audit logs, but MUST still call the stateful
 * `acceptAuthenticated*` method only after outer authentication.
 */
export const inspectPqHealingRecord = (
  record: Uint8Array,
  suite: Readonly<MlKemSuiteDescriptor>,
): PqHealingRecord => {
  assertCanonicalSuite(suite);
  if (!(record instanceof Uint8Array))
    return fail("invalid-record", "record must be a Uint8Array");
  if (record.length < PQ_HEALING_RECORD_HEADER_BYTES)
    return fail(
      "invalid-record",
      "record is shorter than its canonical header",
    );

  if (record[TYPE_OFFSET] === OFFER_TYPE) {
    const offer = decodeOffer(record, suite);
    return {
      type: "offer",
      parameterSet: suite.parameterSet,
      binding: offer.bytes.slice(
        BINDING_OFFSET,
        BINDING_OFFSET + PQ_HEALING_BINDING_BYTES,
      ),
      senderCounter: offer.senderCounter,
      fromEpoch: offer.fromEpoch,
      toEpoch: offer.toEpoch,
      publicKey: Uint8Array.from(offer.publicKey),
    };
  }

  if (record[TYPE_OFFSET] === ADVANCE_TYPE) {
    const advance = decodeAdvance(record, suite);
    const offer: PqHealingOfferRecord = {
      type: "offer",
      parameterSet: suite.parameterSet,
      binding: advance.offer.bytes.slice(
        BINDING_OFFSET,
        BINDING_OFFSET + PQ_HEALING_BINDING_BYTES,
      ),
      senderCounter: advance.offer.senderCounter,
      fromEpoch: advance.offer.fromEpoch,
      toEpoch: advance.offer.toEpoch,
      publicKey: Uint8Array.from(advance.offer.publicKey),
    };
    return {
      type: "advance",
      parameterSet: suite.parameterSet,
      binding: advance.bytes.slice(
        BINDING_OFFSET,
        BINDING_OFFSET + PQ_HEALING_BINDING_BYTES,
      ),
      senderCounter: advance.senderCounter,
      fromEpoch: advance.fromEpoch,
      toEpoch: advance.toEpoch,
      offerBytes: Uint8Array.from(advance.offer.bytes),
      offer,
      ciphertext: Uint8Array.from(advance.ciphertext),
    };
  }

  return fail("invalid-record", "record type is unknown");
};

const encodeOffer = (
  suite: Readonly<MlKemSuiteDescriptor>,
  binding: Uint8Array,
  senderCounter: bigint,
  fromEpoch: bigint,
  publicKey: Uint8Array,
): Uint8Array => {
  requireBytes(publicKey, "ML-KEM public key", suite.publicKeyBytes);
  const record = encodeHeader(
    OFFER_TYPE,
    suite,
    binding,
    senderCounter,
    fromEpoch,
    fromEpoch + 1n,
    offerLength(suite),
  );
  record.set(publicKey, PQ_HEALING_RECORD_HEADER_BYTES);
  return record;
};

const encodeAdvance = (
  suite: Readonly<MlKemSuiteDescriptor>,
  binding: Uint8Array,
  senderCounter: bigint,
  offer: DecodedOffer,
  ciphertext: Uint8Array,
): Uint8Array => {
  requireBytes(ciphertext, "ML-KEM ciphertext", suite.ciphertextBytes);
  const record = encodeHeader(
    ADVANCE_TYPE,
    suite,
    binding,
    senderCounter,
    offer.fromEpoch,
    offer.toEpoch,
    advanceLength(suite),
  );
  record.set(offer.bytes, PQ_HEALING_RECORD_HEADER_BYTES);
  record.set(ciphertext, PQ_HEALING_RECORD_HEADER_BYTES + offer.bytes.length);
  return record;
};

const deriveNextRoot = (
  currentRoot: Uint8Array,
  sharedSecret: Uint8Array,
  advanceRecord: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  requireBytes(currentRoot, "PQ root", PQ_HEALING_ROOT_BYTES);
  const prk = hkdfExtract(currentRoot, sharedSecret, module);
  const info = concatenate(KDF_DOMAIN, advanceRecord);
  try {
    return hkdfExpand(prk, info, PQ_HEALING_ROOT_BYTES, module);
  } finally {
    prk.fill(0);
  }
};

const phaseName = (phase: InternalPhase): PqHealingPhase => {
  switch (phase.kind) {
    case "idle":
      return "idle";
    case "outbound-offer":
      return phase.dispatched
        ? "outbound-offer-dispatched"
        : "outbound-offer-prepared";
    case "inbound-offer":
      return "inbound-offer";
    case "outbound-advance-prepared":
      return "outbound-advance-prepared";
    case "outbound-advance-awaiting-ack":
      return "outbound-advance-awaiting-ack";
    case "inbound-advance-prepared":
      return "inbound-advance-prepared";
    case "inbound-advance-awaiting-ack-dispatch":
      return "inbound-advance-awaiting-ack-dispatch";
  }
};

const sameOfferSlot = (left: DecodedOffer, right: DecodedOffer): boolean =>
  left.senderCounter === right.senderCounter &&
  left.fromEpoch === right.fromEpoch &&
  left.toEpoch === right.toEpoch;

const sameAdvanceSlot = (
  left: DecodedAdvance,
  right: DecodedAdvance,
): boolean =>
  left.senderCounter === right.senderCounter &&
  left.fromEpoch === right.fromEpoch &&
  left.toEpoch === right.toEpoch;

/**
 * One directional-turn PQ healing machine for a single authenticated peer
 * edge. A room mesh owns one instance per edge; a room-wide policy supplies
 * the same exact ML-KEM parameter set to every instance.
 */
export class PqHealingMachine<P extends MlKemParameterSet> {
  readonly #module: LibCrypto;
  readonly #backend: MlKemBackend<P>;
  readonly #suite: Readonly<MlKemSuiteDescriptor<P>>;
  readonly #binding: Uint8Array;

  #rootKey: Uint8Array;
  #epoch: bigint;
  #localCounter: bigint;
  #remoteCounter: bigint;
  #nextOfferer: PqHealingTurn;
  #phase: InternalPhase = { kind: "idle" };
  #lastInboundOffer: DecodedOffer | null = null;
  #lastInboundAdvance: DecodedAdvance | null = null;
  #busy = false;
  #destroyed = false;

  constructor(options: PqHealingMachineOptions<P>) {
    assertSameSuite(options.suite, options.backend.suite);
    requireBytes(options.binding, "binding", PQ_HEALING_BINDING_BYTES);
    requireBytes(options.rootKey, "PQ root", PQ_HEALING_ROOT_BYTES);
    const nextOfferer: unknown = options.nextOfferer;
    if (nextOfferer !== "local" && nextOfferer !== "remote")
      fail("invalid-state", "nextOfferer must be local or remote");

    const epoch = options.epoch ?? 0n;
    const localCounter = options.localCounter ?? 0n;
    const remoteCounter = options.remoteCounter ?? 0n;
    requireU64(epoch, "epoch");
    requireU64(localCounter, "local counter");
    requireU64(remoteCounter, "remote counter");

    this.#module = options.module;
    this.#backend = options.backend;
    this.#suite = options.suite;
    this.#binding = Uint8Array.from(options.binding);
    this.#rootKey = Uint8Array.from(options.rootKey);
    this.#epoch = epoch;
    this.#localCounter = localCounter;
    this.#remoteCounter = remoteCounter;
    this.#nextOfferer = options.nextOfferer;
  }

  get suite(): Readonly<MlKemSuiteDescriptor<P>> {
    return this.#suite;
  }

  get phase(): PqHealingPhase {
    return this.#destroyed ? "destroyed" : phaseName(this.#phase);
  }

  get epoch(): bigint {
    this.#assertActive();
    return this.#epoch;
  }

  get localCounter(): bigint {
    this.#assertActive();
    return this.#localCounter;
  }

  get remoteCounter(): bigint {
    this.#assertActive();
    return this.#remoteCounter;
  }

  get nextOfferer(): PqHealingTurn {
    this.#assertActive();
    return this.#nextOfferer;
  }

  /**
   * New-epoch messages must not race the control exchange across independent
   * WebRTC data channels. The integration must hold application traffic while
   * this is true.
   */
  get trafficBlocked(): boolean {
    return this.#destroyed || this.#phase.kind !== "idle";
  }

  /** Explicit owned copy for the message-key combiner or encrypted checkpoint. */
  copyRootKey(): Uint8Array {
    this.#assertActive();
    return Uint8Array.from(this.#rootKey);
  }

  /**
   * Return the exact public record that should be sent/retransmitted. A caller
   * must never reconstruct a replacement after the original may have escaped.
   */
  copyPendingOutboundRecord(): Uint8Array {
    this.#assertSynchronous();
    const phase = this.#phase;
    if (phase.kind === "outbound-offer")
      return Uint8Array.from(phase.offer.bytes);
    if (
      phase.kind === "outbound-advance-prepared" ||
      phase.kind === "outbound-advance-awaiting-ack"
    )
      return Uint8Array.from(phase.advance.bytes);
    return fail("invalid-state", "there is no pending outbound record");
  }

  async prepareOffer(): Promise<Uint8Array> {
    this.#beginAsyncOperation();
    let keyPair: MlKemKeyPair | undefined;
    try {
      if (this.#phase.kind !== "idle")
        fail(
          "invalid-state",
          "cannot prepare an OFFER while another transition is pending",
        );
      if (this.#nextOfferer !== "local")
        fail("wrong-turn", "the remote peer owns the next OFFER turn");
      this.#assertCanStartExchange();

      keyPair = await this.#backend.generateKeyPair();
      this.#assertActive();
      requireBytes(
        keyPair.publicKey,
        "ML-KEM public key",
        this.#suite.publicKeyBytes,
      );
      requireBytes(
        keyPair.secretKey,
        "ML-KEM secret key",
        this.#suite.secretKeyBytes,
      );

      const bytes = encodeOffer(
        this.#suite,
        this.#binding,
        this.#localCounter,
        this.#epoch,
        keyPair.publicKey,
      );
      const offer = decodeOffer(bytes, this.#suite, this.#binding);
      this.#phase = {
        kind: "outbound-offer",
        dispatched: false,
        offer,
        keyPair,
      };
      keyPair = undefined; // ownership moved into the phase
      return Uint8Array.from(bytes);
    } finally {
      keyPair?.destroy();
      this.#endAsyncOperation();
    }
  }

  /**
   * Mark the persisted OFFER as having possibly escaped to the network. After
   * this point it cannot be aborted or replaced; only its exact bytes may be
   * retransmitted.
   */
  markOfferDispatched(): void {
    this.#assertSynchronous();
    const phase = this.#phase;
    if (phase.kind !== "outbound-offer")
      return fail("invalid-state", "there is no outbound OFFER to dispatch");
    if (phase.dispatched)
      fail("invalid-state", "outbound OFFER was already marked dispatched");
    this.#phase = { ...phase, dispatched: true };
  }

  /**
   * Safe only while the caller can prove the OFFER has never been sent.
   * The pending ML-KEM secret key is wiped.
   */
  abortUnsentOffer(): void {
    this.#assertSynchronous();
    const phase = this.#phase;
    if (phase.kind !== "outbound-offer" || phase.dispatched)
      return fail("invalid-state", "only an undispatched OFFER can be aborted");
    phase.keyPair.destroy();
    this.#phase = { kind: "idle" };
  }

  /**
   * Accept a full OFFER only after the outer AEAD has authenticated it.
   */
  acceptAuthenticatedOffer(record: Uint8Array): void {
    this.#assertSynchronous();
    const offer = decodeOffer(record, this.#suite, this.#binding);
    this.#rejectKnownOfferReplayOrFork(offer);

    if (this.#phase.kind !== "idle")
      fail("invalid-state", "another PQ healing transition is pending");
    if (this.#nextOfferer !== "remote")
      fail("wrong-turn", "the local peer owns the next OFFER turn");
    this.#requireExpectedCounter(offer.senderCounter);
    this.#requireExpectedEpoch(offer.fromEpoch);
    this.#assertCanStartExchange();
    this.#phase = { kind: "inbound-offer", offer };
  }

  /**
   * Prepare an ADVANCE and its candidate root. The caller must outer-encrypt
   * this exact record under `fromEpoch` before committing, then persist the
   * committed state and sealed record before sending.
   */
  async prepareAdvance(): Promise<Uint8Array> {
    this.#beginAsyncOperation();
    let encapsulation:
      Awaited<ReturnType<MlKemBackend<P>["encapsulate"]>> | undefined;
    try {
      const phase = this.#phase;
      if (phase.kind !== "inbound-offer")
        return fail(
          "invalid-state",
          "an authenticated inbound OFFER is required",
        );
      requireIncrementableU64(this.#localCounter, "local counter");

      encapsulation = await this.#backend.encapsulate(phase.offer.publicKey);
      this.#assertActive();
      requireBytes(
        encapsulation.ciphertext,
        "ML-KEM ciphertext",
        this.#suite.ciphertextBytes,
      );
      requireBytes(
        encapsulation.sharedSecret,
        "ML-KEM shared secret",
        this.#suite.sharedSecretBytes,
      );

      const bytes = encodeAdvance(
        this.#suite,
        this.#binding,
        this.#localCounter,
        phase.offer,
        encapsulation.ciphertext,
      );
      const advance = decodeAdvance(bytes, this.#suite, this.#binding);
      const nextRoot = deriveNextRoot(
        this.#rootKey,
        encapsulation.sharedSecret,
        bytes,
        this.#module,
      );
      this.#phase = {
        kind: "outbound-advance-prepared",
        offer: phase.offer,
        advance,
        nextRoot,
      };
      return Uint8Array.from(bytes);
    } finally {
      encapsulation?.destroy();
      this.#endAsyncOperation();
    }
  }

  /**
   * Commit the prepared root after the exact ADVANCE has already been sealed
   * under the old epoch. The returned record is the only record that may be
   * sent. Application traffic remains blocked until a new-epoch authenticated
   * acknowledgement is accepted.
   */
  commitPreparedAdvance(): Uint8Array {
    this.#assertSynchronous();
    const phase = this.#phase;
    if (phase.kind !== "outbound-advance-prepared")
      return fail("invalid-state", "there is no prepared outbound ADVANCE");

    this.#commitRoot(phase.nextRoot);
    this.#epoch = phase.advance.toEpoch;
    this.#localCounter += 1n;
    this.#remoteCounter += 1n;
    this.#nextOfferer = "local";
    this.#lastInboundOffer = phase.offer;
    this.#phase = {
      kind: "outbound-advance-awaiting-ack",
      offer: phase.offer,
      advance: phase.advance,
    };
    return Uint8Array.from(phase.advance.bytes);
  }

  /**
   * Close the responder side only after an acknowledgement authenticated under
   * the new epoch has been received. Exact epoch/counter binding prevents an
   * unrelated transport receipt from unlocking the next OFFER.
   */
  acceptAuthenticatedAdvanceAcknowledgement(acknowledgement: unknown): void {
    this.#assertSynchronous();
    const canonicalAcknowledgement = requireAcknowledgement(acknowledgement);
    const phase = this.#phase;
    if (phase.kind !== "outbound-advance-awaiting-ack")
      return fail(
        "invalid-state",
        "no outbound ADVANCE is awaiting acknowledgement",
      );
    if (
      canonicalAcknowledgement.epoch !== this.#epoch ||
      canonicalAcknowledgement.advanceCounter !== phase.advance.senderCounter
    )
      fail(
        "invalid-record",
        "advance acknowledgement does not bind the pending transition",
      );
    this.#phase = { kind: "idle" };
  }

  /**
   * Accept a full ADVANCE only after its outer AEAD has authenticated it under
   * the old epoch.
   */
  async acceptAuthenticatedAdvance(record: Uint8Array): Promise<void> {
    this.#beginAsyncOperation();
    let decapsulation:
      Awaited<ReturnType<MlKemBackend<P>["decapsulate"]>> | undefined;
    try {
      const advance = decodeAdvance(record, this.#suite, this.#binding);
      this.#rejectKnownAdvanceReplayOrFork(advance);

      const phase = this.#phase;
      if (phase.kind !== "outbound-offer" || !phase.dispatched)
        return fail(
          "invalid-state",
          "a dispatched outbound OFFER is required before ADVANCE",
        );
      this.#requireExpectedCounter(advance.senderCounter);
      this.#requireExpectedEpoch(advance.fromEpoch);
      if (!bytesEqual(advance.offer.bytes, phase.offer.bytes))
        fail("fork", "ADVANCE answers a different OFFER");

      decapsulation = await this.#backend.decapsulate(
        advance.ciphertext,
        phase.keyPair.secretKey,
      );
      this.#assertActive();
      requireBytes(
        decapsulation.sharedSecret,
        "ML-KEM shared secret",
        this.#suite.sharedSecretBytes,
      );
      const nextRoot = deriveNextRoot(
        this.#rootKey,
        decapsulation.sharedSecret,
        advance.bytes,
        this.#module,
      );
      this.#phase = {
        kind: "inbound-advance-prepared",
        offer: phase.offer,
        advance,
        keyPair: phase.keyPair,
        nextRoot,
      };
    } finally {
      decapsulation?.destroy();
      this.#endAsyncOperation();
    }
  }

  /**
   * Commit a successfully decapsulated ADVANCE. The returned binding must be
   * carried by an acknowledgement authenticated under the new epoch. Traffic
   * remains blocked until `markAdvanceAcknowledgementDispatched` is called.
   */
  commitAcceptedAdvance(): PqHealingAdvanceAcknowledgement {
    this.#assertSynchronous();
    const phase = this.#phase;
    if (phase.kind !== "inbound-advance-prepared")
      return fail("invalid-state", "there is no accepted ADVANCE to commit");

    phase.keyPair.destroy();
    this.#commitRoot(phase.nextRoot);
    this.#epoch = phase.advance.toEpoch;
    this.#localCounter += 1n;
    this.#remoteCounter += 1n;
    this.#nextOfferer = "remote";
    this.#lastInboundAdvance = phase.advance;
    this.#phase = {
      kind: "inbound-advance-awaiting-ack-dispatch",
      advance: phase.advance,
    };
    return {
      epoch: this.#epoch,
      advanceCounter: phase.advance.senderCounter,
    };
  }

  /**
   * Mark the new-epoch acknowledgement as having escaped to the network.
   * Integration should persist that fact or retain a transport receipt cache
   * so an exact ADVANCE replay can be answered without rolling state back.
   */
  markAdvanceAcknowledgementDispatched(acknowledgement: unknown): void {
    this.#assertSynchronous();
    const canonicalAcknowledgement = requireAcknowledgement(acknowledgement);
    const phase = this.#phase;
    if (phase.kind !== "inbound-advance-awaiting-ack-dispatch")
      return fail(
        "invalid-state",
        "no advance acknowledgement is pending dispatch",
      );
    if (
      canonicalAcknowledgement.epoch !== this.#epoch ||
      canonicalAcknowledgement.advanceCounter !== phase.advance.senderCounter
    )
      fail(
        "invalid-record",
        "advance acknowledgement does not bind the committed transition",
      );
    this.#phase = { kind: "idle" };
  }

  /**
   * Idempotent terminal cleanup. All live roots, candidate roots, and pending
   * ML-KEM secret keys are wiped. Public record copies may remain with callers.
   */
  destroy(): void {
    if (this.#destroyed) return;
    this.#wipePhaseSecrets(this.#phase);
    this.#rootKey.fill(0);
    this.#binding.fill(0);
    this.#lastInboundOffer = null;
    this.#lastInboundAdvance = null;
    this.#phase = { kind: "idle" };
    this.#destroyed = true;
  }

  #assertActive(): void {
    if (this.#destroyed) fail("destroyed", "state machine is destroyed");
  }

  #assertSynchronous(): void {
    this.#assertActive();
    if (this.#busy)
      fail("invalid-state", "another asynchronous transition is in flight");
  }

  #beginAsyncOperation(): void {
    this.#assertSynchronous();
    this.#busy = true;
  }

  #endAsyncOperation(): void {
    this.#busy = false;
  }

  #assertCanStartExchange(): void {
    requireIncrementableU64(this.#epoch, "epoch");
    requireIncrementableU64(this.#localCounter, "local counter");
    requireIncrementableU64(this.#remoteCounter, "remote counter");
  }

  #requireExpectedCounter(counter: bigint): void {
    if (counter < this.#remoteCounter)
      fail("replay", "record sender counter was already consumed");
    if (counter > this.#remoteCounter)
      fail("counter-gap", "record sender counter skips an expected transition");
  }

  #requireExpectedEpoch(fromEpoch: bigint): void {
    if (fromEpoch < this.#epoch)
      fail("replay", "record PQ epoch was already consumed");
    if (fromEpoch > this.#epoch)
      fail("epoch-gap", "record skips the current PQ epoch");
  }

  #rejectKnownOfferReplayOrFork(offer: DecodedOffer): void {
    let known: DecodedOffer | null = this.#lastInboundOffer;
    const phase = this.#phase;
    if (
      phase.kind === "inbound-offer" ||
      phase.kind === "outbound-advance-prepared" ||
      phase.kind === "outbound-advance-awaiting-ack"
    )
      known = phase.offer;
    if (known === null || !sameOfferSlot(offer, known)) return;
    if (bytesEqual(offer.bytes, known.bytes))
      fail("replay", "OFFER is an exact replay");
    fail("fork", "different OFFER bytes reuse an authenticated slot");
  }

  #rejectKnownAdvanceReplayOrFork(advance: DecodedAdvance): void {
    let known: DecodedAdvance | null = this.#lastInboundAdvance;
    const phase = this.#phase;
    if (
      phase.kind === "inbound-advance-prepared" ||
      phase.kind === "inbound-advance-awaiting-ack-dispatch"
    )
      known = phase.advance;
    if (known === null || !sameAdvanceSlot(advance, known)) return;
    if (bytesEqual(advance.bytes, known.bytes))
      fail("replay", "ADVANCE is an exact replay");
    fail("fork", "different ADVANCE bytes reuse an authenticated slot");
  }

  #commitRoot(nextRoot: Uint8Array): void {
    requireBytes(nextRoot, "candidate PQ root", PQ_HEALING_ROOT_BYTES);
    this.#rootKey.fill(0);
    this.#rootKey = nextRoot;
  }

  #wipePhaseSecrets(phase: InternalPhase): void {
    if (phase.kind === "outbound-offer") phase.keyPair.destroy();
    if (phase.kind === "outbound-advance-prepared") phase.nextRoot.fill(0);
    if (phase.kind === "inbound-advance-prepared") {
      phase.keyPair.destroy();
      phase.nextRoot.fill(0);
    }
  }
}
