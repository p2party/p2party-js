import {
  PqHealingMachine,
  decodePqHealingAck,
  encodePqHealingAck,
  inspectPqHealingRecord,
  wipePqHealingSnapshot,
  PQ_HEALING_ACK_BYTES,
  type PqHealingPhase,
  type PqHealingSnapshot,
  type PqHealingSnapshotPhase,
  type PqHealingTurn,
} from "../cryptography/pqHealing";
import {
  openPqControlFrame,
  sealPqControlFrame,
  type PqControlDirection,
} from "../cryptography/pqHealingFrame";
import {
  createMlKemBackend,
  getMlKemSuite,
  type MlKemParameterSet,
} from "../cryptography/mlkem";
import {
  roomPqModeToParameterSet,
  roomPqModeToRootSuite,
  type RoomPqMode,
} from "../roomPolicy";
import {
  MAX_SKIP_SESSION,
  WIRE_CHUNK_FRAME_LEN,
  type RatchetRootSuite,
} from "../utils/constants";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";

/**
 * Store-free protocol-v4 sparse-PQ controller.
 *
 * The class owns no Redux, IndexedDB, timers, or transport. Callers clone it,
 * perform one transition on the clone, persist `clone.serialize()` together
 * with the Double-Ratchet successor, adopt the clone, and only then dispatch
 * the returned exact frame. That ordering is what prevents crash-induced
 * OFFER/ADVANCE forks and root/message-key rollback.
 */

const EDGE_MAGIC = new Uint8Array([
  0x50, 0x32, 0x45, 0x44, 0x47, 0x45, 0x34, 0x00,
]); // "P2EDGE4\0"
const EDGE_FORMAT_VERSION = 1;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_EDGE_STATE_BYTES = 256 * 1024;
const MAX_ACTIVE_RECEIVE_KEYS = Math.min(MAX_SKIP_SESSION, 256);
const MAX_CACHE_KEY_BYTES = 160;
const CANONICAL_CACHE_KEY = /^[0-9a-f]{64}:[0-9]+:[0-9]+$/;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export const PQ_HEAL_AFTER_MESSAGES = 64;
export const PQ_HEAL_AFTER_MS = 24 * 60 * 60 * 1000;
export const PQ_HEAL_RETRY_MS = 5_000;
export const PQ_HEAL_MAX_RETRIES = 8;

export type PqHealingOutboxKind = "offer" | "advance";

export interface PqHealingOutbox {
  readonly kind: PqHealingOutboxKind;
  readonly frame: Uint8Array;
  readonly attempts: number;
  readonly nextRetryAt: number;
}

export interface PqHealingControlResult {
  /**
   * Exact already-sealed cell to dispatch after the candidate checkpoint is
   * durable. It may be an OFFER, ADVANCE, ACK, or cached duplicate response.
   */
  readonly dispatch: Uint8Array | null;
  /**
   * False only for an exact duplicate whose cached response can be resent
   * without another persistence write.
   */
  readonly changed: boolean;
}

export interface SparsePqHealingOptions {
  readonly module: LibCrypto;
  readonly pqMode: RoomPqMode;
  readonly rootSuite: RatchetRootSuite;
  readonly binding: Uint8Array;
  readonly rootKey: Uint8Array;
  readonly nextOfferer: PqHealingTurn;
  readonly amInitiator: boolean;
  readonly now?: number;
}

export interface RestoreSparsePqHealingOptions {
  readonly module: LibCrypto;
  readonly pqMode: RoomPqMode;
  readonly rootSuite: RatchetRootSuite;
  readonly binding: Uint8Array;
  readonly amInitiator: boolean;
}

const fail = (message: string): never => {
  throw new Error(`pqHealingRuntime: ${message}`);
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
    return fail(`${name} must be a Uint8Array`);
  if (length !== undefined && value.length !== length)
    fail(`${name} must be exactly ${String(length)} bytes`);
  return value;
};

const requireSafeUint = (value: unknown, name: string): number => {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  )
    return fail(`${name} must be a non-negative safe integer`);
  return value;
};

const requireU64 = (value: unknown, name: string): bigint => {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value > MAX_U64
  )
    return fail(`${name} must be an unsigned 64-bit bigint`);
  return value;
};

const suiteTag = (parameterSet: MlKemParameterSet): number => {
  if (parameterSet === 512) return 1;
  if (parameterSet === 768) return 2;
  if (parameterSet === 1024) return 3;
  return fail("unsupported ML-KEM suite");
};

const tagSuite = (tag: number): MlKemParameterSet => {
  if (tag === 1) return 512;
  if (tag === 2) return 768;
  if (tag === 3) return 1024;
  return fail("checkpoint has an unknown ML-KEM suite");
};

const turnTag = (turn: PqHealingTurn): number => {
  if (turn === "local") return 1;
  if (turn === "remote") return 2;
  return fail("invalid next-offerer turn");
};

const tagTurn = (tag: number): PqHealingTurn => {
  if (tag === 1) return "local";
  if (tag === 2) return "remote";
  return fail("checkpoint has an invalid next-offerer turn");
};

const phaseTag = (phase: PqHealingSnapshotPhase): number => {
  switch (phase.kind) {
    case "idle":
      return 0;
    case "outbound-offer-prepared":
      return 1;
    case "outbound-offer-dispatched":
      return 2;
    case "inbound-offer":
      return 3;
    case "outbound-advance-prepared":
      return 4;
    case "outbound-advance-awaiting-ack":
      return 5;
    case "inbound-advance-prepared":
      return 6;
    case "inbound-advance-awaiting-ack-dispatch":
      return 7;
  }
};

class ByteWriter {
  readonly #parts: Uint8Array[] = [];
  #length = 0;

  bytes(value: Uint8Array): void {
    const owned = Uint8Array.from(value);
    this.#parts.push(owned);
    this.#length += owned.length;
    if (this.#length > MAX_EDGE_STATE_BYTES)
      fail("checkpoint exceeds the encrypted edge-state budget");
  }

  u8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff)
      fail("u8 value is out of range");
    this.bytes(Uint8Array.of(value));
  }

  u16(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff)
      fail("u16 value is out of range");
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, false);
    this.bytes(bytes);
    bytes.fill(0);
  }

  u32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff)
      fail("u32 value is out of range");
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.bytes(bytes);
    bytes.fill(0);
  }

  u64(value: bigint): void {
    requireU64(value, "checkpoint counter");
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    this.bytes(bytes);
    bytes.fill(0);
  }

  sized(value: Uint8Array | null): void {
    if (value === null) {
      this.u32(0);
      return;
    }
    if (value.length === 0)
      fail("present checkpoint byte strings must not be empty");
    this.u32(value.length);
    this.bytes(value);
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.#length);
    let offset = 0;
    try {
      for (const part of this.#parts) {
        output.set(part, offset);
        offset += part.length;
      }
      return output;
    } finally {
      for (const part of this.#parts) part.fill(0);
      this.#parts.length = 0;
      this.#length = 0;
    }
  }
}

class ByteReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(value: Uint8Array) {
    if (value.length === 0 || value.length > MAX_EDGE_STATE_BYTES)
      fail("checkpoint length is invalid");
    this.#bytes = Uint8Array.from(value);
  }

  take(length: number): Uint8Array {
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      this.#offset + length > this.#bytes.length
    )
      return fail("checkpoint is truncated");
    const result = this.#bytes.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return result;
  }

  u8(): number {
    const bytes = this.take(1);
    const value = bytes[0];
    bytes.fill(0);
    return value;
  }

  u16(): number {
    const bytes = this.take(2);
    const value = new DataView(bytes.buffer).getUint16(0, false);
    bytes.fill(0);
    return value;
  }

  u32(): number {
    const bytes = this.take(4);
    const value = new DataView(bytes.buffer).getUint32(0, false);
    bytes.fill(0);
    return value;
  }

  u64(): bigint {
    const bytes = this.take(8);
    const value = new DataView(bytes.buffer).getBigUint64(0, false);
    bytes.fill(0);
    return value;
  }

  sized(maximum: number): Uint8Array | null {
    const length = this.u32();
    if (length === 0) return null;
    if (length > maximum) return fail("checkpoint field exceeds its budget");
    return this.take(length);
  }

  finish(): void {
    if (this.#offset !== this.#bytes.length)
      fail("checkpoint contains trailing bytes");
  }

  destroy(): void {
    this.#bytes.fill(0);
    this.#offset = this.#bytes.length;
  }
}

const writePhase = (
  writer: ByteWriter,
  phase: PqHealingSnapshotPhase,
): void => {
  writer.u8(phaseTag(phase));
  switch (phase.kind) {
    case "idle":
      return;
    case "outbound-offer-prepared":
    case "outbound-offer-dispatched":
      writer.sized(phase.offer);
      writer.sized(phase.secretKey);
      return;
    case "inbound-offer":
      writer.sized(phase.offer);
      return;
    case "outbound-advance-prepared":
      writer.sized(phase.advance);
      writer.sized(phase.nextRoot);
      return;
    case "outbound-advance-awaiting-ack":
    case "inbound-advance-awaiting-ack-dispatch":
      writer.sized(phase.advance);
      return;
    case "inbound-advance-prepared":
      writer.sized(phase.advance);
      writer.sized(phase.secretKey);
      writer.sized(phase.nextRoot);
      return;
  }
};

const requiredSized = (
  reader: ByteReader,
  maximum: number,
  name: string,
): Uint8Array => reader.sized(maximum) ?? fail(`${name} is missing`);

const readPhase = (
  reader: ByteReader,
  suite: ReturnType<typeof getMlKemSuite>,
): PqHealingSnapshotPhase => {
  const offerMaximum = 64 + suite.publicKeyBytes;
  const advanceMaximum =
    64 + offerMaximum + suite.ciphertextBytes;
  switch (reader.u8()) {
    case 0:
      return { kind: "idle" };
    case 1:
      return {
        kind: "outbound-offer-prepared",
        offer: requiredSized(reader, offerMaximum, "prepared OFFER"),
        secretKey: requiredSized(
          reader,
          suite.secretKeyBytes,
          "prepared OFFER secret key",
        ),
      };
    case 2:
      return {
        kind: "outbound-offer-dispatched",
        offer: requiredSized(reader, offerMaximum, "dispatched OFFER"),
        secretKey: requiredSized(
          reader,
          suite.secretKeyBytes,
          "dispatched OFFER secret key",
        ),
      };
    case 3:
      return {
        kind: "inbound-offer",
        offer: requiredSized(reader, offerMaximum, "inbound OFFER"),
      };
    case 4:
      return {
        kind: "outbound-advance-prepared",
        advance: requiredSized(reader, advanceMaximum, "prepared ADVANCE"),
        nextRoot: requiredSized(reader, 32, "candidate PQ root"),
      };
    case 5:
      return {
        kind: "outbound-advance-awaiting-ack",
        advance: requiredSized(reader, advanceMaximum, "outbound ADVANCE"),
      };
    case 6:
      return {
        kind: "inbound-advance-prepared",
        advance: requiredSized(reader, advanceMaximum, "inbound ADVANCE"),
        secretKey: requiredSized(
          reader,
          suite.secretKeyBytes,
          "inbound ADVANCE secret key",
        ),
        nextRoot: requiredSized(reader, 32, "candidate PQ root"),
      };
    case 7:
      return {
        kind: "inbound-advance-awaiting-ack-dispatch",
        advance: requiredSized(reader, advanceMaximum, "acknowledged ADVANCE"),
      };
    default:
      return fail("checkpoint has an unknown PQ phase");
  }
};

const writeOutbox = (
  writer: ByteWriter,
  outbox: PqHealingOutbox | null,
): void => {
  if (outbox === null) {
    writer.u8(0);
    return;
  }
  writer.u8(outbox.kind === "offer" ? 1 : 2);
  writer.u8(outbox.attempts);
  writer.u64(BigInt(outbox.nextRetryAt));
  writer.sized(outbox.frame);
};

const readOutbox = (reader: ByteReader): PqHealingOutbox | null => {
  const tag = reader.u8();
  if (tag === 0) return null;
  if (tag !== 1 && tag !== 2) return fail("checkpoint outbox kind is invalid");
  const attempts = reader.u8();
  if (attempts > PQ_HEAL_MAX_RETRIES)
    fail("checkpoint outbox attempts exceed the retry budget");
  const nextRetryAt = reader.u64();
  if (nextRetryAt > BigInt(Number.MAX_SAFE_INTEGER))
    fail("checkpoint retry deadline exceeds the safe-integer range");
  const frame = requiredSized(
    reader,
    WIRE_CHUNK_FRAME_LEN,
    "outbox frame",
  );
  requireBytes(frame, "outbox frame", WIRE_CHUNK_FRAME_LEN);
  return {
    kind: tag === 1 ? "offer" : "advance",
    attempts,
    nextRetryAt: Number(nextRetryAt),
    frame,
  };
};

const writeActiveKeys = (
  writer: ByteWriter,
  keys: ReadonlyMap<string, Uint8Array>,
): void => {
  if (keys.size > MAX_ACTIVE_RECEIVE_KEYS)
    fail("too many active receive message keys");
  const canonical = [...keys.entries()].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  writer.u16(canonical.length);
  for (const [cacheKey, messageKey] of canonical) {
    if (!CANONICAL_CACHE_KEY.test(cacheKey))
      fail("active receive cache key is non-canonical");
    const encodedKey = textEncoder.encode(cacheKey);
    if (encodedKey.length === 0 || encodedKey.length > MAX_CACHE_KEY_BYTES)
      fail("active receive cache key length is invalid");
    requireBytes(messageKey, "active receive message key", 32);
    writer.u16(encodedKey.length);
    writer.bytes(encodedKey);
    writer.bytes(messageKey);
  }
};

const readActiveKeys = (reader: ByteReader): Map<string, Uint8Array> => {
  const count = reader.u16();
  if (count > MAX_ACTIVE_RECEIVE_KEYS)
    fail("checkpoint has too many active receive message keys");
  const result = new Map<string, Uint8Array>();
  try {
    for (let index = 0; index < count; index += 1) {
      const keyLength = reader.u16();
      if (keyLength === 0 || keyLength > MAX_CACHE_KEY_BYTES)
        fail("checkpoint active receive cache key length is invalid");
      const encoded = reader.take(keyLength);
      let key: string;
      try {
        key = textDecoder.decode(encoded);
      } finally {
        encoded.fill(0);
      }
      if (
        key.length === 0 ||
        !CANONICAL_CACHE_KEY.test(key) ||
        result.has(key)
      )
        fail("checkpoint active receive cache key is non-canonical");
      result.set(key, reader.take(32));
    }
    return result;
  } catch (error) {
    for (const value of result.values()) value.fill(0);
    result.clear();
    throw error;
  }
};

const copyOutbox = (
  outbox: PqHealingOutbox | null,
): PqHealingOutbox | null =>
  outbox === null
    ? null
    : {
        kind: outbox.kind,
        frame: Uint8Array.from(outbox.frame),
        attempts: outbox.attempts,
        nextRetryAt: outbox.nextRetryAt,
      };

const wipeMap = (map: Map<string, Uint8Array>): void => {
  for (const value of map.values()) value.fill(0);
  map.clear();
};

const copyMap = (
  source: ReadonlyMap<string, Uint8Array>,
): Map<string, Uint8Array> => {
  const result = new Map<string, Uint8Array>();
  for (const [key, value] of source) result.set(key, Uint8Array.from(value));
  return result;
};

export class SparsePqHealingState {
  readonly #module: LibCrypto;
  readonly #pqMode: RoomPqMode;
  readonly #rootSuite: RatchetRootSuite;
  readonly #suite: ReturnType<typeof getMlKemSuite>;
  readonly #backend: ReturnType<typeof createMlKemBackend>;
  readonly #binding: Uint8Array;
  readonly #outboundDirection: PqControlDirection;
  readonly #inboundDirection: PqControlDirection;

  #machine: PqHealingMachine<MlKemParameterSet>;
  #messageRoot: Uint8Array;
  #outbox: PqHealingOutbox | null = null;
  #lastInboundOfferFrame: Uint8Array | null = null;
  #lastInboundAdvanceFrame: Uint8Array | null = null;
  #cachedAckFrame: Uint8Array | null = null;
  #activeReceiveKeys = new Map<string, Uint8Array>();
  #messagesSinceHealing = 0;
  #lastHealedAt: number;
  #destroyed = false;

  constructor(options: SparsePqHealingOptions) {
    const parameterSet = roomPqModeToParameterSet(options.pqMode);
    if (roomPqModeToRootSuite(options.pqMode) !== options.rootSuite)
      fail("authenticated root suite and room PQ mode disagree");
    requireBytes(options.binding, "edge binding", 32);
    requireBytes(options.rootKey, "PQ root", 32);
    this.#module = options.module;
    this.#pqMode = options.pqMode;
    this.#rootSuite = options.rootSuite;
    this.#suite = getMlKemSuite(parameterSet);
    this.#backend = createMlKemBackend(options.module, this.#suite);
    this.#binding = Uint8Array.from(options.binding);
    this.#machine = new PqHealingMachine({
      module: options.module,
      backend: this.#backend,
      suite: this.#suite,
      binding: this.#binding,
      rootKey: options.rootKey,
      nextOfferer: options.nextOfferer,
    });
    this.#messageRoot = this.#machine.copyRootKey();
    this.#lastHealedAt = requireSafeUint(
      options.now ?? Date.now(),
      "initial healing time",
    );
    this.#outboundDirection = options.amInitiator
      ? "initiator-to-responder"
      : "responder-to-initiator";
    this.#inboundDirection = options.amInitiator
      ? "responder-to-initiator"
      : "initiator-to-responder";
  }

  get pqMode(): RoomPqMode {
    return this.#pqMode;
  }

  get rootSuite(): RatchetRootSuite {
    return this.#rootSuite;
  }

  get epoch(): bigint {
    this.#assertLive();
    return this.#machine.epoch;
  }

  get phase(): PqHealingPhase {
    return this.#machine.phase;
  }

  get trafficBlocked(): boolean {
    return this.#destroyed || this.#machine.trafficBlocked;
  }

  get nextOfferer(): PqHealingTurn {
    return this.#machine.nextOfferer;
  }

  get activeReceiveKeys(): Map<string, Uint8Array> {
    this.#assertLive();
    return this.#activeReceiveKeys;
  }

  get messagesSinceHealing(): number {
    this.#assertLive();
    return this.#messagesSinceHealing;
  }

  get lastHealedAt(): number {
    this.#assertLive();
    return this.#lastHealedAt;
  }

  currentMessageContext(): PqMessageKeyContext {
    this.#assertLive();
    return {
      rootKey: this.#messageRoot,
      binding: this.#binding,
      rootSuite: this.#rootSuite,
      epoch: this.#machine.epoch,
    };
  }

  resolveMessageContext(epoch: bigint): PqMessageKeyContext | null {
    this.#assertLive();
    return epoch === this.#machine.epoch
      ? this.currentMessageContext()
      : null;
  }

  noteApplicationMessage(): void {
    this.#assertLive();
    if (this.#messagesSinceHealing >= Number.MAX_SAFE_INTEGER)
      fail("application-message counter overflow");
    this.#messagesSinceHealing += 1;
  }

  healingDue(now = Date.now()): boolean {
    this.#assertLive();
    requireSafeUint(now, "healing clock");
    return (
      !this.#machine.trafficBlocked &&
      this.#machine.nextOfferer === "local" &&
      (this.#messagesSinceHealing >= PQ_HEAL_AFTER_MESSAGES ||
        now - this.#lastHealedAt >= PQ_HEAL_AFTER_MS)
    );
  }

  copyPendingFrame(): Uint8Array | null {
    this.#assertLive();
    return this.#outbox ? Uint8Array.from(this.#outbox.frame) : null;
  }

  get pendingRetryAt(): number | null {
    this.#assertLive();
    return this.#outbox?.nextRetryAt ?? null;
  }

  get pendingAttempts(): number {
    this.#assertLive();
    return this.#outbox?.attempts ?? 0;
  }

  markPendingDispatched(now = Date.now()): void {
    this.#assertLive();
    const outbox = this.#outbox;
    if (!outbox) return fail("there is no PQ control outbox");
    requireSafeUint(now, "dispatch clock");
    if (outbox.attempts >= PQ_HEAL_MAX_RETRIES)
      fail("PQ control retry budget is exhausted");
    this.#outbox = {
      kind: outbox.kind,
      frame: outbox.frame,
      attempts: outbox.attempts + 1,
      nextRetryAt: now + PQ_HEAL_RETRY_MS,
    };
  }

  async prepareHealingOffer(now = Date.now()): Promise<Uint8Array> {
    this.#assertLive();
    if (!this.healingDue(now))
      fail("a local sparse-PQ healing exchange is not due");
    const record = await this.#machine.prepareOffer();
    const root = this.#machine.copyRootKey();
    try {
      const frame = sealPqControlFrame({
        module: this.#module,
        suite: this.#suite,
        rootKey: root,
        binding: this.#binding,
        direction: this.#outboundDirection,
        keyEpoch: this.#machine.epoch,
        record,
      });
      this.#machine.markOfferDispatched();
      this.#outbox?.frame.fill(0);
      this.#outbox = {
        kind: "offer",
        frame: Uint8Array.from(frame),
        attempts: 0,
        nextRetryAt: now,
      };
      this.#clearDuplicateCache();
      return frame;
    } finally {
      root.fill(0);
      record.fill(0);
    }
  }

  async acceptControlFrame(
    frame: Uint8Array,
    now = Date.now(),
  ): Promise<PqHealingControlResult> {
    this.#assertLive();
    requireBytes(frame, "PQ control frame", WIRE_CHUNK_FRAME_LEN);
    requireSafeUint(now, "control clock");

    if (
      this.#lastInboundOfferFrame &&
      this.#outbox?.kind === "advance" &&
      bytesEqual(frame, this.#lastInboundOfferFrame)
    )
      return {
        dispatch: Uint8Array.from(this.#outbox.frame),
        changed: false,
      };
    if (
      this.#lastInboundAdvanceFrame &&
      this.#cachedAckFrame &&
      bytesEqual(frame, this.#lastInboundAdvanceFrame)
    )
      return {
        dispatch: Uint8Array.from(this.#cachedAckFrame),
        changed: false,
      };

    const root = this.#machine.copyRootKey();
    let record: Uint8Array | null = null;
    try {
      record = openPqControlFrame({
        module: this.#module,
        suite: this.#suite,
        rootKey: root,
        binding: this.#binding,
        direction: this.#inboundDirection,
        keyEpoch: this.#machine.epoch,
        frame,
      });

      if (record.length === PQ_HEALING_ACK_BYTES) {
        const outbox = this.#outbox;
        if (outbox?.kind !== "advance")
          return fail("unexpected PQ ADVANCE acknowledgement");
        const acknowledgement = decodePqHealingAck(
          record,
          this.#suite,
          this.#binding,
        );
        this.#machine.acceptAuthenticatedAdvanceAcknowledgement(
          acknowledgement,
        );
        outbox.frame.fill(0);
        this.#outbox = null;
        this.#clearDuplicateCache();
        this.#messagesSinceHealing = 0;
        this.#lastHealedAt = now;
        this.#refreshMessageRoot();
        return { dispatch: null, changed: true };
      }

      const inspected = inspectPqHealingRecord(record, this.#suite);
      if (inspected.type === "offer") {
        this.#machine.acceptAuthenticatedOffer(record);
        const advance = await this.#machine.prepareAdvance();
        let sealedAdvance: Uint8Array;
        try {
          sealedAdvance = sealPqControlFrame({
            module: this.#module,
            suite: this.#suite,
            rootKey: root,
            binding: this.#binding,
            direction: this.#outboundDirection,
            keyEpoch: this.#machine.epoch,
            record: advance,
          });
          this.#machine.commitPreparedAdvance();
        } finally {
          advance.fill(0);
        }
        this.#outbox?.frame.fill(0);
        this.#outbox = {
          kind: "advance",
          frame: Uint8Array.from(sealedAdvance),
          attempts: 0,
          nextRetryAt: now,
        };
        this.#lastInboundOfferFrame?.fill(0);
        this.#lastInboundOfferFrame = Uint8Array.from(frame);
        this.#lastInboundAdvanceFrame?.fill(0);
        this.#lastInboundAdvanceFrame = null;
        this.#cachedAckFrame?.fill(0);
        this.#cachedAckFrame = null;
        this.#refreshMessageRoot();
        return { dispatch: sealedAdvance, changed: true };
      }

      const offerOutbox = this.#outbox;
      if (offerOutbox?.kind !== "offer")
        return fail("unexpected PQ ADVANCE without a persisted OFFER");
      await this.#machine.acceptAuthenticatedAdvance(record);
      const acknowledgement = this.#machine.commitAcceptedAdvance();
      const ackRecord = encodePqHealingAck(
        acknowledgement,
        this.#suite,
        this.#binding,
      );
      const nextRoot = this.#machine.copyRootKey();
      try {
        const ackFrame = sealPqControlFrame({
          module: this.#module,
          suite: this.#suite,
          rootKey: nextRoot,
          binding: this.#binding,
          direction: this.#outboundDirection,
          keyEpoch: acknowledgement.epoch,
          record: ackRecord,
        });
        this.#machine.markAdvanceAcknowledgementDispatched(acknowledgement);
        offerOutbox.frame.fill(0);
        this.#outbox = null;
        this.#lastInboundAdvanceFrame?.fill(0);
        this.#lastInboundAdvanceFrame = Uint8Array.from(frame);
        this.#cachedAckFrame?.fill(0);
        this.#cachedAckFrame = Uint8Array.from(ackFrame);
        this.#lastInboundOfferFrame?.fill(0);
        this.#lastInboundOfferFrame = null;
        this.#messagesSinceHealing = 0;
        this.#lastHealedAt = now;
        this.#refreshMessageRoot();
        return { dispatch: ackFrame, changed: true };
      } finally {
        nextRoot.fill(0);
        ackRecord.fill(0);
      }
    } finally {
      root.fill(0);
      record?.fill(0);
    }
  }

  clone(): SparsePqHealingState {
    this.#assertLive();
    const root = this.#machine.copyRootKey();
    let clone: SparsePqHealingState | null = null;
    try {
      clone = new SparsePqHealingState({
        module: this.#module,
        pqMode: this.#pqMode,
        rootSuite: this.#rootSuite,
        binding: this.#binding,
        rootKey: root,
        nextOfferer: this.#machine.nextOfferer,
        amInitiator:
          this.#outboundDirection === "initiator-to-responder",
        now: this.#lastHealedAt,
      });
      clone.#machine.destroy();
      clone.#machine = this.#machine.clone();
      clone.#messageRoot.fill(0);
      clone.#messageRoot = Uint8Array.from(this.#messageRoot);
      clone.#outbox = copyOutbox(this.#outbox);
      clone.#lastInboundOfferFrame =
        this.#lastInboundOfferFrame === null
          ? null
          : Uint8Array.from(this.#lastInboundOfferFrame);
      clone.#lastInboundAdvanceFrame =
        this.#lastInboundAdvanceFrame === null
          ? null
          : Uint8Array.from(this.#lastInboundAdvanceFrame);
      clone.#cachedAckFrame =
        this.#cachedAckFrame === null
          ? null
          : Uint8Array.from(this.#cachedAckFrame);
      clone.#activeReceiveKeys = copyMap(this.#activeReceiveKeys);
      clone.#messagesSinceHealing = this.#messagesSinceHealing;
      clone.#lastHealedAt = this.#lastHealedAt;
      return clone;
    } catch (error) {
      clone?.destroy();
      throw error;
    } finally {
      root.fill(0);
    }
  }

  adopt(next: SparsePqHealingState): void {
    this.#assertLive();
    next.#assertLive();
    if (next === this) fail("cannot adopt a PQ runtime into itself");
    if (
      next.#module !== this.#module ||
      next.#pqMode !== this.#pqMode ||
      next.#rootSuite !== this.#rootSuite ||
      next.#outboundDirection !== this.#outboundDirection ||
      !bytesEqual(next.#binding, this.#binding)
    )
      fail("cannot adopt a PQ runtime from another authenticated edge");

    this.#machine.destroy();
    this.#messageRoot.fill(0);
    this.#outbox?.frame.fill(0);
    this.#lastInboundOfferFrame?.fill(0);
    this.#lastInboundAdvanceFrame?.fill(0);
    this.#cachedAckFrame?.fill(0);
    wipeMap(this.#activeReceiveKeys);

    this.#machine = next.#machine;
    this.#messageRoot = next.#messageRoot;
    this.#outbox = next.#outbox;
    this.#lastInboundOfferFrame = next.#lastInboundOfferFrame;
    this.#lastInboundAdvanceFrame = next.#lastInboundAdvanceFrame;
    this.#cachedAckFrame = next.#cachedAckFrame;
    this.#activeReceiveKeys = next.#activeReceiveKeys;
    this.#messagesSinceHealing = next.#messagesSinceHealing;
    this.#lastHealedAt = next.#lastHealedAt;

    next.#messageRoot = new Uint8Array(32);
    next.#outbox = null;
    next.#lastInboundOfferFrame = null;
    next.#lastInboundAdvanceFrame = null;
    next.#cachedAckFrame = null;
    next.#activeReceiveKeys = new Map();
    next.#binding.fill(0);
    next.#destroyed = true;
  }

  serialize(
    activeReceiveKeys: ReadonlyMap<string, Uint8Array> =
      this.#activeReceiveKeys,
  ): Uint8Array {
    this.#assertLive();
    const snapshot = this.#machine.snapshot();
    const writer = new ByteWriter();
    try {
      writer.bytes(EDGE_MAGIC);
      writer.u8(EDGE_FORMAT_VERSION);
      writer.u8(suiteTag(this.#suite.parameterSet));
      writer.u8(
        this.#outboundDirection === "initiator-to-responder" ? 1 : 2,
      );
      writer.u8(0);
      writer.u64(BigInt(this.#lastHealedAt));
      writer.u64(BigInt(this.#messagesSinceHealing));
      writer.bytes(snapshot.binding);
      writer.bytes(snapshot.rootKey);
      writer.u64(snapshot.epoch);
      writer.u64(snapshot.localCounter);
      writer.u64(snapshot.remoteCounter);
      writer.u8(turnTag(snapshot.nextOfferer));
      writePhase(writer, snapshot.phase);
      writer.sized(snapshot.lastInboundOffer);
      writer.sized(snapshot.lastInboundAdvance);
      writeOutbox(writer, this.#outbox);
      writer.sized(this.#lastInboundOfferFrame);
      writer.sized(this.#lastInboundAdvanceFrame);
      writer.sized(this.#cachedAckFrame);
      writeActiveKeys(writer, activeReceiveKeys);
      return writer.finish();
    } finally {
      wipePqHealingSnapshot(snapshot);
    }
  }

  /**
   * Read the public edge binding out of a checkpoint without instantiating the
   * runtime. A store-free consumer that keeps the whole checkpoint under
   * authenticated encryption (rather than a separate binding) uses this to
   * supply the expected binding to `restore`. The binding layout is fixed:
   * magic(8) | version(1) | suite(1) | direction(1) | reserved(1) |
   * lastHealedAt(8) | messagesSinceHealing(8) | binding(32).
   */
  static readCheckpointBinding(bytes: Uint8Array): Uint8Array {
    requireBytes(bytes, "checkpoint");
    const bindingOffset =
      EDGE_MAGIC.length + 1 + 1 + 1 + 1 + 8 + 8;
    if (bytes.length < bindingOffset + 32)
      return fail("checkpoint is too short to contain a binding");
    return bytes.slice(bindingOffset, bindingOffset + 32);
  }

  static restore(
    bytes: Uint8Array,
    options: RestoreSparsePqHealingOptions,
  ): SparsePqHealingState {
    requireBytes(bytes, "encrypted edge checkpoint plaintext");
    requireBytes(options.binding, "expected edge binding", 32);
    const reader = new ByteReader(bytes);
    let snapshot: PqHealingSnapshot | null = null;
    let machine: PqHealingMachine<MlKemParameterSet> | null = null;
    let restored: SparsePqHealingState | null = null;
    let activeKeys: Map<string, Uint8Array> | null = null;
    let outbox: PqHealingOutbox | null = null;
    let lastOfferFrame: Uint8Array | null = null;
    let lastAdvanceFrame: Uint8Array | null = null;
    let cachedAckFrame: Uint8Array | null = null;
    try {
      const magic = reader.take(EDGE_MAGIC.length);
      const validMagic = bytesEqual(magic, EDGE_MAGIC);
      magic.fill(0);
      if (!validMagic) fail("checkpoint magic is invalid");
      if (reader.u8() !== EDGE_FORMAT_VERSION)
        fail("checkpoint version is unsupported");
      const parameterSet = tagSuite(reader.u8());
      if (parameterSet !== roomPqModeToParameterSet(options.pqMode))
        fail("checkpoint suite disagrees with the authenticated room policy");
      if (roomPqModeToRootSuite(options.pqMode) !== options.rootSuite)
        fail("authenticated root suite and room PQ mode disagree");
      const directionTag = reader.u8();
      const expectedDirection = options.amInitiator ? 1 : 2;
      if (directionTag !== expectedDirection)
        fail("checkpoint belongs to the opposite edge direction");
      if (reader.u8() !== 0) fail("checkpoint reserved byte is non-zero");
      const lastHealedAtU64 = reader.u64();
      const messagesSinceHealingU64 = reader.u64();
      if (
        lastHealedAtU64 > BigInt(Number.MAX_SAFE_INTEGER) ||
        messagesSinceHealingU64 > BigInt(Number.MAX_SAFE_INTEGER)
      )
        fail("checkpoint counters exceed the safe-integer range");
      const binding = reader.take(32);
      if (!bytesEqual(binding, options.binding))
        fail("checkpoint belongs to another authenticated edge");
      const rootKey = reader.take(32);
      const suite = getMlKemSuite(parameterSet);
      snapshot = {
        formatVersion: 1,
        parameterSet,
        binding,
        rootKey,
        epoch: reader.u64(),
        localCounter: reader.u64(),
        remoteCounter: reader.u64(),
        nextOfferer: tagTurn(reader.u8()),
        phase: readPhase(reader, suite),
        lastInboundOffer: reader.sized(8 * 1024),
        lastInboundAdvance: reader.sized(8 * 1024),
      };
      outbox = readOutbox(reader);
      lastOfferFrame = reader.sized(WIRE_CHUNK_FRAME_LEN);
      lastAdvanceFrame = reader.sized(WIRE_CHUNK_FRAME_LEN);
      cachedAckFrame = reader.sized(WIRE_CHUNK_FRAME_LEN);
      for (const frame of [
        lastOfferFrame,
        lastAdvanceFrame,
        cachedAckFrame,
      ])
        if (frame) requireBytes(frame, "cached control frame", WIRE_CHUNK_FRAME_LEN);
      activeKeys = readActiveKeys(reader);
      reader.finish();

      const backend = createMlKemBackend(options.module, suite);
      machine = PqHealingMachine.restore(snapshot, {
        module: options.module,
        backend,
        suite,
        binding: options.binding,
      });
      const root = machine.copyRootKey();
      try {
        restored = new SparsePqHealingState({
          module: options.module,
          pqMode: options.pqMode,
          rootSuite: options.rootSuite,
          binding: options.binding,
          rootKey: root,
          nextOfferer: machine.nextOfferer,
          amInitiator: options.amInitiator,
          now: Number(lastHealedAtU64),
        });
      } finally {
        root.fill(0);
      }
      restored.#machine.destroy();
      restored.#machine = machine;
      machine = null;
      restored.#messageRoot.fill(0);
      restored.#messageRoot = restored.#machine.copyRootKey();
      restored.#outbox = outbox;
      outbox = null;
      restored.#lastInboundOfferFrame = lastOfferFrame;
      lastOfferFrame = null;
      restored.#lastInboundAdvanceFrame = lastAdvanceFrame;
      lastAdvanceFrame = null;
      restored.#cachedAckFrame = cachedAckFrame;
      cachedAckFrame = null;
      restored.#activeReceiveKeys = activeKeys;
      activeKeys = null;
      restored.#messagesSinceHealing = Number(messagesSinceHealingU64);
      restored.#validateCheckpointCoherence();
      return restored;
    } catch (error) {
      restored?.destroy();
      throw error;
    } finally {
      reader.destroy();
      if (snapshot) wipePqHealingSnapshot(snapshot);
      machine?.destroy();
      outbox?.frame.fill(0);
      lastOfferFrame?.fill(0);
      lastAdvanceFrame?.fill(0);
      cachedAckFrame?.fill(0);
      if (activeKeys) wipeMap(activeKeys);
    }
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#machine.destroy();
    this.#binding.fill(0);
    this.#messageRoot.fill(0);
    this.#outbox?.frame.fill(0);
    this.#lastInboundOfferFrame?.fill(0);
    this.#lastInboundAdvanceFrame?.fill(0);
    this.#cachedAckFrame?.fill(0);
    wipeMap(this.#activeReceiveKeys);
    this.#outbox = null;
    this.#lastInboundOfferFrame = null;
    this.#lastInboundAdvanceFrame = null;
    this.#cachedAckFrame = null;
    this.#destroyed = true;
  }

  #refreshMessageRoot(): void {
    const next = this.#machine.copyRootKey();
    this.#messageRoot.fill(0);
    this.#messageRoot = next;
  }

  #clearDuplicateCache(): void {
    this.#lastInboundOfferFrame?.fill(0);
    this.#lastInboundAdvanceFrame?.fill(0);
    this.#cachedAckFrame?.fill(0);
    this.#lastInboundOfferFrame = null;
    this.#lastInboundAdvanceFrame = null;
    this.#cachedAckFrame = null;
  }

  #validateCheckpointCoherence(): void {
    const phase = this.#machine.phase;
    if (
      (phase === "outbound-offer-dispatched" &&
        this.#outbox?.kind !== "offer") ||
      (phase === "outbound-advance-awaiting-ack" &&
        this.#outbox?.kind !== "advance") ||
      (this.#outbox?.kind === "offer" &&
        phase !== "outbound-offer-dispatched") ||
      (this.#outbox?.kind === "advance" &&
        phase !== "outbound-advance-awaiting-ack")
    )
      fail("checkpoint PQ phase and sealed outbox disagree");
    if (
      this.#lastInboundOfferFrame !== null &&
      this.#outbox?.kind !== "advance"
    )
      fail("checkpoint cached OFFER has no matching ADVANCE outbox");
    if (
      (this.#lastInboundAdvanceFrame === null) !==
      (this.#cachedAckFrame === null)
    )
      fail("checkpoint ADVANCE replay and ACK cache must be paired");
    if (
      this.#lastInboundOfferFrame !== null &&
      this.#lastInboundAdvanceFrame !== null
    )
      fail("checkpoint contains mutually exclusive replay caches");
  }

  #assertLive(): void {
    if (this.#destroyed) fail("state is destroyed");
  }
}

