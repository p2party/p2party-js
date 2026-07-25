import libcrypto from "./cryptography/libcrypto";
import { wasmLoader } from "./cryptography/wasmLoader";
import { secureRandomUint32 } from "./cryptography/random";
import { newKeyPair } from "./cryptography/ed25519";
import { newX25519KeyPair, x25519Dh } from "./cryptography/x25519";
import {
  crossSignIdentityX25519,
  verifyIdentityCrossSig,
} from "./cryptography/identityCrossSig";
import {
  adoptRatchet,
  cloneRatchet,
  deserializeRatchet,
  ratchetEncrypt,
  serializeRatchet,
  wipeRatchet,
} from "./cryptography/ratchet";
import { getMerkleProof, getMerkleRoot } from "./cryptography/merkle";
import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_scalarmult_curve25519_BYTES,
  crypto_scalarmult_curve25519_SCALARBYTES,
} from "./cryptography/interfaces";
import {
  buildChannelInput,
  performHandshakeCore,
  type HandshakeTransport,
} from "./handlers/handshakeCore";
import { decryptMessageChunk, sealChunk } from "./handlers/messageChunkCrypto";
import { parseChunkFrameHeader } from "./handlers/chunkFrame";
import { SparsePqHealingState } from "./handlers/pqHealingRuntime";
import { hashMerkleLeafWasm } from "./utils/leafHash";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  MAX_SKIP_SESSION,
  METADATA_LEN,
  PROOF_LEN,
  PROTOCOL_VERSION,
  RATCHET_ROOT_SUITE_MLKEM512,
  RATCHET_ROOT_SUITE_MLKEM768,
  RATCHET_ROOT_SUITE_MLKEM1024,
  WIRE_CHUNK_FRAME_LEN,
} from "./utils/constants";
import { rootSuiteToRoomPqMode } from "./roomPolicy";
import { deserializeMetadata, serializeMetadata } from "./utils/metadata";
import { MessageType } from "./utils/messageTypes";
import { AsyncMutex } from "./utils/mutex";

import type { LibCrypto } from "./cryptography/libcrypto";
import type {
  RatchetSessionSecrets,
  RatchetState,
} from "./cryptography/ratchet";
import type { RoomPqMode } from "./roomPolicy";
import type { RatchetRootSuite } from "./utils/constants";

// Format version 4 is the protocol-v4 break: the snapshot carries the sparse
// PQ machine/root/epoch/turn/counters plus its active combined receive keys
// (inside the appended P2EDGE4 checkpoint) alongside the Double Ratchet. A v3
// snapshot is rejected outright. Suite tags are unchanged provenance codes.
const SESSION_SNAPSHOT_VERSION = 4;
const SESSION_ROOT_SUITE_3DH_ML_KEM_768_CPACE21 = 3;
const SESSION_ROOT_SUITE_3DH_ML_KEM_512_CPACE21 = 4;
const SESSION_ROOT_SUITE_3DH_ML_KEM_1024_CPACE21 = 5;
const SESSION_MAGIC = new Uint8Array([
  0x50, 0x32, 0x50, 0x53, 0x45, 0x53, 0x53, 0x00,
]); // "P2PSESS\0"
const SNAPSHOT_FLAG_SENDING_CHAIN = 1 << 0;
const SNAPSHOT_FLAG_RECEIVING_CHAIN = 1 << 1;
const SNAPSHOT_FLAG_REMOTE_DH = 1 << 2;
// The v4 snapshot always carries an edge PQ checkpoint and records the stable
// role so restore rebuilds the runtime with the correct control-frame
// direction.
const SNAPSHOT_FLAG_INITIATOR = 1 << 3;
const SNAPSHOT_KNOWN_FLAGS =
  SNAPSHOT_FLAG_SENDING_CHAIN |
  SNAPSHOT_FLAG_RECEIVING_CHAIN |
  SNAPSHOT_FLAG_REMOTE_DH |
  SNAPSHOT_FLAG_INITIATOR;
const SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES = 4;
const SNAPSHOT_MAX_PQ_CHECKPOINT_BYTES = 256 * 1024;
const SNAPSHOT_FIXED_PREFIX_LEN =
  SESSION_MAGIC.length +
  4 + // snapshot version, protocol version, flags, root suite
  3 * 8 + // Ns, Nr, PN
  32 + // root key
  32 + // self DH public key
  32 + // self DH secret key
  2; // skipped-key count
const SNAPSHOT_SKIPPED_ENTRY_LEN = 32 + 8 + 32;
const SESSION_WASM_PAGES = 32;
const SESSION_METADATA_NAME = "p2party-session";

export type { HandshakeTransport };
export type { RoomPqMode } from "./roomPolicy";

/**
 * The wire constants a caller needs to build its own outer framing. The
 * session hands back opaque fixed-size frames and expects the same back, so an
 * adapter has to length-check and version-check records itself; re-exporting
 * these keeps it from hardcoding values that a wire break would silently
 * invalidate.
 */
export { PROTOCOL_VERSION, WIRE_CHUNK_FRAME_LEN };

export interface LocalSessionIdentity {
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  /** The X25519 identity secret used by interactive 3DH; never Ed25519. */
  x25519SecretKey: Uint8Array;
  x25519CrossSignature: Uint8Array;
}

export interface GeneratedSessionIdentity extends LocalSessionIdentity {
  ed25519SecretKey: Uint8Array;
}

export interface SessionChannelBinding {
  channelId: Uint8Array;
  localFingerprint: Uint8Array;
  remoteFingerprint: Uint8Array;
}

export interface SessionCryptoOptions {
  /**
   * Local/self-hosted libcrypto.wasm bytes. Supply this in Node/Bun or offline
   * deployments; when omitted the versioned p2party CDN loader is used.
   */
  wasmBinary?: ArrayBuffer | Uint8Array;
}

export type SessionAuth =
  { mode: "nopin"; pin?: never } | { mode: "pin"; pin: Uint8Array };

export type CreateSessionOptions = {
  transport: HandshakeTransport;
  role: "initiator" | "responder";
  identity: LocalSessionIdentity;
  /** Externally pinned (or explicitly TOFU-accepted) peer Ed25519 identity. */
  peerIdentityEd25519PublicKey: Uint8Array;
  channel: SessionChannelBinding;
  /** Exact suite chosen out-of-band for both peers; defaults to ML-KEM-768. */
  pqMode?: RoomPqMode;
  crypto?: SessionCryptoOptions;
} & SessionAuth;

export interface EncryptedSessionMessage {
  protocolVersion: 4;
  /** The message Merkle root; authenticated as AEAD additional data. */
  root: Uint8Array;
  /** Uniform protocol-v3 chunk frames. */
  frames: Uint8Array[];
}

/**
 * One exact sealed sparse-PQ control cell to dispatch after the caller has
 * persisted the mutated session, plus whether a durable write is required
 * before sending (false for an exact duplicate response).
 */
export interface SessionControlOutput {
  readonly frame: Uint8Array | null;
  readonly requiresPersistBeforeSend: boolean;
}

export interface P2PartySession {
  readonly protocolVersion: 4;
  readonly pqMode: RoomPqMode;
  /** True for either role after a successful handshake; false after destroy. */
  readonly canEncrypt: boolean;
  /** Current authenticated PQ epoch; 0 before any healing exchange. */
  readonly pqEpoch: bigint;
  /** True while a sparse-PQ healing exchange blocks application traffic. */
  readonly healingInProgress: boolean;
  encrypt(plaintext: Uint8Array): Promise<EncryptedSessionMessage>;
  decrypt(message: EncryptedSessionMessage): Promise<Uint8Array>;
  /**
   * Store-free sparse-PQ healing for custom transports. Contract: after any of
   * these returns a frame, the caller MUST persist `serialize()` BEFORE
   * sending that frame, so a crash cannot fork the OFFER/ADVANCE/ACK sequence.
   *
   * `prepareHealing` starts a due local exchange (returns null when not due or
   * not this side's turn). `acceptControlFrame` processes an inbound OFFER,
   * ADVANCE, or ACK and returns the exact response to send. `pendingControl`
   * returns the exact frame to retransmit for a dropped flight.
   */
  prepareHealing(): Promise<SessionControlOutput>;
  acceptControlFrame(frame: Uint8Array): Promise<SessionControlOutput>;
  pendingControl(): Promise<Uint8Array | null>;
  /**
   * Plaintext secret snapshot (Double Ratchet + PQ machine/root/epoch/turn/
   * counters + active combined receive keys). Store only under authenticated
   * encryption with rollback protection; never send this blob to the peer.
   */
  serialize(): Promise<Uint8Array>;
  destroy(): Promise<void>;
}

export interface GenerateSessionIdentityOptions extends SessionCryptoOptions {
  ed25519KeyPair?: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
}

const copyBytes = (value: Uint8Array): Uint8Array => Uint8Array.from(value);

const exactArrayBuffer = (value: ArrayBuffer | Uint8Array): ArrayBuffer => {
  if (value instanceof Uint8Array) return value.slice().buffer;
  return value.slice(0);
};

function requireBytes(
  value: unknown,
  name: string,
  expectedLength?: number,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array))
    throw new TypeError(`${name} must be a Uint8Array`);
  if (expectedLength !== undefined && value.length !== expectedLength)
    throw new RangeError(`${name} must be ${String(expectedLength)} bytes`);
}

const requireSafeUint = (value: number, name: string): void => {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > Number.MAX_SAFE_INTEGER
  )
    throw new RangeError(`${name} must be a non-negative safe integer`);
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
};

const bytesHex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

const sha512 = async (value: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-512", value.slice().buffer),
  );

const loadSessionCrypto = async (
  options?: SessionCryptoOptions,
): Promise<LibCrypto> => {
  const wasmMemory = new WebAssembly.Memory({
    initial: SESSION_WASM_PAGES,
    maximum: SESSION_WASM_PAGES,
  });
  if (options?.wasmBinary) {
    return (await libcrypto({
      wasmBinary: exactArrayBuffer(options.wasmBinary),
      wasmMemory,
      getRandomValue: secureRandomUint32,
    })) as LibCrypto;
  }
  return (await wasmLoader(wasmMemory)) as LibCrypto;
};

const validateLocalIdentity = (identity: LocalSessionIdentity): void => {
  if (!identity || typeof identity !== "object")
    throw new TypeError("identity is required");
  requireBytes(
    identity.ed25519PublicKey,
    "identity.ed25519PublicKey",
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  requireBytes(
    identity.x25519PublicKey,
    "identity.x25519PublicKey",
    crypto_scalarmult_curve25519_BYTES,
  );
  requireBytes(
    identity.x25519SecretKey,
    "identity.x25519SecretKey",
    crypto_scalarmult_curve25519_SCALARBYTES,
  );
  requireBytes(
    identity.x25519CrossSignature,
    "identity.x25519CrossSignature",
    crypto_sign_ed25519_BYTES,
  );
};

const validateLocalIdentityCryptographically = async (
  identity: LocalSessionIdentity,
  module: LibCrypto,
): Promise<void> => {
  // RFC 7748 X25519 base point (u = 9): scalar-multiplying it derives the
  // public key corresponding to the supplied secret.
  const basePoint = new Uint8Array(crypto_scalarmult_curve25519_BYTES);
  basePoint[0] = 9;
  const derivedPublic = x25519Dh(identity.x25519SecretKey, basePoint, module);
  try {
    if (!bytesEqual(derivedPublic, identity.x25519PublicKey))
      throw new Error("identity X25519 public and secret keys do not match");
  } finally {
    derivedPublic.fill(0);
  }

  if (
    !(await verifyIdentityCrossSig(
      identity.x25519PublicKey,
      identity.x25519CrossSignature,
      identity.ed25519PublicKey,
      module,
    ))
  )
    throw new Error("identity X25519 cross-signature is invalid");
};

export const generateSessionIdentity = async (
  options: GenerateSessionIdentityOptions = {},
): Promise<GeneratedSessionIdentity> => {
  const module = await loadSessionCrypto(options);
  let edPublic: Uint8Array | null = null;
  let edSecret: Uint8Array | null = null;
  let xSecret: Uint8Array | null = null;
  try {
    if (options.ed25519KeyPair) {
      requireBytes(
        options.ed25519KeyPair.publicKey,
        "ed25519KeyPair.publicKey",
        crypto_sign_ed25519_PUBLICKEYBYTES,
      );
      requireBytes(
        options.ed25519KeyPair.secretKey,
        "ed25519KeyPair.secretKey",
        crypto_sign_ed25519_SECRETKEYBYTES,
      );
      edPublic = copyBytes(options.ed25519KeyPair.publicKey);
      edSecret = copyBytes(options.ed25519KeyPair.secretKey);
    } else {
      const generated = await newKeyPair(module);
      edPublic = generated.publicKey;
      edSecret = generated.secretKey;
    }

    const x25519 = await newX25519KeyPair(module);
    xSecret = x25519.secretKey;
    const x25519CrossSignature = await crossSignIdentityX25519(
      x25519.publicKey,
      edSecret,
      module,
    );
    if (
      !(await verifyIdentityCrossSig(
        x25519.publicKey,
        x25519CrossSignature,
        edPublic,
        module,
      ))
    )
      throw new Error("ed25519KeyPair public and secret keys do not match");
    const result: GeneratedSessionIdentity = {
      ed25519PublicKey: edPublic,
      ed25519SecretKey: edSecret,
      x25519PublicKey: x25519.publicKey,
      x25519SecretKey: xSecret,
      x25519CrossSignature,
    };
    edPublic = null;
    edSecret = null;
    xSecret = null;
    return result;
  } finally {
    edPublic?.fill(0);
    edSecret?.fill(0);
    xSecret?.fill(0);
  }
};

interface PreparedMessage {
  root: Uint8Array;
  chunks: Uint8Array[];
  plaintexts: Uint8Array[];
}

const wipePreparedMessage = (prepared: PreparedMessage): void => {
  for (const chunk of prepared.chunks) chunk.fill(0);
  for (const plaintext of prepared.plaintexts) plaintext.fill(0);
};

const prepareMessage = async (
  plaintext: Uint8Array,
  module: LibCrypto,
): Promise<PreparedMessage> => {
  const totalSize = plaintext.length;
  const totalChunks = Math.max(1, Math.ceil(totalSize / CHUNK_LEN));
  const chunks: Uint8Array[] = [];
  const plaintexts: Uint8Array[] = [];
  try {
    for (let index = 0; index < totalChunks; index++) {
      const start = index * CHUNK_LEN;
      const usefulLength = Math.min(CHUNK_LEN, Math.max(0, totalSize - start));
      const chunk = globalThis.crypto.getRandomValues(
        new Uint8Array(CHUNK_LEN),
      );
      chunk.set(plaintext.subarray(start, start + usefulLength), 0);
      chunks.push(chunk);
    }

    const contentHash = await sha512(plaintext);
    const leaves = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
    for (let index = 0; index < chunks.length; index++) {
      leaves.set(
        hashMerkleLeafWasm(chunks[index], module),
        index * crypto_hash_sha512_BYTES,
      );
    }
    // getMerkleRoot returns the input view for a one-leaf tree, so always take
    // an owned copy before wiping the temporary leaf array below.
    const root = Uint8Array.from(await getMerkleRoot(leaves, module));

    for (let index = 0; index < chunks.length; index++) {
      const proof = await getMerkleProof(
        leaves,
        hashMerkleLeafWasm(chunks[index], module),
        module,
        PROOF_LEN,
      );
      const usefulLength = Math.min(
        CHUNK_LEN,
        Math.max(0, totalSize - index * CHUNK_LEN),
      );
      const metadata = serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Unknown,
        hash: contentHash,
        totalSize,
        date: new Date(0),
        name: SESSION_METADATA_NAME,
        chunkStartIndex: 0,
        chunkEndIndex: usefulLength,
        chunkIndex: index,
      });
      const chunkPlaintext = new Uint8Array(DECRYPTED_LEN);
      chunkPlaintext.set(metadata, 0);
      chunkPlaintext.set(proof, METADATA_LEN);
      chunkPlaintext.set(chunks[index], METADATA_LEN + PROOF_LEN);
      plaintexts.push(chunkPlaintext);
    }
    contentHash.fill(0);
    leaves.fill(0);
    return { root, chunks, plaintexts };
  } catch (error) {
    for (const chunk of chunks) chunk.fill(0);
    for (const value of plaintexts) value.fill(0);
    throw error;
  }
};

interface DecryptedRecord {
  metadata: ReturnType<typeof deserializeMetadata>;
  chunk: Uint8Array;
}

const validateAndJoinRecords = async (
  records: DecryptedRecord[],
): Promise<Uint8Array> => {
  if (records.length === 0)
    throw new Error("session: encrypted message has no frames");

  const first = records[0].metadata;
  requireSafeUint(first.totalSize, "metadata.totalSize");
  const expectedChunks = Math.max(1, Math.ceil(first.totalSize / CHUNK_LEN));
  if (records.length !== expectedChunks)
    throw new Error("session: incomplete or excessive frame set");
  const byIndex = new Map<number, DecryptedRecord>();

  for (const record of records) {
    const metadata = record.metadata;
    requireSafeUint(metadata.chunkIndex, "metadata.chunkIndex");
    requireSafeUint(metadata.chunkStartIndex, "metadata.chunkStartIndex");
    requireSafeUint(metadata.chunkEndIndex, "metadata.chunkEndIndex");
    requireSafeUint(metadata.totalSize, "metadata.totalSize");
    if (
      metadata.schemaVersion !== 1 ||
      metadata.messageType !== MessageType.Unknown ||
      metadata.name !== SESSION_METADATA_NAME ||
      metadata.date.getTime() !== 0
    )
      throw new Error("session: unsupported encrypted metadata");
    if (
      metadata.totalSize !== first.totalSize ||
      !bytesEqual(metadata.hash, first.hash)
    )
      throw new Error("session: inconsistent encrypted metadata");
    if (metadata.chunkIndex >= expectedChunks || metadata.chunkStartIndex !== 0)
      throw new Error("session: invalid encrypted chunk range");
    const expectedLength = Math.min(
      CHUNK_LEN,
      Math.max(0, first.totalSize - metadata.chunkIndex * CHUNK_LEN),
    );
    if (metadata.chunkEndIndex !== expectedLength)
      throw new Error("session: invalid encrypted chunk length");
    if (byIndex.has(metadata.chunkIndex))
      throw new Error("session: duplicate encrypted chunk");
    byIndex.set(metadata.chunkIndex, record);
  }

  const plaintext = new Uint8Array(first.totalSize);
  for (let index = 0; index < expectedChunks; index++) {
    const record = byIndex.get(index);
    if (!record) throw new Error("session: missing encrypted chunk");
    const usefulLength = record.metadata.chunkEndIndex;
    plaintext.set(record.chunk.subarray(0, usefulLength), index * CHUNK_LEN);
  }

  const contentHash = await sha512(plaintext);
  const validHash = bytesEqual(contentHash, first.hash);
  contentHash.fill(0);
  if (!validHash) {
    plaintext.fill(0);
    throw new Error("session: plaintext hash mismatch");
  }
  return plaintext;
};

const sameRatchetHeader = (
  left: ReturnType<typeof parseChunkFrameHeader>["header"],
  right: ReturnType<typeof parseChunkFrameHeader>["header"],
): boolean =>
  left.N === right.N &&
  left.PN === right.PN &&
  bytesEqual(left.dhPub, right.dhPub);

class Session implements P2PartySession {
  readonly protocolVersion = PROTOCOL_VERSION;
  readonly #module: LibCrypto;
  readonly #mutex = new AsyncMutex();
  readonly #amInitiator: boolean;
  #state: RatchetState;
  #pq: SparsePqHealingState;
  #destroyed = false;

  constructor(
    state: RatchetState,
    module: LibCrypto,
    pq: SparsePqHealingState,
    amInitiator: boolean,
  ) {
    this.#state = state;
    this.#module = module;
    this.#pq = pq;
    this.#amInitiator = amInitiator;
  }

  get pqMode(): RoomPqMode {
    return rootSuiteToRoomPqMode(this.#state.rootSuite);
  }

  get canEncrypt(): boolean {
    return (
      !this.#destroyed &&
      this.#state.sendingChainKey !== null &&
      !this.#pq.trafficBlocked
    );
  }

  get pqEpoch(): bigint {
    this.#assertLive();
    return this.#pq.epoch;
  }

  get healingInProgress(): boolean {
    return !this.#destroyed && this.#pq.trafficBlocked;
  }

  #assertLive(): void {
    if (this.#destroyed) throw new Error("session: session is destroyed");
  }

  async encrypt(plaintext: Uint8Array): Promise<EncryptedSessionMessage> {
    requireBytes(plaintext, "plaintext");
    const ownedPlaintext = copyBytes(plaintext);
    return this.#mutex.runExclusive(async () => {
      let prepared: PreparedMessage | null = null;
      let next: RatchetState | null = null;
      let messageKey: Uint8Array | null = null;
      let pqContext: ReturnType<
        SparsePqHealingState["currentMessageContext"]
      > | null = null;
      let committed = false;
      try {
        this.#assertLive();
        if (this.#pq.trafficBlocked)
          throw new Error("session: sparse-PQ healing is in progress");
        if (!this.#state.sendingChainKey)
          throw new Error("ratchet: no sending chain");
        prepared = await prepareMessage(ownedPlaintext, this.#module);
        next = cloneRatchet(this.#state);
        const encrypted = ratchetEncrypt(next, this.#module);
        messageKey = encrypted.messageKey;
        // Always combine against the current PQ epoch (zero before healing,
        // then each successive epoch after ACK).
        pqContext = this.#pq.currentMessageContext();
        const frames = prepared.plaintexts.map((chunk) =>
          sealChunk(
            messageKey!,
            encrypted.header,
            chunk,
            prepared!.root,
            this.#module,
            pqContext!,
          ),
        );
        adoptRatchet(this.#state, next);
        this.#pq.noteApplicationMessage();
        committed = true;
        return {
          protocolVersion: PROTOCOL_VERSION,
          root: copyBytes(prepared.root),
          frames,
        };
      } finally {
        ownedPlaintext.fill(0);
        messageKey?.fill(0);
        if (next && !committed) wipeRatchet(next);
        if (prepared) wipePreparedMessage(prepared);
      }
    });
  }

  async decrypt(message: EncryptedSessionMessage): Promise<Uint8Array> {
    if (!message || typeof message !== "object")
      throw new TypeError("message is required");
    if (message.protocolVersion !== PROTOCOL_VERSION)
      throw new Error("session: unsupported protocol version");
    requireBytes(message.root, "message.root", crypto_hash_sha512_BYTES);
    if (!Array.isArray(message.frames) || message.frames.length === 0)
      throw new Error("session: encrypted message has no frames");
    for (const frame of message.frames) {
      requireBytes(frame, "message frame");
      if (frame.length !== WIRE_CHUNK_FRAME_LEN)
        throw new Error("session: invalid encrypted frame length");
    }

    const root = copyBytes(message.root);
    const frames = message.frames.map(copyBytes);
    return this.#mutex.runExclusive(async () => {
      this.#assertLive();
      const parsed = frames.map((frame) => parseChunkFrameHeader(frame));
      for (let index = 1; index < parsed.length; index++) {
        if (!sameRatchetHeader(parsed[0].header, parsed[index].header))
          throw new Error("session: mixed ratchet headers");
      }
      const nonces = new Set<string>();
      for (const frame of parsed) {
        const nonce = bytesHex(frame.nonce);
        if (nonces.has(nonce))
          throw new Error("session: duplicate chunk nonce");
        nonces.add(nonce);
      }

      const next = cloneRatchet(this.#state);
      // A logical message's already-combined keys stay in the runtime's active
      // receive-key collection so they persist in the snapshot; a staged copy
      // is committed only on success.
      const stagedCache = new Map(this.#pq.activeReceiveKeys);
      const decryptedBuffers: Uint8Array[] = [];
      let committed = false;
      try {
        const records: DecryptedRecord[] = [];
        for (const frame of frames) {
          const result = decryptMessageChunk(
            next,
            frame,
            stagedCache,
            root,
            this.#module,
            (epoch: bigint) => this.#pq.resolveMessageContext(epoch),
          );
          if (!result.ok || !result.decrypted)
            throw new Error("session: encrypted frame authentication failed");
          decryptedBuffers.push(result.decrypted);
          const metadata = deserializeMetadata(
            result.decrypted.subarray(0, METADATA_LEN),
          );
          records.push({
            metadata,
            chunk: result.decrypted.subarray(METADATA_LEN + PROOF_LEN),
          });
        }

        const plaintext = await validateAndJoinRecords(records);
        adoptRatchet(this.#state, next);
        // Publish the staged active receive keys and count one application
        // message. A single logical session message is one DR step.
        this.#adoptActiveReceiveKeys(stagedCache);
        this.#pq.noteApplicationMessage();
        committed = true;
        return plaintext;
      } finally {
        root.fill(0);
        for (const decrypted of decryptedBuffers) decrypted.fill(0);
        if (!committed) {
          for (const [key, value] of stagedCache)
            if (!this.#pq.activeReceiveKeys.has(key)) value.fill(0);
          wipeRatchet(next);
        }
      }
    });
  }

  #adoptActiveReceiveKeys(staged: Map<string, Uint8Array>): void {
    const live = this.#pq.activeReceiveKeys;
    for (const [key, value] of staged) if (!live.has(key)) live.set(key, value);
  }

  async prepareHealing(): Promise<SessionControlOutput> {
    return this.#mutex.runExclusive(async () => {
      this.#assertLive();
      if (!this.#pq.healingDue()) return NO_CONTROL;
      const frame = await this.#pq.prepareHealingOffer();
      this.#pq.markPendingDispatched();
      return { frame, requiresPersistBeforeSend: true };
    });
  }

  async acceptControlFrame(frame: Uint8Array): Promise<SessionControlOutput> {
    requireBytes(frame, "control frame", WIRE_CHUNK_FRAME_LEN);
    const owned = copyBytes(frame);
    return this.#mutex.runExclusive(async () => {
      this.#assertLive();
      const result = await this.#pq.acceptControlFrame(owned);
      if (result.changed && result.dispatch && this.#pq.pendingRetryAt !== null)
        this.#pq.markPendingDispatched();
      return {
        frame: result.dispatch,
        requiresPersistBeforeSend: result.changed,
      };
    });
  }

  async pendingControl(): Promise<Uint8Array | null> {
    return this.#mutex.runExclusive(async () => {
      this.#assertLive();
      return this.#pq.copyPendingFrame();
    });
  }

  async serialize(): Promise<Uint8Array> {
    return this.#mutex.runExclusive(async () => {
      this.#assertLive();
      return encodeSessionSnapshot(this.#state, this.#pq, this.#amInitiator);
    });
  }

  async destroy(): Promise<void> {
    await this.#mutex.runExclusive(async () => {
      if (this.#destroyed) return;
      wipeRatchet(this.#state);
      this.#pq.destroy();
      this.#destroyed = true;
    });
  }
}

const NO_CONTROL: SessionControlOutput = {
  frame: null,
  requiresPersistBeforeSend: false,
};

const validateSnapshotState = (state: RatchetState): void => {
  requireBytes(state.rootKey, "snapshot.rootKey", 32);
  requireBytes(state.dhSelfPub, "snapshot.dhSelfPub", 32);
  requireBytes(state.dhSelfSec, "snapshot.dhSelfSec", 32);
  if (state.sendingChainKey)
    requireBytes(state.sendingChainKey, "snapshot.sendingChainKey", 32);
  if (state.receivingChainKey)
    requireBytes(state.receivingChainKey, "snapshot.receivingChainKey", 32);
  if (state.dhRemotePub)
    requireBytes(state.dhRemotePub, "snapshot.dhRemotePub", 32);
  requireSafeUint(state.Ns, "snapshot.Ns");
  requireSafeUint(state.Nr, "snapshot.Nr");
  requireSafeUint(state.PN, "snapshot.PN");
  if (
    (state.sendingChainKey ||
      state.receivingChainKey ||
      state.skipped.size > 0) &&
    !state.dhRemotePub
  )
    throw new Error("snapshot: chain state requires a remote DH key");
  if (state.skipped.size > MAX_SKIP_SESSION)
    throw new Error("snapshot: too many skipped message keys");
};

const writeU64 = (view: DataView, offset: number, value: number): number => {
  requireSafeUint(value, "snapshot counter");
  view.setBigUint64(offset, BigInt(value), false);
  return offset + 8;
};

const snapshotSuiteTag = (suite: RatchetRootSuite): number => {
  if (suite === RATCHET_ROOT_SUITE_MLKEM768)
    return SESSION_ROOT_SUITE_3DH_ML_KEM_768_CPACE21;
  if (suite === RATCHET_ROOT_SUITE_MLKEM512)
    return SESSION_ROOT_SUITE_3DH_ML_KEM_512_CPACE21;
  if (suite === RATCHET_ROOT_SUITE_MLKEM1024)
    return SESSION_ROOT_SUITE_3DH_ML_KEM_1024_CPACE21;
  throw new Error("snapshot: unsupported root suite");
};

const snapshotTagRootSuite = (tag: number): RatchetRootSuite => {
  if (tag === SESSION_ROOT_SUITE_3DH_ML_KEM_768_CPACE21)
    return RATCHET_ROOT_SUITE_MLKEM768;
  if (tag === SESSION_ROOT_SUITE_3DH_ML_KEM_512_CPACE21)
    return RATCHET_ROOT_SUITE_MLKEM512;
  if (tag === SESSION_ROOT_SUITE_3DH_ML_KEM_1024_CPACE21)
    return RATCHET_ROOT_SUITE_MLKEM1024;
  throw new Error("snapshot: unsupported root suite");
};

const encodeSessionSnapshot = (
  state: RatchetState,
  pq: SparsePqHealingState,
  amInitiator: boolean,
): Uint8Array => {
  validateSnapshotState(state);
  const serialized = serializeRatchet(state);
  // The PQ checkpoint carries the machine/root/epoch/turn/counters, exact
  // outbox, replay/ACK caches, and active combined receive keys.
  const pqCheckpoint = pq.serialize();
  if (
    pqCheckpoint.length === 0 ||
    pqCheckpoint.length > SNAPSHOT_MAX_PQ_CHECKPOINT_BYTES
  ) {
    pqCheckpoint.fill(0);
    throw new Error("snapshot: PQ checkpoint length is invalid");
  }
  try {
    const flags =
      (serialized.sendingChainKey ? SNAPSHOT_FLAG_SENDING_CHAIN : 0) |
      (serialized.receivingChainKey ? SNAPSHOT_FLAG_RECEIVING_CHAIN : 0) |
      (serialized.dhRemotePub ? SNAPSHOT_FLAG_REMOTE_DH : 0) |
      (amInitiator ? SNAPSHOT_FLAG_INITIATOR : 0);
    const optionalKeyCount =
      Number(Boolean(serialized.sendingChainKey)) +
      Number(Boolean(serialized.receivingChainKey)) +
      Number(Boolean(serialized.dhRemotePub));
    const output = new Uint8Array(
      SNAPSHOT_FIXED_PREFIX_LEN +
        optionalKeyCount * 32 +
        serialized.skippedMessageKeys.length * SNAPSHOT_SKIPPED_ENTRY_LEN +
        SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES +
        pqCheckpoint.length,
    );
    const view = new DataView(output.buffer);
    let offset = 0;
    output.set(SESSION_MAGIC, offset);
    offset += SESSION_MAGIC.length;
    output[offset++] = SESSION_SNAPSHOT_VERSION;
    output[offset++] = PROTOCOL_VERSION;
    output[offset++] = flags;
    output[offset++] = snapshotSuiteTag(serialized.rootSuite);
    offset = writeU64(view, offset, serialized.Ns);
    offset = writeU64(view, offset, serialized.Nr);
    offset = writeU64(view, offset, serialized.PN);
    output.set(new Uint8Array(serialized.rootKey), offset);
    offset += 32;
    if (serialized.sendingChainKey) {
      output.set(new Uint8Array(serialized.sendingChainKey), offset);
      offset += 32;
    }
    if (serialized.receivingChainKey) {
      output.set(new Uint8Array(serialized.receivingChainKey), offset);
      offset += 32;
    }
    output.set(new Uint8Array(serialized.dhSelfPub), offset);
    offset += 32;
    output.set(new Uint8Array(serialized.dhSelfSec), offset);
    offset += 32;
    if (serialized.dhRemotePub) {
      output.set(new Uint8Array(serialized.dhRemotePub), offset);
      offset += 32;
    }
    view.setUint16(offset, serialized.skippedMessageKeys.length, false);
    offset += 2;
    for (const skipped of serialized.skippedMessageKeys) {
      requireBytes(new Uint8Array(skipped.dhPub), "snapshot.skipped.dhPub", 32);
      requireBytes(
        new Uint8Array(skipped.messageKey),
        "snapshot.skipped.messageKey",
        32,
      );
      output.set(new Uint8Array(skipped.dhPub), offset);
      offset += 32;
      offset = writeU64(view, offset, skipped.n);
      output.set(new Uint8Array(skipped.messageKey), offset);
      offset += 32;
    }
    view.setUint32(offset, pqCheckpoint.length, false);
    offset += SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES;
    output.set(pqCheckpoint, offset);
    offset += pqCheckpoint.length;
    return output;
  } finally {
    pqCheckpoint.fill(0);
    new Uint8Array(serialized.rootKey).fill(0);
    if (serialized.sendingChainKey)
      new Uint8Array(serialized.sendingChainKey).fill(0);
    if (serialized.receivingChainKey)
      new Uint8Array(serialized.receivingChainKey).fill(0);
    new Uint8Array(serialized.dhSelfSec).fill(0);
    for (const skipped of serialized.skippedMessageKeys)
      new Uint8Array(skipped.messageKey).fill(0);
  }
};

interface DecodedSessionSnapshot {
  readonly state: RatchetState;
  readonly pqCheckpoint: Uint8Array;
  readonly amInitiator: boolean;
}

const decodeSessionSnapshot = (
  snapshot: Uint8Array,
): DecodedSessionSnapshot => {
  requireBytes(snapshot, "snapshot");
  const bytes = copyBytes(snapshot);
  let offset = 0;
  let ownershipTransferred = false;
  const ownedSecretCopies: Uint8Array[] = [];
  const take = (length: number): Uint8Array => {
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      offset + length > bytes.length
    )
      throw new Error("snapshot: truncated input");
    // A view avoids the old take().slice() temporary. The aggregate `bytes`
    // buffer is wiped in finally; fields that must outlive parsing get exactly
    // one owned copy below.
    const value = bytes.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const takeBuffer = (length: number, secret = false): ArrayBuffer => {
    const buffer = take(length).slice().buffer;
    if (secret) ownedSecretCopies.push(new Uint8Array(buffer));
    return buffer;
  };
  const readU64 = (): number => {
    if (offset + 8 > bytes.length)
      throw new Error("snapshot: truncated counter");
    const value = new DataView(
      bytes.buffer,
      bytes.byteOffset + offset,
      8,
    ).getBigUint64(0, false);
    offset += 8;
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("snapshot: counter exceeds safe-integer range");
    return Number(value);
  };

  try {
    if (!bytesEqual(take(SESSION_MAGIC.length), SESSION_MAGIC))
      throw new Error("snapshot: invalid magic");
    if (take(1)[0] !== SESSION_SNAPSHOT_VERSION)
      throw new Error("snapshot: unsupported snapshot version");
    if (take(1)[0] !== PROTOCOL_VERSION)
      throw new Error("snapshot: unsupported protocol version");
    const flags = take(1)[0];
    if ((flags & ~SNAPSHOT_KNOWN_FLAGS) !== 0)
      throw new Error("snapshot: unknown flags");
    const rootSuite = snapshotTagRootSuite(take(1)[0]);

    const Ns = readU64();
    const Nr = readU64();
    const PN = readU64();
    const rootKey = takeBuffer(32, true);
    const sendingChainKey =
      flags & SNAPSHOT_FLAG_SENDING_CHAIN ? takeBuffer(32, true) : null;
    const receivingChainKey =
      flags & SNAPSHOT_FLAG_RECEIVING_CHAIN ? takeBuffer(32, true) : null;
    const dhSelfPub = takeBuffer(32);
    const dhSelfSec = takeBuffer(32, true);
    const dhRemotePub = flags & SNAPSHOT_FLAG_REMOTE_DH ? takeBuffer(32) : null;
    if ((sendingChainKey || receivingChainKey) && dhRemotePub === null)
      throw new Error("snapshot: chain state requires a remote DH key");
    if (offset + 2 > bytes.length)
      throw new Error("snapshot: missing skipped-key count");
    const skippedCount = new DataView(
      bytes.buffer,
      bytes.byteOffset + offset,
      2,
    ).getUint16(0, false);
    offset += 2;
    if (skippedCount > MAX_SKIP_SESSION)
      throw new Error("snapshot: too many skipped message keys");
    if (dhRemotePub === null && skippedCount > 0)
      throw new Error("snapshot: skipped keys require a remote DH key");
    const skippedRemaining = skippedCount * SNAPSHOT_SKIPPED_ENTRY_LEN;
    if (
      bytes.length - offset <
      skippedRemaining + SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES
    )
      throw new Error("snapshot: truncated input");

    const skippedMessageKeys: RatchetSessionSecrets["skippedMessageKeys"] = [];
    const seen = new Set<string>();
    for (let index = 0; index < skippedCount; index++) {
      const dhPubBytes = take(32);
      const n = readU64();
      const messageKeyBytes = take(32);
      const key = `${bytesHex(dhPubBytes)}:${String(n)}`;
      if (seen.has(key))
        throw new Error("snapshot: duplicate skipped message key");
      seen.add(key);
      skippedMessageKeys.push({
        dhPub: dhPubBytes.slice().buffer,
        n,
        messageKey: (() => {
          const buffer = messageKeyBytes.slice().buffer;
          ownedSecretCopies.push(new Uint8Array(buffer));
          return buffer;
        })(),
      });
    }

    const pqCheckpointLength = new DataView(
      bytes.buffer,
      bytes.byteOffset + offset,
      SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES,
    ).getUint32(0, false);
    offset += SNAPSHOT_PQ_CHECKPOINT_LENGTH_BYTES;
    if (
      pqCheckpointLength === 0 ||
      pqCheckpointLength > SNAPSHOT_MAX_PQ_CHECKPOINT_BYTES
    )
      throw new Error("snapshot: PQ checkpoint length is invalid");
    if (bytes.length - offset !== pqCheckpointLength)
      throw new Error("snapshot: truncated input or trailing bytes");
    const pqCheckpoint = take(pqCheckpointLength).slice();
    ownedSecretCopies.push(pqCheckpoint);

    const state = deserializeRatchet({
      rootSuite,
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfPub,
      dhSelfSec,
      dhRemotePub,
      Ns,
      Nr,
      PN,
      skippedMessageKeys,
    });
    ownershipTransferred = true;
    return {
      state,
      pqCheckpoint,
      amInitiator: (flags & SNAPSHOT_FLAG_INITIATOR) !== 0,
    };
  } finally {
    bytes.fill(0);
    if (!ownershipTransferred)
      for (const secret of ownedSecretCopies) secret.fill(0);
  }
};

export const createSession = async (
  options: CreateSessionOptions,
): Promise<P2PartySession> => {
  if (!options || typeof options !== "object")
    throw new TypeError("session options are required");
  if (options.role !== "initiator" && options.role !== "responder")
    throw new Error("role must be initiator or responder");
  if (
    !options.transport ||
    typeof options.transport.send !== "function" ||
    typeof options.transport.recv !== "function"
  )
    throw new TypeError("transport must provide send() and recv()");
  validateLocalIdentity(options.identity);
  requireBytes(
    options.peerIdentityEd25519PublicKey,
    "peerIdentityEd25519PublicKey",
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  if (!options.channel || typeof options.channel !== "object")
    throw new TypeError("channel binding is required");
  requireBytes(options.channel.channelId, "channel.channelId");
  if (options.channel.channelId.length === 0)
    throw new RangeError("channel.channelId must not be empty");
  requireBytes(
    options.channel.localFingerprint,
    "channel.localFingerprint",
    32,
  );
  requireBytes(
    options.channel.remoteFingerprint,
    "channel.remoteFingerprint",
    32,
  );
  const runtimeAuth = options as {
    mode?: unknown;
    pin?: unknown;
    pqMode?: unknown;
  };
  if (runtimeAuth.mode !== "pin" && runtimeAuth.mode !== "nopin")
    throw new Error("mode must be pin or nopin");
  const mode = runtimeAuth.mode;
  const pqMode = runtimeAuth.pqMode ?? "hybrid-mlkem768";
  if (
    pqMode !== "hybrid-mlkem512" &&
    pqMode !== "hybrid-mlkem768" &&
    pqMode !== "hybrid-mlkem1024"
  )
    throw new Error(
      "pqMode must select ML-KEM-512, ML-KEM-768, or ML-KEM-1024",
    );
  let pin: Uint8Array | null = null;
  if (mode === "pin") {
    requireBytes(runtimeAuth.pin, "pin");
    if (runtimeAuth.pin.length === 0)
      throw new RangeError("pin must not be empty");
    pin = copyBytes(runtimeAuth.pin);
  } else if (runtimeAuth.pin !== undefined) {
    throw new Error("pin must not be provided in nopin mode");
  }

  const identitySecret = copyBytes(options.identity.x25519SecretKey);
  const identityEd25519Public = copyBytes(options.identity.ed25519PublicKey);
  const identityX25519Public = copyBytes(options.identity.x25519PublicKey);
  const identityCrossSignature = copyBytes(
    options.identity.x25519CrossSignature,
  );
  const peerIdentityEd25519Public = copyBytes(
    options.peerIdentityEd25519PublicKey,
  );
  const channelId = copyBytes(options.channel.channelId);
  const localFingerprint = copyBytes(options.channel.localFingerprint);
  const remoteFingerprint = copyBytes(options.channel.remoteFingerprint);
  let rootSecret: Uint8Array | null = null;
  let pqHealingRoot: Uint8Array | null = null;
  let pqHealingBinding: Uint8Array | null = null;
  let state: RatchetState | null = null;
  let pq: SparsePqHealingState | null = null;
  try {
    const module = await loadSessionCrypto(options.crypto);
    await validateLocalIdentityCryptographically(
      {
        ed25519PublicKey: identityEd25519Public,
        x25519PublicKey: identityX25519Public,
        x25519SecretKey: identitySecret,
        x25519CrossSignature: identityCrossSignature,
      },
      module,
    );
    const initiator = options.role === "initiator";
    const channelInput = buildChannelInput({
      channelId,
      ikInitiator: initiator
        ? identityEd25519Public
        : peerIdentityEd25519Public,
      ikResponder: initiator
        ? peerIdentityEd25519Public
        : identityEd25519Public,
      fpInitiator: initiator ? localFingerprint : remoteFingerprint,
      fpResponder: initiator ? remoteFingerprint : localFingerprint,
      pqMode,
    });
    const result = await performHandshakeCore(
      options.transport,
      {
        mode,
        pqMode,
        pin,
        channelInput,
        amInitiator: initiator,
        idSelfSec: identitySecret,
        selfIdentityX25519Pub: identityX25519Public,
        selfIdentityCrossSignature: identityCrossSignature,
        peerIdentityEd25519Pub: peerIdentityEd25519Public,
      },
      module,
    );
    state = result.state;
    rootSecret = result.secret;
    pqHealingRoot = result.pqHealing.rootKey;
    pqHealingBinding = result.pqHealing.binding;
    // Consume the PQ bootstrap into the session-owned runtime; the constructor
    // copies the root/binding, so the loose buffers are wiped in finally.
    pq = new SparsePqHealingState({
      module,
      pqMode,
      rootSuite: state.rootSuite,
      binding: pqHealingBinding,
      rootKey: pqHealingRoot,
      nextOfferer: result.pqHealing.nextOfferer,
      amInitiator: initiator,
    });
    const session = new Session(state, module, pq, initiator);
    state = null;
    pq = null;
    return session;
  } finally {
    identitySecret.fill(0);
    pin?.fill(0);
    rootSecret?.fill(0);
    pqHealingRoot?.fill(0);
    pqHealingBinding?.fill(0);
    if (state) wipeRatchet(state);
    pq?.destroy();
  }
};

export const restoreSession = async (
  snapshot: Uint8Array,
  crypto?: SessionCryptoOptions,
): Promise<P2PartySession> => {
  const decoded = decodeSessionSnapshot(snapshot);
  let pq: SparsePqHealingState | null = null;
  try {
    const module = await loadSessionCrypto(crypto);
    // Rebuild the PQ runtime from the appended checkpoint. The whole snapshot
    // is the caller's authenticated-at-rest unit, so the expected binding is
    // read from the checkpoint itself; restore still validates that the
    // internal binding, suite, and direction are self-consistent.
    const expectedBinding = SparsePqHealingState.readCheckpointBinding(
      decoded.pqCheckpoint,
    );
    try {
      pq = SparsePqHealingState.restore(decoded.pqCheckpoint, {
        module,
        pqMode: rootSuiteToRoomPqMode(decoded.state.rootSuite),
        rootSuite: decoded.state.rootSuite,
        binding: expectedBinding,
        amInitiator: decoded.amInitiator,
      });
    } finally {
      expectedBinding.fill(0);
    }
    const session = new Session(decoded.state, module, pq, decoded.amInitiator);
    pq = null;
    return session;
  } catch (error) {
    wipeRatchet(decoded.state);
    pq?.destroy();
    throw error;
  } finally {
    decoded.pqCheckpoint.fill(0);
  }
};
