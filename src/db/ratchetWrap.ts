import { getDB } from "./src/getDB";
import { isRatchetRootSuite, MAX_SKIP_SESSION } from "../utils/constants";

import type { RatchetSession } from "./types";

// Out-of-line key in the `meta` store for the single wrap CryptoKey.
const WRAP_KEY_META_ID = "ratchetWrapKey";
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const RATCHET_RECORD_ID_BYTES = 16;
type OwnedBytes = Uint8Array<ArrayBuffer>;

// Ratchet fields use a self-describing envelope rather than the legacy
// iv||ciphertext form used by the identity records. The version is also
// authenticated in the AAD; keeping it in the envelope makes unknown formats
// reject before WebCrypto sees attacker-controlled layout.
export const RATCHET_WRAP_VERSION = 2;
const RATCHET_WRAP_MAGIC = Uint8Array.of(0x50, 0x32, 0x52, 0x57); // "P2RW"
const RATCHET_WRAP_HEADER_BYTES =
  RATCHET_WRAP_MAGIC.byteLength + 1 + RATCHET_RECORD_ID_BYTES + GCM_IV_BYTES;
/** Bounded canonical v4 PQ/outbox/active-key checkpoint (plaintext bytes). */
export const MAX_EDGE_CRYPTO_STATE_BYTES = 256 * 1024;
const RATCHET_AAD_DOMAIN = new TextEncoder().encode(
  "p2party-edge-crypto-at-rest-aad-v2",
);
const MAX_AAD_STRING_BYTES = 1 << 20;

const enum RatchetSecretField {
  RootKey = 1,
  SendingChainKey = 2,
  ReceivingChainKey = 3,
  DhSelfSecret = 4,
  SkippedMessageKey = 5,
  EdgeCryptoState = 6,
}

const copyBuffer = (value: ArrayBuffer): ArrayBuffer => value.slice(0);

const requireBuffer = (
  value: unknown,
  name: string,
  expectedLength?: number,
): ArrayBuffer => {
  if (!(value instanceof ArrayBuffer))
    throw new Error(`${name} must be an ArrayBuffer`);
  if (expectedLength !== undefined && value.byteLength !== expectedLength)
    throw new Error(`${name} must be ${String(expectedLength)} bytes`);
  return value;
};

const requireSafeUint = (value: unknown, name: string): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new Error(`${name} must be a safe unsigned integer`);
  return value;
};

const requireCanonicalString = (value: unknown, name: string): string => {
  if (typeof value !== "string" || value.length === 0)
    throw new Error(`${name} must be a non-empty string`);
  const encoded = new TextEncoder().encode(value);
  if (encoded.byteLength > MAX_AAD_STRING_BYTES)
    throw new Error(`${name} is too long`);
  // TextEncoder replaces lone UTF-16 surrogates with U+FFFD. Rejecting a
  // non-round-tripping string keeps the length-prefixed UTF-8 encoding
  // injective, which is required of a canonical AAD encoding.
  if (new TextDecoder().decode(encoded) !== value)
    throw new Error(`${name} is not canonical Unicode`);
  return value;
};

const encodeU32 = (value: number): OwnedBytes => {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new Error("ratchet wrap: value exceeds uint32");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
};

const encodeU64 = (value: number): OwnedBytes => {
  requireSafeUint(value, "ratchet wrap counter");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
};

const concatBytes = (parts: readonly Uint8Array[]): OwnedBytes => {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
};

const lengthPrefixed = (bytes: Uint8Array): OwnedBytes =>
  concatBytes([encodeU32(bytes.byteLength), bytes]);

const encodeString = (value: string): OwnedBytes =>
  lengthPrefixed(new TextEncoder().encode(value));

interface RatchetMetadata {
  rootSuite: RatchetSession["rootSuite"];
  roomId: string;
  peerPublicKey: string;
  peerId: string;
  dhSelfPub: ArrayBuffer;
  dhRemotePub: ArrayBuffer | null;
  Ns: number;
  Nr: number;
  PN: number;
  skippedMessageKeys: {
    dhPub: ArrayBuffer;
    n: number;
    messageKey: ArrayBuffer;
  }[];
  updatedAt: number;
  sendingChainKey: ArrayBuffer | null;
  receivingChainKey: ArrayBuffer | null;
  edgeCryptoState: ArrayBuffer | null;
}

/**
 * Validate every cleartext value before it participates in AAD construction.
 * These fields remain indexable in IndexedDB, but no longer remain malleable:
 * each encrypted field authenticates this complete canonical description.
 */
const validateMetadata = (s: RatchetMetadata): void => {
  const rootSuite: unknown = s.rootSuite;
  if (!isRatchetRootSuite(rootSuite))
    throw new Error("Unsupported ratchet root suite");
  requireCanonicalString(s.roomId, "ratchet roomId");
  requireCanonicalString(s.peerPublicKey, "ratchet peerPublicKey");
  if (!/^[0-9a-f]{64}$/.test(s.peerPublicKey))
    throw new Error("ratchet peerPublicKey must be 32-byte lowercase hex");
  requireCanonicalString(s.peerId, "ratchet peerId");
  requireBuffer(s.dhSelfPub, "ratchet dhSelfPub", 32);
  if (s.dhRemotePub !== null)
    requireBuffer(s.dhRemotePub, "ratchet dhRemotePub", 32);
  requireSafeUint(s.Ns, "ratchet Ns");
  requireSafeUint(s.Nr, "ratchet Nr");
  requireSafeUint(s.PN, "ratchet PN");
  requireSafeUint(s.updatedAt, "ratchet updatedAt");
  if (
    !Array.isArray(s.skippedMessageKeys) ||
    s.skippedMessageKeys.length > MAX_SKIP_SESSION
  )
    throw new Error("ratchet skipped-message-key count is invalid");
  s.skippedMessageKeys.forEach((skipped, index) => {
    requireBuffer(skipped.dhPub, `ratchet skipped[${String(index)}].dhPub`, 32);
    requireSafeUint(skipped.n, `ratchet skipped[${String(index)}].n`);
  });
  if (s.edgeCryptoState !== null) {
    const checkpoint = requireBuffer(
      s.edgeCryptoState,
      "ratchet edge crypto state",
    );
    if (
      checkpoint.byteLength < 1 ||
      checkpoint.byteLength >
        MAX_EDGE_CRYPTO_STATE_BYTES +
          RATCHET_WRAP_HEADER_BYTES +
          GCM_TAG_BYTES
    )
      throw new Error("ratchet edge crypto state length is invalid");
  }
};

const cloneSession = (s: RatchetSession): RatchetSession => ({
  rootSuite: s.rootSuite,
  roomId: s.roomId,
  peerPublicKey: s.peerPublicKey,
  peerId: s.peerId,
  rootKey: copyBuffer(requireBuffer(s.rootKey, "ratchet rootKey")),
  sendingChainKey:
    s.sendingChainKey === null
      ? null
      : copyBuffer(requireBuffer(s.sendingChainKey, "ratchet sendingChainKey")),
  receivingChainKey:
    s.receivingChainKey === null
      ? null
      : copyBuffer(
          requireBuffer(s.receivingChainKey, "ratchet receivingChainKey"),
        ),
  dhSelfPub: copyBuffer(requireBuffer(s.dhSelfPub, "ratchet dhSelfPub")),
  dhSelfSec: copyBuffer(requireBuffer(s.dhSelfSec, "ratchet dhSelfSec")),
  dhRemotePub:
    s.dhRemotePub === null
      ? null
      : copyBuffer(requireBuffer(s.dhRemotePub, "ratchet dhRemotePub")),
  Ns: s.Ns,
  Nr: s.Nr,
  PN: s.PN,
  skippedMessageKeys: (() => {
    if (!Array.isArray(s.skippedMessageKeys))
      throw new Error("ratchet skippedMessageKeys must be an array");
    return s.skippedMessageKeys.map((skipped, index) => ({
      dhPub: copyBuffer(
        requireBuffer(skipped.dhPub, `ratchet skipped[${String(index)}].dhPub`),
      ),
      n: skipped.n,
      messageKey: copyBuffer(
        requireBuffer(
          skipped.messageKey,
          `ratchet skipped[${String(index)}].messageKey`,
        ),
      ),
    }));
  })(),
  edgeCryptoState:
    s.edgeCryptoState === null
      ? null
      : copyBuffer(
          requireBuffer(s.edgeCryptoState, "ratchet edge crypto state"),
        ),
  updatedAt: s.updatedAt,
});

const wipeSessionSecrets = (s: RatchetSession): void => {
  new Uint8Array(s.rootKey).fill(0);
  if (s.sendingChainKey) new Uint8Array(s.sendingChainKey).fill(0);
  if (s.receivingChainKey) new Uint8Array(s.receivingChainKey).fill(0);
  new Uint8Array(s.dhSelfSec).fill(0);
  for (const skipped of s.skippedMessageKeys)
    new Uint8Array(skipped.messageKey).fill(0);
  if (s.edgeCryptoState) new Uint8Array(s.edgeCryptoState).fill(0);
};

const canonicalRatchetAad = (
  s: RatchetMetadata,
  field: RatchetSecretField,
  recordId: Uint8Array,
  fieldIndex = 0,
): OwnedBytes => {
  validateMetadata(s);
  if (recordId.byteLength !== RATCHET_RECORD_ID_BYTES)
    throw new Error("ratchet wrap: invalid record ID");
  const flags =
    (s.sendingChainKey === null ? 0 : 1) |
    (s.receivingChainKey === null ? 0 : 2) |
    (s.dhRemotePub === null ? 0 : 4) |
    (s.edgeCryptoState === null ? 0 : 8);
  const parts: OwnedBytes[] = [
    lengthPrefixed(RATCHET_AAD_DOMAIN),
    Uint8Array.of(RATCHET_WRAP_VERSION, field),
    lengthPrefixed(recordId),
    encodeU32(fieldIndex),
    encodeString(s.rootSuite),
    encodeString(s.roomId),
    encodeString(s.peerPublicKey),
    encodeString(s.peerId),
    lengthPrefixed(new Uint8Array(s.dhSelfPub)),
    Uint8Array.of(flags),
  ];
  if (s.dhRemotePub !== null)
    parts.push(lengthPrefixed(new Uint8Array(s.dhRemotePub)));
  parts.push(
    encodeU64(s.Ns),
    encodeU64(s.Nr),
    encodeU64(s.PN),
    encodeU64(s.updatedAt),
    encodeU32(s.skippedMessageKeys.length),
  );
  for (const skipped of s.skippedMessageKeys) {
    parts.push(
      lengthPrefixed(new Uint8Array(skipped.dhPub)),
      encodeU64(skipped.n),
    );
  }
  return concatBytes(parts);
};

const ratchetEnvelopeRecordId = (
  blob: ArrayBuffer,
  expectedPlaintextBytes: number | null = 32,
): OwnedBytes => {
  const view = new Uint8Array(blob);
  const minimumLength = RATCHET_WRAP_HEADER_BYTES + 1 + GCM_TAG_BYTES;
  const maximumLength =
    RATCHET_WRAP_HEADER_BYTES +
    MAX_EDGE_CRYPTO_STATE_BYTES +
    GCM_TAG_BYTES;
  if (
    (expectedPlaintextBytes === null &&
      (view.byteLength < minimumLength || view.byteLength > maximumLength)) ||
    (expectedPlaintextBytes !== null &&
      view.byteLength !==
        RATCHET_WRAP_HEADER_BYTES +
          expectedPlaintextBytes +
          GCM_TAG_BYTES)
  )
    throw new Error("Unsupported or malformed ratchet wrap envelope");
  for (let i = 0; i < RATCHET_WRAP_MAGIC.byteLength; i++) {
    if (view[i] !== RATCHET_WRAP_MAGIC[i])
      throw new Error("Unsupported or malformed ratchet wrap envelope");
  }
  if (view[RATCHET_WRAP_MAGIC.byteLength] !== RATCHET_WRAP_VERSION)
    throw new Error("Unsupported or malformed ratchet wrap envelope");
  return Uint8Array.from(
    view.subarray(
      RATCHET_WRAP_MAGIC.byteLength + 1,
      RATCHET_WRAP_MAGIC.byteLength + 1 + RATCHET_RECORD_ID_BYTES,
    ),
  );
};

const wrapRatchetField = async (
  key: CryptoKey,
  plaintext: ArrayBuffer,
  aad: OwnedBytes,
  recordId: OwnedBytes,
  expectedPlaintextBytes: number | null = 32,
): Promise<ArrayBuffer> => {
  requireBuffer(
    plaintext,
    "ratchet secret",
    expectedPlaintextBytes === null ? undefined : expectedPlaintextBytes,
  );
  if (
    expectedPlaintextBytes === null &&
    (plaintext.byteLength < 1 ||
      plaintext.byteLength > MAX_EDGE_CRYPTO_STATE_BYTES)
  )
    throw new Error("ratchet variable secret length is invalid");
  if (recordId.byteLength !== RATCHET_RECORD_ID_BYTES)
    throw new Error("ratchet wrap: invalid record ID");
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: aad,
      tagLength: GCM_TAG_BYTES * 8,
    },
    key,
    plaintext,
  );
  const out = new Uint8Array(RATCHET_WRAP_HEADER_BYTES + ciphertext.byteLength);
  out.set(RATCHET_WRAP_MAGIC, 0);
  out[RATCHET_WRAP_MAGIC.byteLength] = RATCHET_WRAP_VERSION;
  out.set(recordId, RATCHET_WRAP_MAGIC.byteLength + 1);
  out.set(iv, RATCHET_WRAP_MAGIC.byteLength + 1 + RATCHET_RECORD_ID_BYTES);
  out.set(new Uint8Array(ciphertext), RATCHET_WRAP_HEADER_BYTES);
  return out.buffer;
};

const unwrapRatchetField = async (
  key: CryptoKey,
  envelope: ArrayBuffer,
  aad: OwnedBytes,
  expectedRecordId: OwnedBytes,
  expectedPlaintextBytes: number | null = 32,
): Promise<ArrayBuffer> => {
  requireBuffer(envelope, "ratchet wrapped secret");
  const recordId = ratchetEnvelopeRecordId(
    envelope,
    expectedPlaintextBytes,
  );
  if (!equalBytes(recordId, expectedRecordId))
    throw new Error("Ratchet wrap record ID mismatch");
  const view = new Uint8Array(envelope);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: view.subarray(
        RATCHET_WRAP_MAGIC.byteLength + 1 + RATCHET_RECORD_ID_BYTES,
        RATCHET_WRAP_HEADER_BYTES,
      ),
      additionalData: aad,
      tagLength: GCM_TAG_BYTES * 8,
    },
    key,
    view.subarray(RATCHET_WRAP_HEADER_BYTES),
  );
  if (
    (expectedPlaintextBytes !== null &&
      plaintext.byteLength !== expectedPlaintextBytes) ||
    (expectedPlaintextBytes === null &&
      (plaintext.byteLength < 1 ||
        plaintext.byteLength > MAX_EDGE_CRYPTO_STATE_BYTES))
  ) {
    new Uint8Array(plaintext).fill(0);
    throw new Error("Ratchet wrapped secret has an invalid plaintext length");
  }
  return plaintext;
};

const rollbackEdgeKey = (s: RatchetMetadata): string =>
  `${String(s.roomId.length)}:${s.roomId}${String(s.peerPublicKey.length)}:${s.peerPublicKey}`;

const ratchetEnvelopeFingerprint = async (
  s: RatchetSession,
): Promise<OwnedBytes> => {
  validateMetadata(s);
  const recordId = ratchetEnvelopeRecordId(s.rootKey);
  const otherEnvelopes = [
    s.sendingChainKey,
    s.receivingChainKey,
    s.dhSelfSec,
    ...s.skippedMessageKeys.map((skipped) => skipped.messageKey),
  ];
  for (const envelope of otherEnvelopes) {
    if (
      envelope !== null &&
      !equalBytes(ratchetEnvelopeRecordId(envelope), recordId)
    )
      throw new Error("Ratchet wrap record ID mismatch");
  }
  if (
    s.edgeCryptoState !== null &&
    !equalBytes(
      ratchetEnvelopeRecordId(s.edgeCryptoState, null),
      recordId,
    )
  )
    throw new Error("Ratchet wrap record ID mismatch");
  const parts: OwnedBytes[] = [
    canonicalRatchetAad(s, RatchetSecretField.RootKey, recordId),
    lengthPrefixed(new Uint8Array(s.rootKey)),
    lengthPrefixed(
      s.sendingChainKey ? new Uint8Array(s.sendingChainKey) : new Uint8Array(),
    ),
    lengthPrefixed(
      s.receivingChainKey
        ? new Uint8Array(s.receivingChainKey)
        : new Uint8Array(),
    ),
    lengthPrefixed(new Uint8Array(s.dhSelfSec)),
  ];
  for (const skipped of s.skippedMessageKeys)
    parts.push(lengthPrefixed(new Uint8Array(skipped.messageKey)));
  parts.push(
    lengthPrefixed(
      s.edgeCryptoState
        ? new Uint8Array(s.edgeCryptoState)
        : new Uint8Array(),
    ),
  );
  const encoded = concatBytes(parts);
  try {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", encoded));
  } finally {
    encoded.fill(0);
  }
};

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i++) difference |= a[i] ^ b[i];
  return difference === 0;
};

/**
 * Best-effort rollback/equivocation detection for one running client context.
 *
 * Callers pass an instance to `unwrapRatchetSession`; a successfully
 * authenticated record may advance `updatedAt`, but may not move backwards or
 * present different ciphertext at the same timestamp. `forget` is required
 * when an edge is intentionally deleted/re-established.
 *
 * This cannot detect replay of an older *complete* IndexedDB snapshot after a
 * full browser restart: WebCrypto/IndexedDB expose no trusted monotonic
 * counter. Durable cross-restart detection needs an independently protected
 * high-water head (or a remote/trusted anchor), atomically advanced with the
 * ratchet row. AES-GCM alone cannot provide that property.
 */
export class RatchetRollbackGuard {
  readonly #watermarks = new Map<
    string,
    { updatedAt: number; fingerprint: OwnedBytes }
  >();

  #acceptFingerprint(s: RatchetSession, fingerprint: OwnedBytes): void {
    const key = rollbackEdgeKey(s);
    const previous = this.#watermarks.get(key);
    if (previous && s.updatedAt < previous.updatedAt) {
      fingerprint.fill(0);
      throw new Error("Ratchet persistence rollback detected");
    }
    if (
      s.updatedAt === previous?.updatedAt &&
      !equalBytes(fingerprint, previous.fingerprint)
    ) {
      fingerprint.fill(0);
      throw new Error("Ratchet persistence equivocation detected");
    }
    if (!previous || s.updatedAt > previous.updatedAt) {
      previous?.fingerprint.fill(0);
      this.#watermarks.set(key, {
        updatedAt: s.updatedAt,
        fingerprint,
      });
    } else {
      fingerprint.fill(0);
    }
  }

  async acceptAuthenticated(s: RatchetSession): Promise<void> {
    const fingerprint = await ratchetEnvelopeFingerprint(s);
    this.#acceptFingerprint(s, fingerprint);
  }

  /**
   * Advance the in-process high-water mark after, and only after, a local
   * wrapped row was durably stored. The record's canonical metadata and every
   * envelope shape/record ID are validated, but the locally produced
   * ciphertext is intentionally not decrypted.
   */
  async rememberTrustedWrite(wrapped: RatchetSession): Promise<void> {
    const fingerprint = await ratchetEnvelopeFingerprint(wrapped);
    this.#acceptFingerprint(wrapped, fingerprint);
  }

  forget(roomId: string, peerPublicKey: string): void {
    const key = `${String(roomId.length)}:${roomId}${String(peerPublicKey.length)}:${peerPublicKey}`;
    this.#watermarks.get(key)?.fingerprint.fill(0);
    this.#watermarks.delete(key);
  }

  clear(): void {
    for (const value of this.#watermarks.values()) value.fingerprint.fill(0);
    this.#watermarks.clear();
  }
}

// The at-rest wrap key: an AES-GCM 256 CryptoKey with extractable:false, so its
// raw bytes never re-enter JS (stops raw-key export / cross-device copy). It is
// generated ONCE and stored as a live CryptoKey object in IndexedDB (structured-
// cloneable) so it is read back verbatim after a refresh. NOTE (documented
// limit): this does NOT stop local decryption by an attacker with device+origin
// access. First-run concurrent generate is guarded by a double-check inside the
// write tx; a rare cross-tab first-run race just triggers a re-handshake.
export async function getWrapKey(): Promise<CryptoKey> {
  const db = await getDB();
  try {
    const existing = (await db.get("meta", WRAP_KEY_META_ID)) as
      CryptoKey | undefined;
    if (existing) return existing;

    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const tx = db.transaction("meta", "readwrite");
    const store = tx.objectStore("meta");
    const check = (await store.get(WRAP_KEY_META_ID)) as CryptoKey | undefined;
    if (check) {
      await tx.done;
      return check;
    }
    await store.put(key, WRAP_KEY_META_ID);
    await tx.done;
    return key;
  } finally {
    db.close();
  }
}

// AES-GCM encrypt with a fresh 12-byte random IV, output = iv || ciphertext(+tag).
export async function wrapSecret(
  key: CryptoKey,
  bytes: ArrayBuffer,
): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  const out = new Uint8Array(GCM_IV_BYTES + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), GCM_IV_BYTES);
  return out.buffer;
}

export async function unwrapSecret(
  key: CryptoKey,
  blob: ArrayBuffer,
): Promise<ArrayBuffer> {
  const view = new Uint8Array(blob);
  if (view.byteLength < GCM_IV_BYTES + GCM_TAG_BYTES)
    throw new Error("Malformed wrapped secret");
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: view.subarray(0, GCM_IV_BYTES) },
    key,
    view.subarray(GCM_IV_BYTES),
  );
}

// Public/index fields stay visible to IndexedDB but are immutable under the
// wrap: their canonical encoding is AEAD AAD for every versioned secret-field
// envelope. A field discriminator prevents ciphertext transplantation within a
// row; the full edge/session metadata prevents transplantation across rows.
export async function wrapRatchetSession(
  s: RatchetSession,
  key: CryptoKey,
): Promise<RatchetSession> {
  const snapshot = cloneSession(s);
  validateMetadata(snapshot);
  requireBuffer(snapshot.rootKey, "ratchet rootKey", 32);
  if (snapshot.sendingChainKey)
    requireBuffer(snapshot.sendingChainKey, "ratchet sendingChainKey", 32);
  if (snapshot.receivingChainKey)
    requireBuffer(snapshot.receivingChainKey, "ratchet receivingChainKey", 32);
  requireBuffer(snapshot.dhSelfSec, "ratchet dhSelfSec", 32);
  snapshot.skippedMessageKeys.forEach((skipped, index) =>
    requireBuffer(
      skipped.messageKey,
      `ratchet skipped[${String(index)}].messageKey`,
      32,
    ),
  );
  if (snapshot.edgeCryptoState) {
    requireBuffer(snapshot.edgeCryptoState, "ratchet edge crypto state");
    if (
      snapshot.edgeCryptoState.byteLength < 1 ||
      snapshot.edgeCryptoState.byteLength > MAX_EDGE_CRYPTO_STATE_BYTES
    )
      throw new Error("ratchet edge crypto state length is invalid");
  }

  try {
    const recordId = crypto.getRandomValues(
      new Uint8Array(RATCHET_RECORD_ID_BYTES),
    );
    const rootKey = await wrapRatchetField(
      key,
      snapshot.rootKey,
      canonicalRatchetAad(snapshot, RatchetSecretField.RootKey, recordId),
      recordId,
    );
    const sendingChainKey = snapshot.sendingChainKey
      ? await wrapRatchetField(
          key,
          snapshot.sendingChainKey,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.SendingChainKey,
            recordId,
          ),
          recordId,
        )
      : null;
    const receivingChainKey = snapshot.receivingChainKey
      ? await wrapRatchetField(
          key,
          snapshot.receivingChainKey,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.ReceivingChainKey,
            recordId,
          ),
          recordId,
        )
      : null;
    const dhSelfSec = await wrapRatchetField(
      key,
      snapshot.dhSelfSec,
      canonicalRatchetAad(snapshot, RatchetSecretField.DhSelfSecret, recordId),
      recordId,
    );
    const skippedMessageKeys = [];
    for (let index = 0; index < snapshot.skippedMessageKeys.length; index++) {
      const skipped = snapshot.skippedMessageKeys[index];
      skippedMessageKeys.push({
        dhPub: skipped.dhPub,
        n: skipped.n,
        messageKey: await wrapRatchetField(
          key,
          skipped.messageKey,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.SkippedMessageKey,
            recordId,
            index,
          ),
          recordId,
        ),
      });
    }
    const edgeCryptoState = snapshot.edgeCryptoState
      ? await wrapRatchetField(
          key,
          snapshot.edgeCryptoState,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.EdgeCryptoState,
            recordId,
          ),
          recordId,
          null,
        )
      : null;
    return {
      ...snapshot,
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfSec,
      skippedMessageKeys,
      edgeCryptoState,
    };
  } finally {
    wipeSessionSecrets(snapshot);
  }
}

export async function unwrapRatchetSession(
  s: RatchetSession,
  key: CryptoKey,
  rollbackGuard?: RatchetRollbackGuard,
): Promise<RatchetSession> {
  const snapshot = cloneSession(s);
  validateMetadata(snapshot);
  const plaintexts: ArrayBuffer[] = [];
  try {
    const recordId = ratchetEnvelopeRecordId(snapshot.rootKey);
    const rootKey = await unwrapRatchetField(
      key,
      snapshot.rootKey,
      canonicalRatchetAad(snapshot, RatchetSecretField.RootKey, recordId),
      recordId,
    );
    plaintexts.push(rootKey);
    const sendingChainKey = snapshot.sendingChainKey
      ? await unwrapRatchetField(
          key,
          snapshot.sendingChainKey,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.SendingChainKey,
            recordId,
          ),
          recordId,
        )
      : null;
    if (sendingChainKey) plaintexts.push(sendingChainKey);
    const receivingChainKey = snapshot.receivingChainKey
      ? await unwrapRatchetField(
          key,
          snapshot.receivingChainKey,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.ReceivingChainKey,
            recordId,
          ),
          recordId,
        )
      : null;
    if (receivingChainKey) plaintexts.push(receivingChainKey);
    const dhSelfSec = await unwrapRatchetField(
      key,
      snapshot.dhSelfSec,
      canonicalRatchetAad(snapshot, RatchetSecretField.DhSelfSecret, recordId),
      recordId,
    );
    plaintexts.push(dhSelfSec);

    const skippedMessageKeys = [];
    for (let index = 0; index < snapshot.skippedMessageKeys.length; index++) {
      const skipped = snapshot.skippedMessageKeys[index];
      const messageKey = await unwrapRatchetField(
        key,
        skipped.messageKey,
        canonicalRatchetAad(
          snapshot,
          RatchetSecretField.SkippedMessageKey,
          recordId,
          index,
        ),
        recordId,
      );
      plaintexts.push(messageKey);
      skippedMessageKeys.push({
        dhPub: skipped.dhPub,
        n: skipped.n,
        messageKey,
      });
    }
    const edgeCryptoState = snapshot.edgeCryptoState
      ? await unwrapRatchetField(
          key,
          snapshot.edgeCryptoState,
          canonicalRatchetAad(
            snapshot,
            RatchetSecretField.EdgeCryptoState,
            recordId,
          ),
          recordId,
          null,
        )
      : null;
    if (edgeCryptoState) plaintexts.push(edgeCryptoState);

    // A guard observes only after every AEAD has authenticated, so an attacker
    // cannot poison its high-water mark with unauthenticated metadata.
    if (rollbackGuard) await rollbackGuard.acceptAuthenticated(snapshot);

    return {
      ...snapshot,
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfSec,
      skippedMessageKeys,
      edgeCryptoState,
    };
  } catch (error) {
    for (const plaintext of plaintexts) new Uint8Array(plaintext).fill(0);
    throw error;
  } finally {
    // `snapshot` owns ciphertext copies on this path. They are not secret, but
    // wiping them avoids retaining attacker-controlled envelopes after failure.
    wipeSessionSecrets(snapshot);
  }
}
