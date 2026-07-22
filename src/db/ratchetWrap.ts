import { getDB } from "./src/getDB";

import type { RatchetSession } from "./types";

// Out-of-line key in the `meta` store for the single wrap CryptoKey.
const WRAP_KEY_META_ID = "ratchetWrapKey";

// The at-rest wrap key: an AES-GCM 256 CryptoKey with extractable:false, so its
// raw bytes never re-enter JS (stops raw-key export / cross-device copy). It is
// generated ONCE and stored as a live CryptoKey object in IndexedDB (structured-
// cloneable) so it is read back verbatim after a refresh. NOTE (documented
// limit): this does NOT stop local decryption by an attacker with device+origin
// access. First-run concurrent generate is guarded by a double-check inside the
// write tx; a rare cross-tab first-run race just triggers a re-handshake.
export async function getWrapKey(): Promise<CryptoKey> {
  const db = await getDB();
  const existing = (await db.get("meta", WRAP_KEY_META_ID)) as
    | CryptoKey
    | undefined;
  if (existing) {
    db.close();
    return existing;
  }
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
    db.close();
    return check;
  }
  await store.put(key, WRAP_KEY_META_ID);
  await tx.done;
  db.close();
  return key;
}

// AES-GCM encrypt with a fresh 12-byte random IV, output = iv || ciphertext(+tag).
export async function wrapSecret(
  key: CryptoKey,
  bytes: ArrayBuffer,
): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out.buffer;
}

export async function unwrapSecret(
  key: CryptoKey,
  blob: ArrayBuffer,
): Promise<ArrayBuffer> {
  const view = new Uint8Array(blob);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: view.subarray(0, 12) },
    key,
    view.subarray(12),
  );
}

// Wrap only the secret fields; public + counter fields pass through unchanged.
export async function wrapRatchetSession(
  s: RatchetSession,
  key: CryptoKey,
): Promise<RatchetSession> {
  return {
    ...s,
    rootKey: await wrapSecret(key, s.rootKey),
    sendingChainKey: s.sendingChainKey
      ? await wrapSecret(key, s.sendingChainKey)
      : null,
    receivingChainKey: s.receivingChainKey
      ? await wrapSecret(key, s.receivingChainKey)
      : null,
    dhSelfSec: await wrapSecret(key, s.dhSelfSec),
    skippedMessageKeys: await Promise.all(
      s.skippedMessageKeys.map(async (m) => ({
        dhPub: m.dhPub,
        n: m.n,
        messageKey: await wrapSecret(key, m.messageKey),
      })),
    ),
  };
}

export async function unwrapRatchetSession(
  s: RatchetSession,
  key: CryptoKey,
): Promise<RatchetSession> {
  return {
    ...s,
    rootKey: await unwrapSecret(key, s.rootKey),
    sendingChainKey: s.sendingChainKey
      ? await unwrapSecret(key, s.sendingChainKey)
      : null,
    receivingChainKey: s.receivingChainKey
      ? await unwrapSecret(key, s.receivingChainKey)
      : null,
    dhSelfSec: await unwrapSecret(key, s.dhSelfSec),
    skippedMessageKeys: await Promise.all(
      s.skippedMessageKeys.map(async (m) => ({
        dhPub: m.dhPub,
        n: m.n,
        messageKey: await unwrapSecret(key, m.messageKey),
      })),
    ),
  };
}
