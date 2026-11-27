import { getDB } from "./src/getDB";

// The legacy key name also protects long-lived account and X25519 identities.
const WRAP_KEY_META_ID = "ratchetWrapKey";
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;

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
