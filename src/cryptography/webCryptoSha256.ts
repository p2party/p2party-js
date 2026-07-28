/**
 * Shared WebCrypto SHA-256, HMAC-SHA-256, and RFC 5869 HKDF-SHA-256.
 *
 * Every public function snapshots caller-owned bytes synchronously. Callers may
 * therefore mutate or transfer their buffers as soon as the function returns
 * its promise without changing the in-flight operation.
 */

const HASH_BYTES = 32;
const MAX_HKDF_EXPAND_BYTES = 255 * HASH_BYTES;

const requireUint8Array: (
  value: unknown,
  name: string,
) => asserts value is Uint8Array = (value, name) => {
  if (!(value instanceof Uint8Array))
    throw new TypeError(`${name} must be a Uint8Array`);
};

const snapshot = (value: Uint8Array): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(value);

const requireHkdfExpandLength = (length: number): void => {
  if (
    !Number.isSafeInteger(length) ||
    length < 1 ||
    length > MAX_HKDF_EXPAND_BYTES
  )
    throw new RangeError("HKDF-Expand output length is out of range");
};

const concatBytes = (
  ...parts: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> => {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

/** SHA-256 over a synchronous snapshot of `input`. */
export const sha256 = async (input: Uint8Array): Promise<Uint8Array> => {
  requireUint8Array(input, "SHA-256 input");
  const privateInput = snapshot(input);
  try {
    return new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", privateInput),
    );
  } finally {
    privateInput.fill(0);
  }
};

/** HMAC-SHA-256 over synchronous snapshots of `key` and `message`. */
export const hmacSha256 = async (
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> => {
  requireUint8Array(key, "HMAC-SHA-256 key");
  requireUint8Array(message, "HMAC-SHA-256 message");
  const privateKey = snapshot(key);
  const privateMessage = snapshot(message);
  // WebCrypto rejects an empty raw HMAC key. RFC 2104 pads both an empty key
  // and a 32-byte all-zero key to the same SHA-256 block, so this preserves the
  // exact empty-key result required by RFC 5869's omitted/empty salt rule.
  const effectiveKey =
    privateKey.length === 0 ? new Uint8Array(HASH_BYTES) : privateKey;

  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      effectiveKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return new Uint8Array(
      await globalThis.crypto.subtle.sign("HMAC", cryptoKey, privateMessage),
    );
  } finally {
    effectiveKey.fill(0);
    privateKey.fill(0);
    privateMessage.fill(0);
  }
};

/** RFC 5869 HKDF-Extract with SHA-256. */
export const hkdfSha256Extract = async (
  salt: Uint8Array,
  ikm: Uint8Array,
): Promise<Uint8Array> => {
  requireUint8Array(salt, "HKDF-Extract salt");
  requireUint8Array(ikm, "HKDF-Extract input key material");
  const privateSalt = snapshot(salt);
  const privateIkm = snapshot(ikm);
  try {
    return await hmacSha256(privateSalt, privateIkm);
  } finally {
    privateSalt.fill(0);
    privateIkm.fill(0);
  }
};

/**
 * RFC 5869 HKDF-Expand with SHA-256.
 *
 * This API requires a standards-conforming PRK of at least 32 bytes and a
 * nonempty output no longer than RFC 5869's 255-block upper bound.
 */
export const hkdfSha256Expand = async (
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> => {
  // Reject the scalar before touching potentially large caller buffers.
  requireHkdfExpandLength(length);
  requireUint8Array(prk, "HKDF-Expand pseudorandom key");
  requireUint8Array(info, "HKDF-Expand info");
  if (prk.length < HASH_BYTES)
    throw new RangeError(
      `HKDF-Expand pseudorandom key must be at least ${String(HASH_BYTES)} bytes`,
    );
  const privatePrk = snapshot(prk);
  const privateInfo = snapshot(info);

  const output = new Uint8Array(length);
  let previousBlock: Uint8Array = new Uint8Array(0);
  let offset = 0;
  let complete = false;
  try {
    for (let counter = 1; offset < length; counter++) {
      const blockInput = concatBytes(
        previousBlock,
        privateInfo,
        Uint8Array.of(counter),
      );
      const nextBlockPromise = hmacSha256(privatePrk, blockInput);
      blockInput.fill(0);
      const nextBlock = await nextBlockPromise;
      previousBlock.fill(0);
      previousBlock = nextBlock;

      const take = Math.min(previousBlock.length, length - offset);
      output.set(previousBlock.subarray(0, take), offset);
      offset += take;
    }
    complete = true;
    return output;
  } finally {
    if (!complete) output.fill(0);
    privatePrk.fill(0);
    privateInfo.fill(0);
    previousBlock.fill(0);
  }
};
