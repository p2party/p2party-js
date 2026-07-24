import wordlist from "./utils/wordlist.json";

export const ROOM_CAPABILITY_BYTES = 32;
export const ROOM_CAPABILITY_HEX_CHARS = ROOM_CAPABILITY_BYTES * 2;
export const ROOM_CAPABILITY_BASE64URL_CHARS = 43;
export const ROOM_INVITE_WORDS = 24;
export const ROOM_INVITE_VERSION = 1;
export const ROOM_INVITE_PREFIX = `v${String(ROOM_INVITE_VERSION)}.`;
export const ROOM_INVITE_WORDLIST_ID = "p2party-invite-en-v1";

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_PATTERN = /^[0-9a-fA-F]{64}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const CHECKSUM_DOMAIN = new TextEncoder().encode(
  "p2party/room-invite/checksum/v1\u0000",
);

if (wordlist.length !== 2048 || new Set(wordlist).size !== 2048)
  throw new Error("Room invite word list must contain 2,048 unique words");

const wordIndexes = new Map(
  wordlist.map((word, index) => [word, index] as const),
);

const requireCapability = (capability: Uint8Array): Uint8Array => {
  if (!(capability instanceof Uint8Array))
    throw new TypeError("Room capability must be a Uint8Array");
  if (capability.length !== ROOM_CAPABILITY_BYTES)
    throw new Error("Room capability must be exactly 32 bytes");
  return capability;
};

const concatenate = (
  first: Uint8Array,
  second: Uint8Array,
): Uint8Array<ArrayBuffer> => {
  const output = new Uint8Array(first.length + second.length);
  output.set(first);
  output.set(second, first.length);
  return output;
};

const bytesToHex = (bytes: Uint8Array): string => {
  let output = "";
  for (const byte of bytes) output += byte.toString(16).padStart(2, "0");
  return output;
};

const hexToBytes = (hex: string): Uint8Array => {
  if (!HEX_PATTERN.test(hex))
    throw new Error("Room capability hex must contain exactly 64 hex digits");
  const output = new Uint8Array(ROOM_CAPABILITY_BYTES);
  for (let index = 0; index < output.length; index += 1)
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return output;
};

export const generateRoomCapability = (): Uint8Array =>
  globalThis.crypto.getRandomValues(new Uint8Array(ROOM_CAPABILITY_BYTES));

export const encodeRoomCapabilityBase64Url = (
  capability: Uint8Array,
): string => {
  const bytes = requireCapability(capability);
  let output = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const remaining = bytes.length - offset;
    const chunk =
      (bytes[offset] << 16) |
      ((remaining > 1 ? bytes[offset + 1] : 0) << 8) |
      (remaining > 2 ? bytes[offset + 2] : 0);
    output += BASE64URL_ALPHABET[(chunk >>> 18) & 0x3f];
    output += BASE64URL_ALPHABET[(chunk >>> 12) & 0x3f];
    if (remaining > 1) output += BASE64URL_ALPHABET[(chunk >>> 6) & 0x3f];
    if (remaining > 2) output += BASE64URL_ALPHABET[chunk & 0x3f];
  }
  return output;
};

export const decodeRoomCapabilityBase64Url = (encoded: string): Uint8Array => {
  if (typeof encoded !== "string" || !BASE64URL_PATTERN.test(encoded))
    throw new Error(
      "Room capability must be exactly 43 unpadded base64url characters",
    );

  // A 32-byte value uses only the high four bits of the final base64 sextet.
  // Requiring the two unused low bits to be zero rejects alternate encodings of
  // the same capability.
  const finalValue = BASE64URL_ALPHABET.indexOf(encoded.at(-1) ?? "");
  if ((finalValue & 0x03) !== 0)
    throw new Error("Room capability base64url encoding is not canonical");

  const output = new Uint8Array(ROOM_CAPABILITY_BYTES);
  let accumulator = 0;
  let availableBits = 0;
  let outputOffset = 0;
  for (const character of encoded) {
    accumulator = (accumulator << 6) | BASE64URL_ALPHABET.indexOf(character);
    availableBits += 6;
    while (availableBits >= 8) {
      availableBits -= 8;
      output[outputOffset] = (accumulator >>> availableBits) & 0xff;
      outputOffset += 1;
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (
    outputOffset !== ROOM_CAPABILITY_BYTES ||
    encodeRoomCapabilityBase64Url(output) !== encoded
  )
    throw new Error("Room capability base64url encoding is not canonical");
  return output;
};

/** Accept the compact representation or the legacy hex migration form. */
export const decodeRoomCapability = (encoded: string): Uint8Array => {
  if (typeof encoded !== "string")
    throw new TypeError("Room capability must be a string");
  if (
    encoded.startsWith(ROOM_INVITE_PREFIX) ||
    encoded.startsWith(`#${ROOM_INVITE_PREFIX}`)
  )
    return decodeRoomInviteFragment(encoded);
  if (encoded.length === ROOM_CAPABILITY_HEX_CHARS) return hexToBytes(encoded);
  return decodeRoomCapabilityBase64Url(encoded);
};

/** Canonical internal/server representation while the legacy signaling path exists. */
export const normalizeRoomCapability = (encoded: string): string =>
  bytesToHex(decodeRoomCapability(encoded));

export const encodeRoomInviteFragment = (capability: Uint8Array): string =>
  `${ROOM_INVITE_PREFIX}${encodeRoomCapabilityBase64Url(capability)}`;

export const decodeRoomInviteFragment = (fragment: string): Uint8Array => {
  if (typeof fragment !== "string")
    throw new TypeError("Room invite fragment must be a string");
  const withoutHash = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  if (!withoutHash.startsWith(ROOM_INVITE_PREFIX))
    throw new Error("Unsupported room invite version");
  return decodeRoomCapabilityBase64Url(
    withoutHash.slice(ROOM_INVITE_PREFIX.length),
  );
};

const roomInviteChecksum = async (capability: Uint8Array): Promise<number> => {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    concatenate(CHECKSUM_DOMAIN, capability),
  );
  return new Uint8Array(digest)[0];
};

const bytesToWordIndexes = (bytes: Uint8Array): number[] => {
  const indexes: number[] = [];
  let accumulator = 0;
  let availableBits = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    availableBits += 8;
    while (availableBits >= 11) {
      availableBits -= 11;
      indexes.push((accumulator >>> availableBits) & 0x07ff);
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits !== 0)
    throw new Error("Room invite word encoding is not byte-aligned");
  return indexes;
};

const wordIndexesToBytes = (indexes: readonly number[]): Uint8Array => {
  const output = new Uint8Array(ROOM_CAPABILITY_BYTES + 1);
  let accumulator = 0;
  let availableBits = 0;
  let outputOffset = 0;
  for (const index of indexes) {
    accumulator = (accumulator << 11) | index;
    availableBits += 11;
    while (availableBits >= 8) {
      availableBits -= 8;
      output[outputOffset] = (accumulator >>> availableBits) & 0xff;
      outputOffset += 1;
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits !== 0 || outputOffset !== output.length)
    throw new Error("Room invite word encoding is not canonical");
  return output;
};

export const encodeRoomCapabilityWords = async (
  capability: Uint8Array,
): Promise<string> => {
  const bytes = requireCapability(capability);
  const withChecksum = new Uint8Array(ROOM_CAPABILITY_BYTES + 1);
  withChecksum.set(bytes);
  withChecksum[ROOM_CAPABILITY_BYTES] = await roomInviteChecksum(bytes);
  const indexes = bytesToWordIndexes(withChecksum);
  if (indexes.length !== ROOM_INVITE_WORDS)
    throw new Error("Room invite word encoding has an unexpected length");
  return indexes.map((index) => wordlist[index]).join(" ");
};

export const decodeRoomCapabilityWords = async (
  encoded: string,
): Promise<Uint8Array> => {
  if (typeof encoded !== "string")
    throw new TypeError("Room invite words must be a string");
  const normalized = encoded.normalize("NFKD").trim().toLowerCase();
  const words = normalized.length === 0 ? [] : normalized.split(/\s+/u);
  if (words.length !== ROOM_INVITE_WORDS)
    throw new Error("Room invite must contain exactly 24 words");
  const indexes = words.map((word) => {
    const index = wordIndexes.get(word);
    if (index === undefined)
      throw new Error(`Unknown room invite word: ${word}`);
    return index;
  });
  const decoded = wordIndexesToBytes(indexes);
  const capability = decoded.slice(0, ROOM_CAPABILITY_BYTES);
  const expectedChecksum = await roomInviteChecksum(capability);
  if (decoded[ROOM_CAPABILITY_BYTES] !== expectedChecksum)
    throw new Error("Room invite checksum is invalid");
  return capability;
};
