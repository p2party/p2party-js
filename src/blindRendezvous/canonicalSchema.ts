/**
 * Canonical binary schema: the single source of truth for blind-rendezvous
 * wire bytes.
 *
 * Section 4 of the L2/L3 blind-rendezvous specification writes `Canonical(x)`
 * for "the unique encoding in the companion binary-schema artifact". This
 * module is that artifact's executable form. It owns field order, integer
 * widths, enum values, collection ordering, and bounds, so no other module may
 * hand-roll a second encoding of the same value.
 *
 * Status: PROPOSED, NOT FROZEN. Phase 0 of the delivery roadmap freezes these
 * widths and publishes deterministic vectors under one release-registry hash.
 * Until that freeze and its external review, no hash derived from this module
 * may be published as a v0.4 release artifact, and no interoperability claim
 * follows from two implementations agreeing with it.
 *
 * The codec is descriptor-driven rather than hand-written per type. A
 * descriptor is the SSOT: encoders, decoders, key tables, and bound checks are
 * all derived from it, which is what makes the generated projections in
 * `projections.ts` mechanically checkable instead of hand-maintained.
 */

export type Bytes32 = Uint8Array;

/** Maximum entries in any bounded collection with a 16-bit count prefix. */
export const MAX_U16_COLLECTION_ENTRIES = 0xffff;
/** Bound on any canonical NFC text field, in UTF-8 bytes. */
export const MAX_CANONICAL_TEXT_BYTES = 4096;
/** Bound on a single canonically encoded value, in bytes. */
export const MAX_CANONICAL_ENCODING_BYTES = 1 << 24;

const textEncoder = new TextEncoder();

/**
 * True when every UTF-16 code unit is part of a valid scalar value.
 *
 * `String.prototype.isWellFormed` is not assumed present; the manual scan
 * keeps this module free of a runtime-version dependency.
 */
const isWellFormedUtf16 = (value: string): boolean => {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit < 0xd800 || unit > 0xdfff) continue;
    if (unit > 0xdbff) return false; // trailing surrogate with no lead
    const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
    if (next < 0xdc00 || next > 0xdfff) return false; // lead with no trail
    index++;
  }
  return true;
};
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export class CanonicalSchemaError extends Error {
  override readonly name = "CanonicalSchemaError";
  readonly path: string;

  constructor(path: string, message: string) {
    super(`canonicalSchema: ${path}: ${message}`);
    this.path = path;
  }
}

// The explicit annotation is load-bearing: TypeScript narrows control flow
// after a `never`-returning const arrow only when the variable is annotated.
const fail: (path: string, message: string) => never = (path, message) => {
  throw new CanonicalSchemaError(path, message);
};

/* ------------------------------------------------------------------ *
 * Descriptors
 * ------------------------------------------------------------------ */

export interface FieldDescriptor {
  readonly name: string;
  readonly type: TypeDescriptor;
}

export type TypeDescriptor =
  | { readonly kind: "u8" }
  | { readonly kind: "u16" }
  | { readonly kind: "u32" }
  | { readonly kind: "u64" }
  | { readonly kind: "bool" }
  | { readonly kind: "fixedBytes"; readonly length: number }
  | { readonly kind: "varBytes"; readonly maxLength: number }
  | { readonly kind: "text"; readonly maxBytes: number }
  | {
      readonly kind: "enum";
      readonly name: string;
      // Index in this array is the wire byte. Order is protocol-visible and
      // may never be rearranged without a new schema version.
      readonly values: readonly string[];
    }
  | {
      readonly kind: "array";
      readonly item: TypeDescriptor;
      readonly maxEntries: number;
      // Every canonical array is sorted bytewise by its item encoding and
      // duplicate-free. The spec states this as "sorted by their complete
      // canonical key"; the complete canonical key is the item encoding.
      readonly ordering: "sorted-unique" | "sequence";
    }
  | { readonly kind: "optional"; readonly value: TypeDescriptor }
  | {
      readonly kind: "record";
      readonly name: string;
      readonly fields: readonly FieldDescriptor[];
    }
  | {
      readonly kind: "union";
      readonly name: string;
      readonly discriminant: string;
      // Index in this array is the wire tag byte.
      readonly variants: readonly {
        readonly tag: string;
        readonly type: TypeDescriptor;
      }[];
    };

export const u8: TypeDescriptor = { kind: "u8" };
export const u16: TypeDescriptor = { kind: "u16" };
export const u32: TypeDescriptor = { kind: "u32" };
export const u64: TypeDescriptor = { kind: "u64" };
export const bool: TypeDescriptor = { kind: "bool" };

export const fixedBytes = (length: number): TypeDescriptor => {
  if (!Number.isSafeInteger(length) || length <= 0)
    fail("fixedBytes", "length must be a positive safe integer");
  return { kind: "fixedBytes", length };
};

export const bytes32: TypeDescriptor = fixedBytes(32);
export const bytes64: TypeDescriptor = fixedBytes(64);

export const varBytes = (maxLength: number): TypeDescriptor => {
  if (!Number.isSafeInteger(maxLength) || maxLength <= 0)
    fail("varBytes", "maxLength must be a positive safe integer");
  return { kind: "varBytes", maxLength };
};

export const text = (
  maxBytes: number = MAX_CANONICAL_TEXT_BYTES,
): TypeDescriptor => {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0)
    fail("text", "maxBytes must be a positive safe integer");
  return { kind: "text", maxBytes };
};

export const enumOf = (
  name: string,
  values: readonly string[],
): TypeDescriptor => {
  if (values.length === 0 || values.length > 256)
    fail(name, "an enum must have between 1 and 256 values");
  if (new Set(values).size !== values.length)
    fail(name, "enum values must be unique");
  return { kind: "enum", name, values };
};

export const array = (
  item: TypeDescriptor,
  maxEntries: number,
  ordering: "sorted-unique" | "sequence" = "sorted-unique",
): TypeDescriptor => {
  if (
    !Number.isSafeInteger(maxEntries) ||
    maxEntries <= 0 ||
    maxEntries > MAX_U16_COLLECTION_ENTRIES
  )
    fail("array", "maxEntries must be within the 16-bit collection bound");
  return { kind: "array", item, maxEntries, ordering };
};

export const optional = (value: TypeDescriptor): TypeDescriptor => {
  // `optional(optional(T))` would give `null` two encodings — the outer
  // absent tag, and a present tag wrapping an absent one — because no
  // in-memory value distinguishes them.
  if (value.kind === "optional")
    fail("optional", "must not nest: the inner value would have two encodings");
  return { kind: "optional", value };
};

export const record = (
  name: string,
  fields: readonly FieldDescriptor[],
): TypeDescriptor => {
  if (fields.length === 0) fail(name, "a record must have at least one field");
  if (new Set(fields.map((field) => field.name)).size !== fields.length)
    fail(name, "record field names must be unique");
  return { kind: "record", name, fields };
};

export const union = (
  name: string,
  discriminant: string,
  variants: readonly { readonly tag: string; readonly type: TypeDescriptor }[],
): TypeDescriptor => {
  if (variants.length === 0 || variants.length > 256)
    fail(name, "a union must have between 1 and 256 variants");
  if (new Set(variants.map((variant) => variant.tag)).size !== variants.length)
    fail(name, "union variant tags must be unique");
  for (const variant of variants) {
    if (variant.type.kind !== "record")
      fail(name, "every union variant must be a record");
  }
  return { kind: "union", name, discriminant, variants };
};

/* ------------------------------------------------------------------ *
 * Shape validation
 * ------------------------------------------------------------------ */

/**
 * Accept only a plain record with exactly the expected keys, each an
 * enumerable data property. Accessor-backed and prototype-inherited fields are
 * rejected so a getter cannot return different bytes on a second read.
 */
const assertPlainExactRecord = (
  path: string,
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail(path, "must be a plain record");

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    fail(path, "must be a plain record");

  const ownKeys = Reflect.ownKeys(value);
  const expected = new Set(keys);
  if (
    ownKeys.length !== expected.size ||
    ownKeys.some((key) => typeof key !== "string" || !expected.has(key))
  )
    fail(path, "has missing or unexpected fields");

  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      fail(`${path}.${key}`, "must be an enumerable data property");
  }
  return value as Record<string, unknown>;
};

const assertPlainDenseArray = (path: string, value: unknown): unknown[] => {
  if (!Array.isArray(value)) fail(path, "must be an array");
  if (Object.getPrototypeOf(value) !== Array.prototype)
    fail(path, "must be a plain array");

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== value.length + 1 ||
    ownKeys[ownKeys.length - 1] !== "length"
  )
    fail(path, "has unexpected array fields");

  for (let index = 0; index < value.length; index++) {
    if (ownKeys[index] !== String(index))
      fail(path, "must be dense and canonically indexed");
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      fail(`${path}[${index}]`, "must be an enumerable data property");
  }
  return value as unknown[];
};

/* ------------------------------------------------------------------ *
 * Encoder
 * ------------------------------------------------------------------ */

class ByteWriter {
  private chunks: Uint8Array[] = [];
  private total = 0;

  push(bytes: Uint8Array): void {
    this.total += bytes.length;
    if (this.total > MAX_CANONICAL_ENCODING_BYTES)
      fail("encode", "canonical encoding exceeds the maximum encoded size");
    this.chunks.push(bytes);
  }

  pushByte(value: number): void {
    this.push(Uint8Array.of(value));
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.total);
    let offset = 0;
    for (const chunk of this.chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
    }
    return output;
  }
}

const u16be = (value: number): Uint8Array =>
  Uint8Array.of((value >>> 8) & 0xff, value & 0xff);

const u32be = (value: number): Uint8Array =>
  Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );

const u64be = (value: bigint): Uint8Array => {
  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
};

const assertUnsignedInteger = (
  path: string,
  value: unknown,
  max: number,
): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    fail(path, "must be a safe integer");
  if (value < 0 || value > max)
    fail(path, `must be within [0, ${String(max)}]`);
  return value;
};

const assertUnsigned64 = (path: string, value: unknown): bigint => {
  if (typeof value !== "bigint") fail(path, "must be a bigint");
  if (value < 0n || value > 0xffffffffffffffffn)
    fail(path, "must be within the unsigned 64-bit range");
  return value;
};

const assertUint8Array = (path: string, value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) fail(path, "must be a Uint8Array");
  return value;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
};

export const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && compareBytes(left, right) === 0;

const encodeInto = (
  writer: ByteWriter,
  descriptor: TypeDescriptor,
  value: unknown,
  path: string,
): void => {
  switch (descriptor.kind) {
    case "u8":
      writer.pushByte(assertUnsignedInteger(path, value, 0xff));
      return;
    case "u16":
      writer.push(u16be(assertUnsignedInteger(path, value, 0xffff)));
      return;
    case "u32":
      writer.push(u32be(assertUnsignedInteger(path, value, 0xffffffff)));
      return;
    case "u64":
      writer.push(u64be(assertUnsigned64(path, value)));
      return;
    case "bool":
      if (typeof value !== "boolean") fail(path, "must be a boolean");
      writer.pushByte(value ? 1 : 0);
      return;
    case "fixedBytes": {
      const bytes = assertUint8Array(path, value);
      if (bytes.length !== descriptor.length)
        fail(path, `must be exactly ${String(descriptor.length)} bytes`);
      writer.push(bytes);
      return;
    }
    case "varBytes": {
      const bytes = assertUint8Array(path, value);
      if (bytes.length > descriptor.maxLength)
        fail(path, `exceeds its ${String(descriptor.maxLength)}-byte bound`);
      writer.push(u32be(bytes.length));
      writer.push(bytes);
      return;
    }
    case "text": {
      if (typeof value !== "string") fail(path, "must be a string");
      if (value.length === 0) fail(path, "must be non-empty");
      // An unpaired surrogate is NFC-stable but TextEncoder rewrites it to
      // U+FFFD, which would collapse two distinct strings onto one byte
      // string. Reject rather than repair: the encoding must be injective.
      if (!isWellFormedUtf16(value))
        fail(path, "must not contain an unpaired surrogate");
      if (value.normalize("NFC") !== value) fail(path, "must use Unicode NFC");
      const encoded = textEncoder.encode(value);
      if (encoded.length > descriptor.maxBytes)
        fail(path, `exceeds its ${String(descriptor.maxBytes)}-byte bound`);
      writer.push(u32be(encoded.length));
      writer.push(encoded);
      return;
    }
    case "enum": {
      if (typeof value !== "string") fail(path, "must be a string");
      const index = descriptor.values.indexOf(value);
      if (index < 0) fail(path, `is not a member of ${descriptor.name}`);
      writer.pushByte(index);
      return;
    }
    case "optional":
      if (value === null) {
        writer.pushByte(0);
        return;
      }
      writer.pushByte(1);
      encodeInto(writer, descriptor.value, value, path);
      return;
    case "array": {
      const entries = assertPlainDenseArray(path, value);
      if (entries.length > descriptor.maxEntries)
        fail(
          path,
          `exceeds its ${String(descriptor.maxEntries)}-entry collection bound`,
        );
      const encoded = entries.map((entry, index) =>
        encodeCanonical(descriptor.item, entry, `${path}[${String(index)}]`),
      );
      if (descriptor.ordering === "sorted-unique") {
        for (let index = 1; index < encoded.length; index++) {
          const order = compareBytes(encoded[index - 1], encoded[index]);
          if (order > 0)
            fail(path, "must be sorted by its complete canonical key");
          if (order === 0) fail(path, "must be duplicate-free");
        }
      }
      writer.push(u16be(entries.length));
      for (const entry of encoded) writer.push(entry);
      return;
    }
    case "record": {
      const object = assertPlainExactRecord(
        path,
        value,
        descriptor.fields.map((field) => field.name),
      );
      for (const field of descriptor.fields)
        encodeInto(
          writer,
          field.type,
          object[field.name],
          `${path}.${field.name}`,
        );
      return;
    }
    case "union": {
      if (value === null || typeof value !== "object" || Array.isArray(value))
        fail(path, "must be a plain record");
      const tag = (value as Record<string, unknown>)[descriptor.discriminant];
      if (typeof tag !== "string")
        fail(
          `${path}.${descriptor.discriminant}`,
          "must be a string discriminant",
        );
      const variantIndex = descriptor.variants.findIndex(
        (variant) => variant.tag === tag,
      );
      if (variantIndex < 0)
        fail(path, `has no ${descriptor.name} variant "${tag}"`);
      writer.pushByte(variantIndex);
      encodeInto(
        writer,
        descriptor.variants[variantIndex].type,
        value,
        `${path}(${tag})`,
      );
      return;
    }
  }
};

/** The unique canonical encoding of `value` under `descriptor`. */
export const encodeCanonical = (
  descriptor: TypeDescriptor,
  value: unknown,
  path = descriptorName(descriptor),
): Uint8Array => {
  const writer = new ByteWriter();
  encodeInto(writer, descriptor, value, path);
  return writer.finish();
};

/* ------------------------------------------------------------------ *
 * Decoder
 * ------------------------------------------------------------------ */

class ByteReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  take(count: number, path: string): Uint8Array {
    if (this.offset + count > this.bytes.length)
      fail(path, "canonical encoding is truncated");
    const slice = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  }

  takeByte(path: string): number {
    return this.take(1, path)[0];
  }

  get consumed(): number {
    return this.offset;
  }

  get length(): number {
    return this.bytes.length;
  }
}

const readU16 = (reader: ByteReader, path: string): number => {
  const bytes = reader.take(2, path);
  return (bytes[0] << 8) | bytes[1];
};

const readU32 = (reader: ByteReader, path: string): number => {
  const bytes = reader.take(4, path);
  return bytes[0] * 0x1000000 + ((bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
};

const readU64 = (reader: ByteReader, path: string): bigint => {
  const bytes = reader.take(8, path);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const decodeFrom = (
  reader: ByteReader,
  descriptor: TypeDescriptor,
  path: string,
): unknown => {
  switch (descriptor.kind) {
    case "u8":
      return reader.takeByte(path);
    case "u16":
      return readU16(reader, path);
    case "u32":
      return readU32(reader, path);
    case "u64":
      return readU64(reader, path);
    case "bool": {
      const byte = reader.takeByte(path);
      if (byte > 1) fail(path, "boolean must be exactly 0x00 or 0x01");
      return byte === 1;
    }
    case "fixedBytes":
      return Uint8Array.from(reader.take(descriptor.length, path));
    case "varBytes": {
      const length = readU32(reader, path);
      if (length > descriptor.maxLength)
        fail(path, `exceeds its ${String(descriptor.maxLength)}-byte bound`);
      return Uint8Array.from(reader.take(length, path));
    }
    case "text": {
      const length = readU32(reader, path);
      if (length === 0) fail(path, "must be non-empty");
      if (length > descriptor.maxBytes)
        fail(path, `exceeds its ${String(descriptor.maxBytes)}-byte bound`);
      let decoded: string;
      try {
        decoded = textDecoder.decode(reader.take(length, path));
      } catch {
        return fail(path, "must be well-formed UTF-8");
      }
      if (decoded.normalize("NFC") !== decoded)
        fail(path, "must use Unicode NFC");
      return decoded;
    }
    case "enum": {
      const index = reader.takeByte(path);
      if (index >= descriptor.values.length)
        fail(path, `is not a member of ${descriptor.name}`);
      return descriptor.values[index];
    }
    case "optional": {
      const present = reader.takeByte(path);
      if (present === 0) return null;
      if (present !== 1)
        fail(path, "presence tag must be exactly 0x00 or 0x01");
      return decodeFrom(reader, descriptor.value, path);
    }
    case "array": {
      const count = readU16(reader, path);
      if (count > descriptor.maxEntries)
        fail(
          path,
          `exceeds its ${String(descriptor.maxEntries)}-entry collection bound`,
        );
      const entries: unknown[] = [];
      let previous: Uint8Array | null = null;
      for (let index = 0; index < count; index++) {
        const itemPath = `${path}[${String(index)}]`;
        const before = reader.consumed;
        const entry = decodeFrom(reader, descriptor.item, itemPath);
        if (descriptor.ordering === "sorted-unique") {
          const encoded = encodeCanonical(descriptor.item, entry, itemPath);
          if (encoded.length !== reader.consumed - before)
            fail(itemPath, "is not the unique canonical encoding of its value");
          if (previous !== null) {
            const order = compareBytes(previous, encoded);
            if (order > 0)
              fail(path, "must be sorted by its complete canonical key");
            if (order === 0) fail(path, "must be duplicate-free");
          }
          previous = encoded;
        }
        entries.push(entry);
      }
      return entries;
    }
    case "record": {
      const object: Record<string, unknown> = {};
      for (const field of descriptor.fields)
        object[field.name] = decodeFrom(
          reader,
          field.type,
          `${path}.${field.name}`,
        );
      return object;
    }
    case "union": {
      const tagIndex = reader.takeByte(path);
      if (tagIndex >= descriptor.variants.length)
        fail(path, `is not a registered ${descriptor.name} variant`);
      const variant = descriptor.variants[tagIndex];
      const decoded = decodeFrom(
        reader,
        variant.type,
        `${path}(${variant.tag})`,
      ) as Record<string, unknown>;
      if (decoded[descriptor.discriminant] !== variant.tag)
        fail(path, "union tag byte and discriminant field disagree");
      return decoded;
    }
  }
};

/**
 * Decode exactly one canonical value. Trailing bytes, non-minimal encodings,
 * unknown enum/union tags, unsorted collections, and out-of-bound lengths are
 * rejected rather than repaired.
 */
export const decodeCanonical = (
  descriptor: TypeDescriptor,
  bytes: Uint8Array,
  path = descriptorName(descriptor),
): unknown => {
  if (!(bytes instanceof Uint8Array))
    fail(path, "canonical input must be a Uint8Array");
  const reader = new ByteReader(bytes);
  const value = decodeFrom(reader, descriptor, path);
  if (reader.consumed !== reader.length)
    fail(path, "canonical encoding has trailing bytes");
  return value;
};

/**
 * Decode, then prove the result re-encodes to the exact input bytes. Callers
 * at a security boundary use this so a value that decodes but is not the
 * unique encoding of itself can never be accepted.
 */
export const decodeCanonicalStrict = (
  descriptor: TypeDescriptor,
  bytes: Uint8Array,
  path = descriptorName(descriptor),
): unknown => {
  const value = decodeCanonical(descriptor, bytes, path);
  if (!bytesEqual(encodeCanonical(descriptor, value, path), bytes))
    fail(path, "is not the unique canonical encoding of its value");
  return value;
};

export const descriptorName = (descriptor: TypeDescriptor): string => {
  if (
    descriptor.kind === "record" ||
    descriptor.kind === "union" ||
    descriptor.kind === "enum"
  )
    return descriptor.name;
  return descriptor.kind;
};

/* ------------------------------------------------------------------ *
 * Projections
 * ------------------------------------------------------------------ */

/**
 * The exact field-name projection of a record descriptor, in wire order.
 *
 * Section 1.4 makes generated projections mandatory: a hand-maintained key
 * table that disagrees with the schema is a release failure. Consumers import
 * this instead of restating field names.
 */
export const recordFieldNames = (
  descriptor: TypeDescriptor,
): readonly string[] => {
  if (descriptor.kind !== "record")
    fail(descriptorName(descriptor), "is not a record descriptor");
  return descriptor.fields.map((field) => field.name);
};

/** The descriptor of one named field of a record descriptor. */
export const recordFieldType = (
  descriptor: TypeDescriptor,
  fieldName: string,
): TypeDescriptor => {
  if (descriptor.kind !== "record")
    fail(descriptorName(descriptor), "is not a record descriptor");
  const field = descriptor.fields.find((entry) => entry.name === fieldName);
  if (field === undefined)
    fail(descriptorName(descriptor), `has no field "${fieldName}"`);
  return field.type;
};

/** The descriptor of one named variant of a union descriptor. */
export const unionVariantType = (
  descriptor: TypeDescriptor,
  tag: string,
): TypeDescriptor => {
  if (descriptor.kind !== "union")
    fail(descriptorName(descriptor), "is not a union descriptor");
  const variant = descriptor.variants.find((entry) => entry.tag === tag);
  if (variant === undefined)
    fail(descriptorName(descriptor), `has no variant "${tag}"`);
  return variant.type;
};

/** The exact enum-value projection, in wire-byte order. */
export const enumValues = (descriptor: TypeDescriptor): readonly string[] => {
  if (descriptor.kind !== "enum")
    fail(descriptorName(descriptor), "is not an enum descriptor");
  return descriptor.values;
};

/** The wire byte assigned to one enum member. */
export const enumByte = (descriptor: TypeDescriptor, value: string): number => {
  const index = enumValues(descriptor).indexOf(value);
  if (index < 0) fail(descriptorName(descriptor), `has no member "${value}"`);
  return index;
};
