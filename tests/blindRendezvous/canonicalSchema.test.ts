import { describe, expect, test } from "bun:test";

import {
  array,
  bool,
  bytes32,
  decodeCanonical,
  decodeCanonicalStrict,
  encodeCanonical,
  enumByte,
  enumOf,
  optional,
  record,
  recordFieldNames,
  text,
  u16,
  u32,
  u64,
  u8,
  union,
  varBytes,
} from "../../src/blindRendezvous/canonicalSchema";

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const colourSchema = enumOf("Colour", ["red", "green", "blue"]);

const leafSchema = record("Leaf", [
  { name: "id", type: u16 },
  { name: "tag", type: bytes32 },
]);

const sampleSchema = record("Sample", [
  { name: "version", type: u8 },
  { name: "count", type: u32 },
  { name: "window", type: u64 },
  { name: "enabled", type: bool },
  { name: "colour", type: colourSchema },
  { name: "label", type: text(64) },
  { name: "payload", type: varBytes(128) },
  { name: "parent", type: optional(bytes32) },
  { name: "leaves", type: array(leafSchema, 8) },
]);

const sample = {
  version: 1,
  count: 7,
  window: 42n,
  enabled: true,
  colour: "green" as const,
  label: "hello",
  payload: Uint8Array.of(1, 2, 3),
  parent: null,
  leaves: [
    { id: 1, tag: bytes(0xaa) },
    { id: 2, tag: bytes(0xbb) },
  ],
};

describe("canonical encoding is deterministic and unique", () => {
  test("round-trips and reproduces byte-identical output", () => {
    const encoded = encodeCanonical(sampleSchema, sample);
    expect(hex(encodeCanonical(sampleSchema, sample))).toBe(hex(encoded));

    const decoded = decodeCanonical(sampleSchema, encoded);
    expect(hex(encodeCanonical(sampleSchema, decoded))).toBe(hex(encoded));
    expect(decoded).toEqual(sample);
  });

  test("field order is fixed by the descriptor, not by object key order", () => {
    const reordered = {
      leaves: sample.leaves,
      parent: sample.parent,
      payload: sample.payload,
      label: sample.label,
      colour: sample.colour,
      enabled: sample.enabled,
      window: sample.window,
      count: sample.count,
      version: sample.version,
    };
    expect(hex(encodeCanonical(sampleSchema, reordered))).toBe(
      hex(encodeCanonical(sampleSchema, sample)),
    );
  });

  test("integer widths are exact big-endian encodings", () => {
    const widths = record("Widths", [
      { name: "a", type: u8 },
      { name: "b", type: u16 },
      { name: "c", type: u32 },
      { name: "d", type: u64 },
    ]);
    expect(hex(encodeCanonical(widths, { a: 1, b: 2, c: 3, d: 4n }))).toBe(
      "01" + "0002" + "00000003" + "0000000000000004",
    );
  });

  test("enum values map to their declared wire byte", () => {
    expect(enumByte(colourSchema, "red")).toBe(0);
    expect(enumByte(colourSchema, "blue")).toBe(2);
    expect(() => enumByte(colourSchema, "puce")).toThrow(
      'has no member "puce"',
    );
  });

  test("optional presence uses one closed tag byte", () => {
    const present = encodeCanonical(sampleSchema, {
      ...sample,
      parent: bytes(0xcc),
    });
    const absent = encodeCanonical(sampleSchema, sample);
    expect(present.length).toBe(absent.length + 32);
  });
});

describe("canonical encoding rejects everything ambiguous", () => {
  test("rejects unknown, missing, and accessor-backed fields", () => {
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, extra: 1 }),
    ).toThrow("missing or unexpected fields");

    const { count: _removed, ...missing } = sample;
    expect(() => encodeCanonical(sampleSchema, missing)).toThrow(
      "missing or unexpected fields",
    );

    const withAccessor = { ...sample };
    Object.defineProperty(withAccessor, "version", {
      get: () => 1,
      enumerable: true,
      configurable: true,
    });
    expect(() => encodeCanonical(sampleSchema, withAccessor)).toThrow(
      "enumerable data property",
    );
  });

  test("rejects prototype-bearing and sparse containers", () => {
    class Impostor {
      version = 1;
    }
    expect(() => encodeCanonical(sampleSchema, new Impostor())).toThrow(
      "must be a plain record",
    );

    // A hole would encode as some implementation-chosen filler, so a sparse
    // array is rejected outright rather than densified.
    const sparse: unknown[] = [];
    sparse[2] = { id: 1, tag: bytes(1) };
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, leaves: sparse }),
    ).toThrow("unexpected array fields");

    const withExtraKey = [sample.leaves[0]];
    Object.defineProperty(withExtraKey, "note", {
      value: "x",
      enumerable: true,
    });
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, leaves: withExtraKey }),
    ).toThrow("unexpected array fields");
  });

  test("rejects unsorted and duplicated collections", () => {
    expect(() =>
      encodeCanonical(sampleSchema, {
        ...sample,
        leaves: [sample.leaves[1], sample.leaves[0]],
      }),
    ).toThrow("sorted by its complete canonical key");

    expect(() =>
      encodeCanonical(sampleSchema, {
        ...sample,
        leaves: [sample.leaves[0], sample.leaves[0]],
      }),
    ).toThrow("duplicate-free");
  });

  test("rejects out-of-range integers and wrong byte lengths", () => {
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, version: 256 }),
    ).toThrow("must be within");
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, version: -1 }),
    ).toThrow("must be within");
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, version: 1.5 }),
    ).toThrow("must be a safe integer");
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, window: -1n }),
    ).toThrow("unsigned 64-bit range");
    expect(() =>
      encodeCanonical(sampleSchema, {
        ...sample,
        leaves: [{ id: 1, tag: new Uint8Array(31) }],
      }),
    ).toThrow("exactly 32 bytes");
  });

  test("rejects unpaired surrogates so the text encoding stays injective", () => {
    // A lone surrogate is NFC-stable, and TextEncoder would silently rewrite
    // it to U+FFFD — collapsing two distinct strings onto one byte string.
    for (const bad of ["\uD800", "a\uDC00b", "\uD800\uD800"])
      expect(() =>
        encodeCanonical(sampleSchema, { ...sample, label: bad }),
      ).toThrow("unpaired surrogate");
    // A correctly paired surrogate is a valid scalar value and is accepted.
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, label: "\uD83D\uDE00" }),
    ).not.toThrow();
  });

  test("refuses a nested optional, which would give null two encodings", () => {
    expect(() => optional(optional(u8))).toThrow("must not nest");
  });

  test("rejects non-NFC text and over-long values", () => {
    // U+0065 U+0301 is the decomposed form of "é"; NFC composes it to U+00E9.
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, label: "é" }),
    ).toThrow("Unicode NFC");
    expect(() =>
      encodeCanonical(sampleSchema, { ...sample, label: "x".repeat(65) }),
    ).toThrow("byte bound");
    expect(() =>
      encodeCanonical(sampleSchema, {
        ...sample,
        payload: new Uint8Array(129),
      }),
    ).toThrow("byte bound");
  });

  test("rejects trailing bytes and truncation on decode", () => {
    const encoded = encodeCanonical(sampleSchema, sample);
    const extended = new Uint8Array(encoded.length + 1);
    extended.set(encoded);
    expect(() => decodeCanonical(sampleSchema, extended)).toThrow(
      "trailing bytes",
    );
    expect(() =>
      decodeCanonical(sampleSchema, encoded.subarray(0, encoded.length - 1)),
    ).toThrow("truncated");
  });

  test("rejects unregistered enum bytes and non-boolean bytes on decode", () => {
    const encoded = encodeCanonical(sampleSchema, sample);
    const colourOffset = 1 + 4 + 8 + 1;
    const badEnum = Uint8Array.from(encoded);
    badEnum[colourOffset] = 9;
    expect(() => decodeCanonical(sampleSchema, badEnum)).toThrow(
      "not a member of Colour",
    );

    const badBool = Uint8Array.from(encoded);
    badBool[1 + 4 + 8] = 2;
    expect(() => decodeCanonical(sampleSchema, badBool)).toThrow(
      "exactly 0x00 or 0x01",
    );
  });

  test("rejects an unsorted collection carried in already-encoded bytes", () => {
    const listSchema = record("List", [
      { name: "items", type: array(leafSchema, 8) },
    ]);
    const good = encodeCanonical(listSchema, {
      items: [sample.leaves[0], sample.leaves[1]],
    });
    // Swap the two fixed-width leaf encodings in place: each leaf is 2 + 32
    // bytes and the count prefix is 2 bytes.
    const swapped = Uint8Array.from(good);
    const leafBytes = 34;
    swapped.set(good.subarray(2 + leafBytes, 2 + 2 * leafBytes), 2);
    swapped.set(good.subarray(2, 2 + leafBytes), 2 + leafBytes);
    expect(() => decodeCanonical(listSchema, swapped)).toThrow(
      "sorted by its complete canonical key",
    );
  });
});

describe("closed unions", () => {
  const shapeSchema = union("Shape", "kind", [
    {
      tag: "circle",
      type: record("Circle", [
        { name: "kind", type: enumOf("CircleKind", ["circle"]) },
        { name: "radius", type: u16 },
      ]),
    },
    {
      tag: "square",
      type: record("Square", [
        { name: "kind", type: enumOf("SquareKind", ["square"]) },
        { name: "side", type: u16 },
      ]),
    },
  ]);

  test("tags variants by declaration order and round-trips", () => {
    const circle = encodeCanonical(shapeSchema, { kind: "circle", radius: 3 });
    expect(circle[0]).toBe(0);
    const square = encodeCanonical(shapeSchema, { kind: "square", side: 4 });
    expect(square[0]).toBe(1);
    expect(decodeCanonical(shapeSchema, square)).toEqual({
      kind: "square",
      side: 4,
    });
  });

  test("rejects unknown variants and out-of-range tag bytes", () => {
    expect(() =>
      encodeCanonical(shapeSchema, { kind: "triangle", side: 4 }),
    ).toThrow('has no Shape variant "triangle"');

    const encoded = encodeCanonical(shapeSchema, { kind: "circle", radius: 3 });
    const badTag = Uint8Array.from(encoded);
    badTag[0] = 7;
    expect(() => decodeCanonical(shapeSchema, badTag)).toThrow(
      "not a registered Shape variant",
    );
  });
});

describe("strict decoding proves uniqueness", () => {
  test("accepts the canonical encoding of a value", () => {
    const encoded = encodeCanonical(sampleSchema, sample);
    expect(decodeCanonicalStrict(sampleSchema, encoded)).toEqual(sample);
  });

  test("field-name projection is generated from the descriptor", () => {
    expect(recordFieldNames(sampleSchema)).toEqual([
      "version",
      "count",
      "window",
      "enabled",
      "colour",
      "label",
      "payload",
      "parent",
      "leaves",
    ]);
    expect(() => recordFieldNames(colourSchema)).toThrow(
      "is not a record descriptor",
    );
  });
});
