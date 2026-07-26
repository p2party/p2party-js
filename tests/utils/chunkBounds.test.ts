import { describe, expect, test } from "bun:test";

import { isStorableChunkRange } from "../../src/utils/chunkBounds";

// CHUNK_LEN — the real-data region length inside a decrypted chunk.
const CHUNK_LENGTH = 61919;

describe("isStorableChunkRange", () => {
  test("accepts a normal real-data range", () => {
    expect(isStorableChunkRange(0, 100, CHUNK_LENGTH)).toBe(true);
  });

  test("accepts a range that ends exactly at the chunk length", () => {
    expect(isStorableChunkRange(6191, CHUNK_LENGTH, CHUNK_LENGTH)).toBe(true);
  });

  test("rejects an end index past the chunk length (attacker-controlled overrun)", () => {
    expect(isStorableChunkRange(5, 999_999, CHUNK_LENGTH)).toBe(false);
  });

  test("rejects a negative start index", () => {
    expect(isStorableChunkRange(-1, 10, CHUNK_LENGTH)).toBe(false);
  });

  test("rejects start > end", () => {
    expect(isStorableChunkRange(100, 50, CHUNK_LENGTH)).toBe(false);
  });

  test("rejects non-integer indices", () => {
    expect(isStorableChunkRange(0.5, 10, CHUNK_LENGTH)).toBe(false);
  });
});
