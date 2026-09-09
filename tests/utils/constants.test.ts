import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  FRAME_TYPE_LEN,
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
  FRAME_TYPE_COVER,
  FRAME_TYPE_PQ_CONTROL,
  PQ_TAG_LEN,
  PQ_TAG,
  PROTOCOL_VERSION,
  PQ_EPOCH_LEN,
  MESSAGE_START,
  DECRYPTED_LEN,
  CHUNK_LEN,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";

const h = readFileSync(
  new URL("../../src/cryptography/utils.h", import.meta.url),
  "utf8",
);
const cDefine = (name: string): number => {
  const m = h.match(new RegExp(`#define\\s+${name}\\s+(\\d+)`));
  if (!m) throw new Error(`#define ${name} not found in utils.h`);
  return Number(m[1]);
};

describe("protocol-v4 wire constants (C == TS)", () => {
  test("the 1-byte frame tags byte-match the C side", () => {
    expect(cDefine("PROTOCOL_VERSION")).toBe(PROTOCOL_VERSION);
    expect(cDefine("FRAME_TYPE_LEN")).toBe(FRAME_TYPE_LEN);
    expect(cDefine("FRAME_TYPE_HANDSHAKE")).toBe(FRAME_TYPE_HANDSHAKE);
    expect(cDefine("FRAME_TYPE_CHUNK")).toBe(FRAME_TYPE_CHUNK);
    expect(cDefine("FRAME_TYPE_RECEIPT")).toBe(FRAME_TYPE_RECEIPT);
    expect(cDefine("FRAME_TYPE_COVER")).toBe(FRAME_TYPE_COVER);
    expect(cDefine("FRAME_TYPE_PQ_CONTROL")).toBe(FRAME_TYPE_PQ_CONTROL);
    expect(cDefine("PQ_TAG_LEN")).toBe(PQ_TAG_LEN);
    expect(cDefine("PQ_EPOCH_LEN")).toBe(PQ_EPOCH_LEN);
    expect(cDefine("CHUNK_PLAINTEXT_LEN")).toBe(DECRYPTED_LEN);
    expect(cDefine("WIRE_CHUNK_FRAME_LEN")).toBe(WIRE_CHUNK_FRAME_LEN);
  });

  test("the frame tags are distinct and PQ_TAG selects the hybrid bootstrap", () => {
    const tags = [
      FRAME_TYPE_HANDSHAKE,
      FRAME_TYPE_CHUNK,
      FRAME_TYPE_RECEIPT,
      FRAME_TYPE_COVER,
      FRAME_TYPE_PQ_CONTROL,
    ];
    expect(new Set(tags).size).toBe(5);
    expect(PQ_TAG.length).toBe(PQ_TAG_LEN);
    expect([...PQ_TAG]).toEqual([1]);
  });

  test("the wider epoch consumes plaintext padding, not outer-cell bytes", () => {
    expect(PROTOCOL_VERSION).toBe(4);
    expect(PQ_EPOCH_LEN).toBe(8);
    expect(MESSAGE_START).toBe(69);
    expect(DECRYPTED_LEN).toBe(65_405);
    expect(CHUNK_LEN).toBe(61_912);
    expect(WIRE_CHUNK_FRAME_LEN).toBe(65_490);
  });
});
