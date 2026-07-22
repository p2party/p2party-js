import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  FRAME_TYPE_LEN,
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
  PQ_TAG_LEN,
  PQ_TAG,
} from "./constants";

const h = readFileSync(new URL("../cryptography/utils.h", import.meta.url), "utf8");
const cDefine = (name: string): number => {
  const m = h.match(new RegExp(`#define\\s+${name}\\s+(\\d+)`));
  if (!m) throw new Error(`#define ${name} not found in utils.h`);
  return Number(m[1]);
};

describe("protocol-v3 frame-type constants (C == TS)", () => {
  test("the 1-byte frame tags byte-match the C side", () => {
    expect(cDefine("FRAME_TYPE_LEN")).toBe(FRAME_TYPE_LEN);
    expect(cDefine("FRAME_TYPE_HANDSHAKE")).toBe(FRAME_TYPE_HANDSHAKE);
    expect(cDefine("FRAME_TYPE_CHUNK")).toBe(FRAME_TYPE_CHUNK);
    expect(cDefine("FRAME_TYPE_RECEIPT")).toBe(FRAME_TYPE_RECEIPT);
    expect(cDefine("PQ_TAG_LEN")).toBe(PQ_TAG_LEN);
  });

  test("the tags are distinct and PQ_TAG is a zero byte", () => {
    const tags = [FRAME_TYPE_HANDSHAKE, FRAME_TYPE_CHUNK, FRAME_TYPE_RECEIPT];
    expect(new Set(tags).size).toBe(3);
    expect(PQ_TAG.length).toBe(PQ_TAG_LEN);
    expect([...PQ_TAG]).toEqual([0]);
  });
});
