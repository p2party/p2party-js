import { describe, expect, test } from "bun:test";

import { classifyFrame } from "./frameType";
import {
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
  WIRE_RECEIPT_FRAME_LEN,
} from "../utils/constants";

describe("classifyFrame", () => {
  test("reads the leading tag and strips it from the payload", () => {
    const frame = new Uint8Array([FRAME_TYPE_CHUNK, 9, 8, 7]);
    const { type, payload } = classifyFrame(frame);
    expect(type).toBe(FRAME_TYPE_CHUNK);
    expect([...payload]).toEqual([9, 8, 7]);
  });

  test("distinguishes handshake / receipt tags", () => {
    expect(classifyFrame(new Uint8Array([FRAME_TYPE_HANDSHAKE])).type).toBe(
      FRAME_TYPE_HANDSHAKE,
    );
    const receipt = new Uint8Array(WIRE_RECEIPT_FRAME_LEN);
    receipt[0] = FRAME_TYPE_RECEIPT;
    expect(classifyFrame(receipt).type).toBe(FRAME_TYPE_RECEIPT);
    expect(classifyFrame(receipt).payload).toHaveLength(64);
  });

  test("rejects an untagged legacy 64-byte receipt", () => {
    const raw = new Uint8Array(64);
    raw[0] = FRAME_TYPE_RECEIPT;
    expect(classifyFrame(raw).type).toBe(-1);
    expect(classifyFrame(raw).payload).toHaveLength(0);
  });

  test("payload is a zero-copy view over the same buffer", () => {
    const frame = new Uint8Array([FRAME_TYPE_CHUNK, 42]);
    const { payload } = classifyFrame(frame);
    frame[1] = 99;
    expect(payload[0]).toBe(99);
  });

  test("an empty frame classifies as type -1", () => {
    expect(classifyFrame(new Uint8Array(0)).type).toBe(-1);
  });
});
