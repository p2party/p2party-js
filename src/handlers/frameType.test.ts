import { describe, expect, test } from "bun:test";

import { classifyFrame } from "./frameType";
import {
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
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
    expect(classifyFrame(new Uint8Array([FRAME_TYPE_RECEIPT, 1])).type).toBe(
      FRAME_TYPE_RECEIPT,
    );
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
