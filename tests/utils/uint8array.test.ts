import { describe, expect, test } from "bun:test";

import { hexToUint8Array } from "../../src/utils/uint8array";

describe("hexToUint8Array", () => {
  test("decodes ordinary and 0x-prefixed hex", () => {
    expect(hexToUint8Array("00aaff")).toEqual(
      new Uint8Array([0x00, 0xaa, 0xff]),
    );
    expect(hexToUint8Array("0xA5")).toEqual(new Uint8Array([0xa5]));
  });

  test("rejects punctuation instead of silently skipping it", () => {
    expect(() => hexToUint8Array("aa:bb")).toThrow("non-hex");
    expect(() => hexToUint8Array("aa-bb")).toThrow("non-hex");
    expect(() => hexToUint8Array("aa!bb")).toThrow("non-hex");
    expect(() => hexToUint8Array("")).toThrow("No hex");
  });
});
