import { describe, expect, test } from "bun:test";

import { fillRandomBytesInto } from "../../src/cryptography/random";

describe("fillRandomBytesInto", () => {
  test("never gives WebCrypto the WebAssembly-backed destination", () => {
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 1 });
    const destination = new Uint8Array(memory.buffer, 32, 32);
    let capturedTemporary: Uint8Array | undefined;

    fillRandomBytesInto(destination, (temporary) => {
      // Model Chromium 147/149's rejected BufferSource boundary.
      if (temporary.buffer === memory.buffer)
        throw new DOMException(
          "Resizable WebAssembly buffers are not accepted",
          "TypeError",
        );
      capturedTemporary = temporary;
      temporary.fill(0xa5);
    });

    expect(capturedTemporary).toBeDefined();
    expect(capturedTemporary?.buffer).not.toBe(memory.buffer);
    expect(destination.every((byte) => byte === 0xa5)).toBe(true);
    expect(capturedTemporary?.every((byte) => byte === 0)).toBe(true);
  });

  test("wipes the fixed-buffer temporary when entropy generation throws", () => {
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 1 });
    const destination = new Uint8Array(memory.buffer, 64, 32).fill(0x3c);
    let capturedTemporary: Uint8Array | undefined;

    expect(() =>
      fillRandomBytesInto(destination, (temporary) => {
        capturedTemporary = temporary;
        temporary.fill(0x7e);
        throw new DOMException("entropy source failed", "OperationError");
      }),
    ).toThrow("entropy source failed");

    expect(destination.every((byte) => byte === 0x3c)).toBe(true);
    expect(capturedTemporary?.every((byte) => byte === 0)).toBe(true);
  });
});
