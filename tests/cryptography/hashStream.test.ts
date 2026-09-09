import { describe, expect, test } from "bun:test";

import { hashFileStreaming } from "../../src/cryptography/hashStream";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const fakeHashModule = (onUpdate: () => void): LibCrypto => {
  let next = 16;
  return {
    wasmMemory: { buffer: new ArrayBuffer(256 * 1024) },
    _malloc: (length: number) => {
      const pointer = next;
      next += length;
      return pointer;
    },
    _free: () => undefined,
    _sha512_init: () => 0,
    _sha512_update: () => {
      onUpdate();
      return 0;
    },
    _sha512_final: () => 0,
  } as unknown as LibCrypto;
};

describe("streaming file hash cancellation", () => {
  test("checks the abort signal immediately after each disk slice", async () => {
    const controller = new AbortController();
    let updates = 0;
    const file = {
      size: 1,
      slice: () => ({
        arrayBuffer: async () => {
          controller.abort(new Error("cancel during slice"));
          return new ArrayBuffer(1);
        },
      }),
    } as unknown as File;

    await expect(
      hashFileStreaming(
        file,
        fakeHashModule(() => {
          updates++;
        }),
        controller.signal,
      ),
    ).rejects.toThrow("cancel during slice");
    expect(updates).toBe(0);
  });
});
