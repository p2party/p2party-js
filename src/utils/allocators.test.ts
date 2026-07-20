import { describe, expect, test } from "bun:test";

import { allocateSendMessage } from "./allocators";

import type { LibCrypto } from "../cryptography/libcrypto";

// Minimal fake of the WASM module: a bump allocator over a real ArrayBuffer,
// recording frees so leaks are observable.
const fakeModule = (bytes = 1 << 20) => {
  const buffer = new ArrayBuffer(bytes);
  let offset = 8;
  const malloced: number[] = [];
  const freed: number[] = [];
  return {
    wasmMemory: { buffer } as WebAssembly.Memory,
    _malloc: (n: number) => {
      const p = offset;
      offset += n;
      malloced.push(p);
      return p;
    },
    _free: (p: number) => {
      freed.push(p);
    },
    malloced,
    freed,
  } as unknown as LibCrypto & { malloced: number[]; freed: number[] };
};

describe("allocateSendMessage", () => {
  test("exposes a typed-array view for every pointer it allocates (no orphans)", () => {
    const mod = fakeModule();
    const alloc = allocateSendMessage(mod);

    const pointers = Object.entries(alloc)
      .filter(([k]) => /^ptr\d+$/.test(k))
      .map(([, v]) => v as number);

    const viewOffsets = new Set<number>();
    for (const v of Object.values(alloc)) {
      if (v instanceof Uint8Array) viewOffsets.add(v.byteOffset);
    }

    for (const p of pointers) {
      expect(viewOffsets.has(p)).toBe(true);
    }
  });
});
