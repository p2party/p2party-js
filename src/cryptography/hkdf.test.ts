import { hkdfSync } from "node:crypto";

import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { hkdfExtract, hkdfExpand } from "./hkdf";

describe("hkdf-sha512", () => {
  test("extract zeroes salt, IKM, and PRK staging before freeing", async () => {
    const realModule = await loadTestModule();
    const allocations = new Map<number, number>();
    const zeroedAtFree: boolean[] = [];
    const module = new Proxy(realModule, {
      get(target, property, receiver) {
        if (property === "_malloc")
          return (length: number): number => {
            const pointer = target._malloc(length);
            allocations.set(pointer, length);
            return pointer;
          };
        if (property === "_free")
          return (pointer: number): void => {
            const length = allocations.get(pointer);
            if (length !== undefined) {
              const view = new Uint8Array(
                target.wasmMemory.buffer,
                pointer,
                length,
              );
              zeroedAtFree.push(view.every((byte) => byte === 0));
              allocations.delete(pointer);
            }
            target._free(pointer);
          };
        return Reflect.get(target, property, receiver);
      },
    });

    const prk = hkdfExtract(
      new Uint8Array(32).fill(0x71),
      new Uint8Array(64).fill(0x93),
      module,
    );

    expect(prk).toHaveLength(64);
    expect(zeroedAtFree).toEqual([true, true, true]);
    expect(allocations.size).toBe(0);
  });

  test("extract is deterministic and 64 bytes", async () => {
    const module = await loadTestModule();
    const salt = new Uint8Array(32).fill(7);
    const ikm = new Uint8Array(32).fill(9);

    const prk = hkdfExtract(salt, ikm, module);
    const prk2 = hkdfExtract(salt, ikm, module);

    expect(prk.length).toBe(64);
    expect(Buffer.from(prk)).toEqual(Buffer.from(prk2));
  });

  test("expand honours outLen and separates by info label", async () => {
    const module = await loadTestModule();
    const prk = hkdfExtract(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      module,
    );

    const enc = new TextEncoder();
    const o1 = hkdfExpand(prk, enc.encode("label-a"), 64, module);
    const o2 = hkdfExpand(prk, enc.encode("label-b"), 64, module);
    const o32 = hkdfExpand(prk, enc.encode("label-a"), 32, module);

    expect(o1.length).toBe(64);
    expect(o32.length).toBe(32);
    expect(Buffer.from(o1)).not.toEqual(Buffer.from(o2));
    // First 32 bytes of a 64-byte expand equal the 32-byte expand (HKDF T(1) prefix)
    expect(Buffer.from(o1.subarray(0, 32))).toEqual(Buffer.from(o32));
  });

  test("extract+expand matches node crypto.hkdfSync oracle (single block)", async () => {
    const module = await loadTestModule();
    const salt = new Uint8Array(32).fill(7);
    const ikm = new Uint8Array(32).fill(9);
    const info = new Uint8Array(0);

    const prk = hkdfExtract(salt, ikm, module);
    const okm = hkdfExpand(prk, info, 64, module);

    const oracle = Buffer.from(
      hkdfSync(
        "sha512",
        Buffer.from(ikm),
        Buffer.from(salt),
        Buffer.from(info),
        64,
      ),
    );

    expect(Buffer.from(okm)).toEqual(oracle);
  });

  test("extract+expand matches node crypto.hkdfSync oracle (multi-block, labeled info)", async () => {
    const module = await loadTestModule();
    const salt = new Uint8Array(32).fill(7);
    const ikm = new Uint8Array(32).fill(9);
    const info = new TextEncoder().encode("label-a");

    const prk = hkdfExtract(salt, ikm, module);
    // 100 bytes > 64-byte HMAC-SHA512 output, forcing a second HKDF-Expand block (T(2)).
    const okm = hkdfExpand(prk, info, 100, module);

    const oracle = Buffer.from(
      hkdfSync(
        "sha512",
        Buffer.from(ikm),
        Buffer.from(salt),
        Buffer.from(info),
        100,
      ),
    );

    expect(Buffer.from(okm)).toEqual(oracle);
  });
});
