import { describe, expect, test } from "bun:test";

import { zeroFree } from "./zeroFree";

import type { LibCrypto } from "../cryptography/libcrypto";

describe("zeroFree", () => {
  test("zeroes the secret view before freeing its offset", () => {
    const buffer = new ArrayBuffer(64);
    const view = new Uint8Array(buffer, 8, 32);
    view.fill(0xff);

    const freed: number[] = [];
    const order: string[] = [];
    const module = {
      _free: (p: number) => {
        // The buffer must already be wiped by the time free is called.
        order.push(
          [...view].every((b) => b === 0) ? "zeroed-then-freed" : "freed-dirty",
        );
        freed.push(p);
      },
    } as unknown as LibCrypto;

    zeroFree(module, view);

    expect([...view].every((b) => b === 0)).toBe(true);
    expect(freed).toEqual([8]);
    expect(order).toEqual(["zeroed-then-freed"]);
  });
});
