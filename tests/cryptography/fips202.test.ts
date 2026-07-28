import { describe, expect, test } from "bun:test";

import {
  FIPS202_MAX_BUFFER_BYTES,
  sha3_256,
  shake256,
} from "../../src/cryptography/fips202";
import { loadTestModule } from "../../src/cryptography/testModule";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

interface FreedAllocation {
  readonly pointer: number;
  readonly bytes: Uint8Array;
}

interface FakeFips202Module {
  readonly module: LibCrypto;
  readonly allocations: Array<{ pointer: number; length: number }>;
  readonly calls: Array<{
    primitive: "SHA3-256" | "SHAKE256";
    input: Uint8Array;
    outputLength: number;
  }>;
  readonly freed: FreedAllocation[];
  readonly live: Map<number, number>;
}

const makeFakeFips202Module = (options?: {
  readonly failAllocationAt?: number;
  readonly growAllocationAt?: number;
  readonly primitiveResult?: number;
}): FakeFips202Module => {
  const wasmMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const allocations: Array<{ pointer: number; length: number }> = [];
  const calls: FakeFips202Module["calls"] = [];
  const freed: FreedAllocation[] = [];
  const live = new Map<number, number>();
  let allocationCount = 0;
  let nextPointer = 64;

  const allocate = (length: number): number => {
    allocationCount += 1;
    if (allocationCount === options?.failAllocationAt) return 0;
    if (allocationCount === options?.growAllocationAt) wasmMemory.grow(1);

    const pointer = nextPointer;
    nextPointer += length + 16;
    allocations.push({ pointer, length });
    live.set(pointer, length);
    new Uint8Array(wasmMemory.buffer, pointer, length).fill(0xa5);
    return pointer;
  };

  const free = (pointer: number): void => {
    const length = live.get(pointer);
    if (length === undefined)
      throw new Error(`test double: invalid free at ${String(pointer)}`);
    freed.push({
      pointer,
      bytes: Uint8Array.from(
        new Uint8Array(wasmMemory.buffer, pointer, length),
      ),
    });
    live.delete(pointer);
  };

  const module = {
    wasmMemory,
    _malloc: allocate,
    _free: free,
    _fips202_shake256(
      outputPointer: number,
      outputLength: number,
      inputPointer: number,
      inputLength: number,
    ): number {
      calls.push({
        primitive: "SHAKE256",
        input: Uint8Array.from(
          new Uint8Array(wasmMemory.buffer, inputPointer, inputLength),
        ),
        outputLength,
      });
      new Uint8Array(wasmMemory.buffer, outputPointer, outputLength).fill(0x42);
      return options?.primitiveResult ?? 0;
    },
    _fips202_sha3_256(
      outputPointer: number,
      inputPointer: number,
      inputLength: number,
    ): number {
      calls.push({
        primitive: "SHA3-256",
        input: Uint8Array.from(
          new Uint8Array(wasmMemory.buffer, inputPointer, inputLength),
        ),
        outputLength: 32,
      });
      new Uint8Array(wasmMemory.buffer, outputPointer, 32).fill(0x24);
      return options?.primitiveResult ?? 0;
    },
  } as unknown as LibCrypto;

  return { module, allocations, calls, freed, live };
};

const expectAllZero = (bytes: Uint8Array): void => {
  expect(bytes.every((byte) => byte === 0)).toBe(true);
};

describe("FIPS 202 WASM boundary", () => {
  test("matches the FIPS 202 empty-message SHA3-256 vector", async () => {
    const module = await loadTestModule();

    expect(
      Buffer.from(sha3_256(new Uint8Array(), module)).toString("hex"),
    ).toBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  });

  test("matches the FIPS 202 empty-message SHAKE256 vector", async () => {
    const module = await loadTestModule();

    expect(
      Buffer.from(shake256(new Uint8Array(), 64, module)).toString("hex"),
    ).toBe(
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    );
  });

  test("raw ABI rejects null, signed-length, proof-bound, and overlap violations", async () => {
    const module = await loadTestModule();
    const pointer = module._malloc(64);
    expect(pointer).not.toBe(0);

    try {
      expect(module._fips202_sha3_256(0, pointer + 32, 0)).toBe(-1);
      expect(module._fips202_sha3_256(pointer, pointer + 32, -1)).toBe(-1);
      expect(
        module._fips202_sha3_256(
          pointer,
          pointer + 32,
          FIPS202_MAX_BUFFER_BYTES + 1,
        ),
      ).toBe(-1);
      expect(module._fips202_sha3_256(pointer, pointer, 32)).toBe(-1);
      expect(module._fips202_shake256(pointer, -1, pointer + 32, 0)).toBe(-1);
      expect(module._fips202_shake256(pointer, 0, pointer + 32, -1)).toBe(-1);
      expect(
        module._fips202_shake256(
          pointer,
          FIPS202_MAX_BUFFER_BYTES + 1,
          pointer + 32,
          0,
        ),
      ).toBe(-1);
      expect(module._fips202_shake256(pointer, 32, pointer, 32)).toBe(-1);
    } finally {
      new Uint8Array(module.wasmMemory.buffer, pointer, 64).fill(0);
      module._free(pointer);
    }
  });

  test("supports an empty SHAKE256 output without passing null to C", () => {
    const fake = makeFakeFips202Module();

    expect(shake256(new Uint8Array(), 0, fake.module)).toEqual(
      new Uint8Array(),
    );
    expect(fake.allocations.map(({ length }) => length)).toEqual([1, 1]);
    expect(fake.calls).toEqual([
      {
        primitive: "SHAKE256",
        input: new Uint8Array(),
        outputLength: 0,
      },
    ]);
    expect(fake.freed).toHaveLength(2);
    expectAllZero(fake.freed[0].bytes);
    expectAllZero(fake.freed[1].bytes);
    expect(fake.live.size).toBe(0);
  });

  test("rejects invalid types and lengths before allocating", () => {
    const fake = makeFakeFips202Module();
    const exact = new Uint8Array();

    expect(() =>
      shake256("not bytes" as unknown as Uint8Array, 32, fake.module),
    ).toThrow("input must be a Uint8Array");
    expect(() =>
      shake256(new Uint8Array(FIPS202_MAX_BUFFER_BYTES + 1), 32, fake.module),
    ).toThrow("input exceeds the FIPS 202 one-shot limit");
    expect(() => shake256(exact, -1, fake.module)).toThrow(
      "outputLength exceeds the FIPS 202 one-shot limit",
    );
    expect(() =>
      shake256(exact, FIPS202_MAX_BUFFER_BYTES + 1, fake.module),
    ).toThrow("outputLength exceeds the FIPS 202 one-shot limit");
    expect(() => shake256(exact, 1.5, fake.module)).toThrow(
      "outputLength must be a safe integer",
    );
    expect(() => shake256(exact, Number.NaN, fake.module)).toThrow(
      "outputLength must be a safe integer",
    );

    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("rejects proxied byte inputs before allocating", () => {
    const fake = makeFakeFips202Module();
    const proxied = new Proxy(Uint8Array.of(1, 2, 3), {
      get(): never {
        throw new Error("hostile proxy surface must not run");
      },
    });

    expect(proxied).toBeInstanceOf(Uint8Array);
    expect(() => sha3_256(proxied, fake.module)).toThrow(
      "input must be a Uint8Array",
    );
    expect(fake.allocations).toHaveLength(0);
  });

  test("hashes intrinsic bytes despite shadowed length and iteration", () => {
    const fake = makeFakeFips202Module();
    const input = Uint8Array.of(1, 2, 3);
    Object.defineProperty(input, "length", { value: 0 });
    Object.defineProperty(input, Symbol.iterator, {
      value: (): never => {
        throw new Error("hostile iterator must not run");
      },
    });

    expect(shake256(input, 4, fake.module)).toEqual(
      new Uint8Array(4).fill(0x42),
    );
    expect(fake.calls).toEqual([
      {
        primitive: "SHAKE256",
        input: Uint8Array.of(1, 2, 3),
        outputLength: 4,
      },
    ]);
    expect(fake.allocations.map(({ length }) => length)).toEqual([4, 3]);
    expect(fake.live.size).toBe(0);
  });

  test("snapshots a WASM-backed input before malloc grows memory", () => {
    const fake = makeFakeFips202Module({ growAllocationAt: 1 });
    const originalBuffer = fake.module.wasmMemory.buffer;
    const input = new Uint8Array(originalBuffer, 2048, 32);
    input.fill(0x71);

    expect(shake256(input, 48, fake.module)).toEqual(
      new Uint8Array(48).fill(0x42),
    );
    expect(fake.module.wasmMemory.buffer).not.toBe(originalBuffer);
    expect(fake.calls).toEqual([
      {
        primitive: "SHAKE256",
        input: new Uint8Array(32).fill(0x71),
        outputLength: 48,
      },
    ]);
    expect(fake.freed).toHaveLength(2);
    expectAllZero(fake.freed[0].bytes);
    expectAllZero(fake.freed[1].bytes);
    expect(fake.live.size).toBe(0);
  });

  test("zero-frees every scratch allocation when the primitive rejects", () => {
    const fake = makeFakeFips202Module({ primitiveResult: -1 });

    expect(() => sha3_256(new Uint8Array([1, 2, 3]), fake.module)).toThrow(
      "SHA3-256 failed",
    );
    expect(fake.freed).toHaveLength(2);
    expectAllZero(fake.freed[0].bytes);
    expectAllZero(fake.freed[1].bytes);
    expect(fake.live.size).toBe(0);
  });

  test("zero-frees the first allocation when the second malloc fails", () => {
    const fake = makeFakeFips202Module({ failAllocationAt: 2 });

    expect(() => shake256(new Uint8Array([1]), 32, fake.module)).toThrow(
      "SHAKE256 failed (allocation)",
    );
    expect(fake.allocations).toHaveLength(1);
    expect(fake.freed).toHaveLength(1);
    expectAllZero(fake.freed[0].bytes);
    expect(fake.live.size).toBe(0);
  });
});
