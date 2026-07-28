import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  X25519RejectedPublicPointError,
  newX25519KeyPair,
  x25519Dh,
  x25519Keypair,
  x25519PublicFromSecret,
} from "../../src/cryptography/x25519";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

interface FreedAllocation {
  pointer: number;
  bytes: Uint8Array;
}

interface FakeX25519Module {
  module: LibCrypto;
  allocations: Array<{ pointer: number; length: number }>;
  dhInputs: Array<{ secretKey: Uint8Array; publicKey: Uint8Array }>;
  freed: FreedAllocation[];
  live: Map<number, number>;
}

const makeFakeX25519Module = (options?: {
  failAllocationAt?: number;
  growAllocationAt?: number;
  keypairResult?: number;
  dhResult?: number;
}): FakeX25519Module => {
  const wasmMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const allocations: Array<{ pointer: number; length: number }> = [];
  const dhInputs: Array<{
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  }> = [];
  const freed: FreedAllocation[] = [];
  const live = new Map<number, number>();
  let nextPointer = 64;
  let allocationCount = 0;

  const module = {
    wasmMemory,
    _malloc(length: number): number {
      allocationCount += 1;
      if (allocationCount === options?.failAllocationAt) return 0;
      if (allocationCount === options?.growAllocationAt) wasmMemory.grow(1);

      const pointer = nextPointer;
      nextPointer += length + 16;
      allocations.push({ pointer, length });
      live.set(pointer, length);
      new Uint8Array(wasmMemory.buffer, pointer, length).fill(0xa5);
      return pointer;
    },
    _free(pointer: number): void {
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
    },
    _x25519_keypair(
      publicKeyPointer: number,
      secretKeyPointer: number,
    ): number {
      new Uint8Array(wasmMemory.buffer, publicKeyPointer, 32).fill(0x11);
      new Uint8Array(wasmMemory.buffer, secretKeyPointer, 32).fill(0x22);
      return options?.keypairResult ?? 0;
    },
    _x25519_dh(
      sharedPointer: number,
      secretKeyPointer: number,
      publicKeyPointer: number,
    ): number {
      dhInputs.push({
        secretKey: Uint8Array.from(
          new Uint8Array(wasmMemory.buffer, secretKeyPointer, 32),
        ),
        publicKey: Uint8Array.from(
          new Uint8Array(wasmMemory.buffer, publicKeyPointer, 32),
        ),
      });
      new Uint8Array(wasmMemory.buffer, sharedPointer, 32).fill(0x33);
      return options?.dhResult ?? 0;
    },
  } as unknown as LibCrypto;

  return { module, allocations, dhInputs, freed, live };
};

const expectAllZero = (bytes: Uint8Array): void => {
  expect(bytes.every((byte) => byte === 0)).toBe(true);
};

const freedBytesAt = (fake: FakeX25519Module, pointer: number): Uint8Array => {
  const allocation = fake.freed.find((entry) => entry.pointer === pointer);
  if (allocation === undefined)
    throw new Error(`test double: pointer ${String(pointer)} was not freed`);
  return allocation.bytes;
};

describe("x25519", () => {
  test("keypair produces 32-byte keys and DH agrees both ways", async () => {
    const module = await loadTestModule();

    const a = x25519Keypair(module);
    const b = x25519Keypair(module);

    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(32);

    const sa = x25519Dh(a.secretKey, b.publicKey, module);
    const sb = x25519Dh(b.secretKey, a.publicKey, module);

    expect(sa.length).toBe(32);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });

  test("newX25519KeyPair(module) mints a valid, random 32/32 identity pair usable for DH", async () => {
    const module = await loadTestModule();

    const a = await newX25519KeyPair(module);
    const b = x25519Keypair(module);

    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(32);

    // two calls produce distinct random keys (not a fixed/zero key)
    const a2 = await newX25519KeyPair(module);
    expect(Buffer.from(a.secretKey)).not.toEqual(Buffer.from(a2.secretKey));

    // the minted identity key does real DH, agreeing with a peer both ways
    const sa = x25519Dh(a.secretKey, b.publicKey, module);
    const sb = x25519Dh(b.secretKey, a.publicKey, module);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });

  test("derives the RFC 7748 Alice public key from her private scalar", async () => {
    // RFC 7748, Section 6.1.
    const secretKey = hexToBytes(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    const expectedPublicKey = hexToBytes(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    const module = await loadTestModule();

    expect(x25519PublicFromSecret(secretKey, module)).toEqual(
      expectedPublicKey,
    );
  });

  test("rejects wrong-type and non-exact DH inputs before allocating", () => {
    const fake = makeFakeX25519Module();
    const exact = new Uint8Array(32);

    expect(() =>
      x25519Dh("not bytes" as unknown as Uint8Array, exact, fake.module),
    ).toThrow("secretKey must be a Uint8Array");
    expect(() => x25519Dh(new Uint8Array(31), exact, fake.module)).toThrow(
      "secretKey must be exactly 32 bytes",
    );
    expect(() =>
      x25519Dh(exact, {} as unknown as Uint8Array, fake.module),
    ).toThrow("publicKey must be a Uint8Array");
    expect(() => x25519Dh(exact, new Uint8Array(31), fake.module)).toThrow(
      "publicKey must be exactly 32 bytes",
    );
    expect(() =>
      x25519PublicFromSecret(new Uint8Array(33), fake.module),
    ).toThrow("secretKey must be exactly 32 bytes");

    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("rejects proxied DH inputs before allocating", () => {
    const fake = makeFakeX25519Module();
    const exact = new Uint8Array(32);
    const proxied = (): Uint8Array =>
      new Proxy(new Uint8Array(32), {
        get(): never {
          throw new Error("hostile proxy surface must not run");
        },
      });

    expect(() => x25519Dh(proxied(), exact, fake.module)).toThrow(
      "secretKey must be a Uint8Array",
    );
    expect(() => x25519Dh(exact, proxied(), fake.module)).toThrow(
      "publicKey must be a Uint8Array",
    );
    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("uses intrinsic DH bytes despite shadowed length and iteration", () => {
    const shadow = (byte: number, claimedLength: number): Uint8Array => {
      const bytes = new Uint8Array(32).fill(byte);
      Object.defineProperty(bytes, "length", { value: claimedLength });
      Object.defineProperty(bytes, Symbol.iterator, {
        value: (): never => {
          throw new Error("hostile iterator must not run");
        },
      });
      return bytes;
    };
    const fake = makeFakeX25519Module();

    expect(x25519Dh(shadow(0x44, 0), shadow(0x55, 1_000), fake.module)).toEqual(
      new Uint8Array(32).fill(0x33),
    );
    expect(fake.dhInputs).toEqual([
      {
        secretKey: new Uint8Array(32).fill(0x44),
        publicKey: new Uint8Array(32).fill(0x55),
      },
    ]);
    expect(fake.allocations.map(({ length }) => length)).toEqual([32, 32, 32]);
    expect(fake.live.size).toBe(0);
  });

  test("snapshots wasm-backed inputs before malloc can grow their memory", () => {
    const fake = makeFakeX25519Module({ growAllocationAt: 1 });
    const originalBuffer = fake.module.wasmMemory.buffer;
    const secretKey = new Uint8Array(originalBuffer, 2048, 32);
    const publicKey = new Uint8Array(originalBuffer, 2080, 32);
    secretKey.fill(0x44);
    publicKey.fill(0x55);

    expect(x25519Dh(secretKey, publicKey, fake.module)).toEqual(
      new Uint8Array(32).fill(0x33),
    );
    expect(fake.module.wasmMemory.buffer).not.toBe(originalBuffer);
    expect(fake.dhInputs).toEqual([
      {
        secretKey: new Uint8Array(32).fill(0x44),
        publicKey: new Uint8Array(32).fill(0x55),
      },
    ]);
    expect(fake.freed).toHaveLength(3);
    expectAllZero(freedBytesAt(fake, fake.allocations[0].pointer));
    expectAllZero(freedBytesAt(fake, fake.allocations[1].pointer));
    expect(freedBytesAt(fake, fake.allocations[2].pointer)).toEqual(
      new Uint8Array(32).fill(0x55),
    );
    expect(fake.live.size).toBe(0);
  });

  test("keypair frees its first allocation when the second malloc fails", () => {
    const fake = makeFakeX25519Module({ failAllocationAt: 2 });

    expect(() => x25519Keypair(fake.module)).toThrow(
      "x25519_keypair failed (allocation)",
    );
    expect(fake.allocations).toHaveLength(1);
    expect(freedBytesAt(fake, fake.allocations[0].pointer)).toEqual(
      new Uint8Array(32).fill(0xa5),
    );
    expect(fake.live.size).toBe(0);
  });

  test("keypair zero-frees secret scratch when the primitive rejects", () => {
    const fake = makeFakeX25519Module({ keypairResult: -1 });

    expect(() => x25519Keypair(fake.module)).toThrow("x25519_keypair failed");
    expect(fake.freed).toHaveLength(2);
    expectAllZero(freedBytesAt(fake, fake.allocations[1].pointer));
    expect(freedBytesAt(fake, fake.allocations[0].pointer)).toEqual(
      new Uint8Array(32).fill(0x11),
    );
    expect(fake.live.size).toBe(0);
  });

  test("DH zero-frees secret scratch when a later malloc fails", () => {
    const fake = makeFakeX25519Module({ failAllocationAt: 3 });
    const secretKey = new Uint8Array(32).fill(0x44);
    const publicKey = new Uint8Array(32).fill(0x55);

    expect(() => x25519Dh(secretKey, publicKey, fake.module)).toThrow(
      "x25519_dh failed (allocation)",
    );
    expect(fake.allocations).toHaveLength(2);
    expect(fake.freed).toHaveLength(2);
    expectAllZero(freedBytesAt(fake, fake.allocations[0].pointer));
    expectAllZero(freedBytesAt(fake, fake.allocations[1].pointer));
    expect(fake.live.size).toBe(0);
  });

  test("DH zero-frees secret scratch and frees public input on rejection", () => {
    const fake = makeFakeX25519Module({ dhResult: -1 });

    expect(() =>
      x25519Dh(
        new Uint8Array(32).fill(0x44),
        new Uint8Array(32).fill(0x55),
        fake.module,
      ),
    ).toThrow(X25519RejectedPublicPointError);
    expect(fake.freed).toHaveLength(3);
    expectAllZero(freedBytesAt(fake, fake.allocations[0].pointer));
    expectAllZero(freedBytesAt(fake, fake.allocations[1].pointer));
    expect(freedBytesAt(fake, fake.allocations[2].pointer)).toEqual(
      new Uint8Array(32).fill(0x55),
    );
    expect(fake.live.size).toBe(0);
  });
});
