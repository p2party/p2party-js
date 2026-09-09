import { describe, expect, test } from "bun:test";

import {
  CHACHA20POLY1305_MAX_PLAINTEXT_BYTES,
  CHACHA20POLY1305_MAX_WASM_BYTES,
  chacha20Poly1305Open,
  chacha20Poly1305Seal,
} from "../../src/cryptography/chacha20poly1305";
import { loadTestModule } from "../../src/cryptography/testModule";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const fromHex = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const module = await loadTestModule();

describe("ChaCha20-Poly1305-IETF adapter", () => {
  // RFC 8439, Section 2.8.2.
  const key = fromHex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  );
  const nonce = fromHex("070000004041424344454647");
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const plaintext = fromHex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
      "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069742e",
  );
  const expectedCiphertextAndTag = fromHex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
      "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060" +
      "0691",
  );

  test("matches the RFC 8439 ciphertext and tag byte-for-byte", () => {
    const sealed = chacha20Poly1305Seal(module, key, nonce, plaintext, aad);
    expectBytesEqual(sealed, expectedCiphertextAndTag);
    expectBytesEqual(
      chacha20Poly1305Open(module, key, nonce, sealed, aad)!,
      plaintext,
    );
  });

  test("round-trips empty plaintext and associated data", () => {
    const empty = new Uint8Array(0);
    const sealed = chacha20Poly1305Seal(module, key, nonce, empty, empty);

    expect(sealed).toHaveLength(16);
    const opened = chacha20Poly1305Open(module, key, nonce, sealed, empty);
    expect(opened).not.toBeNull();
    expect(opened).toHaveLength(0);
  });

  test("returns null for authentication failure and structurally short input", () => {
    const sealed = chacha20Poly1305Seal(module, key, nonce, plaintext, aad);
    sealed[sealed.length - 1] ^= 1;

    expect(chacha20Poly1305Open(module, key, nonce, sealed, aad)).toBeNull();
    expect(
      chacha20Poly1305Open(
        module,
        key,
        nonce,
        expectedCiphertextAndTag,
        Uint8Array.of(1),
      ),
    ).toBeNull();
    expect(
      chacha20Poly1305Open(module, key, nonce, new Uint8Array(15), aad),
    ).toBeNull();
  });
});

interface FreedAllocation {
  readonly pointer: number;
  readonly bytes: Uint8Array;
}

interface FakeChaChaModule {
  readonly module: LibCrypto;
  readonly allocations: Array<{ pointer: number; length: number }>;
  readonly freed: FreedAllocation[];
  readonly live: Map<number, number>;
  readonly encryptionInputs: Array<{
    key: Uint8Array;
    nonce: Uint8Array;
    plaintext: Uint8Array;
    associatedData: Uint8Array;
  }>;
  readonly decryptionInputs: Array<{
    key: Uint8Array;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    associatedData: Uint8Array;
  }>;
}

const makeFakeChaChaModule = (options?: {
  readonly failAllocationAt?: number;
  readonly growAllocationAt?: number;
  readonly encryptionResult?: number;
  readonly decryptionResult?: number;
  readonly throwOnEncryption?: boolean;
  readonly throwOnDecryption?: boolean;
}): FakeChaChaModule => {
  const wasmMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const allocations: Array<{ pointer: number; length: number }> = [];
  const freed: FreedAllocation[] = [];
  const live = new Map<number, number>();
  const encryptionInputs: FakeChaChaModule["encryptionInputs"] = [];
  const decryptionInputs: FakeChaChaModule["decryptionInputs"] = [];
  let allocationCount = 0;
  let nextPointer = 64;

  const view = (pointer: number, length: number): Uint8Array =>
    new Uint8Array(wasmMemory.buffer, pointer, length);

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
      view(pointer, length).fill(0xa5);
      return pointer;
    },
    _free(pointer: number): void {
      const length = live.get(pointer);
      if (length === undefined)
        throw new Error(`test double: invalid free at ${String(pointer)}`);
      freed.push({ pointer, bytes: Uint8Array.from(view(pointer, length)) });
      live.delete(pointer);
    },
    _encrypt_chachapoly_symmetric(
      outputPointer: number,
      plaintextPointer: number,
      plaintextLength: number,
      keyPointer: number,
      noncePointer: number,
      aadPointer: number,
      aadLength: number,
    ): number {
      encryptionInputs.push({
        key: Uint8Array.from(view(keyPointer, 32)),
        nonce: Uint8Array.from(view(noncePointer, 12)),
        plaintext: Uint8Array.from(view(plaintextPointer, plaintextLength)),
        associatedData: Uint8Array.from(view(aadPointer, aadLength)),
      });
      view(outputPointer, plaintextLength + 16).fill(0x71);
      if (options?.throwOnEncryption) throw new Error("fake encryption trap");
      return options?.encryptionResult ?? 0;
    },
    _decrypt_chachapoly_symmetric(
      outputPointer: number,
      ciphertextPointer: number,
      ciphertextLength: number,
      keyPointer: number,
      noncePointer: number,
      aadPointer: number,
      aadLength: number,
    ): number {
      decryptionInputs.push({
        key: Uint8Array.from(view(keyPointer, 32)),
        nonce: Uint8Array.from(view(noncePointer, 12)),
        ciphertext: Uint8Array.from(view(ciphertextPointer, ciphertextLength)),
        associatedData: Uint8Array.from(view(aadPointer, aadLength)),
      });
      view(outputPointer, Math.max(1, ciphertextLength - 16)).fill(0x52);
      if (options?.throwOnDecryption) throw new Error("fake decryption trap");
      return options?.decryptionResult ?? 0;
    },
  } as unknown as LibCrypto;

  return {
    module,
    allocations,
    freed,
    live,
    encryptionInputs,
    decryptionInputs,
  };
};

const expectAllZero = (bytes: Uint8Array): void => {
  expect(bytes.every((byte) => byte === 0)).toBe(true);
};

const freedBytesAt = (fake: FakeChaChaModule, pointer: number): Uint8Array => {
  const allocation = fake.freed.find((entry) => entry.pointer === pointer);
  if (allocation === undefined)
    throw new Error(`test double: pointer ${String(pointer)} was not freed`);
  return allocation.bytes;
};

const bytesWithSpoofedLength = (length: number): Uint8Array =>
  new Proxy(new Uint8Array(0), {
    get(target, property) {
      if (property === "length") return length;
      return Reflect.get(target, property, target) as unknown;
    },
  });

describe("ChaCha20-Poly1305 WASM ownership boundary", () => {
  const key = new Uint8Array(32).fill(0x31);
  const nonce = new Uint8Array(12).fill(0x42);
  const plaintext = Uint8Array.of(0x53, 0x54, 0x55);
  const aad = Uint8Array.of(0x64, 0x65);
  const ciphertext = new Uint8Array(plaintext.length + 16).fill(0x76);

  test("rejects wrong types, exact-size violations, and hostile wrappers before allocating", () => {
    const fake = makeFakeChaChaModule();

    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        "key" as unknown as Uint8Array,
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow("key must be a Uint8Array");
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        new Uint8Array(31),
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow("key must be exactly 32 bytes");
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        key,
        new Uint8Array(13),
        plaintext,
        aad,
      ),
    ).toThrow("nonce must be exactly 12 bytes");
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        "plaintext" as unknown as Uint8Array,
        aad,
      ),
    ).toThrow("plaintext must be a Uint8Array");
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        plaintext,
        {} as unknown as Uint8Array,
      ),
    ).toThrow("associatedData must be a Uint8Array");
    expect(() =>
      chacha20Poly1305Open(
        fake.module,
        key,
        nonce,
        "ciphertext" as unknown as Uint8Array,
        aad,
      ),
    ).toThrow("ciphertextAndTag must be a Uint8Array");
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        bytesWithSpoofedLength(CHACHA20POLY1305_MAX_PLAINTEXT_BYTES + 1),
        aad,
      ),
    ).toThrow(TypeError);
    expect(() =>
      chacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        plaintext,
        bytesWithSpoofedLength(CHACHA20POLY1305_MAX_WASM_BYTES + 1),
      ),
    ).toThrow(TypeError);
    expect(() =>
      chacha20Poly1305Open(
        fake.module,
        key,
        nonce,
        bytesWithSpoofedLength(CHACHA20POLY1305_MAX_WASM_BYTES + 1),
        aad,
      ),
    ).toThrow(TypeError);

    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("snapshots all seal and open inputs before malloc grows WASM memory", () => {
    const sealFake = makeFakeChaChaModule({ growAllocationAt: 1 });
    const sealBuffer = sealFake.module.wasmMemory.buffer;
    const sealKey = new Uint8Array(sealBuffer, 40_000, 32);
    const sealNonce = new Uint8Array(sealBuffer, 40_040, 12);
    const sealPlaintext = new Uint8Array(sealBuffer, 40_100, 3);
    const sealAad = new Uint8Array(sealBuffer, 40_200, 2);
    sealKey.fill(0x31);
    sealNonce.fill(0x42);
    sealPlaintext.fill(0x53);
    sealAad.fill(0x64);
    const expectedSealInputs = {
      key: Uint8Array.from(sealKey),
      nonce: Uint8Array.from(sealNonce),
      plaintext: Uint8Array.from(sealPlaintext),
      associatedData: Uint8Array.from(sealAad),
    };

    const sealed = chacha20Poly1305Seal(
      sealFake.module,
      sealKey,
      sealNonce,
      sealPlaintext,
      sealAad,
    );
    expect(sealFake.module.wasmMemory.buffer).not.toBe(sealBuffer);
    expect(sealFake.encryptionInputs).toEqual([expectedSealInputs]);
    expect(sealed).toEqual(new Uint8Array(19).fill(0x71));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[3].pointer));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[4].pointer));
    expect(sealFake.live.size).toBe(0);

    const openFake = makeFakeChaChaModule({ growAllocationAt: 1 });
    const openBuffer = openFake.module.wasmMemory.buffer;
    const openKey = new Uint8Array(openBuffer, 40_000, 32);
    const openNonce = new Uint8Array(openBuffer, 40_040, 12);
    const openCiphertext = new Uint8Array(openBuffer, 40_100, 19);
    const openAad = new Uint8Array(openBuffer, 40_200, 2);
    openKey.fill(0x31);
    openNonce.fill(0x42);
    openCiphertext.fill(0x76);
    openAad.fill(0x64);
    const expectedOpenInputs = {
      key: Uint8Array.from(openKey),
      nonce: Uint8Array.from(openNonce),
      ciphertext: Uint8Array.from(openCiphertext),
      associatedData: Uint8Array.from(openAad),
    };

    const opened = chacha20Poly1305Open(
      openFake.module,
      openKey,
      openNonce,
      openCiphertext,
      openAad,
    );
    expect(openFake.module.wasmMemory.buffer).not.toBe(openBuffer);
    expect(openFake.decryptionInputs).toEqual([expectedOpenInputs]);
    expect(opened).toEqual(new Uint8Array(3).fill(0x52));
    expectAllZero(freedBytesAt(openFake, openFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(openFake, openFake.allocations[4].pointer));
    expect(openFake.live.size).toBe(0);
  });

  test("cleans every prior allocation when the last malloc fails", () => {
    const sealFake = makeFakeChaChaModule({ failAllocationAt: 5 });
    expect(() =>
      chacha20Poly1305Seal(sealFake.module, key, nonce, plaintext, aad),
    ).toThrow("failed to allocate ciphertext");
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[3].pointer));
    expect(sealFake.live.size).toBe(0);

    const openFake = makeFakeChaChaModule({ failAllocationAt: 5 });
    expect(() =>
      chacha20Poly1305Open(openFake.module, key, nonce, ciphertext, aad),
    ).toThrow("failed to allocate plaintext");
    expectAllZero(freedBytesAt(openFake, openFake.allocations[0].pointer));
    expect(openFake.live.size).toBe(0);
  });

  test("zero-frees secret scratch on primitive rejection and traps", () => {
    const sealFake = makeFakeChaChaModule({ encryptionResult: -7 });
    expect(() =>
      chacha20Poly1305Seal(sealFake.module, key, nonce, plaintext, aad),
    ).toThrow("encryption failed");
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[3].pointer));
    expectAllZero(freedBytesAt(sealFake, sealFake.allocations[4].pointer));
    expect(sealFake.live.size).toBe(0);

    const rejectedFake = makeFakeChaChaModule({ decryptionResult: -1 });
    expect(
      chacha20Poly1305Open(rejectedFake.module, key, nonce, ciphertext, aad),
    ).toBeNull();
    expectAllZero(
      freedBytesAt(rejectedFake, rejectedFake.allocations[0].pointer),
    );
    expectAllZero(
      freedBytesAt(rejectedFake, rejectedFake.allocations[4].pointer),
    );
    expect(rejectedFake.live.size).toBe(0);

    const trappedFake = makeFakeChaChaModule({ throwOnDecryption: true });
    expect(() =>
      chacha20Poly1305Open(trappedFake.module, key, nonce, ciphertext, aad),
    ).toThrow("fake decryption trap");
    expectAllZero(
      freedBytesAt(trappedFake, trappedFake.allocations[0].pointer),
    );
    expectAllZero(
      freedBytesAt(trappedFake, trappedFake.allocations[4].pointer),
    );
    expect(trappedFake.live.size).toBe(0);
  });
});
