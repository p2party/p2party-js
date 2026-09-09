import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  XCHACHA20POLY1305_MAX_PLAINTEXT_BYTES,
  XCHACHA20POLY1305_MAX_WASM_BYTES,
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
} from "../../src/cryptography/xchacha20poly1305";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const fromHex = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const module = await loadTestModule();

describe("XChaCha20-Poly1305-IETF adapter", () => {
  // Appendix A.3.1 of draft-irtf-cfrg-xchacha-03.
  const key = fromHex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  );
  const nonce = fromHex("404142434445464748494a4b4c4d4e4f5051525354555657");
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const plaintext = fromHex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
      "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069742e",
  );
  const expectedCiphertextAndTag = fromHex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
      "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
      "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
      "21f9664c97637da9768812f615c68b13b52e" +
      "c0875924c1c7987947deafd8780acf49",
  );

  test("matches the published ciphertext and tag byte-for-byte", () => {
    const sealed = xchacha20Poly1305Seal(module, key, nonce, plaintext, aad);
    expectBytesEqual(sealed, expectedCiphertextAndTag);
    expectBytesEqual(
      xchacha20Poly1305Open(module, key, nonce, sealed, aad)!,
      plaintext,
    );
  });

  test("round-trips empty input and fails closed on invalid authentication", () => {
    const empty = new Uint8Array(0);
    const emptySealed = xchacha20Poly1305Seal(module, key, nonce, empty, empty);
    expect(emptySealed).toHaveLength(16);
    expect(
      xchacha20Poly1305Open(module, key, nonce, emptySealed, empty),
    ).toEqual(empty);

    const tampered = Uint8Array.from(expectedCiphertextAndTag);
    tampered[tampered.length - 1] ^= 1;
    expect(xchacha20Poly1305Open(module, key, nonce, tampered, aad)).toBeNull();
    expect(
      xchacha20Poly1305Open(
        module,
        key,
        nonce,
        expectedCiphertextAndTag,
        Uint8Array.of(1),
      ),
    ).toBeNull();
    expect(
      xchacha20Poly1305Open(module, key, nonce, new Uint8Array(15), aad),
    ).toBeNull();
  });
});

interface FreedAllocation {
  readonly pointer: number;
  readonly bytes: Uint8Array;
}

interface FakeXChaChaModule {
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

const makeFakeXChaChaModule = (options?: {
  readonly failAllocationAt?: number;
  readonly growAllocationAt?: number;
  readonly encryptionResult?: number;
  readonly decryptionResult?: number;
  readonly growOnEncryption?: boolean;
  readonly growOnDecryption?: boolean;
  readonly throwOnEncryption?: boolean;
  readonly throwOnDecryption?: boolean;
}): FakeXChaChaModule => {
  const wasmMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const allocations: Array<{ pointer: number; length: number }> = [];
  const freed: FreedAllocation[] = [];
  const live = new Map<number, number>();
  const encryptionInputs: FakeXChaChaModule["encryptionInputs"] = [];
  const decryptionInputs: FakeXChaChaModule["decryptionInputs"] = [];
  let allocationCount = 0;
  let nextPointer = 64;

  const view = (pointer: number, length: number): Uint8Array =>
    new Uint8Array(wasmMemory.buffer, pointer, length);

  const fakeModule = {
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
    _carrier_aead_xchacha20poly1305_encrypt(
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
        nonce: Uint8Array.from(view(noncePointer, 24)),
        plaintext: Uint8Array.from(view(plaintextPointer, plaintextLength)),
        associatedData: Uint8Array.from(view(aadPointer, aadLength)),
      });
      if (options?.growOnEncryption) wasmMemory.grow(1);
      view(outputPointer, plaintextLength + 16).fill(0x71);
      if (options?.throwOnEncryption) throw new Error("fake encryption trap");
      return options?.encryptionResult ?? 0;
    },
    _carrier_aead_xchacha20poly1305_decrypt(
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
        nonce: Uint8Array.from(view(noncePointer, 24)),
        ciphertext: Uint8Array.from(view(ciphertextPointer, ciphertextLength)),
        associatedData: Uint8Array.from(view(aadPointer, aadLength)),
      });
      if (options?.growOnDecryption) wasmMemory.grow(1);
      view(outputPointer, Math.max(1, ciphertextLength - 16)).fill(0x52);
      if (options?.throwOnDecryption) throw new Error("fake decryption trap");
      return options?.decryptionResult ?? 0;
    },
  } as unknown as LibCrypto;

  return {
    module: fakeModule,
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

const freedBytesAt = (fake: FakeXChaChaModule, pointer: number): Uint8Array => {
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

describe("XChaCha20-Poly1305 WASM ownership boundary", () => {
  const key = new Uint8Array(32).fill(0x31);
  const nonce = new Uint8Array(24).fill(0x42);
  const plaintext = Uint8Array.of(0x53, 0x54, 0x55);
  const aad = Uint8Array.of(0x64, 0x65);
  const ciphertext = new Uint8Array(plaintext.length + 16).fill(0x76);

  test("rejects invalid types, sizes, and hostile wrappers before allocating", () => {
    const fake = makeFakeXChaChaModule();

    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        "key" as unknown as Uint8Array,
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        new Uint8Array(31),
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow(RangeError);
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        key,
        new Uint8Array(23),
        plaintext,
        aad,
      ),
    ).toThrow("nonce must be exactly 24 bytes");
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        "plaintext" as unknown as Uint8Array,
        aad,
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        plaintext,
        {} as unknown as Uint8Array,
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Open(
        fake.module,
        key,
        nonce,
        "ciphertext" as unknown as Uint8Array,
        aad,
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        bytesWithSpoofedLength(XCHACHA20POLY1305_MAX_PLAINTEXT_BYTES + 1),
        aad,
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Seal(
        fake.module,
        key,
        nonce,
        plaintext,
        bytesWithSpoofedLength(XCHACHA20POLY1305_MAX_WASM_BYTES + 1),
      ),
    ).toThrow(TypeError);
    expect(() =>
      xchacha20Poly1305Open(
        fake.module,
        key,
        nonce,
        bytesWithSpoofedLength(XCHACHA20POLY1305_MAX_WASM_BYTES + 1),
        aad,
      ),
    ).toThrow(TypeError);

    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("snapshots every input before malloc can detach WASM-backed views", () => {
    const sealFake = makeFakeXChaChaModule({ growAllocationAt: 1 });
    const sealBuffer = sealFake.module.wasmMemory.buffer;
    const sealKey = new Uint8Array(sealBuffer, 40_000, 32);
    const sealNonce = new Uint8Array(sealBuffer, 40_040, 24);
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

    const sealed = xchacha20Poly1305Seal(
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

    const openFake = makeFakeXChaChaModule({ growAllocationAt: 1 });
    const openBuffer = openFake.module.wasmMemory.buffer;
    const openKey = new Uint8Array(openBuffer, 40_000, 32);
    const openNonce = new Uint8Array(openBuffer, 40_040, 24);
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

    const opened = xchacha20Poly1305Open(
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

  test("copies intrinsic bytes, ignoring shadowed length and iterator properties", () => {
    const shadow = (value: Uint8Array, claimedLength: number): Uint8Array => {
      Object.defineProperty(value, "length", { value: claimedLength });
      Object.defineProperty(value, Symbol.iterator, {
        value: (): never => {
          throw new Error("hostile iterator must not run");
        },
      });
      return value;
    };

    const fake = makeFakeXChaChaModule();
    const shadowedKey = shadow(Uint8Array.from(key), 0);
    const shadowedNonce = shadow(Uint8Array.from(nonce), 0);
    const shadowedPlaintext = shadow(Uint8Array.from(plaintext), 0);
    const shadowedAad = shadow(Uint8Array.from(aad), 0);
    const sealed = xchacha20Poly1305Seal(
      fake.module,
      shadowedKey,
      shadowedNonce,
      shadowedPlaintext,
      shadowedAad,
    );

    expect(fake.encryptionInputs).toEqual([
      { key, nonce, plaintext, associatedData: aad },
    ]);
    expect(sealed).toEqual(new Uint8Array(19).fill(0x71));

    const opened = xchacha20Poly1305Open(
      fake.module,
      shadow(Uint8Array.from(key), 1_000),
      shadow(Uint8Array.from(nonce), 1_000),
      shadow(Uint8Array.from(sealed), 0),
      shadow(Uint8Array.from(aad), 1_000),
    );
    expect(opened).toEqual(new Uint8Array(3).fill(0x52));
    expect(fake.live.size).toBe(0);
  });

  test("refreshes the output heap if the primitive grows WASM memory", () => {
    const sealFake = makeFakeXChaChaModule({ growOnEncryption: true });
    const sealBuffer = sealFake.module.wasmMemory.buffer;
    const sealed = xchacha20Poly1305Seal(
      sealFake.module,
      key,
      nonce,
      plaintext,
      aad,
    );
    expect(sealFake.module.wasmMemory.buffer).not.toBe(sealBuffer);
    expect(sealed).toEqual(new Uint8Array(19).fill(0x71));
    expect(sealFake.live.size).toBe(0);

    const openFake = makeFakeXChaChaModule({ growOnDecryption: true });
    const openBuffer = openFake.module.wasmMemory.buffer;
    const opened = xchacha20Poly1305Open(
      openFake.module,
      key,
      nonce,
      ciphertext,
      aad,
    );
    expect(openFake.module.wasmMemory.buffer).not.toBe(openBuffer);
    expect(opened).toEqual(new Uint8Array(3).fill(0x52));
    expect(openFake.live.size).toBe(0);
  });

  test("takes owned snapshots of SharedArrayBuffer-backed inputs", () => {
    const shared = new SharedArrayBuffer(128);
    const sharedKey = new Uint8Array(shared, 0, 32);
    const sharedNonce = new Uint8Array(shared, 32, 24);
    const sharedPlaintext = new Uint8Array(shared, 56, 3);
    const sharedAad = new Uint8Array(shared, 64, 2);
    sharedKey.set(key);
    sharedNonce.set(nonce);
    sharedPlaintext.set(plaintext);
    sharedAad.set(aad);

    const fake = makeFakeXChaChaModule();
    xchacha20Poly1305Seal(
      fake.module,
      sharedKey,
      sharedNonce,
      sharedPlaintext,
      sharedAad,
    );
    new Uint8Array(shared).fill(0);

    expect(fake.encryptionInputs).toEqual([
      { key, nonce, plaintext, associatedData: aad },
    ]);
    expect(fake.live.size).toBe(0);
  });

  test("cleans all live allocations on allocation, primitive, and auth failure", () => {
    const allocationFailure = makeFakeXChaChaModule({
      failAllocationAt: 5,
    });
    expect(() =>
      xchacha20Poly1305Seal(
        allocationFailure.module,
        key,
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow("failed to allocate ciphertext");
    expectAllZero(
      freedBytesAt(allocationFailure, allocationFailure.allocations[0].pointer),
    );
    expectAllZero(
      freedBytesAt(allocationFailure, allocationFailure.allocations[3].pointer),
    );
    expect(allocationFailure.live.size).toBe(0);

    const encryptionFailure = makeFakeXChaChaModule({
      encryptionResult: -7,
    });
    expect(() =>
      xchacha20Poly1305Seal(
        encryptionFailure.module,
        key,
        nonce,
        plaintext,
        aad,
      ),
    ).toThrow("encryption failed");
    expectAllZero(
      freedBytesAt(encryptionFailure, encryptionFailure.allocations[0].pointer),
    );
    expectAllZero(
      freedBytesAt(encryptionFailure, encryptionFailure.allocations[3].pointer),
    );
    expectAllZero(
      freedBytesAt(encryptionFailure, encryptionFailure.allocations[4].pointer),
    );
    expect(encryptionFailure.live.size).toBe(0);

    const authenticationFailure = makeFakeXChaChaModule({
      decryptionResult: -1,
    });
    expect(
      xchacha20Poly1305Open(
        authenticationFailure.module,
        key,
        nonce,
        ciphertext,
        aad,
      ),
    ).toBeNull();
    expectAllZero(
      freedBytesAt(
        authenticationFailure,
        authenticationFailure.allocations[0].pointer,
      ),
    );
    expectAllZero(
      freedBytesAt(
        authenticationFailure,
        authenticationFailure.allocations[4].pointer,
      ),
    );
    expect(authenticationFailure.live.size).toBe(0);

    const primitiveTrap = makeFakeXChaChaModule({
      throwOnDecryption: true,
    });
    expect(() =>
      xchacha20Poly1305Open(primitiveTrap.module, key, nonce, ciphertext, aad),
    ).toThrow("fake decryption trap");
    expectAllZero(
      freedBytesAt(primitiveTrap, primitiveTrap.allocations[0].pointer),
    );
    expectAllZero(
      freedBytesAt(primitiveTrap, primitiveTrap.allocations[4].pointer),
    );
    expect(primitiveTrap.live.size).toBe(0);
  });
});
