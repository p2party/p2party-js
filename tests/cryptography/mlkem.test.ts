import { describe, expect, test } from "bun:test";

import {
  createMlKemBackend,
  ML_KEM_1024_SUITE,
  ML_KEM_512_SUITE,
  ML_KEM_768_SUITE,
  type MlKemModule,
  type MlKemParameterSet,
  type MlKemSuiteDescriptor,
} from "../../src/cryptography/mlkem";
import { loadTestModule } from "../../src/cryptography/testModule";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const sha256Hex = async (bytes: Uint8Array): Promise<string> =>
  Buffer.from(
    await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer),
  ).toString("hex");

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const expectBytesDifferent = (
  actual: Uint8Array,
  expected: Uint8Array,
): void => {
  expect(Buffer.from(actual)).not.toEqual(Buffer.from(expected));
};

interface SuiteCase<P extends MlKemParameterSet = MlKemParameterSet> {
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;
  readonly expected: {
    readonly publicKeyBytes: number;
    readonly secretKeyBytes: number;
    readonly ciphertextBytes: number;
  };
  readonly acvp: {
    readonly tgId: number;
    readonly tcId: number;
    readonly d: string;
    readonly z: string;
    readonly publicKeySha256: string;
    readonly secretKeySha256: string;
  };
}

/**
 * Official NIST ACVP-Server vectors pinned at:
 * 2972def23bf9f3680c2c531561ed9bdd0f1086ad
 * gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
 *
 * Hashing ek/dk keeps the test compact while still comparing every output
 * byte. Inputs, group IDs, case IDs, and expected hashes are all pinned.
 */
const SUITE_CASES: readonly SuiteCase[] = [
  {
    suite: ML_KEM_512_SUITE,
    expected: {
      publicKeyBytes: 800,
      secretKeyBytes: 1632,
      ciphertextBytes: 768,
    },
    acvp: {
      tgId: 1,
      tcId: 1,
      d: "47B893474672BA92E4B12EE44FB32953AF8E8503B5FB471D1614FB8A021A660A",
      z: "1F8CB39E9E30BC458A0DC5408884B1187FB217018DF760FA57317703B844A0A9",
      publicKeySha256:
        "7e4a2b716a684c1ad33c43c808782da9e1a72f14ccda82723f712d49f53a9f28",
      secretKeySha256:
        "c725c25ca8636d75653a07e7a9ccf0b3c2b927617e8f99f0f05ab1f9cb7e046d",
    },
  },
  {
    suite: ML_KEM_768_SUITE,
    expected: {
      publicKeyBytes: 1184,
      secretKeyBytes: 2400,
      ciphertextBytes: 1088,
    },
    acvp: {
      tgId: 2,
      tcId: 26,
      d: "E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0",
      z: "1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0",
      publicKeySha256:
        "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
      secretKeySha256:
        "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079",
    },
  },
  {
    suite: ML_KEM_1024_SUITE,
    expected: {
      publicKeyBytes: 1568,
      secretKeyBytes: 3168,
      ciphertextBytes: 1568,
    },
    acvp: {
      tgId: 3,
      tcId: 51,
      d: "F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009",
      z: "35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275",
      publicKeySha256:
        "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6",
      secretKeySha256:
        "925ed6f1cf0379ede29d8209432d6e08c73ed0423883febf85416343f4fa1f86",
    },
  },
];

type RawWasmFunction = (...arguments_: number[]) => number;

const getRawWasmFunction = (
  module: MlKemModule,
  name: string,
): RawWasmFunction => {
  const candidate = (module as unknown as Record<string, unknown>)[name];
  if (typeof candidate !== "function")
    throw new Error(`test module is missing ${name}`);
  return candidate as RawWasmFunction;
};

interface FreedAllocation {
  readonly pointer: number;
  readonly bytes: Uint8Array;
}

interface FakeMlKemModule {
  readonly module: LibCrypto;
  readonly allocations: Array<{ pointer: number; length: number }>;
  readonly freed: FreedAllocation[];
  readonly live: Map<number, number>;
  readonly keyPairSeeds: Uint8Array[];
  readonly encapsulationInputs: Array<{
    publicKey: Uint8Array;
    randomness: Uint8Array;
  }>;
  readonly decapsulationInputs: Array<{
    ciphertext: Uint8Array;
    secretKey: Uint8Array;
  }>;
}

const makeFakeMlKem768Module = (options?: {
  readonly failAllocationAt?: number;
  readonly growAllocationAt?: number;
  readonly keyPairResult?: number;
  readonly encapsulationResult?: number;
  readonly decapsulationResult?: number;
}): FakeMlKemModule => {
  const suite = ML_KEM_768_SUITE;
  const wasmMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const allocations: Array<{ pointer: number; length: number }> = [];
  const freed: FreedAllocation[] = [];
  const live = new Map<number, number>();
  const keyPairSeeds: Uint8Array[] = [];
  const encapsulationInputs: Array<{
    publicKey: Uint8Array;
    randomness: Uint8Array;
  }> = [];
  const decapsulationInputs: Array<{
    ciphertext: Uint8Array;
    secretKey: Uint8Array;
  }> = [];
  let nextPointer = 64;
  let allocationCount = 0;

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
    _mlkem768_keypair(
      publicKeyPointer: number,
      secretKeyPointer: number,
      seedPointer: number,
    ): number {
      const seed = Uint8Array.from(view(seedPointer, suite.keyPairRandomBytes));
      keyPairSeeds.push(seed);
      view(publicKeyPointer, suite.publicKeyBytes).fill(seed[0] ^ 0x11);
      view(secretKeyPointer, suite.secretKeyBytes).fill(seed[1] ^ 0x22);
      return options?.keyPairResult ?? 0;
    },
    _mlkem768_encaps(
      ciphertextPointer: number,
      sharedSecretPointer: number,
      publicKeyPointer: number,
      randomnessPointer: number,
    ): number {
      const publicKey = Uint8Array.from(
        view(publicKeyPointer, suite.publicKeyBytes),
      );
      const randomness = Uint8Array.from(
        view(randomnessPointer, suite.encapsRandomBytes),
      );
      encapsulationInputs.push({ publicKey, randomness });
      view(ciphertextPointer, suite.ciphertextBytes).fill(
        publicKey[0] ^ randomness[0],
      );
      view(sharedSecretPointer, suite.sharedSecretBytes).fill(
        randomness[0] ^ 0x44,
      );
      return options?.encapsulationResult ?? 0;
    },
    _mlkem768_decaps(
      sharedSecretPointer: number,
      ciphertextPointer: number,
      secretKeyPointer: number,
    ): number {
      const ciphertext = Uint8Array.from(
        view(ciphertextPointer, suite.ciphertextBytes),
      );
      const secretKey = Uint8Array.from(
        view(secretKeyPointer, suite.secretKeyBytes),
      );
      decapsulationInputs.push({ ciphertext, secretKey });
      view(sharedSecretPointer, suite.sharedSecretBytes).fill(
        ciphertext[0] ^ secretKey[0],
      );
      return options?.decapsulationResult ?? 0;
    },
  } as unknown as LibCrypto;

  return {
    module,
    allocations,
    freed,
    live,
    keyPairSeeds,
    encapsulationInputs,
    decapsulationInputs,
  };
};

const expectAllZero = (bytes: Uint8Array): void => {
  expect(bytes.every((byte) => byte === 0)).toBe(true);
};

const freedBytesAt = (fake: FakeMlKemModule, pointer: number): Uint8Array => {
  const allocation = fake.freed.find((entry) => entry.pointer === pointer);
  if (allocation === undefined)
    throw new Error(`test double: pointer ${String(pointer)} was not freed`);
  return allocation.bytes;
};

for (const { suite, expected, acvp } of SUITE_CASES) {
  describe(`${suite.standardName} WASM backend`, () => {
    test("carries the exact FIPS 203 sizes", () => {
      expect(suite.publicKeyBytes).toBe(expected.publicKeyBytes);
      expect(suite.secretKeyBytes).toBe(expected.secretKeyBytes);
      expect(suite.ciphertextBytes).toBe(expected.ciphertextBytes);
      expect(suite.sharedSecretBytes).toBe(32);
      expect(suite.keyPairRandomBytes).toBe(64);
      expect(suite.encapsRandomBytes).toBe(32);
    });

    test(`matches NIST ACVP FIPS 203 keyGen tgId ${String(acvp.tgId)} tcId ${String(acvp.tcId)}`, async () => {
      const d = hexToBytes(acvp.d);
      const z = hexToBytes(acvp.z);
      const module = (await loadTestModule()) as MlKemModule;
      const publicKeyPtr = module._malloc(suite.publicKeyBytes);
      const secretKeyPtr = module._malloc(suite.secretKeyBytes);
      const coinsPtr = module._malloc(suite.keyPairRandomBytes);
      expect(publicKeyPtr).not.toBe(0);
      expect(secretKeyPtr).not.toBe(0);
      expect(coinsPtr).not.toBe(0);

      const publicKeyHeap = new Uint8Array(
        module.wasmMemory.buffer,
        publicKeyPtr,
        suite.publicKeyBytes,
      );
      const secretKeyHeap = new Uint8Array(
        module.wasmMemory.buffer,
        secretKeyPtr,
        suite.secretKeyBytes,
      );
      const coinsHeap = new Uint8Array(
        module.wasmMemory.buffer,
        coinsPtr,
        suite.keyPairRandomBytes,
      );
      try {
        coinsHeap.set(d, 0);
        coinsHeap.set(z, d.length);
        const keypair = getRawWasmFunction(module, suite.wasmExports.keypair);
        expect(keypair(publicKeyPtr, secretKeyPtr, coinsPtr)).toBe(0);
        expect(await sha256Hex(Uint8Array.from(publicKeyHeap))).toBe(
          acvp.publicKeySha256,
        );
        expect(await sha256Hex(Uint8Array.from(secretKeyHeap))).toBe(
          acvp.secretKeySha256,
        );
      } finally {
        secretKeyHeap.fill(0);
        coinsHeap.fill(0);
        module._free(publicKeyPtr);
        module._free(secretKeyPtr);
        module._free(coinsPtr);
      }
    });

    test("deterministic surface matches ACVP key generation and repeatable encapsulation", async () => {
      const seed = new Uint8Array(suite.keyPairRandomBytes);
      seed.set(hexToBytes(acvp.d), 0);
      seed.set(hexToBytes(acvp.z), 32);
      const seedBefore = Uint8Array.from(seed);
      const randomness = new Uint8Array(suite.encapsRandomBytes).fill(0x42);
      const randomnessBefore = Uint8Array.from(randomness);
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const keyPair = await backend.deriveKeyPair(seed);
      const first = await backend.encapsulateDeterministically(
        keyPair.publicKey,
        randomness,
      );
      const second = await backend.encapsulateDeterministically(
        keyPair.publicKey,
        randomness,
      );
      const decapsulated = await backend.decapsulate(
        first.ciphertext,
        keyPair.secretKey,
      );

      expect(await sha256Hex(keyPair.publicKey)).toBe(acvp.publicKeySha256);
      expect(await sha256Hex(keyPair.secretKey)).toBe(acvp.secretKeySha256);
      expectBytesEqual(first.ciphertext, second.ciphertext);
      expectBytesEqual(first.sharedSecret, second.sharedSecret);
      expectBytesEqual(decapsulated.sharedSecret, first.sharedSecret);
      expectBytesEqual(seed, seedBefore);
      expectBytesEqual(randomness, randomnessBefore);

      decapsulated.destroy();
      second.destroy();
      first.destroy();
      keyPair.destroy();
    });

    test("key generation, encapsulation, and decapsulation round trip", async () => {
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const keyPair = await backend.generateKeyPair();
      const encapsulated = await backend.encapsulate(keyPair.publicKey);
      const decapsulated = await backend.decapsulate(
        encapsulated.ciphertext,
        keyPair.secretKey,
      );

      expect(backend.suite).toBe(suite);
      expect(keyPair.publicKey).toHaveLength(suite.publicKeyBytes);
      expect(keyPair.secretKey).toHaveLength(suite.secretKeyBytes);
      expect(encapsulated.ciphertext).toHaveLength(suite.ciphertextBytes);
      expect(encapsulated.sharedSecret).toHaveLength(suite.sharedSecretBytes);
      expect(decapsulated.sharedSecret).toHaveLength(suite.sharedSecretBytes);
      expectBytesEqual(decapsulated.sharedSecret, encapsulated.sharedSecret);

      decapsulated.destroy();
      encapsulated.destroy();
      keyPair.destroy();
    });

    test("tampered ciphertext uses implicit rejection", async () => {
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const keyPair = await backend.generateKeyPair();
      const encapsulated = await backend.encapsulate(keyPair.publicKey);
      const tampered = Uint8Array.from(encapsulated.ciphertext);
      tampered[Math.floor(tampered.length / 2)] ^= 0x80;

      const rejected = await backend.decapsulate(tampered, keyPair.secretKey);
      expect(rejected.sharedSecret).toHaveLength(suite.sharedSecretBytes);
      expectBytesDifferent(rejected.sharedSecret, encapsulated.sharedSecret);

      rejected.destroy();
      encapsulated.destroy();
      keyPair.destroy();
    });

    test("independent keypairs do not decapsulate to the sender secret", async () => {
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const first = await backend.generateKeyPair();
      const second = await backend.generateKeyPair();
      const encapsulated = await backend.encapsulate(first.publicKey);
      const wrongRecipient = await backend.decapsulate(
        encapsulated.ciphertext,
        second.secretKey,
      );

      expectBytesDifferent(first.publicKey, second.publicKey);
      expectBytesDifferent(first.secretKey, second.secretKey);
      expectBytesDifferent(
        wrongRecipient.sharedSecret,
        encapsulated.sharedSecret,
      );

      wrongRecipient.destroy();
      encapsulated.destroy();
      first.destroy();
      second.destroy();
    });

    test("rejects every non-exact public input length", async () => {
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const keyPair = await backend.generateKeyPair();
      const encapsulated = await backend.encapsulate(keyPair.publicKey);

      await expect(
        backend.encapsulate(new Uint8Array(suite.publicKeyBytes - 1)),
      ).rejects.toThrow(
        `must be exactly ${String(suite.publicKeyBytes)} bytes`,
      );
      await expect(
        backend.encapsulate(new Uint8Array(suite.publicKeyBytes + 1)),
      ).rejects.toThrow(
        `must be exactly ${String(suite.publicKeyBytes)} bytes`,
      );
      await expect(
        backend.decapsulate(
          new Uint8Array(suite.ciphertextBytes - 1),
          keyPair.secretKey,
        ),
      ).rejects.toThrow(
        `must be exactly ${String(suite.ciphertextBytes)} bytes`,
      );
      await expect(
        backend.decapsulate(
          new Uint8Array(suite.ciphertextBytes + 1),
          keyPair.secretKey,
        ),
      ).rejects.toThrow(
        `must be exactly ${String(suite.ciphertextBytes)} bytes`,
      );
      await expect(
        backend.decapsulate(
          encapsulated.ciphertext,
          new Uint8Array(suite.secretKeyBytes - 1),
        ),
      ).rejects.toThrow(
        `must be exactly ${String(suite.secretKeyBytes)} bytes`,
      );
      await expect(
        backend.decapsulate(
          encapsulated.ciphertext,
          new Uint8Array(suite.secretKeyBytes + 1),
        ),
      ).rejects.toThrow(
        `must be exactly ${String(suite.secretKeyBytes)} bytes`,
      );

      encapsulated.destroy();
      keyPair.destroy();
    });

    test("destroy is idempotent and wipes copied secret bytes", async () => {
      const backend = createMlKemBackend(await loadTestModule(), suite);
      const keyPair = await backend.generateKeyPair();
      const encapsulated = await backend.encapsulate(keyPair.publicKey);
      const decapsulated = await backend.decapsulate(
        encapsulated.ciphertext,
        keyPair.secretKey,
      );

      keyPair.destroy();
      keyPair.destroy();
      encapsulated.destroy();
      encapsulated.destroy();
      decapsulated.destroy();
      decapsulated.destroy();

      expect(keyPair.destroyed).toBe(true);
      expect(encapsulated.destroyed).toBe(true);
      expect(decapsulated.destroyed).toBe(true);
      expect(keyPair.secretKey.every((byte) => byte === 0)).toBe(true);
      expect(encapsulated.sharedSecret.every((byte) => byte === 0)).toBe(true);
      expect(decapsulated.sharedSecret.every((byte) => byte === 0)).toBe(true);
    });

    test("fails closed when a selected-suite WASM export is missing", async () => {
      const module = await loadTestModule();
      const withoutSelectedKeypair = new Proxy(module, {
        get(target, property, receiver) {
          if (property === suite.wasmExports.keypair) return undefined;
          return Reflect.get(target, property, receiver);
        },
      });

      expect(() => createMlKemBackend(withoutSelectedKeypair, suite)).toThrow(
        `${suite.standardName} WASM exports are unavailable; rebuild libcrypto.wasm`,
      );
    });

    test("rejects a forged suite descriptor before using its sizes", async () => {
      const module = await loadTestModule();
      const forged = {
        ...suite,
        publicKeyBytes: 1,
      } as Readonly<MlKemSuiteDescriptor>;

      expect(() => createMlKemBackend(module, forged)).toThrow(
        "ML-KEM suite descriptor must be one of the exported canonical suites",
      );
    });
  });
}

describe("deterministic ML-KEM WASM ownership boundary", () => {
  const suite = ML_KEM_768_SUITE;

  test("uses caller-supplied seed and randomness without consulting Web Crypto", async () => {
    const fake = makeFakeMlKem768Module();
    const backend = createMlKemBackend(fake.module, suite);
    const seed = Uint8Array.from(
      { length: suite.keyPairRandomBytes },
      (_, index) => index,
    );
    const publicKey = new Uint8Array(suite.publicKeyBytes).fill(0x53);
    const randomness = new Uint8Array(suite.encapsRandomBytes).fill(0x64);
    const seedBefore = Uint8Array.from(seed);
    const publicKeyBefore = Uint8Array.from(publicKey);
    const randomnessBefore = Uint8Array.from(randomness);
    const cryptoApi = globalThis.crypto;
    const originalGetRandomValues = cryptoApi.getRandomValues;
    let keyPairPromise: ReturnType<typeof backend.deriveKeyPair>;
    let encapsulationPromise: ReturnType<
      typeof backend.encapsulateDeterministically
    >;

    expect(
      Reflect.set(cryptoApi, "getRandomValues", () => {
        throw new Error("deterministic ML-KEM unexpectedly requested entropy");
      }),
    ).toBe(true);
    try {
      // Both async-compatible methods execute their WASM work synchronously,
      // so the global poison is restored before this test yields.
      keyPairPromise = backend.deriveKeyPair(seed);
      encapsulationPromise = backend.encapsulateDeterministically(
        publicKey,
        randomness,
      );
    } finally {
      expect(
        Reflect.set(cryptoApi, "getRandomValues", originalGetRandomValues),
      ).toBe(true);
    }

    const keyPair = await keyPairPromise;
    const encapsulation = await encapsulationPromise;
    expect(fake.keyPairSeeds).toEqual([seedBefore]);
    expect(fake.encapsulationInputs).toEqual([
      { publicKey: publicKeyBefore, randomness: randomnessBefore },
    ]);
    expectBytesEqual(seed, seedBefore);
    expectBytesEqual(publicKey, publicKeyBefore);
    expectBytesEqual(randomness, randomnessBefore);
    expect(fake.live.size).toBe(0);

    encapsulation.destroy();
    keyPair.destroy();
  });

  test("rejects wrong types and non-exact deterministic inputs before allocating", async () => {
    const fake = makeFakeMlKem768Module();
    const backend = createMlKemBackend(fake.module, suite);
    const publicKey = new Uint8Array(suite.publicKeyBytes);
    const randomness = new Uint8Array(suite.encapsRandomBytes);
    const proxiedBytes = (length: number): Uint8Array =>
      new Proxy(new Uint8Array(length), {
        get(): never {
          throw new Error("hostile proxy surface must not run");
        },
      });

    await expect(
      backend.deriveKeyPair("seed" as unknown as Uint8Array),
    ).rejects.toThrow("key-generation seed must be a Uint8Array");
    await expect(
      backend.deriveKeyPair(new Uint8Array(suite.keyPairRandomBytes - 1)),
    ).rejects.toThrow(
      `key-generation seed must be exactly ${String(suite.keyPairRandomBytes)} bytes`,
    );
    await expect(
      backend.deriveKeyPair(new Uint8Array(suite.keyPairRandomBytes + 1)),
    ).rejects.toThrow(
      `key-generation seed must be exactly ${String(suite.keyPairRandomBytes)} bytes`,
    );
    await expect(
      backend.encapsulateDeterministically(
        new Uint8Array(suite.publicKeyBytes - 1),
        randomness,
      ),
    ).rejects.toThrow(
      `public key must be exactly ${String(suite.publicKeyBytes)} bytes`,
    );
    await expect(
      backend.encapsulateDeterministically(
        publicKey,
        "randomness" as unknown as Uint8Array,
      ),
    ).rejects.toThrow("encapsulation randomness must be a Uint8Array");
    await expect(
      backend.encapsulateDeterministically(
        publicKey,
        new Uint8Array(suite.encapsRandomBytes + 1),
      ),
    ).rejects.toThrow(
      `encapsulation randomness must be exactly ${String(suite.encapsRandomBytes)} bytes`,
    );
    await expect(
      backend.deriveKeyPair(proxiedBytes(suite.keyPairRandomBytes)),
    ).rejects.toThrow("key-generation seed must be a Uint8Array");
    await expect(
      backend.encapsulate(proxiedBytes(suite.publicKeyBytes)),
    ).rejects.toThrow("public key must be a Uint8Array");
    await expect(
      backend.encapsulateDeterministically(
        publicKey,
        proxiedBytes(suite.encapsRandomBytes),
      ),
    ).rejects.toThrow("encapsulation randomness must be a Uint8Array");
    await expect(
      backend.decapsulate(
        proxiedBytes(suite.ciphertextBytes),
        new Uint8Array(suite.secretKeyBytes),
      ),
    ).rejects.toThrow("ciphertext must be a Uint8Array");
    await expect(
      backend.decapsulate(
        new Uint8Array(suite.ciphertextBytes),
        proxiedBytes(suite.secretKeyBytes),
      ),
    ).rejects.toThrow("secret key must be a Uint8Array");

    expect(fake.allocations).toHaveLength(0);
    expect(fake.freed).toHaveLength(0);
  });

  test("uses intrinsic bytes despite shadowed length and iteration", async () => {
    const shadow = (bytes: Uint8Array, claimedLength = 0): Uint8Array => {
      const shadowed = Uint8Array.from(bytes);
      Object.defineProperty(shadowed, "length", { value: claimedLength });
      Object.defineProperty(shadowed, Symbol.iterator, {
        value: (): never => {
          throw new Error("hostile iterator must not run");
        },
      });
      return shadowed;
    };
    const fake = makeFakeMlKem768Module();
    const backend = createMlKemBackend(fake.module, suite);
    const seed = Uint8Array.from(
      { length: suite.keyPairRandomBytes },
      (_, index) => index,
    );
    const publicKey = new Uint8Array(suite.publicKeyBytes).fill(0x42);
    const randomness = new Uint8Array(suite.encapsRandomBytes).fill(0x43);
    const ciphertext = new Uint8Array(suite.ciphertextBytes).fill(0x54);
    const secretKey = new Uint8Array(suite.secretKeyBytes).fill(0x65);

    const keyPair = await backend.deriveKeyPair(shadow(seed, 1_000));
    const random = await backend.encapsulate(shadow(publicKey));
    const deterministic = await backend.encapsulateDeterministically(
      shadow(publicKey, 1_000),
      shadow(randomness),
    );
    const decapsulation = await backend.decapsulate(
      shadow(ciphertext),
      shadow(secretKey, 1_000),
    );

    expect(fake.keyPairSeeds).toEqual([seed]);
    expect(fake.encapsulationInputs[0]?.publicKey).toEqual(publicKey);
    expect(fake.encapsulationInputs[1]).toEqual({ publicKey, randomness });
    expect(fake.decapsulationInputs).toEqual([{ ciphertext, secretKey }]);
    expect(fake.live.size).toBe(0);

    decapsulation.destroy();
    deterministic.destroy();
    random.destroy();
    keyPair.destroy();
  });

  test("snapshots every borrowed input before malloc can grow WASM memory", async () => {
    const keyPairFake = makeFakeMlKem768Module({ growAllocationAt: 1 });
    const keyPairBuffer = keyPairFake.module.wasmMemory.buffer;
    const seed = new Uint8Array(
      keyPairBuffer,
      50_000,
      suite.keyPairRandomBytes,
    );
    seed.fill(0x31);
    const expectedSeed = Uint8Array.from(seed);
    const keyPair = await createMlKemBackend(
      keyPairFake.module,
      suite,
    ).deriveKeyPair(seed);

    expect(keyPairFake.module.wasmMemory.buffer).not.toBe(keyPairBuffer);
    expect(keyPairFake.keyPairSeeds).toEqual([expectedSeed]);
    expectAllZero(
      freedBytesAt(keyPairFake, keyPairFake.allocations[1].pointer),
    );
    expectAllZero(
      freedBytesAt(keyPairFake, keyPairFake.allocations[2].pointer),
    );
    expect(keyPairFake.live.size).toBe(0);
    keyPair.destroy();

    const encapsFake = makeFakeMlKem768Module({ growAllocationAt: 1 });
    const encapsBuffer = encapsFake.module.wasmMemory.buffer;
    const publicKey = new Uint8Array(
      encapsBuffer,
      48_000,
      suite.publicKeyBytes,
    );
    const randomness = new Uint8Array(
      encapsBuffer,
      50_000,
      suite.encapsRandomBytes,
    );
    publicKey.fill(0x42);
    randomness.fill(0x43);
    const expectedPublicKey = Uint8Array.from(publicKey);
    const expectedRandomness = Uint8Array.from(randomness);
    const encapsulation = await createMlKemBackend(
      encapsFake.module,
      suite,
    ).encapsulateDeterministically(publicKey, randomness);

    expect(encapsFake.module.wasmMemory.buffer).not.toBe(encapsBuffer);
    expect(encapsFake.encapsulationInputs).toEqual([
      {
        publicKey: expectedPublicKey,
        randomness: expectedRandomness,
      },
    ]);
    expectAllZero(freedBytesAt(encapsFake, encapsFake.allocations[1].pointer));
    expectAllZero(freedBytesAt(encapsFake, encapsFake.allocations[3].pointer));
    expect(encapsFake.live.size).toBe(0);
    encapsulation.destroy();

    const decapsFake = makeFakeMlKem768Module({ growAllocationAt: 1 });
    const decapsBuffer = decapsFake.module.wasmMemory.buffer;
    const ciphertext = new Uint8Array(
      decapsBuffer,
      44_000,
      suite.ciphertextBytes,
    );
    const secretKey = new Uint8Array(
      decapsBuffer,
      48_000,
      suite.secretKeyBytes,
    );
    ciphertext.fill(0x54);
    secretKey.fill(0x65);
    const expectedCiphertext = Uint8Array.from(ciphertext);
    const expectedSecretKey = Uint8Array.from(secretKey);
    const decapsulation = await createMlKemBackend(
      decapsFake.module,
      suite,
    ).decapsulate(ciphertext, secretKey);

    expect(decapsFake.module.wasmMemory.buffer).not.toBe(decapsBuffer);
    expect(decapsFake.decapsulationInputs).toEqual([
      {
        ciphertext: expectedCiphertext,
        secretKey: expectedSecretKey,
      },
    ]);
    expectAllZero(freedBytesAt(decapsFake, decapsFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(decapsFake, decapsFake.allocations[2].pointer));
    expect(decapsFake.live.size).toBe(0);
    decapsulation.destroy();
  });

  test("cleans all prior allocations when a later malloc fails", async () => {
    const keyPairFake = makeFakeMlKem768Module({ failAllocationAt: 3 });
    await expect(
      createMlKemBackend(keyPairFake.module, suite).deriveKeyPair(
        new Uint8Array(suite.keyPairRandomBytes).fill(0x31),
      ),
    ).rejects.toThrow("failed to allocate key-generation seed");
    expectAllZero(
      freedBytesAt(keyPairFake, keyPairFake.allocations[1].pointer),
    );
    expect(keyPairFake.live.size).toBe(0);

    const encapsFake = makeFakeMlKem768Module({ failAllocationAt: 4 });
    await expect(
      createMlKemBackend(encapsFake.module, suite).encapsulateDeterministically(
        new Uint8Array(suite.publicKeyBytes).fill(0x42),
        new Uint8Array(suite.encapsRandomBytes).fill(0x43),
      ),
    ).rejects.toThrow("failed to allocate encapsulation randomness");
    expectAllZero(freedBytesAt(encapsFake, encapsFake.allocations[1].pointer));
    expect(encapsFake.live.size).toBe(0);

    const decapsFake = makeFakeMlKem768Module({ failAllocationAt: 3 });
    await expect(
      createMlKemBackend(decapsFake.module, suite).decapsulate(
        new Uint8Array(suite.ciphertextBytes).fill(0x54),
        new Uint8Array(suite.secretKeyBytes).fill(0x65),
      ),
    ).rejects.toThrow("failed to allocate secret key");
    expectAllZero(freedBytesAt(decapsFake, decapsFake.allocations[0].pointer));
    expect(decapsFake.live.size).toBe(0);
  });

  test("zero-frees every secret scratch when a primitive rejects", async () => {
    const keyPairFake = makeFakeMlKem768Module({ keyPairResult: -7 });
    await expect(
      createMlKemBackend(keyPairFake.module, suite).deriveKeyPair(
        new Uint8Array(suite.keyPairRandomBytes).fill(0x31),
      ),
    ).rejects.toThrow("key generation failed (-7)");
    expectAllZero(
      freedBytesAt(keyPairFake, keyPairFake.allocations[1].pointer),
    );
    expectAllZero(
      freedBytesAt(keyPairFake, keyPairFake.allocations[2].pointer),
    );
    expect(keyPairFake.live.size).toBe(0);

    const encapsFake = makeFakeMlKem768Module({ encapsulationResult: -8 });
    await expect(
      createMlKemBackend(encapsFake.module, suite).encapsulateDeterministically(
        new Uint8Array(suite.publicKeyBytes).fill(0x42),
        new Uint8Array(suite.encapsRandomBytes).fill(0x43),
      ),
    ).rejects.toThrow("encapsulation failed (-8)");
    expectAllZero(freedBytesAt(encapsFake, encapsFake.allocations[1].pointer));
    expectAllZero(freedBytesAt(encapsFake, encapsFake.allocations[3].pointer));
    expect(encapsFake.live.size).toBe(0);

    const decapsFake = makeFakeMlKem768Module({ decapsulationResult: -9 });
    await expect(
      createMlKemBackend(decapsFake.module, suite).decapsulate(
        new Uint8Array(suite.ciphertextBytes).fill(0x54),
        new Uint8Array(suite.secretKeyBytes).fill(0x65),
      ),
    ).rejects.toThrow("decapsulation failed (-9)");
    expectAllZero(freedBytesAt(decapsFake, decapsFake.allocations[0].pointer));
    expectAllZero(freedBytesAt(decapsFake, decapsFake.allocations[2].pointer));
    expect(decapsFake.live.size).toBe(0);
  });
});
