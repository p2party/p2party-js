import { describe, expect, test } from "bun:test";

import {
  createMlKemBackend,
  ML_KEM_1024_SUITE,
  ML_KEM_512_SUITE,
  ML_KEM_768_SUITE,
  type MlKemModule,
  type MlKemParameterSet,
  type MlKemSuiteDescriptor,
} from "./mlkem";
import { loadTestModule } from "./testModule";

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
