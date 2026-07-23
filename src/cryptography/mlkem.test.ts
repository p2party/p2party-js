import { describe, expect, test } from "bun:test";

import {
  createMlKem768Backend,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_768_SECRET_KEY_BYTES,
  ML_KEM_SHARED_SECRET_BYTES,
  type MlKem768Module,
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

describe("ML-KEM-768 WASM backend", () => {
  test("matches NIST ACVP FIPS 203 key-generation vector tcId 26", async () => {
    // NIST ACVP-Server:
    // gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json,
    // parameterSet=ML-KEM-768, tgId=2, tcId=26. Hashing the large expected
    // ek/dk keeps this regression compact while still comparing every byte.
    const d = hexToBytes(
      "E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0",
    );
    const z = hexToBytes(
      "1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0",
    );
    const expectedPublicKeySha256 =
      "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e";
    const expectedSecretKeySha256 =
      "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079";

    const module = (await loadTestModule()) as MlKem768Module;
    const publicKeyPtr = module._malloc(ML_KEM_768_PUBLIC_KEY_BYTES);
    const secretKeyPtr = module._malloc(ML_KEM_768_SECRET_KEY_BYTES);
    const coinsPtr = module._malloc(64);
    expect(publicKeyPtr).not.toBe(0);
    expect(secretKeyPtr).not.toBe(0);
    expect(coinsPtr).not.toBe(0);

    const publicKeyHeap = new Uint8Array(
      module.wasmMemory.buffer,
      publicKeyPtr,
      ML_KEM_768_PUBLIC_KEY_BYTES,
    );
    const secretKeyHeap = new Uint8Array(
      module.wasmMemory.buffer,
      secretKeyPtr,
      ML_KEM_768_SECRET_KEY_BYTES,
    );
    const coinsHeap = new Uint8Array(module.wasmMemory.buffer, coinsPtr, 64);
    try {
      coinsHeap.set(d, 0);
      coinsHeap.set(z, 32);
      expect(
        module._mlkem768_keypair(publicKeyPtr, secretKeyPtr, coinsPtr),
      ).toBe(0);
      expect(await sha256Hex(Uint8Array.from(publicKeyHeap))).toBe(
        expectedPublicKeySha256,
      );
      expect(await sha256Hex(Uint8Array.from(secretKeyHeap))).toBe(
        expectedSecretKeySha256,
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
    const backend = createMlKem768Backend(await loadTestModule());
    const keyPair = await backend.generateKeyPair();
    const encapsulated = await backend.encapsulate(keyPair.publicKey);
    const decapsulated = await backend.decapsulate(
      encapsulated.ciphertext,
      keyPair.secretKey,
    );

    expect(keyPair.publicKey).toHaveLength(ML_KEM_768_PUBLIC_KEY_BYTES);
    expect(keyPair.secretKey).toHaveLength(ML_KEM_768_SECRET_KEY_BYTES);
    expect(encapsulated.ciphertext).toHaveLength(ML_KEM_768_CIPHERTEXT_BYTES);
    expect(encapsulated.sharedSecret).toHaveLength(ML_KEM_SHARED_SECRET_BYTES);
    expect(decapsulated.sharedSecret).toHaveLength(ML_KEM_SHARED_SECRET_BYTES);
    expectBytesEqual(decapsulated.sharedSecret, encapsulated.sharedSecret);

    decapsulated.destroy();
    encapsulated.destroy();
    keyPair.destroy();
  });

  test("tampered ciphertext uses implicit rejection and yields a different secret", async () => {
    const backend = createMlKem768Backend(await loadTestModule());
    const keyPair = await backend.generateKeyPair();
    const encapsulated = await backend.encapsulate(keyPair.publicKey);
    const tampered = Uint8Array.from(encapsulated.ciphertext);
    tampered[Math.floor(tampered.length / 2)] ^= 0x80;

    const rejected = await backend.decapsulate(tampered, keyPair.secretKey);
    expect(rejected.sharedSecret).toHaveLength(ML_KEM_SHARED_SECRET_BYTES);
    expectBytesDifferent(rejected.sharedSecret, encapsulated.sharedSecret);

    rejected.destroy();
    encapsulated.destroy();
    keyPair.destroy();
  });

  test("independent keypairs do not decapsulate to the sender's secret", async () => {
    const backend = createMlKem768Backend(await loadTestModule());
    const first = await backend.generateKeyPair();
    const second = await backend.generateKeyPair();

    expectBytesDifferent(first.publicKey, second.publicKey);
    expectBytesDifferent(first.secretKey, second.secretKey);

    const encapsulated = await backend.encapsulate(first.publicKey);
    const wrongRecipient = await backend.decapsulate(
      encapsulated.ciphertext,
      second.secretKey,
    );
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
    const backend = createMlKem768Backend(await loadTestModule());
    const keyPair = await backend.generateKeyPair();
    const encapsulated = await backend.encapsulate(keyPair.publicKey);

    await expect(
      backend.encapsulate(new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES - 1)),
    ).rejects.toThrow("must be exactly 1184 bytes");
    await expect(
      backend.encapsulate(new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES + 1)),
    ).rejects.toThrow("must be exactly 1184 bytes");
    await expect(
      backend.decapsulate(
        new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES - 1),
        keyPair.secretKey,
      ),
    ).rejects.toThrow("must be exactly 1088 bytes");
    await expect(
      backend.decapsulate(
        new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES + 1),
        keyPair.secretKey,
      ),
    ).rejects.toThrow("must be exactly 1088 bytes");
    await expect(
      backend.decapsulate(
        encapsulated.ciphertext,
        new Uint8Array(ML_KEM_768_SECRET_KEY_BYTES - 1),
      ),
    ).rejects.toThrow("must be exactly 2400 bytes");
    await expect(
      backend.decapsulate(
        encapsulated.ciphertext,
        new Uint8Array(ML_KEM_768_SECRET_KEY_BYTES + 1),
      ),
    ).rejects.toThrow("must be exactly 2400 bytes");

    encapsulated.destroy();
    keyPair.destroy();
  });

  test("destroy is idempotent and wipes copied secret bytes", async () => {
    const backend = createMlKem768Backend(await loadTestModule());
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
});
