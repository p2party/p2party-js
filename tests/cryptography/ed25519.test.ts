import { describe, expect, test } from "bun:test";

import { keyPairFromSecretKey, newKeyPair, sign } from "../../src/cryptography/ed25519";
import { loadTestModule } from "../../src/cryptography/testModule";

describe("Ed25519 secret staging", () => {
  test("sign checks the C result and wipes the staged long-term secret", async () => {
    const module = await loadTestModule();
    const keyPair = await newKeyPair(module);
    const originalSign = module._sign;
    const originalFree = module._free;
    let secretPtr = -1;
    let wipedBeforeFree = false;

    module._sign = (_len, _data, secret): number => {
      secretPtr = secret;
      return -1;
    };
    module._free = (ptr: number): void => {
      if (ptr === secretPtr) {
        const view = new Uint8Array(module.wasmMemory.buffer, ptr, 64);
        wipedBeforeFree = view.every((byte) => byte === 0);
      }
      originalFree(ptr);
    };

    try {
      await expect(
        sign(new Uint8Array([1, 2, 3]), keyPair.secretKey, module),
      ).rejects.toThrow("Could not sign");
      expect(wipedBeforeFree).toBe(true);
    } finally {
      module._sign = originalSign;
      module._free = originalFree;
      keyPair.secretKey.fill(0);
    }
  });

  test("key import wipes its WASM secret copy before free", async () => {
    const module = await loadTestModule();
    const keyPair = await newKeyPair(module);
    const originalDerive = module._keypair_from_secret_key;
    const originalFree = module._free;
    let secretPtr = -1;
    let wipedBeforeFree = false;

    module._keypair_from_secret_key = (publicKey, secret): number => {
      secretPtr = secret;
      return originalDerive(publicKey, secret);
    };
    module._free = (ptr: number): void => {
      if (ptr === secretPtr) {
        const view = new Uint8Array(module.wasmMemory.buffer, ptr, 64);
        wipedBeforeFree = view.every((byte) => byte === 0);
      }
      originalFree(ptr);
    };

    try {
      const restored = await keyPairFromSecretKey(
        keyPair.secretKey,
        module,
      );
      expect(restored.publicKey).toEqual(keyPair.publicKey);
      expect(wipedBeforeFree).toBe(true);
    } finally {
      module._keypair_from_secret_key = originalDerive;
      module._free = originalFree;
      keyPair.secretKey.fill(0);
    }
  });
});
