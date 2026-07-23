import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

/** FIPS 203 ML-KEM-768 byte lengths. */
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const ML_KEM_SHARED_SECRET_BYTES = 32;

const ML_KEM_768_KEYPAIR_RANDOM_BYTES = 64;
const ML_KEM_768_ENCAPS_RANDOM_BYTES = 32;

/**
 * The small ABI exported by the pinned mlkem-native build.
 *
 * It is kept local to this backend so callers can use the ordinary LibCrypto
 * module while the generated Emscripten declaration remains an implementation
 * detail of the build.
 */
export interface MlKem768Module extends LibCrypto {
  _mlkem768_keypair(
    publicKey: number,
    secretKey: number,
    coins64: number,
  ): number;
  _mlkem768_encaps(
    ciphertext: number,
    sharedSecret: number,
    publicKey: number,
    coins32: number,
  ): number;
  _mlkem768_decaps(
    sharedSecret: number,
    ciphertext: number,
    secretKey: number,
  ): number;
}

export interface MlKem768KeyPair {
  /**
   * A copy suitable for transport or serialization. This is not secret.
   */
  readonly publicKey: Uint8Array;
  /**
   * Plaintext secret key bytes suitable for encrypted serialization.
   * Call destroy() as soon as the key is no longer needed.
   */
  readonly secretKey: Uint8Array;
  readonly destroyed: boolean;
  /** Idempotently wipes this object's secretKey bytes. */
  destroy(): void;
}

export interface MlKem768Encapsulation {
  /** A copy suitable for transport or serialization. This is not secret. */
  readonly ciphertext: Uint8Array;
  /**
   * Plaintext shared-secret bytes. Mix these into a KDF, then call destroy().
   */
  readonly sharedSecret: Uint8Array;
  readonly destroyed: boolean;
  /** Idempotently wipes this object's sharedSecret bytes. */
  destroy(): void;
}

export interface MlKem768Decapsulation {
  /**
   * Plaintext shared-secret bytes. Mix these into a KDF, then call destroy().
   */
  readonly sharedSecret: Uint8Array;
  readonly destroyed: boolean;
  /** Idempotently wipes this object's sharedSecret bytes. */
  destroy(): void;
}

/**
 * Async-compatible ML-KEM API. The underlying WASM calls are synchronous, but
 * returning promises lets protocol code swap in a worker-backed implementation
 * without changing the handshake state machine.
 */
export interface MlKem768Backend {
  generateKeyPair(): Promise<MlKem768KeyPair>;
  encapsulate(publicKey: Uint8Array): Promise<MlKem768Encapsulation>;
  decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKem768Decapsulation>;
}

const requireExactBytes: (
  value: unknown,
  name: string,
  expectedLength: number,
) => asserts value is Uint8Array = (value, name, expectedLength) => {
  if (!(value instanceof Uint8Array))
    throw new TypeError(`${name} must be a Uint8Array`);
  if (value.length !== expectedLength)
    throw new RangeError(
      `${name} must be exactly ${String(expectedLength)} bytes`,
    );
};

const checkedMalloc = (
  module: MlKem768Module,
  length: number,
  name: string,
): number => {
  const pointer = module._malloc(length);
  if (pointer === 0) throw new Error(`ML-KEM-768: failed to allocate ${name}`);
  return pointer;
};

const heapView = (
  module: MlKem768Module,
  pointer: number,
  length: number,
): Uint8Array => new Uint8Array(module.wasmMemory.buffer, pointer, length);

const publicFree = (
  module: MlKem768Module,
  pointer: number | undefined,
): void => {
  if (pointer !== undefined) module._free(pointer);
};

const secretFree = (
  module: MlKem768Module,
  pointer: number | undefined,
  length: number,
): void => {
  if (pointer !== undefined)
    zeroFree(module, heapView(module, pointer, length));
};

const makeKeyPair = (
  publicKey: Uint8Array,
  secretKey: Uint8Array,
): MlKem768KeyPair => {
  let destroyed = false;
  return {
    publicKey,
    secretKey,
    get destroyed(): boolean {
      return destroyed;
    },
    destroy(): void {
      if (destroyed) return;
      secretKey.fill(0);
      destroyed = true;
    },
  };
};

const makeEncapsulation = (
  ciphertext: Uint8Array,
  sharedSecret: Uint8Array,
): MlKem768Encapsulation => {
  let destroyed = false;
  return {
    ciphertext,
    sharedSecret,
    get destroyed(): boolean {
      return destroyed;
    },
    destroy(): void {
      if (destroyed) return;
      sharedSecret.fill(0);
      destroyed = true;
    },
  };
};

const makeDecapsulation = (sharedSecret: Uint8Array): MlKem768Decapsulation => {
  let destroyed = false;
  return {
    sharedSecret,
    get destroyed(): boolean {
      return destroyed;
    },
    destroy(): void {
      if (destroyed) return;
      sharedSecret.fill(0);
      destroyed = true;
    },
  };
};

const requireMlKemModule = (module: LibCrypto): MlKem768Module => {
  const candidate = module as Partial<MlKem768Module>;
  if (
    typeof candidate._mlkem768_keypair !== "function" ||
    typeof candidate._mlkem768_encaps !== "function" ||
    typeof candidate._mlkem768_decaps !== "function"
  )
    throw new Error(
      "ML-KEM-768 WASM exports are unavailable; rebuild libcrypto.wasm",
    );
  return module;
};

class WasmMlKem768Backend implements MlKem768Backend {
  readonly #module: MlKem768Module;

  constructor(module: LibCrypto) {
    this.#module = requireMlKemModule(module);
  }

  async generateKeyPair(): Promise<MlKem768KeyPair> {
    await Promise.resolve();
    const module = this.#module;
    let publicKeyPtr: number | undefined;
    let secretKeyPtr: number | undefined;
    let coinsPtr: number | undefined;

    try {
      publicKeyPtr = checkedMalloc(
        module,
        ML_KEM_768_PUBLIC_KEY_BYTES,
        "public key",
      );
      secretKeyPtr = checkedMalloc(
        module,
        ML_KEM_768_SECRET_KEY_BYTES,
        "secret key",
      );
      coinsPtr = checkedMalloc(
        module,
        ML_KEM_768_KEYPAIR_RANDOM_BYTES,
        "key-generation randomness",
      );

      const coins = heapView(module, coinsPtr, ML_KEM_768_KEYPAIR_RANDOM_BYTES);
      globalThis.crypto.getRandomValues(coins);

      const result = module._mlkem768_keypair(
        publicKeyPtr,
        secretKeyPtr,
        coinsPtr,
      );
      if (result !== 0)
        throw new Error(`ML-KEM-768 key generation failed (${String(result)})`);

      return makeKeyPair(
        Uint8Array.from(
          heapView(module, publicKeyPtr, ML_KEM_768_PUBLIC_KEY_BYTES),
        ),
        Uint8Array.from(
          heapView(module, secretKeyPtr, ML_KEM_768_SECRET_KEY_BYTES),
        ),
      );
    } finally {
      publicFree(module, publicKeyPtr);
      secretFree(module, secretKeyPtr, ML_KEM_768_SECRET_KEY_BYTES);
      secretFree(module, coinsPtr, ML_KEM_768_KEYPAIR_RANDOM_BYTES);
    }
  }

  async encapsulate(publicKey: Uint8Array): Promise<MlKem768Encapsulation> {
    await Promise.resolve();
    requireExactBytes(
      publicKey,
      "ML-KEM-768 public key",
      ML_KEM_768_PUBLIC_KEY_BYTES,
    );

    const module = this.#module;
    let ciphertextPtr: number | undefined;
    let sharedSecretPtr: number | undefined;
    let publicKeyPtr: number | undefined;
    let coinsPtr: number | undefined;

    try {
      ciphertextPtr = checkedMalloc(
        module,
        ML_KEM_768_CIPHERTEXT_BYTES,
        "ciphertext",
      );
      sharedSecretPtr = checkedMalloc(
        module,
        ML_KEM_SHARED_SECRET_BYTES,
        "shared secret",
      );
      publicKeyPtr = checkedMalloc(
        module,
        ML_KEM_768_PUBLIC_KEY_BYTES,
        "public key",
      );
      coinsPtr = checkedMalloc(
        module,
        ML_KEM_768_ENCAPS_RANDOM_BYTES,
        "encapsulation randomness",
      );

      heapView(module, publicKeyPtr, ML_KEM_768_PUBLIC_KEY_BYTES).set(
        publicKey,
      );
      const coins = heapView(module, coinsPtr, ML_KEM_768_ENCAPS_RANDOM_BYTES);
      globalThis.crypto.getRandomValues(coins);

      const result = module._mlkem768_encaps(
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr,
        coinsPtr,
      );
      if (result !== 0)
        throw new Error(`ML-KEM-768 encapsulation failed (${String(result)})`);

      return makeEncapsulation(
        Uint8Array.from(
          heapView(module, ciphertextPtr, ML_KEM_768_CIPHERTEXT_BYTES),
        ),
        Uint8Array.from(
          heapView(module, sharedSecretPtr, ML_KEM_SHARED_SECRET_BYTES),
        ),
      );
    } finally {
      publicFree(module, ciphertextPtr);
      secretFree(module, sharedSecretPtr, ML_KEM_SHARED_SECRET_BYTES);
      publicFree(module, publicKeyPtr);
      secretFree(module, coinsPtr, ML_KEM_768_ENCAPS_RANDOM_BYTES);
    }
  }

  async decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKem768Decapsulation> {
    await Promise.resolve();
    requireExactBytes(
      ciphertext,
      "ML-KEM-768 ciphertext",
      ML_KEM_768_CIPHERTEXT_BYTES,
    );
    requireExactBytes(
      secretKey,
      "ML-KEM-768 secret key",
      ML_KEM_768_SECRET_KEY_BYTES,
    );

    const module = this.#module;
    let sharedSecretPtr: number | undefined;
    let ciphertextPtr: number | undefined;
    let secretKeyPtr: number | undefined;

    try {
      sharedSecretPtr = checkedMalloc(
        module,
        ML_KEM_SHARED_SECRET_BYTES,
        "shared secret",
      );
      ciphertextPtr = checkedMalloc(
        module,
        ML_KEM_768_CIPHERTEXT_BYTES,
        "ciphertext",
      );
      secretKeyPtr = checkedMalloc(
        module,
        ML_KEM_768_SECRET_KEY_BYTES,
        "secret key",
      );

      heapView(module, ciphertextPtr, ML_KEM_768_CIPHERTEXT_BYTES).set(
        ciphertext,
      );
      heapView(module, secretKeyPtr, ML_KEM_768_SECRET_KEY_BYTES).set(
        secretKey,
      );

      const result = module._mlkem768_decaps(
        sharedSecretPtr,
        ciphertextPtr,
        secretKeyPtr,
      );
      if (result !== 0)
        throw new Error(`ML-KEM-768 decapsulation failed (${String(result)})`);

      return makeDecapsulation(
        Uint8Array.from(
          heapView(module, sharedSecretPtr, ML_KEM_SHARED_SECRET_BYTES),
        ),
      );
    } finally {
      secretFree(module, sharedSecretPtr, ML_KEM_SHARED_SECRET_BYTES);
      publicFree(module, ciphertextPtr);
      secretFree(module, secretKeyPtr, ML_KEM_768_SECRET_KEY_BYTES);
    }
  }
}

export const createMlKem768Backend = (module: LibCrypto): MlKem768Backend =>
  new WasmMlKem768Backend(module);
