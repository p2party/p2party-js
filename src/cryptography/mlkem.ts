import { zeroFree } from "../utils/zeroFree";

import { fillRandomBytesInto } from "./random";

import type { LibCrypto } from "./libcrypto";

export type MlKemParameterSet = 512 | 768 | 1024;

export const ML_KEM_512_PUBLIC_KEY_BYTES = 800;
export const ML_KEM_512_SECRET_KEY_BYTES = 1632;
export const ML_KEM_512_CIPHERTEXT_BYTES = 768;

export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;

export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;
export const ML_KEM_1024_SECRET_KEY_BYTES = 3168;
export const ML_KEM_1024_CIPHERTEXT_BYTES = 1568;

export const ML_KEM_SHARED_SECRET_BYTES = 32;
export const ML_KEM_KEYPAIR_RANDOM_BYTES = 64;
export const ML_KEM_ENCAPS_RANDOM_BYTES = 32;

type MlKemKeyPairExport<P extends MlKemParameterSet> = `_mlkem${P}_keypair`;
type MlKemEncapsExport<P extends MlKemParameterSet> = `_mlkem${P}_encaps`;
type MlKemDecapsExport<P extends MlKemParameterSet> = `_mlkem${P}_decaps`;

/**
 * Complete runtime description of one FIPS 203 parameter set.
 *
 * The sizes are carried with the selected suite so callers cannot
 * accidentally validate an ML-KEM-512 key with ML-KEM-768 constants.
 */
export interface MlKemSuiteDescriptor<
  P extends MlKemParameterSet = MlKemParameterSet,
> {
  readonly parameterSet: P;
  readonly standardName: `ML-KEM-${P}`;
  readonly publicKeyBytes: number;
  readonly secretKeyBytes: number;
  readonly ciphertextBytes: number;
  readonly sharedSecretBytes: typeof ML_KEM_SHARED_SECRET_BYTES;
  readonly keyPairRandomBytes: typeof ML_KEM_KEYPAIR_RANDOM_BYTES;
  readonly encapsRandomBytes: typeof ML_KEM_ENCAPS_RANDOM_BYTES;
  readonly wasmExports: {
    readonly keypair: MlKemKeyPairExport<P>;
    readonly encaps: MlKemEncapsExport<P>;
    readonly decaps: MlKemDecapsExport<P>;
  };
}

const freezeSuite = <P extends MlKemParameterSet>(
  suite: MlKemSuiteDescriptor<P>,
): Readonly<MlKemSuiteDescriptor<P>> =>
  Object.freeze({
    ...suite,
    wasmExports: Object.freeze({ ...suite.wasmExports }),
  });

export const ML_KEM_512_SUITE = freezeSuite({
  parameterSet: 512,
  standardName: "ML-KEM-512",
  publicKeyBytes: ML_KEM_512_PUBLIC_KEY_BYTES,
  secretKeyBytes: ML_KEM_512_SECRET_KEY_BYTES,
  ciphertextBytes: ML_KEM_512_CIPHERTEXT_BYTES,
  sharedSecretBytes: ML_KEM_SHARED_SECRET_BYTES,
  keyPairRandomBytes: ML_KEM_KEYPAIR_RANDOM_BYTES,
  encapsRandomBytes: ML_KEM_ENCAPS_RANDOM_BYTES,
  wasmExports: {
    keypair: "_mlkem512_keypair",
    encaps: "_mlkem512_encaps",
    decaps: "_mlkem512_decaps",
  },
} satisfies MlKemSuiteDescriptor<512>);

export const ML_KEM_768_SUITE = freezeSuite({
  parameterSet: 768,
  standardName: "ML-KEM-768",
  publicKeyBytes: ML_KEM_768_PUBLIC_KEY_BYTES,
  secretKeyBytes: ML_KEM_768_SECRET_KEY_BYTES,
  ciphertextBytes: ML_KEM_768_CIPHERTEXT_BYTES,
  sharedSecretBytes: ML_KEM_SHARED_SECRET_BYTES,
  keyPairRandomBytes: ML_KEM_KEYPAIR_RANDOM_BYTES,
  encapsRandomBytes: ML_KEM_ENCAPS_RANDOM_BYTES,
  wasmExports: {
    keypair: "_mlkem768_keypair",
    encaps: "_mlkem768_encaps",
    decaps: "_mlkem768_decaps",
  },
} satisfies MlKemSuiteDescriptor<768>);

export const ML_KEM_1024_SUITE = freezeSuite({
  parameterSet: 1024,
  standardName: "ML-KEM-1024",
  publicKeyBytes: ML_KEM_1024_PUBLIC_KEY_BYTES,
  secretKeyBytes: ML_KEM_1024_SECRET_KEY_BYTES,
  ciphertextBytes: ML_KEM_1024_CIPHERTEXT_BYTES,
  sharedSecretBytes: ML_KEM_SHARED_SECRET_BYTES,
  keyPairRandomBytes: ML_KEM_KEYPAIR_RANDOM_BYTES,
  encapsRandomBytes: ML_KEM_ENCAPS_RANDOM_BYTES,
  wasmExports: {
    keypair: "_mlkem1024_keypair",
    encaps: "_mlkem1024_encaps",
    decaps: "_mlkem1024_decaps",
  },
} satisfies MlKemSuiteDescriptor<1024>);

export const ML_KEM_SUITES = Object.freeze({
  512: ML_KEM_512_SUITE,
  768: ML_KEM_768_SUITE,
  1024: ML_KEM_1024_SUITE,
});

export const getMlKemSuite = <P extends MlKemParameterSet>(
  parameterSet: P,
): Readonly<MlKemSuiteDescriptor<P>> => {
  const suite = (
    ML_KEM_SUITES as Partial<Record<MlKemParameterSet, MlKemSuiteDescriptor>>
  )[parameterSet];
  if (suite === undefined)
    throw new RangeError(
      `unsupported ML-KEM parameter set: ${String(parameterSet)}`,
    );
  return suite as Readonly<MlKemSuiteDescriptor<P>>;
};

type MlKemKeyPairFunction = (
  publicKey: number,
  secretKey: number,
  coins64: number,
) => number;
type MlKemEncapsFunction = (
  ciphertext: number,
  sharedSecret: number,
  publicKey: number,
  coins32: number,
) => number;
type MlKemDecapsFunction = (
  sharedSecret: number,
  ciphertext: number,
  secretKey: number,
) => number;

/**
 * The deterministic ABI exported by the pinned, portable mlkem-native build.
 * JavaScript supplies all entropy; the WASM has no second RNG path.
 */
export interface MlKemModule extends LibCrypto {
  _mlkem512_keypair: MlKemKeyPairFunction;
  _mlkem512_encaps: MlKemEncapsFunction;
  _mlkem512_decaps: MlKemDecapsFunction;
  _mlkem768_keypair: MlKemKeyPairFunction;
  _mlkem768_encaps: MlKemEncapsFunction;
  _mlkem768_decaps: MlKemDecapsFunction;
  _mlkem1024_keypair: MlKemKeyPairFunction;
  _mlkem1024_encaps: MlKemEncapsFunction;
  _mlkem1024_decaps: MlKemDecapsFunction;
}

/** Compatibility type for protocol-v3 code while suite negotiation lands. */
export type MlKem768Module = LibCrypto &
  Pick<
    MlKemModule,
    "_mlkem768_keypair" | "_mlkem768_encaps" | "_mlkem768_decaps"
  >;

export interface MlKemKeyPair {
  /** A copy suitable for transport or serialization. This is not secret. */
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

export interface MlKemEncapsulation {
  /** A copy suitable for transport or serialization. This is not secret. */
  readonly ciphertext: Uint8Array;
  /** Plaintext shared-secret bytes. Mix into a KDF, then call destroy(). */
  readonly sharedSecret: Uint8Array;
  readonly destroyed: boolean;
  /** Idempotently wipes this object's sharedSecret bytes. */
  destroy(): void;
}

export interface MlKemDecapsulation {
  /** Plaintext shared-secret bytes. Mix into a KDF, then call destroy(). */
  readonly sharedSecret: Uint8Array;
  readonly destroyed: boolean;
  /** Idempotently wipes this object's sharedSecret bytes. */
  destroy(): void;
}

/**
 * Async-compatible ML-KEM API. The WASM calls are synchronous, but promises
 * allow a worker-backed implementation without changing protocol state
 * machines.
 */
export interface MlKemBackend<P extends MlKemParameterSet = MlKemParameterSet> {
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;
  generateKeyPair(): Promise<MlKemKeyPair>;
  encapsulate(publicKey: Uint8Array): Promise<MlKemEncapsulation>;
  decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKemDecapsulation>;
}

/** Compatibility aliases for the currently shipped ML-KEM-768 handshake. */
export type MlKem768KeyPair = MlKemKeyPair;
export type MlKem768Encapsulation = MlKemEncapsulation;
export type MlKem768Decapsulation = MlKemDecapsulation;
export type MlKem768Backend = MlKemBackend<768>;

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
  module: LibCrypto,
  suite: MlKemSuiteDescriptor,
  length: number,
  name: string,
): number => {
  const pointer = module._malloc(length);
  if (pointer === 0)
    throw new Error(`${suite.standardName}: failed to allocate ${name}`);
  return pointer;
};

const heapView = (
  module: LibCrypto,
  pointer: number,
  length: number,
): Uint8Array => new Uint8Array(module.wasmMemory.buffer, pointer, length);

const publicFree = (module: LibCrypto, pointer: number | undefined): void => {
  if (pointer !== undefined) module._free(pointer);
};

const secretFree = (
  module: LibCrypto,
  pointer: number | undefined,
  length: number,
): void => {
  if (pointer !== undefined)
    zeroFree(module, heapView(module, pointer, length));
};

const makeKeyPair = (
  publicKey: Uint8Array,
  secretKey: Uint8Array,
): MlKemKeyPair => {
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
): MlKemEncapsulation => {
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

const makeDecapsulation = (sharedSecret: Uint8Array): MlKemDecapsulation => {
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

interface SelectedMlKemExports {
  readonly keypair: MlKemKeyPairFunction;
  readonly encaps: MlKemEncapsFunction;
  readonly decaps: MlKemDecapsFunction;
}

const requireMlKemExports = (
  module: LibCrypto,
  suite: MlKemSuiteDescriptor,
): SelectedMlKemExports => {
  const candidate = module as unknown as Record<string, unknown>;
  const names = suite.wasmExports;
  const missing = [names.keypair, names.encaps, names.decaps].filter(
    (name) => typeof candidate[name] !== "function",
  );
  if (missing.length !== 0)
    throw new Error(
      `${suite.standardName} WASM exports are unavailable; ` +
        `rebuild libcrypto.wasm (missing ${missing.join(", ")})`,
    );
  return {
    keypair: (candidate[names.keypair] as MlKemKeyPairFunction).bind(module),
    encaps: (candidate[names.encaps] as MlKemEncapsFunction).bind(module),
    decaps: (candidate[names.decaps] as MlKemDecapsFunction).bind(module),
  };
};

class WasmMlKemBackend<P extends MlKemParameterSet> implements MlKemBackend<P> {
  readonly #module: LibCrypto;
  readonly #exports: SelectedMlKemExports;
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;

  constructor(module: LibCrypto, suite: Readonly<MlKemSuiteDescriptor<P>>) {
    this.#module = module;
    this.suite = suite;
    this.#exports = requireMlKemExports(module, suite);
  }

  async generateKeyPair(): Promise<MlKemKeyPair> {
    await Promise.resolve();
    const module = this.#module;
    const suite = this.suite;
    let publicKeyPtr: number | undefined;
    let secretKeyPtr: number | undefined;
    let coinsPtr: number | undefined;

    try {
      publicKeyPtr = checkedMalloc(
        module,
        suite,
        suite.publicKeyBytes,
        "public key",
      );
      secretKeyPtr = checkedMalloc(
        module,
        suite,
        suite.secretKeyBytes,
        "secret key",
      );
      coinsPtr = checkedMalloc(
        module,
        suite,
        suite.keyPairRandomBytes,
        "key-generation randomness",
      );

      const coins = heapView(module, coinsPtr, suite.keyPairRandomBytes);
      fillRandomBytesInto(coins);

      const result = this.#exports.keypair(
        publicKeyPtr,
        secretKeyPtr,
        coinsPtr,
      );
      if (result !== 0)
        throw new Error(
          `${suite.standardName} key generation failed (${String(result)})`,
        );

      return makeKeyPair(
        Uint8Array.from(heapView(module, publicKeyPtr, suite.publicKeyBytes)),
        Uint8Array.from(heapView(module, secretKeyPtr, suite.secretKeyBytes)),
      );
    } finally {
      publicFree(module, publicKeyPtr);
      secretFree(module, secretKeyPtr, suite.secretKeyBytes);
      secretFree(module, coinsPtr, suite.keyPairRandomBytes);
    }
  }

  async encapsulate(publicKey: Uint8Array): Promise<MlKemEncapsulation> {
    await Promise.resolve();
    const module = this.#module;
    const suite = this.suite;
    requireExactBytes(
      publicKey,
      `${suite.standardName} public key`,
      suite.publicKeyBytes,
    );

    let ciphertextPtr: number | undefined;
    let sharedSecretPtr: number | undefined;
    let publicKeyPtr: number | undefined;
    let coinsPtr: number | undefined;

    try {
      ciphertextPtr = checkedMalloc(
        module,
        suite,
        suite.ciphertextBytes,
        "ciphertext",
      );
      sharedSecretPtr = checkedMalloc(
        module,
        suite,
        suite.sharedSecretBytes,
        "shared secret",
      );
      publicKeyPtr = checkedMalloc(
        module,
        suite,
        suite.publicKeyBytes,
        "public key",
      );
      coinsPtr = checkedMalloc(
        module,
        suite,
        suite.encapsRandomBytes,
        "encapsulation randomness",
      );

      heapView(module, publicKeyPtr, suite.publicKeyBytes).set(publicKey);
      const coins = heapView(module, coinsPtr, suite.encapsRandomBytes);
      fillRandomBytesInto(coins);

      const result = this.#exports.encaps(
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr,
        coinsPtr,
      );
      if (result !== 0)
        throw new Error(
          `${suite.standardName} encapsulation failed (${String(result)})`,
        );

      return makeEncapsulation(
        Uint8Array.from(heapView(module, ciphertextPtr, suite.ciphertextBytes)),
        Uint8Array.from(
          heapView(module, sharedSecretPtr, suite.sharedSecretBytes),
        ),
      );
    } finally {
      publicFree(module, ciphertextPtr);
      secretFree(module, sharedSecretPtr, suite.sharedSecretBytes);
      publicFree(module, publicKeyPtr);
      secretFree(module, coinsPtr, suite.encapsRandomBytes);
    }
  }

  async decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKemDecapsulation> {
    await Promise.resolve();
    const module = this.#module;
    const suite = this.suite;
    requireExactBytes(
      ciphertext,
      `${suite.standardName} ciphertext`,
      suite.ciphertextBytes,
    );
    requireExactBytes(
      secretKey,
      `${suite.standardName} secret key`,
      suite.secretKeyBytes,
    );

    let sharedSecretPtr: number | undefined;
    let ciphertextPtr: number | undefined;
    let secretKeyPtr: number | undefined;

    try {
      sharedSecretPtr = checkedMalloc(
        module,
        suite,
        suite.sharedSecretBytes,
        "shared secret",
      );
      ciphertextPtr = checkedMalloc(
        module,
        suite,
        suite.ciphertextBytes,
        "ciphertext",
      );
      secretKeyPtr = checkedMalloc(
        module,
        suite,
        suite.secretKeyBytes,
        "secret key",
      );

      heapView(module, ciphertextPtr, suite.ciphertextBytes).set(ciphertext);
      heapView(module, secretKeyPtr, suite.secretKeyBytes).set(secretKey);

      const result = this.#exports.decaps(
        sharedSecretPtr,
        ciphertextPtr,
        secretKeyPtr,
      );
      if (result !== 0)
        throw new Error(
          `${suite.standardName} decapsulation failed (${String(result)})`,
        );

      return makeDecapsulation(
        Uint8Array.from(
          heapView(module, sharedSecretPtr, suite.sharedSecretBytes),
        ),
      );
    } finally {
      secretFree(module, sharedSecretPtr, suite.sharedSecretBytes);
      publicFree(module, ciphertextPtr);
      secretFree(module, secretKeyPtr, suite.secretKeyBytes);
    }
  }
}

export const createMlKemBackend = <P extends MlKemParameterSet>(
  module: LibCrypto,
  suite: Readonly<MlKemSuiteDescriptor<P>>,
): MlKemBackend<P> => {
  const canonicalSuite = getMlKemSuite(suite.parameterSet);
  if (suite !== canonicalSuite)
    throw new TypeError(
      "ML-KEM suite descriptor must be one of the exported canonical suites",
    );
  return new WasmMlKemBackend(module, canonicalSuite);
};

/**
 * Temporary compatibility factory for the protocol-v3 ML-KEM-768 wire suite.
 */
export const createMlKem768Backend = (module: LibCrypto): MlKem768Backend =>
  createMlKemBackend(module, ML_KEM_768_SUITE);
