import { zeroFree } from "../utils/zeroFree";

import { snapshotByteInput } from "./byteInput";
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
const ML_KEM_PUBLIC_SEED_BYTES = 32;
const ML_KEM_COEFFICIENT_MODULUS = 3_329;

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

/**
 * FIPS 203 Section 7.2 modulus check for one encoded encapsulation key.
 *
 * Each three-byte group in the encoded polynomial vector contains two
 * little-endian 12-bit coefficients, both of which must be below q=3329.
 * The final 32-byte public seed is unrestricted. This pure check is shared by
 * every composed KEM so canonical ML-KEM public-key encoding has one SSOT.
 */
export const mlKemPublicKeyHasCanonicalEncoding = (
  publicKey: unknown,
  parameterSet: MlKemParameterSet,
): boolean => {
  const suite = getMlKemSuite(parameterSet);
  let privatePublicKey: Uint8Array;
  try {
    privatePublicKey = snapshotByteInput(
      publicKey,
      `${suite.standardName} public key`,
      { exactLength: suite.publicKeyBytes },
    );
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) return false;
    throw error;
  }

  try {
    const encodedPolyvecBytes = suite.publicKeyBytes - ML_KEM_PUBLIC_SEED_BYTES;
    if (encodedPolyvecBytes < 0 || encodedPolyvecBytes % 3 !== 0)
      throw new Error(`${suite.standardName} public-key geometry is invalid`);

    for (let offset = 0; offset < encodedPolyvecBytes; offset += 3) {
      const first =
        privatePublicKey[offset] | ((privatePublicKey[offset + 1] & 0x0f) << 8);
      const second =
        (privatePublicKey[offset + 1] >> 4) |
        (privatePublicKey[offset + 2] << 4);
      if (
        first >= ML_KEM_COEFFICIENT_MODULUS ||
        second >= ML_KEM_COEFFICIENT_MODULUS
      )
        return false;
    }
    return true;
  } finally {
    privatePublicKey.fill(0);
  }
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

/**
 * Real-WASM ML-KEM backend with the explicit deterministic inputs required by
 * composed, version-pinned KEMs. The ordinary backend remains the narrower
 * seam used by protocol state machines and test doubles.
 */
export interface DeterministicMlKemBackend<
  P extends MlKemParameterSet = MlKemParameterSet,
> extends MlKemBackend<P> {
  /**
   * FIPS 203 KeyGen_internal with the caller-supplied 64-byte d || z seed.
   * The seed is borrowed; this method snapshots but never wipes caller bytes.
   */
  deriveKeyPair(seed: Uint8Array): Promise<MlKemKeyPair>;
  /**
   * FIPS 203 Encaps_internal with caller-supplied 32-byte randomness.
   * Inputs are borrowed; this method snapshots but never wipes caller bytes.
   */
  encapsulateDeterministically(
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): Promise<MlKemEncapsulation>;
}

/** Compatibility aliases for the currently shipped ML-KEM-768 handshake. */
export type MlKem768KeyPair = MlKemKeyPair;
export type MlKem768Encapsulation = MlKemEncapsulation;
export type MlKem768Decapsulation = MlKemDecapsulation;
export type MlKem768Backend = MlKemBackend<768>;

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

class WasmMlKemBackend<
  P extends MlKemParameterSet,
> implements DeterministicMlKemBackend<P> {
  readonly #module: LibCrypto;
  readonly #exports: SelectedMlKemExports;
  readonly suite: Readonly<MlKemSuiteDescriptor<P>>;

  constructor(module: LibCrypto, suite: Readonly<MlKemSuiteDescriptor<P>>) {
    this.#module = module;
    this.suite = suite;
    this.#exports = requireMlKemExports(module, suite);
  }

  async generateKeyPair(): Promise<MlKemKeyPair> {
    const suite = this.suite;
    const privateSeed = new Uint8Array(suite.keyPairRandomBytes);

    try {
      fillRandomBytesInto(privateSeed);
      return this.#deriveKeyPair(privateSeed);
    } finally {
      privateSeed.fill(0);
    }
  }

  async deriveKeyPair(seed: Uint8Array): Promise<MlKemKeyPair> {
    const suite = this.suite;
    const privateSeed = snapshotByteInput(
      seed,
      `${suite.standardName} key-generation seed`,
      { exactLength: suite.keyPairRandomBytes },
    );

    // Snapshot before any allocation: `_malloc` may grow and detach a caller
    // view backed by this module's WebAssembly.Memory.
    try {
      return this.#deriveKeyPair(privateSeed);
    } finally {
      privateSeed.fill(0);
    }
  }

  #deriveKeyPair(privateSeed: Uint8Array): MlKemKeyPair {
    const module = this.#module;
    const suite = this.suite;
    let publicKeyPtr: number | undefined;
    let secretKeyPtr: number | undefined;
    let seedPtr: number | undefined;

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
      seedPtr = checkedMalloc(
        module,
        suite,
        privateSeed.length,
        "key-generation seed",
      );

      heapView(module, seedPtr, privateSeed.length).set(privateSeed);

      const result = this.#exports.keypair(publicKeyPtr, secretKeyPtr, seedPtr);
      if (result !== 0)
        throw new Error(
          `${suite.standardName} key generation failed (${String(result)})`,
        );

      return makeKeyPair(
        Uint8Array.from(heapView(module, publicKeyPtr, suite.publicKeyBytes)),
        Uint8Array.from(heapView(module, secretKeyPtr, suite.secretKeyBytes)),
      );
    } finally {
      try {
        publicFree(module, publicKeyPtr);
      } finally {
        try {
          secretFree(module, secretKeyPtr, suite.secretKeyBytes);
        } finally {
          secretFree(module, seedPtr, privateSeed.length);
        }
      }
    }
  }

  async encapsulate(publicKey: Uint8Array): Promise<MlKemEncapsulation> {
    const suite = this.suite;
    const privatePublicKey = snapshotByteInput(
      publicKey,
      `${suite.standardName} public key`,
      { exactLength: suite.publicKeyBytes },
    );

    const privateRandomness = new Uint8Array(suite.encapsRandomBytes);
    try {
      fillRandomBytesInto(privateRandomness);
      return this.#encapsulate(privatePublicKey, privateRandomness);
    } finally {
      privateRandomness.fill(0);
    }
  }

  async encapsulateDeterministically(
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): Promise<MlKemEncapsulation> {
    const suite = this.suite;
    const privatePublicKey = snapshotByteInput(
      publicKey,
      `${suite.standardName} public key`,
      { exactLength: suite.publicKeyBytes },
    );
    const privateRandomness = snapshotByteInput(
      randomness,
      `${suite.standardName} encapsulation randomness`,
      { exactLength: suite.encapsRandomBytes },
    );

    // Snapshot both borrowed inputs before `_malloc` can detach views into the
    // module's current memory buffer.
    try {
      return this.#encapsulate(privatePublicKey, privateRandomness);
    } finally {
      privateRandomness.fill(0);
    }
  }

  #encapsulate(
    privatePublicKey: Uint8Array,
    privateRandomness: Uint8Array,
  ): MlKemEncapsulation {
    const module = this.#module;
    const suite = this.suite;
    let ciphertextPtr: number | undefined;
    let sharedSecretPtr: number | undefined;
    let publicKeyPtr: number | undefined;
    let randomnessPtr: number | undefined;

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
        privatePublicKey.length,
        "public key",
      );
      randomnessPtr = checkedMalloc(
        module,
        suite,
        privateRandomness.length,
        "encapsulation randomness",
      );

      heapView(module, publicKeyPtr, privatePublicKey.length).set(
        privatePublicKey,
      );
      heapView(module, randomnessPtr, privateRandomness.length).set(
        privateRandomness,
      );

      const result = this.#exports.encaps(
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr,
        randomnessPtr,
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
      try {
        publicFree(module, ciphertextPtr);
      } finally {
        try {
          secretFree(module, sharedSecretPtr, suite.sharedSecretBytes);
        } finally {
          try {
            publicFree(module, publicKeyPtr);
          } finally {
            secretFree(module, randomnessPtr, privateRandomness.length);
          }
        }
      }
    }
  }

  async decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKemDecapsulation> {
    const suite = this.suite;
    const privateCiphertext = snapshotByteInput(
      ciphertext,
      `${suite.standardName} ciphertext`,
      { exactLength: suite.ciphertextBytes },
    );
    const privateSecretKey = snapshotByteInput(
      secretKey,
      `${suite.standardName} secret key`,
      { exactLength: suite.secretKeyBytes },
    );

    try {
      return this.#decapsulate(privateCiphertext, privateSecretKey);
    } finally {
      privateSecretKey.fill(0);
    }
  }

  #decapsulate(
    privateCiphertext: Uint8Array,
    privateSecretKey: Uint8Array,
  ): MlKemDecapsulation {
    const module = this.#module;
    const suite = this.suite;
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
        privateCiphertext.length,
        "ciphertext",
      );
      secretKeyPtr = checkedMalloc(
        module,
        suite,
        privateSecretKey.length,
        "secret key",
      );

      heapView(module, ciphertextPtr, privateCiphertext.length).set(
        privateCiphertext,
      );
      heapView(module, secretKeyPtr, privateSecretKey.length).set(
        privateSecretKey,
      );

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
      try {
        secretFree(module, sharedSecretPtr, suite.sharedSecretBytes);
      } finally {
        try {
          publicFree(module, ciphertextPtr);
        } finally {
          secretFree(module, secretKeyPtr, privateSecretKey.length);
        }
      }
    }
  }
}

export const createMlKemBackend = <P extends MlKemParameterSet>(
  module: LibCrypto,
  suite: Readonly<MlKemSuiteDescriptor<P>>,
): DeterministicMlKemBackend<P> => {
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
