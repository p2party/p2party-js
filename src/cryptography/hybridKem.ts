import { fillRandomBytesInto } from "./random";
import { snapshotByteInput } from "./byteInput";
import {
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_ENCAPS_RANDOM_BYTES,
  ML_KEM_KEYPAIR_RANDOM_BYTES,
  ML_KEM_768_SUITE,
  createMlKemBackend,
} from "./mlkem";
import { sha3_256, shake256 } from "./fips202";
import { crypto_scalarmult_curve25519_SCALARBYTES } from "./interfaces";
import {
  X25519RejectedPublicPointError,
  x25519Dh,
  x25519PublicFromSecret,
} from "./x25519";
import {
  MLKEM768_X25519_SEED_BYTES,
  MLKEM768_X25519_SUITE,
} from "./hybridKemSuite";

import type { LibCrypto } from "./libcrypto";
import type {
  DeterministicMlKemBackend,
  MlKemDecapsulation,
  MlKemEncapsulation,
  MlKemKeyPair,
} from "./mlkem";

export {
  MLKEM768_X25519_CIPHERTEXT_BYTES,
  MLKEM768_X25519_PUBLIC_KEY_BYTES,
  MLKEM768_X25519_RANDOM_BYTES,
  MLKEM768_X25519_SEED_BYTES,
  MLKEM768_X25519_SECRET_KEY_BYTES,
  MLKEM768_X25519_SHARED_SECRET_BYTES,
  MLKEM768_X25519_SUITE,
} from "./hybridKemSuite";

const MLKEM768_X25519_EXPANDED_SEED_BYTES =
  ML_KEM_KEYPAIR_RANDOM_BYTES + crypto_scalarmult_curve25519_SCALARBYTES;
const MLKEM768_X25519_LABEL = Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c);

export type MlKem768X25519KeyPair = MlKemKeyPair;
export type MlKem768X25519Encapsulation = MlKemEncapsulation;
export type MlKem768X25519Decapsulation = MlKemDecapsulation;

/**
 * A correctly framed peer ciphertext is not a valid ciphertext for this
 * hybrid KEM. Infrastructure and local-key failures use their original errors.
 */
export class HybridKemInvalidCiphertextError extends Error {
  override readonly name = "HybridKemInvalidCiphertextError";

  constructor() {
    super("MLKEM768-X25519 rejected an invalid ciphertext");
  }
}

export interface MlKem768X25519Backend {
  readonly suite: typeof MLKEM768_X25519_SUITE;
  generateKeyPair(): Promise<MlKem768X25519KeyPair>;
  deriveKeyPair(seed: Uint8Array): Promise<MlKem768X25519KeyPair>;
  encapsulate(publicKey: Uint8Array): Promise<MlKem768X25519Encapsulation>;
  encapsulateDeterministically(
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): Promise<MlKem768X25519Encapsulation>;
  decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKem768X25519Decapsulation>;
}

const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const makeKeyPair = (
  publicKey: Uint8Array,
  secretKey: Uint8Array,
): MlKem768X25519KeyPair => {
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
): MlKem768X25519Encapsulation => {
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

const makeDecapsulation = (
  sharedSecret: Uint8Array,
): MlKem768X25519Decapsulation => {
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

class WasmMlKem768X25519Backend implements MlKem768X25519Backend {
  readonly #module: LibCrypto;
  readonly #mlKem: DeterministicMlKemBackend<768>;
  readonly suite = MLKEM768_X25519_SUITE;

  constructor(module: LibCrypto) {
    this.#module = module;
    this.#mlKem = createMlKemBackend(module, ML_KEM_768_SUITE);
  }

  generateKeyPair(): Promise<MlKem768X25519KeyPair> {
    const seed = new Uint8Array(MLKEM768_X25519_SEED_BYTES);
    try {
      fillRandomBytesInto(seed);
      return this.#deriveOwnedSeed(seed);
    } catch (error) {
      seed.fill(0);
      throw error;
    }
  }

  deriveKeyPair(seed: Uint8Array): Promise<MlKem768X25519KeyPair> {
    const privateSeed = snapshotByteInput(
      seed,
      `${this.suite.standardName} seed`,
      { exactLength: this.suite.seedBytes },
    );
    return this.#deriveOwnedSeed(privateSeed);
  }

  encapsulate(publicKey: Uint8Array): Promise<MlKem768X25519Encapsulation> {
    const privatePublicKey = snapshotByteInput(
      publicKey,
      `${this.suite.standardName} public key`,
      { exactLength: this.suite.publicKeyBytes },
    );
    const randomness = new Uint8Array(this.suite.randomnessBytes);
    try {
      fillRandomBytesInto(randomness);
      return this.#encapsulateOwned(privatePublicKey, randomness);
    } catch (error) {
      randomness.fill(0);
      throw error;
    }
  }

  encapsulateDeterministically(
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): Promise<MlKem768X25519Encapsulation> {
    const privatePublicKey = snapshotByteInput(
      publicKey,
      `${this.suite.standardName} public key`,
      { exactLength: this.suite.publicKeyBytes },
    );
    const privateRandomness = snapshotByteInput(
      randomness,
      `${this.suite.standardName} encapsulation randomness`,
      { exactLength: this.suite.randomnessBytes },
    );
    return this.#encapsulateOwned(privatePublicKey, privateRandomness);
  }

  decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKem768X25519Decapsulation> {
    const privateCiphertext = snapshotByteInput(
      ciphertext,
      `${this.suite.standardName} ciphertext`,
      { exactLength: this.suite.ciphertextBytes },
    );
    const privateSecretKey = snapshotByteInput(
      secretKey,
      `${this.suite.standardName} secret key`,
      { exactLength: this.suite.secretKeyBytes },
    );
    return this.#decapsulateOwned(privateCiphertext, privateSecretKey);
  }

  async #deriveOwnedSeed(seed: Uint8Array): Promise<MlKem768X25519KeyPair> {
    let expandedSeed: Uint8Array | undefined;
    let mlKemKeyPair: MlKemKeyPair | undefined;
    let returnedSecretKey: Uint8Array | undefined;
    let transferred = false;

    try {
      await Promise.resolve();
      expandedSeed = shake256(
        seed,
        MLKEM768_X25519_EXPANDED_SEED_BYTES,
        this.#module,
      );
      mlKemKeyPair = await this.#mlKem.deriveKeyPair(
        expandedSeed.subarray(0, ML_KEM_KEYPAIR_RANDOM_BYTES),
      );
      const x25519PublicKey = x25519PublicFromSecret(
        expandedSeed.subarray(ML_KEM_KEYPAIR_RANDOM_BYTES),
        this.#module,
      );
      const publicKey = concatenate(mlKemKeyPair.publicKey, x25519PublicKey);
      returnedSecretKey = Uint8Array.from(seed);
      const result = makeKeyPair(publicKey, returnedSecretKey);
      transferred = true;
      return result;
    } finally {
      mlKemKeyPair?.destroy();
      expandedSeed?.fill(0);
      seed.fill(0);
      if (!transferred) returnedSecretKey?.fill(0);
    }
  }

  async #encapsulateOwned(
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): Promise<MlKem768X25519Encapsulation> {
    let mlKemEncapsulation: MlKemEncapsulation | undefined;
    let x25519SharedSecret: Uint8Array | undefined;
    let combinerInput: Uint8Array | undefined;
    let hybridSharedSecret: Uint8Array | undefined;
    let transferred = false;

    try {
      await Promise.resolve();
      const mlKemPublicKey = publicKey.subarray(0, ML_KEM_768_PUBLIC_KEY_BYTES);
      const x25519PublicKey = publicKey.subarray(ML_KEM_768_PUBLIC_KEY_BYTES);
      const mlKemRandomness = randomness.subarray(
        0,
        ML_KEM_ENCAPS_RANDOM_BYTES,
      );
      const x25519SecretKey = randomness.subarray(ML_KEM_ENCAPS_RANDOM_BYTES);

      mlKemEncapsulation = await this.#mlKem.encapsulateDeterministically(
        mlKemPublicKey,
        mlKemRandomness,
      );
      const x25519Ciphertext = x25519PublicFromSecret(
        x25519SecretKey,
        this.#module,
      );
      x25519SharedSecret = x25519Dh(
        x25519SecretKey,
        x25519PublicKey,
        this.#module,
      );
      combinerInput = concatenate(
        mlKemEncapsulation.sharedSecret,
        x25519SharedSecret,
        x25519Ciphertext,
        x25519PublicKey,
        MLKEM768_X25519_LABEL,
      );
      hybridSharedSecret = sha3_256(combinerInput, this.#module);
      const result = makeEncapsulation(
        concatenate(mlKemEncapsulation.ciphertext, x25519Ciphertext),
        hybridSharedSecret,
      );
      transferred = true;
      return result;
    } finally {
      mlKemEncapsulation?.destroy();
      x25519SharedSecret?.fill(0);
      combinerInput?.fill(0);
      randomness.fill(0);
      if (!transferred) hybridSharedSecret?.fill(0);
    }
  }

  async #decapsulateOwned(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKem768X25519Decapsulation> {
    let expandedSeed: Uint8Array | undefined;
    let mlKemKeyPair: MlKemKeyPair | undefined;
    let mlKemDecapsulation: MlKemDecapsulation | undefined;
    let x25519SharedSecret: Uint8Array | undefined;
    let combinerInput: Uint8Array | undefined;
    let hybridSharedSecret: Uint8Array | undefined;
    let transferred = false;

    try {
      await Promise.resolve();
      expandedSeed = shake256(
        secretKey,
        MLKEM768_X25519_EXPANDED_SEED_BYTES,
        this.#module,
      );
      mlKemKeyPair = await this.#mlKem.deriveKeyPair(
        expandedSeed.subarray(0, ML_KEM_KEYPAIR_RANDOM_BYTES),
      );

      const x25519SecretKey = expandedSeed.subarray(
        ML_KEM_KEYPAIR_RANDOM_BYTES,
      );
      const x25519PublicKey = x25519PublicFromSecret(
        x25519SecretKey,
        this.#module,
      );
      const mlKemCiphertext = ciphertext.subarray(
        0,
        ML_KEM_768_CIPHERTEXT_BYTES,
      );
      const x25519Ciphertext = ciphertext.subarray(ML_KEM_768_CIPHERTEXT_BYTES);

      mlKemDecapsulation = await this.#mlKem.decapsulate(
        mlKemCiphertext,
        mlKemKeyPair.secretKey,
      );
      try {
        x25519SharedSecret = x25519Dh(
          x25519SecretKey,
          x25519Ciphertext,
          this.#module,
        );
      } catch (error) {
        if (error instanceof X25519RejectedPublicPointError)
          throw new HybridKemInvalidCiphertextError();
        throw error;
      }
      combinerInput = concatenate(
        mlKemDecapsulation.sharedSecret,
        x25519SharedSecret,
        x25519Ciphertext,
        x25519PublicKey,
        MLKEM768_X25519_LABEL,
      );
      hybridSharedSecret = sha3_256(combinerInput, this.#module);
      const result = makeDecapsulation(hybridSharedSecret);
      transferred = true;
      return result;
    } finally {
      mlKemDecapsulation?.destroy();
      mlKemKeyPair?.destroy();
      expandedSeed?.fill(0);
      x25519SharedSecret?.fill(0);
      combinerInput?.fill(0);
      secretKey.fill(0);
      if (!transferred) hybridSharedSecret?.fill(0);
    }
  }
}

export const createMlKem768X25519Backend = (
  module: LibCrypto,
): MlKem768X25519Backend => new WasmMlKem768X25519Backend(module);
