/**
 * Internal, owned Ed25519 secret-key capture shared by trusted local
 * persistence and custody boundaries.
 *
 * This module deliberately exposes no process-local capability and no signing
 * operation. Callers must keep the returned material behind their own trusted
 * boundary and wipe it when that ownership ends.
 */

import { snapshotByteInput } from "./byteInput";
import { keyPairFromSeed } from "./ed25519";
import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "./interfaces";

import type { SignKeyPair } from "./interfaces";
import type { LibCrypto } from "./libcrypto";

export interface OwnedEd25519KeyMaterial {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface CaptureConsistentEd25519KeyMaterialOptions {
  readonly module?: LibCrypto;
  readonly secretKey: Uint8Array;
  readonly inputLabel: string;
  /** Optional synchronous validation after secret capture and before await. */
  readonly validateBeforeDerivation?: () => void;
  readonly rejectInconsistentSecretKey: () => never;
}

/**
 * Own a 64-byte Ed25519 secret before the first await and verify its public
 * suffix by deriving the key pair from its seed.
 */
export const captureConsistentEd25519KeyMaterial = async (
  options: CaptureConsistentEd25519KeyMaterialOptions,
): Promise<OwnedEd25519KeyMaterial> => {
  let ownedSecretKey: Uint8Array | undefined;
  let derivedKeyPair: SignKeyPair | undefined;
  let transferred = false;

  try {
    ownedSecretKey = snapshotByteInput(options.secretKey, options.inputLabel, {
      exactLength: crypto_sign_ed25519_SECRETKEYBYTES,
    });
    options.validateBeforeDerivation?.();
    derivedKeyPair = await keyPairFromSeed(
      ownedSecretKey.subarray(0, crypto_sign_ed25519_SEEDBYTES),
      options.module,
    );
    if (!equalBytes(derivedKeyPair.secretKey, ownedSecretKey))
      return options.rejectInconsistentSecretKey();

    const material = {
      secretKey: ownedSecretKey,
      publicKey: Uint8Array.from(derivedKeyPair.publicKey),
    };
    transferred = true;
    return material;
  } finally {
    derivedKeyPair?.secretKey.fill(0);
    if (!transferred) ownedSecretKey?.fill(0);
  }
};

export const wipeOwnedEd25519KeyMaterial = (
  material: OwnedEd25519KeyMaterial,
): void => {
  material.secretKey.fill(0);
};

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++)
    difference |= left[index] ^ right[index];
  return difference === 0;
};
