/**
 * Internal, owned Ed25519 secret-key capture shared by local custody handles.
 *
 * This module deliberately exposes no process-local capability and no signing
 * operation. Callers must keep the returned material behind their own opaque
 * WeakMap-backed custody boundary and wipe it when that custody is retired.
 */

import { snapshotByteInput } from "../cryptography/byteInput";
import { keyPairFromSeed } from "../cryptography/ed25519";
import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../cryptography/interfaces";
import { bytesEqual } from "./canonicalSchema";

import type { SignKeyPair } from "../cryptography/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";

export interface OwnedLocalEd25519KeyMaterial {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface CaptureConsistentLocalEd25519KeyMaterialOptions {
  readonly module: LibCrypto;
  readonly secretKey: Uint8Array;
  readonly inputLabel: string;
  /** Optional synchronous validation after secret capture and before await. */
  readonly validateBeforeDerivation?: () => void;
  readonly rejectInconsistentPublicSuffix: () => never;
}

/**
 * Own a 64-byte Ed25519 secret before the first await and verify its public
 * suffix by deriving the key pair from its seed.
 */
export const captureConsistentLocalEd25519KeyMaterial = async (
  options: CaptureConsistentLocalEd25519KeyMaterialOptions,
): Promise<OwnedLocalEd25519KeyMaterial> => {
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
    if (!bytesEqual(derivedKeyPair.secretKey, ownedSecretKey))
      return options.rejectInconsistentPublicSuffix();

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

export const wipeOwnedLocalEd25519KeyMaterial = (
  material: OwnedLocalEd25519KeyMaterial,
): void => {
  material.secretKey.fill(0);
};
