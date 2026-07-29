/**
 * Process-local custody for one persisted stable Ed25519 identity key.
 *
 * Trusted key storage constructs this handle from the secret key and its
 * non-reused record revision. The public key is derived rather than accepted
 * from the caller, so later receiver-key custody cannot bind an unrelated
 * public identity. This internal module is absent from the package barrel.
 */

import { snapshotByteInput } from "../cryptography/byteInput";
import { bytesEqual } from "./canonicalSchema";
import { keyPairFromSeed } from "../cryptography/ed25519";
import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../cryptography/interfaces";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { SignKeyPair } from "../cryptography/interfaces";

const U64_MAX = 0xffffffffffffffffn;

declare const localStableIdentityCustodyBrand: unique symbol;

/** Opaque live custody for one exact persisted stable identity key record. */
export interface LocalStableIdentityCustodyV1 {
  readonly [localStableIdentityCustodyBrand]: true;
}

export interface CreateLocalStableIdentityCustodyOptionsV1 {
  readonly module: LibCrypto;
  readonly stableEd25519SecretKey: Uint8Array;
  readonly localIdentityKeyRecordRevision: bigint;
}

export interface LocalStableIdentityCustodySnapshotV1 {
  readonly version: 1;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly localIdentityKeyRecordRevision: bigint;
}

export class LocalStableIdentityCustodyError extends Error {
  override readonly name = "LocalStableIdentityCustodyError";

  constructor(message: string) {
    super(`localStableIdentityCustody: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new LocalStableIdentityCustodyError(message);
};

interface PrivateLocalStableIdentityCustody {
  readonly stableEd25519SecretKey: Uint8Array;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly localIdentityKeyRecordRevision: bigint;
}

const custodyStates = new WeakMap<object, PrivateLocalStableIdentityCustody>();
const genuineCustodies = new WeakSet<object>();

const requireU64 = (name: string, value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${name} must be an unsigned 64-bit integer`);
  return value;
};

const requireCustodyState = (
  custody: LocalStableIdentityCustodyV1,
): PrivateLocalStableIdentityCustody => {
  if (typeof custody !== "object" || custody === null)
    return fail("custody must be a genuine live process-local handle");
  const state = custodyStates.get(custody);
  if (state === undefined)
    return fail("custody must be a genuine live process-local handle");
  return state;
};

/**
 * Copy one stable secret and derive its public identity before minting custody.
 *
 * All caller-controlled values are captured before the first await. Mutating
 * or wiping the caller's secret after invocation therefore cannot change the
 * key held by the returned capability.
 */
export const createLocalStableIdentityCustodyV1 = async (
  options: CreateLocalStableIdentityCustodyOptionsV1,
): Promise<LocalStableIdentityCustodyV1> => {
  const cryptoModule = options.module;
  let privateSecretKey: Uint8Array | undefined;
  let derivedKeyPair: SignKeyPair | undefined;
  let transferred = false;

  try {
    privateSecretKey = snapshotByteInput(
      options.stableEd25519SecretKey,
      "localStableIdentityCustody: stable Ed25519 secret key",
      { exactLength: crypto_sign_ed25519_SECRETKEYBYTES },
    );
    const localIdentityKeyRecordRevision = requireU64(
      "localIdentityKeyRecordRevision",
      options.localIdentityKeyRecordRevision,
    );
    derivedKeyPair = await keyPairFromSeed(
      privateSecretKey.subarray(0, crypto_sign_ed25519_SEEDBYTES),
      cryptoModule,
    );
    if (!bytesEqual(derivedKeyPair.secretKey, privateSecretKey))
      return fail(
        "stable Ed25519 secret key has an inconsistent public suffix",
      );

    const handle = Object.freeze({}) as LocalStableIdentityCustodyV1;
    genuineCustodies.add(handle);
    custodyStates.set(handle, {
      stableEd25519SecretKey: privateSecretKey,
      localStableEd25519PublicKey: Uint8Array.from(derivedKeyPair.publicKey),
      localIdentityKeyRecordRevision,
    });
    transferred = true;
    return handle;
  } finally {
    derivedKeyPair?.secretKey.fill(0);
    if (!transferred) privateSecretKey?.fill(0);
  }
};

/** Return a fresh non-secret projection and assert that custody is still live. */
export const snapshotLocalStableIdentityCustodyV1 = (
  custody: LocalStableIdentityCustodyV1,
): LocalStableIdentityCustodySnapshotV1 => {
  const state = requireCustodyState(custody);
  return {
    version: 1,
    localStableEd25519PublicKey: Uint8Array.from(
      state.localStableEd25519PublicKey,
    ),
    localIdentityKeyRecordRevision: state.localIdentityKeyRecordRevision,
  };
};

/**
 * Wipe stable identity custody after its persisted key record is retired.
 *
 * Destruction is idempotent for a genuine handle. Dependent receiver custody
 * retains the exact handle and therefore fails closed after this transition.
 */
export const destroyLocalStableIdentityCustodyV1 = (
  custody: LocalStableIdentityCustodyV1,
): void => {
  if (
    typeof custody !== "object" ||
    custody === null ||
    !genuineCustodies.has(custody)
  )
    return fail("custody must be a genuine process-local handle");
  const state = custodyStates.get(custody);
  if (state === undefined) return;
  state.stableEd25519SecretKey.fill(0);
  custodyStates.delete(custody);
};
