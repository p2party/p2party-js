/**
 * Main-realm ownership boundary for the persisted Ed25519 identity.
 *
 * The database worker only wraps bytes and allocates revisions. Seed
 * derivation stays here so it uses the application's one configured
 * cryptography/WASM source.
 */

import {
  captureConsistentEd25519KeyMaterial,
  wipeOwnedEd25519KeyMaterial,
} from "../cryptography/ownedEd25519KeyMaterial";

import type { IdentityEd25519, IdentityEd25519KeyMaterial } from "./types";

const UINT64_MAX = 0xffff_ffff_ffff_ffffn;

type IdentityWriter = (
  identity: IdentityEd25519KeyMaterial,
  transfer: Transferable[],
) => Promise<unknown> | unknown;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++)
    difference |= left[index] ^ right[index];
  return difference === 0;
};

const requireRecord = (value: unknown): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Ed25519 identity is malformed");
  return value as Record<string, unknown>;
};

const requireRevision = (value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 1n || value > UINT64_MAX)
    throw new Error("Ed25519 identity revision must be a non-zero uint64");
  return value;
};

const captureConsistentIdentity = async (
  value: unknown,
): Promise<{
  readonly input: IdentityEd25519KeyMaterial;
  readonly material: Awaited<
    ReturnType<typeof captureConsistentEd25519KeyMaterial>
  >;
}> => {
  const record = requireRecord(value);
  const pub = record.pub;
  const secret = record.secret;
  if (
    !(pub instanceof ArrayBuffer) ||
    !(secret instanceof ArrayBuffer) ||
    pub.byteLength !== 32 ||
    secret.byteLength !== 64
  )
    throw new Error("Ed25519 identity has invalid key lengths");

  const publicKey = Uint8Array.from(new Uint8Array(pub));
  const material = await captureConsistentEd25519KeyMaterial({
    secretKey: new Uint8Array(secret),
    inputLabel: "db: Ed25519 identity secret key",
    rejectInconsistentSecretKey: () => {
      throw new Error("Ed25519 secret key is inconsistent with its seed");
    },
  });
  if (!bytesEqual(publicKey, material.publicKey)) {
    wipeOwnedEd25519KeyMaterial(material);
    throw new Error("Ed25519 public key does not match the secret key");
  }
  return { input: { pub, secret }, material };
};

export const wipeUnclaimedWorkerSecret = (value: unknown): void => {
  if (typeof value !== "object" || value === null) return;
  const descriptor = Object.getOwnPropertyDescriptor(value, "secret");
  if (
    descriptor &&
    "value" in descriptor &&
    descriptor.value instanceof ArrayBuffer &&
    descriptor.value.byteLength !== 0
  )
    new Uint8Array(descriptor.value).fill(0);
};

export const readIdentityEd25519AtClientBoundary = async (
  read: () => Promise<unknown>,
): Promise<IdentityEd25519 | undefined> => {
  const value = await read();
  if (value === undefined) return undefined;

  try {
    const record = requireRecord(value);
    const recordRevision = requireRevision(record.recordRevision);
    const { input, material } = await captureConsistentIdentity(value);
    wipeOwnedEd25519KeyMaterial(material);
    return { ...input, recordRevision };
  } catch (error) {
    wipeUnclaimedWorkerSecret(value);
    throw error;
  }
};

export const writeIdentityEd25519AtClientBoundary = async (
  identity: IdentityEd25519KeyMaterial,
  write: IdentityWriter,
): Promise<bigint> => {
  const { material } = await captureConsistentIdentity(identity);
  let transferredSecret: ArrayBuffer | undefined;
  try {
    const publicKey = Uint8Array.from(material.publicKey).buffer;
    transferredSecret = Uint8Array.from(material.secretKey).buffer;
    const revision = await write(
      { pub: publicKey, secret: transferredSecret },
      [publicKey, transferredSecret],
    );
    return requireRevision(revision);
  } finally {
    wipeOwnedEd25519KeyMaterial(material);
    if (transferredSecret !== undefined && transferredSecret.byteLength !== 0)
      new Uint8Array(transferredSecret).fill(0);
  }
};
