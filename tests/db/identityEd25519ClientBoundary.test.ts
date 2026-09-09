import { describe, expect, test } from "bun:test";

import {
  readIdentityEd25519AtClientBoundary,
  wipeUnclaimedWorkerSecret,
  writeIdentityEd25519AtClientBoundary,
} from "../../src/db/identityEd25519ClientBoundary";

import type { IdentityEd25519KeyMaterial } from "../../src/db/types";

const vectors = [
  {
    seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  },
  {
    seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  },
] as const;

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const identity = (
  vector: (typeof vectors)[number],
): IdentityEd25519KeyMaterial => {
  const pub = bytes(vector.pub);
  const secret = new Uint8Array(64);
  secret.set(bytes(vector.seed));
  secret.set(pub, 32);
  return {
    pub: Uint8Array.from(pub).buffer,
    secret: Uint8Array.from(secret).buffer,
  };
};

const copy = (value: ArrayBuffer): Uint8Array =>
  Uint8Array.from(new Uint8Array(value));

const isZero = (value: ArrayBuffer): boolean =>
  [...new Uint8Array(value)].every((byte) => byte === 0);

describe("Ed25519 identity client boundary", () => {
  test("accepts a seed-consistent worker value and its non-zero u64 revision", async () => {
    const stored = identity(vectors[0]);
    const result = await readIdentityEd25519AtClientBoundary(async () => ({
      ...stored,
      recordRevision: 7n,
    }));

    expect(result?.recordRevision).toBe(7n);
    expect(copy(result!.pub)).toEqual(copy(stored.pub));
    expect(copy(result!.secret)).toEqual(copy(stored.secret));
  });

  test("rejects seed-A/public-B worker output and wipes the delivered secret", async () => {
    const seedOwner = identity(vectors[0]);
    const suffixOwner = identity(vectors[1]);
    const forgedSecret = new Uint8Array(64);
    forgedSecret.set(new Uint8Array(seedOwner.secret).subarray(0, 32));
    forgedSecret.set(new Uint8Array(suffixOwner.pub), 32);
    const delivered = {
      pub: suffixOwner.pub,
      secret: forgedSecret.buffer,
      recordRevision: 1n,
    };

    await expect(
      readIdentityEd25519AtClientBoundary(async () => delivered),
    ).rejects.toThrow("inconsistent with its seed");
    expect(isZero(delivered.secret)).toBe(true);
  });

  test("rejects a mismatched public field and wipes the delivered secret", async () => {
    const first = identity(vectors[0]);
    const second = identity(vectors[1]);
    const delivered = {
      pub: second.pub,
      secret: first.secret,
      recordRevision: 1n,
    };

    await expect(
      readIdentityEd25519AtClientBoundary(async () => delivered),
    ).rejects.toThrow("public key does not match");
    expect(isZero(delivered.secret)).toBe(true);
  });

  test("rejects non-positive revisions and wipes secret bytes before returning", async () => {
    const stored = identity(vectors[0]);
    const delivered = { ...stored, recordRevision: -1n };

    await expect(
      readIdentityEd25519AtClientBoundary(async () => delivered),
    ).rejects.toThrow("non-zero uint64");
    expect(isZero(delivered.secret)).toBe(true);
  });

  test("copies valid caller material into a transferred worker-owned message", async () => {
    const caller = identity(vectors[0]);
    const callerPub = copy(caller.pub);
    const callerSecret = copy(caller.secret);
    let workerCopy: IdentityEd25519KeyMaterial | undefined;

    const revision = await writeIdentityEd25519AtClientBoundary(
      caller,
      (owned, transfer) => {
        expect(owned.pub).not.toBe(caller.pub);
        expect(owned.secret).not.toBe(caller.secret);
        expect(transfer).toEqual([owned.pub, owned.secret]);
        workerCopy = structuredClone(owned, { transfer });
        expect(owned.pub.byteLength).toBe(0);
        expect(owned.secret.byteLength).toBe(0);
        return 9n;
      },
    );

    expect(revision).toBe(9n);
    expect(copy(workerCopy!.pub)).toEqual(callerPub);
    expect(copy(workerCopy!.secret)).toEqual(callerSecret);
    expect(copy(caller.pub)).toEqual(callerPub);
    expect(copy(caller.secret)).toEqual(callerSecret);
  });

  test("wipes the owned message secret after a synchronous post failure", async () => {
    const caller = identity(vectors[0]);
    const callerSecret = copy(caller.secret);
    let ownedSecret: ArrayBuffer | undefined;

    await expect(
      writeIdentityEd25519AtClientBoundary(caller, (owned) => {
        ownedSecret = owned.secret;
        throw new Error("structured clone failed");
      }),
    ).rejects.toThrow("structured clone failed");

    expect(isZero(ownedSecret!)).toBe(true);
    expect(copy(caller.secret)).toEqual(callerSecret);
  });

  test("wipes the owned message secret when the worker bundle is unavailable", async () => {
    const caller = identity(vectors[0]);
    const callerSecret = copy(caller.secret);
    let ownedSecret: ArrayBuffer | undefined;

    await expect(
      writeIdentityEd25519AtClientBoundary(caller, (owned) => {
        ownedSecret = owned.secret;
        return Promise.reject(new Error("database worker bundle is missing"));
      }),
    ).rejects.toThrow("worker bundle is missing");

    expect(isZero(ownedSecret!)).toBe(true);
    expect(copy(caller.secret)).toEqual(callerSecret);
  });

  test("rejects an invalid worker revision and wipes an untransferred copy", async () => {
    const caller = identity(vectors[0]);
    let ownedSecret: ArrayBuffer | undefined;

    await expect(
      writeIdentityEd25519AtClientBoundary(caller, (owned) => {
        ownedSecret = owned.secret;
        return 0n;
      }),
    ).rejects.toThrow("non-zero uint64");

    expect(isZero(ownedSecret!)).toBe(true);
  });

  test("rejects inconsistent caller material without invoking the writer", async () => {
    const caller = identity(vectors[0]);
    const other = identity(vectors[1]);
    new Uint8Array(caller.secret).set(new Uint8Array(other.pub), 32);
    const callerSecret = copy(caller.secret);
    let invoked = false;

    await expect(
      writeIdentityEd25519AtClientBoundary(caller, () => {
        invoked = true;
        return 1n;
      }),
    ).rejects.toThrow("inconsistent with its seed");

    expect(invoked).toBe(false);
    expect(copy(caller.secret)).toEqual(callerSecret);
  });

  test("wipes a late worker result whose pending owner no longer exists", () => {
    const late = identity(vectors[0]);

    wipeUnclaimedWorkerSecret(late);

    expect(isZero(late.secret)).toBe(true);
  });
});
