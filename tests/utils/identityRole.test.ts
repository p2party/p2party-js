import { describe, expect, test } from "bun:test";

import {
  assertCanonicalEd25519Identity,
  isCanonicalEd25519Identity,
  isIdentityInitiator,
  shouldAcceptIncomingMain,
} from "../../src/utils/identityRole";

describe("stable identity-edge role", () => {
  test("exactly one side opens main and initiates protocol v3", () => {
    const alice = "11".repeat(32);
    const bob = "aa".repeat(32);

    expect(isIdentityInitiator(alice, bob)).toBe(true);
    expect(isIdentityInitiator(bob, alice)).toBe(false);
  });

  test("the opener rejects a duplicate remotely-created main while the receiver accepts it", () => {
    const alice = "11".repeat(32);
    const bob = "aa".repeat(32);

    expect(shouldAcceptIncomingMain(alice, bob)).toBe(false);
    expect(shouldAcceptIncomingMain(bob, alice)).toBe(true);
  });

  test("the same identity fails closed instead of assigning an ambiguous role", () => {
    const identity = "42".repeat(32);
    expect(() => isIdentityInitiator(identity, identity)).toThrow(
      /same Ed25519 identity/,
    );
  });

  test("only exact lowercase 32-byte hexadecimal identities are accepted", () => {
    const canonical = "ab".repeat(32);
    expect(() => assertCanonicalEd25519Identity(canonical)).not.toThrow();
    expect(isCanonicalEd25519Identity(canonical)).toBe(true);

    for (const malformed of [
      canonical.toUpperCase(),
      "ab".repeat(31),
      "ab".repeat(33),
      `${"ab".repeat(31)}g0`,
      `0x${canonical}`,
    ]) {
      expect(() => assertCanonicalEd25519Identity(malformed)).toThrow(
        /lowercase hexadecimal/,
      );
      expect(() => isIdentityInitiator(canonical, malformed)).toThrow(
        /lowercase hexadecimal/,
      );
      expect(isCanonicalEd25519Identity(malformed)).toBe(false);
    }
  });
});
