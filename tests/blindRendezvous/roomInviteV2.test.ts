import { describe, expect, test } from "bun:test";

import {
  decodeRoomCapability,
  decodeRoomInviteFragment,
  encodeRoomCapabilityBase64Url,
  encodeRoomInviteFragment,
  normalizeRoomCapability,
} from "../../src/roomInvite";
import { base64urlNoPad } from "../../src/blindRendezvous/derivations";
import {
  BlindStoreAliasResolutionError,
  LegacySignalingAdapterUnavailableError,
  MAX_INVITE_POLICY_BYTES,
  encodeBlindRoomInviteV2Default,
  encodeBlindRoomInviteV2WithPolicy,
  parseRoomInvite,
  resolveInviteRoomPolicy,
} from "../../src/blindRendezvous/roomInviteV2";
import {
  DEFAULT_BLIND_POLICY_V4_0,
  encodeRoomPolicyV4,
  roomPoliciesEqualV4,
} from "../../src/blindRendezvous/roomPolicyV4";

import type { BlindRoomInviteV2 } from "../../src/blindRendezvous/roomInviteV2";

const capability = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const capabilityBase64Url = encodeRoomCapabilityBase64Url(capability);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

describe("deployed v1 invitation forms are untouched", () => {
  test("every legacy form still decodes to the same capability", () => {
    const compact = capabilityBase64Url;
    const v1Fragment = encodeRoomInviteFragment(capability);
    const legacyHex = hex(capability);

    expect(v1Fragment).toBe(`v1.${compact}`);
    expect(hex(decodeRoomCapability(compact))).toBe(legacyHex);
    expect(hex(decodeRoomCapability(v1Fragment))).toBe(legacyHex);
    expect(hex(decodeRoomCapability(`#${v1Fragment}`))).toBe(legacyHex);
    expect(hex(decodeRoomCapability(legacyHex))).toBe(legacyHex);
    expect(normalizeRoomCapability(v1Fragment)).toBe(legacyHex);
  });

  test("parseRoomInvite classifies every legacy form as version 1", () => {
    for (const form of [
      capabilityBase64Url,
      `v1.${capabilityBase64Url}`,
      `#v1.${capabilityBase64Url}`,
      hex(capability),
    ]) {
      const parsed = parseRoomInvite(form);
      expect(parsed.version).toBe(1);
      expect(hex(parsed.capability)).toBe(hex(capability));
    }
  });
});

describe("v2 fragment grammar", () => {
  test("the capability-only form resolves to the frozen blind default", () => {
    const fragment = encodeBlindRoomInviteV2Default(capability);
    expect(fragment).toBe(`v2.${capabilityBase64Url}`);

    const parsed = parseRoomInvite(fragment) as BlindRoomInviteV2;
    expect(parsed.version).toBe(2);
    expect(parsed.form).toBe("default");
    expect(hex(parsed.capability)).toBe(hex(capability));
    expect(
      roomPoliciesEqualV4(
        resolveInviteRoomPolicy(parsed),
        DEFAULT_BLIND_POLICY_V4_0,
      ),
    ).toBe(true);
  });

  test("resolving a bare invite hands out a copy, not the frozen default", () => {
    const parsed = parseRoomInvite(
      encodeBlindRoomInviteV2Default(capability),
    ) as BlindRoomInviteV2;
    const first = resolveInviteRoomPolicy(parsed);
    const second = resolveInviteRoomPolicy(parsed);

    expect(first).not.toBe(DEFAULT_BLIND_POLICY_V4_0);
    expect(first.sessionPolicyV1).not.toBe(
      DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1,
    );

    // Object.freeze cannot protect typed-array storage, so a holder mutating
    // its copy must not be able to change what the next bare invite resolves
    // to — otherwise one client would silently join a different room than
    // everyone else following the same link.
    first.sessionPolicyV1[7] = 2; // pqMode: ML-KEM-768 -> ML-KEM-512
    expect(hex(second.sessionPolicyV1)).toBe(
      hex(DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1),
    );
    expect(
      roomPoliciesEqualV4(
        resolveInviteRoomPolicy(parsed),
        DEFAULT_BLIND_POLICY_V4_0,
      ),
    ).toBe(true);
  });

  test("a leading hash is accepted only by the fragment parser", () => {
    const fragment = encodeBlindRoomInviteV2Default(capability);
    const withHash = parseRoomInvite(`#${fragment}`) as BlindRoomInviteV2;
    expect(withHash.form).toBe("default");
  });

  test("the policy-bearing form round-trips its exact policy", () => {
    const policy = {
      ...DEFAULT_BLIND_POLICY_V4_0,
      maxRoomMembers: 8,
    };
    const fragment = encodeBlindRoomInviteV2WithPolicy(capability, policy);
    const parsed = parseRoomInvite(fragment) as BlindRoomInviteV2;

    expect(parsed.form).toBe("room-policy");
    if (parsed.form !== "room-policy") throw new Error("unreachable");
    expect(parsed.roomPolicy.maxRoomMembers).toBe(8);
    expect(roomPoliciesEqualV4(parsed.roomPolicy, policy)).toBe(true);
    // No application default is merged into a policy-bearing invite.
    expect(
      roomPoliciesEqualV4(parsed.roomPolicy, DEFAULT_BLIND_POLICY_V4_0),
    ).toBe(false);
  });

  test("a canonical policy fits the invitation bound", () => {
    expect(
      encodeRoomPolicyV4(DEFAULT_BLIND_POLICY_V4_0).length,
    ).toBeLessThanOrEqual(MAX_INVITE_POLICY_BYTES);
  });
});

describe("cross-version safety", () => {
  test("an old capability-only helper rejects v2 instead of downgrading it", () => {
    const fragment = encodeBlindRoomInviteV2Default(capability);
    // The deployed helpers must never strip the version and hand back bare
    // bytes: that would silently reinterpret a blind invite as a legacy one.
    expect(() => decodeRoomCapability(fragment)).toThrow();
    expect(() => normalizeRoomCapability(fragment)).toThrow();
    expect(() => decodeRoomInviteFragment(fragment)).toThrow(
      "Unsupported room invite version",
    );
  });

  test("an unknown future version is rejected, not treated as legacy", () => {
    expect(() => parseRoomInvite(`v3.${capabilityBase64Url}`)).toThrow(
      'unsupported room invite version "v3"',
    );
  });

  test("noncanonical v2 forms fail closed", () => {
    const good = `v2.${capabilityBase64Url}`;
    expect(() => parseRoomInvite(`v2.${capabilityBase64Url}=`)).toThrow(
      "43 unpadded base64url characters",
    );
    expect(() =>
      parseRoomInvite(`v2.${capabilityBase64Url.slice(0, 42)}`),
    ).toThrow("43 unpadded base64url characters");
    expect(() => parseRoomInvite(`${good}.`)).toThrow("must not be empty");
    expect(() => parseRoomInvite(`${good}.AQ.AQ`)).toThrow(
      "at most a capability and a policy component",
    );
    expect(() => parseRoomInvite(` ${good}`)).toThrow();
    // A capability whose final sextet carries non-zero unused bits is an
    // alternate encoding of the same 32 bytes.
    const alternate = `${capabilityBase64Url.slice(0, 42)}${
      capabilityBase64Url.at(-1) === "A" ? "B" : "B"
    }`;
    expect(() => parseRoomInvite(`v2.${alternate}`)).toThrow();
  });

  test("a policy suffix that is not blind-meeting-point is rejected", () => {
    const legacySessionPolicy = Uint8Array.from(
      DEFAULT_BLIND_POLICY_V4_0.sessionPolicyV1,
    );
    legacySessionPolicy[8] = 0; // legacy-signaling
    expect(() =>
      encodeBlindRoomInviteV2WithPolicy(capability, {
        ...DEFAULT_BLIND_POLICY_V4_0,
        sessionPolicyV1: legacySessionPolicy,
      }),
    ).toThrow("does not select blind-meeting-point");
  });

  test("a policy suffix with trailing bytes is rejected", () => {
    const policyBytes = encodeRoomPolicyV4(DEFAULT_BLIND_POLICY_V4_0);
    const extended = new Uint8Array(policyBytes.length + 1);
    extended.set(policyBytes);
    expect(() =>
      parseRoomInvite(`v2.${capabilityBase64Url}.${base64urlNoPad(extended)}`),
    ).toThrow("trailing bytes");
  });
});

describe("typed errors carry their frozen codes", () => {
  test("the legacy adapter error names its code and version", () => {
    const error = new LegacySignalingAdapterUnavailableError();
    expect(error.name).toBe("LegacySignalingAdapterUnavailableError");
    expect(error.code).toBe("legacy-signaling-adapter-unavailable");
    expect(error.inviteVersion).toBe(1);
  });

  test("the store alias error names the option it refused to guess", () => {
    const error = new BlindStoreAliasResolutionError();
    expect(error.name).toBe("BlindStoreAliasResolutionError");
    expect(error.code).toBe("blind-store-alias-unmapped");
    expect(error.option).toBe("signalingServerUrl");
  });
});
