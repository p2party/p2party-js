import { describe, expect, test } from "bun:test";

import {
  decodeRoomCapability,
  decodeRoomCapabilityBase64Url,
  decodeRoomCapabilityWords,
  decodeRoomInviteFragment,
  encodeRoomCapabilityBase64Url,
  encodeRoomCapabilityWords,
  encodeRoomInviteFragment,
  generateRoomCapability,
  normalizeRoomCapability,
  ROOM_CAPABILITY_BASE64URL_CHARS,
  ROOM_CAPABILITY_BYTES,
  ROOM_INVITE_WORDS,
} from "./roomInvite";

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

describe("room invite codec", () => {
  test("compact form preserves all 256 capability bits", () => {
    const capability = Uint8Array.from(
      { length: ROOM_CAPABILITY_BYTES },
      (_, index) => index,
    );
    const encoded = encodeRoomCapabilityBase64Url(capability);

    expect(encoded).toBe("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
    expect(encoded).toHaveLength(ROOM_CAPABILITY_BASE64URL_CHARS);
    expect(encoded).not.toContain("=");
    expectBytesEqual(decodeRoomCapabilityBase64Url(encoded), capability);
    expectBytesEqual(decodeRoomCapability(encoded), capability);
  });

  test("legacy hex normalizes to one canonical internal identifier", () => {
    const legacy = "AB".repeat(ROOM_CAPABILITY_BYTES);
    const compact = encodeRoomCapabilityBase64Url(
      new Uint8Array(ROOM_CAPABILITY_BYTES).fill(0xab),
    );

    expect(normalizeRoomCapability(legacy)).toBe("ab".repeat(32));
    expect(normalizeRoomCapability(compact)).toBe("ab".repeat(32));
  });

  test("versioned fragment never needs the capability in an HTTP path", () => {
    const capability = new Uint8Array(ROOM_CAPABILITY_BYTES).fill(0x42);
    const fragment = encodeRoomInviteFragment(capability);

    expect(fragment).toStartWith("v1.");
    expectBytesEqual(decodeRoomInviteFragment(fragment), capability);
    expectBytesEqual(decodeRoomInviteFragment(`#${fragment}`), capability);
    expectBytesEqual(decodeRoomCapability(fragment), capability);
    expect(normalizeRoomCapability(`#${fragment}`)).toBe("42".repeat(32));
    expect(() =>
      decodeRoomInviteFragment(fragment.replace("v1.", "v2.")),
    ).toThrow("Unsupported room invite version");
  });

  test("rejects padded, malformed, and noncanonical compact aliases", () => {
    const canonical = encodeRoomCapabilityBase64Url(
      new Uint8Array(ROOM_CAPABILITY_BYTES),
    );

    expect(() => decodeRoomCapabilityBase64Url(`${canonical}=`)).toThrow();
    expect(() => decodeRoomCapabilityBase64Url(canonical.slice(1))).toThrow();
    expect(() =>
      decodeRoomCapabilityBase64Url(`${canonical.slice(0, -1)}B`),
    ).toThrow("not canonical");
  });

  test("24 words are a checksum-protected encoding, not reduced entropy", async () => {
    const capability = Uint8Array.from(
      { length: ROOM_CAPABILITY_BYTES },
      (_, index) => (index * 29 + 7) & 0xff,
    );
    const encoded = await encodeRoomCapabilityWords(capability);
    const words = encoded.split(" ");

    expect(encoded).toBe(
      "already capital fiscal warm mercy truly rotate lunch edit bright cherry interest leg ancient rice home mad bicycle warm vendor glimpse popular renew eager",
    );
    expect(words).toHaveLength(ROOM_INVITE_WORDS);
    expectBytesEqual(await decodeRoomCapabilityWords(encoded), capability);
    expectBytesEqual(
      await decodeRoomCapabilityWords(`  ${encoded.toUpperCase()}  `),
      capability,
    );

    const tampered = [...words];
    tampered[23] = tampered[23] === "zoo" ? "zone" : "zoo";
    await expect(decodeRoomCapabilityWords(tampered.join(" "))).rejects.toThrow(
      "checksum",
    );
  });

  test("generation returns direct uniform 32-byte capability material", () => {
    const first = generateRoomCapability();
    const second = generateRoomCapability();

    expect(first).toHaveLength(ROOM_CAPABILITY_BYTES);
    expect(second).toHaveLength(ROOM_CAPABILITY_BYTES);
    expect(Buffer.from(first)).not.toEqual(Buffer.from(second));
  });
});
