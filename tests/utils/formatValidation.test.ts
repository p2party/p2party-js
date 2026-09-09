import { describe, expect, test } from "bun:test";
import { isHexadecimal, isUUID } from "../../src/utils/formatValidation";

const UUID = "12345678-1234-4abc-8abc-123456789abc";

describe("protocol format validation", () => {
  test("generic UUIDs preserve versions 1–8 and RFC variants, while v4 stays exact", () => {
    for (let version = 0; version < 16; version++) {
      for (let variant = 0; variant < 16; variant++) {
        const value = `12345678-1234-${version.toString(16)}abc-${variant.toString(16)}abc-123456789abc`;
        const validVariant = variant >= 8 && variant <= 11;
        const validVersion = version >= 1 && version <= 8;
        for (const candidate of [value, value.toUpperCase()]) {
          expect(isUUID(candidate)).toBe(validVersion && validVariant);
          expect(isUUID(candidate, 4)).toBe(version === 4 && validVariant);
        }
      }
    }
  });

  test("nil and max remain generic UUIDs but cannot pass explicit v4 gates", () => {
    for (const value of [
      "00000000-0000-0000-0000-000000000000",
      "ffffffff-ffff-ffff-ffff-ffffffffffff",
      "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
    ]) {
      expect(isUUID(value)).toBe(true);
      expect(isUUID(value, 4)).toBe(false);
    }
  });

  test("UUID checks reject malformed separators, nonhex characters and extra data", () => {
    for (let index = 0; index < UUID.length; index++) {
      const replacement = UUID[index] === "-" ? "a" : "g";
      const malformed =
        UUID.slice(0, index) + replacement + UUID.slice(index + 1);
      expect(isUUID(malformed)).toBe(false);
      expect(isUUID(malformed, 4)).toBe(false);
    }
    for (const malformed of [
      "",
      UUID.slice(1),
      UUID.replaceAll("-", ""),
      `{${UUID}}`,
      `urn:uuid:${UUID}`,
      `${UUID}${UUID}`,
    ]) {
      expect(isUUID(malformed)).toBe(false);
      expect(isUUID(malformed, 4)).toBe(false);
    }
  });

  test("hex checks retain prefixes, case and odd-length digits", () => {
    for (const digits of [
      "0",
      "1",
      "a",
      "F",
      "aB9",
      "0b010",
      "0123456789abcdefABCDEF",
    ]) {
      for (const prefix of ["", "0x", "0X", "0h", "0H"])
        expect(isHexadecimal(prefix + digits)).toBe(true);
    }
    for (const value of ["", "0x", "0h", "0x0x01", "-1", "+1", "1.5", "0g"])
      expect(isHexadecimal(value)).toBe(false);
    for (let code = 0; code < 128; code++) {
      const asciiHex =
        (code >= 48 && code <= 57) ||
        (code >= 65 && code <= 70) ||
        (code >= 97 && code <= 102);
      expect(isHexadecimal(String.fromCharCode(code))).toBe(asciiHex);
    }
  });

  test("all field checks reject surrounding whitespace and line terminators", () => {
    for (const delimiter of [
      " ",
      "\t",
      "\n",
      "\r",
      "\r\n",
      "\u2028",
      "\u2029",
      "\0",
    ]) {
      for (const value of [delimiter + UUID, UUID + delimiter]) {
        expect(isUUID(value)).toBe(false);
        expect(isUUID(value, 4)).toBe(false);
      }
      expect(isHexadecimal(delimiter + "ab01")).toBe(false);
      expect(isHexadecimal("ab01" + delimiter)).toBe(false);
    }
  });

  test("untrusted nonstrings are rejected without coercion", () => {
    const hostile = {
      toString: () => {
        throw new Error("format validation must not coerce input");
      },
    };
    for (const value of [
      null,
      undefined,
      123,
      0n,
      true,
      [],
      {},
      Object(UUID),
      hostile,
    ]) {
      expect(isUUID(value)).toBe(false);
      expect(isUUID(value, 4)).toBe(false);
      expect(isHexadecimal(value)).toBe(false);
    }
  });
});
