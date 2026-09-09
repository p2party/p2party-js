import { describe, expect, test } from "bun:test";

import { PROTOCOL_VERSION } from "../../src/utils/constants";
import { isProtocolVersionCompatible } from "../../src/utils/protocolVersion";

describe("isProtocolVersionCompatible", () => {
  test("accepts only the exact current protocol version", () => {
    expect(PROTOCOL_VERSION).toBe(4);
    expect(isProtocolVersionCompatible(PROTOCOL_VERSION)).toBe(true);
    expect(isProtocolVersionCompatible(3)).toBe(false);
    expect(isProtocolVersionCompatible(5)).toBe(false);
  });

  test("rejects missing and malformed versions without fallback", () => {
    expect(isProtocolVersionCompatible(undefined)).toBe(false);
    expect(isProtocolVersionCompatible(Number.NaN)).toBe(false);
    expect(isProtocolVersionCompatible(3.5)).toBe(false);
    expect(
      isProtocolVersionCompatible(
        "3" as unknown as Parameters<
          typeof isProtocolVersionCompatible
        >[0],
      ),
    ).toBe(false);
  });
});
