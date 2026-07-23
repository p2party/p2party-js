import { describe, expect, test } from "bun:test";

import { PROTOCOL_VERSION } from "./constants";
import { isProtocolVersionCompatible } from "./protocolVersion";

describe("isProtocolVersionCompatible", () => {
  test("accepts only the exact current protocol version", () => {
    expect(PROTOCOL_VERSION).toBe(3);
    expect(isProtocolVersionCompatible(PROTOCOL_VERSION)).toBe(true);
    expect(isProtocolVersionCompatible(2)).toBe(false);
    expect(isProtocolVersionCompatible(4)).toBe(false);
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
