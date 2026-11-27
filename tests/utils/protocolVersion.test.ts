import { describe, expect, test } from "bun:test";

import { SIGNALING_PROTOCOL_VERSION } from "../../src/utils/constants";
import {
  isProtocolVersionCompatible,
  isSignalingVersionRefusal,
} from "../../src/utils/protocolVersion";

describe("isProtocolVersionCompatible", () => {
  test("accepts only the exact current protocol version", () => {
    expect(SIGNALING_PROTOCOL_VERSION).toBe(5);
    expect(isProtocolVersionCompatible(SIGNALING_PROTOCOL_VERSION)).toBe(true);
    expect(isProtocolVersionCompatible(3)).toBe(false);
    expect(isProtocolVersionCompatible(4)).toBe(false);
  });

  test("recognizes the server's version refusal separately from malformed frames", () => {
    const reason =
      "Unsupported signaling protocol version; this server speaks version 5";
    expect(isSignalingVersionRefusal(1003, reason)).toBe(true);
    expect(isSignalingVersionRefusal(1008, reason)).toBe(false);
    expect(isSignalingVersionRefusal(1003, "Malformed signaling frame")).toBe(
      false,
    );
  });

  test("rejects missing and malformed versions without fallback", () => {
    expect(isProtocolVersionCompatible(undefined)).toBe(false);
    expect(isProtocolVersionCompatible(Number.NaN)).toBe(false);
    expect(isProtocolVersionCompatible(3.5)).toBe(false);
    expect(
      isProtocolVersionCompatible(
        "3" as unknown as Parameters<typeof isProtocolVersionCompatible>[0],
      ),
    ).toBe(false);
  });
});
