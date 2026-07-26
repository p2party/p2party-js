import { describe, expect, test } from "bun:test";

// randomNumberInRange reads `window.crypto.getRandomValues`; under Bun the Web
// Crypto API is a global but `window` is not, so alias it.
(globalThis as unknown as { window: typeof globalThis }).window = globalThis;

import { randomNumberInRange } from "../../src/cryptography/utils";

describe("randomNumberInRange", () => {
  test("returns in-range safe integers across a 2^53-sized range (decoy range)", async () => {
    // This is the range used for decoy chunkEndIndex in splitToChunks.ts:
    // [chunkEnd + totalSize + 1, Number.MAX_SAFE_INTEGER - start].
    const min = 100_000;
    const max = Number.MAX_SAFE_INTEGER - min;

    for (let i = 0; i < 200; i++) {
      const r = await randomNumberInRange(min, max);
      expect(Number.isSafeInteger(r)).toBe(true);
      expect(r).toBeGreaterThanOrEqual(min);
      expect(r).toBeLessThan(max);
    }
  });
});
