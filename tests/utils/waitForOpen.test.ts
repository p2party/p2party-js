import { describe, expect, test } from "bun:test";

import { waitForOpen } from "../../src/utils/waitForOpen";

describe("waitForOpen", () => {
  test("returns true immediately if already open", async () => {
    const dc = { readyState: "open" };
    expect(await waitForOpen(dc, 1000, 10)).toBe(true);
  });

  test("resolves true once the channel transitions to open", async () => {
    const dc = { readyState: "connecting" };
    setTimeout(() => (dc.readyState = "open"), 60);
    const start = Date.now();
    expect(await waitForOpen(dc, 2000, 10)).toBe(true);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  test("returns false after the timeout if it never opens", async () => {
    const dc = { readyState: "connecting" };
    expect(await waitForOpen(dc, 120, 20)).toBe(false);
  });

  test("returns false for a closed channel", async () => {
    const dc = { readyState: "closed" };
    expect(await waitForOpen(dc, 120, 20)).toBe(false);
  });

  test("returns promptly when the logical transfer is aborted", async () => {
    const dc = { readyState: "connecting" };
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    const start = Date.now();
    expect(await waitForOpen(dc, 2000, 10, controller.signal)).toBe(false);
    expect(Date.now() - start).toBeLessThan(500);
  });
});
