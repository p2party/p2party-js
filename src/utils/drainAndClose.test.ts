import { describe, expect, test } from "bun:test";

import { drainAndClose } from "./drainAndClose";

describe("drainAndClose", () => {
  test("closes immediately when already drained", async () => {
    let closed = false;
    const dc = {
      readyState: "open",
      bufferedAmount: 0,
      close: () => (closed = true),
    };
    await drainAndClose(dc);
    expect(closed).toBe(true);
  });

  test("waits until bufferedAmount reaches 0 before closing (no data wiped)", async () => {
    const dc = {
      readyState: "open",
      bufferedAmount: 300,
      close() {
        // capture the buffer level at the moment of close
        (dc as { closedAt?: number }).closedAt = dc.bufferedAmount;
        dc.readyState = "closed";
      },
    };
    const timer = setInterval(() => {
      dc.bufferedAmount = Math.max(0, dc.bufferedAmount - 100);
    }, 15);
    await drainAndClose(dc, 2000, 10);
    clearInterval(timer);
    expect((dc as { closedAt?: number }).closedAt).toBe(0);
  });

  test("closes after the timeout even if the buffer never drains (no hang)", async () => {
    let closed = false;
    const dc = {
      readyState: "open",
      bufferedAmount: 500,
      close: () => (closed = true),
    };
    const start = Date.now();
    await drainAndClose(dc, 120, 20);
    expect(closed).toBe(true);
    expect(Date.now() - start).toBeGreaterThanOrEqual(100);
  });
});
