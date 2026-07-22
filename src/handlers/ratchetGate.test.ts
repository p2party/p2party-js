import { describe, expect, test } from "bun:test";

import {
  getRatchetGate,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "./ratchetGate";

describe("ratchetEstablished gate (per peer)", () => {
  test("awaiters obtained before open resolve when the gate opens", async () => {
    resetRatchetGate("A");
    let opened = false;
    const waiter = getRatchetGate("A").then(() => {
      opened = true;
    });
    expect(opened).toBe(false);
    openRatchetGate("A");
    await waiter;
    expect(opened).toBe(true);
    resetRatchetGate("A");
  });

  test("the same peer returns the same promise until reset", () => {
    resetRatchetGate("B");
    const first = getRatchetGate("B");
    expect(getRatchetGate("B")).toBe(first);
    resetRatchetGate("B");
    const second = getRatchetGate("B");
    expect(second).not.toBe(first);
    resetRatchetGate("B");
  });

  test("awaiting an already-open gate resolves immediately", async () => {
    resetRatchetGate("C");
    openRatchetGate("C");
    await getRatchetGate("C"); // must not hang
    resetRatchetGate("C");
  });

  test("gates are isolated per peer", async () => {
    resetRatchetGate("D");
    resetRatchetGate("E");
    let dOpen = false;
    const dWaiter = getRatchetGate("D").then(() => {
      dOpen = true;
    });
    openRatchetGate("E");
    await Promise.resolve();
    expect(dOpen).toBe(false);
    openRatchetGate("D");
    await dWaiter;
    expect(dOpen).toBe(true);
    resetRatchetGate("D");
    resetRatchetGate("E");
  });

  test("reject makes the current promise reject; open is then a no-op", async () => {
    resetRatchetGate("F");
    const p = getRatchetGate("F");
    rejectRatchetGate("F", new Error("handshake failed"));
    await expect(p).rejects.toThrow("handshake failed");
    resetRatchetGate("F");
  });
});
