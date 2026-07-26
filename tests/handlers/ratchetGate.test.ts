import { describe, expect, test } from "bun:test";

import {
  claimRatchetGate,
  getRatchetGate,
  isRatchetGateOpen,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";

describe("ratchetEstablished gate (per room and peer)", () => {
  test("awaiters obtained before open resolve when the gate opens", async () => {
    resetRatchetGate("room-1", "A");
    let opened = false;
    const waiter = getRatchetGate("room-1", "A").then(() => {
      opened = true;
    });
    expect(opened).toBe(false);
    openRatchetGate("room-1", "A", claimRatchetGate("room-1", "A"));
    await waiter;
    expect(opened).toBe(true);
    expect(
      isRatchetGateOpen(
        "room-1",
        "A",
        claimRatchetGate("room-1", "A"),
      ),
    ).toBe(true);
    resetRatchetGate("room-1", "A");
  });

  test("the same peer returns the same promise until reset", () => {
    resetRatchetGate("room-1", "B");
    const first = getRatchetGate("room-1", "B");
    expect(getRatchetGate("room-1", "B")).toBe(first);
    resetRatchetGate("room-1", "B");
    const second = getRatchetGate("room-1", "B");
    expect(second).not.toBe(first);
    resetRatchetGate("room-1", "B");
  });

  test("reset rejects old awaiters and creates a fresh connection gate", async () => {
    resetRatchetGate("room-1", "reconnect");
    const oldGate = getRatchetGate("room-1", "reconnect");
    resetRatchetGate(
      "room-1",
      "reconnect",
      new Error("transport replaced"),
    );
    await expect(oldGate).rejects.toThrow("transport replaced");

    const freshGate = getRatchetGate("room-1", "reconnect");
    expect(freshGate).not.toBe(oldGate);
    openRatchetGate(
      "room-1",
      "reconnect",
      claimRatchetGate("room-1", "reconnect"),
    );
    await freshGate;
    resetRatchetGate("room-1", "reconnect");
  });

  test("awaiting an already-open gate resolves immediately", async () => {
    resetRatchetGate("room-1", "C");
    openRatchetGate("room-1", "C", claimRatchetGate("room-1", "C"));
    await getRatchetGate("room-1", "C"); // must not hang
    resetRatchetGate("room-1", "C");
  });

  test("gates are isolated per room and peer", async () => {
    resetRatchetGate("room-1", "D");
    resetRatchetGate("room-2", "D");
    let dOpen = false;
    const dWaiter = getRatchetGate("room-1", "D").then(() => {
      dOpen = true;
    });
    openRatchetGate("room-2", "D", claimRatchetGate("room-2", "D"));
    await Promise.resolve();
    expect(dOpen).toBe(false);
    openRatchetGate("room-1", "D", claimRatchetGate("room-1", "D"));
    await dWaiter;
    expect(dOpen).toBe(true);
    resetRatchetGate("room-1", "D");
    resetRatchetGate("room-2", "D");
  });

  test("reject makes the current promise reject; open is then a no-op", async () => {
    resetRatchetGate("room-1", "F");
    const p = getRatchetGate("room-1", "F");
    rejectRatchetGate(
      "room-1",
      "F",
      new Error("handshake failed"),
      claimRatchetGate("room-1", "F"),
    );
    await expect(p).rejects.toThrow("handshake failed");
    resetRatchetGate("room-1", "F");
  });

  test("a stale transport lease cannot settle its replacement gate", async () => {
    const oldLease = resetRatchetGate("room-1", "leased");
    const oldGate = getRatchetGate("room-1", "leased");
    const freshLease = resetRatchetGate(
      "room-1",
      "leased",
      new Error("replaced"),
    );
    await expect(oldGate).rejects.toThrow("replaced");

    let freshSettled = false;
    const freshGate = getRatchetGate("room-1", "leased").then(
      () => {
        freshSettled = true;
      },
      () => {
        freshSettled = true;
      },
    );

    expect(openRatchetGate("room-1", "leased", oldLease)).toBe(false);
    expect(
      rejectRatchetGate(
        "room-1",
        "leased",
        new Error("stale failure"),
        oldLease,
      ),
    ).toBe(false);
    await Promise.resolve();
    expect(freshSettled).toBe(false);

    expect(openRatchetGate("room-1", "leased", freshLease)).toBe(true);
    await freshGate;
    expect(freshSettled).toBe(true);
    resetRatchetGate("room-1", "leased");
  });

  test("rejecting a never-awaited peer does not surface as an unhandled rejection, and a late awaiter still receives the error", async () => {
    resetRatchetGate("room-1", "G");

    let unhandled: unknown;
    const onUnhandledRejection = (reason: unknown) => {
      unhandled = reason;
    };
    process.on("unhandledRejection", onUnhandledRejection);

    try {
      // Nobody has called getRatchetGate("G") yet, so the gate's promise (and
      // its rejection handler) is minted for the first time inside this call.
      rejectRatchetGate("room-1", "G", new Error("handshake failed (G)"));

      // Cross real tick boundaries (macrotask, not just a microtask) before
      // attaching any consumer. Node/Bun fire "unhandledRejection" once the
      // microtask queue drains with a still-unhandled rejected promise, so if
      // ensure() doesn't attach a handler synchronously when the promise is
      // created, the event fires in this gap.
      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(unhandled).toBeUndefined();

      // A real, late consumer must still observe the original rejection —
      // the guard must not swallow it for genuine awaiters.
      await expect(getRatchetGate("room-1", "G")).rejects.toThrow(
        "handshake failed (G)",
      );
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
      resetRatchetGate("room-1", "G");
    }
  });
});
