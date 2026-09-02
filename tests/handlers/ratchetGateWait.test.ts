import { describe, expect, test } from "bun:test";

import {
  claimRatchetGate,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";
import {
  RATCHET_GATE_WAIT_TIMEOUT_MESSAGE,
  isRatchetGateWaitTimeout,
  waitForRatchetGate,
} from "../../src/handlers/ratchetGateWait";
import { RATCHET_GATE_WAIT_TIMEOUT_MS } from "../../src/utils/constants";

const ROOM = "gate-wait-room";

describe("bounded ratchet-gate wait in the send path", () => {
  test("the budget outlasts one handshake step timeout", () => {
    // handleHandshake fails a step that does not answer within 30 s
    // (HANDSHAKE_STEP_TIMEOUT_MS). The send-side wait must not give up before
    // the handshake itself has had the chance to fail, or a slow-but-healthy
    // handshake is reported as "never authenticated".
    expect(RATCHET_GATE_WAIT_TIMEOUT_MS).toBeGreaterThanOrEqual(30_000);
  });

  test("a gate that never opens rejects with the transport-binding error", async () => {
    resetRatchetGate(ROOM, "silent");
    const started = Date.now();
    await expect(
      waitForRatchetGate(ROOM, "silent", undefined, 20),
    ).rejects.toThrow(RATCHET_GATE_WAIT_TIMEOUT_MESSAGE);
    expect(Date.now() - started).toBeLessThan(1000);
    expect(RATCHET_GATE_WAIT_TIMEOUT_MESSAGE).toBe(
      "Peer is not authenticated on this transport: the handshake did not complete within the wait budget",
    );
    resetRatchetGate(ROOM, "silent");
  });

  test("the timeout error is recognisable so callers can pass it through unwrapped", async () => {
    resetRatchetGate(ROOM, "recognise");
    let caught: unknown;
    try {
      await waitForRatchetGate(ROOM, "recognise", undefined, 5);
    } catch (error) {
      caught = error;
    }
    expect(isRatchetGateWaitTimeout(caught)).toBe(true);
    expect(isRatchetGateWaitTimeout(new Error("something else"))).toBe(false);
    expect(isRatchetGateWaitTimeout(undefined)).toBe(false);
    resetRatchetGate(ROOM, "recognise");
  });

  test("a gate opened before the budget resolves and clears its timer", async () => {
    resetRatchetGate(ROOM, "opens");
    const originalClear = globalThis.clearTimeout;
    let cleared = 0;
    globalThis.clearTimeout = ((id: Parameters<typeof clearTimeout>[0]) => {
      cleared += 1;
      originalClear(id);
    }) as typeof clearTimeout;
    try {
      const pending = waitForRatchetGate(ROOM, "opens", undefined, 10_000);
      setTimeout(() => {
        openRatchetGate(ROOM, "opens", claimRatchetGate(ROOM, "opens"));
      }, 5);
      await expect(pending).resolves.toBeUndefined();
      expect(cleared).toBeGreaterThanOrEqual(1);
    } finally {
      globalThis.clearTimeout = originalClear;
      resetRatchetGate(ROOM, "opens");
    }
  });

  test("an already-open gate resolves immediately", async () => {
    resetRatchetGate(ROOM, "open-already");
    openRatchetGate(
      ROOM,
      "open-already",
      claimRatchetGate(ROOM, "open-already"),
    );
    await expect(
      waitForRatchetGate(ROOM, "open-already", undefined, 10_000),
    ).resolves.toBeUndefined();
    resetRatchetGate(ROOM, "open-already");
  });

  test("a rejected gate propagates its own rejection, not the timeout", async () => {
    resetRatchetGate(ROOM, "rejects");
    const handshakeFailure = new Error("handshake failed: bad transcript");
    const pending = waitForRatchetGate(ROOM, "rejects", undefined, 10_000);
    rejectRatchetGate(
      ROOM,
      "rejects",
      handshakeFailure,
      claimRatchetGate(ROOM, "rejects"),
    );
    let caught: unknown;
    try {
      await pending;
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(handshakeFailure);
    expect(isRatchetGateWaitTimeout(caught)).toBe(false);
    resetRatchetGate(ROOM, "rejects");
  });

  test("a transfer abort still wins over the budget", async () => {
    resetRatchetGate(ROOM, "aborts");
    const controller = new AbortController();
    const pending = waitForRatchetGate(
      ROOM,
      "aborts",
      controller.signal,
      10_000,
    );
    const started = Date.now();
    setTimeout(() => {
      controller.abort(new Error("Message transfer cancelled"));
    }, 5);
    await expect(pending).rejects.toThrow("Message transfer cancelled");
    expect(Date.now() - started).toBeLessThan(1000);
    resetRatchetGate(ROOM, "aborts");
  });

  test("an already-aborted transfer rejects before arming any timer", async () => {
    resetRatchetGate(ROOM, "pre-aborted");
    const controller = new AbortController();
    controller.abort(new Error("Message transfer cancelled"));
    await expect(
      waitForRatchetGate(ROOM, "pre-aborted", controller.signal, 10_000),
    ).rejects.toThrow("Message transfer cancelled");
    resetRatchetGate(ROOM, "pre-aborted");
  });
});
