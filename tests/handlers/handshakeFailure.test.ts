import { describe, expect, test } from "bun:test";

import {
  HandshakeFailure,
  classifyHandshakeFailure,
  isTerminalHandshakeFailure,
} from "../../src/handlers/handshakeFailure";

describe("handshake failure classification", () => {
  test("a typed failure wins over any message shape", () => {
    const error = new HandshakeFailure(
      "Malformed, surplus, or out-of-order handshake frame",
      "policy",
    );
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: true,
        pinRoom: true,
      }),
    ).toEqual({ reason: "policy", retryAfter: undefined });
  });

  test("a typed failure carries its own retry deadline", () => {
    const at = Date.parse("2026-09-08T12:00:00.000Z");
    const error = new HandshakeFailure("throttled", "pin-throttled", at);
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: true,
        pinRoom: true,
      }),
    ).toEqual({ reason: "pin-throttled", retryAfter: at });
  });

  test("an untyped throttle message keeps its parsed deadline", () => {
    const error = new Error(
      "Room PIN attempts are throttled until 2026-09-08T12:00:00.000Z",
    );
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: true,
        pinRoom: true,
      }),
    ).toEqual({
      reason: "pin-throttled",
      retryAfter: Date.parse("2026-09-08T12:00:00.000Z"),
    });
  });

  test("an untyped key-confirmation failure is a PIN mismatch on a PIN room", () => {
    const error = new Error("Handshake key-confirmation failed");
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: true,
        pinRoom: true,
      }),
    ).toEqual({ reason: "pin-mismatch", retryAfter: undefined });
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: true,
        pinRoom: false,
      }),
    ).toEqual({ reason: "policy", retryAfter: undefined });
  });

  test("a key-confirmation message before the handshake started is transport", () => {
    const error = new Error("Handshake key-confirmation failed");
    expect(
      classifyHandshakeFailure(error, {
        handshakeStarted: false,
        pinRoom: true,
      }),
    ).toEqual({ reason: "transport", retryAfter: undefined });
  });

  test("an unrecognised failure stays transport, which is the only re-dialable one", () => {
    expect(
      classifyHandshakeFailure(new Error("ICE failed"), {
        handshakeStarted: true,
        pinRoom: false,
      }),
    ).toEqual({ reason: "transport", retryAfter: undefined });
    expect(isTerminalHandshakeFailure("transport")).toBe(false);
    expect(isTerminalHandshakeFailure("policy")).toBe(true);
    expect(isTerminalHandshakeFailure("pin-mismatch")).toBe(true);
    expect(isTerminalHandshakeFailure("pin-throttled")).toBe(true);
  });

  test("a non-Error throw does not crash the classifier", () => {
    expect(
      classifyHandshakeFailure("boom", {
        handshakeStarted: true,
        pinRoom: true,
      }),
    ).toEqual({ reason: "transport", retryAfter: undefined });
  });
});
