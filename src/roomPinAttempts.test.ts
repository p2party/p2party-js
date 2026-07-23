import { describe, expect, test } from "bun:test";

import {
  MAX_PIN_ATTEMPTS,
  MAX_ROOM_PIN_FAILURES_PER_WINDOW,
  PIN_BACKOFF_BASE_MS,
  PIN_BACKOFF_MAX_MS,
  ROOM_PIN_FAILURE_WINDOW_MS,
  assertRoomPinAggregateAllowed,
  clearRoomPinAggregateFailures,
  pinBackoffMs,
  recordRoomPinAggregateFailure,
} from "./roomPinAttempts";

describe("per-room/per-peer PIN attempt backoff", () => {
  test("starts throttling after the third failure and doubles to the five-minute cap", () => {
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS - 1)).toBe(0);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS)).toBe(PIN_BACKOFF_BASE_MS);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 1)).toBe(
      PIN_BACKOFF_BASE_MS * 2,
    );
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 40)).toBe(PIN_BACKOFF_MAX_MS);
  });
});

describe("soft room-wide PIN failure window", () => {
  test("a few failures do not lock unrelated identities", () => {
    const room = "aggregate-few";
    clearRoomPinAggregateFailures(room);
    for (let i = 0; i < MAX_PIN_ATTEMPTS; i++)
      recordRoomPinAggregateFailure(room, 1000 + i);
    expect(() => assertRoomPinAggregateAllowed(room, 2000)).not.toThrow();
    clearRoomPinAggregateFailures(room);
  });

  test("identity rotation cannot obtain an unlimited room budget", () => {
    const room = "aggregate-sybil";
    clearRoomPinAggregateFailures(room);
    for (let i = 0; i < MAX_ROOM_PIN_FAILURES_PER_WINDOW; i++)
      recordRoomPinAggregateFailure(room, 1000 + i);
    expect(() => assertRoomPinAggregateAllowed(room, 2000)).toThrow(
      "temporarily throttled",
    );
    expect(() =>
      assertRoomPinAggregateAllowed(
        room,
        1000 + ROOM_PIN_FAILURE_WINDOW_MS + 1,
      ),
    ).not.toThrow();
    clearRoomPinAggregateFailures(room);
  });
});
