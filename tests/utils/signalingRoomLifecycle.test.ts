import { describe, expect, test } from "bun:test";

import { findActiveSignalingRoomIndex } from "../../src/utils/signalingRoomLifecycle";

describe("one-socket multi-room lifecycle", () => {
  test("inbound signaling never routes to an inactive or unknown room", () => {
    const roomId = "00000000-0000-4000-8000-000000000123";
    const rooms = [
      { url: "a".repeat(64), id: "", signalingActive: false },
      { url: "b".repeat(64), id: roomId, signalingActive: false },
      {
        url: "c".repeat(64),
        id: "00000000-0000-4000-8000-000000000456",
        signalingActive: true,
      },
    ];
    expect(findActiveSignalingRoomIndex(rooms, "")).toBe(-1);
    expect(findActiveSignalingRoomIndex(rooms, roomId)).toBe(-1);
    expect(
      findActiveSignalingRoomIndex(
        rooms,
        "00000000-0000-4000-8000-000000000456",
      ),
    ).toBe(2);
  });
});
