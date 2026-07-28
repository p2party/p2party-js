import { describe, expect, test } from "bun:test";

import { SignalingPeerRequestDebouncer } from "../../src/utils/signalingPeerRequestDebouncer";

describe("signaling peer request debounce", () => {
  test("debounces within a socket but permits the first request after reconnect", () => {
    const debouncer = new SignalingPeerRequestDebouncer();

    expect(debouncer.shouldSend("join", "room-id", 2000, 10_000)).toBe(true);
    expect(debouncer.shouldSend("join", "room-id", 2000, 10_001)).toBe(false);

    debouncer.resetSocketLifecycle();
    expect(debouncer.shouldSend("join", "room-id", 2000, 10_001)).toBe(true);
  });

  test("keeps join and empty-roster retry budgets independent", () => {
    const debouncer = new SignalingPeerRequestDebouncer();

    expect(debouncer.shouldSend("join", "room-id", 2000, 10_000)).toBe(true);
    expect(debouncer.shouldSend("empty-roster", "room-id", 5000, 10_000)).toBe(
      true,
    );
  });
});
