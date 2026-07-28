import { describe, expect, test } from "bun:test";

import {
  MAX_COVER_CHANNELS_PER_EDGE,
  registerCoverChannel,
  registerCoverChannelUntilClose,
  unregisterCoverChannel,
} from "../../src/handlers/coverChannelRegistry";

class FakeCoverChannel extends EventTarget {
  readyState = "open";

  closeDuringSetup(): void {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

describe("cover DataChannel lifetime bounds", () => {
  test("an authenticated peer cannot exceed the per-edge cover-lane cap", () => {
    const registry = new Set<object>();
    for (let index = 0; index < MAX_COVER_CHANNELS_PER_EDGE; index++)
      registerCoverChannel(registry, { index });

    expect(() => registerCoverChannel(registry, { overflow: true })).toThrow(
      "Too many cover DataChannels",
    );
    expect(registry.size).toBe(MAX_COVER_CHANNELS_PER_EDGE);
  });

  test("remote ingress and local scheduler rollover share one cap", () => {
    const registry = new Set<object>();
    for (let index = 0; index < MAX_COVER_CHANNELS_PER_EDGE - 1; index++)
      registerCoverChannel(registry, { owner: "remote", index });

    registerCoverChannel(registry, { owner: "local-rollover" });
    expect(registry.size).toBe(MAX_COVER_CHANNELS_PER_EDGE);
    expect(() =>
      registerCoverChannel(registry, { owner: "next-local-rollover" }),
    ).toThrow("Too many cover DataChannels");
    expect(registry.size).toBe(MAX_COVER_CHANNELS_PER_EDGE);
  });

  test("repeated cover cycles release the exact lane from both registries", () => {
    const registry = new Set<object>();
    const openChannels: object[] = [];

    for (let cycle = 0; cycle < 1_000; cycle++) {
      const lane = { label: "reused-cover-label", cycle };
      registerCoverChannel(registry, lane);
      openChannels.push(lane);
      unregisterCoverChannel(registry, openChannels, lane);
      expect(registry.size).toBe(0);
      expect(openChannels).toHaveLength(0);
    }
  });

  test("a close during awaited label setup releases the lane immediately", async () => {
    const registry = new Set<FakeCoverChannel>();
    const openChannels: FakeCoverChannel[] = [];
    const lane = new FakeCoverChannel();

    registerCoverChannelUntilClose(registry, lane, openChannels);
    openChannels.push(lane);
    await Promise.resolve().then(() => lane.closeDuringSetup());

    expect(registry.size).toBe(0);
    expect(openChannels).toHaveLength(0);
  });

  test("exact-object removal preserves a replacement with the same label", () => {
    const oldLane = { label: "same" };
    const replacement = { label: "same" };
    const registry = new Set([oldLane, replacement]);
    const openChannels = [oldLane, replacement];

    unregisterCoverChannel(registry, openChannels, oldLane);

    expect(registry.has(oldLane)).toBe(false);
    expect(registry.has(replacement)).toBe(true);
    expect(openChannels).toEqual([replacement]);
  });
});
