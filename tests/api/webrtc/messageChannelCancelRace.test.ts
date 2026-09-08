import { describe, expect, test } from "bun:test";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCDataChannel } from "../../../src/api/webrtc/interfaces";

const memory = new Map<string, string>();
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => {
    memory.set(key, value);
  },
  removeItem: (key: string) => {
    memory.delete(key);
  },
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

describe("message cancellation during shared channel-array teardown", () => {
  test("every original target is closed once and another room's channel survives", async () => {
    await import("../../../src/store");
    const { default: disconnect } =
      await import("../../../src/api/webrtc/disconnectFromChannelLabelQuery");
    const channels: IRTCDataChannel[] = [];
    const closed: string[] = [];
    const cancelled: string[] = [];
    const make = (peer: string, room = "room") =>
      ({
        label: "main",
        protocol: "raw",
        readyState: "open",
        bufferedAmount: 0,
        roomIds: [room],
        withPeerId: peer,
        close: () => {
          closed.push(peer);
        },
        cancelReceiveTransfer: async () => {
          cancelled.push(peer);
          const index = channels.indexOf(targets[peer]);
          if (index !== -1) channels.splice(index, 1);
          await Promise.resolve();
        },
      }) as unknown as IRTCDataChannel;
    const targets = {
      A: make("A"),
      B: make("B"),
      C: make("C", "other-room"),
    } as Record<string, IRTCDataChannel>;
    channels.push(targets.A, targets.B, targets.C);
    await disconnect(
      {
        roomId: "room",
        label: "main",
        alsoDeleteData: true,
        dataChannels: channels,
      },
      {
        dispatch: () => undefined,
        getState: () => ({}),
      } as unknown as BaseQueryApi,
      {},
    );
    expect(cancelled).toEqual(["A", "B"]);
    expect(closed).toEqual(["A", "B"]);
    expect(channels).toEqual([targets.C]);
  });
});
