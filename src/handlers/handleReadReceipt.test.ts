import { beforeAll, describe, expect, test } from "bun:test";

import { compileChannelMessageLabel } from "../utils/channelLabel";
import { clearTransfer, isTransferComplete } from "./reconcile";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { Room } from "../reducers/roomSlice";

const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {},
  key: () => null,
  length: 0,
} as Storage;

let handleReadReceipt: (typeof import("./handleReadReceipt"))["handleReadReceipt"];

beforeAll(async () => {
  await import("../store");
  ({ handleReadReceipt } = await import("./handleReadReceipt"));
});

describe("terminal receipt edge semantics", () => {
  test("duplicates are idempotent, peer-scoped, and never own channel close", async () => {
    const roomId = "room-receipts";
    const transferId = "11".repeat(32);
    const merkleRootHex = "22".repeat(64);
    const hashHex = "33".repeat(64);
    const room = {
      id: roomId,
      messages: [
        {
          transferId,
          merkleRootHex,
          sha512Hex: hashHex,
          fromPeerId: "self",
          filename: "message.txt",
          messageType: 1,
          savedSize: 0,
          totalSize: 5,
          chunksCreated: 1,
          totalChunks: 1,
          channelLabel: "chat",
          timestamp: 1,
        },
      ],
    } as Room;
    const dispatched: unknown[] = [];
    const api = {
      getState: () => ({ rooms: [room] }),
      dispatch: (action: unknown) => {
        dispatched.push(action);
        return action;
      },
    } as unknown as BaseQueryApi;
    const channel = await compileChannelMessageLabel("chat", merkleRootHex);
    const terminal = new Uint8Array(64).fill(0x33);

    clearTransfer(roomId, "peer-a", transferId);
    clearTransfer(roomId, "peer-b", transferId);
    const first = await handleReadReceipt(
      terminal,
      channel,
      "peer-a",
      roomId,
      api,
    );
    const duplicate = await handleReadReceipt(
      terminal,
      channel,
      "peer-a",
      roomId,
      api,
    );

    expect(first).toMatchObject({
      kind: "peer-complete",
      peerId: "peer-a",
      newlyAccepted: true,
    });
    expect(duplicate).toMatchObject({
      kind: "peer-complete",
      peerId: "peer-a",
      newlyAccepted: false,
    });
    // sendWithReconcile owns the normal terminal close after all queued cover
    // frames and receipts drain. The receipt handler only records completion.
    expect(dispatched).toHaveLength(0);
    expect(isTransferComplete(roomId, "peer-a", transferId)).toBe(true);
    expect(isTransferComplete(roomId, "peer-b", transferId)).toBe(false);
    expect(room.messages[0].savedSize).toBe(0);

    clearTransfer(roomId, "peer-a", transferId);
    clearTransfer(roomId, "peer-b", transferId);
  });
});
