import { describe, expect, test } from "bun:test";

import { deleteRoomDataTerminal } from "../../../src/api/webrtc/deleteRoomData";

const message = (merkleRoot: string) => ({
  roomId: "room",
  timestamp: 1,
  fromPeerId: "peer",
  channelLabel: "label",
  hash: "aa".repeat(64),
  merkleRoot,
  filename: "file",
  messageType: 1,
  savedSize: 1,
  totalSize: 1,
});

describe("awaited terminal room-data deletion", () => {
  test("an injected DB failure rejects only after every reachable record is attempted", async () => {
    const roots = ["11".repeat(64), "22".repeat(64)];
    const order: string[] = [];
    const removed: string[] = [];

    const deleting = deleteRoomDataTerminal(
      "room",
      (root) => {
        order.push(`state:${root}`);
        removed.push(root);
      },
      {
        getMessages: async () => roots.map(message),
        deleteRoomRecord: async () => {
          order.push("room");
          throw new Error("injected room-row failure");
        },
        deleteReceive: async (root) => {
          order.push(`receive:${root}`);
          if (root === roots[0]) throw new Error("injected receive failure");
        },
        deleteOutgoing: async (root) => {
          order.push(`outgoing:${root}`);
        },
      },
    );

    await expect(deleting).rejects.toBeInstanceOf(AggregateError);
    expect(removed).toEqual(roots);
    expect(order).toEqual([
      "room",
      `receive:${roots[0]}`,
      `outgoing:${roots[0]}`,
      `state:${roots[0]}`,
      `receive:${roots[1]}`,
      `outgoing:${roots[1]}`,
      `state:${roots[1]}`,
    ]);
  });

  test("message enumeration failure still attempts the room and surfaces both failures", async () => {
    let roomDeleteAttempted = false;
    const deleting = deleteRoomDataTerminal(
      "room",
      () => {
        throw new Error("no message should be published");
      },
      {
        getMessages: async () => {
          throw new Error("enumeration failed");
        },
        deleteRoomRecord: async () => {
          roomDeleteAttempted = true;
          throw new Error("room delete failed");
        },
        deleteReceive: async () => undefined,
        deleteOutgoing: async () => undefined,
      },
    );

    try {
      await deleting;
      throw new Error("expected deletion failure");
    } catch (error) {
      expect(error).toBeInstanceOf(AggregateError);
      expect((error as AggregateError).errors).toHaveLength(2);
    }
    expect(roomDeleteAttempted).toBe(true);
  });
});
