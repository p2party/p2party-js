import { beforeAll, describe, expect, test } from "bun:test";

import { compileChannelMessageLabel } from "../../src/utils/channelLabel";
import {
  clearTransfer,
  hasChunkAcked,
  isTransferComplete,
} from "../../src/handlers/reconcile";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { Room } from "../../src/reducers/roomSlice";

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

let handleReadReceipt: (typeof import("../../src/handlers/handleReadReceipt"))["handleReadReceipt"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleReadReceipt } =
    await import("../../src/handlers/handleReadReceipt"));
});

describe("terminal receipt edge semantics", () => {
  test("durable chunk ACKs stay invisible until commit and cannot cross an identity change", async () => {
    const roomId = "durable-receipts",
      peerId = "peer",
      transferId = "44".repeat(32);
    const merkleRootHex = "55".repeat(64),
      tokenHex = "66".repeat(64);
    const room = {
      id: roomId,
      peers: [{ peerId, peerPublicKey: "77".repeat(32) }],
      messages: [{ transferId, merkleRootHex, sha512Hex: "88".repeat(64) }],
    } as Room;
    const api = {
      getState: () => ({ rooms: [room] }),
    } as unknown as BaseQueryApi;
    const channel = await compileChannelMessageLabel("chat", merkleRootHex);
    const token = new Uint8Array(64).fill(0x66);
    const chunk = {
      transferId,
      merkleRoot: merkleRootHex,
      receiptToken: tokenHex,
      chunkIndex: 2,
    };
    const getChunk = async () => chunk;
    try {
      for (const changeIdentity of [false, true]) {
        clearTransfer(roomId, peerId, transferId);
        let finish!: (accepted: boolean) => void;
        const pending = handleReadReceipt(token, channel, peerId, roomId, api, {
          getChunk,
          persist: () =>
            new Promise<boolean>((resolve) => {
              finish = resolve;
            }),
        });
        for (let i = 0; i < 20 && !finish; i++) await Promise.resolve();
        expect(finish).toBeDefined();
        expect(hasChunkAcked(roomId, peerId, transferId, 2)).toBe(false);
        if (changeIdentity) room.peers[0].peerPublicKey = "99".repeat(32);
        finish(true);
        expect((await pending).kind).toBe(
          changeIdentity ? "ignored" : "chunk-acked",
        );
        expect(hasChunkAcked(roomId, peerId, transferId, 2)).toBe(
          !changeIdentity,
        );
      }
    } finally {
      clearTransfer(roomId, peerId, transferId);
    }
  });

  test("refused persistence, wrong lookup scope and invalid indices cannot advance an immediate ACK", async () => {
    const roomId = "rejected-receipts",
      peerId = "peer",
      transferId = "aa".repeat(32);
    const merkleRootHex = "bb".repeat(64),
      tokenHex = "cc".repeat(64);
    const room = {
      id: roomId,
      peers: [{ peerId, peerPublicKey: "dd".repeat(32) }],
      messages: [{ transferId, merkleRootHex, sha512Hex: "ee".repeat(64) }],
    } as Room;
    const api = {
      getState: () => ({ rooms: [room] }),
    } as unknown as BaseQueryApi;
    const channel = await compileChannelMessageLabel("chat", merkleRootHex);
    const token = new Uint8Array(64).fill(0xcc);
    const chunk = {
      transferId,
      merkleRoot: merkleRootHex,
      receiptToken: tokenHex,
      chunkIndex: 2,
    };
    let writes = 0;
    const persist = async () => {
      writes++;
      return false;
    };
    for (const changed of [
      { transferId: "other" },
      { merkleRoot: "other" },
      { receiptToken: "other" },
      { chunkIndex: -1 },
      { chunkIndex: 1.5 },
    ]) {
      expect(
        (
          await handleReadReceipt(token, channel, peerId, roomId, api, {
            getChunk: async () => ({ ...chunk, ...changed }),
            persist,
          })
        ).kind,
      ).toBe("ignored");
    }
    expect(writes).toBe(0);
    expect(
      (
        await handleReadReceipt(token, channel, peerId, roomId, api, {
          getChunk: async () => chunk,
          persist,
        })
      ).kind,
    ).toBe("ignored");
    expect(writes).toBe(1);
    expect(hasChunkAcked(roomId, peerId, transferId, 2)).toBe(false);
    clearTransfer(roomId, peerId, transferId);
  });

  test("duplicates are idempotent, peer-scoped, and never own channel close", async () => {
    const roomId = "room-receipts";
    const transferId = "11".repeat(32);
    const merkleRootHex = "22".repeat(64);
    const hashHex = "33".repeat(64);
    const room = {
      id: roomId,
      peers: [
        { peerId: "peer-a", peerPublicKey: "44".repeat(32) },
        { peerId: "peer-b", peerPublicKey: "55".repeat(32) },
      ],
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
    let durableWrites = 0;
    const persist = async () => {
      durableWrites++;
      return true;
    };

    clearTransfer(roomId, "peer-a", transferId);
    clearTransfer(roomId, "peer-b", transferId);
    const first = await handleReadReceipt(
      terminal,
      channel,
      "peer-a",
      roomId,
      api,
      { persist },
    );
    const duplicate = await handleReadReceipt(
      terminal,
      channel,
      "peer-a",
      roomId,
      api,
      { persist },
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
    expect(durableWrites).toBe(1);
    expect(isTransferComplete(roomId, "peer-a", transferId)).toBe(true);
    expect(isTransferComplete(roomId, "peer-b", transferId)).toBe(false);
    expect(room.messages[0].savedSize).toBe(0);

    clearTransfer(roomId, "peer-a", transferId);
    clearTransfer(roomId, "peer-b", transferId);
  });
});
