import { describe, expect, spyOn, test } from "bun:test";

import { storeReceiveChunkFailClosed } from "../../src/handlers/handleReceiveMessage";

import type { ReceiveChunk } from "../../src/db/types";

const storedChunk = (): Omit<ReceiveChunk, "data"> => ({
  schemaVersion: 1,
  roomId: "room-1",
  fromPeerId: "peer-1",
  channelLabel: "chat",
  timestamp: 1,
  merkleRoot: "ab".repeat(64),
  hash: "cd".repeat(64),
  filename: "",
  messageType: 1,
  chunkIndex: 0,
  mimeType: "text/plain",
  leafHash: "ef".repeat(64),
  realLen: 4,
  totalSize: 4,
  storage: "indexeddb",
});

describe("receive storage durability boundary", () => {
  test("a worker failure yields drop semantics and wipes the owned real-byte copy", async () => {
    const realChunk = Uint8Array.of(1, 2, 3, 4);
    let clonedBeforeFailure: Uint8Array | undefined;
    const errorLog = spyOn(console, "error").mockImplementation(() => {});

    try {
      const result = await storeReceiveChunkFailClosed(
        storedChunk(),
        realChunk,
        async (chunk) => {
          clonedBeforeFailure = Uint8Array.from(new Uint8Array(chunk.data));
          throw new Error("injected storage fault");
        },
      );

      expect(result).toBeNull();
      expect(Array.from(clonedBeforeFailure ?? [])).toEqual([1, 2, 3, 4]);
      expect(Array.from(realChunk)).toEqual([0, 0, 0, 0]);
    } finally {
      errorLog.mockRestore();
    }
  });
});
