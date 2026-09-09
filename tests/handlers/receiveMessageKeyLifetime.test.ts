import { describe, expect, test } from "bun:test";

import {
  bindReceiveMessageKey,
  forgetCompletedReceiveMessageKey,
  forgetMappedReceiveMessageKey,
} from "../../src/handlers/receiveMessageKeyLifetime";

import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

const makeConnection = (
  cacheKey: string,
  messageKey: Uint8Array,
): IRTCPeerConnection =>
  ({
    messageKeyCache: new Map([[cacheKey, messageKey]]),
  }) as unknown as IRTCPeerConnection;

describe("receive message-key lifetime", () => {
  test("incomplete transport close preserves the key for resume", async () => {
    const roomId = "room-resume";
    const merkleRootHex = "33".repeat(64);
    const cacheKey = "44".repeat(32);
    const messageKey = new Uint8Array([5, 6, 7, 8]);
    const epc = makeConnection(cacheKey, messageKey);
    bindReceiveMessageKey(epc, merkleRootHex, cacheKey);

    let forgetCalls = 0;
    const forgotten = await forgetCompletedReceiveMessageKey(
      epc,
      roomId,
      merkleRootHex,
      {
        savedSize: 2,
        totalSize: 4,
      },
      async () => {
        forgetCalls += 1;
      },
    );

    expect(forgotten).toBe(false);
    expect(forgetCalls).toBe(0);
    expect(epc.messageKeyCache?.get(cacheKey)).toBe(messageKey);
    expect(epc.messageKeyByMerkleRoot?.get(merkleRootHex)).toBe(cacheKey);
  });

  test("malformed zero-size or overshot progress never retires a key", async () => {
    const roomId = "room-malformed";
    const merkleRootHex = "77".repeat(64);
    const cacheKey = "88".repeat(32);
    const messageKey = new Uint8Array([13, 14, 15, 16]);
    const epc = makeConnection(cacheKey, messageKey);
    bindReceiveMessageKey(epc, merkleRootHex, cacheKey);

    let forgetCalls = 0;
    const forget = async (): Promise<void> => {
      forgetCalls += 1;
    };
    expect(
      await forgetCompletedReceiveMessageKey(
        epc,
        roomId,
        merkleRootHex,
        { savedSize: 1, totalSize: 0 },
        forget,
      ),
    ).toBe(false);
    expect(
      await forgetCompletedReceiveMessageKey(
        epc,
        roomId,
        merkleRootHex,
        { savedSize: 5, totalSize: 4 },
        forget,
      ),
    ).toBe(false);
    expect(forgetCalls).toBe(0);
    expect(epc.messageKeyCache?.get(cacheKey)).toBe(messageKey);
  });

  test("explicit cancel retires and wipes a mapped key regardless of progress", async () => {
    const roomId = "room-cancel";
    const merkleRootHex = "55".repeat(64);
    const cacheKey = "66".repeat(32);
    const messageKey = new Uint8Array([9, 10, 11, 12]);
    const epc = makeConnection(cacheKey, messageKey);
    bindReceiveMessageKey(epc, merkleRootHex, cacheKey);

    const forgotten = await forgetMappedReceiveMessageKey(
      epc,
      roomId,
      merkleRootHex,
      async (_epc, _roomId, cache: Map<string, Uint8Array>, key: string) => {
        cache.get(key)?.fill(0);
        cache.delete(key);
      },
    );

    expect(forgotten).toBe(true);
    expect(messageKey).toEqual(new Uint8Array(4));
    expect(epc.messageKeyCache?.has(cacheKey)).toBe(false);
    expect(epc.messageKeyByMerkleRoot?.has(merkleRootHex)).toBe(false);
  });

  test("concurrent close and cancel share one durable retirement", async () => {
    const roomId = "room-close-cancel";
    const merkleRootHex = "99".repeat(64);
    const cacheKey = "aa".repeat(32);
    const messageKey = new Uint8Array([17, 18, 19, 20]);
    const epc = makeConnection(cacheKey, messageKey);
    bindReceiveMessageKey(epc, merkleRootHex, cacheKey);

    let forgetCalls = 0;
    let finishForget!: () => void;
    const forgetGate = new Promise<void>((resolve) => {
      finishForget = resolve;
    });
    const forget = async (
      _epc: IRTCPeerConnection,
      _roomId: string,
      cache: Map<string, Uint8Array>,
      key: string,
    ): Promise<void> => {
      forgetCalls += 1;
      await forgetGate;
      cache.get(key)?.fill(0);
      cache.delete(key);
    };

    const close = forgetCompletedReceiveMessageKey(
      epc,
      roomId,
      merkleRootHex,
      { savedSize: 4, totalSize: 4 },
      forget,
    );
    const cancel = forgetMappedReceiveMessageKey(
      epc,
      roomId,
      merkleRootHex,
      forget,
    );
    expect(forgetCalls).toBe(1);
    finishForget();

    expect(await Promise.all([close, cancel])).toEqual([true, true]);
    expect(forgetCalls).toBe(1);
    expect(messageKey).toEqual(new Uint8Array(4));
    expect(epc.messageKeyByMerkleRoot?.has(merkleRootHex)).toBe(false);
  });
});
