import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";

import { getDB } from "../../src/db/src/getDB";
import { getWrapKey, wrapSecret } from "../../src/db/ratchetWrap";
import { MAX_MESSAGE_SIZE } from "../../src/utils/constants";

import type {
  MessageData,
  ReceiveChunk,
  ReceiveChunkStoreResult,
  RoomStats,
} from "../../src/db/types";

beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
  lastDispatchedWorkerMessage = undefined;
  lastWorkerTransferredBuffers = [];
});

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
  Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}

let nextId = 1;
let lastDispatchedWorkerMessage:
  { id: number; method: string; args: unknown[] } | undefined;
let lastWorkerTransferredBuffers: ArrayBuffer[] = [];

// Dispatches a real message through db.worker.ts's actual `onmessage` handler
// and captures whatever it posts back, matched by id.
async function callWorker(
  method: string,
  args: unknown[],
): Promise<WorkerResponse> {
  await import("../../src/db/db.worker"); // idempotent after the first call
  const id = nextId++;
  let captured: WorkerResponse | undefined;
  (
    globalThis as unknown as {
      postMessage: (
        message: unknown,
        transferOrOptions?: Transferable[] | StructuredSerializeOptions,
      ) => void;
    }
  ).postMessage = (
    message: unknown,
    transferOrOptions?: Transferable[] | StructuredSerializeOptions,
  ) => {
    const transfer = (
      Array.isArray(transferOrOptions)
        ? transferOrOptions
        : (transferOrOptions?.transfer ?? [])
    ).filter((value): value is ArrayBuffer => value instanceof ArrayBuffer);
    lastWorkerTransferredBuffers = transfer;
    captured = structuredClone(message, { transfer }) as WorkerResponse;
  };
  const handler = (
    globalThis as unknown as {
      onmessage: (e: MessageEvent) => Promise<void>;
    }
  ).onmessage;
  // A real Worker receives a structured clone. Preserve that boundary here so
  // worker-side secret wiping cannot mutate the caller's buffers in-process.
  lastDispatchedWorkerMessage = structuredClone({ id, method, args });
  await handler({ data: lastDispatchedWorkerMessage } as MessageEvent);
  if (!captured || captured.id !== id) {
    throw new Error(`worker did not respond to message id ${id}`);
  }
  return captured;
}

async function callWorkersConcurrently(
  calls: Array<{ method: string; args: unknown[] }>,
): Promise<WorkerResponse[]> {
  await import("../../src/db/db.worker");
  const responses = new Map<number, WorkerResponse>();
  const ids = calls.map(() => nextId++);
  (
    globalThis as unknown as {
      postMessage: (
        message: unknown,
        transferOrOptions?: Transferable[] | StructuredSerializeOptions,
      ) => void;
    }
  ).postMessage = (
    message: unknown,
    transferOrOptions?: Transferable[] | StructuredSerializeOptions,
  ) => {
    const transfer = Array.isArray(transferOrOptions)
      ? transferOrOptions
      : (transferOrOptions?.transfer ?? []);
    const response = structuredClone(message, { transfer }) as WorkerResponse;
    responses.set(response.id, response);
  };
  const handler = (
    globalThis as unknown as {
      onmessage: (e: MessageEvent) => Promise<void>;
    }
  ).onmessage;

  await Promise.all(
    calls.map((call, index) =>
      handler({
        data: structuredClone({
          id: ids[index],
          method: call.method,
          args: call.args,
        }),
      } as MessageEvent),
    ),
  );

  return ids.map((id) => {
    const response = responses.get(id);
    if (!response)
      throw new Error(`worker did not respond to message id ${id}`);
    return response;
  });
}

test("the worker refuses the obsolete browser ratchet checkpoint API", async () => {
  for (const method of [
    "setRatchetSession",
    "getRatchetSession",
    "deleteRatchetSession",
  ]) {
    expect((await callWorker(method, [])).error).toBe("Method not found");
  }
});

describe("db.worker PIN attempt state", () => {
  test("throttles the same stable identity without locking another peer in the room", async () => {
    const peerA = "aa".repeat(32);
    const peerB = "bb".repeat(32);

    for (let attempt = 1; attempt <= 3; attempt++) {
      const response = await callWorker("incrementPinAttemptState", [
        "room-1",
        peerA,
        10_000,
        3,
        500,
        300_000,
      ]);
      expect(response.error).toBeUndefined();
      expect(response.result).toEqual({
        failures: attempt,
        retryAfter: attempt < 3 ? 10_000 : 10_500,
      });
    }
    const throttledPeer = await callWorker("getPinAttemptState", [
      "room-1",
      peerA,
    ]);
    expect(throttledPeer.result).toEqual({
      failures: 3,
      retryAfter: 10_500,
    });

    const unaffectedPeer = await callWorker("getPinAttemptState", [
      "room-1",
      peerB,
    ]);
    expect(unaffectedPeer.result).toBeUndefined();

    const firstPeerBFailure = await callWorker("incrementPinAttemptState", [
      "room-1",
      peerB,
      10_000,
      3,
      500,
      300_000,
    ]);
    expect(firstPeerBFailure.result).toEqual({
      failures: 1,
      retryAfter: 10_000,
    });

    await callWorker("deletePinAttemptState", ["room-1", peerA]);
    const peerAAfterScopedClear = await callWorker("getPinAttemptState", [
      "room-1",
      peerA,
    ]);
    expect(peerAAfterScopedClear.result).toBeUndefined();
    const peerBAfterScopedClear = await callWorker("getPinAttemptState", [
      "room-1",
      peerB,
    ]);
    expect(peerBAfterScopedClear.result).toEqual({
      failures: 1,
      retryAfter: 10_000,
    });

    await callWorker("deletePinAttemptState", ["room-1"]);
    const peerBAfterRoomClear = await callWorker("getPinAttemptState", [
      "room-1",
      peerB,
    ]);
    expect(peerBAfterRoomClear.result).toBeUndefined();
  });
});

describe("db.worker atomic receive progress", () => {
  const receiveChunk = (
    chunkIndex: number,
    data: number[],
    overrides: Partial<ReceiveChunk> = {},
  ): ReceiveChunk => ({
    schemaVersion: 1,
    roomId: "room-1",
    fromPeerId: "peer-1",
    channelLabel: "chat",
    timestamp: 1234,
    merkleRoot: "ab".repeat(64),
    hash: "cd".repeat(64),
    filename: "",
    messageType: 1,
    chunkIndex,
    mimeType: "text/plain",
    leafHash: (chunkIndex === 0 ? "01" : "02").repeat(64),
    realLen: data.length,
    totalSize: 10,
    data: Uint8Array.from(data).buffer,
    storage: "indexeddb",
    ...overrides,
  });

  test("history keeps the authenticated sender key when a routing ID is reassigned", async () => {
    const fromPeerPublicKey = "ab".repeat(32);
    const first = receiveChunk(0, [1, 2, 3, 4, 5], { fromPeerPublicKey });
    const store = (chunk: ReceiveChunk) =>
      callWorker("storeReceiveChunk", [chunk]);
    expect((await store(first)).result).toMatchObject({
      fromPeerPublicKey,
      stored: true,
    });
    const otherKey = "cd".repeat(32);
    const next = receiveChunk(1, [6, 7, 8, 9, 10], { fromPeerPublicKey });
    const replaced = await store({ ...next, fromPeerPublicKey: otherKey });
    expect(String(replaced.error)).toContain("ownership conflicts");
    expect((await store(next)).result).toMatchObject({
      fromPeerPublicKey,
      complete: true,
    });
    expect((await store(first)).result).toMatchObject({
      fromPeerPublicKey,
      stored: false,
    });
    const history = await callWorker("getDBRoomMessageData", [first.roomId]);
    expect(history.result).toEqual([
      expect.objectContaining({ fromPeerPublicKey, savedSize: 10 }),
    ]);
  });

  test("a retransmission never attributes a legacy message to the current user of its routing ID", async () => {
    await callWorker("storeReceiveChunk", [receiveChunk(0, [1, 2, 3, 4, 5])]);
    const next = receiveChunk(1, [6, 7, 8, 9, 10], {
      fromPeerPublicKey: "ef".repeat(32),
    });
    const reply = await callWorker("storeReceiveChunk", [next]);
    expect(reply.result).toMatchObject({ complete: true });
    expect(reply.result).toMatchObject({ fromPeerPublicKey: undefined });
    const history = await callWorker("getDBRoomMessageData", [next.roomId]);
    expect(history.result).toEqual([
      expect.objectContaining({ fromPeerPublicKey: undefined }),
    ]);
  });

  test("stale receive expiry uses local activity, not attacker-controlled message timestamps", async () => {
    let now = 1_800_000_000_000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    try {
      const chunk = receiveChunk(0, [1, 2, 3, 4, 5], {
        timestamp: Number.MAX_SAFE_INTEGER,
      });
      expect(
        (await callWorker("storeReceiveChunk", [chunk])).error,
      ).toBeUndefined();
      now += 24 * 60 * 60 * 1000 - 1;
      expect((await callWorker("sweepStaleReceives", [])).result).toEqual([]);
      now += 2;
      expect((await callWorker("sweepStaleReceiveDetails", [])).result).toEqual(
        [
          {
            merkleRoot: chunk.merkleRoot,
            roomId: chunk.roomId,
            fromPeerId: chunk.fromPeerId,
          },
        ],
      );
      expect(
        (await callWorker("getDBAllChunksCount", [chunk.merkleRoot])).result,
      ).toBe(0);
      expect(
        (await callWorker("getDBMessageData", [chunk.merkleRoot])).result,
      ).toBeUndefined();
    } finally {
      clock.mockRestore();
    }
  });

  test("stale sweep preserves completed messages, sender copies and another receive owner's data", async () => {
    let now = 1_800_000_000_000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    try {
      const roots = ["31".repeat(64), "32".repeat(64), "33".repeat(64)];
      for (const merkleRoot of roots)
        expect(
          (
            await callWorker("storeReceiveChunk", [
              receiveChunk(0, [1, 2, 3, 4, 5], { merkleRoot }),
            ])
          ).error,
        ).toBeUndefined();
      expect(
        (
          await callWorker("storeReceiveChunk", [
            receiveChunk(1, [6, 7, 8, 9, 10], { merkleRoot: roots[0] }),
          ])
        ).error,
      ).toBeUndefined();
      const db = await getDB();
      const self = (await db.getFromIndex(
        "messageData",
        "merkleRoot",
        roots[1],
      ))!;
      await db.put("messageData", { ...self, transferId: "55".repeat(32) });
      for (let index = 0; index < roots.length; index++)
        await db.put("receiveActivity", {
          merkleRoot: roots[index],
          roomId: "room-1",
          fromPeerId: index === 2 ? "wrong-peer" : "peer-1",
          lastActivityAt: now,
        });
      db.close();
      now += 24 * 60 * 60 * 1000 + 1;
      expect((await callWorker("sweepStaleReceives", [])).result).toEqual([]);
      for (const merkleRoot of roots)
        expect(
          (await callWorker("getDBAllChunksCount", [merkleRoot])).result,
        ).toBeGreaterThan(0);
    } finally {
      clock.mockRestore();
    }
  });

  test("a receive queued before cancellation cannot recreate the deleted partial", async () => {
    const first = receiveChunk(0, [1, 2, 3, 4, 5], {
      merkleRoot: "41".repeat(64),
    });
    const replies = await callWorkersConcurrently([
      { method: "storeReceiveChunk", args: [first] },
      { method: "deleteReceiveTransfer", args: [first.merkleRoot] },
      {
        method: "storeReceiveChunk",
        args: [
          receiveChunk(1, [6, 7, 8, 9, 10], { merkleRoot: first.merkleRoot }),
        ],
      },
    ]);
    expect(replies[0].error).toBeUndefined();
    expect(replies[1].error).toBeUndefined();
    expect(String(replies[2].error)).toContain("cancelled");
    expect(
      (await callWorker("getDBAllChunksCount", [first.merkleRoot])).result,
    ).toBe(0);
    expect(
      (await callWorker("getDBMessageData", [first.merkleRoot])).result,
    ).toBeUndefined();
  });

  test("a queued final chunk wins over stale collection and remains complete", async () => {
    let now = 1_800_000_000_000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    try {
      const root = "42".repeat(64);
      expect(
        (
          await callWorker("storeReceiveChunk", [
            receiveChunk(0, [1, 2, 3, 4, 5], { merkleRoot: root }),
          ])
        ).error,
      ).toBeUndefined();
      now += 24 * 60 * 60 * 1000 + 1;
      const replies = await callWorkersConcurrently([
        {
          method: "storeReceiveChunk",
          args: [receiveChunk(1, [6, 7, 8, 9, 10], { merkleRoot: root })],
        },
        { method: "sweepStaleReceives", args: [] },
      ]);
      expect(replies[0].result).toEqual({
        stored: true,
        savedSize: 10,
        complete: true,
      });
      expect(replies[1].result).toEqual([]);
      expect((await callWorker("getDBAllChunksCount", [root])).result).toBe(2);
    } finally {
      clock.mockRestore();
    }
  });

  test("a live cross-worker receive lease protects stale bytes until its queued storage commits", async () => {
    let now = 1_800_000_000_000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    try {
      const root = "43".repeat(64);
      expect(
        (
          await callWorker("storeReceiveChunk", [
            receiveChunk(0, [1, 2, 3, 4, 5], { merkleRoot: root }),
          ])
        ).error,
      ).toBeUndefined();
      const db = await getDB();
      const row = (await db.get("receiveActivity", root))!;
      now += 24 * 60 * 60 * 1000 + 1;
      await db.put("receiveActivity", {
        ...row,
        writeToken: "another-worker-opfs-write",
        leaseUntil: now + 120_000,
      });
      db.close();
      expect((await callWorker("sweepStaleReceives", [])).result).toEqual([]);
      expect((await callWorker("getDBAllChunksCount", [root])).result).toBe(1);
    } finally {
      clock.mockRestore();
    }
  });

  test("guarded remote cancel refuses another owner and a receive completed by the queued final chunk", async () => {
    const root = "44".repeat(64);
    expect(
      (
        await callWorker("storeReceiveChunk", [
          receiveChunk(0, [1, 2, 3, 4, 5], { merkleRoot: root }),
        ])
      ).error,
    ).toBeUndefined();
    expect(
      (
        await callWorker("deleteReceiveTransfer", [
          root,
          { roomId: "room-1", fromPeerId: "wrong-peer", incompleteOnly: true },
        ])
      ).result,
    ).toBe(false);
    const replies = await callWorkersConcurrently([
      {
        method: "storeReceiveChunk",
        args: [receiveChunk(1, [6, 7, 8, 9, 10], { merkleRoot: root })],
      },
      {
        method: "deleteReceiveTransfer",
        args: [
          root,
          { roomId: "room-1", fromPeerId: "peer-1", incompleteOnly: true },
        ],
      },
    ]);
    expect(replies[0].result).toEqual({
      stored: true,
      savedSize: 10,
      complete: true,
    });
    expect(replies[1].result).toBe(false);
    expect((await callWorker("getDBAllChunksCount", [root])).result).toBe(2);
    const other = "45".repeat(64);
    expect(
      (
        await callWorker("storeReceiveChunk", [
          receiveChunk(0, [1, 2, 3, 4, 5], { merkleRoot: other }),
        ])
      ).error,
    ).toBeUndefined();
    expect(
      (
        await callWorker("deleteReceiveTransfer", [
          other,
          { roomId: "room-1", fromPeerId: "peer-1", incompleteOnly: true },
        ])
      ).result,
    ).toBe(true);
    expect((await callWorker("getDBAllChunksCount", [other])).result).toBe(0);
  });

  test("a duplicate chunk cannot falsely complete while another chunk is absent", async () => {
    const chunk0 = receiveChunk(0, [0, 1, 2, 3, 4]);

    const first = await callWorker("storeReceiveChunk", [chunk0]);
    expect(first.error).toBeUndefined();
    expect(first.result as ReceiveChunkStoreResult).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });
    const afterFirst = await callWorker("getDBMessageData", [
      chunk0.merkleRoot,
      undefined,
    ]);
    expect(
      (afterFirst.result as { savedSize: number } | undefined)?.savedSize,
    ).toBe(5);

    const duplicate = await callWorker("storeReceiveChunk", [chunk0]);
    expect(duplicate.error).toBeUndefined();
    expect(duplicate.result as ReceiveChunkStoreResult).toEqual({
      stored: false,
      savedSize: 5,
      complete: false,
    });
    const afterDuplicate = await callWorker("getDBMessageData", [
      chunk0.merkleRoot,
      undefined,
    ]);
    expect(
      (afterDuplicate.result as { savedSize: number } | undefined)?.savedSize,
    ).toBe(5);

    const final = await callWorker("storeReceiveChunk", [
      receiveChunk(1, [5, 6, 7, 8, 9]),
    ]);
    expect(final.error).toBeUndefined();
    expect(final.result as ReceiveChunkStoreResult).toEqual({
      stored: true,
      savedSize: 10,
      complete: true,
    });
    const afterFinal = await callWorker("getDBMessageData", [
      chunk0.merkleRoot,
      undefined,
    ]);
    expect(
      (afterFinal.result as { savedSize: number } | undefined)?.savedSize,
    ).toBe(10);
  });

  test("out-of-order contiguous chunks complete against one canonical manifest", async () => {
    const root = "ef".repeat(64);
    const finalFirst = receiveChunk(1, [5, 6, 7, 8, 9], {
      merkleRoot: root,
    });
    const partial = await callWorker("storeReceiveChunk", [finalFirst]);
    expect(partial.error).toBeUndefined();
    expect(partial.result as ReceiveChunkStoreResult).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });

    const completed = await callWorker("storeReceiveChunk", [
      receiveChunk(0, [0, 1, 2, 3, 4], { merkleRoot: root }),
    ]);
    expect(completed.error).toBeUndefined();
    expect(completed.result as ReceiveChunkStoreResult).toEqual({
      stored: true,
      savedSize: 10,
      complete: true,
    });
  });

  test("a same-size index gap is rejected and cannot claim byte-sum completion", async () => {
    const root = "12".repeat(64);
    const first = await callWorker("storeReceiveChunk", [
      receiveChunk(0, [0, 1, 2, 3, 4], { merkleRoot: root }),
    ]);
    expect(first.error).toBeUndefined();

    const gap = await callWorker("storeReceiveChunk", [
      receiveChunk(2, [5, 6, 7, 8, 9], { merkleRoot: root }),
    ]);
    expect(String(gap.error)).toContain("canonical manifest");

    const message = await callWorker("getDBMessageData", [root, undefined]);
    expect(
      (message.result as { savedSize: number } | undefined)?.savedSize,
    ).toBe(5);
    const count = await callWorker("getDBAllChunksCount", [root, undefined]);
    expect(count.result).toBe(1);
  });

  test("an inconsistent manifest aborts without stranding a chunk outside messageData", async () => {
    const root = "34".repeat(64);
    const first = await callWorker("storeReceiveChunk", [
      receiveChunk(0, [0, 1, 2, 3, 4], { merkleRoot: root }),
    ]);
    expect(first.error).toBeUndefined();

    const conflict = await callWorker("storeReceiveChunk", [
      receiveChunk(1, [5, 6, 7, 8, 9], {
        merkleRoot: root,
        hash: "99".repeat(64),
      }),
    ]);
    expect(String(conflict.error)).toContain("conflicts with message");

    const message = await callWorker("getDBMessageData", [root, undefined]);
    expect(message.result).toMatchObject({
      hash: "cd".repeat(64),
      savedSize: 5,
      totalSize: 10,
    });
    const count = await callWorker("getDBAllChunksCount", [root, undefined]);
    expect(count.result).toBe(1);
  });

  test("rejects unsupported schemas, message types, oversized totals, and unsafe integers", async () => {
    const invalid: Array<Partial<ReceiveChunk>> = [
      { schemaVersion: 2 },
      { messageType: 0 },
      { messageType: 65 },
      { totalSize: MAX_MESSAGE_SIZE + 1 },
      { chunkIndex: Number.MAX_SAFE_INTEGER + 1 },
      { timestamp: Number.MAX_SAFE_INTEGER + 1 },
    ];

    for (let index = 0; index < invalid.length; index++) {
      const response = await callWorker("storeReceiveChunk", [
        receiveChunk(0, [1], {
          merkleRoot: index.toString(16).padStart(2, "0").repeat(64),
          totalSize: 1,
          ...invalid[index],
        }),
      ]);
      expect(String(response.error)).toContain("invalid receive chunk bounds");
    }
  });

  test("closes an acquired OPFS handle when pre-sizing throws", async () => {
    const navigatorDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "navigator",
    );
    let closeCalls = 0;
    const access = {
      getSize: () => 0,
      truncate: () => {
        throw new Error("injected truncate failure");
      },
      write: () => 0,
      flush: () => {},
      close: () => {
        closeCalls += 1;
      },
    };
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        storage: {
          getDirectory: async () => ({
            getDirectoryHandle: async () => ({
              getFileHandle: async () => ({
                createSyncAccessHandle: async () => access,
              }),
            }),
          }),
        },
      },
    });
    const errorLog = spyOn(console, "error").mockImplementation(() => {});

    try {
      const response = await callWorker("storeReceiveChunk", [
        receiveChunk(0, [7], {
          merkleRoot: "77".repeat(64),
          // The file's real whole-file hash, so completion verifies.
          hash: createHash("sha512").update(Uint8Array.of(7)).digest("hex"),
          messageType: 2,
          totalSize: 1,
          storage: "opfs",
        }),
      ]);
      // The storage layer safely falls back to IndexedDB, but the exclusive
      // handle acquired before truncate failed must already be released.
      expect(response.error).toBeUndefined();
      // Its only chunk is held until the file verifies, from the bytes kept
      // in IndexedDB since OPFS failed.
      const held = response.result as { verification: string };
      expect(held).toMatchObject({ stored: true, complete: false });
      const root = "77".repeat(64);
      expect(
        (
          await callWorker("verifyReceivedFile", [
            root,
            held.verification,
            "test-holder",
          ])
        ).result,
      ).toBe("match");
      expect(
        (
          await callWorker("settleReceivedFileVerification", [
            root,
            held.verification,
            true,
            "test-holder",
          ])
        ).result,
      ).toBe("complete");
      expect(closeCalls).toBe(1);
    } finally {
      errorLog.mockRestore();
      if (navigatorDescriptor)
        Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
      else delete (globalThis as { navigator?: unknown }).navigator;
    }
  });

  test("cancellation queues behind an in-flight store and leaves no receive artifacts", async () => {
    const root = "88".repeat(64);
    const chunk = receiveChunk(0, [1, 2, 3, 4, 5], {
      merkleRoot: root,
    });

    const [stored, deleted] = await callWorkersConcurrently([
      { method: "storeReceiveChunk", args: [chunk] },
      { method: "deleteReceiveTransfer", args: [root] },
    ]);
    expect(stored.error).toBeUndefined();
    expect(deleted.error).toBeUndefined();

    const message = await callWorker("getDBMessageData", [root, undefined]);
    const chunks = await callWorker("getDBAllChunksCount", [root, undefined]);
    expect(message.result).toBeUndefined();
    expect(chunks.result).toBe(0);
  });

  test("rejects malformed receive-transfer deletion roots", async () => {
    const response = await callWorker("deleteReceiveTransfer", ["not-a-root"]);
    expect(String(response.error)).toContain(
      "invalid receive transfer Merkle root",
    );
  });

  test("targeted chunk deletion accepts index zero", async () => {
    const root = "99".repeat(64);
    const stored = await callWorker("storeReceiveChunk", [
      receiveChunk(0, [9, 9, 9, 9, 9], { merkleRoot: root }),
    ]);
    expect(stored.error).toBeUndefined();
    await callWorker("deleteDBChunk", [root, 0]);
    const chunks = await callWorker("getDBAllChunksCount", [root, undefined]);
    expect(chunks.result).toBe(0);
  });
});

describe("db.worker room policy persistence", () => {
  test("moves a legacy known-contacts preference once and preserves later choices", async () => {
    const roomUrl = "fa".repeat(32);
    const db = await getDB();
    await db.put("uniqueRoom", {
      roomUrl,
      roomId: "00000000-0000-4000-8000-000000000017",
      messageCount: 0,
      lastMessageMerkleRoot: "",
      createdAt: 1,
      updatedAt: 1,
    });
    db.close();
    const legacy = { [roomUrl]: true };
    const first = await callWorker("getAllDBUniqueRooms", [legacy]);
    expect(first.result).toMatchObject([{ onlyConnectWithKnownPeers: true }]);
    await callWorker("setDBRoomKnownOnly", [roomUrl, false]);
    const second = await callWorker("getAllDBUniqueRooms", [legacy]);
    expect(second.result).toMatchObject([{ onlyConnectWithKnownPeers: false }]);
    await callWorker("setDBRoomKnownOnly", ["11".repeat(32), true]);
    expect((await callWorker("getAllDBUniqueRooms", [])).result).toHaveLength(
      1,
    );
  });

  test("stores and updates the canonical public policy with the room record", async () => {
    const roomUrl = "ef".repeat(32);
    const roomId = "00000000-0000-4000-8000-000000000017";
    const initial = new Uint8Array(32);
    initial[0] = 1;

    const set = await callWorker("setDBUniqueRoom", [
      roomUrl,
      roomId,
      initial.buffer,
    ]);
    expect(set.error).toBeUndefined();

    const updated = Uint8Array.from(initial);
    updated[1] = 3;
    const update = await callWorker("setDBUniqueRoom", [
      roomUrl,
      roomId,
      updated.buffer,
    ]);
    expect(update.error).toBeUndefined();

    const get = await callWorker("getAllDBUniqueRooms", []);
    expect(get.error).toBeUndefined();
    const rooms = get.result as Array<{ roomPolicy?: ArrayBuffer }>;
    expect(rooms).toHaveLength(1);
    expect(
      Array.from(new Uint8Array(rooms[0].roomPolicy as ArrayBuffer)),
    ).toEqual(Array.from(updated));
  });
});

describe("db.worker identityX25519 wiring (WebCrypto-wrapped at rest)", () => {
  const sampleIdentity = () => ({
    pub: rnd(32),
    secret: rnd(32),
    crossSig: rnd(64),
  });

  test("setIdentityX25519 -> getIdentityX25519 round-trips pub/secret/crossSig", async () => {
    const idn = sampleIdentity();
    const setResp = await callWorker("setIdentityX25519", [idn]);
    expect(setResp.error).toBeUndefined();

    const getResp = await callWorker("getIdentityX25519", []);
    expect(getResp.error).toBeUndefined();
    const got = getResp.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      crossSig: ArrayBuffer;
    };
    expect(got).toBeDefined();
    expect(eq(got.pub, idn.pub)).toBe(true);
    expect(eq(got.secret, idn.secret)).toBe(true);
    expect(eq(got.crossSig, idn.crossSig)).toBe(true);
  });

  test("KEY SECURITY ASSERTION: the raw stored identity secret is ciphertext; pub/crossSig are plaintext", async () => {
    const idn = sampleIdentity();
    await callWorker("setIdentityX25519", [idn]);

    // Read the raw record directly, bypassing the unwrap step.
    const db = await getDB();
    const raw = (await db.get("meta", "identityX25519")) as unknown as {
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      crossSig: ArrayBuffer;
    };
    db.close();

    expect(raw).toBeDefined();
    // secret is wrapped (iv||ct): different bytes AND longer than the 32B plaintext.
    expect(eq(raw.wrappedSecret, idn.secret)).toBe(false);
    expect(raw.wrappedSecret.byteLength).toBeGreaterThan(idn.secret.byteLength);
    // public fields are stored in the clear.
    expect(eq(raw.pub, idn.pub)).toBe(true);
    expect(eq(raw.crossSig, idn.crossSig)).toBe(true);
  });

  test("deleteIdentityX25519 removes the identity", async () => {
    const idn = sampleIdentity();
    await callWorker("setIdentityX25519", [idn]);
    expect((await callWorker("getIdentityX25519", [])).result).toBeDefined();

    const delResp = await callWorker("deleteIdentityX25519", []);
    expect(delResp.error).toBeUndefined();

    const after = await callWorker("getIdentityX25519", []);
    expect(after.result).toBeUndefined();
  });

  test("getIdentityX25519 with no record returns undefined (not an error)", async () => {
    const resp = await callWorker("getIdentityX25519", []);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeUndefined();
  });
});

describe("db.worker identityEd25519 wiring (WebCrypto-wrapped at rest)", () => {
  const revisionMetaId = "identityEd25519Revision";
  const uint64Max = 0xffff_ffff_ffff_ffffn;
  const identityVectors = [
    {
      seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    },
    {
      seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    },
    {
      seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    },
  ] as const;
  let identityVectorIndex = 0;
  beforeEach(() => {
    identityVectorIndex = 0;
  });
  const sampleIdentity = () => {
    const vector =
      identityVectors[identityVectorIndex++ % identityVectors.length];
    const publicBytes = Uint8Array.from(Buffer.from(vector.pub, "hex"));
    const secretBytes = new Uint8Array(64);
    secretBytes.set(Buffer.from(vector.seed, "hex"));
    secretBytes.set(publicBytes, 32);
    return {
      pub: publicBytes.buffer,
      secret: secretBytes.buffer,
    };
  };

  test("round-trips a bigint revision while keeping the raw secret encrypted", async () => {
    const identity = sampleIdentity();
    const set = await callWorker("setIdentityEd25519", [identity]);
    expect(set.error).toBeUndefined();
    expect(set.result).toBe(1n);
    const dispatchedSetIdentity = lastDispatchedWorkerMessage?.args[0] as {
      secret: ArrayBuffer;
    };
    expect(
      [...new Uint8Array(dispatchedSetIdentity.secret)].every(
        (value) => value === 0,
      ),
    ).toBe(true);

    const get = await callWorker("getIdentityEd25519", []);
    expect(get.error).toBeUndefined();
    const restored = get.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(eq(restored.pub, identity.pub)).toBe(true);
    expect(eq(restored.secret, identity.secret)).toBe(true);
    expect(restored.recordRevision).toBe(1n);
    expect(lastWorkerTransferredBuffers).toHaveLength(1);
    expect(lastWorkerTransferredBuffers[0].byteLength).toBe(0);

    const db = await getDB();
    const raw = (await db.get("meta", "identityEd25519")) as unknown as {
      version: number;
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      recordRevision: bigint;
    };
    const revision = (await db.get("meta", revisionMetaId)) as unknown as {
      version: number;
      lastRevision: bigint;
    };
    db.close();
    expect(raw.version).toBe(1);
    expect(raw.recordRevision).toBe(1n);
    expect(revision).toEqual({ version: 1, lastRevision: 1n });
    expect(eq(raw.pub, identity.pub)).toBe(true);
    expect(eq(raw.wrappedSecret, identity.secret)).toBe(false);
    expect(raw.wrappedSecret.byteLength).toBeGreaterThan(
      identity.secret.byteLength,
    );
  });

  test("overwrites monotonically and returns each allocated revision", async () => {
    const first = sampleIdentity();
    const second = sampleIdentity();

    expect((await callWorker("setIdentityEd25519", [first])).result).toBe(1n);
    expect((await callWorker("setIdentityEd25519", [second])).result).toBe(2n);

    const get = await callWorker("getIdentityEd25519", []);
    const restored = get.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(restored.recordRevision).toBe(2n);
    expect(eq(restored.pub, second.pub)).toBe(true);
    expect(eq(restored.secret, second.secret)).toBe(true);
  });

  test("serializes concurrent sets into unique revisions and a matching final row", async () => {
    const identities = [sampleIdentity(), sampleIdentity(), sampleIdentity()];
    const responses = await callWorkersConcurrently(
      identities.map((identity) => ({
        method: "setIdentityEd25519",
        args: [identity],
      })),
    );
    expect(responses.every((response) => response.error === undefined)).toBe(
      true,
    );

    const allocations = responses.map((response, index) => ({
      revision: response.result as bigint,
      identity: identities[index],
    }));
    expect(
      allocations
        .map(({ revision }) => revision)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    ).toEqual([1n, 2n, 3n]);

    const winner = allocations.find(({ revision }) => revision === 3n);
    expect(winner).toBeDefined();
    const get = await callWorker("getIdentityEd25519", []);
    const restored = get.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(restored.recordRevision).toBe(3n);
    expect(eq(restored.pub, winner!.identity.pub)).toBe(true);
    expect(eq(restored.secret, winner!.identity.secret)).toBe(true);
  });

  test("delete records a tombstone, repeated delete is idempotent, and recreate cannot ABA", async () => {
    const first = sampleIdentity();
    const second = sampleIdentity();
    expect((await callWorker("setIdentityEd25519", [first])).result).toBe(1n);

    expect(
      (await callWorker("deleteIdentityEd25519", [])).error,
    ).toBeUndefined();
    const dbAfterDelete = await getDB();
    expect(await dbAfterDelete.get("meta", "identityEd25519")).toBeUndefined();
    expect(await dbAfterDelete.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 2n,
    });
    dbAfterDelete.close();

    expect(
      (await callWorker("deleteIdentityEd25519", [])).error,
    ).toBeUndefined();
    const dbAfterRepeatedDelete = await getDB();
    expect(await dbAfterRepeatedDelete.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 2n,
    });
    dbAfterRepeatedDelete.close();

    expect((await callWorker("setIdentityEd25519", [second])).result).toBe(3n);
    const restored = (await callWorker("getIdentityEd25519", [])).result as {
      pub: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(restored.recordRevision).toBe(3n);
    expect(eq(restored.pub, second.pub)).toBe(true);
  });

  test("concurrent identity set/delete linearizes revisions", async () => {
    const first = sampleIdentity();
    const replacement = sampleIdentity();
    expect((await callWorker("setIdentityEd25519", [first])).result).toBe(1n);

    const [set, del] = await callWorkersConcurrently([
      { method: "setIdentityEd25519", args: [replacement] },
      { method: "deleteIdentityEd25519", args: [] },
    ]);
    expect(set.error).toBeUndefined();
    expect(del.error).toBeUndefined();
    expect([2n, 3n]).toContain(set.result as bigint);

    const get = await callWorker("getIdentityEd25519", []);
    if (set.result === 2n) {
      // set(2) linearized first, then delete retired it at tombstone 3.
      expect(get.result).toBeUndefined();
    } else {
      // delete retired revision 1 at tombstone 2, then set allocated 3.
      const restored = get.result as {
        pub: ArrayBuffer;
        secret: ArrayBuffer;
        recordRevision: bigint;
      };
      expect(restored.recordRevision).toBe(3n);
      expect(eq(restored.pub, replacement.pub)).toBe(true);
      expect(eq(restored.secret, replacement.secret)).toBe(true);
    }

    const db = await getDB();
    expect(await db.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 3n,
    });
    db.close();
  });

  test("lazily migrates a legacy identity and absent counter as one revision", async () => {
    const identity = sampleIdentity();
    const wrappedSecret = await wrapSecret(await getWrapKey(), identity.secret);
    const db = await getDB();
    await db.put(
      "meta",
      { pub: identity.pub, wrappedSecret } as never,
      "identityEd25519",
    );
    db.close();

    const get = await callWorker("getIdentityEd25519", []);
    expect(get.error).toBeUndefined();
    const restored = get.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(restored.recordRevision).toBe(1n);
    expect(eq(restored.pub, identity.pub)).toBe(true);
    expect(eq(restored.secret, identity.secret)).toBe(true);

    const migratedDb = await getDB();
    const raw = (await migratedDb.get(
      "meta",
      "identityEd25519",
    )) as unknown as {
      version: number;
      recordRevision: bigint;
    };
    expect(raw.version).toBe(1);
    expect(raw.recordRevision).toBe(1n);
    expect(await migratedDb.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 1n,
    });
    migratedDb.close();
  });

  test("direct legacy delete reserves revision 1, writes tombstone 2", async () => {
    const legacyIdentity = sampleIdentity();
    const wrappedSecret = await wrapSecret(
      await getWrapKey(),
      legacyIdentity.secret,
    );
    const db = await getDB();
    await db.put(
      "meta",
      { pub: legacyIdentity.pub, wrappedSecret } as never,
      "identityEd25519",
    );
    db.close();

    const del = await callWorker("deleteIdentityEd25519", []);
    expect(del.error).toBeUndefined();

    const after = await getDB();
    expect(await after.get("meta", "identityEd25519")).toBeUndefined();
    expect(await after.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 2n,
    });
    after.close();
  });

  test("a direct overwrite of a legacy identity allocates after its migration revision", async () => {
    const legacyIdentity = sampleIdentity();
    const replacement = sampleIdentity();
    const wrappedSecret = await wrapSecret(
      await getWrapKey(),
      legacyIdentity.secret,
    );
    const db = await getDB();
    await db.put(
      "meta",
      { pub: legacyIdentity.pub, wrappedSecret } as never,
      "identityEd25519",
    );
    db.close();

    const set = await callWorker("setIdentityEd25519", [replacement]);
    expect(set.error).toBeUndefined();
    expect(set.result).toBe(2n);

    const get = await callWorker("getIdentityEd25519", []);
    const restored = get.result as {
      pub: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(restored.recordRevision).toBe(2n);
    expect(eq(restored.pub, replacement.pub)).toBe(true);
    const finalDb = await getDB();
    expect(await finalDb.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 2n,
    });
    finalDb.close();
  });

  test("a get racing a legacy overwrite returns a coherent revision and preserves the replacement", async () => {
    const legacyIdentity = sampleIdentity();
    const replacement = sampleIdentity();
    const wrappedSecret = await wrapSecret(
      await getWrapKey(),
      legacyIdentity.secret,
    );
    const db = await getDB();
    await db.put(
      "meta",
      { pub: legacyIdentity.pub, wrappedSecret } as never,
      "identityEd25519",
    );
    db.close();

    const [get, set] = await callWorkersConcurrently([
      { method: "getIdentityEd25519", args: [] },
      { method: "setIdentityEd25519", args: [replacement] },
    ]);
    expect(get.error).toBeUndefined();
    expect(set.error).toBeUndefined();
    expect(set.result).toBe(2n);
    const racedRead = get.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect([1n, 2n]).toContain(racedRead.recordRevision);
    if (racedRead.recordRevision === 1n) {
      expect(eq(racedRead.pub, legacyIdentity.pub)).toBe(true);
      expect(eq(racedRead.secret, legacyIdentity.secret)).toBe(true);
    } else {
      expect(eq(racedRead.pub, replacement.pub)).toBe(true);
      expect(eq(racedRead.secret, replacement.secret)).toBe(true);
    }

    const final = (await callWorker("getIdentityEd25519", [])).result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      recordRevision: bigint;
    };
    expect(final.recordRevision).toBe(2n);
    expect(eq(final.pub, replacement.pub)).toBe(true);
    expect(eq(final.secret, replacement.secret)).toBe(true);
  });

  test("rejects invalid lengths and mismatched public/secret material without allocating", async () => {
    const invalid = await callWorker("setIdentityEd25519", [
      { pub: rnd(31), secret: rnd(64) },
    ]);
    expect(String(invalid.error)).toContain("invalid key lengths");

    const mismatched = sampleIdentity();
    mismatched.pub = rnd(32);
    const mismatch = await callWorker("setIdentityEd25519", [mismatched]);
    expect(String(mismatch.error)).toContain(
      "public key does not match the secret key",
    );
    const rejectedWorkerSecret = (
      lastDispatchedWorkerMessage?.args[0] as { secret: ArrayBuffer }
    ).secret;
    expect(
      [...new Uint8Array(rejectedWorkerSecret)].every((value) => value === 0),
    ).toBe(true);

    const db = await getDB();
    expect(await db.get("meta", "identityEd25519")).toBeUndefined();
    expect(await db.get("meta", revisionMetaId)).toBeUndefined();
    db.close();
  });

  test("rejects a stored public/secret mismatch without returning custody material", async () => {
    const identity = sampleIdentity();
    await callWorker("setIdentityEd25519", [identity]);
    const db = await getDB();
    const raw = (await db.get("meta", "identityEd25519")) as unknown as {
      version: 1;
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      recordRevision: bigint;
    };
    await db.put("meta", { ...raw, pub: rnd(32) }, "identityEd25519");
    db.close();

    const get = await callWorker("getIdentityEd25519", []);
    expect(String(get.error)).toContain(
      "public and secret keys are inconsistent",
    );
    expect(get.result).toBeUndefined();
  });

  test("does not migrate or overwrite a malformed stored identity", async () => {
    const identity = sampleIdentity();
    const malformed = {
      pub: identity.pub,
      wrappedSecret: rnd(91),
    };
    const db = await getDB();
    await db.put("meta", malformed as never, "identityEd25519");
    db.close();

    const get = await callWorker("getIdentityEd25519", []);
    expect(String(get.error)).toContain("wrapped secret is malformed");
    const set = await callWorker("setIdentityEd25519", [sampleIdentity()]);
    expect(String(set.error)).toContain("wrapped secret is malformed");

    const after = await getDB();
    const raw = (await after.get("meta", "identityEd25519")) as unknown as {
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      version?: number;
    };
    expect(raw.version).toBeUndefined();
    expect(eq(raw.pub, malformed.pub)).toBe(true);
    expect(eq(raw.wrappedSecret, malformed.wrappedSecret)).toBe(true);
    expect(await after.get("meta", revisionMetaId)).toBeUndefined();
    after.close();
  });

  test("fails closed on malformed and overflow revision state without partial mutation", async () => {
    const identity = sampleIdentity();
    const malformedDb = await getDB();
    await malformedDb.put(
      "meta",
      { version: 1, lastRevision: "1" } as never,
      revisionMetaId,
    );
    malformedDb.close();

    const malformedSet = await callWorker("setIdentityEd25519", [identity]);
    expect(String(malformedSet.error)).toContain("must be a uint64");
    const afterMalformed = await getDB();
    expect(await afterMalformed.get("meta", "identityEd25519")).toBeUndefined();
    expect(await afterMalformed.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: "1",
    } as never);
    afterMalformed.close();

    (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
      new IDBFactory();
    const overflowDb = await getDB();
    await overflowDb.put(
      "meta",
      { version: 1, lastRevision: uint64Max },
      revisionMetaId,
    );
    overflowDb.close();

    const overflowSet = await callWorker("setIdentityEd25519", [identity]);
    expect(String(overflowSet.error)).toContain("revision overflow");
    const afterOverflow = await getDB();
    expect(await afterOverflow.get("meta", "identityEd25519")).toBeUndefined();
    expect(await afterOverflow.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: uint64Max,
    });
    afterOverflow.close();
  });

  test("overflowing delete retains the identity", async () => {
    const identity = sampleIdentity();
    const wrappedSecret = await wrapSecret(await getWrapKey(), identity.secret);
    const db = await getDB();
    const tx = db.transaction("meta", "readwrite");
    await Promise.all([
      tx.store.put(
        {
          version: 1,
          pub: identity.pub,
          wrappedSecret,
          recordRevision: uint64Max,
        },
        "identityEd25519",
      ),
      tx.store.put({ version: 1, lastRevision: uint64Max }, revisionMetaId),
    ]);
    await tx.done;
    db.close();

    const del = await callWorker("deleteIdentityEd25519", []);
    expect(String(del.error)).toContain("revision overflow");

    const after = await getDB();
    expect(await after.get("meta", "identityEd25519")).toBeDefined();
    expect(await after.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: uint64Max,
    });
    after.close();
  });

  test("delete retains the identity tombstone", async () => {
    const identity = sampleIdentity();
    await callWorker("setIdentityEd25519", [identity]);

    const del = await callWorker("deleteIdentityEd25519", []);
    expect(del.error).toBeUndefined();
    expect((await callWorker("getIdentityEd25519", [])).result).toBeUndefined();

    const db = await getDB();
    expect(await db.get("meta", revisionMetaId)).toEqual({
      version: 1,
      lastRevision: 2n,
    });
    db.close();
  });
});

describe("db.worker identityDerivation wiring (non-secret provenance flag)", () => {
  // The flag is bound to the account key it describes, so a rotation must be
  // reproducible here: RFC 8032 vectors give two distinct valid identities.
  const edVectors = [
    {
      seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    },
    {
      seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    },
  ] as const;

  // setIdentityEd25519 takes ownership of the secret buffer and zeroes it, so
  // every store needs a freshly built identity.
  const edIdentity = (index: number) => {
    const vector = edVectors[index];
    const publicBytes = Uint8Array.from(Buffer.from(vector.pub, "hex"));
    const secretBytes = new Uint8Array(64);
    secretBytes.set(Buffer.from(vector.seed, "hex"));
    secretBytes.set(publicBytes, 32);
    return { pub: publicBytes.buffer, secret: secretBytes.buffer };
  };

  test("getIdentityDerivation is null before anything was ever recorded", async () => {
    const resp = await callWorker("getIdentityDerivation", []);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeNull();
  });

  test("set -> get round-trips each derivation and overwrites in place", async () => {
    const setMnemonic = await callWorker("setIdentityDerivation", ["mnemonic"]);
    expect(setMnemonic.error).toBeUndefined();
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "mnemonic",
    );

    const setRandom = await callWorker("setIdentityDerivation", ["random"]);
    expect(setRandom.error).toBeUndefined();
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "random",
    );
  });

  test("deleteIdentityDerivation clears the flag back to null", async () => {
    await callWorker("setIdentityDerivation", ["mnemonic"]);
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "mnemonic",
    );

    const del = await callWorker("deleteIdentityDerivation", []);
    expect(del.error).toBeUndefined();
    const after = await callWorker("getIdentityDerivation", []);
    expect(after.error).toBeUndefined();
    expect(after.result).toBeNull();

    const db = await getDB();
    expect(await db.get("meta", "identityDerivation")).toBeUndefined();
    db.close();
  });

  test("deleting a flag that was never written is not an error", async () => {
    const del = await callWorker("deleteIdentityDerivation", []);
    expect(del.error).toBeUndefined();
    expect((await callWorker("getIdentityDerivation", [])).result).toBeNull();
  });

  test("rejects an unknown derivation and leaves the stored flag untouched", async () => {
    await callWorker("setIdentityDerivation", ["mnemonic"]);

    const bad = await callWorker("setIdentityDerivation", ["imported"]);
    expect(bad.error).toBeDefined();
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "mnemonic",
    );
  });

  test("the stored row is plaintext, non-secret metadata", async () => {
    await callWorker("setIdentityDerivation", ["mnemonic"]);

    const db = await getDB();
    const raw = (await db.get("meta", "identityDerivation")) as unknown as {
      version: number;
      derivation: string;
    };
    db.close();

    expect(raw.version).toBe(1);
    expect(raw.derivation).toBe("mnemonic");
  });

  test("a corrupt row reads back as null instead of claiming recoverability", async () => {
    const db = await getDB();
    await db.put(
      "meta",
      { version: 2, derivation: "mnemonic" } as never,
      "identityDerivation",
    );
    db.close();

    const resp = await callWorker("getIdentityDerivation", []);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeNull();
  });

  test("a flag left over from a previous account key reads back as null", async () => {
    await callWorker("setIdentityEd25519", [edIdentity(0)]);
    await callWorker("setIdentityDerivation", ["mnemonic"]);
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "mnemonic",
    );

    // Rotating the account key without touching the flag must not let the old
    // "recoverable" claim describe the new, unrelated identity.
    await callWorker("setIdentityEd25519", [edIdentity(1)]);
    expect((await callWorker("getIdentityDerivation", [])).result).toBeNull();
  });

  test("a flag recorded before any account key still reads back", async () => {
    await callWorker("setIdentityDerivation", ["random"]);
    expect((await callWorker("getIdentityDerivation", [])).result).toBe(
      "random",
    );
  });
});

describe("getDBRoomStats", () => {
  const roomId = "11111111-1111-4111-8111-111111111111";
  const peerA = "aaaaaaaa-1111-4111-8111-111111111111";
  const peerB = "bbbbbbbb-1111-4111-8111-111111111111";

  const message = (over: Partial<MessageData>): MessageData => ({
    roomId,
    timestamp: 1,
    fromPeerId: peerA,
    channelLabel: "c",
    hash: "h",
    merkleRoot: "m",
    filename: "f",
    messageType: 1,
    savedSize: 0,
    totalSize: 0,
    ...over,
  });

  const seed = async (rows: MessageData[]) => {
    const db = await getDB();
    const tx = db.transaction("messageData", "readwrite");
    await Promise.all(
      rows.map((row, index) =>
        tx.store.put({ ...row, hash: `h${index}`, merkleRoot: `m${index}` }),
      ),
    );
    await tx.done;
    db.close();
  };

  test("splits sent from received by transferId, not by peer id", async () => {
    // transferId is written only on rows this device sent, which is the only
    // discriminator available without knowing our own peer id.
    await seed([
      message({ transferId: "t1", totalSize: 1000, savedSize: 1000 }),
      message({ transferId: "t2", totalSize: 500, savedSize: 500 }),
      message({ fromPeerId: peerA, totalSize: 300, savedSize: 300 }),
      message({ fromPeerId: peerB, totalSize: 200, savedSize: 200 }),
    ]);

    const { result } = await callWorker("getDBRoomStats", [roomId]);
    const stats = result as RoomStats;

    expect(stats.messagesSent).toBe(2);
    expect(stats.messagesReceived).toBe(2);
    expect(stats.bytesSent).toBe(1500);
    expect(stats.bytesReceived).toBe(500);
    expect(stats.bytesTotal).toBe(2000);
    expect(stats.messageCount).toBe(4);
    // Only peers we received from; our own sends are not "historical peers".
    expect([...stats.peerIds].sort()).toEqual([peerA, peerB].sort());
  });

  test("a partially received message counts what arrived, not what was promised", async () => {
    // Otherwise an abandoned 10 GiB transfer would report 10 GiB received.
    await seed([
      message({ fromPeerId: peerA, totalSize: 10_000, savedSize: 40 }),
    ]);

    const { result } = await callWorker("getDBRoomStats", [roomId]);
    expect((result as RoomStats).bytesReceived).toBe(40);
  });

  test("a room with no messages reports zeroes rather than failing", async () => {
    const { result } = await callWorker("getDBRoomStats", [
      "99999999-9999-4999-8999-999999999999",
    ]);
    const stats = result as RoomStats;
    expect(stats.messageCount).toBe(0);
    expect(stats.bytesTotal).toBe(0);
    expect(stats.peerIds).toEqual([]);
  });
});

test("receipt lookup returns only its scope and index, while a full staged read transfers its buffers", async () => {
  const merkleRoot = "01".repeat(64);
  const receiptToken = "02".repeat(64);
  const row = {
    transferId: "11".repeat(32),
    chunkIndex: 0,
    hash: merkleRoot,
    leafHash: merkleRoot,
    merkleRoot,
    receiptToken,
    data: rnd(1024),
    metadata: rnd(64),
    merkleProof: rnd(80),
  };
  expect((await callWorker("setDBNewChunk", [row])).error).toBeUndefined();
  const found = await callWorker("getDBNewChunkByReceipt", [
    merkleRoot,
    receiptToken,
  ]);
  expect(found.result).toEqual({
    transferId: row.transferId,
    chunkIndex: 0,
    merkleRoot,
    receiptToken,
  });
  const full = await callWorker("getDBNewChunk", [row.transferId, 0]);
  expect((full.result as typeof row).data).toEqual(row.data);
  expect(
    lastWorkerTransferredBuffers.map((buffer) => buffer.byteLength),
  ).toEqual([0, 0, 0]);
});

describe("contact and blacklist identity", () => {
  test("a blocked key stays blocked across routing IDs and repeated writes keep one record", async () => {
    const key = "ab".repeat(32);
    const other = "cd".repeat(32);
    expect(
      (await callWorker("setDBPeerInBlacklist", ["old-id", key])).error,
    ).toBeUndefined();
    expect((await callWorker("getDBPeerIsBlacklisted", [key])).result).toBe(
      true,
    );
    expect(
      (await callWorker("recordAuthenticatedPeer", ["new-id", key])).result,
    ).toEqual({ blocked: true, known: false });
    expect(
      (await callWorker("setDBPeerInBlacklist", ["latest-id", key])).error,
    ).toBeUndefined();
    const blocks = (await callWorker("getAllDBBlacklisted", [])).result;
    expect(blocks).toEqual([
      {
        peerId: "latest-id",
        peerPublicKey: key,
        dateAdded: expect.any(Number),
      },
    ]);
    expect((await callWorker("getDBPeerIsBlacklisted", [other])).result).toBe(
      false,
    );
  });

  test("a saved contact follows the authenticated key and a reused ID does not grant admission", async () => {
    const key = "ab".repeat(32);
    const other = "cd".repeat(32);
    expect(
      (await callWorker("setDBAddressBookEntry", ["Ada", "old-id", key])).error,
    ).toBeUndefined();
    expect(
      (await callWorker("recordAuthenticatedPeer", ["new-id", key])).result,
    ).toEqual({ blocked: false, known: true });
    expect(
      (await callWorker("getDBAddressBookEntry", [key])).result,
    ).toMatchObject({ username: "Ada", peerId: "new-id", peerPublicKey: key });
    expect(
      (await callWorker("recordAuthenticatedPeer", ["old-id", other])).result,
    ).toEqual({ blocked: false, known: false });
    expect(
      (await callWorker("deleteDBAddressBookEntry", [key])).error,
    ).toBeUndefined();
    expect(
      (await callWorker("getDBAddressBookEntry", [key])).result,
    ).toBeUndefined();
  });
});
