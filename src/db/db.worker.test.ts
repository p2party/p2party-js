// Stage 3 / Task 4 — db.worker.ts wiring for the `ratchetSessions` store:
// fnGetRatchetSession / fnSetRatchetSession / fnDeleteRatchetSession, plus the
// onmessage cases that dispatch "getRatchetSession" / "setRatchetSession" /
// "deleteRatchetSession" to them.
//
// db.worker.ts has no exports (it's a worker entry point that wires up a
// global `onmessage`), so it is exercised here the same way the real caller
// (src/db/api.ts, via a Worker) exercises it: by importing the module (which
// installs `onmessage` as a side effect) and dispatching real
// `{ id, method, args }` messages through that handler, capturing whatever it
// posts back via `postMessage`. This covers the actual wiring end-to-end
// (onmessage -> fn* -> getDB / getWrapKey / wrap|unwrapRatchetSession), not a
// re-implemented test double.
//
// The key security assertion: after fnSetRatchetSession, the RAW row read
// directly from the `ratchetSessions` store (bypassing fnGetRatchetSession's
// unwrap step) must be ciphertext — the plaintext ratchet secrets must never
// touch disk.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, spyOn, test } from "bun:test";

import { getDB } from "./src/getDB";
import { MAX_MESSAGE_SIZE } from "../utils/constants";

import type {
  RatchetSession,
  ReceiveChunk,
  ReceiveChunkStoreResult,
} from "./types";

beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
  Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

const sampleSession = (): RatchetSession => ({
  rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
  roomId: "room-1",
  peerPublicKey: "aa".repeat(32),
  peerId: "peer-abc-123",
  rootKey: rnd(32),
  sendingChainKey: rnd(32),
  receivingChainKey: null,
  dhSelfPub: rnd(32),
  dhSelfSec: rnd(32),
  dhRemotePub: rnd(32),
  Ns: 3,
  Nr: 1,
  PN: 2,
  skippedMessageKeys: [{ dhPub: rnd(32), n: 0, messageKey: rnd(32) }],
  edgeCryptoState: rnd(6_144),
  updatedAt: 111,
});

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}

let nextId = 1;

// Dispatches a real message through db.worker.ts's actual `onmessage` handler
// and captures whatever it posts back, matched by id.
async function callWorker(
  method: string,
  args: unknown[],
): Promise<WorkerResponse> {
  await import("./db.worker"); // idempotent after the first call
  const id = nextId++;
  let captured: WorkerResponse | undefined;
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (m: unknown) => {
      captured = m as WorkerResponse;
    };
  const handler = (
    globalThis as unknown as {
      onmessage: (e: MessageEvent) => Promise<void>;
    }
  ).onmessage;
  // A real Worker receives a structured clone. Preserve that boundary here so
  // worker-side secret wiping cannot mutate the caller's buffers in-process.
  await handler({
    data: structuredClone({ id, method, args }),
  } as MessageEvent);
  if (!captured || captured.id !== id) {
    throw new Error(`worker did not respond to message id ${id}`);
  }
  return captured;
}

async function callWorkersConcurrently(
  calls: Array<{ method: string; args: unknown[] }>,
): Promise<WorkerResponse[]> {
  await import("./db.worker");
  const responses = new Map<number, WorkerResponse>();
  const ids = calls.map(() => nextId++);
  (
    globalThis as unknown as { postMessage: (m: unknown) => void }
  ).postMessage = (message: unknown) => {
    const response = message as WorkerResponse;
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
    if (!response) throw new Error(`worker did not respond to message id ${id}`);
    return response;
  });
}

describe("db.worker ratchetSessions wiring", () => {
  test("setRatchetSession -> getRatchetSession round-trips the ORIGINAL session (secrets intact)", async () => {
    const s = sampleSession();
    const setResp = await callWorker("setRatchetSession", [s]);
    expect(setResp.error).toBeUndefined();

    const getResp = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(getResp.error).toBeUndefined();
    const got = getResp.result as RatchetSession;
    expect(got).toBeDefined();
    expect(eq(got.rootKey, s.rootKey)).toBe(true);
    expect(eq(got.dhSelfSec, s.dhSelfSec)).toBe(true);
    expect(
      got.sendingChainKey != null &&
        eq(got.sendingChainKey, s.sendingChainKey as ArrayBuffer),
    ).toBe(true);
    expect(got.receivingChainKey).toBe(null);
    expect(
      eq(
        got.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(true);
    expect(
      eq(got.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true);
    expect(got.Ns).toBe(3);
    expect(got.Nr).toBe(1);
    expect(got.PN).toBe(2);
    expect(
      got.edgeCryptoState !== null &&
        s.edgeCryptoState !== null &&
        eq(got.edgeCryptoState, s.edgeCryptoState),
    ).toBe(true);
    expect(got.peerId).toBe("peer-abc-123");
    expect(got.roomId).toBe("room-1");
    expect(got.rootSuite).toBe("hybrid-3dh-mlkem768-cpace21-v4");
  });

  test("KEY SECURITY ASSERTION: the raw stored row in `ratchetSessions` is ciphertext, not plaintext", async () => {
    const s = sampleSession();
    await callWorker("setRatchetSession", [s]);

    // Read the RAW row directly from the store, bypassing fnGetRatchetSession's
    // unwrap step entirely — this is what would be visible to anything reading
    // the on-disk IndexedDB directly.
    const db = await getDB();
    const raw = (await db.get("ratchetSessions", [
      s.roomId,
      s.peerPublicKey,
    ])) as RatchetSession;
    db.close();

    expect(raw).toBeDefined();
    expect(eq(raw.rootKey, s.rootKey)).toBe(false);
    expect(eq(raw.dhSelfSec, s.dhSelfSec)).toBe(false);
    expect(
      raw.sendingChainKey != null &&
        eq(raw.sendingChainKey, s.sendingChainKey as ArrayBuffer),
    ).toBe(false);
    expect(
      eq(
        raw.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(false);
    expect(
      raw.edgeCryptoState !== null &&
        s.edgeCryptoState !== null &&
        eq(raw.edgeCryptoState, s.edgeCryptoState),
    ).toBe(false);
    // Public / counter fields pass through unwrapped — stored plaintext.
    expect(eq(raw.dhSelfPub, s.dhSelfPub)).toBe(true);
    expect(
      eq(raw.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true);
    expect(raw.receivingChainKey).toBe(null);
    expect(raw.Ns).toBe(3);
    expect(raw.roomId).toBe("room-1");
    expect(raw.rootSuite).toBe("hybrid-3dh-mlkem768-cpace21-v4");
    expect(raw.peerPublicKey).toBe("aa".repeat(32));
  });

  test("deleteRatchetSession removes the row", async () => {
    const s = sampleSession();
    await callWorker("setRatchetSession", [s]);

    const before = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(before.result).toBeDefined();

    const delResp = await callWorker("deleteRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(delResp.error).toBeUndefined();

    const after = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(after.result).toBeUndefined();
  });

  test("stamps and authenticates a strictly monotonic write version before wrapping", async () => {
    const first = sampleSession();
    await callWorker("setRatchetSession", [first]);
    let db = await getDB();
    const firstRaw = await db.get("ratchetSessions", [
      first.roomId,
      first.peerPublicKey,
    ]);
    db.close();
    expect(firstRaw).toBeDefined();

    const second = { ...sampleSession(), Ns: first.Ns + 1 };
    await callWorker("setRatchetSession", [second]);
    db = await getDB();
    const secondRaw = await db.get("ratchetSessions", [
      second.roomId,
      second.peerPublicKey,
    ]);
    db.close();
    expect(secondRaw).toBeDefined();
    expect(secondRaw!.updatedAt).toBeGreaterThan(firstRaw!.updatedAt);

    // updatedAt and Ns were both present before AES-GCM wrapping, so the row
    // remains decryptable rather than being mutated after authentication.
    const restored = await callWorker("getRatchetSession", [
      second.roomId,
      second.peerPublicKey,
    ]);
    expect(restored.error).toBeUndefined();
    expect(restored.result).toMatchObject({
      Ns: second.Ns,
      updatedAt: secondRaw!.updatedAt,
    });
  });

  test("deleting a room purges only that room's persisted ratchets", async () => {
    const first = sampleSession();
    const second = {
      ...sampleSession(),
      roomId: "room-2",
      peerPublicKey: "bb".repeat(32),
    };
    await callWorker("setRatchetSession", [first]);
    await callWorker("setRatchetSession", [second]);

    await callWorker("deleteDBUniqueRoom", [first.roomId]);

    expect(
      (
        await callWorker("getRatchetSession", [
          first.roomId,
          first.peerPublicKey,
        ])
      ).result,
    ).toBeUndefined();
    expect(
      (
        await callWorker("getRatchetSession", [
          second.roomId,
          second.peerPublicKey,
        ])
      ).result,
    ).toBeDefined();
  });

  test("getRatchetSession on a missing row returns undefined (not an error)", async () => {
    const resp = await callWorker("getRatchetSession", [
      "no-such-room",
      "bb".repeat(32),
    ]);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeUndefined();
  });
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
          messageType: 2,
          totalSize: 1,
          storage: "opfs",
        }),
      ]);
      // The storage layer safely falls back to IndexedDB, but the exclusive
      // handle acquired before truncate failed must already be released.
      expect(response.error).toBeUndefined();
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

  test("deleteIdentityX25519 removes the identity and every bound ratchet", async () => {
    const idn = sampleIdentity();
    await callWorker("setIdentityX25519", [idn]);
    const session = sampleSession();
    await callWorker("setRatchetSession", [session]);
    expect((await callWorker("getIdentityX25519", [])).result).toBeDefined();

    const delResp = await callWorker("deleteIdentityX25519", []);
    expect(delResp.error).toBeUndefined();

    const after = await callWorker("getIdentityX25519", []);
    expect(after.result).toBeUndefined();
    expect(
      (
        await callWorker("getRatchetSession", [
          session.roomId,
          session.peerPublicKey,
        ])
      ).result,
    ).toBeUndefined();
  });

  test("getIdentityX25519 with no record returns undefined (not an error)", async () => {
    const resp = await callWorker("getIdentityX25519", []);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeUndefined();
  });
});

describe("db.worker identityEd25519 wiring (WebCrypto-wrapped at rest)", () => {
  const sampleIdentity = () => ({
    pub: rnd(32),
    secret: rnd(64),
  });

  test("round-trips while keeping the raw secret encrypted", async () => {
    const identity = sampleIdentity();
    const set = await callWorker("setIdentityEd25519", [identity]);
    expect(set.error).toBeUndefined();

    const get = await callWorker("getIdentityEd25519", []);
    expect(get.error).toBeUndefined();
    const restored = get.result as { pub: ArrayBuffer; secret: ArrayBuffer };
    expect(eq(restored.pub, identity.pub)).toBe(true);
    expect(eq(restored.secret, identity.secret)).toBe(true);

    const db = await getDB();
    const raw = (await db.get("meta", "identityEd25519")) as unknown as {
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
    };
    db.close();
    expect(eq(raw.pub, identity.pub)).toBe(true);
    expect(eq(raw.wrappedSecret, identity.secret)).toBe(false);
    expect(raw.wrappedSecret.byteLength).toBeGreaterThan(
      identity.secret.byteLength,
    );
  });

  test("rejects invalid lengths and deletes the wrapped identity", async () => {
    const invalid = await callWorker("setIdentityEd25519", [
      { pub: rnd(31), secret: rnd(64) },
    ]);
    expect(String(invalid.error)).toContain("invalid key lengths");

    const identity = sampleIdentity();
    await callWorker("setIdentityEd25519", [identity]);
    const del = await callWorker("deleteIdentityEd25519", []);
    expect(del.error).toBeUndefined();
    expect((await callWorker("getIdentityEd25519", [])).result).toBeUndefined();
  });
});
