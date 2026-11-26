// Receive-path cost and storage failure in db.worker.ts, driven through the
// worker's real `onmessage` handler over fake-indexeddb (the same harness as
// db.worker.test.ts), with an in-memory OPFS where a test needs one.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";

import { getDB } from "../../src/db/src/getDB";
import { buildReceiveManifest } from "../../src/db/receiveManifest";

import type {
  Chunk,
  MessageData,
  ReceiveChunk,
  ReceiveChunkStoreResult,
} from "../../src/db/types";
import type { ReceiveActivity } from "../../src/db/outboxTypes";

import fixture from "./fixtures/receive-progress-0.14.10.json";

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}

let nextId = 1;
async function callWorker(
  method: string,
  args: unknown[],
): Promise<WorkerResponse> {
  await import("../../src/db/db.worker");
  const id = nextId++;
  let captured: WorkerResponse | undefined;
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (message: unknown) => {
      captured = message as WorkerResponse;
    };
  const handler = (
    globalThis as unknown as { onmessage: (e: MessageEvent) => Promise<void> }
  ).onmessage;
  await handler({
    data: structuredClone({ id, method, args }),
  } as MessageEvent);
  if (!captured || captured.id !== id)
    throw new Error(`worker did not respond to message id ${id}`);
  return captured;
}

const store = async (chunk: ReceiveChunk): Promise<ReceiveChunkStoreResult> => {
  const reply = await callWorker("storeReceiveChunk", [chunk]);
  if (reply.error !== undefined) throw new Error(String(reply.error));
  return reply.result as ReceiveChunkStoreResult;
};

// SHA-512 hex of a whole transfer whose bytes are 0, 1, 2, ... (mod 256).
const contentHash = (totalSize: number): string =>
  createHash("sha512")
    .update(Uint8Array.from({ length: totalSize }, (_, k) => k & 0xff))
    .digest("hex");

// Chunk `index` of a transfer whose bytes are 0, 1, 2, ... (mod 256), cut at
// `uniform` real bytes per chunk, carrying that content's whole-file hash.
// Matches the fixture generator.
const chunkOf = (
  merkleRoot: string,
  index: number,
  totalSize: number,
  uniform: number,
  overrides: Partial<ReceiveChunk> = {},
): ReceiveChunk => {
  const start = index * uniform;
  const len = Math.min(uniform, totalSize - start);
  const data = new Uint8Array(len);
  for (let k = 0; k < len; k++) data[k] = (start + k) & 0xff;
  return {
    schemaVersion: 1,
    roomId: "00000000-0000-4000-8000-000000000a05",
    fromPeerId: "peer-a5-sender",
    channelLabel: "chat",
    timestamp: 1_790_000_000_000,
    merkleRoot,
    hash: contentHash(totalSize),
    filename: "",
    messageType: 1,
    chunkIndex: index,
    mimeType: "text/plain",
    leafHash: (index + 16).toString(16).padStart(2, "0").repeat(64),
    realLen: len,
    totalSize,
    data: data.buffer,
    storage: "indexeddb",
    ...overrides,
  };
};

const rows = async () => {
  const db = await getDB();
  try {
    return {
      messageData: await db.getAll("messageData"),
      chunks: await db.getAll("chunks"),
      receiveActivity: await db.getAll("receiveActivity"),
    };
  } finally {
    db.close();
  }
};

const messageRow = async (
  merkleRoot: string,
): Promise<MessageData | undefined> => {
  const db = await getDB();
  try {
    return await db.getFromIndex("messageData", "merkleRoot", merkleRoot);
  } finally {
    db.close();
  }
};

// Count cursor advances (records a cursor visits: the per-record cost the
// audit measured) and transactions until the test ends. Iterating to the end
// calls continue() once per visited record, so the two counts are the same.
// IDBCursor.prototype.continue itself is not replaced: idb recognizes cursor
// methods by identity, memoized on first use, so swapping it would break
// cursor iteration for the rest of the process.
const countCursorWork = () => {
  type Opener = { openCursor: (...a: unknown[]) => unknown };
  const globals = globalThis as unknown as {
    IDBIndex: { prototype: Opener };
    IDBObjectStore: { prototype: Opener };
    IDBDatabase: { prototype: { transaction: (...a: unknown[]) => unknown } };
  };
  const counts = { advances: 0, transactions: 0 };
  for (const proto of [
    globals.IDBIndex.prototype,
    globals.IDBObjectStore.prototype,
  ]) {
    const openCursor = proto.openCursor;
    proto.openCursor = function (this: unknown, ...args: unknown[]) {
      const request = openCursor.apply(this, args) as IDBRequest;
      request.addEventListener("success", () => {
        if (request.result) counts.advances += 1;
      });
      return request;
    };
    restores.push(() => {
      proto.openCursor = openCursor;
    });
  }
  const database = globals.IDBDatabase.prototype;
  const transaction = database.transaction;
  database.transaction = function (this: unknown, ...args: unknown[]) {
    counts.transactions += 1;
    return transaction.apply(this, args);
  };
  restores.push(() => {
    database.transaction = transaction;
  });
  return counts;
};

// In-memory OPFS: one Uint8Array per file name, with the sync-access-handle
// surface the worker uses. Every read is logged.
const installOpfs = (
  files: Map<string, Uint8Array>,
  extra: Record<string, unknown> = {},
): {
  directoryOpens: number;
  reads: Array<{ name: string; at: number; length: number }>;
} => {
  const stats = {
    directoryOpens: 0,
    reads: [] as Array<{ name: string; at: number; length: number }>,
  };
  const access = (name: string) => ({
    getSize: () => (files.get(name) ?? new Uint8Array()).length,
    read: (view: ArrayBufferView, { at }: { at: number }) => {
      const buf = files.get(name) ?? new Uint8Array();
      const into = new Uint8Array(
        view.buffer,
        view.byteOffset,
        view.byteLength,
      );
      const n = Math.max(0, Math.min(into.length, buf.length - at));
      into.set(buf.subarray(at, at + n));
      stats.reads.push({ name, at, length: n });
      return n;
    },
    truncate: (size: number) => {
      const old = files.get(name) ?? new Uint8Array();
      const next = new Uint8Array(size);
      next.set(old.subarray(0, Math.min(size, old.length)));
      files.set(name, next);
    },
    write: (view: ArrayBufferView, { at }: { at: number }) => {
      const src = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      let buf = files.get(name) ?? new Uint8Array();
      if (at + src.length > buf.length) {
        const grown = new Uint8Array(at + src.length);
        grown.set(buf);
        buf = grown;
      }
      buf.set(src, at);
      files.set(name, buf);
      return src.length;
    },
    flush: () => {},
    close: () => {},
  });
  installStorage({
    getDirectory: async () => {
      stats.directoryOpens += 1;
      return {
        getDirectoryHandle: async () => ({
          removeEntry: async (name: string) => {
            files.delete(name);
          },
          getFileHandle: async (name: string) => ({
            createSyncAccessHandle: async () => access(name),
            getFile: async () =>
              new File(
                [
                  (files.get(name) ??
                    new Uint8Array()) as Uint8Array<ArrayBuffer>,
                ],
                name,
              ),
          }),
        }),
      };
    },
    ...extra,
  });
  return stats;
};

const navigatorDescriptor = Object.getOwnPropertyDescriptor(
  globalThis,
  "navigator",
);
const installStorage = (storage: Record<string, unknown>): void => {
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { storage },
  });
};

const restores: Array<() => void> = [];
beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});
afterEach(() => {
  while (restores.length > 0) restores.pop()!();
  if (navigatorDescriptor)
    Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
  else delete (globalThis as { navigator?: unknown }).navigator;
});

const quietConsole = () => {
  const errorLog = spyOn(console, "error").mockImplementation(() => {});
  restores.push(() => errorLog.mockRestore());
};

describe("receive cost does not grow with chunks already held", () => {
  test("cursor advances are linear in chunks", async () => {
    const root = "5a".repeat(64);
    const chunks = 400;
    const counts = countCursorWork();
    const perChunk: Array<{ advances: number; transactions: number }> = [];
    let last: ReceiveChunkStoreResult | undefined;
    for (let index = 0; index < chunks; index++) {
      const before = { ...counts };
      last = await store(chunkOf(root, index, 4 * chunks, 4));
      perChunk.push({
        advances: counts.advances - before.advances,
        transactions: counts.transactions - before.transactions,
      });
    }

    expect(last).toEqual({
      stored: true,
      savedSize: 4 * chunks,
      complete: true,
    });
    // 0.14.10 re-read every held record twice per chunk: 159,600 advances.
    expect(counts.advances).toBeLessThanOrEqual(8 * chunks);
    expect(
      Math.max(...perChunk.map((chunk) => chunk.advances)),
    ).toBeLessThanOrEqual(8);
    // Database round trips per chunk are a constant, not a function of index.
    expect(
      new Set(perChunk.slice(1).map((chunk) => chunk.transactions)).size,
    ).toBe(1);
  }, 60_000);

  test("an old-format receive store resumes cleanly on upgrade", async () => {
    // Raw rows and the OPFS file as 0.14.10 left them (tests/db/fixtures,
    // written by the 0.14.10 worker). Rows without a manifest are summarized
    // once from their chunk records, so nothing needs to be reset.
    const decode = (row: Record<string, unknown>) =>
      Object.fromEntries(
        Object.entries(row).map(([key, value]) =>
          typeof value === "object" && value !== null && "$hex" in value
            ? [
                key,
                Uint8Array.from(Buffer.from(String(value.$hex), "hex")).buffer,
              ]
            : [key, value],
        ),
      );
    const db = await getDB();
    const tx = db.transaction(
      ["messageData", "chunks", "receiveActivity"],
      "readwrite",
    );
    for (const row of fixture.messageData)
      await tx
        .objectStore("messageData")
        .put(decode(row) as unknown as MessageData);
    for (const row of fixture.chunks)
      await tx.objectStore("chunks").put(decode(row) as unknown as Chunk);
    for (const row of fixture.receiveActivity)
      await tx
        .objectStore("receiveActivity")
        .put(decode(row) as unknown as ReceiveActivity);
    await tx.done;
    db.close();
    const files = new Map(
      Object.entries(fixture.opfs).map(([name, bytes]) => [
        name,
        Uint8Array.from(Buffer.from(bytes, "hex")),
      ]),
    );
    installOpfs(files);

    // The partial file: held 0, 1, 3 (bytes still in IndexedDB), 7, 9.
    const file = fixture.roots.partialFile;
    const fileChunk = (index: number) =>
      chunkOf(file, index, 48, 5, {
        messageType: 2,
        filename: "report.bin",
        mimeType: "application/octet-stream",
        storage: "opfs",
      });
    expect((await messageRow(file))?.receiveManifest).toBeUndefined();
    const counts = countCursorWork();
    const results: ReceiveChunkStoreResult[] = [];
    const advances: number[] = [];
    for (const index of [2, 4, 5, 6, 8]) {
      const before = counts.advances;
      results.push(await store(fileChunk(index)));
      advances.push(counts.advances - before);
    }
    expect(results).toEqual([
      { stored: true, savedSize: 28, complete: false },
      { stored: true, savedSize: 33, complete: false },
      { stored: true, savedSize: 38, complete: false },
      { stored: true, savedSize: 43, complete: false },
      { stored: true, savedSize: 48, complete: true },
    ]);
    // The 0.14.10 row is summarized once (validation pass + commit pass over
    // its five records), then never re-read until the completing chunk, whose
    // whole-file verification visits each of the nine held records once.
    expect(advances).toEqual([10, 0, 0, 0, 9]);
    const completed = await messageRow(file);
    expect(completed?.savedSize).toBe(48);
    const records = (await rows()).chunks.filter(
      (record) => record.merkleRoot === file,
    );
    expect(completed?.receiveManifest).toEqual(
      buildReceiveManifest(records, 48),
    );

    // The finished file reads back byte-exact, stragglers migrated.
    const read = await callWorker("getReceiveFile", [
      file,
      48,
      "report.bin",
      "application/octet-stream",
    ]);
    const bytes = new Uint8Array(await (read.result as File).arrayBuffer());
    expect(Array.from(bytes)).toEqual(Array.from({ length: 48 }, (_, i) => i));

    // Text partials: chunk 0 held; and only chunk 1 held (size not yet known).
    expect(await store(chunkOf(fixture.roots.partialText, 1, 10, 5))).toEqual({
      stored: true,
      savedSize: 10,
      complete: true,
    });
    expect(
      await store(chunkOf(fixture.roots.stragglerOnlyText, 0, 10, 5)),
    ).toEqual({ stored: true, savedSize: 10, complete: true });
    // A late duplicate of a message 0.14.10 completed is still complete.
    expect(await store(chunkOf(fixture.roots.completeText, 1, 10, 5))).toEqual({
      stored: false,
      savedSize: 10,
      complete: true,
    });
  });

  test("a manifest another writer left behind is rebuilt, not trusted", async () => {
    const root = "5b".repeat(64);
    for (const index of [0, 1]) await store(chunkOf(root, index, 15, 5));
    const row = (await messageRow(root))!;
    expect(row.receiveManifest).toEqual({
      version: 1,
      count: 2,
      savedSize: 10,
      uniformSize: 5,
    });

    // A writer that kept the stale field but moved savedSize (any writer that
    // does not maintain the manifest), adding chunk 2 the way 0.14.10 commits.
    const db = await getDB();
    const third = chunkOf(root, 2, 15, 5);
    await db.add("chunks", {
      merkleRoot: root,
      hash: third.hash,
      chunkIndex: 2,
      mimeType: third.mimeType,
      realLen: 5,
      leafHash: third.leafHash,
      data: third.data,
    });
    await db.put("messageData", { ...row, savedSize: 15 });
    db.close();
    expect(await store(third)).toEqual({
      stored: false,
      savedSize: 15,
      complete: true,
    });

    // A 0.14.10 tab rewrites the row without the field at all.
    const other = "5c".repeat(64);
    await store(chunkOf(other, 0, 15, 5));
    const otherRow = (await messageRow(other))!;
    const legacy = await getDB();
    await legacy.add("chunks", {
      merkleRoot: other,
      hash: otherRow.hash,
      chunkIndex: 1,
      mimeType: "text/plain",
      realLen: 5,
      leafHash: "aa".repeat(64),
      data: new Uint8Array(5).buffer,
    });
    const { receiveManifest: _dropped, ...withoutManifest } = otherRow;
    void _dropped;
    await legacy.put("messageData", { ...withoutManifest, savedSize: 10 });
    legacy.close();
    expect(await store(chunkOf(other, 2, 15, 5))).toEqual({
      stored: true,
      savedSize: 15,
      complete: true,
    });
  });

  test("a chunk deleted out of band is not counted by the manifest", async () => {
    const root = "5d".repeat(64);
    await store(chunkOf(root, 0, 10, 5));
    await callWorker("deleteDBChunk", [root, 0]);
    expect((await messageRow(root))?.receiveManifest).toBeUndefined();
    expect(await store(chunkOf(root, 0, 10, 5))).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });
  });
});

describe("whole-file verification", () => {
  const fileChunk = (
    root: string,
    index: number,
    totalSize: number,
    overrides: Partial<ReceiveChunk> = {},
  ) =>
    chunkOf(root, index, totalSize, 5, {
      messageType: 2,
      filename: "f.bin",
      mimeType: "application/octet-stream",
      storage: "opfs",
      ...overrides,
    });

  test("a completed file whose stored bytes do not match the message hash is refused", async () => {
    quietConsole();
    const root = "7a".repeat(64);
    const files = new Map<string, Uint8Array>();
    installOpfs(files);
    expect(await store(fileChunk(root, 0, 13))).toMatchObject({ stored: true });
    expect(await store(fileChunk(root, 1, 13))).toMatchObject({ stored: true });
    // The stored bytes change after their have-set record was committed.
    files.get(root)![3] ^= 0xff;

    expect(await store(fileChunk(root, 2, 13))).toEqual({
      failure: "integrity",
    });
    // Not complete, nothing held: the have-set and the OPFS file are gone and
    // the row says why, so a reconnect has no final receipt to replay.
    const after = await rows();
    expect(after.chunks.filter((c) => c.merkleRoot === root)).toEqual([]);
    expect(files.has(root)).toBe(false);
    expect(await messageRow(root)).toMatchObject({
      savedSize: 0,
      totalSize: 13,
      integrityFailed: true,
    });

    // A later full resend that stores intact bytes completes and clears it.
    for (const index of [0, 1])
      expect(await store(fileChunk(root, index, 13))).toMatchObject({
        stored: true,
        complete: false,
      });
    expect(await store(fileChunk(root, 2, 13))).toEqual({
      stored: true,
      savedSize: 13,
      complete: true,
    });
    expect((await messageRow(root))?.integrityFailed).toBeUndefined();

    // A sender whose bytes never match the hash it claims is refused too.
    const liar = "7b".repeat(64);
    const claimed = { hash: contentHash(14) };
    await store(fileChunk(liar, 0, 13, claimed));
    await store(fileChunk(liar, 1, 13, claimed));
    expect(await store(fileChunk(liar, 2, 13, claimed))).toEqual({
      failure: "integrity",
    });
  });

  test("verification reads the file once", async () => {
    const root = "7c".repeat(64);
    const files = new Map<string, Uint8Array>();
    const opfs = installOpfs(files);
    const counts = countCursorWork();
    // Chunk 3 arrives first, before the uniform size is known, so its bytes
    // stay in its IndexedDB record; the others land in OPFS.
    const visits: number[] = [];
    const readsPerStore: number[] = [];
    let last: ReceiveChunkStoreResult | undefined;
    for (const index of [3, 0, 1, 2, 4]) {
      const visitsBefore = counts.advances;
      const readsBefore = opfs.reads.length;
      last = await store(fileChunk(root, index, 23));
      visits.push(counts.advances - visitsBefore);
      readsPerStore.push(opfs.reads.length - readsBefore);
    }
    expect(last).toEqual({ stored: true, savedSize: 23, complete: true });
    // Only the completing store reads, and it reads each byte once, in order:
    // chunks 0-2 from OPFS, chunk 3 from its record, chunk 4 from memory.
    expect(readsPerStore).toEqual([0, 0, 0, 0, 3]);
    expect(opfs.reads).toEqual([
      { name: root, at: 0, length: 5 },
      { name: root, at: 5, length: 5 },
      { name: root, at: 10, length: 5 },
    ]);
    // One pass over the four held records, at completion only.
    expect(visits).toEqual([0, 0, 0, 0, 4]);
  });
});

describe("receive storage failure", () => {
  test("transfer larger than free quota is refused before any write", async () => {
    const root = "6a".repeat(64);
    const files = new Map<string, Uint8Array>();
    let free = 9;
    const opfs = installOpfs(files, {
      estimate: async () => ({ quota: 1_000, usage: 1_000 - free }),
    });
    const first = chunkOf(root, 0, 10, 5, {
      messageType: 2,
      mimeType: "application/octet-stream",
      storage: "opfs",
    });

    expect(await store(first)).toEqual({
      failure: "insufficient-quota",
      requiredBytes: 10,
      availableBytes: 9,
    });
    // Nothing: no have-set, no message row, no activity row, no OPFS file.
    expect(await rows()).toEqual({
      messageData: [],
      chunks: [],
      receiveActivity: [],
    });
    expect(opfs.directoryOpens).toBe(0);
    expect(files.size).toBe(0);

    // With room for it the same transfer is accepted, and once accepted its
    // later chunks are not re-checked (its file is already sized).
    free = 10;
    expect(await store(first)).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });
    free = 0;
    expect(
      await store(
        chunkOf(root, 1, 10, 5, {
          messageType: 2,
          mimeType: "application/octet-stream",
          storage: "opfs",
        }),
      ),
    ).toEqual({ stored: true, savedSize: 10, complete: true });
  });

  test("an unavailable estimate does not block a transfer", async () => {
    quietConsole();
    installStorage({
      estimate: async () => {
        throw new Error("estimate unavailable");
      },
    });
    expect(await store(chunkOf("6b".repeat(64), 0, 5, 5))).toEqual({
      stored: true,
      savedSize: 5,
      complete: true,
    });
  });

  test("a write the browser refuses is a typed failure that commits nothing", async () => {
    quietConsole();
    const proto = (
      globalThis as unknown as {
        IDBObjectStore: { prototype: { add: (...a: unknown[]) => unknown } };
      }
    ).IDBObjectStore.prototype;
    const add = proto.add;
    let failWith: string | undefined;
    proto.add = function (this: { name: string }, ...args: unknown[]) {
      if (this.name === "chunks" && failWith !== undefined) {
        const name = failWith;
        failWith = undefined;
        throw new DOMException("injected storage fault", name);
      }
      return add.apply(this, args);
    };
    restores.push(() => {
      proto.add = add;
    });

    const root = "6c".repeat(64);
    failWith = "QuotaExceededError";
    expect(await store(chunkOf(root, 0, 10, 5))).toEqual({
      failure: "quota-exceeded",
    });
    failWith = "UnknownError";
    expect(await store(chunkOf(root, 0, 10, 5))).toEqual({
      failure: "storage-failed",
    });
    const after = await rows();
    expect(after.chunks).toEqual([]);
    expect(after.messageData).toEqual([]);

    // A rejected chunk is still a refusal, never mistaken for a storage fault.
    const rejected = await callWorker("storeReceiveChunk", [
      chunkOf(root, 0, 10, 5, { schemaVersion: 2 }),
    ]);
    expect(rejected.result).toBeUndefined();
    expect(String(rejected.error)).toContain("invalid receive chunk bounds");

    // The retransmission is stored.
    expect(await store(chunkOf(root, 0, 10, 5))).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });
  });
});
