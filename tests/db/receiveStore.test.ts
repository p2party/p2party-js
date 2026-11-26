// Receive-path cost and storage failure in db.worker.ts, driven through the
// worker's real `onmessage` handler over fake-indexeddb (the same harness as
// db.worker.test.ts), with an in-memory OPFS where a test needs one.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

// Process-wide state this file changes, restored in afterAll.
const indexedDBBefore = (globalThis as unknown as { indexedDB: IDBFactory })
  .indexedDB;
const postMessageBefore = Object.getOwnPropertyDescriptor(
  globalThis,
  "postMessage",
);
afterAll(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    indexedDBBefore;
  if (postMessageBefore)
    Object.defineProperty(globalThis, "postMessage", postMessageBefore);
  else delete (globalThis as { postMessage?: unknown }).postMessage;
});
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import { createHash } from "node:crypto";

import { getDB } from "../../src/db/src/getDB";
import { buildReceiveManifest } from "../../src/db/receiveManifest";

import type {
  Chunk,
  HeldFileSettledNotice,
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

// Replies are routed by id, so calls may overlap as they do in a real worker.
let nextId = 1;
const pendingReplies = new Map<number, (reply: WorkerResponse) => void>();
// Notices the worker posts outside any request (a held file it verified on
// its own), in arrival order.
const notices: HeldFileSettledNotice[] = [];
async function callWorker(
  method: string,
  args: unknown[],
): Promise<WorkerResponse> {
  await import("../../src/db/db.worker");
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (message: unknown) => {
      const { notice } = message as { notice?: HeldFileSettledNotice };
      if (notice) {
        notices.push(notice);
        return;
      }
      const reply = message as WorkerResponse;
      pendingReplies.get(reply.id)?.(reply);
      pendingReplies.delete(reply.id);
    };
  const id = nextId++;
  const reply = new Promise<WorkerResponse>((resolve) =>
    pendingReplies.set(id, resolve),
  );
  const handler = (
    globalThis as unknown as { onmessage: (e: MessageEvent) => Promise<void> }
  ).onmessage;
  await handler({
    data: structuredClone({ id, method, args }),
  } as MessageEvent);
  return reply;
}

// Dispatch several requests in order without waiting for each to finish.
const callWorkersConcurrently = (
  calls: Array<{ method: string; args: unknown[] }>,
): Promise<WorkerResponse[]> =>
  Promise.all(calls.map((call) => callWorker(call.method, call.args)));

const store = async (chunk: ReceiveChunk): Promise<ReceiveChunkStoreResult> => {
  const reply = await callWorker("storeReceiveChunk", [chunk]);
  if (reply.error !== undefined) throw new Error(String(reply.error));
  return reply.result as ReceiveChunkStoreResult;
};

const verify = async (merkleRoot: string, token: string) =>
  (await callWorker("verifyReceivedFile", [merkleRoot, token])).result;

const settle = async (merkleRoot: string, token: string, commit = true) =>
  (
    await callWorker("settleReceivedFileVerification", [
      merkleRoot,
      token,
      commit,
    ])
  ).result;

// Store a file's chunk; when it is the completing one, verify and commit the
// file as the receive path does, and return what that settled to.
const storeAndSettle = async (
  chunk: ReceiveChunk,
): Promise<ReceiveChunkStoreResult | string> => {
  const result = await store(chunk);
  if (result.failure !== undefined || result.verification === undefined)
    return result;
  await verify(chunk.merkleRoot, result.verification);
  return (await settle(chunk.merkleRoot, result.verification)) as string;
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

// Count records read by scans (the per-record cost the audit measured: each
// record a cursor visits, and each record a getAll/getAllKeys returns) and
// transactions until the test ends. Iterating a cursor to the end calls
// continue() once per visited record, so visits equal the audit's advances.
// IDBCursor.prototype.continue itself is not replaced: idb recognizes cursor
// methods by identity, memoized on first use, so swapping it would break
// cursor iteration for the rest of the process.
const countCursorWork = () => {
  type Opener = {
    openCursor: (...a: unknown[]) => unknown;
    getAll: (...a: unknown[]) => unknown;
    getAllKeys: (...a: unknown[]) => unknown;
  };
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
    for (const method of ["getAll", "getAllKeys"] as const) {
      const original = proto[method];
      proto[method] = function (this: unknown, ...args: unknown[]) {
        const request = original.apply(this, args) as IDBRequest<unknown[]>;
        request.addEventListener("success", () => {
          counts.advances += request.result.length;
        });
        return request;
      };
      restores.push(() => {
        proto[method] = original;
      });
    }
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
// A closed handle refuses reads and writes, as a real one does.
const installOpfs = (
  files: Map<string, Uint8Array>,
  extra: Record<string, unknown> = {},
  hooks: {
    onRead?: (name: string, at: number) => void;
    onWrite?: (name: string, at: number, bytes: Uint8Array) => void;
  } = {},
): {
  directoryOpens: number;
  closes: string[];
  fileOpens: Array<{ name: string; create: boolean }>;
  reads: Array<{ name: string; at: number; length: number }>;
} => {
  const stats = {
    directoryOpens: 0,
    closes: [] as string[],
    fileOpens: [] as Array<{ name: string; create: boolean }>,
    reads: [] as Array<{ name: string; at: number; length: number }>,
  };
  const access = (name: string) => {
    let closed = false;
    const open = (): void => {
      if (closed)
        throw new DOMException("handle is closed", "InvalidStateError");
    };
    return {
      getSize: () => (files.get(name) ?? new Uint8Array()).length,
      read: (view: ArrayBufferView, { at }: { at: number }) => {
        open();
        hooks.onRead?.(name, at);
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
        open();
        const src = Uint8Array.from(
          new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
        );
        hooks.onWrite?.(name, at, src);
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
      close: () => {
        closed = true;
        stats.closes.push(name);
      },
    };
  };
  installStorage({
    getDirectory: async () => {
      stats.directoryOpens += 1;
      return {
        getDirectoryHandle: async () => ({
          removeEntry: async (name: string) => {
            files.delete(name);
          },
          getFileHandle: async (
            name: string,
            options: { create?: boolean } = {},
          ) => {
            if (!options.create && !files.has(name))
              throw new DOMException("no such file", "NotFoundError");
            stats.fileOpens.push({ name, create: options.create === true });
            return {
              createSyncAccessHandle: async () => access(name),
              getFile: async () =>
                new File(
                  [
                    (files.get(name) ??
                      new Uint8Array()) as Uint8Array<ArrayBuffer>,
                  ],
                  name,
                ),
            };
          },
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
    expect(results).toMatchObject([
      { stored: true, savedSize: 28, complete: false },
      { stored: true, savedSize: 33, complete: false },
      { stored: true, savedSize: 38, complete: false },
      { stored: true, savedSize: 43, complete: false },
      // The completing chunk is held until the file verifies.
      { stored: true, savedSize: 43, complete: false },
    ]);
    // The 0.14.10 row is summarized once (validation pass + commit pass over
    // its five records), then never re-read.
    expect(advances).toEqual([10, 0, 0, 0, 0]);
    const token = (results[4] as { verification: string }).verification;
    const visitsBefore = counts.advances;
    expect(await verify(file, token)).toBe("match");
    // Verification reads each of the nine recorded chunks once.
    expect(counts.advances - visitsBefore).toBe(9);
    expect(await settle(file, token)).toBe("complete");
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

    const held = await store(fileChunk(root, 2, 13));
    expect(held).toMatchObject({ stored: true, complete: false });
    const token = (held as { verification: string }).verification;
    expect(await verify(root, token)).toBe("mismatch");
    expect(await settle(root, token)).toBe("integrity");
    // Not complete, nothing held: the have-set and the OPFS file are gone and
    // the row says why, so a reconnect has no final receipt to replay.
    const after = await rows();
    expect(after.chunks.filter((c) => c.merkleRoot === root)).toEqual([]);
    expect(files.has(root)).toBe(false);
    const failed = await messageRow(root);
    expect(failed).toMatchObject({
      savedSize: 0,
      totalSize: 13,
      integrityFailed: true,
    });
    expect(failed?.receiveVerification).toBeUndefined();

    // A later full resend that stores intact bytes completes and clears it.
    for (const index of [0, 1])
      expect(await store(fileChunk(root, index, 13))).toMatchObject({
        stored: true,
        complete: false,
      });
    expect(await storeAndSettle(fileChunk(root, 2, 13))).toBe("complete");
    const repaired = await messageRow(root);
    expect(repaired?.integrityFailed).toBeUndefined();
    expect(repaired?.savedSize).toBe(13);

    // A sender whose bytes never match the hash it claims is refused too.
    const liar = "7b".repeat(64);
    const claimed = { hash: contentHash(14) };
    await store(fileChunk(liar, 0, 13, claimed));
    await store(fileChunk(liar, 1, 13, claimed));
    expect(await storeAndSettle(fileChunk(liar, 2, 13, claimed))).toBe(
      "integrity",
    );
  });

  test("verification hashes the stored bytes of the completing chunk", async () => {
    quietConsole();
    const root = "7d".repeat(64);
    const files = new Map<string, Uint8Array>();
    // The completing chunk's bytes are damaged on their way to disk; the copy
    // the worker was handed stays intact.
    installOpfs(
      files,
      {},
      {
        onWrite: (_name, at, bytes) => {
          if (at === 10) bytes[0] ^= 0xff;
        },
      },
    );
    await store(fileChunk(root, 0, 13));
    await store(fileChunk(root, 1, 13));
    expect(await storeAndSettle(fileChunk(root, 2, 13))).toBe("integrity");
  });

  test("a retransmitted short last chunk on a fresh handle lands at its own offset", async () => {
    quietConsole();
    const root = "7e".repeat(64);
    const files = new Map<string, Uint8Array>();
    installOpfs(files);
    await store(fileChunk(root, 0, 13));
    await store(fileChunk(root, 1, 13));
    // A reload or an eviction: the next chunk opens a fresh handle.
    await callWorker("closeReceiveFile", [root]);
    // The short last chunk's first commit fails for lack of space: its first
    // write is refused before anything is issued, so nothing commits.
    const proto = (
      globalThis as unknown as {
        IDBObjectStore: {
          prototype: Record<"add" | "put", (...a: unknown[]) => unknown>;
        };
      }
    ).IDBObjectStore.prototype;
    let failNext = true;
    for (const method of ["add", "put"] as const) {
      const original = proto[method];
      proto[method] = function (this: { name: string }, ...args: unknown[]) {
        if (
          failNext &&
          (this.name === "chunks" || this.name === "messageData")
        ) {
          failNext = false;
          throw new DOMException("injected", "QuotaExceededError");
        }
        return original.apply(this, args);
      };
      restores.push(() => {
        proto[method] = original;
      });
    }
    expect(await store(fileChunk(root, 2, 13))).toEqual({
      failure: "quota-exceeded",
    });
    // The retransmission is the second placement on that handle. It must land
    // at 2 × 5, not at 2 × its own length over chunk 1's bytes.
    expect(await storeAndSettle(fileChunk(root, 2, 13))).toBe("complete");
    expect(Array.from(files.get(root)!)).toEqual(
      Array.from({ length: 13 }, (_, i) => i),
    );
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
    expect(last).toMatchObject({
      stored: true,
      savedSize: 20,
      complete: false,
    });
    // No store reads the file or scans its records.
    expect(readsPerStore).toEqual([0, 0, 0, 0, 0]);
    expect(visits).toEqual([0, 0, 0, 0, 0]);

    const token = (last as { verification: string }).verification;
    const visitsBefore = counts.advances;
    expect(await verify(root, token)).toBe("match");
    // Each stored byte is read back once, in order: chunks 0-2 and the held
    // chunk 4 from OPFS, chunk 3 from its record, which is read once.
    expect(opfs.reads).toEqual([
      { name: root, at: 0, length: 5 },
      { name: root, at: 5, length: 5 },
      { name: root, at: 10, length: 5 },
      { name: root, at: 20, length: 3 },
    ]);
    expect(counts.advances - visitsBefore).toBe(4);
    expect(await settle(root, token)).toBe("complete");
  });

  test("a resent chunk during verification changes nothing", async () => {
    const root = "7f".repeat(64);
    const files = new Map<string, Uint8Array>();
    const opfs = installOpfs(files);
    await store(fileChunk(root, 0, 13));
    await store(fileChunk(root, 1, 13));
    const held = await store(fileChunk(root, 2, 13));
    const token = (held as { verification: string }).verification;
    const before = await rows();

    // Verification has started; copies of the held chunk and of a recorded
    // one arrive, and a second completion asks to verify again.
    const [first, resentHeld, resentRecorded, second] =
      await callWorkersConcurrently([
        { method: "verifyReceivedFile", args: [root, token] },
        { method: "storeReceiveChunk", args: [fileChunk(root, 2, 13)] },
        { method: "storeReceiveChunk", args: [fileChunk(root, 0, 13)] },
        { method: "verifyReceivedFile", args: [root, token] },
      ]);
    // The held chunk's copy is handed the running attempt, so the connection
    // it came on can settle it; nothing is written for it.
    expect(resentHeld.result).toEqual({
      stored: false,
      savedSize: 10,
      complete: false,
      verification: token,
    });
    expect(resentRecorded.result).toEqual({
      stored: false,
      savedSize: 10,
      complete: false,
    });
    expect(first.result).toBe("match");
    expect(second.result).toBe("match");
    // Nothing was written (beyond the verification's own lease), and the
    // file was read once, not twice.
    const after = await rows();
    expect(after.chunks).toEqual(before.chunks);
    expect(after.messageData).toEqual(before.messageData);
    expect(opfs.reads.length).toBe(3);
    expect(await settle(root, token)).toBe("complete");
  });

  test("a reload during verification verifies again on the next start", async () => {
    quietConsole();
    let now = 1_800_000_000_000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    restores.push(() => clock.mockRestore());
    const root = "70".repeat(64);
    const files = new Map<string, Uint8Array>();
    installOpfs(files);
    await store(fileChunk(root, 0, 13));
    await store(fileChunk(root, 1, 13));
    const held = await store(fileChunk(root, 2, 13));
    const lost = (held as { verification: string }).verification;
    // The page dies mid-verification: its lease outlives it, nothing settles.
    const db = await getDB();
    const activity = (await db.get("receiveActivity", root))!;
    await db.put("receiveActivity", {
      ...activity,
      writeToken: "the-reloaded-page",
      leaseUntil: now + 120_000,
    });
    db.close();

    // Not complete and not stuck: the held chunk is not in the have-set the
    // receiver replays on reconnect, so the sender sends it again.
    expect(await messageRow(root)).toMatchObject({ savedSize: 10 });
    const replay = await callWorker("getDBAllChunkLeafHashes", [root]);
    expect(
      (replay.result as { chunkIndex: number }[]).map((c) => c.chunkIndex),
    ).toEqual([0, 1]);
    // The old attempt cannot be resumed.
    expect(await verify(root, lost)).toBe("aborted");
    expect(await settle(root, lost)).toBe("aborted");

    // Once the dead page's lease has expired, that copy verifies the file.
    now += 120_001;
    expect(await storeAndSettle(fileChunk(root, 2, 13))).toBe("complete");
    expect(await messageRow(root)).toMatchObject({ savedSize: 13 });
  });

  test("a stopped verification commits nothing and is verified again", async () => {
    const root = "71".repeat(64);
    const files = new Map<string, Uint8Array>();
    installOpfs(files);
    await store(fileChunk(root, 0, 13));
    await store(fileChunk(root, 1, 13));
    const held = await store(fileChunk(root, 2, 13));
    const token = (held as { verification: string }).verification;
    const [verdict] = await callWorkersConcurrently([
      { method: "verifyReceivedFile", args: [root, token] },
      { method: "abortReceivedFileVerification", args: [root, token] },
    ]);
    expect(verdict.result).toBe("aborted");
    // Settling without committing (the edge is gone) leaves it unfinished.
    expect(await settle(root, token, false)).toBe("aborted");
    const row = await messageRow(root);
    expect(row?.savedSize).toBe(10);
    expect(row?.receiveVerification?.token).toBe(token);
    expect(await storeAndSettle(fileChunk(root, 2, 13))).toBe("complete");
  });

  test("another transfer's chunk commits while a file is being verified", async () => {
    const big = "72".repeat(64);
    const other = "73".repeat(64);
    const files = new Map<string, Uint8Array>();
    // 160 chunks = 10 verification batches.
    const total = 160 * 5;
    installOpfs(files);
    for (let index = 0; index < 159; index++)
      await store(fileChunk(big, index, total));
    const held = await store(fileChunk(big, 159, total));
    const token = (held as { verification: string }).verification;

    const order: string[] = [];
    const verifying = callWorker("verifyReceivedFile", [big, token]).then(
      (reply) => {
        order.push("verified");
        return reply.result;
      },
    );
    const committed = callWorker("storeReceiveChunk", [
      chunkOf(other, 0, 10, 5),
    ]).then((reply) => {
      order.push("other committed");
      return reply.result;
    });
    expect(await committed).toEqual({
      stored: true,
      savedSize: 5,
      complete: false,
    });
    expect(await verifying).toBe("match");
    expect(order).toEqual(["other committed", "verified"]);
    expect(await settle(big, token)).toBe("complete");
  });

  test("a file being verified keeps its handle while other files open theirs", async () => {
    const root = "74".repeat(64);
    const files = new Map<string, Uint8Array>();
    const others = Array.from({ length: 8 }, (_, i) =>
      (0x80 + i).toString(16).repeat(64),
    );
    let opened: Promise<WorkerResponse[]> | undefined;
    const opfs = installOpfs(
      files,
      {},
      {
        onRead: () => {
          // Eight other files open handles while this one is read: one more
          // than the cap of eight, so the oldest unpinned handle is evicted.
          opened ??= callWorkersConcurrently(
            others.map((other) => ({
              method: "storeReceiveChunk",
              args: [fileChunk(other, 0, 13)],
            })),
          );
        },
      },
    );
    // 40 chunks: three verification batches, yielding between them.
    for (let index = 0; index < 39; index++)
      await store(fileChunk(root, index, 200));
    const held = await store(fileChunk(root, 39, 200));
    const token = (held as { verification: string }).verification;

    expect(await verify(root, token)).toBe("match");
    const stored = await opened!;
    expect(stored.map((reply) => reply.error)).toEqual(
      others.map(() => undefined),
    );
    // Another file's handle was evicted; the one being read never was.
    expect(opfs.closes).not.toContain(root);
    expect(opfs.closes.length).toBeGreaterThan(0);
    expect(await settle(root, token)).toBe("complete");
  });
});

describe("no failure leaves a verification behind", () => {
  const fileChunk = (root: string, index: number) =>
    chunkOf(root, index, 13, 5, {
      messageType: 2,
      filename: "f.bin",
      mimeType: "application/octet-stream",
      storage: "opfs",
    });
  const holdFile = async (root: string) => {
    await store(fileChunk(root, 0));
    await store(fileChunk(root, 1));
    const held = await store(fileChunk(root, 2));
    return (held as { verification: string }).verification;
  };
  // A copy of the held chunk: it must start a fresh attempt, and complete.
  const resendCompletes = async (root: string, lost: string) => {
    const again = (await store(fileChunk(root, 2))) as {
      verification?: string;
    };
    expect(again).toMatchObject({ stored: true, complete: false });
    expect(again.verification).toBeDefined();
    expect(again.verification).not.toBe(lost);
    expect(await verify(root, again.verification!)).toBe("match");
    expect(await settle(root, again.verification!)).toBe("complete");
  };

  test("a failed verification start leaves no live entry and a resend verifies again", async () => {
    quietConsole();
    const root = "63".repeat(64);
    installOpfs(new Map());
    const token = await holdFile(root);
    // The start's first write (taking the receive lease) fails: disk full.
    const proto = (
      globalThis as unknown as {
        IDBObjectStore: { prototype: { put: (...a: unknown[]) => unknown } };
      }
    ).IDBObjectStore.prototype;
    const put = proto.put;
    let armed = true;
    proto.put = function (this: { name: string }, ...args: unknown[]) {
      if (armed && this.name === "receiveActivity") {
        armed = false;
        throw new DOMException("injected", "QuotaExceededError");
      }
      return put.apply(this, args);
    };
    restores.push(() => {
      proto.put = put;
    });

    expect(await verify(root, token)).toBe("storage-failed");
    expect(await settle(root, token)).toBe("aborted");
    // Nothing committed, nothing leased: the attempt is gone, and the next
    // copy of the held chunk is not answered "held" but verified afresh.
    const activity = (await rows()).receiveActivity.find(
      (row) => row.merkleRoot === root,
    );
    expect(activity?.writeToken).toBeUndefined();
    await resendCompletes(root, token);
  });

  // Fail one transaction the run asks for, as a connection that another tab's
  // upgrade has closed refuses it.
  const closeConnectionAt = (matches: (args: unknown[]) => boolean) => {
    const proto = (
      globalThis as unknown as {
        IDBDatabase: {
          prototype: { transaction: (...a: unknown[]) => unknown };
        };
      }
    ).IDBDatabase.prototype;
    const transaction = proto.transaction;
    let armed = true;
    proto.transaction = function (this: unknown, ...args: unknown[]) {
      if (armed && matches(args)) {
        armed = false;
        throw new DOMException("connection closed", "InvalidStateError");
      }
      return transaction.apply(this, args);
    };
    restores.push(() => {
      proto.transaction = transaction;
    });
  };

  test("a verification whose connection another tab's upgrade closed leaves no live entry", async () => {
    quietConsole();
    const root = "64".repeat(64);
    installOpfs(new Map());
    const token = await holdFile(root);
    // The run's start: its lease transaction is refused.
    closeConnectionAt(
      ([stores, mode]) =>
        mode === "readwrite" &&
        Array.isArray(stores) &&
        stores.includes("receiveActivity") &&
        stores.includes("chunks"),
    );

    expect(await verify(root, token)).toBe("storage-failed");
    expect(await settle(root, token)).toBe("aborted");
    await resendCompletes(root, token);
  });

  test("a verification that loses its connection mid-run gives its lease back", async () => {
    quietConsole();
    const root = "68".repeat(64);
    installOpfs(new Map());
    const token = await holdFile(root);
    // After the lease was taken: the next batch read is refused.
    closeConnectionAt(
      ([stores, mode]) => stores === "chunks" && mode === "readonly",
    );

    expect(await verify(root, token)).toBe("storage-failed");
    expect(await settle(root, token)).toBe("aborted");
    const activity = (await rows()).receiveActivity.find(
      (row) => row.merkleRoot === root,
    );
    expect(activity?.writeToken).toBeUndefined();
    await resendCompletes(root, token);
  });

  test("a verification run opens one connection", async () => {
    const root = "65".repeat(64);
    installOpfs(new Map());
    // 40 chunks: three batches.
    for (let index = 0; index < 39; index++)
      await store(
        chunkOf(root, index, 200, 5, {
          messageType: 2,
          storage: "opfs",
          mimeType: "application/octet-stream",
        }),
      );
    const held = (await store(
      chunkOf(root, 39, 200, 5, {
        messageType: 2,
        storage: "opfs",
        mimeType: "application/octet-stream",
      }),
    )) as { verification: string };
    const factory = (globalThis as unknown as { indexedDB: IDBFactory })
      .indexedDB;
    const open = factory.open.bind(factory);
    let opens = 0;
    factory.open = ((...args: Parameters<IDBFactory["open"]>) => {
      opens += 1;
      return open(...args);
    }) as IDBFactory["open"];
    restores.push(() => {
      factory.open = open;
    });
    expect(await verify(root, held.verification)).toBe("match");
    expect(opens).toBe(1);
    expect(await settle(root, held.verification)).toBe("complete");
  });

  test("deleting a message during its verification removes the file and emits nothing", async () => {
    const root = "66".repeat(64);
    const files = new Map<string, Uint8Array>();
    let deleting: Promise<WorkerResponse> | undefined;
    const opfs = installOpfs(
      files,
      {},
      {
        // The message is deleted while its file is being read.
        onRead: () => {
          deleting ??= callWorker("deleteDBMessageData", [root]);
        },
      },
    );
    for (let index = 0; index < 39; index++)
      await store(
        chunkOf(root, index, 200, 5, {
          messageType: 2,
          storage: "opfs",
          mimeType: "application/octet-stream",
        }),
      );
    const held = (await store(
      chunkOf(root, 39, 200, 5, {
        messageType: 2,
        storage: "opfs",
        mimeType: "application/octet-stream",
      }),
    )) as { verification: string };
    const opensBefore = opfs.fileOpens.length;

    // Stopped, not failed: no storage-failed verdict, so no event goes out.
    expect(await verify(root, held.verification)).toBe("aborted");
    expect((await deleting!).error).toBeUndefined();
    expect(await settle(root, held.verification)).toBe("aborted");
    // The file is gone, its handle closed, nothing reopened or recreated.
    expect(files.has(root)).toBe(false);
    expect(opfs.closes).toContain(root);
    expect(
      opfs.fileOpens.slice(opensBefore).filter((open) => open.create),
    ).toEqual([]);
    expect(await messageRow(root)).toBeUndefined();
  });

  test("verification never creates a file", async () => {
    quietConsole();
    const root = "67".repeat(64);
    const files = new Map<string, Uint8Array>();
    const opfs = installOpfs(files);
    const token = await holdFile(root);
    // The file vanished (another context removed it) and no handle is open.
    await callWorker("closeReceiveFile", [root]);
    files.delete(root);
    const opensBefore = opfs.fileOpens.length;

    expect(await verify(root, token)).toBe("storage-failed");
    expect(files.has(root)).toBe(false);
    expect(
      opfs.fileOpens.slice(opensBefore).filter((open) => open.create),
    ).toEqual([]);
    expect(await settle(root, token)).toBe("aborted");
  });
});

describe("held files are verified at the next start", () => {
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
  const ROOM = "00000000-0000-4000-8000-000000000a05";

  // Hold a file's last chunk as an interrupted verification leaves it: the
  // page went away before (or while) the file was verified.
  const holdFile = async (
    root: string,
    overrides: Partial<ReceiveChunk> = {},
  ) => {
    await store(fileChunk(root, 0, 13, overrides));
    await store(fileChunk(root, 1, 13, overrides));
    const held = await store(fileChunk(root, 2, 13, overrides));
    return (held as { verification: string }).verification;
  };

  const waitForNotices = async (count: number): Promise<void> => {
    for (let attempt = 0; attempt < 200 && notices.length < count; attempt++)
      await new Promise((resolve) => setTimeout(resolve, 5));
    expect(notices.length).toBe(count);
  };

  test("a file whose verification was interrupted by a reload is verified at the next start without the sender", async () => {
    quietConsole();
    notices.length = 0;
    const files = new Map<string, Uint8Array>();
    const opfs = installOpfs(files);
    const intact = "60".repeat(64);
    const lying = "61".repeat(64);
    await holdFile(intact);
    await holdFile(lying, { hash: contentHash(14) });
    const readsBefore = opfs.reads.length;

    // The next start: the SDK loads the room's messages. The reply carries the
    // rows as they are; both files are then verified, one after the other.
    const rows = (await callWorker("getDBRoomMessageData", [ROOM]))
      .result as MessageData[];
    expect(rows.find((r) => r.merkleRoot === intact)?.savedSize).toBe(10);
    await waitForNotices(2);
    expect(notices).toMatchObject([
      { merkleRoot: intact, verdict: "match", outcome: "complete" },
      { merkleRoot: lying, verdict: "mismatch", outcome: "integrity" },
    ]);
    // Each file was read back once (three chunks each).
    expect(opfs.reads.length - readsBefore).toBe(6);
    const verified = await messageRow(intact);
    expect(verified?.savedSize).toBe(13);
    expect(verified?.receiveVerification).toBeUndefined();
    expect(await messageRow(lying)).toMatchObject({
      savedSize: 0,
      integrityFailed: true,
    });
    // A later load verifies nothing again.
    await callWorker("getDBRoomMessageData", [ROOM]);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(notices.length).toBe(2);
  });

  test("a start does not verify a file another tab is verifying", async () => {
    notices.length = 0;
    const files = new Map<string, Uint8Array>();
    const opfs = installOpfs(files);
    const root = "62".repeat(64);
    await holdFile(root);
    // Another tab holds the file's receive lease for a little longer.
    const db = await getDB();
    const activity = (await db.get("receiveActivity", root))!;
    await db.put("receiveActivity", {
      ...activity,
      writeToken: "another-tab",
      leaseUntil: Date.now() + 80,
    });
    db.close();
    const readsBefore = opfs.reads.length;

    await callWorker("getDBRoomMessageData", [ROOM]);
    await new Promise((resolve) => setTimeout(resolve, 30));
    // Not while the other tab holds it.
    expect(notices).toEqual([]);
    expect(opfs.reads.length).toBe(readsBefore);
    // One timer fires when that lease ends; the file is verified once.
    await waitForNotices(1);
    expect(notices[0]).toMatchObject({ merkleRoot: root, outcome: "complete" });
    expect(opfs.reads.length - readsBefore).toBe(3);
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
      await storeAndSettle(
        chunkOf(root, 1, 10, 5, {
          messageType: 2,
          mimeType: "application/octet-stream",
          storage: "opfs",
        }),
      ),
    ).toBe("complete");
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
