// A received file that a removal could not take off the disk: on every path
// that removes files the refusal is reported once, the removal is tried again
// at the worker's next start and when the application repeats its call, and
// no path forgets the file while it exists. Each test runs through the real
// SDK, store and listener, with every database call sent to the real worker
// in this process over the client's own message path (fake-indexeddb, and the
// fake OPFS of fakeOpfs.ts, whose file system refuses to remove the files
// named below, or a file some other context holds open).
//
// Nothing here sleeps: waits are event-loop turns until a condition holds,
// and time is a clock the test moves.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import { readFileSync } from "node:fs";
import { installFakeClock } from "./fakeClock";
import { fakeOpfs } from "./fakeOpfs";

import { getDB } from "../../src/db/src/getDB";

import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { DatabaseWorkerPort } from "../../src/db/api";
import type { FileRemovalFailure } from "../../src/db/dbErrors";
import type { ReceiveChunk } from "../../src/db/types";
import type { ReceiveStorageError } from "../../src/handlers/handleReceiveMessage";
import type { FakeOpfsStats } from "./fakeOpfs";

// Process-wide state this file changes, restored in afterAll.
const globals = globalThis as unknown as {
  indexedDB: IDBFactory;
  postMessage?: unknown;
  localStorage?: unknown;
  onmessage?: (event: MessageEvent) => Promise<void>;
};
const indexedDBBefore = globals.indexedDB;
const descriptors = Object.fromEntries(
  ["postMessage", "localStorage", "navigator"].map((name) => [
    name,
    Object.getOwnPropertyDescriptor(globalThis, name),
  ]),
);
const memory = new Map<string, string>();
globals.localStorage ??= {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

// The worker in this process: a port that hands each request to its
// onmessage, and its replies (postMessage) back to the database client.
const { INCOMPLETE_RECEIVE_RETENTION_MS } =
  await import("../../src/db/db.worker");
// The instance every other test file shares, put back in afterAll.
const sharedWorker = globals.onmessage;
const port: DatabaseWorkerPort = {
  postMessage: (message: unknown) => {
    void globals.onmessage!({
      data: structuredClone(message),
    } as MessageEvent);
  },
  onmessage: null,
  onerror: null,
  onmessageerror: null,
};
const routeReplies = () => {
  globals.postMessage = (reply: unknown) =>
    port.onmessage?.({ data: structuredClone(reply) } as MessageEvent);
};
routeReplies();
const db = await import("../../src/db/api");
const restoreClient = db.useDatabaseWorkerForTests(port);

// A start of the database worker: a fresh instance of its module, whose
// start-up pass runs as it loads. The instance before it stays in memory the
// way another tab's worker would: it gets no more requests, and a handle it
// holds stays open.
let workerStarts = 0;
const startWorker = async (wait = true): Promise<void> => {
  workerStarts += 1;
  await import(`../../src/db/db.worker.ts?start=${String(workerStarts)}`);
  routeReplies();
  // A request that waits for the start: once it answers, the pass is over.
  if (wait) await db.retryFileRemovals({ roomId: "no such room" });
};

const { store } = await import("../../src/store");
const {
  deleteMessage,
  deleteMessageStateOnly,
  purgeAllRooms,
  setMessage,
  setRoom,
} = await import("../../src/reducers/roomSlice");

// A reload of the page: the worker starts again, and the page lists what the
// database holds, so a message without a row is no longer listed. (The client
// is kept, so a late answer from the worker before it is still routed to the
// call that asked.)
const reload = async (): Promise<void> => {
  await startWorker();
  for (const room of store.getState().rooms)
    for (const { merkleRootHex } of room.messages)
      if ((await db.getDBMessageData(merkleRootHex)) === undefined)
        store.dispatch(
          deleteMessageStateOnly({ roomId: room.id, merkleRootHex }),
        );
};
const { resetIdentity, setKeyPair } =
  await import("../../src/reducers/keyPairSlice");
const { sweepCancelledInboundTransfer } =
  await import("../../src/handlers/inboundTransferSweep");
const { DEFAULT_ROOM_POLICY_V1, encodeRoomPolicyV1 } =
  await import("../../src/roomPolicy");
const { hexToUint8Array, uint8ArrayToHex } =
  await import("../../src/utils/uint8array");
const { normalizeRoomCapability } = await import("../../src/roomInvite");
const { InvalidMessageHashError, StorageFailedError } =
  await import("../../src/db/dbErrors");
const { RECEIVE_RECONCILE_GATE_MS } = await import("../../src/utils/constants");
const p2party = (await import("../../src/index")).default;

const ROOM = "00000000-0000-4000-8000-0000000000c1";
const ROOM_URL = normalizeRoomCapability("c1".repeat(32));
const PEER = "00000000-0000-4000-8000-0000000000c2";
const SELF = "00000000-0000-4000-8000-0000000000c3";
const OTHER_ROOM = "00000000-0000-4000-8000-0000000000c9";
const OTHER_ROOM_URL = normalizeRoomCapability("c9".repeat(32));
// The whole-file hash every message of this file carries.
const HASH = "c3".repeat(64);

afterAll(() => {
  // No room of this file is left in the SDK's store for the files that run
  // after it. (Not deleteRoom: that keeps a placeholder for the URL, and its
  // listener would ask the database, which is no longer this file's.)
  store.dispatch(purgeAllRooms());
  restoreClient();
  globals.onmessage = sharedWorker;
  globals.indexedDB = indexedDBBefore;
  for (const [name, descriptor] of Object.entries(descriptors))
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete (globalThis as Record<string, unknown>)[name];
});

const restores: Array<() => void> = [];
let opfs: FakeOpfsStats;
interface HeldHandle {
  close: () => void;
}
interface FakeDirectory {
  getFileHandle: (
    name: string,
    options?: { create?: boolean },
  ) => Promise<{
    createSyncAccessHandle: () => Promise<HeldHandle>;
    getFile: () => Promise<File>;
  }>;
}
let directory: FakeDirectory;
// The fake file system of the test that is running.
let storage: Record<string, unknown>;
// Files whose removal the file system refuses, and the error it throws.
const refused = new Set<string>();
let refusal: () => DOMException;
// Called (once) when the file system is asked to remove a file.
let onRemoval: ((name: string) => void) | undefined;
// Called when a removal is refused because the file is held open.
let onHeldRefusal: ((name: string) => void) | undefined;
// Awaited by the file system before it lists the directory.
let listing: (() => Promise<void>) | undefined;
let errors: ReceiveStorageError[];
let stopListening: () => void;

// Time for this file: each test starts at the time this file was loaded, and
// Date.now moves only when the test moves it.
const clockBase = Date.now();
let clockOffset = 0;
const advanceClock = (ms: number): void => {
  clockOffset += ms;
};

beforeEach(async () => {
  routeReplies();
  globals.indexedDB = new IDBFactory();
  refused.clear();
  refusal = () =>
    new DOMException(
      "the device refused to remove it",
      "NoModificationAllowedError",
    );
  onRemoval = undefined;
  onHeldRefusal = undefined;
  listing = undefined;
  const fake = fakeOpfs(
    new Map(),
    {},
    {
      onRemove: (name) => {
        const hook = onRemoval;
        onRemoval = undefined;
        hook?.(name);
        if (refused.has(name)) throw refusal();
      },
      onHeldRemove: (name) => onHeldRefusal?.(name),
      onList: () => listing?.(),
    },
  );
  opfs = fake.stats;
  storage = fake.storage;
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { storage: fake.storage },
  });
  directory = (await (
    await (
      fake.storage as unknown as {
        getDirectory: () => Promise<{
          getDirectoryHandle: (name: string) => Promise<FakeDirectory>;
        }>;
      }
    ).getDirectory()
  ).getDirectoryHandle("p2party-reassembled")) as FakeDirectory;
  const clock = spyOn(Date, "now").mockImplementation(
    () => clockBase + clockOffset,
  );
  restores.push(() => clock.mockRestore());
  clockOffset = 0;
  // The SDK's store outlives every test and every test file. Each test
  // starts from this one room, whatever rooms an earlier test, or an earlier
  // file, left there.
  store.dispatch(purgeAllRooms());
  store.dispatch(
    setRoom({
      url: ROOM_URL,
      id: ROOM,
      rtcConfig: {},
      policy: DEFAULT_ROOM_POLICY_V1,
    }),
  );
  const errorLog = spyOn(console, "error").mockImplementation(() => {});
  restores.push(() => errorLog.mockRestore());
  errors = [];
  stopListening = p2party.onReceiveStorageError((error) => errors.push(error));
  restores.push(() => stopListening());
  await reload();
});
afterEach(async () => {
  while (restores.length > 0) restores.pop()!();
  // A report raised while nothing listened waits for the next listener; none
  // is left for the next test, or for another file's.
  const stop = p2party.onReceiveStorageError(() => {});
  await turn();
  stop();
});

const chunkOf = (
  root: string,
  chunkIndex: number,
  roomId = ROOM,
): ReceiveChunk => ({
  schemaVersion: 1,
  roomId,
  fromPeerId: PEER,
  channelLabel: "chat",
  timestamp: 1_790_000_000_000,
  merkleRoot: root,
  hash: HASH,
  filename: "f.bin",
  messageType: 2,
  chunkIndex,
  mimeType: "application/octet-stream",
  leafHash: "c4".repeat(64),
  realLen: 5,
  totalSize: 10,
  data: Uint8Array.from({ length: 5 }, (_, k) => chunkIndex * 16 + k).buffer,
  storage: "opfs",
});
const list = (root: string, roomId = ROOM): void => {
  store.dispatch(
    setMessage({
      roomId,
      merkleRootHex: root,
      sha512Hex: HASH,
      fromPeerId: PEER,
      chunkSize: 5,
      totalSize: 10,
      messageType: 2,
      filename: "f.bin",
      channelLabel: "chat",
      timestamp: 1,
    }),
  );
};
// One received chunk (of two) of a file written to OPFS, and the message the
// app lists for it.
const receive = async (root: string, roomId = ROOM) => {
  expect(await db.storeReceiveChunk(chunkOf(root, 0, roomId))).toMatchObject({
    stored: true,
  });
  await db.closeReceiveFile(root);
  list(root, roomId);
};
const listed = (root: string) =>
  store
    .getState()
    .rooms.find((room) => room.id === ROOM)
    ?.messages.some((message) => message.merkleRootHex === root) ?? false;
// Another context (another tab) holds the file open.
const hold = async (root: string): Promise<() => void> => {
  const handle = await (
    await directory.getFileHandle(root)
  ).createSyncAccessHandle();
  return () => handle.close();
};
const turn = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));
// Let queued work run until `condition` holds: turns of the event loop.
const until = async (condition: () => boolean): Promise<void> => {
  for (let turns = 0; turns < 50_000 && !condition(); turns++) await turn();
  expect(condition()).toBe(true);
};
// Everything queued for this file in the worker has run, and what the page
// does with the answers too: the request below waits its turn at the file's
// lock.
const quiesce = async (root: string): Promise<void> => {
  await db.closeReceiveFile(root);
  await turn();
};
const outcome = (call: Promise<unknown>): Promise<unknown> =>
  call.then(
    () => "resolved",
    (error: unknown) => error,
  );
type Typed = InstanceType<typeof StorageFailedError>;
const fileFailures = (error: unknown) =>
  (error as Typed).failures.map((failure: FileRemovalFailure) => ({
    merkleRootHex: failure.merkleRootHex,
    name: failure.error.name,
  }));
const tombstone = async (root: string) => {
  const connection = await getDB();
  try {
    return await connection.get("receiveActivity", root);
  } finally {
    connection.close();
  }
};
const HELD = "NoModificationAllowedError";
// A second room of this page. (The next test starts from one room again.)
const addOtherRoom = (): void => {
  store.dispatch(
    setRoom({
      url: OTHER_ROOM_URL,
      id: OTHER_ROOM,
      rtcConfig: {},
      policy: DEFAULT_ROOM_POLICY_V1,
    }),
  );
};
// The room's record in the database, which the page writes when the room
// gets its id. Waited for where a test deletes the room.
const roomRecord = async (roomId = ROOM) => {
  const connection = await getDB();
  try {
    return await connection.getFromIndex("uniqueRoom", "roomId", roomId);
  } finally {
    connection.close();
  }
};
const roomRecorded = async (roomId = ROOM): Promise<void> => {
  for (let turns = 0; turns < 50_000; turns++) {
    if (await roomRecord(roomId)) return;
    await turn();
  }
  throw new Error("the room's record was never written");
};
// A file this device sent, listed under the transfer ID it was sent with.
// Its copy on disk was assembled when the application read it back.
const sent = async (root: string, transferId: string): Promise<void> => {
  await db.setDBRoomMessageData(
    ROOM,
    root,
    HASH,
    SELF,
    10,
    10,
    2,
    "f.bin",
    "chat",
    1,
    transferId,
  );
  for (const chunkIndex of [0, 1])
    await db.setDBChunk({
      merkleRoot: root,
      hash: HASH,
      chunkIndex,
      mimeType: "application/octet-stream",
      data: Uint8Array.from({ length: 5 }, (_, k) => chunkIndex * 16 + k)
        .buffer,
    });
  expect(
    await db.assembleToOPFS(root, 10, "f.bin", "application/octet-stream"),
  ).not.toBeNull();
  store.dispatch(
    setMessage({
      roomId: ROOM,
      transferId,
      merkleRootHex: root,
      sha512Hex: HASH,
      fromPeerId: SELF,
      chunkSize: 10,
      totalSize: 10,
      messageType: 2,
      filename: "f.bin",
      channelLabel: "chat",
      timestamp: 1,
    }),
  );
};
// The bytes of a stored file, as another context would read them.
const bytesOf = async (root: string): Promise<number[]> => [
  ...new Uint8Array(
    await (await (await directory.getFileHandle(root)).getFile()).arrayBuffer(),
  ),
];

describe("a received file a delete could not remove reaches the application", () => {
  test("deleteMessage rejects once, with its records gone and its file still on disk", async () => {
    const root = "c5".repeat(64);
    await receive(root);
    refused.add(root);

    const failure = await outcome(p2party.deleteMessage(ROOM, root));
    expect(failure).toBeInstanceOf(StorageFailedError);
    const typed = failure as Typed;
    expect(typed.code).toBe("storage-failed");
    expect(typed.message).toContain(root);
    // What is gone: the message's records, and with them its place in the
    // list. What is left: the bytes.
    expect(await db.getDBMessageData(root)).toBeUndefined();
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);

    // The same call again tries the file again, though nothing lists it.
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBeInstanceOf(
      StorageFailedError,
    );
    refused.clear();
    await p2party.deleteMessage(ROOM, root);
    expect(opfs.list()).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("a deleteMessage action dispatched to the store raises the event", async () => {
    const root = "d0".repeat(64);
    await receive(root);
    refused.add(root);

    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await until(() => errors.length === 1);
    expect(errors[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
      filename: "f.bin",
      totalSize: 10,
      chunkIndex: -1,
    });
    expect(errors[0].cause?.name).toBe(HELD);
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);
  });

  test("a deleteMessage that meets a handle still open rejects, and removes the file once it is closed", async () => {
    const root = "cb".repeat(64);
    await receive(root);
    const release = await hold(root);

    const failure = await outcome(p2party.deleteMessage(ROOM, root));
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect((failure as Error).message).toContain(root);
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);

    // Closed there, the same call removes it.
    release();
    await p2party.deleteMessage(ROOM, root);
    expect(opfs.list()).toEqual([]);
  });

  test("disconnectFromRoom rejects when a received file cannot be removed, and tries it again when called again", async () => {
    const kept = "c6".repeat(64);
    const removed = "c7".repeat(64);
    await receive(kept);
    await receive(removed);
    refused.add(kept);

    const failure = await outcome(p2party.disconnectFromRoom(ROOM, true));
    // One typed error, not an AggregateError; each file is named in it with
    // the browser's error.
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(failure).not.toBeInstanceOf(AggregateError);
    expect((failure as Typed).cause).toBeInstanceOf(AggregateError);
    expect(fileFailures(failure)).toEqual([
      { merkleRootHex: kept, name: HELD },
    ]);
    // Every other message was still removed.
    expect(opfs.list()).toEqual([kept]);
    expect(listed(kept)).toBe(false);

    // Nothing lists the message now; the same call still reaches its file.
    const again = await outcome(p2party.disconnectFromRoom(ROOM, true));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: kept, name: HELD }]);
    refused.clear();
    expect(await outcome(p2party.disconnectFromRoom(ROOM, true))).toBe(
      "resolved",
    );
    expect(opfs.list()).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("disconnectFromAllRooms rejects when a received file cannot be removed", async () => {
    const otherRoom = OTHER_ROOM;
    addOtherRoom();
    const kept = "ca".repeat(64);
    const removed = "cc".repeat(64);
    const inOtherRoom = "cd".repeat(64);
    await receive(kept);
    await receive(removed);
    await receive(inOtherRoom, otherRoom);
    refused.add(kept);

    const failure = await outcome(p2party.disconnectFromAllRooms(true));
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(failure).not.toBeInstanceOf(AggregateError);
    expect((failure as Typed).cause).toBeInstanceOf(AggregateError);
    // Each file, not each room.
    expect(fileFailures(failure)).toEqual([
      { merkleRootHex: kept, name: HELD },
    ]);
    // Every other room and message was still removed.
    expect(opfs.list()).toEqual([kept]);
  });

  test("purgeRoom rejects with StorageFailedError when a received file cannot be removed", async () => {
    const kept = "ce".repeat(64);
    const removed = "cf".repeat(64);
    await receive(kept);
    await receive(removed);
    refused.add(kept);

    const failure = await outcome(
      p2party.purgeRoom(normalizeRoomCapability("c1".repeat(32))),
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(failure)).toEqual([
      { merkleRootHex: kept, name: HELD },
    ]);
    // What the purge's steps threw; each file's own error is in failures.
    expect((failure as Typed).cause).toBeInstanceOf(AggregateError);
    // Everything else was done: the room is gone, the other file removed.
    expect(store.getState().rooms.some((room) => room.id === ROOM)).toBe(false);
    expect(opfs.list()).toEqual([kept]);
  });

  test("purge reports each received file it could not remove, and removes the others", async () => {
    const kept = "c8".repeat(64);
    const removed = "c9".repeat(64);
    await receive(kept);
    await receive(removed);
    // Another tab holds one file: the directory cannot go as a whole.
    const release = await hold(kept);
    restores.push(release);

    const failure = await outcome(p2party.purge());
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(failure)).toEqual([
      { merkleRootHex: kept, name: HELD },
    ]);
    expect((failure as Typed).cause).toBeInstanceOf(AggregateError);
    // Everything else was done: the database is gone, and so are the rooms
    // and every file that could be removed.
    expect(await db.getDBMessageData(kept)).toBeUndefined();
    expect(store.getState().rooms).toEqual([]);
    expect(opfs.list()).toEqual([kept]);
  });
});

describe("a refused removal is retried and never forgotten", () => {
  test("a file whose removal was refused is removed at the next start", async () => {
    const root = "e0".repeat(64);
    await receive(root);
    const release = await hold(root);
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBeInstanceOf(
      StorageFailedError,
    );
    expect(opfs.list()).toEqual([root]);

    // The other tab lets go; nothing here is told. The next start finds the
    // file with no record that owns it, and removes it.
    release();
    expect(opfs.list()).toEqual([root]);
    await reload();
    expect(opfs.list()).toEqual([]);
    expect(await tombstone(root)).toMatchObject({ merkleRoot: root });
    expect((await tombstone(root))?.fileNotRemoved).toBeUndefined();
    expect(errors).toEqual([]);
  });

  test("a start that is refused again reports it once, to a listener that subscribes later too", async () => {
    const root = "e1".repeat(64);
    await receive(root);
    const release = await hold(root);
    restores.push(release);
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBeInstanceOf(
      StorageFailedError,
    );

    // The application subscribes only after the SDK has started.
    stopListening();
    await reload();
    const late: ReceiveStorageError[] = [];
    restores.push(p2party.onReceiveStorageError((error) => late.push(error)));
    await turn();
    expect(late).toHaveLength(1);
    expect(late[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
      chunkIndex: -1,
    });
    expect(late[0].cause?.name).toBe(HELD);
    expect(opfs.list()).toEqual([root]);
  });

  test("deleting a message again after a reload retries its file's removal", async () => {
    const root = "e2".repeat(64);
    await receive(root);
    const release = await hold(root);
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBeInstanceOf(
      StorageFailedError,
    );

    // After a reload the message has no record, and so is not listed.
    await reload();
    expect(await db.getDBMessageData(root)).toBeUndefined();
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);

    // The same call still reaches the file: refused while it is held...
    const again = await outcome(p2party.deleteMessage(ROOM, root));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: root, name: HELD }]);
    expect(opfs.list()).toEqual([root]);
    // ...and removed once it is not.
    release();
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBe("resolved");
    expect(opfs.list()).toEqual([]);
  });

  test("the stale-receive sweep does not forget a file it could not remove", async () => {
    const root = "e3".repeat(64);
    await receive(root);
    const release = await hold(root);

    // A day without a chunk: the sweep expires the receive. Its records go,
    // its file is refused, and the sweep still returns what it expired.
    advanceClock(INCOMPLETE_RECEIVE_RETENTION_MS + 1);
    expect(await db.sweepStaleReceiveDetails()).toEqual([
      { merkleRoot: root, roomId: ROOM, fromPeerId: PEER },
    ]);
    expect(await db.getDBMessageData(root)).toBeUndefined();
    expect(opfs.list()).toEqual([root]);
    expect(await tombstone(root)).toMatchObject({ fileNotRemoved: true });
    expect(errors.map((error) => error.code)).toEqual(["not-removed"]);

    // Another day: the deleted transfer's row would expire. The file is
    // tried first, refused again, and the row is kept.
    advanceClock(INCOMPLETE_RECEIVE_RETENTION_MS + 1);
    expect(await db.sweepStaleReceiveDetails()).toEqual([]);
    expect(opfs.list()).toEqual([root]);
    expect(await tombstone(root)).toMatchObject({ fileNotRemoved: true });

    // Once the file can go, the sweep that next looks at the row removes
    // both.
    release();
    advanceClock(INCOMPLETE_RECEIVE_RETENTION_MS + 1);
    expect(await db.sweepStaleReceiveDetails()).toEqual([]);
    expect(opfs.list()).toEqual([]);
    expect(await tombstone(root)).toBeUndefined();
    // Reported once, however often it was refused.
    expect(errors).toHaveLength(1);
  });

  test("a purge that could not remove a file leaves nothing a later start cannot remove", async () => {
    const kept = "e4".repeat(64);
    await receive(kept);
    await receive("e5".repeat(64));
    const release = await hold(kept);

    expect(await outcome(p2party.purge())).toBeInstanceOf(StorageFailedError);
    // The database is gone, and with it every record of the file.
    expect(await tombstone(kept)).toBeUndefined();
    expect(opfs.list()).toEqual([kept]);

    release();
    await reload();
    expect(opfs.list()).toEqual([]);
  });

  test("a peer's cancel whose file removal is refused is retried at the next start", async () => {
    const root = "e6".repeat(64);
    await receive(root);
    const release = await hold(root);

    // The peer cancels the transfer it was sending.
    const peer = { withPeerId: PEER } as unknown as IRTCPeerConnection;
    expect(await sweepCancelledInboundTransfer(peer, ROOM, root)).toBe(true);
    // The partial is gone from the records and the list; its bytes are not,
    // and the application is told once, with the browser's error.
    expect(await db.getDBMessageData(root)).toBeUndefined();
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
      filename: "f.bin",
      totalSize: 10,
    });
    expect(errors[0].cause?.name).toBe(HELD);

    release();
    await reload();
    expect(opfs.list()).toEqual([]);
    expect(errors).toHaveLength(1);
  });
});

describe("the start-up pass and a receive in the same Worker", () => {
  test("a file a live receive owns is never removed by the start-up pass", async () => {
    const resumed = "e7".repeat(64);
    const fresh = "e8".repeat(64);
    const orphan = "e9".repeat(64);
    // An earlier run received half of one file, and left one file no record
    // owns.
    await receive(resumed);
    await receive(orphan);
    const connection = await getDB();
    await connection.delete("receiveActivity", orphan);
    for (const key of await connection.getAllKeysFromIndex(
      "messageData",
      "merkleRoot",
      orphan,
    ))
      await connection.delete("messageData", key);
    for (const key of await connection.getAllKeysFromIndex(
      "chunks",
      "merkleRoot",
      orphan,
    ))
      await connection.delete("chunks", key);
    connection.close();

    // The worker starts, and chunks arrive at once: the rest of the first
    // file, and the first chunk of a new one.
    const order: string[] = [];
    onRemoval = (name) => order.push(`removed ${name.slice(0, 2)}`);
    await startWorker(false);
    const stored = await Promise.all([
      db.storeReceiveChunk(chunkOf(resumed, 1)),
      db.storeReceiveChunk(chunkOf(fresh, 0)),
    ]);
    expect(stored).toMatchObject([{ stored: true }, { stored: true }]);
    await db.closeReceiveFile(resumed);
    await db.closeReceiveFile(fresh);

    // The pass ran (the orphan is gone) and took neither file.
    expect(order).toEqual(["removed e9"]);
    expect(opfs.list()).toEqual([resumed, fresh].sort());
    // The resumed file still has the bytes the earlier run wrote.
    const file = await db.getReceiveFile(resumed, 10, "f.bin", "");
    expect([...new Uint8Array(await file!.arrayBuffer())]).toEqual([
      0, 1, 2, 3, 4, 16, 17, 18, 19, 20,
    ]);
    expect(errors).toEqual([]);
  });

  test("a receive that starts during the pass creates its file after the pass", async () => {
    const orphan = "ea".repeat(64);
    const fresh = "eb".repeat(64);
    await receive(orphan);
    const connection = await getDB();
    await connection.clear("receiveActivity");
    await connection.clear("messageData");
    await connection.clear("chunks");
    connection.close();

    // The pass is held at its listing of the directory.
    let letListingGo!: () => void;
    const listingHeld = new Promise<void>((resolve) => {
      letListingGo = resolve;
    });
    listing = () => listingHeld;
    await startWorker(false);
    const storing = db.storeReceiveChunk(chunkOf(fresh, 0));
    // A request that takes the new file's lock and does not wait for the
    // start: it would queue behind the chunk's write had that begun.
    await db.closeReceiveFile(fresh);
    expect(opfs.list()).toEqual([orphan]);

    letListingGo();
    expect(await storing).toMatchObject({ stored: true });
    expect(opfs.list()).toEqual([fresh]);
  });
});

describe("a file that failed its verification and could not be removed", () => {
  // Both chunks of a file whose stored bytes do not hash to the hash its
  // message carries; the second is held until the file is verified.
  const failVerification = async (root: string): Promise<void> => {
    expect(await db.storeReceiveChunk(chunkOf(root, 0))).toMatchObject({
      stored: true,
    });
    const last = await db.storeReceiveChunk(chunkOf(root, 1));
    const token = (last as { verification?: string }).verification ?? "";
    expect(token).not.toBe("");
    expect(await db.verifyReceivedFile(root, token, "this-edge")).toBe(
      "mismatch",
    );
    expect(
      await db.settleReceivedFileVerification(root, token, true, "this-edge"),
    ).toBe("integrity");
  };

  test("the drop is reported as not removed, and the file goes at the next start", async () => {
    const root = "ee".repeat(64);
    refused.add(root);
    await failVerification(root);

    // The outcome stands: the chunks are dropped and the message is marked.
    expect(await db.getDBMessageData(root)).toMatchObject({
      savedSize: 0,
      integrityFailed: true,
    });
    // The file could not be removed: said once, with the browser's error.
    expect(opfs.list()).toEqual([root]);
    await until(() => errors.length === 1);
    expect(errors[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
      filename: "f.bin",
      totalSize: 10,
    });
    expect(errors[0].cause?.name).toBe(HELD);

    // Nothing vouches for its bytes any more: the next start removes it.
    refused.clear();
    await reload();
    expect(opfs.list()).toEqual([]);
    expect(await db.getDBMessageData(root)).toMatchObject({
      integrityFailed: true,
    });
    expect(errors).toHaveLength(1);
  });

  test("once it is being received again the start-up pass leaves it alone", async () => {
    const root = "ef".repeat(64);
    refused.add(root);
    await failVerification(root);
    expect(opfs.list()).toEqual([root]);

    // The sender's resume sends the file again; its first chunk is stored
    // in the file that was left.
    expect(await db.storeReceiveChunk(chunkOf(root, 0))).toMatchObject({
      stored: true,
    });
    await db.closeReceiveFile(root);
    refused.clear();
    await reload();
    expect(opfs.list()).toEqual([root]);
    expect(await db.getDBMessageData(root)).toMatchObject({ savedSize: 5 });
  });
});

describe("a file that failed its verification and is wanted again", () => {
  // A file of one chunk, which is also its last: held until it is verified.
  const oneChunk = (root: string): ReceiveChunk => ({
    ...chunkOf(root, 0),
    totalSize: 5,
  });
  const failOneChunkFile = async (root: string): Promise<void> => {
    const held = await db.storeReceiveChunk(oneChunk(root));
    const token = (held as { verification?: string }).verification ?? "";
    expect(token).not.toBe("");
    expect(await db.verifyReceivedFile(root, token, "this-edge")).toBe(
      "mismatch",
    );
    expect(
      await db.settleReceivedFileVerification(root, token, true, "this-edge"),
    ).toBe("integrity");
    expect(opfs.list()).toEqual([root]);
  };

  test("a file whose last chunk is held for verification again is kept by the start-up pass", async () => {
    const root = "fb".repeat(64);
    refused.add(root);
    await failOneChunkFile(root);

    // The sender sends it again: its one chunk is in the file, held until
    // the file is verified. No chunk record exists yet.
    const again = await db.storeReceiveChunk(oneChunk(root));
    expect((again as { verification?: string }).verification).toBeDefined();
    await db.closeReceiveFile(root);
    refused.clear();
    await reload();
    expect(opfs.list()).toEqual([root]);
  });

  test("a file another tab is writing again is kept by the start-up pass", async () => {
    const root = "fc".repeat(64);
    refused.add(root);
    await failOneChunkFile(root);

    // Another tab has taken the receive's lease for a chunk it is storing,
    // and has not committed the chunk yet.
    const connection = await getDB();
    const activity = (await connection.get("receiveActivity", root))!;
    await connection.put("receiveActivity", {
      ...activity,
      writeToken: "another-tab",
      leaseUntil: Date.now() + 60_000,
    });
    connection.close();
    refused.clear();
    await reload();
    expect(opfs.list()).toEqual([root]);
  });
});

describe("no file is created without a record that owns it", () => {
  test("reading a message that has no stored chunk creates no file", async () => {
    const root = "fa".repeat(64);
    // As a received file, and as a sent copy.
    expect(await db.getReceiveFile(root, 10, "f.bin", "")).toBeNull();
    expect(await db.assembleToOPFS(root, 10, "f.bin", "")).toBeNull();
    expect(opfs.list()).toEqual([]);
    expect(opfs.fileOpens.filter((open) => open.create)).toEqual([]);
  });
});

describe("the start-up pass over a whole directory", () => {
  test("every file no record owns is removed, however many, and nothing else", async () => {
    // More files than the pass looks up in one transaction, none with a
    // record; one file a receive owns; and one entry that is not named by a
    // Merkle root, which is not this SDK's.
    const owned = "a0".repeat(64);
    await receive(owned);
    const orphans = Array.from({ length: 150 }, (_, index) =>
      index.toString(16).padStart(4, "0").repeat(32),
    );
    for (const name of [...orphans, "not-ours.txt"])
      await directory.getFileHandle(name, { create: true });
    expect(opfs.list()).toHaveLength(152);

    await reload();
    expect(opfs.list()).toEqual([owned, "not-ours.txt"].sort());
    expect(errors).toEqual([]);
  });
});

describe("the start-up pass and a file held open by another context", () => {
  test("a file a live receive owns is never removed by the start-up pass", async () => {
    const root = "ec".repeat(64);
    // Another tab's worker is receiving the file and holds it open (the
    // worker before this start never closed it).
    expect(await db.storeReceiveChunk(chunkOf(root, 0))).toMatchObject({
      stored: true,
    });
    expect(opfs.openHandles()).toBe(1);

    await reload();
    // Its records own it: the pass did not try to remove it, and reported
    // nothing.
    expect(opfs.list()).toEqual([root]);
    expect(opfs.openHandles()).toBe(1);
    expect(errors).toEqual([]);
    expect(await db.getDBMessageData(root)).toMatchObject({ savedSize: 5 });
  });

  test("a held file whose record appears while the pass looks at it is not reported", async () => {
    const root = "ed".repeat(64);
    await receive(root);
    const connection = await getDB();
    const activity = (await connection.get("receiveActivity", root))!;
    await connection.clear("receiveActivity");
    await connection.clear("messageData");
    await connection.clear("chunks");
    connection.close();
    const release = await hold(root);
    restores.push(release);
    // The other context writes its record just as this worker's removal is
    // refused: the file is owned by the time the records are read again.
    let written: Promise<void> | undefined;
    onHeldRefusal = () => {
      written ??= (async () => {
        const other = await getDB();
        await other.put("receiveActivity", activity);
        other.close();
      })();
    };

    await reload();
    await written;
    expect(written).toBeDefined();
    expect(opfs.list()).toEqual([root]);
    expect(errors).toEqual([]);
  });
});

describe("how a refused removal is reported", () => {
  test("listing pending messages returns the list when a background removal fails, and raises the event", async () => {
    // The listing runs the stale-receive sweep at most once in 30 s, by a
    // throttle that lives as long as the SDK module: its last pass may be
    // one another test file made, on whatever clock that file had. This
    // test's clock starts an hour back, so that the last pass it leaves is
    // long past for whatever runs after it.
    advanceClock(-3_600_000);

    // One pending outbound transfer of this identity, for the listing to
    // return.
    const sender = "11".repeat(32);
    const identity = await getDB();
    await identity.put(
      "meta",
      {
        version: 1,
        pub: new Uint8Array(32).fill(0x11).buffer,
        wrappedSecret: new Uint8Array(80).fill(0xcc).buffer,
        recordRevision: 1n,
      },
      "identityEd25519",
    );
    identity.close();
    store.dispatch(
      setKeyPair({ publicKey: sender, secretKey: "22".repeat(64) }),
    );
    restores.push(() => store.dispatch(resetIdentity()));
    const transferId = "ab".repeat(32);
    await db.outboxRequest({
      kind: "create",
      input: {
        transferId,
        owner: "this-page",
        senderPublicKey: sender,
        roomId: ROOM,
        roomUrl: "c1".repeat(32),
        policyHex: uint8ArrayToHex(encodeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1)),
        channelLabel: "chat",
        filename: "out.bin",
        totalSize: 8,
        totalChunks: 2,
        stagedBytes: 8192,
        recipients: [{ peerId: PEER, publicKey: "33".repeat(32) }],
      },
    });

    // Two listings 30 s apart pin the throttle. Whatever its last pass was,
    // the first leaves it at most 30 s before this clock, so the second
    // makes a pass, and the last pass is then at this clock exactly.
    await p2party.listPendingMessages();
    advanceClock(30_000);
    await p2party.listPendingMessages();

    // A receive that last saw a chunk more than the retention window ago,
    // whose file another tab holds open.
    const root = "f0".repeat(64);
    await receive(root);
    const release = await hold(root);
    restores.push(release);
    const connection = await getDB();
    const activity = (await connection.get("receiveActivity", root))!;
    await connection.put("receiveActivity", {
      ...activity,
      lastActivityAt: Date.now() - INCOMPLETE_RECEIVE_RETENTION_MS - 60_000,
    });
    connection.close();

    // One millisecond short of the 30 s the SDK leaves between two sweeps,
    // a listing makes no pass: the expired receive is as it was.
    advanceClock(29_999);
    expect(
      (await p2party.listPendingMessages()).map((m) => m.transferId),
    ).toEqual([transferId]);
    expect(listed(root)).toBe(true);
    expect(errors).toEqual([]);

    // At 30 s the listing runs the sweep, whose removal is refused. It still
    // returns its list.
    advanceClock(1);
    const pending = await p2party.listPendingMessages();
    expect(pending.map((message) => message.transferId)).toEqual([transferId]);
    expect(pending[0]).toMatchObject({ roomId: ROOM, filename: "out.bin" });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
    });
    expect(errors[0].cause?.name).toBe(HELD);
    // The expired receive left the list all the same.
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([root]);
  });

  test("the error deleteMessage rejects with carries the browser's failure as cause", async () => {
    const root = "f1".repeat(64);
    await receive(root);
    refused.add(root);
    refusal = () =>
      new DOMException(
        "the disk said no, in its own words",
        "InvalidStateError",
      );

    const failure = await outcome(p2party.deleteMessage(ROOM, root));
    expect(failure).toBeInstanceOf(StorageFailedError);
    const typed = failure as Typed;
    // The error crossed from the worker as a message (structuredClone both
    // ways): its cause is still an Error with the name and message the file
    // system threw.
    expect(typed.cause).toBeInstanceOf(Error);
    expect((typed.cause as Error).name).toBe("InvalidStateError");
    expect((typed.cause as Error).message).toBe(
      "the disk said no, in its own words",
    );
    expect(typed.failures).toHaveLength(1);
    expect(typed.failures[0].merkleRootHex).toBe(root);
    expect(typed.failures[0].error).toBeInstanceOf(Error);
    expect(typed.failures[0].error.name).toBe("InvalidStateError");
    expect(typed.failures[0].error.message).toBe(
      "the disk said no, in its own words",
    );
  });

  test("one refused removal is reported once per call", async () => {
    // A call the application made to delete: one rejection, no event. The
    // delete action its channel query dispatches while it runs is part of
    // the same call.
    const deleted = "f2".repeat(64);
    await receive(deleted);
    refused.add(deleted);
    onRemoval = () => {
      store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: deleted }));
    };
    expect(await outcome(p2party.deleteMessage(ROOM, deleted))).toBeInstanceOf(
      StorageFailedError,
    );
    await quiesce(deleted);
    expect(errors).toEqual([]);

    // cancelMessage is such a call too.
    const cancelled = "f3".repeat(64);
    await receive(cancelled);
    refused.add(cancelled);
    expect(
      await outcome(p2party.cancelMessage(ROOM, "chat", cancelled)),
    ).toBeInstanceOf(StorageFailedError);
    await quiesce(cancelled);
    expect(listed(cancelled)).toBe(false);
    expect(errors).toEqual([]);

    // A peer's cancel: one event, though the delete action that follows it
    // meets the same refusal.
    const peers = "f4".repeat(64);
    await receive(peers);
    refused.add(peers);
    expect(
      await db.deleteReceiveTransfer(peers, {
        roomId: ROOM,
        fromPeerId: PEER,
        incompleteOnly: true,
      }),
    ).toBe(true);
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: peers }));
    await quiesce(peers);
    expect(errors.map((error) => error.merkleRootHex)).toEqual([peers]);
  });

  test("a file is reported again only after a chunk of it was stored again", async () => {
    const root = "f5".repeat(64);
    await receive(root);
    refused.add(root);

    // Two deletes the SDK started itself meet the same refusal: one report.
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await until(() => errors.length === 1);
    list(root);
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await quiesce(root);
    expect(errors).toHaveLength(1);

    // The sender resumes the transfer and a chunk of it is stored: the file
    // is in use again. A refusal to remove it after that is a new one.
    advanceClock(1);
    await receive(root);
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await until(() => errors.length === 2);
    expect(errors.map((error) => error.code)).toEqual([
      "not-removed",
      "not-removed",
    ]);
  });

  test("a file that a repeated call removed is reported anew when it is left again", async () => {
    const root = "f8".repeat(32) + "8f".repeat(32);
    await receive(root);
    refused.add(root);
    // A delete the SDK started itself is refused: one report.
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await until(() => errors.length === 1);
    // The application's delete, repeated once the file can go, removes it.
    refused.delete(root);
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBe("resolved");
    expect(opfs.list()).toEqual([]);

    // Another tab receives the same message again. Its chunk reaches the
    // worker without passing through this page's client, so nothing on this
    // page saw the file come back into use.
    advanceClock(1);
    port.postMessage(
      { id: -1, method: "storeReceiveChunk", args: [chunkOf(root, 0)] },
      [],
    );
    await until(() => opfs.list().includes(root));
    await quiesce(root);
    list(root);
    // A delete the SDK starts itself is refused that file: a new report.
    refused.add(root);
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await until(() => errors.length === 2);
    expect(errors.map((error) => error.merkleRootHex)).toEqual([root, root]);
  });

  test("a peer's cancel that lands inside a delete call is the call's to report", async () => {
    const root = "f7".repeat(64);
    await receive(root);
    refused.add(root);

    // While the application's delete of the message runs, the peer cancels
    // the same transfer: the worker announces the file it could not remove,
    // and the call's own attempt is refused too.
    const failure = await outcome(
      db.answeringForRemoval(root, async () => {
        expect(
          await db.deleteReceiveTransfer(root, {
            roomId: ROOM,
            fromPeerId: PEER,
            incompleteOnly: true,
          }),
        ).toBe(true);
        await db.deleteReceiveTransfer(root);
      }),
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    await quiesce(root);
    expect(errors).toEqual([]);
  });

  test("the last attempt of a delete call decides how it ends", async () => {
    const root = "f6".repeat(64);
    await receive(root);
    const release = await hold(root);

    // Inside one call that answers for the file: an attempt that is refused,
    // then, the other tab having let go, one that removes it.
    await db.answeringForRemoval(root, async () => {
      await db.deleteReceiveTransfer(root);
      expect(opfs.list()).toEqual([root]);
      release();
      await db.deleteReceiveTransfer(root);
    });
    expect(opfs.list()).toEqual([]);
    expect(errors).toEqual([]);
  });
});

describe("a call that asks for a removal is repeated", () => {
  test("cancelling a message again after a refused removal retries it and rejects while the file remains", async () => {
    const root = "a1".repeat(64);
    await receive(root);
    const release = await hold(root);
    expect(
      await outcome(p2party.cancelMessage(ROOM, "chat", root)),
    ).toBeInstanceOf(StorageFailedError);
    expect(listed(root)).toBe(false);

    // Nothing lists the message now. The same call still reaches its file,
    // and says so while the file is there.
    const again = await outcome(p2party.cancelMessage(ROOM, "chat", root));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: root, name: HELD }]);
    expect(opfs.list()).toEqual([root]);
    // After a reload too.
    await reload();
    expect(
      await outcome(p2party.cancelMessage(ROOM, "chat", root)),
    ).toBeInstanceOf(StorageFailedError);
    expect(opfs.list()).toEqual([root]);

    release();
    expect(await outcome(p2party.cancelMessage(ROOM, "chat", root))).toBe(
      "resolved",
    );
    expect(opfs.list()).toEqual([]);
    expect((await tombstone(root))?.fileNotRemoved).toBeUndefined();
  });

  test("cancelling a sent message again by its transfer ID retries its file and rejects while it remains", async () => {
    const root = "a2".repeat(64);
    const transferId = "a3".repeat(32);
    await sent(root, transferId);
    const release = await hold(root);

    // What handle.cancel() calls.
    const cancel = () =>
      p2party.cancelMessage(ROOM, "chat", undefined, undefined, transferId);
    expect(await outcome(cancel())).toBeInstanceOf(StorageFailedError);
    expect(listed(root)).toBe(false);
    expect(await db.getDBMessageData(root)).toBeUndefined();

    // The message is gone from the list and the records; its transfer ID
    // still finds the file it left.
    const again = await outcome(cancel());
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: root, name: HELD }]);
    // So does cancelPendingMessage, which goes through the same call.
    expect(
      await outcome(p2party.cancelPendingMessage(ROOM, transferId)),
    ).toBeInstanceOf(StorageFailedError);
    expect(opfs.list()).toEqual([root]);

    release();
    expect(await outcome(cancel())).toBe("resolved");
    expect(opfs.list()).toEqual([]);
  });

  test("a repeated call that names one file twice tries it under each name and lists it once", async () => {
    const root = "a7".repeat(64);
    await receive(root);
    const release = await hold(root);
    expect(
      await outcome(p2party.deleteMessage(ROOM, root, HASH)),
    ).toBeInstanceOf(StorageFailedError);

    // By its root and its hash: one file, listed once.
    const again = await outcome(p2party.deleteMessage(ROOM, root, HASH));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: root, name: HELD }]);
    expect((again as Typed).cause).toMatchObject({ name: HELD });
    // A transfer ID that names nothing does not hide the file the root
    // names (a received message has no transfer ID).
    const unknownId = "00".repeat(32);
    const withId = () =>
      p2party.cancelMessage(ROOM, "chat", root, undefined, unknownId);
    const stillThere = await outcome(withId());
    expect(stillThere).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(stillThere)).toEqual([
      { merkleRootHex: root, name: HELD },
    ]);
    expect(opfs.list()).toEqual([root]);

    release();
    expect(await outcome(withId())).toBe("resolved");
    expect(opfs.list()).toEqual([]);
  });

  test("purging a room again retries its files and rejects while one remains", async () => {
    const kept = "a4".repeat(64);
    const removed = "a5".repeat(64);
    await receive(kept);
    await receive(removed);
    await roomRecorded();
    const release = await hold(kept);
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBeInstanceOf(
      StorageFailedError,
    );
    expect(store.getState().rooms.some((room) => room.id === ROOM)).toBe(false);
    expect(await roomRecord()).toBeUndefined();
    expect(opfs.list()).toEqual([kept]);

    // The room is gone. The same call still reaches the file it left, and
    // says so while the file is there.
    const again = await outcome(p2party.purgeRoom(ROOM_URL));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: kept, name: HELD }]);
    // After a reload too, when the page no longer knows the room at all.
    await reload();
    store.dispatch(purgeAllRooms());
    expect(store.getState().rooms).toEqual([]);
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBeInstanceOf(
      StorageFailedError,
    );
    // A purge of some other URL is not about this room's file.
    release();
    expect(await outcome(p2party.purgeRoom(OTHER_ROOM_URL))).toBe("resolved");
    expect(opfs.list()).toEqual([kept]);

    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBe("resolved");
    expect(opfs.list()).toEqual([]);
    expect((await tombstone(kept))?.fileNotRemoved).toBeUndefined();
  });

  test("a room's URL is not kept: its leftovers carry a digest of it", async () => {
    const kept = "a6".repeat(64);
    await receive(kept);
    await roomRecorded();
    const release = await hold(kept);
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBeInstanceOf(
      StorageFailedError,
    );
    const left = await tombstone(kept);
    expect(left).toMatchObject({
      fileNotRemoved: true,
      roomId: ROOM,
      hash: HASH,
    });
    expect(left?.roomKey).toMatch(/^[0-9a-f]{128}$/);
    expect(JSON.stringify(left)).not.toContain(ROOM_URL);

    // The digest and the message's other names go when the file does.
    release();
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBe("resolved");
    expect(opfs.list()).toEqual([]);
    const after = await tombstone(kept);
    expect(after).toMatchObject({ merkleRoot: kept, roomId: ROOM });
    expect(Object.keys(after ?? {}).sort()).toEqual(
      Object.keys(left ?? {})
        .filter(
          (key) =>
            !["fileNotRemoved", "roomKey", "hash", "transferId"].includes(key),
        )
        .sort(),
    );
  });

  test("purging a room again also retries what an earlier delete of one of its messages left", async () => {
    const root = "a8".repeat(64);
    await receive(root);
    await roomRecorded();
    const release = await hold(root);
    // The message is deleted first, and its file is refused: the room still
    // has its record then.
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBeInstanceOf(
      StorageFailedError,
    );
    // Then the room is purged, twice. The second time only its URL names it.
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBeInstanceOf(
      StorageFailedError,
    );
    const again = await outcome(p2party.purgeRoom(ROOM_URL));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: root, name: HELD }]);

    release();
    expect(await outcome(p2party.purgeRoom(ROOM_URL))).toBe("resolved");
    expect(opfs.list()).toEqual([]);
  });

  // Every call an application makes to have a file removed, each on a
  // message of its own whose file another tab holds open.
  const deletingCalls: Array<{
    name: string;
    root: string;
    arrange?: (root: string) => Promise<void>;
    call: (root: string) => Promise<unknown>;
  }> = [
    {
      name: "deleteMessage(roomId, merkleRoot)",
      root: "b0".repeat(64),
      call: (root) => p2party.deleteMessage(ROOM, root),
    },
    {
      name: "deleteMessage(roomId, merkleRoot as bytes)",
      root: "b1".repeat(64),
      call: (root) => p2party.deleteMessage(ROOM, hexToUint8Array(root)),
    },
    {
      name: "deleteMessage(roomId, undefined, hash)",
      root: "b2".repeat(64),
      call: () => p2party.deleteMessage(ROOM, undefined, HASH),
    },
    {
      name: "cancelMessage(roomId, label, merkleRoot)",
      root: "b3".repeat(64),
      call: (root) => p2party.cancelMessage(ROOM, "chat", root),
    },
    {
      name: "cancelMessage(roomId, label, undefined, hash)",
      root: "b4".repeat(64),
      call: () => p2party.cancelMessage(ROOM, "chat", undefined, HASH),
    },
    {
      name: "cancelMessage by transfer ID, which is handle.cancel()",
      root: "b5".repeat(64),
      arrange: (root) => sent(root, "d5".repeat(32)),
      call: () =>
        p2party.cancelMessage(
          ROOM,
          "chat",
          undefined,
          undefined,
          "d5".repeat(32),
        ),
    },
    {
      // The handle of a send made under the message's transfer ID, cancelled
      // at once (the send is aborted) and then cancelled again and again, as
      // a cancel button pressed more than once would.
      name: "handle.cancel() of a send under the message's transfer ID",
      root: "bb".repeat(64),
      arrange: (root) => sent(root, "d7".repeat(32)),
      call: (() => {
        let handle: ReturnType<typeof p2party.sendMessage> | undefined;
        return () => {
          if (!handle) {
            handle = p2party.sendMessage(
              "again",
              "chat",
              ROOM,
              0.9,
              3,
              undefined,
              1,
              "d7".repeat(32),
            );
            handle.done.catch(() => {});
          }
          return handle.cancel();
        };
      })(),
    },
    {
      name: "cancelPendingMessage(roomId, transferId)",
      root: "b6".repeat(64),
      arrange: (root) => sent(root, "d6".repeat(32)),
      call: () => p2party.cancelPendingMessage(ROOM, "d6".repeat(32)),
    },
    {
      name: "disconnectFromRoom(roomId, true)",
      root: "b7".repeat(64),
      call: () => p2party.disconnectFromRoom(ROOM, true),
    },
    {
      name: "disconnectFromAllRooms(true)",
      root: "b8".repeat(64),
      call: () => p2party.disconnectFromAllRooms(true),
    },
    {
      name: "purgeRoom(roomUrl)",
      root: "b9".repeat(64),
      call: () => p2party.purgeRoom(ROOM_URL),
    },
    {
      name: "purge()",
      root: "ba".repeat(64),
      call: () => p2party.purge(),
    },
  ];
  test.each(deletingCalls)(
    "no deleting call resolves while its file is still on disk: $name",
    async ({ root, arrange, call }) => {
      await (arrange ?? receive)(root);
      await roomRecorded();
      const release = await hold(root);
      const attempt = async (): Promise<unknown> => {
        const result = await outcome(call(root));
        return result instanceof StorageFailedError
          ? { rejected: fileFailures(result), onDisk: opfs.list() }
          : { result, onDisk: opfs.list() };
      };
      const refusedIt = {
        rejected: [{ merkleRootHex: root, name: HELD }],
        onDisk: [root],
      };

      // The first call, the same call again, and again after a reload: each
      // rejects, naming the file, for as long as the file is there. After a
      // reload the page lists no room until the application joins one again.
      expect(await attempt()).toEqual(refusedIt);
      expect(await attempt()).toEqual(refusedIt);
      await reload();
      store.dispatch(purgeAllRooms());
      expect(await attempt()).toEqual(refusedIt);

      // It resolves once the file can go, and the file is gone then.
      release();
      expect(await attempt()).toEqual({ result: "resolved", onDisk: [] });
    },
  );

  test("a Merkle root or hash in a form the SDK does not report is refused with a typed error", async () => {
    const root = "ab".repeat(64);
    await receive(root);
    const refusedForms: Array<[() => Promise<unknown>, string]> = [
      [() => p2party.deleteMessage(ROOM, root.toUpperCase()), "merkleRoot"],
      [
        () => p2party.cancelMessage(ROOM, "chat", root.toUpperCase()),
        "merkleRoot",
      ],
      [() => p2party.deleteMessage(ROOM, root.slice(2)), "merkleRoot"],
      [() => p2party.deleteMessage(ROOM, new Uint8Array(63)), "merkleRoot"],
      [
        () => p2party.deleteMessage(ROOM, undefined, HASH.toUpperCase()),
        "hash",
      ],
      [
        () => p2party.cancelMessage(ROOM, "chat", undefined, `${HASH}00`),
        "hash",
      ],
    ];
    for (const [call, argument] of refusedForms) {
      const failure = await outcome(call());
      expect(failure).toBeInstanceOf(InvalidMessageHashError);
      expect(failure).toMatchObject({
        code: "invalid-message-hash",
        argument,
      });
    }
    // Nothing was looked up or changed.
    expect(listed(root)).toBe(true);
    expect(opfs.list()).toEqual([root]);

    // The 64 bytes are the other accepted form.
    await p2party.deleteMessage(ROOM, hexToUint8Array(root));
    expect(listed(root)).toBe(false);
    expect(opfs.list()).toEqual([]);
  });
});

describe("what the guide says is what the package exports", () => {
  test("every error class the guide names on p2party is on the default export", () => {
    const guide = readFileSync(
      new URL("../../docs/getting-started.md", import.meta.url),
      "utf8",
    );
    const named = [
      ...new Set(guide.match(/\bp2party\.[A-Z][A-Za-z]*Error\b/g) ?? []),
    ]
      .map((name) => name.slice("p2party.".length))
      .sort();
    expect(named).toContain("StorageFailedError");
    expect(named).toContain("InvalidMessageHashError");
    const exported = p2party as unknown as Record<string, unknown>;
    expect(
      named.filter((name) => typeof exported[name] !== "function"),
    ).toEqual([]);
    // The same classes the SDK throws, so `instanceof` holds.
    expect(exported.StorageFailedError).toBe(StorageFailedError);
    expect(exported.InvalidMessageHashError).toBe(InvalidMessageHashError);
  });
});

describe("a call that names a room touches only what that room left", () => {
  test("a repeated delete naming another room never removes a live message's file", async () => {
    addOtherRoom();
    const root = "ac".repeat(64);
    // The message is in the other room: half received, its file on disk.
    await receive(root, OTHER_ROOM);
    const removals: string[] = [];
    const watch = (): void => {
      onRemoval = (name) => {
        removals.push(name);
        watch();
      };
    };
    watch();

    // A delete and a cancel that name this room, for that root, each made
    // twice as an application that repeats its call would.
    for (const call of [
      () => p2party.deleteMessage(ROOM, root),
      () => p2party.cancelMessage(ROOM, "chat", root),
    ]) {
      expect(await outcome(call())).toBe("resolved");
      expect(await outcome(call())).toBe("resolved");
    }
    // The file was not asked to go, and the message is as it was.
    expect(removals).toEqual([]);
    expect(opfs.list()).toEqual([root]);
    expect(await bytesOf(root)).toEqual([0, 1, 2, 3, 4, 0, 0, 0, 0, 0]);
    expect(await db.getDBMessageData(root)).toMatchObject({
      roomId: OTHER_ROOM,
      savedSize: 5,
    });
    expect(errors).toEqual([]);
  });

  test("a repeated delete never removes the file of a live message this page does not list", async () => {
    const root = "ad".repeat(64);
    // Another tab is receiving the message in this room: its records are in
    // the database, and this page has not listed it.
    expect(await db.storeReceiveChunk(chunkOf(root, 0))).toMatchObject({
      stored: true,
    });
    await db.closeReceiveFile(root);
    expect(listed(root)).toBe(false);

    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBe("resolved");
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBe("resolved");
    expect(opfs.list()).toEqual([root]);
    expect(await bytesOf(root)).toEqual([0, 1, 2, 3, 4, 0, 0, 0, 0, 0]);
    expect(await db.getDBMessageData(root)).toMatchObject({ savedSize: 5 });
  });

  test("a delete naming another room does not retry what that room left behind", async () => {
    addOtherRoom();
    const root = "ae".repeat(64);
    await receive(root, OTHER_ROOM);
    const release = await hold(root);
    expect(
      await outcome(p2party.deleteMessage(OTHER_ROOM, root)),
    ).toBeInstanceOf(StorageFailedError);
    expect(await tombstone(root)).toMatchObject({
      roomId: OTHER_ROOM,
      fileNotRemoved: true,
    });
    release();

    // The file could go now. A call that names this room is not about it:
    // by its root, by its hash, or as a whole room.
    const removals: string[] = [];
    onRemoval = (name) => removals.push(name);
    expect(await outcome(p2party.deleteMessage(ROOM, root))).toBe("resolved");
    expect(await outcome(p2party.deleteMessage(ROOM, undefined, HASH))).toBe(
      "resolved",
    );
    expect(await outcome(p2party.disconnectFromRoom(ROOM, true))).toBe(
      "resolved",
    );
    expect(removals).toEqual([]);
    expect(opfs.list()).toEqual([root]);

    // The room that left it removes it.
    expect(await outcome(p2party.deleteMessage(OTHER_ROOM, root))).toBe(
      "resolved",
    );
    expect(opfs.list()).toEqual([]);
  });

  test("leaving all rooms does not retry what an excepted room left behind", async () => {
    addOtherRoom();
    const root = "b3".repeat(32) + "3b".repeat(32);
    await receive(root, OTHER_ROOM);
    const release = await hold(root);
    expect(
      await outcome(p2party.deleteMessage(OTHER_ROOM, root)),
    ).toBeInstanceOf(StorageFailedError);
    release();

    const removals: string[] = [];
    onRemoval = (name) => removals.push(name);
    expect(
      await outcome(p2party.disconnectFromAllRooms(true, [OTHER_ROOM])),
    ).toBe("resolved");
    expect(removals).toEqual([]);
    expect(opfs.list()).toEqual([root]);

    // Without the exception it is one of the files the call covers.
    expect(await outcome(p2party.disconnectFromAllRooms(true))).toBe(
      "resolved",
    );
    expect(opfs.list()).toEqual([]);
  });

  test("a file no record of any room names is retried by a delete that names its root", async () => {
    const kept = "af".repeat(64);
    await receive(kept);
    const release = await hold(kept);
    // A full purge deletes the database: nothing names the file it leaves.
    expect(await outcome(p2party.purge())).toBeInstanceOf(StorageFailedError);
    expect(await tombstone(kept)).toBeUndefined();

    const again = await outcome(p2party.deleteMessage(ROOM, kept));
    expect(again).toBeInstanceOf(StorageFailedError);
    expect(fileFailures(again)).toEqual([{ merkleRootHex: kept, name: HELD }]);
    release();
    expect(await outcome(p2party.deleteMessage(ROOM, kept))).toBe("resolved");
    expect(opfs.list()).toEqual([]);
  });
});

describe("the start-up pass decides under the file's lock", () => {
  test("a record that appears between the pass's batch read and the removal keeps its file", async () => {
    const root = "b0".repeat(32) + "0b".repeat(32);
    await receive(root);
    // An earlier run left the file with no record: what a delete whose
    // removal was refused leaves.
    const connection = await getDB();
    const activity = (await connection.get("receiveActivity", root))!;
    const rows = await connection.getAllFromIndex(
      "messageData",
      "merkleRoot",
      root,
    );
    const chunks = await connection.getAllFromIndex(
      "chunks",
      "merkleRoot",
      root,
    );
    await connection.clear("receiveActivity");
    await connection.clear("messageData");
    await connection.clear("chunks");
    connection.close();
    expect(rows).toHaveLength(1);
    expect(chunks).toHaveLength(1);

    // Another tab receives the same file again. It commits its records and
    // lets go of the file's lock after this worker's pass has read the
    // records for its batch (none then), and before the pass takes the lock:
    // the lock is granted here once those records are in.
    let granted = 0;
    const locks = {
      request: async (name: string, second: unknown, third?: unknown) => {
        const run = (typeof second === "function" ? second : third) as (
          lock: unknown,
        ) => unknown;
        if (name === `p2party:receive:${root}` && granted++ === 0) {
          const other = await getDB();
          await other.put("receiveActivity", activity);
          for (const row of rows) await other.put("messageData", row);
          for (const chunk of chunks) await other.put("chunks", chunk);
          other.close();
        }
        return await run({ name });
      },
    };
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { storage, locks },
    });
    const removals: string[] = [];
    onRemoval = (name) => removals.push(name);

    await reload();
    // The pass got as far as the file's lock, found the file owned there,
    // and left it.
    expect(granted).toBeGreaterThan(0);
    expect(removals).toEqual([]);
    expect(opfs.list()).toEqual([root]);
    expect(await bytesOf(root)).toEqual([0, 1, 2, 3, 4, 0, 0, 0, 0, 0]);
    expect(await db.getDBMessageData(root)).toMatchObject({ savedSize: 5 });
    expect(errors).toEqual([]);
  });
});

describe("the wait for the start-up pass is bounded", () => {
  test("file requests are served once the start pass has run past its bound", async () => {
    const orphan = "b1".repeat(32) + "1b".repeat(32);
    const fresh = "b2".repeat(32) + "2b".repeat(32);
    await receive(orphan);
    const connection = await getDB();
    await connection.clear("receiveActivity");
    await connection.clear("messageData");
    await connection.clear("chunks");
    connection.close();

    // The pass never gets its listing of the directory.
    let letListingGo!: () => void;
    const listingHeld = new Promise<void>((resolve) => {
      letListingGo = resolve;
    });
    listing = () => listingHeld;
    const clock = installFakeClock();
    restores.push(clock.restore);
    await startWorker(false);

    // A request that creates a file waits for the pass, up to the bound.
    let stored: unknown;
    void db.storeReceiveChunk(chunkOf(fresh, 0)).then((result) => {
      stored = result;
    });
    for (let turns = 0; turns < 200; turns++) await turn();
    expect(stored).toBeUndefined();
    clock.advance(RECEIVE_RECONCILE_GATE_MS - 1);
    for (let turns = 0; turns < 200; turns++) await turn();
    expect(stored).toBeUndefined();
    expect(opfs.list()).toEqual([orphan]);

    // Past the bound it is served, with the pass still under way.
    clock.advance(1);
    await until(() => stored !== undefined);
    expect(stored).toMatchObject({ stored: true });
    await db.closeReceiveFile(fresh);
    expect(opfs.list()).toEqual([orphan, fresh].sort());

    // The pass, once it gets its listing, removes the file no record owns
    // and leaves the one that was created meanwhile.
    letListingGo();
    await until(() => !opfs.list().includes(orphan));
    expect(opfs.list()).toEqual([fresh]);
    expect(await db.getDBMessageData(fresh)).toMatchObject({ savedSize: 5 });
    expect(errors).toEqual([]);
  });
});
