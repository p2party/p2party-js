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
  deleteRoom,
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
const { uint8ArrayToHex } = await import("../../src/utils/uint8array");
const { normalizeRoomCapability } = await import("../../src/roomInvite");
const { StorageFailedError } = await import("../../src/db/dbErrors");
const p2party = (await import("../../src/index")).default;

const ROOM = "00000000-0000-4000-8000-0000000000c1";
const PEER = "00000000-0000-4000-8000-0000000000c2";

afterAll(() => {
  restoreClient();
  globals.onmessage = sharedWorker;
  store.dispatch(deleteRoom(ROOM));
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
  }>;
}
let directory: FakeDirectory;
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
  store.dispatch(
    setRoom({
      url: normalizeRoomCapability("c1".repeat(32)),
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
  hash: "c3".repeat(64),
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
      sha512Hex: "c3".repeat(64),
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
    const otherRoom = "00000000-0000-4000-8000-0000000000c9";
    store.dispatch(
      setRoom({
        url: normalizeRoomCapability("c9".repeat(32)),
        id: otherRoom,
        rtcConfig: {},
        policy: DEFAULT_ROOM_POLICY_V1,
      }),
    );
    restores.push(() => store.dispatch(deleteRoom(otherRoom)));
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
      lastActivityAt: Date.now() - INCOMPLETE_RECEIVE_RETENTION_MS - 1,
    });
    connection.close();
    // Past the 30 s the SDK leaves between two sweeps.
    advanceClock(31_000);

    // The listing runs the stale-receive sweep, whose removal is refused. It
    // still returns its list.
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
