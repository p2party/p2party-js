// A received file that a delete could not remove reaches the application on
// every public path that removes files: p2party.deleteMessage,
// p2party.disconnectFromRoom(roomId, true) and p2party.purge. Each runs through
// the real SDK, store and listener, with every database call sent to the real
// worker in this process (fake-indexeddb, and the fake OPFS of fakeOpfs.ts,
// whose file system refuses to remove the files named below).
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

import type { DatabaseWorkerPort } from "../../src/db/api";
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
await import("../../src/db/db.worker");
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

const { store } = await import("../../src/store");
const { deleteMessage, deleteRoom, setMessage, setRoom } =
  await import("../../src/reducers/roomSlice");
const { DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy");
const { normalizeRoomCapability } = await import("../../src/roomInvite");
const { StorageFailedError } = await import("../../src/db/dbErrors");
const p2party = (await import("../../src/index")).default;

const ROOM = "00000000-0000-4000-8000-0000000000c1";
const PEER = "00000000-0000-4000-8000-0000000000c2";

afterAll(() => {
  restoreClient();
  store.dispatch(deleteRoom(ROOM));
  globals.indexedDB = indexedDBBefore;
  for (const [name, descriptor] of Object.entries(descriptors))
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete (globalThis as Record<string, unknown>)[name];
});

const restores: Array<() => void> = [];
let opfs: FakeOpfsStats;
// Files whose removal the file system refuses (by file name, or the
// reassembly directory's name for a purge).
const refused = new Set<string>();
beforeEach(() => {
  routeReplies();
  globals.indexedDB = new IDBFactory();
  refused.clear();
  const fake = fakeOpfs(
    new Map(),
    {},
    {
      onRemove: (name) => {
        if (refused.has(name))
          throw new DOMException(
            "the device refused to remove it",
            "NoModificationAllowedError",
          );
      },
    },
  );
  opfs = fake.stats;
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { storage: fake.storage },
  });
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
});
afterEach(() => {
  while (restores.length > 0) restores.pop()!();
});

// One received chunk (of two) of a file written to OPFS, and the message the
// app lists for it.
const receive = async (root: string, roomId = ROOM) => {
  const data = Uint8Array.from({ length: 5 }, (_, k) => k);
  const chunk: ReceiveChunk = {
    schemaVersion: 1,
    roomId,
    fromPeerId: PEER,
    channelLabel: "chat",
    timestamp: 1_790_000_000_000,
    merkleRoot: root,
    hash: "c3".repeat(64),
    filename: "f.bin",
    messageType: 2,
    chunkIndex: 0,
    mimeType: "application/octet-stream",
    leafHash: "c4".repeat(64),
    realLen: 5,
    totalSize: 10,
    data: data.buffer,
    storage: "opfs",
  };
  expect(await db.storeReceiveChunk(chunk)).toMatchObject({ stored: true });
  await db.closeReceiveFile(root);
  store.dispatch(
    setMessage({
      roomId,
      merkleRootHex: root,
      sha512Hex: chunk.hash,
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
const listed = (root: string) =>
  store
    .getState()
    .rooms.find((room) => room.id === ROOM)
    ?.messages.some((message) => message.merkleRootHex === root) ?? false;
const waitFor = async (condition: () => boolean): Promise<void> => {
  for (let attempt = 0; attempt < 400 && !condition(); attempt++)
    await new Promise((resolve) => setTimeout(resolve, 5));
  expect(condition()).toBe(true);
};

describe("a received file a delete could not remove reaches the application", () => {
  test("deleteMessage reports a file removal failure to the application", async () => {
    const root = "c5".repeat(64);
    await receive(root);
    refused.add(root);

    // p2party.deleteMessage returns the delete's own promise: it rejects,
    // and the message stays listed so the delete can be tried again.
    const failure = await p2party.deleteMessage(ROOM, root).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    const typed = failure as InstanceType<typeof StorageFailedError>;
    expect(typed.code).toBe("storage-failed");
    expect(typed.message).toContain(root);
    expect(listed(root)).toBe(true);
    expect(opfs.list()).toEqual([root]);

    // A deleteMessage action dispatched to the store returns nothing: the
    // failure arrives through onReceiveStorageError.
    const errors: ReceiveStorageError[] = [];
    restores.push(p2party.onReceiveStorageError((error) => errors.push(error)));
    store.dispatch(deleteMessage({ roomId: ROOM, merkleRootHex: root }));
    await waitFor(() => errors.length === 1);
    expect(errors[0]).toMatchObject({
      code: "not-removed",
      roomId: ROOM,
      fromPeerId: PEER,
      merkleRootHex: root,
      filename: "f.bin",
      totalSize: 10,
      chunkIndex: -1,
    });
    expect(opfs.list()).toEqual([root]);

    // Once the device lets it go, the same call removes it.
    refused.clear();
    store.dispatch(
      setMessage({
        roomId: ROOM,
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
    await p2party.deleteMessage(ROOM, root);
    expect(opfs.list()).toEqual([]);
    expect(listed(root)).toBe(false);
  });

  test("a deleteMessage that meets a handle still open rejects, and the file stays listed", async () => {
    const root = "cb".repeat(64);
    await receive(root);
    // Another context (a tab writing it) holds the file open.
    const storage = (
      navigator as unknown as {
        storage: {
          getDirectory: () => Promise<{
            getDirectoryHandle: (name: string) => Promise<{
              getFileHandle: (name: string) => Promise<{
                createSyncAccessHandle: () => Promise<{ close: () => void }>;
              }>;
            }>;
          }>;
        };
      }
    ).storage;
    const elsewhere = await (
      await (
        await (
          await storage.getDirectory()
        ).getDirectoryHandle("p2party-reassembled")
      ).getFileHandle(root)
    ).createSyncAccessHandle();

    const failure = await p2party.deleteMessage(ROOM, root).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect((failure as Error).message).toContain(root);
    expect(listed(root)).toBe(true);
    expect(opfs.list()).toEqual([root]);

    // Closed there, the same call removes it.
    elsewhere.close();
    await p2party.deleteMessage(ROOM, root);
    expect(opfs.list()).toEqual([]);
    expect(listed(root)).toBe(false);
  });

  test("disconnectFromRoom rejects when a received file cannot be removed", async () => {
    const kept = "c6".repeat(64);
    const removed = "c7".repeat(64);
    await receive(kept);
    await receive(removed);
    refused.add(kept);

    const failure = await p2party.disconnectFromRoom(ROOM, true).then(
      () => undefined,
      (error: unknown) => error,
    );
    // One typed error, not an AggregateError; each message's failure is
    // reachable from it.
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(failure).not.toBeInstanceOf(AggregateError);
    const typed = failure as InstanceType<typeof StorageFailedError>;
    expect(typed.cause).toBeInstanceOf(AggregateError);
    expect(typed.failures).toHaveLength(1);
    expect(typed.failures[0]).toBeInstanceOf(StorageFailedError);
    expect((typed.failures[0] as Error).message).toContain(kept);
    // Every other message was still removed.
    expect(opfs.list()).toEqual([kept]);
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

    const failure = await p2party.disconnectFromAllRooms(true).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    expect(failure).not.toBeInstanceOf(AggregateError);
    const typed = failure as InstanceType<typeof StorageFailedError>;
    expect(typed.cause).toBeInstanceOf(AggregateError);
    // Each message's failure, not each room's.
    expect(typed.failures).toHaveLength(1);
    expect(typed.failures[0]).toBeInstanceOf(StorageFailedError);
    expect((typed.failures[0] as Error).message).toContain(kept);
    // Every other room and message was still removed.
    expect(opfs.list()).toEqual([kept]);
  });

  test("purgeRoom rejects with StorageFailedError when a received file cannot be removed", async () => {
    const kept = "ce".repeat(64);
    const removed = "cf".repeat(64);
    await receive(kept);
    await receive(removed);
    refused.add(kept);

    const failure = await p2party
      .purgeRoom(normalizeRoomCapability("c1".repeat(32)))
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(failure).toBeInstanceOf(StorageFailedError);
    const typed = failure as InstanceType<typeof StorageFailedError>;
    expect(
      typed.failures.some(
        (item) =>
          item instanceof StorageFailedError && item.message.includes(kept),
      ),
    ).toBe(true);
    // Everything else was done: the room is gone, the other file removed.
    expect(store.getState().rooms.some((room) => room.id === ROOM)).toBe(false);
    expect(opfs.list()).toEqual([kept]);
  });

  test("purge reports a received file it could not remove", async () => {
    const root = "c8".repeat(64);
    await receive(root);
    // The device refuses to remove the reassembly directory.
    refused.add("p2party-reassembled");

    const failure = await p2party.purge().then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(StorageFailedError);
    // Everything else was done: the database is gone, and so are the rooms.
    expect(await db.getDBMessageData(root)).toBeUndefined();
    expect(store.getState().rooms).toEqual([]);
    // The file it could not remove is still there, and the call said so.
    expect(opfs.list()).toEqual([root]);
  });
});
