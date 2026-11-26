import { afterAll, describe, expect, mock, test } from "bun:test";

import type { MessageData } from "../../src/db/types";

// The public readMessage reads message rows and finished files through the
// database API, whose worker bundle is not inlined in a unit run. Stand in for
// the two calls it makes for these roots (same pattern as
// receiveCloseLocalOrigin.test.ts); any other root reaches the real module.
const localStorageBefore = Object.getOwnPropertyDescriptor(
  globalThis,
  "localStorage",
);
const memory = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage ??= {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

const realDb = await import("../../src/db/api");
const rows = new Map<string, Partial<MessageData>>();
const files = new Map<string, File>();
mock.module("../../src/db/api", () => ({
  ...realDb,
  getDBMessageData: async (merkleRootHex?: string, hashHex?: string) =>
    merkleRootHex !== undefined && rows.has(merkleRootHex)
      ? rows.get(merkleRootHex)
      : realDb.getDBMessageData(merkleRootHex, hashHex),
  getReceiveFile: async (
    merkleRootHex: string,
    totalSize: number,
    filename: string,
    mimeType: string,
  ) =>
    files.get(merkleRootHex) ??
    realDb.getReceiveFile(merkleRootHex, totalSize, filename, mimeType),
}));

const { store } = await import("../../src/store");
const { deleteRoom, setRoom, setMessage, setMessageAllChunks } =
  await import("../../src/reducers/roomSlice");
const { DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy");
const { normalizeRoomCapability } = await import("../../src/roomInvite");
const { MessageType } = await import("../../src/utils/messageTypes");
const index = await import("../../src/index");
const p2party = index.default;

const ROOM = "00000000-0000-4000-8000-0000000000b6";
const PEER = "00000000-0000-4000-8000-0000000000b7";

const received = (merkleRootHex: string, chunkSize: number) =>
  setMessage({
    roomId: ROOM,
    merkleRootHex,
    sha512Hex: "cd".repeat(64),
    fromPeerId: PEER,
    chunkSize,
    totalSize: 8,
    messageType: MessageType.ImagePNG,
    filename: "a.png",
    channelLabel: "chat",
    timestamp: 1,
  });

// Put back everything this file changed for the rest of the run: the real
// database API module, its room in the shared store, and the global.
afterAll(() => {
  store.dispatch(deleteRoom(ROOM));
  mock.module("../../src/db/api", () => realDb);
  if (localStorageBefore)
    Object.defineProperty(globalThis, "localStorage", localStorageBefore);
  else delete (globalThis as { localStorage?: unknown }).localStorage;
});

describe("readMessage and whole-file verification", () => {
  test("readMessage throws the integrity error for a file that failed verification", async () => {
    store.dispatch(
      setRoom({
        url: normalizeRoomCapability("b6".repeat(32)),
        id: ROOM,
        rtcConfig: {},
        policy: DEFAULT_ROOM_POLICY_V1,
      }),
    );

    // A file whose last chunk failed verification: progress was shown, its
    // chunks were dropped, and its row is marked.
    const failed = "e1".repeat(64);
    store.dispatch(received(failed, 5));
    rows.set(failed, { savedSize: 0, totalSize: 8, integrityFailed: true });
    const read = p2party.readMessage(failed);
    await expect(read).rejects.toBeInstanceOf(index.ReceiveIntegrityError);
    await expect(read).rejects.toMatchObject({
      code: "integrity",
      merkleRootHex: failed,
    });
    // A metadata-only read returns no bytes, so it does not throw.
    expect((await p2party.readMessage(failed, undefined, false)).message).toBe(
      "",
    );

    // A file that verified is read back as its bytes.
    const intact = "e2".repeat(64);
    const bytes = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
    store.dispatch(received(intact, 5));
    store.dispatch(
      setMessageAllChunks({
        roomId: ROOM,
        merkleRootHex: intact,
        sha512Hex: "cd".repeat(64),
        fromPeerId: PEER,
        totalSize: 8,
        messageType: MessageType.ImagePNG,
        filename: "a.png",
        channelLabel: "chat",
        timestamp: 1,
      }),
    );
    files.set(intact, new File([bytes], "a.png"));
    const opened = await p2party.readMessage(intact);
    expect(opened.percentage).toBe(100);
    expect(
      Array.from(new Uint8Array(await (opened.message as Blob).arrayBuffer())),
    ).toEqual(Array.from(bytes));

    // A file still arriving, not marked, reads as in progress.
    const arriving = "e3".repeat(64);
    store.dispatch(received(arriving, 5));
    rows.set(arriving, { savedSize: 5, totalSize: 8 });
    const partial = await p2party.readMessage(arriving);
    expect(partial.percentage).toBe(62);
  });
});
