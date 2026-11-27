// IndexedDB migrations exercised against fake-indexeddb so they run under
// `bun test` without a real browser.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import { dbName, dbVersion, getDB } from "../../../src/db/src/getDB";
import { DatabaseUpgradeBlockedError } from "../../../src/db/dbErrors";

// Every test gets a pristine, empty IndexedDB environment so the fixed
// `dbName` ("p2party") never leaks state between tests.
beforeEach(() => {
  (globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
});

let openDbs: IDBDatabase[] = [];
afterEach(() => {
  for (const db of openDbs) db.close();
  openDbs = [];
});

const LEGACY_VERSION = 17;

// Simulates a real user's pre-existing v17 database, including the unsafe
// content-hash-keyed outbound staging store. v18 changed newChunks; v19 also
// invalidates only legacy crypto/transient wire state for the protocol-v4 break.
function openLegacyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, LEGACY_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      const chunks = db.createObjectStore("chunks", {
        keyPath: ["merkleRoot", "chunkIndex"],
      });
      chunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
      chunks.createIndex("hash", "hash", { unique: false });
      const newChunks = db.createObjectStore("newChunks", {
        keyPath: ["hash", "chunkIndex"],
      });
      newChunks.createIndex("hash", "hash", { unique: false });
      newChunks.createIndex("merkleRoot", "merkleRoot", { unique: false });
      newChunks.createIndex("realChunkHash", "realChunkHash", {
        unique: true,
      });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function putLegacyChunk(db: IDBDatabase, chunk: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("chunks", "readwrite");
    tx.objectStore("chunks").put(chunk);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function putLegacyNewChunk(db: IDBDatabase, chunk: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("newChunks", "readwrite");
    tx.objectStore("newChunks").put(chunk);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

describe("getDB — v17 -> v20 protocol-v4/outbox migration", () => {
  test("dbVersion is bumped to exactly 22", () => {
    expect(dbVersion).toBe(22);
  });

  test("upgrade preserves received data but recreates only outbound newChunks", async () => {
    const legacyChunk = {
      merkleRoot: "deadbeef",
      hash: "cafebabe",
      chunkIndex: 0,
      mimeType: "text/plain",
    };

    // Arrange: a v16 database that already has real data in `chunks`.
    const legacyDb = await openLegacyDB();
    await putLegacyChunk(legacyDb, legacyChunk);
    await putLegacyNewChunk(legacyDb, {
      hash: "11".repeat(64),
      chunkIndex: 0,
      merkleRoot: "",
      realChunkHash: "22".repeat(64),
    });
    legacyDb.close();

    // Act: open through the real (updated) getDB(), which runs the module's
    // upgrade() callback with oldVersion=16, newVersion=17.
    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);

    // Stores introduced before this migration still exist.
    expect(db.objectStoreNames.contains("ratchetSessions")).toBe(true);
    expect(db.objectStoreNames.contains("meta")).toBe(true);

    // Assert: ratchetSessions has the documented keyPath + non-unique indexes.
    const tx = db.transaction("ratchetSessions");
    const ratchetSessions = tx.objectStore("ratchetSessions");
    expect(ratchetSessions.keyPath).toEqual(["roomId", "peerPublicKey"]);
    expect((Array.from(ratchetSessions.indexNames) as string[]).sort()).toEqual(
      ["peerId", "peerPublicKey", "roomId"].sort(),
    );
    expect(ratchetSessions.index("peerId").unique).toBe(false);
    expect(ratchetSessions.index("peerPublicKey").unique).toBe(false);
    expect(ratchetSessions.index("roomId").unique).toBe(false);
    await tx.done;

    // Received data survives the migration completely untouched.
    expect(db.objectStoreNames.contains("chunks")).toBe(true);
    const stored = await db.get("chunks", ["deadbeef", 0]);
    expect(stored).toEqual(legacyChunk);

    // Outbound staging is transient and recreated: v17 rows cannot be assigned
    // an unambiguous random transfer identity. V19 additionally clears legacy
    // ratchet/send-ciphertext rows (empty in this v17 fixture).
    expect(await db.count("newChunks")).toBe(0);
    const outboundTx = db.transaction("newChunks");
    const outbound = outboundTx.objectStore("newChunks");
    expect(outbound.keyPath).toEqual(["transferId", "chunkIndex"]);
    expect((Array.from(outbound.indexNames) as string[]).sort()).toEqual(
      ["hash", "merkleRoot", "receiptScope", "stagedSize", "transferId"].sort(),
    );
    expect(outbound.index("receiptScope").unique).toBe(false);
    await outboundTx.done;
  });

  test("meta store is an out-of-line (keyPath-less) store that round-trips by explicit key", async () => {
    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);

    const tx = db.transaction("meta");
    expect(tx.objectStore("meta").keyPath).toBeNull();
    await tx.done;

    // The real value is a non-extractable CryptoKey (Task 3); here we only
    // prove the store is out-of-line and round-trips arbitrary values by key.
    const fakeKey = { alg: "AES-GCM" } as unknown as CryptoKey;
    await db.put("meta", fakeKey, "ratchetWrapKey");
    const value = await db.get("meta", "ratchetWrapKey");
    expect(value).toEqual(fakeKey);
  });

  test("opening at v22 fresh creates the complete schema", async () => {
    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);

    expect(db.objectStoreNames.contains("ratchetSessions")).toBe(true);
    expect(db.objectStoreNames.contains("meta")).toBe(true);
    // All pre-existing stores are still created as before.
    expect(db.objectStoreNames.contains("addressBook")).toBe(true);
    expect(db.objectStoreNames.contains("blacklist")).toBe(true);
    expect(db.objectStoreNames.contains("uniqueRoom")).toBe(true);
    expect(db.objectStoreNames.contains("messageData")).toBe(true);
    expect(db.objectStoreNames.contains("chunks")).toBe(true);
    expect(db.objectStoreNames.contains("newChunks")).toBe(true);
    expect(db.objectStoreNames.contains("sendQueue")).toBe(true);
    expect(db.objectStoreNames.contains("outbox")).toBe(true);
    expect(db.objectStoreNames.contains("outboxTrees")).toBe(true);
    expect(db.objectStoreNames.contains("outboxAcks")).toBe(true);
    expect(db.objectStoreNames.contains("receiveActivity")).toBe(true);
  });

  test("identical content stages independently and receipts are root-scoped", async () => {
    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);
    const sameHash = "ab".repeat(64);
    const sameLeaf = "cd".repeat(64);
    const first = {
      transferId: "11".repeat(32),
      hash: sameHash,
      chunkIndex: 0,
      merkleRoot: "21".repeat(64),
      leafHash: sameLeaf,
      receiptToken: "31".repeat(64),
      data: new Uint8Array([1]).buffer,
      metadata: new Uint8Array().buffer,
      merkleProof: new Uint8Array().buffer,
    };
    const second = {
      ...first,
      transferId: "12".repeat(32),
      merkleRoot: "22".repeat(64),
      receiptToken: "32".repeat(64),
    };

    await db.put("newChunks", first);
    await db.put("newChunks", second);

    expect(
      await db.countFromIndex("newChunks", "transferId", first.transferId),
    ).toBe(1);
    expect(
      await db.countFromIndex("newChunks", "transferId", second.transferId),
    ).toBe(1);
    expect(await db.countFromIndex("newChunks", "hash", sameHash)).toBe(2);
    expect(
      await db.getFromIndex("newChunks", "receiptScope", [
        first.merkleRoot,
        first.receiptToken,
      ]),
    ).toEqual(first);
    expect(
      await db.getFromIndex("newChunks", "receiptScope", [
        second.merkleRoot,
        second.receiptToken,
      ]),
    ).toEqual(second);
  });
});

// ── v21: ratchet rows wrapped in an older envelope form do not survive ───────

interface FixtureRatchetRow {
  roomId: string;
  peerPublicKey: string;
  peerId: string;
  rootKey: string;
  [field: string]: unknown;
}

// The ratchet rows 0.14.10 wrote (envelope version 2), as raw stored rows.
const releaseRatchetRows = (): Record<string, unknown>[] => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../fixtures/ratchet-wrap-v2-0.14.10.json", import.meta.url),
      "utf8",
    ),
  ) as { sessions: { wrapped: FixtureRatchetRow }[] };
  const bytes = (hex: unknown) =>
    typeof hex === "string"
      ? Uint8Array.from(Buffer.from(hex, "hex")).buffer
      : hex;
  return fixture.sessions.map(({ wrapped }) => ({
    ...wrapped,
    rootKey: bytes(wrapped.rootKey),
    sendingChainKey: bytes(wrapped.sendingChainKey),
    receivingChainKey: bytes(wrapped.receivingChainKey),
    dhSelfPub: bytes(wrapped.dhSelfPub),
    dhSelfSec: bytes(wrapped.dhSelfSec),
    dhRemotePub: bytes(wrapped.dhRemotePub),
    edgeCryptoState: bytes(wrapped.edgeCryptoState),
  }));
};

// A database at version 20 (the 0.14.10 schema) holding those rows and one
// received message, opened without the current upgrade code.
function openVersion20WithRows(
  ratchetRows: Record<string, unknown>[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 20);
    req.onupgradeneeded = () => {
      const db = req.result;
      const ratchets = db.createObjectStore("ratchetSessions", {
        keyPath: ["roomId", "peerPublicKey"],
      });
      ratchets.createIndex("peerId", "peerId", { unique: false });
      ratchets.createIndex("peerPublicKey", "peerPublicKey", { unique: false });
      ratchets.createIndex("roomId", "roomId", { unique: false });
      const messages = db.createObjectStore("messageData", {
        keyPath: ["timestamp", "roomId", "merkleRoot"],
      });
      messages.createIndex("merkleRoot", "merkleRoot", { unique: true });
      for (const row of ratchetRows) ratchets.put(row);
      messages.put({
        roomId: "room-v20",
        timestamp: 1,
        merkleRoot: "ab".repeat(64),
        hash: "cd".repeat(64),
        fromPeerId: "peer-v20",
        filename: "",
        messageType: 1,
        savedSize: 5,
        totalSize: 5,
        channelLabel: "chat",
      });
    };
    req.onsuccess = () => {
      req.result.close();
      resolve();
    };
    req.onerror = () => reject(req.error);
  });
}

describe("getDB — v21 clears ratchet rows in an older envelope form", () => {
  test("upgrading the database removes ratchet rows in an older envelope form", async () => {
    const rows = releaseRatchetRows();
    expect(rows.length).toBeGreaterThan(0);
    // Envelope version byte of each row's root key: 2, the 0.14.10 form.
    for (const row of rows)
      expect(new Uint8Array(row.rootKey as ArrayBuffer)[4]).toBe(2);
    await openVersion20WithRows(rows);

    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);
    expect(db.version).toBe(22);
    expect(await db.count("ratchetSessions")).toBe(0);
    // Other stores are untouched; the schema is complete.
    expect(await db.count("messageData")).toBe(1);
    expect(db.objectStoreNames.contains("receiveActivity")).toBe(true);
    expect(db.objectStoreNames.contains("meta")).toBe(true);
  });

  test("a database already on the new version keeps its ratchet rows", async () => {
    const [row] = releaseRatchetRows();
    const first = await getDB();
    await first.put("ratchetSessions", row as never);
    first.close();

    const reopened = await getDB();
    openDbs.push(reopened as unknown as IDBDatabase);
    expect(await reopened.count("ratchetSessions")).toBe(1);
  });
});

// While a blocked upgrade is still pending, an open fails at once. Open again
// each turn of the event loop until one succeeds: turns and not time, since
// the pending upgrade ends by queued work. One that never ends fails the test
// at the runner's timeout.
const openOnceUnblocked = async (): Promise<
  Awaited<ReturnType<typeof getDB>>
> => {
  for (;;) {
    const db = await getDB().catch(() => undefined);
    if (db) return db;
    await new Promise((resolve) => setImmediate(resolve));
  }
};

describe("getDB — connections never block or hang an upgrade", () => {
  test("a connection closes on versionchange", async () => {
    const db = await getDB();
    // A newer tab of this site upgrades while this connection is open.
    const outcome = await new Promise<string>((resolve, reject) => {
      const req = indexedDB.open(dbName, dbVersion + 1);
      req.onblocked = () => resolve("blocked");
      req.onsuccess = () => {
        req.result.close();
        resolve("upgraded");
      };
      req.onerror = () => reject(req.error);
    });
    expect(outcome).toBe("upgraded");
    // This side's connection is closed, not left to block the other tab.
    expect(() => db.transaction("meta")).toThrow();
  });

  test("a blocked upgrade fails with a typed error instead of hanging", async () => {
    // An older tab keeps a connection open and ignores versionchange.
    const old = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(dbName, 20);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("meta");
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    await expect(getDB()).rejects.toBeInstanceOf(DatabaseUpgradeBlockedError);
    // While that upgrade is pending, every open fails at once too.
    await expect(getDB()).rejects.toMatchObject({
      code: "database-upgrade-blocked",
    });

    // Once the old tab goes, the pending upgrade completes and opens work.
    old.close();
    const db = await openOnceUnblocked();
    expect(db.version).toBe(dbVersion);
    db.close();
  });

  // An older tab that keeps a connection open and ignores versionchange.
  const openOldTab = () =>
    new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(dbName, 20);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("meta");
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

  test("concurrent opens during a blocked upgrade all fail with the typed error", async () => {
    const old = await openOldTab();
    // Concurrent calls are normal in the worker: none may hang.
    const results = await Promise.allSettled([getDB(), getDB(), getDB()]);
    expect(results.map((result) => result.status)).toEqual([
      "rejected",
      "rejected",
      "rejected",
    ]);
    for (const result of results)
      expect((result as PromiseRejectedResult).reason).toBeInstanceOf(
        DatabaseUpgradeBlockedError,
      );
    old.close();
  });

  test("an open requested as the upgrade is found blocked fails at once", async () => {
    // Earlier tests' blocked opens settle first (opens fail at once until
    // they have); wait for that on a scratch database.
    const factoryUnderTest = indexedDB;
    (globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
    (await openOnceUnblocked()).close();
    (globalThis as { indexedDB: IDBFactory }).indexedDB = factoryUnderTest;
    const old = await openOldTab();
    // Request one more open at the moment `blocked` fires, after getDB's own
    // handler has run and before the rejection it caused has landed.
    const factory = indexedDB;
    const open = factory.open.bind(factory);
    let late: Promise<unknown> | undefined;
    factory.open = ((...args: Parameters<IDBFactory["open"]>) => {
      const request = open(...args);
      // Right behind getDB's own `blocked` listener.
      const add = request.addEventListener.bind(request);
      request.addEventListener = ((
        type: string,
        listener: EventListenerOrEventListenerObject,
        options?: boolean | AddEventListenerOptions,
      ) => {
        add(type, listener, options);
        if (type === "blocked")
          add("blocked", () => {
            late ??= getDB().then(
              () => "opened",
              (error: unknown) => error,
            );
          });
      }) as typeof request.addEventListener;
      return request;
    }) as IDBFactory["open"];
    try {
      await expect(getDB()).rejects.toBeInstanceOf(DatabaseUpgradeBlockedError);
      expect(late).toBeDefined();
      // The old tab is still open here: an open that waited for it instead
      // of failing never settles, and the test ends at the runner's timeout.
      expect(await late).toBeInstanceOf(DatabaseUpgradeBlockedError);
    } finally {
      factory.open = open;
      old.close();
    }
  });

  test("an open succeeds once the blocking tab has closed", async () => {
    const old = await openOldTab();
    await expect(getDB()).rejects.toBeInstanceOf(DatabaseUpgradeBlockedError);
    old.close();
    // The queued upgrade completes and is closed; then opens work again.
    const db = await openOnceUnblocked();
    expect(db.version).toBe(dbVersion);
    expect(db.objectStoreNames.contains("receiveActivity")).toBe(true);
    db.close();
  });
});

test("v22 drops server-ID PIN records, preserving locator PIN records and other metadata", async () => {
  const uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const identity = "cc".repeat(32);
  const locator = "de".repeat(64);
  const scopes = (id: string) =>
    [id, `pin-room-window:${id}`, `pin-known-peers:${id}`].map(
      (scope) => `pinAttempts:v2:${String(scope.length)}:${scope}:${identity}`,
    );
  const obsolete = [`pinAttempts:${uuid}`, ...scopes(uuid)];
  const kept = ["other-setting", ...scopes(locator)];
  await new Promise<void>((resolve, reject) => {
    const opening = indexedDB.open(dbName, 21);
    opening.onupgradeneeded = () => {
      const meta = opening.result.createObjectStore("meta");
      for (const key of [...obsolete, ...kept]) meta.put(1, key);
    };
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
      opening.result.close();
      resolve();
    };
  });
  const db = await getDB();
  try {
    expect((await db.getAllKeys("meta")).sort()).toEqual(kept.sort());
  } finally {
    db.close();
  }
});
