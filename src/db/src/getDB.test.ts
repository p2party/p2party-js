// Stage 3 / Task 2 — dbVersion 16 -> 17, additive `ratchetSessions` + `meta`
// stores. Exercised against fake-indexeddb so it runs under `bun test`
// without a real browser.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import { dbName, dbVersion, getDB } from "./getDB";

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

const LEGACY_VERSION = 16;

// Simulates a real user's pre-existing v16 database: hand-rolled `chunks`
// store (mirrors the pre-Stage-3 `getDB.ts` create-branch) with one real row
// of data already in it, and nothing else. `getDB()` (already bumped to
// v17) must upgrade this in place, additively, in the test below.
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

describe("getDB — Stage 3 Task 2 (v16 -> v17 additive upgrade)", () => {
  test("dbVersion is bumped to exactly 17", () => {
    expect(dbVersion).toBe(17);
  });

  test("upgrade adds ratchetSessions + meta stores and preserves existing chunks data", async () => {
    const legacyChunk = {
      merkleRoot: "deadbeef",
      hash: "cafebabe",
      chunkIndex: 0,
      mimeType: "text/plain",
    };

    // Arrange: a v16 database that already has real data in `chunks`.
    const legacyDb = await openLegacyDB();
    await putLegacyChunk(legacyDb, legacyChunk);
    legacyDb.close();

    // Act: open through the real (updated) getDB(), which runs the module's
    // upgrade() callback with oldVersion=16, newVersion=17.
    const db = await getDB();
    openDbs.push(db as unknown as IDBDatabase);

    // Assert: new stores exist.
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

    // Assert: the pre-existing `chunks` store and its data survived the
    // upgrade completely untouched (additive-only guarantee).
    expect(db.objectStoreNames.contains("chunks")).toBe(true);
    const stored = await db.get("chunks", ["deadbeef", 0]);
    expect(stored).toEqual(legacyChunk);
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

  test("opening at v17 fresh (no pre-existing database) also creates both new stores", async () => {
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
  });
});
