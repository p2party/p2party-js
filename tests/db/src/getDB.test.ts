// IndexedDB migrations exercised against fake-indexeddb so they run under
// `bun test` without a real browser.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import { dbName, dbVersion, getDB } from "../../../src/db/src/getDB";

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

describe("getDB — v17 -> v19 protocol-v4 migration", () => {
  test("dbVersion is bumped to exactly 19", () => {
    expect(dbVersion).toBe(19);
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
      ["hash", "merkleRoot", "receiptScope", "transferId"].sort(),
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

  test("opening at v19 fresh creates the complete schema", async () => {
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
