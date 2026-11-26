import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { encodeCanonical } from "../../../src/blindRendezvous/canonicalSchema";
import {
  publicChunkV1Schema,
  publicStoreCheckpointV1Schema,
} from "../../../src/blindRendezvous/schemas";
import {
  encodePublicAllocationLeaseBodyV1,
  encodePublicAllocationLeaseV1,
  encodeStoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";

import type {
  PublicAllocationLeaseV1,
  StoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import type {
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../../src/blindRendezvous/publicWindow";
import type {
  StoreAllocationRecord,
  StoreWindowState,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const filled = (length: number, byte: number): Uint8Array =>
  new Uint8Array(length).fill(byte);

const root = mkdtempSync(join(tmpdir(), "p2party-store-sqlite-"));
let databaseCounter = 0;

/** One fresh database file per test; the port is a file, so reuse would leak
 * one test's rows into the next. */
const databasePath = (): string =>
  join(root, `store-${String(databaseCounter++)}.sqlite`);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const leaseOf = (
  ordinal: number,
  ingressWindow: bigint,
): PublicAllocationLeaseV1 => ({
  version: 1,
  storeId: filled(32, 0x11),
  deliveryProfileHash: filled(32, 0x22),
  ingressWindow,
  requestHash: filled(32, 0x30 + ordinal),
  allocationOrdinal: ordinal,
  allocationEd25519PublicKey: filled(32, 0x40 + ordinal),
  storeSignature: filled(64, 0x50 + ordinal),
});

/** Chunks here are deliberately tiny: the persistence port stores whatever
 * the core hands it and never re-derives the profile geometry, so a
 * profile-sized chunk would only make the test slow. */
const chunkOf = (
  sizeClass: number,
  chunkIndex: bigint,
  ingressWindow: bigint,
): PublicChunkV1 => ({
  version: 1,
  bucket: {
    deliveryProfileHash: filled(32, 0x22),
    ingressWindow,
    sizeClass,
  },
  chunkIndex,
  previousChunkHash: filled(32, 0x60 + Number(chunkIndex)),
  fixedObjects: [filled(8, 0x70 + sizeClass), filled(8, 0x71 + sizeClass)],
  storeSignature: filled(64, 0x80 + sizeClass),
});

const checkpointOf = (ingressWindow: bigint): PublicStoreCheckpointV1 => ({
  version: 1,
  storeId: filled(32, 0x11),
  descriptorHash: filled(32, 0x12),
  deliveryProfileHash: filled(32, 0x22),
  ingressWindow,
  chainStartIngressWindow: 425_000_000n,
  previousCheckpointHash: filled(32, 0x13),
  finalizedChunkCount: 5,
  finalizedChunkRoot: filled(32, 0x14),
  storeSignature: filled(64, 0x15),
});

const witnessOf = (
  ingressWindow: bigint,
  checkpointByte: number,
): StoreWitnessRecordV1 => ({
  version: 1,
  witnessedStoreId: filled(32, 0x91),
  deliveryProfileHash: filled(32, 0x22),
  ingressWindow,
  checkpointHash: filled(32, checkpointByte),
});

/** No admission: one shared bound per window, no per-key share. */
const openWitnessBounds = {
  maxRecordsPerWindow: 4_096,
  quotaKey32: null,
  maxRecordsPerQuotaKey: 0,
};

const allocationOf = (
  ordinal: number,
  window: bigint,
): StoreAllocationRecord => {
  const { storeSignature: _storeSignature, ...leaseBody } = leaseOf(
    ordinal,
    window,
  );
  return {
    leaseBody,
    lease: leaseOf(ordinal, window),
    requestHash: filled(32, 0x30 + ordinal),
  };
};

const unfinalizedState = (window: bigint): StoreWindowState => ({
  window,
  allocations: new Map([
    [0, allocationOf(0, window)],
    [3, allocationOf(3, window)],
  ]),
  slots: new Map([
    ["0:1:3", { objectHash: filled(32, 0xa1), object: filled(24, 0xa2) }],
    ["1:0:7", { objectHash: filled(32, 0xb1), object: filled(24, 0xb2) }],
  ]),
  finalized: null,
});

const finalizedState = (window: bigint): StoreWindowState => ({
  ...unfinalizedState(window),
  finalized: {
    chunks: new Map([
      [0, [chunkOf(0, 0n, window), chunkOf(0, 1n, window)]],
      [1, [chunkOf(1, 0n, window)]],
    ]),
    checkpoint: checkpointOf(window),
  },
});

/**
 * Everything a window state holds, projected through the canonical encoders.
 * Comparing the encodings rather than the objects is what proves the stored
 * rows are the same *values*, not merely structurally similar ones.
 */
const fingerprint = (state: StoreWindowState): string =>
  JSON.stringify({
    window: String(state.window),
    allocations: [...state.allocations]
      .map(
        ([ordinal, record]) =>
          [
            ordinal,
            hex(encodePublicAllocationLeaseBodyV1(record.leaseBody)),
            hex(encodePublicAllocationLeaseV1(record.lease)),
            hex(record.requestHash),
          ] as const,
      )
      .sort((left, right) => left[0] - right[0]),
    slots: [...state.slots]
      .map(
        ([key, slot]) => [key, hex(slot.objectHash), hex(slot.object)] as const,
      )
      .sort((left, right) => (left[0] < right[0] ? -1 : 1)),
    finalized:
      state.finalized === null
        ? null
        : {
            checkpoint: hex(
              encodeCanonical(
                publicStoreCheckpointV1Schema,
                state.finalized.checkpoint,
              ),
            ),
            chunks: [...state.finalized.chunks]
              .map(
                ([sizeClass, chunks]) =>
                  [
                    sizeClass,
                    chunks.map((chunk) =>
                      hex(encodeCanonical(publicChunkV1Schema, chunk)),
                    ),
                  ] as const,
              )
              .sort((left, right) => left[0] - right[0]),
          },
  });

const withRawDatabase = <T>(path: string, body: (db: Database) => T): T => {
  const db = new Database(path, { readwrite: true, safeIntegers: true });
  try {
    return body(db);
  } finally {
    db.close();
  }
};

const storedDocument = (
  path: string,
  window: bigint,
): { allocations: { admissionQuotaKey32?: unknown }[] } =>
  withRawDatabase(path, (db) => {
    const row = db
      .query<{ state: Uint8Array }, [bigint]>(
        'SELECT state FROM "window" WHERE "window" = ?',
      )
      .get(window);
    if (row === null) throw new Error(`no row for window ${String(window)}`);
    return JSON.parse(new TextDecoder().decode(row.state)) as {
      allocations: { admissionQuotaKey32?: unknown }[];
    };
  });

describe("prototype store SQLite persistence", () => {
  test("optional admission quota keys are copied across both persistence boundaries", async () => {
    const path = databasePath();
    const db = new SqliteStorePersistence(path);
    try {
      const state = unfinalizedState(425_000_000n);
      const key = filled(32, 0xe3);
      const allocation = state.allocations.get(0);
      if (!allocation) throw new Error("missing allocation fixture");
      allocation.admissionQuotaKey32 = key;
      await db.saveWindow(state);
      key.fill(0);
      const loaded = await db.loadWindow(state.window);
      expect(loaded?.allocations.get(0)?.admissionQuotaKey32).toEqual(
        filled(32, 0xe3),
      );
      expect(loaded?.allocations.get(3)?.admissionQuotaKey32).toBeUndefined();
      loaded?.allocations.get(0)?.admissionQuotaKey32?.fill(0xff);
      expect(
        (await db.loadWindow(state.window))?.allocations.get(0)
          ?.admissionQuotaKey32,
      ).toEqual(filled(32, 0xe3));
    } finally {
      db.close();
    }
  });

  test.each([null, 7, "a".repeat(62), "A".repeat(64), "z".repeat(64)])(
    "refuses a malformed stored admission quota key: %s",
    async (invalid) => {
      const path = databasePath();
      const db = new SqliteStorePersistence(path);
      const window = 425_000_000n;
      try {
        await db.saveWindow(unfinalizedState(window));
        const document = storedDocument(path, window);
        document.allocations[0].admissionQuotaKey32 = invalid;
        withRawDatabase(path, (raw) => {
          raw
            .query<unknown, [Uint8Array, bigint]>(
              'UPDATE "window" SET state = ? WHERE "window" = ?',
            )
            .run(new TextEncoder().encode(JSON.stringify(document)), window);
        });
        await expect(db.loadWindow(window)).rejects.toThrow(
          "admission quota key",
        );
      } finally {
        db.close();
      }
    },
  );

  test("round-trips an unfinalized window across a reopen", async () => {
    const path = databasePath();
    const state = unfinalizedState(425_000_000n);

    const writer = new SqliteStorePersistence(path);
    try {
      await writer.saveWindow(state);
    } finally {
      writer.close();
    }

    const reader = new SqliteStorePersistence(path);
    try {
      const loaded = await reader.loadWindow(425_000_000n);
      expect(loaded).not.toBeNull();
      expect(fingerprint(loaded as StoreWindowState)).toBe(fingerprint(state));
      expect(await reader.lastFinalizedWindow()).toBeNull();
    } finally {
      reader.close();
    }
  });

  test("round-trips a finalized window and reports it as the last finalized", async () => {
    const path = databasePath();
    const state = finalizedState(425_000_001n);

    const writer = new SqliteStorePersistence(path);
    try {
      // An earlier unfinalized window must not win MAX(), and a later one must
      // not either: `lastFinalizedWindow` drives where finalization resumes.
      await writer.saveWindow(unfinalizedState(425_000_000n));
      await writer.saveWindow(state);
      await writer.saveWindow(unfinalizedState(425_000_002n));
    } finally {
      writer.close();
    }

    const reader = new SqliteStorePersistence(path);
    try {
      const loaded = await reader.loadWindow(425_000_001n);
      expect(loaded).not.toBeNull();
      expect(fingerprint(loaded as StoreWindowState)).toBe(fingerprint(state));
      expect(await reader.lastFinalizedWindow()).toBe(425_000_001n);
    } finally {
      reader.close();
    }
  });

  test("answers null for an unknown window and an empty chain", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    try {
      expect(await persistence.loadWindow(7n)).toBeNull();
      expect(await persistence.lastFinalizedWindow()).toBeNull();
      expect(await persistence.loadWitnessRecords(7n)).toEqual([]);
    } finally {
      persistence.close();
    }
  });

  test("keeps windows beyond Number.MAX_SAFE_INTEGER lossless", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    const window = 9_007_199_254_740_993n;
    try {
      await persistence.saveWindow(finalizedState(window));
      const loaded = await persistence.loadWindow(window);
      expect(loaded?.window).toBe(window);
      expect(await persistence.lastFinalizedWindow()).toBe(window);
    } finally {
      persistence.close();
    }
  });

  test("never aliases caller buffers in either direction", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    try {
      const state = finalizedState(425_000_003n);
      const expected = fingerprint(state);
      await persistence.saveWindow(state);

      // The core keeps mutating its working state after a save.
      state.slots.get("0:1:3")?.object.fill(0xff);
      state.finalized?.chunks.get(0)?.[0].fixedObjects[0].fill(0xff);
      expect(fingerprint((await persistence.loadWindow(425_000_003n))!)).toBe(
        expected,
      );

      // And a reader that scribbles on what it was handed must not rewrite a
      // signed chunk for the next reader.
      const loaded = (await persistence.loadWindow(425_000_003n))!;
      loaded.finalized?.chunks.get(0)?.[0].fixedObjects[0].fill(0xee);
      expect(fingerprint((await persistence.loadWindow(425_000_003n))!)).toBe(
        expected,
      );
    } finally {
      persistence.close();
    }
  });

  test("witness records are idempotent on identical canonical bytes", async () => {
    const path = databasePath();
    const persistence = new SqliteStorePersistence(path);
    try {
      const add = (record: StoreWitnessRecordV1) =>
        persistence.addWitnessRecord(record, openWitnessBounds);
      expect(await add(witnessOf(425_000_000n, 0xc1))).toBe("added");
      expect(await add(witnessOf(425_000_000n, 0xc1))).toBe("present");
      expect(await add(witnessOf(425_000_000n, 0xc2))).toBe("added");
      expect(await add(witnessOf(425_000_001n, 0xc1))).toBe("added");

      const first = await persistence.loadWitnessRecords(425_000_000n);
      expect(first.length).toBe(2);
      // Observation order is the witness's own, so the stored order is the
      // order they arrived in.
      expect(first.map((record) => hex(record.checkpointHash))).toEqual([
        hex(filled(32, 0xc1)),
        hex(filled(32, 0xc2)),
      ]);
      expect((await persistence.loadWitnessRecords(425_000_001n)).length).toBe(
        1,
      );
    } finally {
      persistence.close();
    }

    const reopened = new SqliteStorePersistence(path);
    try {
      const records = await reopened.loadWitnessRecords(425_000_000n);
      expect(
        records.map((record) => hex(encodeStoreWitnessRecordV1(record))),
      ).toEqual([
        hex(encodeStoreWitnessRecordV1(witnessOf(425_000_000n, 0xc1))),
        hex(encodeStoreWitnessRecordV1(witnessOf(425_000_000n, 0xc2))),
      ]);
      // The counts survive the reopen with the rows they count.
      expect(
        await reopened.addWitnessRecord(witnessOf(425_000_000n, 0xc3), {
          ...openWitnessBounds,
          maxRecordsPerWindow: 2,
        }),
      ).toBe("window-full");
    } finally {
      reopened.close();
    }
  });

  test("witness inserts are bounded per window and per quota key", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    try {
      const bounds = (quotaByte: number) => ({
        maxRecordsPerWindow: 3,
        quotaKey32: filled(32, quotaByte),
        maxRecordsPerQuotaKey: 2,
      });
      const window = 425_000_000n;
      const outcomes = [
        await persistence.addWitnessRecord(witnessOf(window, 1), bounds(0xa)),
        await persistence.addWitnessRecord(witnessOf(window, 2), bounds(0xa)),
        // The key's share is spent; a record already held costs no share.
        await persistence.addWitnessRecord(witnessOf(window, 3), bounds(0xa)),
        await persistence.addWitnessRecord(witnessOf(window, 1), bounds(0xa)),
        // Another key fills the window, and then nobody can add.
        await persistence.addWitnessRecord(witnessOf(window, 3), bounds(0xb)),
        await persistence.addWitnessRecord(witnessOf(window, 4), bounds(0xb)),
        await persistence.addWitnessRecord(witnessOf(window, 4), {
          ...openWitnessBounds,
          maxRecordsPerWindow: 3,
        }),
        // A refused insert left nothing behind, so the next window is fresh.
        await persistence.addWitnessRecord(
          witnessOf(window + 1n, 3),
          bounds(0xa),
        ),
      ];
      expect(outcomes).toEqual([
        "added",
        "added",
        "quota-full",
        "present",
        "added",
        "window-full",
        "window-full",
        "added",
      ]);
      expect((await persistence.loadWitnessRecords(window)).length).toBe(3);
    } finally {
      persistence.close();
    }
  });

  test("sweeps delete windows and witness rows in bounded batches, smallest first", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    try {
      const base = 425_000_000n;
      for (let offset = 0n; offset < 5n; offset++) {
        await persistence.saveWindow(finalizedState(base + offset));
        await persistence.addWitnessRecord(witnessOf(base + offset, 1), {
          maxRecordsPerWindow: 4,
          quotaKey32: filled(32, 9),
          maxRecordsPerQuotaKey: 4,
        });
      }
      expect(await persistence.deleteWindowsBefore(base + 4n, 2)).toBe(2);
      expect(await persistence.deleteWitnessRecordsBefore(base + 4n, 3)).toBe(
        3,
      );
      const kept: string[] = [];
      for (let offset = 0n; offset < 5n; offset++)
        kept.push(
          `${String(offset)}:${(await persistence.loadWindow(base + offset)) === null ? "-" : "w"}${(await persistence.loadWitnessRecords(base + offset)).length === 0 ? "-" : "r"}`,
        );
      expect(kept).toEqual(["0:--", "1:--", "2:w-", "3:wr", "4:wr"]);
      // The next batch finishes the job and never reaches the floor.
      expect(await persistence.deleteWindowsBefore(base + 4n, 8)).toBe(2);
      expect(await persistence.deleteWitnessRecordsBefore(base + 4n, 8)).toBe(
        1,
      );
      expect(await persistence.deleteWindowsBefore(base + 4n, 8)).toBe(0);
      expect(await persistence.lastFinalizedWindow()).toBe(base + 4n);
      // A swept window's quota share is gone with it: the key may add again.
      expect(
        await persistence.addWitnessRecord(witnessOf(base, 2), {
          maxRecordsPerWindow: 4,
          quotaKey32: filled(32, 9),
          maxRecordsPerQuotaKey: 1,
        }),
      ).toBe("added");
    } finally {
      persistence.close();
    }
  });

  test("an older database's witness rows are discarded at open and its windows kept", async () => {
    const path = databasePath();
    // The schema and rows an older build left behind: the same window and
    // witness tables, no per-window witness counts, no schema version.
    new Database(path, { create: true }).close();
    withRawDatabase(path, (db) => {
      db.exec(`
        CREATE TABLE "window" ("window" INTEGER PRIMARY KEY, finalized INTEGER NOT NULL, state BLOB NOT NULL);
        CREATE TABLE witness ("window" INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY ("window", record));
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      `);
      for (let byte = 0; byte < 6; byte++)
        db.query('INSERT INTO witness ("window", record) VALUES (?, ?)').run(
          425_000_000n,
          encodeStoreWitnessRecordV1(witnessOf(425_000_000n, byte)),
        );
      db.query("INSERT INTO meta (key, value) VALUES (?, ?)").run(
        "chainStartIngressWindow",
        "425000000",
      );
    });
    const seeded = new SqliteStorePersistence(path);
    try {
      // Rows written through the current port survive every later open.
      await seeded.saveWindow(finalizedState(425_000_000n));
    } finally {
      seeded.close();
    }
    withRawDatabase(path, (db) => {
      db.exec("PRAGMA user_version = 0");
      db.query('INSERT INTO witness ("window", record) VALUES (?, ?)').run(
        425_000_001n,
        encodeStoreWitnessRecordV1(witnessOf(425_000_001n, 7)),
      );
    });

    const reopened = new SqliteStorePersistence(path);
    try {
      expect(await reopened.loadWitnessRecords(425_000_000n)).toEqual([]);
      expect(await reopened.loadWitnessRecords(425_000_001n)).toEqual([]);
      expect(await reopened.lastFinalizedWindow()).toBe(425_000_000n);
      expect(reopened.loadMeta("chainStartIngressWindow")).toBe("425000000");
      // The bound is counted from what is actually held.
      for (let byte = 0; byte < 2; byte++)
        expect(
          await reopened.addWitnessRecord(witnessOf(425_000_000n, byte), {
            ...openWitnessBounds,
            maxRecordsPerWindow: 2,
          }),
        ).toBe("added");
      expect(
        await reopened.addWitnessRecord(witnessOf(425_000_000n, 9), {
          ...openWitnessBounds,
          maxRecordsPerWindow: 2,
        }),
      ).toBe("window-full");
    } finally {
      reopened.close();
    }
  });

  test("a database from a newer build is refused with a typed error", () => {
    const path = databasePath();
    new SqliteStorePersistence(path).close();
    withRawDatabase(path, (db) => {
      db.exec("PRAGMA user_version = 99");
    });
    let refusal: unknown = null;
    try {
      new SqliteStorePersistence(path).close();
    } catch (error) {
      refusal = error;
    }
    expect(refusal).toMatchObject({ name: "StorePersistenceError" });
  });

  test("meta rows survive a reopen, which is what pins the chain start", async () => {
    const path = databasePath();
    const writer = new SqliteStorePersistence(path);
    try {
      expect(writer.loadMeta("chainStartIngressWindow")).toBeNull();
      writer.saveMeta("chainStartIngressWindow", "425000000");
      writer.saveMeta("deliveryProfileHash", hex(filled(32, 0x22)));
    } finally {
      writer.close();
    }

    const reader = new SqliteStorePersistence(path);
    try {
      expect(reader.loadMeta("chainStartIngressWindow")).toBe("425000000");
      expect(reader.loadMeta("deliveryProfileHash")).toBe(
        hex(filled(32, 0x22)),
      );
      // Rewriting one key must replace it rather than add a second row.
      reader.saveMeta("chainStartIngressWindow", "425000009");
      expect(reader.loadMeta("chainStartIngressWindow")).toBe("425000009");
    } finally {
      reader.close();
    }
  });
});
