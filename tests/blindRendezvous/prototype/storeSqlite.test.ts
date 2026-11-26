import { afterAll, describe, expect, spyOn, test } from "bun:test";
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
  StoreWindowSlot,
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

/**
 * The stored `state` blob, as the row actually holds it.
 *
 * Only the fields these tests read are named. Reaching into the row is the
 * only way to test the decoder's refusals: nothing above this port can write
 * a malformed document, and a decoder that is never handed one is a decoder
 * whose validation is never exercised.
 */
interface StoredDocumentShape {
  allocations: {
    leaseBody: string;
    lease: string;
    requestHash: string;
    admissionQuotaKey32?: unknown;
  }[];
  slots: { key: string; objectHash: string; object: string }[];
  finalized: {
    checkpoint: string;
    chunks: { sizeClass: number; chunks: string[] }[];
  } | null;
}

const storedDocument = (path: string, window: bigint): StoredDocumentShape =>
  withRawDatabase(path, (db) => {
    const row = db
      .query<{ state: Uint8Array }, [bigint]>(
        'SELECT state FROM "window" WHERE "window" = ?',
      )
      .get(window);
    if (row === null) throw new Error(`no row for window ${String(window)}`);
    return JSON.parse(
      new TextDecoder().decode(row.state),
    ) as StoredDocumentShape;
  });

/** Rewrites one slot's `object` field in place, leaving the row otherwise
 * byte-identical, so the load path meets exactly one bad value. */
const corruptStoredObject = (
  path: string,
  window: bigint,
  corrupt: (value: string) => string,
): void => {
  const document = storedDocument(path, window);
  document.slots[0].object = corrupt(document.slots[0].object);
  withRawDatabase(path, (db) => {
    db.query<unknown, [Uint8Array, bigint]>(
      'UPDATE "window" SET state = ? WHERE "window" = ?',
    ).run(new TextEncoder().encode(JSON.stringify(document)), window);
  });
};

/** Every byte value once, in order: 0x00 exercises the leading-zero nibble,
 * 0xa0-0xff the letter nibbles, and `filled()` exercises neither end. */
const EVERY_BYTE = Uint8Array.from({ length: 256 }, (_, index) => index);

/** `EVERY_BYTE` rotated by `offset`, cut to `length` (wrapping as needed), so
 * a fixed-width field still carries values from both ends of the range. */
const everyByteFrom = (offset: number, length: number): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => (offset + index) % 256);

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

  /* ---------------------------------------------------------------- *
   * The hex codec
   *
   * The stored document is hex throughout, so the codec is on the path of
   * every read and every write this port serves. These pin the things a
   * faster codec is most likely to get wrong quietly: that it round-trips
   * every byte value in every field it stores, and that it still refuses a
   * row it cannot read rather than inventing bytes for it. A table that maps
   * an unexpected character to zero turns a corrupt row into a silently wrong
   * object, and the store signs what it serves.
   * ---------------------------------------------------------------- */

  test("sqlite codec round-trips all byte values", async () => {
    const path = databasePath();
    const window = 425_000_010n;
    // Eight allocations and eight slots, so each 32-byte field carries all 256
    // values across them, and every variable-length field carries all 256 in
    // one value.
    const ordinals = Array.from({ length: 8 }, (_, ordinal) => ordinal);
    const allocations = new Map(
      ordinals.map((ordinal): [number, StoreAllocationRecord] => {
        const leaseBody = {
          version: 1 as const,
          storeId: everyByteFrom(ordinal * 32, 32),
          deliveryProfileHash: everyByteFrom(ordinal * 32 + 7, 32),
          ingressWindow: window,
          requestHash: everyByteFrom(ordinal * 32 + 13, 32),
          allocationOrdinal: ordinal,
          allocationEd25519PublicKey: everyByteFrom(ordinal * 32 + 19, 32),
        };
        return [
          ordinal,
          {
            leaseBody,
            lease: {
              ...leaseBody,
              storeSignature: everyByteFrom(ordinal * 32 + 23, 64),
            },
            requestHash: everyByteFrom(ordinal * 32 + 29, 32),
            admissionQuotaKey32: everyByteFrom(ordinal * 32 + 31, 32),
          },
        ];
      }),
    );
    const slots = new Map(
      ordinals.map((ordinal): [string, StoreWindowSlot] => [
        `0:0:${String(ordinal)}`,
        {
          objectHash: everyByteFrom(ordinal * 32, 32),
          object: everyByteFrom(ordinal, 256),
        },
      ]),
    );
    const chunk: PublicChunkV1 = {
      ...chunkOf(0, 0n, window),
      previousChunkHash: everyByteFrom(200, 32),
      fixedObjects: [EVERY_BYTE, everyByteFrom(128, 256)],
      storeSignature: everyByteFrom(64, 64),
    };
    const checkpoint: PublicStoreCheckpointV1 = {
      ...checkpointOf(window),
      storeId: everyByteFrom(0, 32),
      descriptorHash: everyByteFrom(32, 32),
      previousCheckpointHash: everyByteFrom(96, 32),
      finalizedChunkRoot: everyByteFrom(160, 32),
      storeSignature: everyByteFrom(192, 64),
    };
    const state: StoreWindowState = {
      window,
      allocations,
      slots,
      finalized: { chunks: new Map([[0, [chunk]]]), checkpoint },
    };

    const writer = new SqliteStorePersistence(path);
    try {
      await writer.saveWindow(state);
    } finally {
      writer.close();
    }
    const reader = new SqliteStorePersistence(path);
    try {
      const loaded = await reader.loadWindow(window);
      expect(loaded).not.toBeNull();
      expect(hex(loaded!.slots.get("0:0:0")!.object)).toBe(hex(EVERY_BYTE));
      expect(hex(loaded!.finalized!.chunks.get(0)![0].fixedObjects[0])).toBe(
        hex(EVERY_BYTE),
      );
      expect(fingerprint(loaded as StoreWindowState)).toBe(fingerprint(state));
      // The quota key is not in the fingerprint; every value of it is here.
      expect(
        ordinals.map((ordinal) =>
          hex(loaded!.allocations.get(ordinal)!.admissionQuotaKey32!),
        ),
      ).toEqual(
        ordinals.map((ordinal) => hex(everyByteFrom(ordinal * 32 + 31, 32))),
      );
    } finally {
      reader.close();
    }
  });

  test("loading a stored window does not parse its hex one byte at a time", async () => {
    const path = databasePath();
    const window = 425_000_014n;
    const persistence = new SqliteStorePersistence(path);
    try {
      await persistence.saveWindow(finalizedState(window));
      // `Number.parseInt` over a two-character slice was the per-byte decoder;
      // a window document is megabytes, so that one call per byte was most of
      // what a store read cost. Counted, not timed.
      const parseInt = spyOn(Number, "parseInt");
      try {
        const loaded = await persistence.loadWindow(window);
        expect(fingerprint(loaded as StoreWindowState)).toBe(
          fingerprint(finalizedState(window)),
        );
        expect(parseInt).toHaveBeenCalledTimes(0);
      } finally {
        parseInt.mockRestore();
      }
    } finally {
      persistence.close();
    }
  });

  test("writes the stored document as lowercase hex", async () => {
    const path = databasePath();
    const persistence = new SqliteStorePersistence(path);
    try {
      await persistence.saveWindow(finalizedState(425_000_011n));
    } finally {
      persistence.close();
    }

    // The reader's own validation demands lowercase, so an encoder that emitted
    // uppercase would write rows this port could never read back.
    const document = storedDocument(path, 425_000_011n);
    for (const [field, value] of Object.entries(document.slots[0]))
      if (field !== "key") expect(value).toMatch(/^[0-9a-f]*$/);
    expect(document.finalized?.checkpoint).toMatch(/^[0-9a-f]+$/);
    expect(document.finalized?.chunks[0].chunks[0]).toMatch(/^[0-9a-f]+$/);
  });

  // `A` is the uppercase half of the alphabet the codec does accept, `g` the
  // character just past it, and `中` the case a table indexed by character code
  // cannot hold a row for at all — three different ways to reach the same
  // refusal, and the third is the one an out-of-range lookup answers `0` to.
  for (const [label, replacement] of [
    ["an uppercase hex digit", "A"],
    ["a letter past f", "g"],
    ["a character above U+00FF", "中"],
  ] as const)
    test(`refuses a stored row holding ${label}`, async () => {
      const path = databasePath();
      const window = 425_000_012n;
      const persistence = new SqliteStorePersistence(path);
      try {
        await persistence.saveWindow(finalizedState(window));
      } finally {
        persistence.close();
      }
      corruptStoredObject(
        path,
        window,
        (value) => `${replacement}${value.slice(1)}`,
      );

      const reader = new SqliteStorePersistence(path);
      try {
        await expect(reader.loadWindow(window)).rejects.toThrow(
          /stored object is not lowercase hex/,
        );
      } finally {
        reader.close();
      }
    });

  test("refuses a stored row whose hex has an odd number of characters", async () => {
    const path = databasePath();
    const persistence = new SqliteStorePersistence(path);
    try {
      await persistence.saveWindow(finalizedState(425_000_013n));
    } finally {
      persistence.close();
    }
    corruptStoredObject(path, 425_000_013n, (value) => value.slice(1));

    const reader = new SqliteStorePersistence(path);
    try {
      await expect(reader.loadWindow(425_000_013n)).rejects.toThrow(
        /stored object is not lowercase hex/,
      );
    } finally {
      reader.close();
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

  test("witness insert is a fixed set of full-key lookups whatever the window holds", async () => {
    const path = databasePath();
    const persistence = new SqliteStorePersistence(path);
    const bounds = {
      maxRecordsPerWindow: 4_096,
      quotaKey32: filled(32, 0x0b),
      maxRecordsPerQuotaKey: 4_096,
    };
    const window = 425_000_000n;
    const recordFor = (index: number): StoreWitnessRecordV1 => ({
      ...witnessOf(window, index & 0xff),
      witnessedStoreId: Uint8Array.from({ length: 32 }, (_, byte) =>
        byte === 0 ? index >> 8 : 0x91,
      ),
    });
    // Every statement one insert prepares, read off the driver itself.
    const statementsOf = async (index: number): Promise<string[]> => {
      const prepared: string[] = [];
      const query = Database.prototype.query;
      const spy = spyOn(Database.prototype, "query").mockImplementation(
        function (this: Database, sql: string) {
          prepared.push(sql);
          return query.call(this, sql);
        } as typeof Database.prototype.query,
      );
      try {
        expect(
          await persistence.addWitnessRecord(recordFor(index), bounds),
        ).toBe("added");
      } finally {
        spy.mockRestore();
      }
      return prepared;
    };
    try {
      const first = await statementsOf(0);
      for (let index = 1; index < 400; index++)
        await persistence.addWitnessRecord(recordFor(index), bounds);
      // The 401st insert into a window holding 400 runs the same statements.
      expect(await statementsOf(400)).toEqual(first);

      // And each lookup among them names its table's whole key, so none can
      // be a scan or a count over the window's rows.
      withRawDatabase(path, (raw) => {
        for (const sql of first.filter((statement) =>
          statement.startsWith("SELECT"),
        )) {
          const plan = raw
            .query<{ detail: string }, number[]>(`EXPLAIN QUERY PLAN ${sql}`)
            .all(
              ...sql
                .split("?")
                .slice(1)
                .map(() => 1),
            );
          expect(plan.length).toBeGreaterThan(0);
          for (const { detail } of plan) {
            const match = /^SEARCH (\w+) USING .*\((.+)\)$/.exec(detail);
            if (match === null)
              throw new Error(`not a keyed lookup: ${detail}`);
            const constrained = new Set(
              match[2].split(" AND ").map((term) => term.replace(/=\?$/, "")),
            );
            const key = raw
              .query<{ name: string; pk: bigint }, []>(
                `PRAGMA table_info("${match[1]}")`,
              )
              .all()
              .filter((column) => column.pk > 0n)
              .map((column) => column.name);
            const whole =
              (key.length === 1 && constrained.has("rowid")) ||
              key.every((column) => constrained.has(column));
            expect({ sql, detail, whole }).toEqual({
              sql,
              detail,
              whole: true,
            });
          }
        }
      });
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

  test("precomputed responses are kept by window and deleted with it", async () => {
    const persistence = new SqliteStorePersistence(databasePath());
    const base = 425_000_000n;
    const descriptorHash = filled(32, 0x12);
    const responsesOf = (window: bigint, fill: number) => ({
      window,
      descriptorHash,
      checkpoint: everyByteFrom(fill, 300),
      chunks: [
        { sizeClass: 0, chunkIndex: 0n, body: everyByteFrom(fill + 1, 400) },
        { sizeClass: 1, chunkIndex: 1n, body: everyByteFrom(fill + 2, 500) },
      ],
    });
    try {
      for (let offset = 0n; offset < 4n; offset++) {
        await persistence.saveWindow(finalizedState(base + offset));
        await persistence.saveFinalizedResponses(
          responsesOf(base + offset, Number(offset)),
        );
      }
      expect(hex((await persistence.loadChunkResponse(base, 1, 1n))!)).toBe(
        hex(everyByteFrom(2, 500)),
      );
      // Only what was written: no other coordinate answers.
      expect(await persistence.loadChunkResponse(base, 1, 0n)).toBeNull();
      expect(await persistence.loadChunkResponse(base + 9n, 0, 0n)).toBeNull();
      expect(
        hex((await persistence.loadCheckpointResponse(base, descriptorHash))!),
      ).toBe(hex(everyByteFrom(0, 300)));
      expect(
        await persistence.loadCheckpointResponse(base, filled(32, 0x13)),
      ).toBeNull();

      // A second write for one window replaces the first, as a re-finalized
      // window that never committed its state row must.
      await persistence.saveFinalizedResponses(responsesOf(base, 77));
      expect(hex((await persistence.loadChunkResponse(base, 0, 0n))!)).toBe(
        hex(everyByteFrom(78, 400)),
      );

      expect(await persistence.deleteWindowsBefore(base + 2n, 16)).toBe(2);
      const kept: string[] = [];
      for (let offset = 0n; offset < 4n; offset++)
        kept.push(
          [
            (await persistence.loadWindow(base + offset)) === null ? "-" : "w",
            (await persistence.loadChunkResponse(base + offset, 0, 0n)) === null
              ? "-"
              : "c",
            (await persistence.loadCheckpointResponse(
              base + offset,
              descriptorHash,
            )) === null
              ? "-"
              : "k",
          ].join(""),
        );
      expect(kept).toEqual(["---", "---", "wck", "wck"]);
    } finally {
      persistence.close();
    }
  });

  test("a schema-1 database gains the response tables and keeps its windows and witness rows", async () => {
    const path = databasePath();
    const window = 425_000_000n;
    const bounds = {
      maxRecordsPerWindow: 2,
      quotaKey32: filled(32, 9),
      maxRecordsPerQuotaKey: 2,
    };
    const seeded = new SqliteStorePersistence(path);
    try {
      await seeded.saveWindow(finalizedState(window));
      expect(await seeded.addWitnessRecord(witnessOf(window, 1), bounds)).toBe(
        "added",
      );
    } finally {
      seeded.close();
    }
    // What the previous schema left: no response tables, version 1.
    withRawDatabase(path, (db) => {
      db.exec(
        "DROP TABLE chunk_response; DROP TABLE checkpoint_response; PRAGMA user_version = 1",
      );
    });

    const reopened = new SqliteStorePersistence(path);
    try {
      expect(fingerprint((await reopened.loadWindow(window))!)).toBe(
        fingerprint(finalizedState(window)),
      );
      expect(await reopened.loadChunkResponse(window, 0, 0n)).toBeNull();
      // Its witness rows had counts, so they are kept and still bound.
      expect(await reopened.loadWitnessRecords(window)).toHaveLength(1);
      expect(
        await reopened.addWitnessRecord(witnessOf(window, 2), bounds),
      ).toBe("added");
      expect(
        await reopened.addWitnessRecord(witnessOf(window, 3), bounds),
      ).toBe("window-full");
    } finally {
      reopened.close();
    }
    expect(
      withRawDatabase(path, (db) =>
        Number(
          db.query<{ user_version: bigint }, []>("PRAGMA user_version").get()
            ?.user_version,
        ),
      ),
    ).toBe(2);
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
