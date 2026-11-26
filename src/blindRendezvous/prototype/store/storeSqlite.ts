/// <reference types="bun" />
/**
 * The durable half of the prototype store: `StorePersistencePort` over one
 * SQLite file (`bun:sqlite`, no new dependency).
 *
 * Windows store geometry — an ingress window, a size class, an ordinal — and
 * opaque object bytes, without a room identifier. Allocation records contain
 * public allocation keys and request hashes, and optional
 * experimental admission records additionally contain grant quota keys that
 * link that grant's allocations. These are private store metadata beyond the
 * finalized public chunks; the database does not establish participant anonymity.
 *
 * Two properties this file must not break:
 *
 * - **A finalized window is never lost.** Re-signing one window is a permanent
 *   fault proof against the store, and `lastFinalizedWindow()` is the only
 *   thing that stops `finalizeDue` from starting over. Hence `synchronous =
 *   FULL`: WAL's usual `NORMAL` can drop the last commits on power loss, and
 *   here that loss is not "a little data", it is the store equivocating.
 * - **No row aliases a caller's buffer.** Values cross this boundary as
 *   canonical bytes and are re-decoded on the way out, so the core's mutable
 *   working state and the stored state are never the same objects.
 *
 * `bun:sqlite` is imported here and nowhere else in the prototype, so nothing
 * a browser bundle can reach ever pulls a server-only module in.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry.
 */

import { Database } from "bun:sqlite";

import { decodeCanonicalStrict, encodeCanonical } from "../../canonicalSchema";
import {
  publicChunkV1Schema,
  publicStoreCheckpointV1Schema,
} from "../../schemas";
import {
  decodePublicAllocationLeaseBodyV1,
  decodePublicAllocationLeaseV1,
  decodeStoreWitnessRecordV1,
  encodePublicAllocationLeaseBodyV1,
  encodePublicAllocationLeaseV1,
  encodeStoreWitnessRecordV1,
} from "../storeWire";

import type { StoreWitnessRecordV1 } from "../storeWire";
import type {
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../publicWindow";
import type {
  StorePersistencePort,
  StoreWindowState,
} from "./storePersistence";

export class StorePersistenceError extends Error {
  override readonly name = "StorePersistenceError";

  constructor(message: string) {
    super(`storeSqlite: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new StorePersistenceError(message);
};

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesFrom = (value: string, field: string): Uint8Array => {
  if (!/^(?:[0-9a-f]{2})*$/.test(value))
    fail(`stored ${field} is not lowercase hex`);
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++)
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return output;
};

/**
 * The JSON shape of the `state` blob.
 *
 * Every byte field is hex, and every structured field is the *canonical*
 * encoding of the value rather than a JSON transcription of its fields. That
 * is deliberate: a chunk and a checkpoint are objects the store has signed, so
 * round-tripping them through the same encoder the signature was computed over
 * is what guarantees a restarted store serves the identical bytes. A
 * hand-written field-by-field JSON form would silently drop any wire field
 * added later.
 */
interface StoredAllocationV1 {
  ordinal: number;
  leaseBody: string;
  lease: string;
  requestHash: string;
  admissionQuotaKey32?: string;
}

const quotaKeyFrom = (value: unknown): Uint8Array => {
  if (typeof value !== "string" || value.length !== 64)
    fail(
      "stored admission quota key must be exactly 32 bytes of lowercase hex",
    );
  return bytesFrom(value as string, "admission quota key");
};

const quotaKeyHex = (value: Uint8Array): string => {
  if (!(value instanceof Uint8Array) || value.length !== 32)
    fail("admission quota key must be exactly 32 bytes");
  return hexOf(value);
};

interface StoredSlotV1 {
  key: string;
  objectHash: string;
  object: string;
}

interface StoredChunkGroupV1 {
  sizeClass: number;
  chunks: string[];
}

interface StoredWindowDocumentV1 {
  version: 1;
  window: string;
  allocations: StoredAllocationV1[];
  slots: StoredSlotV1[];
  finalized: {
    checkpoint: string;
    chunks: StoredChunkGroupV1[];
  } | null;
}

const encodeChunk = (chunk: PublicChunkV1): string =>
  hexOf(encodeCanonical(publicChunkV1Schema, chunk));

const decodeChunk = (value: string): PublicChunkV1 =>
  decodeCanonicalStrict(
    publicChunkV1Schema,
    bytesFrom(value, "chunk"),
  ) as PublicChunkV1;

const encodeCheckpoint = (checkpoint: PublicStoreCheckpointV1): string =>
  hexOf(encodeCanonical(publicStoreCheckpointV1Schema, checkpoint));

const decodeCheckpoint = (value: string): PublicStoreCheckpointV1 =>
  decodeCanonicalStrict(
    publicStoreCheckpointV1Schema,
    bytesFrom(value, "checkpoint"),
  ) as PublicStoreCheckpointV1;

const toDocument = (state: StoreWindowState): StoredWindowDocumentV1 => ({
  version: 1,
  window: String(state.window),
  allocations: [...state.allocations].map(([ordinal, record]) => ({
    ordinal,
    leaseBody: hexOf(encodePublicAllocationLeaseBodyV1(record.leaseBody)),
    lease: hexOf(encodePublicAllocationLeaseV1(record.lease)),
    requestHash: hexOf(record.requestHash),
    ...(record.admissionQuotaKey32 === undefined
      ? {}
      : { admissionQuotaKey32: quotaKeyHex(record.admissionQuotaKey32) }),
  })),
  slots: [...state.slots].map(([key, slot]) => ({
    key,
    objectHash: hexOf(slot.objectHash),
    object: hexOf(slot.object),
  })),
  finalized:
    state.finalized === null
      ? null
      : {
          checkpoint: encodeCheckpoint(state.finalized.checkpoint),
          chunks: [...state.finalized.chunks].map(([sizeClass, chunks]) => ({
            sizeClass,
            chunks: chunks.map(encodeChunk),
          })),
        },
});

const fromDocument = (document: StoredWindowDocumentV1): StoreWindowState => {
  if (document.version !== 1)
    fail("unsupported stored window document version");
  return {
    window: BigInt(document.window),
    allocations: new Map(
      document.allocations.map((record) => [
        record.ordinal,
        {
          leaseBody: decodePublicAllocationLeaseBodyV1(
            bytesFrom(record.leaseBody, "lease body"),
          ),
          lease: decodePublicAllocationLeaseV1(
            bytesFrom(record.lease, "lease"),
          ),
          requestHash: bytesFrom(record.requestHash, "request hash"),
          ...(record.admissionQuotaKey32 === undefined
            ? {}
            : {
                admissionQuotaKey32: quotaKeyFrom(record.admissionQuotaKey32),
              }),
        },
      ]),
    ),
    slots: new Map(
      document.slots.map((slot) => [
        slot.key,
        {
          objectHash: bytesFrom(slot.objectHash, "object hash"),
          object: bytesFrom(slot.object, "object"),
        },
      ]),
    ),
    finalized:
      document.finalized === null
        ? null
        : {
            checkpoint: decodeCheckpoint(document.finalized.checkpoint),
            chunks: new Map(
              document.finalized.chunks.map((group) => [
                group.sizeClass,
                group.chunks.map(decodeChunk),
              ]),
            ),
          },
  };
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Tables, and why they are shaped this way.
 *
 * `window` is the unit the specification makes atomic — ordinals, slot
 * bindings, and the finalization that freezes both — so the whole window is
 * one row and one statement. `finalized` is a column rather than a field
 * inside the blob because `lastFinalizedWindow()` runs on every `finalizeDue`
 * tick and must not have to parse every window's multi-megabyte state to
 * answer `MAX(window)`.
 *
 * `witness` makes the canonical record bytes half of the primary key, so
 * "idempotent on identical canonical bytes" is enforced by the database
 * rather than by a read-then-write the store would have to get right.
 *
 * `meta` holds `chainStartIngressWindow`. The descriptor's validity interval
 * is anchored to the chain start so a restart re-derives byte-identical
 * descriptor bytes; if the chain start were re-chosen at each boot, every
 * checkpoint already signed would name a `descriptorHash` the running store no
 * longer serves, and a client would mark the store inert.
 *
 * `window` is a SQLite keyword (window functions), so it is quoted everywhere.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS "window" (
  "window" INTEGER PRIMARY KEY,
  finalized INTEGER NOT NULL,
  state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS witness (
  "window" INTEGER NOT NULL,
  record BLOB NOT NULL,
  PRIMARY KEY ("window", record)
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

export class SqliteStorePersistence implements StorePersistencePort {
  readonly #db: Database;

  constructor(path: string) {
    // `safeIntegers` is not a preference: an ingress window is a u64, and the
    // driver's default truncates integers to 52 bits. A silently shortened
    // window would make the store finalize the wrong one.
    this.#db = new Database(path, {
      create: true,
      readwrite: true,
      safeIntegers: true,
    });
    // WAL keeps a reader (a chunk GET) from blocking the finalizer's writes.
    this.#db.exec("PRAGMA journal_mode = WAL");
    // See the file header: losing a committed finalization is the store
    // equivocating, not merely losing data, so this stays FULL.
    this.#db.exec("PRAGMA synchronous = FULL");
    this.#db.exec(SCHEMA);
  }

  close(): void {
    this.#db.close();
  }

  /* ---------------------------------------------------------------- *
   * Windows
   * ---------------------------------------------------------------- */

  async loadWindow(window: bigint): Promise<StoreWindowState | null> {
    const row = this.#db
      .query<{ state: Uint8Array }, [bigint]>(
        'SELECT state FROM "window" WHERE "window" = ?',
      )
      .get(window);
    if (row === null) return null;
    return fromDocument(
      JSON.parse(textDecoder.decode(row.state)) as StoredWindowDocumentV1,
    );
  }

  async saveWindow(state: StoreWindowState): Promise<void> {
    const blob = textEncoder.encode(JSON.stringify(toDocument(state)));
    this.#db
      .query<unknown, [bigint, bigint, Uint8Array]>(
        'INSERT INTO "window" ("window", finalized, state) VALUES (?, ?, ?)' +
          ' ON CONFLICT("window") DO UPDATE SET finalized = excluded.finalized,' +
          " state = excluded.state",
      )
      .run(state.window, state.finalized === null ? 0n : 1n, blob);
  }

  async lastFinalizedWindow(): Promise<bigint | null> {
    return (
      this.#db
        .query<{ latest: bigint | null }, []>(
          'SELECT MAX("window") AS latest FROM "window" WHERE finalized = 1',
        )
        .get()?.latest ?? null
    );
  }

  /* ---------------------------------------------------------------- *
   * Witness records
   * ---------------------------------------------------------------- */

  async loadWitnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]> {
    // `rowid` order is arrival order, and the canonical array is a sequence
    // rather than a sorted set: reordering it would erase when each
    // observation was made.
    return this.#db
      .query<{ record: Uint8Array }, [bigint]>(
        'SELECT record FROM witness WHERE "window" = ? ORDER BY rowid',
      )
      .all(window)
      .map((row) => decodeStoreWitnessRecordV1(row.record));
  }

  async saveWitnessRecord(record: StoreWitnessRecordV1): Promise<void> {
    this.#db
      .query<unknown, [bigint, Uint8Array]>(
        'INSERT OR IGNORE INTO witness ("window", record) VALUES (?, ?)',
      )
      .run(record.ingressWindow, encodeStoreWitnessRecordV1(record));
  }

  /* ---------------------------------------------------------------- *
   * Meta
   *
   * Synchronous because the entrypoint reads and writes these before the
   * store exists, and an async read there would only add a await to a
   * single-row lookup on a file this process has exclusive use of.
   * ---------------------------------------------------------------- */

  loadMeta(key: string): string | null {
    return (
      this.#db
        .query<{ value: string }, [string]>(
          "SELECT value FROM meta WHERE key = ?",
        )
        .get(key)?.value ?? null
    );
  }

  saveMeta(key: string, value: string): void {
    this.#db
      .query<unknown, [string, string]>(
        "INSERT INTO meta (key, value) VALUES (?, ?)" +
          " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      )
      .run(key, value);
  }
}
