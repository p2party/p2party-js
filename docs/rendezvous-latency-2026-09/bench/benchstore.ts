/// <reference types="bun" />
// Measures SqliteStorePersistence.saveWindow / loadWindow on a window built to
// the pinned profile geometry (cohort 8, 2 clients' worth of occupied slots).
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";
import { PROTOTYPE_DELIVERY_PROFILE_V0 as P } from "../../../src/blindRendezvous/prototype/profile";

import type {
  StoreWindowState,
  StoreAllocationRecord,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";
import type {
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../../src/blindRendezvous/publicWindow";

const rnd = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out.subarray(0, Math.min(n, 65536)));
  for (let i = 65536; i < n; i += 65536)
    out.copyWithin(i, 0, Math.min(65536, n - i));
  return out;
};

const W = 425_000_000n;
const PROFILE_HASH = rnd(32);

const alloc = (ordinal: number): StoreAllocationRecord => {
  const leaseBody = {
    version: 1 as const,
    storeId: rnd(32),
    deliveryProfileHash: PROFILE_HASH,
    ingressWindow: W,
    requestHash: rnd(32),
    allocationOrdinal: ordinal,
    allocationEd25519PublicKey: rnd(32),
  };
  return {
    leaseBody,
    lease: { ...leaseBody, storeSignature: rnd(64) },
    requestHash: rnd(32),
  };
};

const chunk = (
  sizeClass: number,
  index: bigint,
  objectBytes: number,
): PublicChunkV1 => ({
  version: 1,
  bucket: { deliveryProfileHash: PROFILE_HASH, ingressWindow: W, sizeClass },
  chunkIndex: index,
  previousChunkHash: rnd(32),
  fixedObjects: Array.from({ length: P.publicChunkObjectCount }, () =>
    rnd(objectBytes),
  ),
  storeSignature: rnd(64),
});

const checkpoint: PublicStoreCheckpointV1 = {
  version: 1,
  storeId: rnd(32),
  descriptorHash: rnd(32),
  deliveryProfileHash: PROFILE_HASH,
  ingressWindow: W,
  chainStartIngressWindow: W - 10n,
  previousCheckpointHash: rnd(32),
  finalizedChunkCount: 5,
  finalizedChunkRoot: rnd(32),
  storeSignature: rnd(64),
};

// Two clients hold ordinals 0 and 1; each fills every append slot in both classes.
const slots = new Map<string, { objectHash: Uint8Array; object: Uint8Array }>();
let scanned = 0;
for (const sc of P.sizeClasses) {
  const perChunk = P.publicChunkObjectCount;
  for (let ordinal = 0; ordinal < 2; ordinal++)
    for (let s = 0; s < sc.appendSchedule.length; s++) {
      const objectIndex = ordinal * sc.appendSchedule.length + s;
      const key = `${sc.id}:${Math.floor(objectIndex / perChunk)}:${objectIndex % perChunk}`;
      slots.set(key, {
        objectHash: rnd(32),
        object: rnd(sc.fixedCarrierObjectBytes),
      });
    }
  scanned += sc.publicChunksPerWindow * perChunk * sc.fixedCarrierObjectBytes;
}

const state: StoreWindowState = {
  window: W,
  allocations: new Map(
    Array.from({ length: P.cohortAllocationsPerWindow }, (_, i) => [
      i,
      alloc(i),
    ]),
  ),
  slots,
  finalized: {
    checkpoint,
    chunks: new Map(
      P.sizeClasses.map((sc) => [
        sc.id,
        Array.from({ length: sc.publicChunksPerWindow }, (_, i) =>
          chunk(sc.id, BigInt(i), sc.fixedCarrierObjectBytes),
        ),
      ]),
    ),
  },
};

console.log(
  `geometry: ${String(slots.size)} occupied slots, ${String(scanned)} bytes of fixedObjects across 5 chunks`,
);

const root = mkdtempSync(join(tmpdir(), "p2party-benchstore-"));
const path = join(root, "bench.sqlite");
const p = new SqliteStorePersistence(path);

const N = Number(Bun.argv[2] ?? 12);
const times = (label: string, fn: () => Promise<unknown>) =>
  (async () => {
    const samples: number[] = [];
    for (let i = 0; i < N; i++) {
      const t0 = performance.now();
      await fn();
      samples.push(performance.now() - t0);
    }
    samples.sort((a, b) => a - b);
    const f = (x: number) => x.toFixed(2);
    console.log(
      `${label.padEnd(14)} n=${String(N)}  min ${f(samples[0])}  p50 ${f(samples[Math.floor(N / 2)])}  max ${f(samples[N - 1])} ms`,
    );
  })();

// The precomputed rows, sized the way the core writes them: one encoded
// response per finalized chunk plus one for the checkpoint.
const responses = {
  window: W,
  descriptorHash: rnd(32),
  checkpoint: rnd(500),
  chunks: [...state.finalized!.chunks].flatMap(([sizeClass, chunks]) =>
    chunks.map((chunk, index) => ({
      sizeClass,
      chunkIndex: BigInt(index),
      body: rnd(chunk.fixedObjects.reduce((sum, o) => sum + o.length, 0) + 200),
    })),
  ),
};

await times("saveWindow", () => p.saveWindow(state));
await times("loadWindow", () => p.loadWindow(W));
await times("saveResponses", () => p.saveFinalizedResponses(responses));
await times("loadChunkRow", () => p.loadChunkResponse(W, 1, 0n));
await times("loadCkptRow", () =>
  p.loadCheckpointResponse(W, responses.descriptorHash),
);
p.close();
{
  const { Database } = await import("bun:sqlite");
  const db = new Database(path, { readonly: true });
  const one = (sql: string): number =>
    Number((db.query<{ n: number }, []>(sql).get() as { n: number }).n);
  console.log(
    `disk per window: window row ${String(one('SELECT SUM(LENGTH(state)) AS n FROM "window"'))} B` +
      `, chunk_response ${String(one("SELECT SUM(LENGTH(body)) AS n FROM chunk_response"))} B` +
      `, checkpoint_response ${String(one("SELECT SUM(LENGTH(body)) AS n FROM checkpoint_response"))} B`,
  );
  db.close();
}
console.log(`whole db file: ${String(statSync(path).size)} bytes`);
rmSync(root, { recursive: true, force: true });
