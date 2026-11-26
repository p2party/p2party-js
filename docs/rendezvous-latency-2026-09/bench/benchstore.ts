/// <reference types="bun" />
// Measures SqliteStorePersistence.saveWindow / loadWindow on a window built to
// the pinned profile geometry (cohort 8, 2 clients' worth of occupied slots).
//
// `--readers=N [--windows=K]` (added 2026-11-26) measures instead what whole
// windows cost the store itself: a real core over this SQLite port behind its
// HTTP handler, called in this process with no socket. Per window, a full
// cohort of 8 clients allocates and fills all 40 slots, the finalizer signs
// the window, and N readers each read its checkpoint and every chunk. Process
// CPU (user + system) is summed around the store's calls only; the client
// work (keys, admissions, decoding answers) happens outside them. It uses only
// calls that exist at 41e8943 too, so the same file measures before and after.
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { loadavg, tmpdir } from "node:os";
import { join } from "node:path";

import { newKeyPair } from "../../../src/cryptography/ed25519";
import { loadTestModule } from "../../../src/cryptography/testModule";
import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import { ingressWindowStartMs } from "../../../src/blindRendezvous/publicWindow";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0 as P,
  carrierObjectWireBytes,
} from "../../../src/blindRendezvous/prototype/profile";
import { buildAppendAdmission } from "../../../src/blindRendezvous/prototype/storeClient";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../../../src/blindRendezvous/prototype/storeRoutes";
import {
  decodePublicAllocationResultV1,
  encodePublicAllocationRequestV1,
  encodePublicAppendRequestV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type {
  StoreWindowState,
  StoreAllocationRecord,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";
import type {
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../../src/blindRendezvous/publicWindow";

const flag = (name: string): string | undefined =>
  Bun.argv
    .find((value) => value.startsWith(`--${name}=`))
    ?.slice(name.length + 3);

const readersFlag = flag("readers");
if (readersFlag !== undefined) {
  const readers = Number(readersFlag);
  const windows = Number(flag("windows") ?? 5);
  const module = await loadTestModule();
  const profileHash = await deliveryProfileHash(P);
  const profileHex = [...profileHash]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const root = mkdtempSync(join(tmpdir(), "p2party-benchwindow-"));
  const persistence = new SqliteStorePersistence(join(root, "store.sqlite"));
  const chainStart = 450_000_000n;
  let now = ingressWindowStartMs(chainStart, P.deliveryWindowMs);
  const core = await PrototypeStoreCore.create({
    module,
    seed: new Uint8Array(32).fill(0x42),
    profile: P,
    clock: { nowMs: () => now },
    persistence,
    chainStartIngressWindow: chainStart,
    origin: "http://127.0.0.1:5910",
    descriptorValidityMs: 2_592_000_000n,
  });
  const handler = createPrototypeStoreHandler({ core });
  const randomObject = (length: number): Uint8Array => {
    const out = new Uint8Array(length);
    for (let offset = 0; offset < length; offset += 65_536)
      crypto.getRandomValues(
        out.subarray(offset, Math.min(offset + 65_536, length)),
      );
    return out;
  };
  const cpuMs = (): number => {
    const usage = process.cpuUsage();
    return (usage.user + usage.system) / 1000;
  };
  // The store's own time: CPU and wall, summed over the calls made through it.
  const spent = { cpu: 0, wall: 0 };
  const store = async <T>(call: () => Promise<T>): Promise<T> => {
    const cpu = cpuMs();
    const wall = performance.now();
    try {
      return await call();
    } finally {
      spent.cpu += cpuMs() - cpu;
      spent.wall += performance.now() - wall;
    }
  };
  const request = (path: string, init?: RequestInit): Promise<Response> =>
    store(() => handler(new Request(`http://127.0.0.1:5910${path}`, init)));
  const body = (bytes: Uint8Array): ArrayBuffer => {
    const buffer = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buffer).set(bytes);
    return buffer;
  };
  const rows: {
    window: bigint;
    allocate: number;
    append: number;
    finalize: number;
    read: number;
    wall: number;
  }[] = [];
  console.log(
    `readers mode: ${String(readers)} readers, ${String(windows)} windows, load averages ${loadavg()
      .map((value) => value.toFixed(2))
      .join(" ")}`,
  );
  for (let index = 0; index < windows; index++) {
    const window = chainStart + BigInt(index);
    now = ingressWindowStartMs(window, P.deliveryWindowMs);
    const phase = (): number => {
      const value = spent.cpu;
      spent.cpu = 0;
      return value;
    };
    spent.wall = 0;
    // A full cohort: eight allocations, then every slot appended.
    const clients = await Promise.all(
      Array.from({ length: P.cohortAllocationsPerWindow }, () =>
        newKeyPair(module),
      ),
    );
    const leases = [];
    for (const keyPair of clients) {
      const answer = await request(PROTOTYPE_STORE_ROUTES.allocation, {
        method: "POST",
        headers: {
          "content-type": PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
        },
        body: body(
          encodePublicAllocationRequestV1({
            version: 1,
            deliveryProfileHash: profileHash,
            ingressWindow: window,
            allocationEd25519PublicKey: keyPair.publicKey,
            privacyPassToken: new Uint8Array(32),
          }),
        ),
      });
      const result = decodePublicAllocationResultV1(
        new Uint8Array(await answer.arrayBuffer()),
      );
      if (result.kind !== "allocated") throw new Error("no lease");
      leases.push({ lease: result.lease, secretKey: keyPair.secretKey });
    }
    const allocate = phase();
    const appends: ArrayBuffer[] = [];
    for (const { lease, secretKey } of leases)
      for (const sizeClass of P.sizeClasses)
        for (
          let ordinal = 0;
          ordinal < sizeClass.appendSchedule.length;
          ordinal++
        ) {
          const object = randomObject(
            carrierObjectWireBytes(P, sizeClass.id, profileHash),
          );
          appends.push(
            body(
              encodePublicAppendRequestV1({
                version: 1,
                bucket: {
                  deliveryProfileHash: profileHash,
                  ingressWindow: window,
                  sizeClass: sizeClass.id,
                },
                exactFixedObject: object,
                admission: await buildAppendAdmission(
                  lease,
                  secretKey,
                  sizeClass.id,
                  ordinal,
                  object,
                  module,
                ),
              }),
            ),
          );
        }
    now += P.allocationRequestOffsetMs;
    for (const append of appends) {
      const answer = await request(PROTOTYPE_STORE_ROUTES.append, {
        method: "POST",
        headers: { "content-type": PROTOTYPE_STORE_MEDIA_TYPES.appendRequest },
        body: append,
      });
      if (answer.status !== 200)
        throw new Error(`append ${String(answer.status)}`);
    }
    const append = phase();
    now =
      ingressWindowStartMs(window, P.deliveryWindowMs) +
      P.chunkFinalizationOffsetMs;
    await store(() => core.finalizeDue());
    const finalize = phase();
    now =
      ingressWindowStartMs(window + 1n, P.deliveryWindowMs) +
      P.publicReadOffsetMs;
    for (let reader = 0; reader < readers; reader++) {
      const paths = [
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${profileHex}/${String(window)}`,
        ...P.sizeClasses.flatMap((sizeClass) =>
          Array.from(
            { length: sizeClass.publicChunksPerWindow },
            (_, chunk) =>
              `${PROTOTYPE_STORE_ROUTES.chunk}/${profileHex}/${String(window)}/${String(sizeClass.id)}/${String(chunk)}`,
          ),
        ),
      ];
      for (const path of paths) {
        const answer = await request(path);
        if (answer.headers.get("cache-control")?.includes("immutable") !== true)
          throw new Error(`${path} was not a finalized read`);
      }
    }
    const read = phase();
    rows.push({ window, allocate, append, finalize, read, wall: spent.wall });
    console.log(
      `window ${String(index)}: store CPU ms allocate ${allocate.toFixed(1)}  append ${append.toFixed(1)}  finalize ${finalize.toFixed(1)}  read (${String(readers)} readers) ${read.toFixed(1)}  total ${(allocate + append + finalize + read).toFixed(1)}  (wall ${spent.wall.toFixed(1)})`,
    );
  }
  // The chain-start window loads no predecessor at finalization; the median
  // is over the windows after it.
  const median = (values: number[]): number => {
    const sorted = [...values].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
  };
  const later = rows.slice(1);
  const fields = ["allocate", "append", "finalize", "read"] as const;
  console.log(
    `median over windows 1..${String(windows - 1)}: ${fields
      .map(
        (field) =>
          `${field} ${median(later.map((row) => row[field])).toFixed(1)}`,
      )
      .join("  ")}  total ${median(
      later.map((row) => row.allocate + row.append + row.finalize + row.read),
    ).toFixed(1)} ms CPU per window`,
  );
  persistence.close();
  rmSync(root, { recursive: true, force: true });
  process.exit(0);
}

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
