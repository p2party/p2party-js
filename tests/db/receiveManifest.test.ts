import { describe, expect, test } from "bun:test";

import {
  advanceReceiveManifest,
  buildReceiveManifest,
  EMPTY_RECEIVE_MANIFEST,
  isCurrentReceiveManifest,
  ReceiveChunkRejectedError,
  receiveProgress,
  type ReceiveManifest,
} from "../../src/db/receiveManifest";

// Deterministic PRNG so a failure reproduces.
const prng = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

type Outcome =
  { ok: true; savedSize: number; complete: boolean } | { ok: false };

const attempt = (fn: () => ReceiveManifest, totalSize: number) => {
  try {
    const manifest = fn();
    return {
      outcome: { ok: true, ...receiveProgress(manifest, totalSize) } as Outcome,
      manifest,
    };
  } catch (error) {
    expect(error).toBeInstanceOf(ReceiveChunkRejectedError);
    return { outcome: { ok: false } as Outcome, manifest: undefined };
  }
};

describe("incremental receive manifest", () => {
  test("agrees with full validation of every held chunk on every insert", () => {
    const random = prng(0xa5);
    let accepted = 0;
    let rejected = 0;
    let completed = 0;
    for (let run = 0; run < 4_000; run++) {
      const totalSize = 1 + Math.floor(random() * 40);
      const uniform = 1 + Math.floor(random() * totalSize);
      const count = Math.ceil(totalSize / uniform);
      const held: Array<{ chunkIndex: number; realLen: number }> = [];
      let manifest: ReceiveManifest = { ...EMPTY_RECEIVE_MANIFEST };
      for (let step = 0; step < 12; step++) {
        // Mostly canonical chunks, sometimes a wrong length or index.
        const chunkIndex =
          random() < 0.85
            ? Math.floor(random() * count)
            : Math.floor(random() * totalSize);
        const canonical =
          chunkIndex === count - 1
            ? totalSize - uniform * (count - 1)
            : uniform;
        const realLen =
          random() < 0.85 ? canonical : 1 + Math.floor(random() * totalSize);
        if (held.some((record) => record.chunkIndex === chunkIndex)) continue;

        const candidate = { chunkIndex, realLen };
        const full = attempt(
          () => buildReceiveManifest([...held, candidate], totalSize),
          totalSize,
        );
        const incremental = attempt(
          () =>
            advanceReceiveManifest(manifest, totalSize, chunkIndex, realLen),
          totalSize,
        );
        expect(incremental.outcome).toEqual(full.outcome);
        if (!incremental.manifest) {
          rejected += 1;
          continue;
        }
        // The running summary equals the one rebuilt from the records, and
        // reads back as current from a row carrying its savedSize.
        expect(incremental.manifest).toEqual(full.manifest!);
        expect(
          isCurrentReceiveManifest(
            incremental.manifest,
            incremental.manifest.savedSize,
            totalSize,
          ),
        ).toBe(true);
        manifest = incremental.manifest;
        held.push(candidate);
        accepted += 1;
        if (full.outcome.ok && full.outcome.complete) completed += 1;
      }
    }
    // The generator exercises every branch, not just one of them.
    expect(accepted).toBeGreaterThan(10_000);
    expect(rejected).toBeGreaterThan(1_000);
    expect(completed).toBeGreaterThan(500);
  });

  test("a chunk that cannot be placed in the layout is refused", () => {
    const zero = advanceReceiveManifest(EMPTY_RECEIVE_MANIFEST, 10, 0, 5);
    expect(() => advanceReceiveManifest(zero, 10, 2, 5)).toThrow(
      "receive chunk index exceeds canonical manifest",
    );
    expect(() => advanceReceiveManifest(zero, 10, 1, 4)).toThrow(
      "receive chunk length conflicts with manifest",
    );
    // A lone non-zero chunk carrying every byte cannot be the whole message.
    expect(() =>
      advanceReceiveManifest(EMPTY_RECEIVE_MANIFEST, 10, 1, 10),
    ).toThrow("receive completion is missing chunk zero");
  });

  test("only a well-formed manifest in step with its row is trusted", () => {
    const manifest = advanceReceiveManifest(
      advanceReceiveManifest(EMPTY_RECEIVE_MANIFEST, 15, 0, 5),
      15,
      1,
      5,
    );
    expect(isCurrentReceiveManifest(manifest, 10, 15)).toBe(true);
    // 0.14.10 rows carry no manifest.
    expect(isCurrentReceiveManifest(undefined, 10, 15)).toBe(false);
    // The row moved on without it.
    expect(isCurrentReceiveManifest(manifest, 15, 15)).toBe(false);
    for (const broken of [
      { ...manifest, version: 2 },
      { ...manifest, count: -1 },
      { ...manifest, count: 4 },
      { ...manifest, count: 3 },
      { ...manifest, uniformSize: 16 },
      { ...manifest, uniformSize: 1.5 },
      { ...manifest, pendingIndex: 2, pendingRealLen: 5 },
      { version: 1, count: 1, savedSize: 10, uniformSize: 0 },
      {
        version: 1,
        count: 1,
        savedSize: 10,
        uniformSize: 0,
        pendingIndex: 0,
        pendingRealLen: 10,
      },
    ])
      expect(isCurrentReceiveManifest(broken, 10, 15)).toBe(false);
    const pending = advanceReceiveManifest(EMPTY_RECEIVE_MANIFEST, 15, 2, 5);
    expect(isCurrentReceiveManifest(pending, 5, 15)).toBe(true);
  });
});
