/// <reference types="bun" />
/**
 * Harness-only cohort override for the pinned prototype delivery profile.
 *
 * `run.mjs --cohort=<n>` measures how the fixed per-window scan trades against
 * the window length. `cohortAllocationsPerWindow` is a field of the *pinned*
 * profile (`src/blindRendezvous/prototype/profile.ts`), which is deliberately
 * frozen and has no runtime override: the client's
 * `runBlindRendezvousPrototype` accepts `deliveryWindowMs` and nothing else,
 * and the store reads `P2PARTY_STORE_WINDOW_MS` and nothing else. Both sides
 * must agree, because `DeliveryProfileHash` covers the whole geometry and a
 * store serving another hash serves another bucket.
 *
 * Rather than change either of those files — this is a measurement harness,
 * not a feature — the override is applied where the harness already controls
 * the toolchain: a Bun loader plugin that rewrites `profile.ts` as it is read.
 * The same `patchProfileSource` serves the store process (as `bun --preload`)
 * and the browser bundle (as a `Bun.build` plugin, see `profileTool.ts`), so
 * the two sides cannot drift.
 *
 * The rewrite does not guess the derived numbers. It keeps the pinned literal
 * under a private name and re-derives `publicChunksPerWindow` per size class
 * from the specification's own inequality —
 * `ceil(cohortAllocationsPerWindow * roomSlotsPerClient *
 * appendSchedule.length / publicChunkObjectCount)`, the minimum satisfying
 * `scheduledObjects <= chunkCapacity` — and every consumer then runs
 * `validateDeliveryProfileGeometry` over the result, which rejects an
 * inconsistent profile rather than carrying it into a run.
 *
 * Status: HARNESS. Nothing here is imported by `src/`.
 */

import { plugin } from "bun";
import { readFileSync } from "node:fs";

import type { BunPlugin } from "bun";

/** Set by `run.mjs` on the store process and on the bundle build. */
export const COHORT_ENV = "P2PARTY_BLIND_COHORT";

/** The one declaration in `profile.ts` this rewrite renames. */
const PROFILE_ANCHOR =
  "export const PROTOTYPE_DELIVERY_PROFILE_V0: DeliveryProfileV1 = Object.freeze({";

const BASE_NAME = "HARNESS_PINNED_PROFILE";

/** Matches only `src/blindRendezvous/prototype/profile.ts`. */
export const PROFILE_MODULE_FILTER =
  /blindRendezvous[/\\]prototype[/\\]profile\.ts$/;

/**
 * Rewrite `profile.ts` so its exported profile carries `cohort` allocations
 * per window and the size-class chunk counts that geometry implies.
 *
 * Throws when the anchor is not present exactly once: a silently unpatched
 * profile would make the store and the page derive different bucket hashes and
 * the run would fail far from the cause.
 */
export const patchProfileSource = (source: string, cohort: number): string => {
  if (!Number.isSafeInteger(cohort) || cohort < 1)
    throw new Error(
      `cohortPreload: ${COHORT_ENV} must be a positive integer, got ${String(cohort)}`,
    );
  const occurrences = source.split(PROFILE_ANCHOR).length - 1;
  if (occurrences !== 1)
    throw new Error(
      `cohortPreload: expected exactly one pinned-profile declaration in profile.ts, found ${String(occurrences)}`,
    );

  const literal = String(cohort);
  return `${source.replace(
    PROFILE_ANCHOR,
    `const ${BASE_NAME}: DeliveryProfileV1 = Object.freeze({`,
  )}

/* Injected by docs/e2e/blind-two-store/cohortPreload.ts (harness only). */
export const PROTOTYPE_DELIVERY_PROFILE_V0: DeliveryProfileV1 = Object.freeze({
  ...${BASE_NAME},
  cohortAllocationsPerWindow: ${literal},
  sizeClasses: ${BASE_NAME}.sizeClasses.map((sizeClass) => ({
    ...sizeClass,
    publicChunksPerWindow: Math.ceil(
      (${literal} *
        ${BASE_NAME}.roomSlotsPerClient *
        sizeClass.appendSchedule.length) /
        ${BASE_NAME}.publicChunkObjectCount,
    ),
  })),
}) as DeliveryProfileV1;
`;
};

/** `null` when the variable is unset or empty, so an exported-but-empty shell
 * variable is an accident rather than a configured cohort of `NaN`. */
export const cohortFromEnv = (): number | null => {
  const raw = process.env[COHORT_ENV];
  if (raw === undefined || raw === "") return null;
  if (!/^[1-9][0-9]*$/.test(raw))
    throw new Error(`cohortPreload: ${COHORT_ENV} must be a positive integer`);
  return Number(raw);
};

export const cohortProfilePlugin = (cohort: number): BunPlugin => ({
  name: "p2party-harness-cohort-override",
  setup(build) {
    build.onLoad({ filter: PROFILE_MODULE_FILTER }, (args) => ({
      contents: patchProfileSource(readFileSync(args.path, "utf8"), cohort),
      loader: "ts",
    }));
  },
});

// Registering at import time is what makes this usable as `bun --preload`.
// With the variable unset it registers nothing at all, so preloading it
// unconditionally cannot change a default run.
const configured = cohortFromEnv();
if (configured !== null) plugin(cohortProfilePlugin(configured));
