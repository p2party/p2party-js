/// <reference types="bun" />
/**
 * Harness helper for the cohort measurement in `run.mjs --cohort=<n>`.
 *
 *   bun run docs/e2e/blind-two-store/profileTool.ts info  [--window-ms=4000]
 *   bun run docs/e2e/blind-two-store/profileTool.ts build --out=<path>
 *
 * `info` prints, as JSON, the geometry the run is about to use: the
 * `DeliveryProfileHash` both sides must agree on, the per-size-class chunk
 * counts, and the two numbers the measurement is for — the bytes one client
 * appends and the bytes it scans, per window, per store. `run.mjs` cannot
 * compute these itself: it is plain Node ESM and the profile, its validator and
 * the carrier-envelope codec are TypeScript in `src/`.
 *
 * `build` bundles `entry.ts` for the browser with the same cohort rewrite
 * applied, so the page and the store cannot disagree about the bucket.
 *
 * Both subcommands read the cohort from `P2PARTY_BLIND_COHORT`
 * (see `cohortPreload.ts`); `info` must therefore be run with that preload,
 * which is how `run.mjs` invokes it.
 *
 * Status: HARNESS. Nothing here is imported by `src/`.
 */

import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  carrierObjectWireBytes,
  validateDeliveryProfileGeometry,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import { cohortFromEnv, cohortProfilePlugin } from "./cohortPreload";

import type { DeliveryProfileV1 } from "../../../src/blindRendezvous/prototype/profile";

const here = new URL(".", import.meta.url).pathname;

const argOf = (name: string): string | undefined => {
  const hit = process.argv.find((value) => value.startsWith(`--${name}=`));
  return hit === undefined ? undefined : hit.slice(name.length + 3);
};

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const info = async (): Promise<void> => {
  const windowMs = argOf("window-ms");
  const profile: DeliveryProfileV1 =
    windowMs === undefined
      ? PROTOTYPE_DELIVERY_PROFILE_V0
      : withDeliveryWindowMs(PROTOTYPE_DELIVERY_PROFILE_V0, BigInt(windowMs));
  // The store rescales and validates; a profile that would be rejected there
  // must be rejected here, before anything is spawned.
  validateDeliveryProfileGeometry(profile);
  const profileHash = await deliveryProfileHash(profile);

  let appendedBytesPerWindow = 0;
  let scannedBytesPerWindow = 0;
  const sizeClasses = profile.sizeClasses.map((sizeClass) => {
    const objectBytes = carrierObjectWireBytes(
      profile,
      sizeClass.id,
      profileHash,
    );
    const appended = sizeClass.appendSchedule.length * objectBytes;
    const scanned =
      sizeClass.publicChunksPerWindow *
      profile.publicChunkObjectCount *
      objectBytes;
    appendedBytesPerWindow += appended;
    scannedBytesPerWindow += scanned;
    return {
      id: sizeClass.id,
      appendsPerWindow: sizeClass.appendSchedule.length,
      publicChunksPerWindow: sizeClass.publicChunksPerWindow,
      objectWireBytes: objectBytes,
      appendedBytesPerWindow: appended,
      scannedBytesPerWindow: scanned,
    };
  });

  process.stdout.write(
    `${JSON.stringify(
      {
        cohortAllocationsPerWindow: profile.cohortAllocationsPerWindow,
        cohortFromEnv: cohortFromEnv(),
        deliveryWindowMs: String(profile.deliveryWindowMs),
        chunkFinalizationOffsetMs: String(profile.chunkFinalizationOffsetMs),
        lastAppendOffsetMs: String(
          profile.sizeClasses
            .flatMap((sizeClass) => sizeClass.appendSchedule)
            .reduce(
              (latest, entry) =>
                entry.offsetMs > latest ? entry.offsetMs : latest,
              0n,
            ),
        ),
        publicChunkObjectCount: profile.publicChunkObjectCount,
        deliveryProfileHash: hexOf(profileHash),
        sizeClasses,
        // Per client, per store, per window. The append side is fixed by the
        // schedule and does not move with the cohort; the scan side is the
        // whole bucket and does.
        appendedBytesPerWindow,
        scannedBytesPerWindow,
      },
      null,
      2,
    )}\n`,
  );
};

const build = async (): Promise<void> => {
  const out = argOf("out");
  if (out === undefined)
    throw new Error("profileTool build needs --out=<path>");
  const cohort = cohortFromEnv();
  if (cohort === null)
    throw new Error("profileTool build needs P2PARTY_BLIND_COHORT");

  const result = await Bun.build({
    entrypoints: [`${here}entry.ts`],
    target: "browser",
    define: { "process.env.NODE_ENV": '"production"' },
    plugins: [cohortProfilePlugin(cohort)],
  });
  if (!result.success)
    throw new Error(
      `profileTool build failed: ${result.logs.map(String).join("; ")}`,
    );
  await Bun.write(out, result.outputs[0]);
  process.stdout.write(`${out}\n`);
};

const command = process.argv[2];
if (command === "info") await info();
else if (command === "build") await build();
else {
  process.stderr.write(
    "usage: profileTool.ts info|build [--out=] [--window-ms=]\n",
  );
  process.exit(2);
}
