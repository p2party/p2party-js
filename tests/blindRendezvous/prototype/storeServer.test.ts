import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import { ingressWindow } from "../../../src/blindRendezvous/publicWindow";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";

import type { Subprocess } from "bun";

/**
 * The entrypoint is a script with no exports, so it is tested the way it is
 * run: as a process. That is also the only way to test the property under
 * examination — what a *refused* start leaves behind on disk — because the
 * refusal is `process.exit`, which a same-process test cannot survive.
 */
const ENTRYPOINT = join(
  import.meta.dir,
  "../../../src/blindRendezvous/prototype/store/storeServer.ts",
);
const REPO_ROOT = join(import.meta.dir, "../../..");

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const root = mkdtempSync(join(tmpdir(), "p2party-store-server-"));

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const spawnStore = (
  env: Record<string, string>,
): Subprocess<"ignore", "pipe", "pipe"> =>
  Bun.spawn([process.execPath, "run", ENTRYPOINT], {
    cwd: REPO_ROOT,
    env: { ...process.env, ...env },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });

/**
 * An ephemeral port the kernel just handed back, so two of these tests (or two
 * developers) never collide on a literal. Ephemeral ranges sit far above the
 * entrypoint's 5001 floor; the assertion is there so a machine configured
 * otherwise fails loudly rather than mysteriously.
 */
const freePort = (): number => {
  const probe = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch: () => new Response(""),
  });
  const port = probe.port;
  void probe.stop(true);
  expect(port).toBeGreaterThanOrEqual(5001);
  return port ?? 0;
};

const waitForHealth = async (
  child: Subprocess<"ignore", "pipe", "pipe">,
  port: number,
): Promise<void> => {
  for (let attempt = 0; attempt < 60; attempt++) {
    if (child.exitCode !== null)
      throw new Error(
        `the store exited with ${String(child.exitCode)}: ${await new Response(
          child.stderr,
        ).text()}`,
      );
    try {
      const response = await fetch(`http://127.0.0.1:${String(port)}/health`);
      if (response.ok) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // Not listening yet.
    }
    await Bun.sleep(250);
  }
  throw new Error("the store never answered /health");
};

describe("prototype store entrypoint", () => {
  test("a refused start anchors nothing, so the next launch is free to choose", async () => {
    const directory = join(root, "recovery");
    mkdirSync(directory, { recursive: true });
    const databasePath = join(directory, "store.sqlite");
    const keyFilePath = join(directory, "store.key");

    const base = {
      P2PARTY_STORE_PROTOTYPE: "1",
      P2PARTY_STORE_OPEN_ALLOCATION: "1",
      P2PARTY_STORE_DB: databasePath,
      P2PARTY_STORE_KEY_FILE: keyFilePath,
    };

    // Window 1 is 1970: the descriptor anchored there expired decades ago,
    // so `create` refuses. Nothing is signed and nothing is served.
    const refused = spawnStore({
      ...base,
      P2PARTY_STORE_CHAIN_START: "1",
      P2PARTY_STORE_PORT: String(freePort()),
    });
    const refusal = await new Response(refused.stderr).text();
    expect(await refused.exited).toBe(1);
    expect(refusal).toContain("cannot serve the chain anchored at window 1");

    // The anchor must not survive a start that never produced a signature:
    // a committed chain start is the one thing a later launch cannot move.
    const afterRefusal = new SqliteStorePersistence(databasePath);
    try {
      expect(afterRefusal.loadMeta("chainStartIngressWindow")).toBeNull();
      expect(afterRefusal.loadMeta("deliveryProfileHash")).toBeNull();
      expect(await afterRefusal.lastFinalizedWindow()).toBeNull();
    } finally {
      afterRefusal.close();
    }

    // So the same database now accepts a different, valid chain start.
    const chainStart = ingressWindow(
      PROTOTYPE_DELIVERY_PROFILE_V0.deliveryWindowMs,
      BigInt(Date.now()),
    );
    const port = freePort();
    const started = spawnStore({
      ...base,
      P2PARTY_STORE_CHAIN_START: String(chainStart),
      P2PARTY_STORE_PORT: String(port),
    });
    try {
      await waitForHealth(started, port);
    } finally {
      started.kill("SIGTERM");
      await started.exited;
    }

    const afterStart = new SqliteStorePersistence(databasePath);
    try {
      expect(afterStart.loadMeta("chainStartIngressWindow")).toBe(
        String(chainStart),
      );
      expect(afterStart.loadMeta("deliveryProfileHash")).toBe(
        hex(await deliveryProfileHash(PROTOTYPE_DELIVERY_PROFILE_V0)),
      );
    } finally {
      afterStart.close();
    }
  }, 60_000);

  test("it refuses without both gate flags and anchors nothing", async () => {
    const databasePath = join(root, "gated.sqlite");
    const child = spawnStore({
      P2PARTY_STORE_PROTOTYPE: "1",
      P2PARTY_STORE_OPEN_ALLOCATION: "",
      P2PARTY_STORE_DB: databasePath,
      P2PARTY_STORE_KEY_FILE: join(root, "gated.key"),
    });
    const refusal = await new Response(child.stderr).text();
    expect(await child.exited).toBe(1);
    expect(refusal.trim()).toBe(
      "p2party store prototype: set P2PARTY_STORE_PROTOTYPE=1 and P2PARTY_STORE_OPEN_ALLOCATION=1 to run this non-conformant prototype",
    );
    // The gate is checked before the database is opened at all.
    expect(await Bun.file(databasePath).exists()).toBe(false);
  }, 30_000);
});
