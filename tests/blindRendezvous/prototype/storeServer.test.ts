import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";
import { ingressWindow } from "../../../src/blindRendezvous/publicWindow";
import { PROTOTYPE_DELIVERY_PROFILE_V0 } from "../../../src/blindRendezvous/prototype/profile";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../../../src/blindRendezvous/prototype/storeRoutes";
import {
  decodePublicAllocationResultV1,
  encodePublicAllocationRequestV1,
  encodePublicAppendRequestV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import { carrierObjectWireBytes } from "../../../src/blindRendezvous/prototype/profile";

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

  test("the entrypoint passes a configured admission hook", async () => {
    const directory = join(root, "admission");
    mkdirSync(directory, { recursive: true });
    // Admits a token whose first byte is 7 on every route, refuses the rest.
    const hookPath = join(directory, "hook.mjs");
    writeFileSync(
      hookPath,
      `export default {
  authorize(request) {
    return request.privacyPassToken[0] === 7
      ? new Uint8Array(32).fill(request.route === "allocation" ? 1 : 2)
      : null;
  },
};
`,
    );
    const port = freePort();
    const child = spawnStore({
      P2PARTY_STORE_PROTOTYPE: "1",
      P2PARTY_STORE_OPEN_ALLOCATION: "1",
      P2PARTY_STORE_PORT: String(port),
      P2PARTY_STORE_DB: join(directory, "store.sqlite"),
      P2PARTY_STORE_KEY_FILE: join(directory, "store.key"),
      P2PARTY_STORE_ADMISSION_MODULE: hookPath,
    });
    try {
      await waitForHealth(child, port);
      const origin = `http://127.0.0.1:${String(port)}`;
      const health = (await (await fetch(`${origin}/health`)).json()) as {
        window: string;
      };
      // The next window is open for both writes whenever this test runs.
      const target = BigInt(health.window) + 1n;
      const profileHash = await deliveryProfileHash(
        PROTOTYPE_DELIVERY_PROFILE_V0,
      );
      const postBody = async (
        path: string,
        mediaType: string,
        body: Uint8Array,
        headers: Record<string, string> = {},
      ): Promise<Response> => {
        const buffer = new ArrayBuffer(body.byteLength);
        new Uint8Array(buffer).set(body);
        return fetch(`${origin}${path}`, {
          method: "POST",
          headers: { "content-type": mediaType, ...headers },
          body: buffer,
        });
      };
      const allocation = async (tokenByte: number): Promise<string> => {
        const response = await postBody(
          PROTOTYPE_STORE_ROUTES.allocation,
          PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
          encodePublicAllocationRequestV1({
            version: 1,
            deliveryProfileHash: profileHash,
            ingressWindow: target,
            allocationEd25519PublicKey: new Uint8Array(32).fill(tokenByte + 1),
            privacyPassToken: new Uint8Array(32).fill(tokenByte),
          }),
        );
        const result = decodePublicAllocationResultV1(
          new Uint8Array(await response.arrayBuffer()),
        );
        return result.kind === "allocated" ? "allocated" : result.value.status;
      };
      expect(await allocation(0)).toBe("invalid-token");
      expect(await allocation(7)).toBe("allocated");

      const cover = encodePublicAppendRequestV1({
        version: 1,
        bucket: {
          deliveryProfileHash: profileHash,
          ingressWindow: target,
          sizeClass: 0,
        },
        exactFixedObject: new Uint8Array(
          carrierObjectWireBytes(PROTOTYPE_DELIVERY_PROFILE_V0, 0, profileHash),
        ),
        admission: null,
      });
      const refused = await postBody(
        PROTOTYPE_STORE_ROUTES.append,
        PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        cover,
      );
      expect(refused.status).toBe(403);
      await refused.arrayBuffer();
      const admitted = await postBody(
        PROTOTYPE_STORE_ROUTES.append,
        PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        cover,
        { authorization: `Bearer ${hex(new Uint8Array(32).fill(7))}` },
      );
      expect(admitted.status).toBe(200);
      await admitted.arrayBuffer();
    } finally {
      child.kill("SIGTERM");
      await child.exited;
    }
  }, 60_000);

  test("the entrypoint refuses an admission module without an authorize function", async () => {
    const directory = join(root, "admission-invalid");
    mkdirSync(directory, { recursive: true });
    const hookPath = join(directory, "hook.mjs");
    writeFileSync(hookPath, "export default { allow: true };\n");
    const child = spawnStore({
      P2PARTY_STORE_PROTOTYPE: "1",
      P2PARTY_STORE_OPEN_ALLOCATION: "1",
      P2PARTY_STORE_PORT: String(freePort()),
      P2PARTY_STORE_DB: join(directory, "store.sqlite"),
      P2PARTY_STORE_KEY_FILE: join(directory, "store.key"),
      P2PARTY_STORE_ADMISSION_MODULE: hookPath,
    });
    // A store that started anyway is stopped by its own PID, never left
    // listening; the bound is on the failure path only.
    const outcome = await Promise.race([
      child.exited,
      Bun.sleep(20_000).then(() => "still running" as const),
    ]);
    if (outcome === "still running") {
      child.kill("SIGTERM");
      await child.exited;
    }
    expect(outcome).toBe(1);
    expect(await new Response(child.stderr).text()).toContain(
      "P2PARTY_STORE_ADMISSION_MODULE",
    );
  }, 30_000);

  test("the entrypoint sweeps windows past its retention", async () => {
    const directory = join(root, "retention");
    mkdirSync(directory, { recursive: true });
    const databasePath = join(directory, "store.sqlite");
    const retention = 4;
    // A chain that started a dozen windows ago: the finalizer catches up at
    // start, so the database holds every one of them unless something sweeps.
    const chainStart =
      ingressWindow(
        PROTOTYPE_DELIVERY_PROFILE_V0.deliveryWindowMs,
        BigInt(Date.now()),
      ) - 12n;
    const port = freePort();
    const child = spawnStore({
      P2PARTY_STORE_PROTOTYPE: "1",
      P2PARTY_STORE_OPEN_ALLOCATION: "1",
      P2PARTY_STORE_PORT: String(port),
      P2PARTY_STORE_DB: databasePath,
      P2PARTY_STORE_KEY_FILE: join(directory, "store.key"),
      P2PARTY_STORE_CHAIN_START: String(chainStart),
      P2PARTY_STORE_RETENTION_WINDOWS: String(retention),
    });
    let observed: { rows: number; oldest: bigint; newest: bigint } | null =
      null;
    try {
      await waitForHealth(child, port);
      // Polled rather than timed: the assertion is the row count once the
      // catch-up has passed the retention floor, however long that takes.
      for (let attempt = 0; attempt < 120; attempt++) {
        const db = new Database(databasePath, {
          readonly: true,
          safeIntegers: true,
        });
        try {
          const row = db
            .query<{ rows: bigint; oldest: bigint; newest: bigint }, []>(
              'SELECT count(*) AS rows, min("window") AS oldest, max("window") AS newest FROM "window" WHERE finalized = 1',
            )
            .get();
          if (
            row !== null &&
            row.newest !== null &&
            row.newest >= chainStart + 11n
          ) {
            observed = {
              rows: Number(row.rows),
              oldest: row.oldest,
              newest: row.newest,
            };
            if (row.oldest > chainStart) break;
          }
        } finally {
          db.close();
        }
        await Bun.sleep(250);
      }
    } finally {
      child.kill("SIGTERM");
      await child.exited;
    }
    if (observed === null) throw new Error("the finalizer never caught up");
    expect(observed.oldest).toBeGreaterThan(chainStart);
    expect(observed.rows).toBeLessThanOrEqual(retention + 2);
  }, 90_000);
});
