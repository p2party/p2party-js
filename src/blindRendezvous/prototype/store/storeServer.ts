/// <reference types="bun" />
/**
 * The prototype store entrypoint: configuration, the identity key file, and
 * process lifecycle. `bun run store:prototype`.
 *
 * This process is **not conformant**. It implements open allocation only —
 * there is no Privacy Pass issuer, so it carries no Sybil or fairness claim at
 * all, only a fixed traffic shape. Two environment flags must both be set
 * before it will start, so nobody deploys it by accident and nobody can point
 * at a running instance as evidence of the specified store.
 *
 * What it owns that no other file does:
 *
 * - **The chain start is chosen once and then persisted.** The descriptor's
 *   validity interval is anchored to it so a restart re-derives byte-identical
 *   descriptor bytes; every finalized checkpoint names the `descriptorHash` it
 *   was signed under, so a store that re-chose its chain start on each boot
 *   would orphan its own chain and be marked inert by every client.
 * - **The delivery profile is pinned to that chain.** A restart under a
 *   different `P2PARTY_STORE_WINDOW_MS` would measure windows with a different
 *   ruler and sign a chain that disagrees with the one already on disk, so a
 *   mismatch refuses to start rather than equivocate.
 * - **The identity seed is created 0600 or not at all.**
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry.
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";

import { wasmLoader } from "../../../cryptography/wasmLoader";
import { deliveryProfileHash } from "../../derivations";
import { ingressWindow } from "../../publicWindow";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  withDeliveryWindowMs,
} from "../profile";
import { PrototypeStoreCore } from "./storeCore";
import {
  PROTOTYPE_STORE_MAX_REQUEST_BODY_BYTES,
  createPrototypeStoreHandler,
} from "./storeHttp";
import { SqliteStorePersistence } from "./storeSqlite";

import type { LibCrypto } from "../../../cryptography/libcrypto";
import type { DeliveryProfileV1 } from "../profile";

/** Printed verbatim; the E2E asserts on this exact line. */
const GATE_REFUSAL =
  "p2party store prototype: set P2PARTY_STORE_PROTOTYPE=1 and P2PARTY_STORE_OPEN_ALLOCATION=1 to run this non-conformant prototype";

const DEFAULT_PORT = 5910;
const MIN_PORT = 5001;
const MAX_PORT = 65535;
const DEFAULT_DB_PATH = "./p2party-store-prototype.sqlite";
const DEFAULT_KEY_FILE = "./p2party-store-prototype.key";
const DESCRIPTOR_VALIDITY_MS = 2_592_000_000n; // 30 days
const FINALIZE_INTERVAL_MS = 250;
const SEED_BYTES = 32;

/**
 * The same linear memory the store's own tests run against. Every transcript
 * this process signs is a domain string plus a 32-byte digest, so the working
 * set is small; the headroom is here because a store that ran out of WASM
 * memory mid-finalization would leave a window half-signed.
 */
const STORE_WASM_PAGES = 1024;

const META_CHAIN_START = "chainStartIngressWindow";
const META_PROFILE_HASH = "deliveryProfileHash";

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = (1n << 64n) - 1n;

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const refuse: (message: string) => never = (message) => {
  console.error(`p2party store prototype: ${message}`);
  process.exit(1);
};

/* ------------------------------------------------------------------ *
 * Gate
 * ------------------------------------------------------------------ */

if (
  process.env.P2PARTY_STORE_PROTOTYPE !== "1" ||
  process.env.P2PARTY_STORE_OPEN_ALLOCATION !== "1"
) {
  console.error(GATE_REFUSAL);
  process.exit(1);
}

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

const parsePort = (raw: string | undefined): number => {
  if (raw === undefined) return DEFAULT_PORT;
  if (!DECIMAL.test(raw))
    refuse("P2PARTY_STORE_PORT must be a decimal integer");
  const port = Number(raw);
  // Nothing binds below 5000 on these machines; 5432 is Postgres and the rest
  // of the low range belongs to whatever the developer already runs.
  if (port < MIN_PORT || port > MAX_PORT)
    refuse(
      `P2PARTY_STORE_PORT must be between ${String(MIN_PORT)} and ${String(MAX_PORT)}`,
    );
  return port;
};

const parseProfile = (raw: string | undefined): DeliveryProfileV1 => {
  if (raw === undefined) return PROTOTYPE_DELIVERY_PROFILE_V0;
  if (!DECIMAL.test(raw) || raw === "0")
    refuse("P2PARTY_STORE_WINDOW_MS must be a positive decimal integer");
  // Every schedule offset is rescaled by the same ratio, so the profile's
  // ordering inequalities survive the change; the client passes the same
  // override, and both then derive the same profile hash.
  return withDeliveryWindowMs(PROTOTYPE_DELIVERY_PROFILE_V0, BigInt(raw));
};

const parseFault = (raw: string | undefined): "withhold" | null => {
  if (raw === undefined || raw === "") return null;
  if (raw !== "withhold")
    refuse('P2PARTY_STORE_FAULT must be "withhold" if it is set');
  return "withhold";
};

/**
 * Load the store's identity seed, or create it.
 *
 * `wx` rather than a check-then-write: two stores pointed at one key file must
 * not both believe they created it. The mode is passed at creation because a
 * seed written world-readable and chmod'ed afterwards is world-readable for
 * the window between the two calls; the explicit `chmod` afterwards only pins
 * the result against a permissive umask having been applied.
 */
const loadOrCreateSeed = (path: string): Uint8Array => {
  if (existsSync(path)) {
    const stored = readFileSync(path);
    if (stored.length !== SEED_BYTES)
      refuse(`${path} is not a ${String(SEED_BYTES)}-byte store identity seed`);
    return new Uint8Array(stored);
  }
  const seed = new Uint8Array(SEED_BYTES);
  crypto.getRandomValues(seed);
  writeFileSync(path, seed, { mode: 0o600, flag: "wx" });
  chmodSync(path, 0o600);
  return seed;
};

/** An exported-but-empty variable is a shell accident, not a configured
 * value; treating `FOO=` as "set" turns it into an unreadable path. */
const setting = (name: string): string | undefined => {
  const raw = process.env[name];
  return raw === undefined || raw === "" ? undefined : raw;
};

const port = parsePort(setting("P2PARTY_STORE_PORT"));
const profile = parseProfile(setting("P2PARTY_STORE_WINDOW_MS"));
const fault = parseFault(setting("P2PARTY_STORE_FAULT"));
const databasePath = setting("P2PARTY_STORE_DB") ?? DEFAULT_DB_PATH;
const keyFilePath = setting("P2PARTY_STORE_KEY_FILE") ?? DEFAULT_KEY_FILE;
const logBodiesPath = setting("P2PARTY_STORE_LOG_BODIES");

/* ------------------------------------------------------------------ *
 * Start
 * ------------------------------------------------------------------ */

const persistence = new SqliteStorePersistence(databasePath);
const profileHashHex = hexOf(await deliveryProfileHash(profile));

// A chain already on disk was measured with one ruler; changing the ruler now
// would sign windows that disagree with the ones already signed.
const persistedProfileHash = persistence.loadMeta(META_PROFILE_HASH);
if (persistedProfileHash !== null && persistedProfileHash !== profileHashHex)
  refuse(
    `${databasePath} holds a chain for another delivery profile; use a fresh database or restore P2PARTY_STORE_WINDOW_MS`,
  );

const persistedChainStart = persistence.loadMeta(META_CHAIN_START);
const configuredChainStart = setting("P2PARTY_STORE_CHAIN_START");
if (
  configuredChainStart !== undefined &&
  // A window wider than u64 has no canonical encoding, so the descriptor that
  // names it could not be signed at all; refusing here is the readable version
  // of the codec failure that would otherwise happen mid-start.
  (!DECIMAL.test(configuredChainStart) ||
    BigInt(configuredChainStart) > MAX_U64)
)
  refuse("P2PARTY_STORE_CHAIN_START must be a decimal integer that fits u64");
if (
  persistedChainStart !== null &&
  configuredChainStart !== undefined &&
  configuredChainStart !== persistedChainStart
)
  refuse(
    `${databasePath} is already anchored at chain start ${persistedChainStart}; P2PARTY_STORE_CHAIN_START cannot move it`,
  );

const chainStartIngressWindow =
  persistedChainStart !== null
    ? BigInt(persistedChainStart)
    : configuredChainStart !== undefined
      ? BigInt(configuredChainStart)
      : ingressWindow(profile.deliveryWindowMs, BigInt(Date.now()));

const module = (await wasmLoader(
  new WebAssembly.Memory({
    initial: STORE_WASM_PAGES,
    maximum: STORE_WASM_PAGES,
  }),
)) as LibCrypto;

const origin = `http://127.0.0.1:${String(port)}`;
// The reachable failure here is expiry: with the descriptor anchored to the
// chain start, a chain older than DESCRIPTOR_VALIDITY_MS needs a new
// descriptor generation that this prototype's persistence cannot express. It
// refuses with a sentence rather than a stack trace, because the operator's
// fix is a fresh database, not a code change.
const core = await PrototypeStoreCore.create({
  module,
  seed: loadOrCreateSeed(keyFilePath),
  profile,
  clock: { nowMs: () => BigInt(Date.now()) },
  persistence,
  chainStartIngressWindow,
  origin,
  descriptorValidityMs: DESCRIPTOR_VALIDITY_MS,
  fault,
}).catch((error: unknown) =>
  refuse(
    `cannot serve the chain anchored at window ${String(chainStartIngressWindow)}: ${
      error instanceof Error ? error.message : "unknown error"
    }`,
  ),
);

// Anchored only now, and only because `create` succeeded.
//
// `create` writes nothing to persistence — it reads the last finalized window
// and refuses rather than sign when the configuration contradicts it — so
// there is no window in which a signature could exist without its anchor.
// Committing the anchor first would durably record a chain start that was
// never used: every later launch would then either refuse to move it ("cannot
// move it") or reproduce the same failure forever, and the only way out would
// be deleting a database that holds nothing.
persistence.saveMeta(META_CHAIN_START, String(chainStartIngressWindow));
persistence.saveMeta(META_PROFILE_HASH, profileHashHex);

// A window closes on the clock, so the finalizer only has to catch up to it;
// running far more often than the shortest window keeps the gap between "the
// window is closed" and "its checkpoint exists" down to a tick.
const finalizeTimer = setInterval(() => {
  void core.finalizeDue().catch((error: unknown) => {
    // Never the message: a failure here can quote the bytes it was signing.
    console.error(
      `p2party store: finalization failed (${error instanceof Error ? error.name : "unknown error"})`,
    );
  });
}, FINALIZE_INTERVAL_MS);

const listen = (): Bun.Server<undefined> => {
  try {
    return Bun.serve({
      port,
      // Loopback only. This process answers without authentication and is not
      // conformant; it has no business being reachable from the network.
      hostname: "127.0.0.1",
      maxRequestBodySize: PROTOTYPE_STORE_MAX_REQUEST_BODY_BYTES,
      fetch: createPrototypeStoreHandler({ core, logBodiesPath }),
    });
    // The E2E runs two of these side by side, so "the port is already taken"
    // is the failure an operator will actually hit; it deserves a sentence.
  } catch (error) {
    refuse(
      `cannot bind ${origin}: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
};

const server = listen();

console.log(
  [
    `p2party store prototype: listening on ${origin}`,
    `storeId=${hexOf(core.storeId)}`,
    `profile=${profileHashHex}`,
    `windowMs=${String(profile.deliveryWindowMs)}`,
    `chainStart=${String(chainStartIngressWindow)}`,
    `db=${databasePath}`,
    fault === null ? "fault=none" : `fault=${fault}`,
    logBodiesPath === undefined
      ? "log-bodies=off"
      : `log-bodies=${logBodiesPath}`,
  ].join(" "),
);
console.warn(
  "p2party store prototype: open allocation, no Privacy Pass issuer — this store carries no Sybil or fairness claim",
);

/* ------------------------------------------------------------------ *
 * Shutdown
 * ------------------------------------------------------------------ */

let stopping = false;
const shutdown = (signal: string): void => {
  // `stop(true)` terminates in-flight requests rather than draining them: a
  // keep-alive connection would otherwise hold the process open, and a request
  // cut short loses only its response — every write it made was committed
  // (`synchronous = FULL`) before the answer was built. The guard is for a
  // second Ctrl-C, which would otherwise close the database twice.
  if (stopping) return;
  stopping = true;
  clearInterval(finalizeTimer);
  void server.stop(true).then(
    () => {
      persistence.close();
      console.log(`p2party store prototype: stopped on ${signal}`);
      process.exit(0);
    },
    () => {
      process.exit(0);
    },
  );
};

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});
process.on("SIGINT", () => {
  shutdown("SIGINT");
});
