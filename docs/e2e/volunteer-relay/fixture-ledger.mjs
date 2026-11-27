// Bun process. A fresh database is created and dropped for this process only.
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [root, genesisFile, chainId] = process.argv.slice(2);
const source = (name) =>
  import(pathToFileURL(join(root, "src", "ledger", name + ".ts")).href);
const [{ LedgerStore }, { ledgerConfig }, { ledgerRpc }] = await Promise.all([
  source("store"),
  source("config"),
  source("rpc"),
]);
const url = new URL(process.env.P2PARTY_TEST_POSTGRES_URL);
if (
  url.protocol !== "postgresql:" ||
  url.hostname !== "127.0.0.1" ||
  Number(url.port) <= 5000 ||
  url.port === "5432" ||
  url.pathname !== "/postgres" ||
  url.search ||
  url.hash
)
  throw new Error(
    "Expected a disposable PostgreSQL server on IPv4 loopback port >5000, database postgres, no URL options",
  );
const { Client } = createRequire(join(root, "package.json"))("pg");
const admin = new Client({ connectionString: url.href });
await admin.connect();
const name = "p2party_relay_" + randomBytes(12).toString("hex");
let store,
  server,
  created = false;
try {
  await admin.query("CREATE DATABASE " + name);
  created = true;
  url.pathname = "/" + name;
  url.search = "?sslmode=disable";
  const cfg = ledgerConfig({
    LEDGER_ENABLED: "true",
    LEDGER_CHAIN_ID: chainId,
    LEDGER_GENESIS_FILE: genesisFile,
    LEDGER_VERIFIER: process.env.P2PARTY_TEST_LEDGER_VERIFIER,
  });
  store = new LedgerStore(cfg, url.href);
  await store.initialize();
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: ledgerRpc(store),
  });
  process.stdout.write(
    JSON.stringify({
      url: server.url.origin + "/rpc",
      genesis: cfg.genesisHash,
    }) + "\n",
  );
  for await (const unused of process.stdin) {
    void unused;
  }
} finally {
  if (server) await server.stop(true);
  if (store) await store.close();
  if (created) await admin.query("DROP DATABASE " + name);
  await admin.end();
}
