// Full app-stack browser E2E: two headless-Chromium pages each run the REAL
// p2party API (Redux store + IndexedDB DB worker + WebRTC). A Bun signaling
// relay stands in for the Postgres-backed server. Verifies immediate, PIN, and
// scheduled-cover rooms deliver a message byte-exact through the whole stack.
import http from "node:http";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "/Users/deliberative/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
const HTTP_PORT = 8831;
const RELAY_PORT = 8830;
const wsUrl = `ws://localhost:${RELAY_PORT}/ws`;
const wasmUrl = `http://localhost:${HTTP_PORT}/libcrypto.wasm`;
const say = (...a) => process.stdout.write(a.join(" ") + "\n");

// Serve the appstack assets.
const mime = (p) =>
  p.endsWith(".js") ? "text/javascript" : p.endsWith(".wasm") ? "application/wasm" : "text/html";
const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/app.html" : req.url.split("?")[0];
  try {
    res.writeHead(200, { "content-type": mime(name), "cache-control": "no-store" });
    res.end(readFileSync(path.join(dir, name)));
  } catch {
    res.writeHead(404);
    res.end("nf");
  }
});
await new Promise((r) => server.listen(HTTP_PORT, r));

// Launch the Bun signaling relay.
const relay = spawn("bun", [path.join(dir, "relay.ts")], {
  env: { ...process.env, RELAY_PORT: String(RELAY_PORT) },
  stdio: ["ignore", "pipe", "pipe"],
});
relay.stdout.on("data", (d) => process.stdout.write(String(d)));
relay.stderr.on("data", (d) => process.stdout.write("[relay-err] " + String(d)));
await new Promise((r) => setTimeout(r, 800)); // let the relay bind

const withTimeout = (p, ms, label) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms))]);

const poll = async (page, fn, arg, ms, label) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const v = await page.evaluate(fn, arg);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`poll timeout: ${label}`);
};

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
let failed = false;

const runScenario = async (label, roomUrl, mode, pinHex) => {
  say(`\n=== ${label} ===`);
  const a = await browser.newPage();
  const b = await browser.newPage();
  for (const [name, pg] of [["A", a], ["B", b]]) {
    pg.on("pageerror", (e) => say(`  [${name} pageerror] ${e.message}`));
    pg.on("console", (m) => {
      const t = m.text();
      if (/error|reject|fail|throw|MITM/i.test(t)) say(`  [${name}] ${t.slice(0, 200)}`);
    });
    await pg.goto(`http://localhost:${HTTP_PORT}/`);
    await pg.waitForFunction("window.__app !== undefined", null, { timeout: 15000 });
    await pg.evaluate((u) => window.__app.boot(u), wasmUrl);
  }

  // Connect both peers to the same room.
  const opts = { mode, pinHex };
  await a.evaluate(([r, w, o]) => window.__app.connect(r, w, o), [roomUrl, wsUrl, opts]);
  await b.evaluate(([r, w, o]) => window.__app.connect(r, w, o), [roomUrl, wsUrl, opts]);

  // Wait for signaling verification + mutual peer discovery.
  await poll(a, () => window.__app.isVerified(), null, 15000, "A verified");
  await poll(b, () => window.__app.isVerified(), null, 15000, "B verified");
  await withTimeout(poll(a, (r) => window.__app.peerCount(r) >= 1, roomUrl, 20000, "A sees peer"), 21000, "A discovery");
  await withTimeout(poll(b, (r) => window.__app.peerCount(r) >= 1, roomUrl, 20000, "B sees peer"), 21000, "B discovery");
  say(`  both peers discovered each other (verified + roster)`);

  // A joins a chat channel with the discovered peer, then sends. sendMessage
  // internally waits for the PACE + Double-Ratchet handshake to complete.
  await a.evaluate((r) => window.__app.joinChannel(r, "chat"), roomUrl);
  const text = `full-stack ${mode} message :: ${"z".repeat(500)}`;
  const sendResult = await withTimeout(
    a.evaluate(([r, t]) => window.__app.send(r, "chat", t), [roomUrl, text]),
    60000,
    `${label} send`,
  );
  say(`  A sent: delivered=${sendResult.delivered}, root=${sendResult.merkleRootHex.slice(0, 12)}…`);
  if (sendResult.delivered < 1) throw new Error(`${label}: no peer confirmed delivery`);

  // B reads the received message and asserts byte-exact.
  const incoming = await withTimeout(
    poll(b, (r) => window.__app.latestIncoming(r), roomUrl, 30000, "B incoming"),
    31000,
    `${label} B incoming`,
  );
  const got = await b.evaluate((root) => window.__app.read(root), incoming.merkleRootHex);
  if (got !== text) throw new Error(`${label}: message not byte-exact (got ${got.length} chars)`);
  say(`  B received BYTE-EXACT through the full Redux/DB/WebRTC stack (${text.length} chars)`);

  await a.evaluate(() => window.__app.disconnectAll()).catch(() => {});
  await b.evaluate(() => window.__app.disconnectAll()).catch(() => {});
  await a.close();
  await b.close();
  say(`  ${label} PASS`);
};

try {
  const roomImmediate = "aa".repeat(32);
  const roomPin = "bb".repeat(32);
  const roomScheduled = "cc".repeat(32);
  const pinHex = "dd".repeat(16); // 16-byte PIN

  await runScenario("immediate room (Redux/DB/WebRTC)", roomImmediate, "immediate");
  await runScenario("PIN room (Redux/DB/WebRTC)", roomPin, "pin", pinHex);
  await runScenario("scheduled-cover room (Redux/DB/WebRTC)", roomScheduled, "scheduled");

  say("\nALL FULL-APP-STACK BROWSER E2E SCENARIOS PASSED (immediate, PIN, scheduled).");
} catch (e) {
  failed = true;
  say("\nAPP-STACK E2E FAILURE: " + e.message);
  console.error(e);
} finally {
  await browser.close();
  relay.kill("SIGKILL");
  server.close();
}
process.exit(failed ? 1 : 0);
