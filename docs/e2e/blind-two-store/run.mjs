// End-to-end driver for the flagged two-store blind-rendezvous prototype.
//
//   bash docs/e2e/blind-two-store/build.sh
//   PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
//     node docs/e2e/blind-two-store/run.mjs [--window-ms=4000] [--deadline-ms=180000]
//
// One run is the whole claim of the prototype, end to end and with nothing
// stubbed: two REAL store processes on 5910/5911 with fresh databases and
// fresh identity keys, two REAL headless-Chromium pages that share nothing but
// a 32-byte room capability, and no signaling server anywhere. Each page
// publishes PRESENCE through both stores, discovers the other through either,
// completes IDENTITY_HELLO -> IDENTITY_ACCEPT -> TRANSPORT_OFFER ->
// TRANSPORT_ANSWER as pair-sealed operations the stores carry blind, connects
// WebRTC from the exchanged SDP, runs the protocol-v4 handshake over the data
// channel, and exchanges one encrypted application message each way, asserted
// byte-exact.
//
// This is Task 8b's verification of `src/blindRendezvous/prototype/index.ts`.
// Task 9 owns the multi-scenario version (kill-a, withhold-a,
// unreachable-b-for-one, the full privacy audit and the timing table); this
// file is its healthy-path starting point.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "~/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(dir, "../../..");

const argOf = (name, fallback) => {
  const hit = process.argv.find((value) => value.startsWith(`--${name}=`));
  return hit === undefined ? fallback : Number(hit.split("=")[1]);
};

// Project rule: nothing binds below 5000.
const STORE_A_PORT = argOf("store-a-port", 5910);
const STORE_B_PORT = argOf("store-b-port", 5911);
const PAGE_PORT = argOf("page-port", 5920);
const WINDOW_MS = argOf("window-ms", 4000);
const DEADLINE_MS = argOf("deadline-ms", 180_000);

// A→B is deliberately multi-frame (the session's uniform chunk frame is
// 65,490 bytes) and B→A single-frame, so one run exercises both shapes of the
// app-lane framing in `prototype/index.ts`.
const MESSAGE_AB = `A->B ${"a".repeat(140_000)}`;
const MESSAGE_BA = `B->A ${"b".repeat(9_000)}`;

const say = (...parts) => process.stdout.write(parts.join(" ") + "\n");

const started = Date.now();
const stamp = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;

const withTimeout = (promise, ms, label) =>
  Promise.race([
    promise,
    new Promise((_resolve, reject) =>
      setTimeout(() => reject(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms),
    ),
  ]);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* ------------------------------------------------------------------ *
 * Stores
 * ------------------------------------------------------------------ */

const workspace = mkdtempSync(path.join(tmpdir(), "p2party-blind-e2e-"));
const children = [];

const startStore = (name, port) => {
  const child = spawn(
    "bun",
    ["run", "src/blindRendezvous/prototype/store/storeServer.ts"],
    {
      cwd: root,
      env: {
        ...process.env,
        P2PARTY_STORE_PROTOTYPE: "1",
        P2PARTY_STORE_OPEN_ALLOCATION: "1",
        P2PARTY_STORE_PORT: String(port),
        P2PARTY_STORE_DB: path.join(workspace, `${name}.sqlite`),
        P2PARTY_STORE_KEY_FILE: path.join(workspace, `${name}.key`),
        // The client rescales the same pinned profile by the same ratio, so
        // both sides derive one delivery-profile hash — i.e. one bucket.
        P2PARTY_STORE_WINDOW_MS: String(WINDOW_MS),
        P2PARTY_STORE_LOG_BODIES: path.join(workspace, `${name}.bodies.log`),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.on("data", (chunk) =>
    say(`  [store ${name}] ${String(chunk).trimEnd()}`),
  );
  child.stderr.on("data", (chunk) =>
    say(`  [store ${name}!] ${String(chunk).trimEnd()}`),
  );
  children.push(child);
  return child;
};

const waitHealthy = async (name, port) => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) {
        const body = await response.json();
        say(`store ${name} healthy on ${port} (storeId ${body.storeId})`);
        return;
      }
    } catch {
      /* not up yet */
    }
    await sleep(250);
  }
  throw new Error(`store ${name} never answered /health on ${port}`);
};

/* ------------------------------------------------------------------ *
 * Static page server
 * ------------------------------------------------------------------ */

const mime = (name) =>
  name.endsWith(".js")
    ? "text/javascript"
    : name.endsWith(".wasm")
      ? "application/wasm"
      : "text/html";

const pageServer = http.createServer((request, response) => {
  const name = request.url === "/" ? "/index.html" : request.url.split("?")[0];
  try {
    response.writeHead(200, { "content-type": mime(name) });
    response.end(readFileSync(path.join(dir, name)));
  } catch {
    response.writeHead(404);
    response.end("not found");
  }
});

/* ------------------------------------------------------------------ *
 * Run
 * ------------------------------------------------------------------ */

const events = [];
const problems = [];

const openPage = async (browser, label) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("pageerror", (error) =>
    say(`  [${label} pageerror] ${error.message}`),
  );
  page.on("console", (message) => {
    if (message.type() === "error")
      say(`  [${label} console.error] ${message.text()}`);
  });
  await page.exposeFunction("__blindEvent", (json) => {
    const event = JSON.parse(json);
    events.push({ page: label, ...event });
    say(
      `  ${stamp()} [${label}] ${event.kind}` +
        (event.detail === undefined ? "" : ` — ${event.detail}`),
    );
  });
  await page.goto(`http://localhost:${PAGE_PORT}/`);
  await withTimeout(
    page.waitForFunction("window.__blind !== undefined", null, {
      timeout: 20_000,
    }),
    21_000,
    `${label} bundle load`,
  );
  return { label, context, page };
};

const capability = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
const capabilityHex = capability.toString("hex");

let browser = null;
let failed = false;

try {
  startStore("a", STORE_A_PORT);
  startStore("b", STORE_B_PORT);
  await Promise.all([
    waitHealthy("a", STORE_A_PORT),
    waitHealthy("b", STORE_B_PORT),
  ]);

  await new Promise((resolve) => pageServer.listen(PAGE_PORT, resolve));
  say(`page server on http://localhost:${PAGE_PORT}/`);

  // `--disable-features=WebRtcHideLocalIpsWithMdns` is required, not cosmetic:
  // Chromium otherwise replaces host candidates with `<uuid>.local` mDNS names
  // this sandbox cannot resolve, and because the blind profile is COMPLETE
  // gathering (one SDP blob, no trickle) an unresolvable candidate is simply
  // dropped — both connections then sit at "new" forever.
  browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-features=WebRtcHideLocalIpsWithMdns"],
  });

  const [a, b] = await Promise.all([
    openPage(browser, "A"),
    openPage(browser, "B"),
  ]);
  say(`both pages loaded (capability ${capabilityHex.slice(0, 16)}…)`);

  const runOptions = JSON.stringify({
    capabilityHex,
    storeOrigins: [
      `http://127.0.0.1:${STORE_A_PORT}`,
      `http://127.0.0.1:${STORE_B_PORT}`,
    ],
    rtcConfig: { iceServers: [] },
    deliveryWindowMs: String(WINDOW_MS),
  });

  const connectStarted = Date.now();
  await Promise.all([
    a.page.evaluate((json) => window.__blind.run(json), runOptions),
    b.page.evaluate((json) => window.__blind.run(json), runOptions),
  ]);
  say(`${stamp()} both endpoints armed; delivery window ${WINDOW_MS}ms`);

  const [, gotAtB, , gotAtA] = await withTimeout(
    Promise.all([
      a.page.evaluate(
        ([text, ms]) => window.__blind.send(text, ms),
        [MESSAGE_AB, DEADLINE_MS],
      ),
      b.page.evaluate((ms) => window.__blind.recv(ms), DEADLINE_MS),
      b.page.evaluate(
        ([text, ms]) => window.__blind.send(text, ms),
        [MESSAGE_BA, DEADLINE_MS],
      ),
      a.page.evaluate((ms) => window.__blind.recv(ms), DEADLINE_MS),
    ]),
    DEADLINE_MS,
    "rendezvous and message exchange",
  );
  const connectedMs = Date.now() - connectStarted;

  if (gotAtB !== MESSAGE_AB)
    problems.push(
      `A->B was not byte-exact (${gotAtB.length} of ${MESSAGE_AB.length} chars)`,
    );
  if (gotAtA !== MESSAGE_BA)
    problems.push(
      `B->A was not byte-exact (${gotAtA.length} of ${MESSAGE_BA.length} chars)`,
    );

  const topologies = await Promise.all([
    a.page.evaluate(() => window.__blind.topology()),
    b.page.evaluate(() => window.__blind.topology()),
  ]);
  const faults = await Promise.all([
    a.page.evaluate(() => window.__blind.faults()),
    b.page.evaluate(() => window.__blind.faults()),
  ]);

  // The only privacy statement this run supports, and it is about THIS run:
  // neither store's parsed-body log contains the capability, the RoomContextId,
  // either stable Ed25519 key, or an SDP byte.
  const audits = await Promise.all([
    a.page.evaluate(() => window.__blind.audit()),
    b.page.evaluate(() => window.__blind.audit()),
  ]);
  const bodyLogs = ["a", "b"].map((name) => {
    try {
      return readFileSync(path.join(workspace, `${name}.bodies.log`), "utf8");
    } catch {
      return "";
    }
  });
  const needles = [];
  for (const audit of audits) {
    needles.push(["capability", audit.capabilityHex]);
    needles.push(["roomContextId", audit.roomContextIdHex]);
    needles.push(["stableKey", audit.stableKeyHex]);
    for (const [which, sdp] of [
      ["sdpLocal", audit.sdpLocalUtf8],
      ["sdpRemote", audit.sdpRemoteUtf8],
    ])
      if (sdp !== null)
        needles.push([which, Buffer.from(sdp, "utf8").toString("hex")]);
  }
  for (const [index, log] of bodyLogs.entries())
    for (const [name, hex] of needles)
      if (hex.length > 0 && log.includes(hex))
        problems.push(
          `store ${"ab"[index]} received ${name} in the clear in a request body`,
        );

  await Promise.all([
    a.page.evaluate(() => window.__blind.stop()),
    b.page.evaluate(() => window.__blind.stop()),
  ]);

  const at = (label, kind) => {
    const hit = events.find(
      (event) => event.page === label && event.kind === kind,
    );
    return hit === undefined ? null : hit.atMs;
  };
  const relative = (label, kind) => {
    const value = at(label, kind);
    return value === null
      ? "     —"
      : `${((value - connectStarted) / 1000).toFixed(1)}s`.padStart(6);
  };

  say("");
  say(
    `phase                     A       B     (seconds after both endpoints armed)`,
  );
  for (const kind of [
    "presence-published",
    "peer-observed",
    "hello-sent",
    "hello-opened",
    "accepted",
    "offer-sent",
    "offer-opened",
    "answered",
    "handoff",
    "webrtc-connected",
    "dtls-verified",
    "session-authenticated",
    "message-sent",
    "message-verified",
  ])
    say(`${kind.padEnd(24)} ${relative("A", kind)} ${relative("B", kind)}`);
  say("");
  say(`topology            A=${topologies[0]} B=${topologies[1]}`);
  say(
    `store request bodies logged   a=${bodyLogs[0].trimEnd().split("\n").filter(Boolean).length} b=${bodyLogs[1].trimEnd().split("\n").filter(Boolean).length}`,
  );
  say(
    `faults              A=${JSON.stringify(faults[0])} B=${JSON.stringify(faults[1])}`,
  );

  if (events.some((event) => event.kind === "failed"))
    problems.push("a pair edge reported the phase `failed`");
  for (const [index, topology] of topologies.entries())
    if (topology !== "multi-store-union")
      problems.push(`page ${"AB"[index]} topology is ${topology}`);

  if (problems.length > 0) {
    failed = true;
    say("");
    say(`TWO-STORE E2E FAILURE: ${problems.join("; ")}`);
  } else {
    say("");
    say(
      `TWO-STORE E2E PASS in ${(connectedMs / 1000).toFixed(1)}s ` +
        `(window ${WINDOW_MS}ms; ${MESSAGE_AB.length} bytes A→B and ` +
        `${MESSAGE_BA.length} bytes B→A decrypted byte-exact)`,
    );
  }
} catch (error) {
  failed = true;
  say("");
  say(`TWO-STORE E2E FAILURE: ${error.message}`);
  say("--- event log ---");
  for (const event of events)
    say(
      `  [${event.page}] +${((event.atMs - started) / 1000).toFixed(1)}s ${event.kind}` +
        (event.detail === undefined ? "" : ` — ${event.detail}`),
    );
} finally {
  if (browser !== null) await browser.close();
  pageServer.close();
  for (const child of children) child.kill("SIGKILL");
  rmSync(workspace, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
