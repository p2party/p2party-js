// Multi-scenario end-to-end driver for the flagged two-store blind-rendezvous
// prototype.
//
//   bash docs/e2e/blind-two-store/build.sh
//   PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
//     node docs/e2e/blind-two-store/run.mjs \
//       [--scenario=healthy|kill-a|withhold-a|unreachable-b-for-one|all] \
//       [--window-ms=4000] [--cohort=8] [--deadline-ms=180000]
//
// One scenario is the whole claim of the prototype, end to end and with nothing
// stubbed: two REAL store processes with fresh databases and fresh identity
// keys, two REAL headless-Chromium pages that share nothing but a 32-byte room
// capability, and no signaling server anywhere. Each page publishes PRESENCE
// through the stores it was given, discovers the other through any of them,
// completes IDENTITY_HELLO -> IDENTITY_ACCEPT -> TRANSPORT_OFFER ->
// TRANSPORT_ANSWER as pair-sealed operations the stores carry blind, connects
// WebRTC from the exchanged SDP, runs the protocol-v4 handshake over the data
// channel, and exchanges one encrypted application message each way, asserted
// byte-exact.
//
// The four scenarios differ only in what is done to the stores:
//
//   healthy               both stores honest and reachable throughout.
//   kill-a                store A is SIGKILLed once both pages have published
//                         presence and A has logged at least one request body;
//                         the kill is confirmed, not assumed — the child's exit
//                         is awaited and /health polled until it refuses.
//   withhold-a            store A runs P2PARTY_STORE_FAULT=withhold: it answers
//                         `stored` to every append and finalizes dummies.
//   unreachable-b-for-one page B is given ONLY store A's origin; page A is
//                         given both, so store B only ever sees page B's
//                         operations as page A's backfill.
//
// What a run may claim is exactly what it measured: "on this run, none of the
// audit's needles appeared in the N request bodies it searched" — N being the
// count it prints, which is the corpus the search actually saw and not the
// log's final size — "the rendezvous completed with store A killed /
// withholding", and "these are the measured times". Two store processes on one
// laptop are ONE fault domain: nothing here is evidence of independence, and
// nothing here earns a label.
import http from "node:http";
import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
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
const stringArgOf = (name, fallback) => {
  const hit = process.argv.find((value) => value.startsWith(`--${name}=`));
  return hit === undefined ? fallback : hit.slice(name.length + 3);
};

const SCENARIOS = ["healthy", "kill-a", "withhold-a", "unreachable-b-for-one"];

const REQUESTED = stringArgOf("scenario", "all");
if (REQUESTED !== "all" && !SCENARIOS.includes(REQUESTED)) {
  process.stderr.write(
    `unknown --scenario=${REQUESTED}; expected one of ${SCENARIOS.join(", ")}, all\n`,
  );
  process.exit(2);
}
const SELECTED = REQUESTED === "all" ? SCENARIOS : [REQUESTED];

// Project rule: nothing binds below 5000. Each scenario takes its own pair so a
// SIGKILLed store's port is never rebound by the next one.
const STORE_PORT_BASE = argOf("store-port-base", 5910);
const PAGE_PORT = argOf("page-port", 5920);
const WINDOW_MS = argOf("window-ms", 4000);
const DEADLINE_MS = argOf("deadline-ms", 180_000);
// The pinned profile's own value. `--cohort` rebuilds the geometry on both
// sides (see cohortPreload.ts) and is the only reason a store ever runs with a
// preload.
const PINNED_COHORT = 8;
const COHORT = argOf("cohort", null);

// A→B is deliberately multi-frame (the session's uniform chunk frame is
// 65,490 bytes) and B→A single-frame, so one run exercises both shapes of the
// app-lane framing in `prototype/index.ts`.
const MESSAGE_AB = `A->B ${"a".repeat(140_000)}`;
const MESSAGE_BA = `B->A ${"b".repeat(9_000)}`;

const say = (...parts) => process.stdout.write(parts.join(" ") + "\n");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const withTimeout = (promise, ms, label) => {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`TIMEOUT ${label} (${ms}ms)`)),
        ms,
      );
    }),
  ]);
};

const seconds = (ms) => `${(ms / 1000).toFixed(1)}s`;

/* ------------------------------------------------------------------ *
 * The privacy audit
 *
 * The store logs the exact bytes of every request body it accepts, BEFORE
 * parsing. The audit decodes that log and looks for each room secret in every
 * encoding the client could plausibly have used: the raw bytes, the ASCII of
 * the lower- and upper-case hex, the ASCII of base64 and base64url, and — for
 * text needles such as an SDP line — base64 at all three byte alignments, since
 * a marker embedded in a larger base64 blob starts wherever its offset mod 3
 * puts it.
 *
 * Three properties keep this from being theatre:
 *
 *  - a needle shorter than MIN_NEEDLE_BYTES is REFUSED, not searched. `v=0`
 *    alone is three bytes; a three-byte needle appears by chance about once per
 *    16 MB of ciphertext, and these logs are megabytes. The SDP session line is
 *    therefore searched as `v=0\r\n`, which is what Chromium actually emits.
 *  - a POSITIVE CONTROL runs against the same logs with the same matcher: the
 *    delivery-profile hash is a field of every allocation-token request body,
 *    so it MUST be found. A run where it is not found has a broken audit, and
 *    the scenario fails rather than reporting a vacuous pass.
 *  - the needle count is ASSERTED, not printed. A future edit that drops a
 *    secret or an encoding shrinks the search silently otherwise.
 *
 * What the audit does NOT cover, and what the verdict line must therefore not
 * imply:
 *
 *  - GET routes. The store's log call is inside the POST branch, so the chunk
 *    and checkpoint reads — whose coordinates live in the URL path — are never
 *    examined.
 *  - Bodies logged after the audit ran. The logs are read once, right after
 *    both pages report `message-verified` and before `stop()`, so the
 *    scheduled traffic of the windows that follow is outside the corpus. The
 *    verdict line reports the count the audit actually searched, which is why
 *    that count is carried out of the loop rather than re-read afterwards.
 * ------------------------------------------------------------------ */

/** Below this, a hit is as likely to be ciphertext as evidence. */
const MIN_NEEDLE_BYTES = 4;

/**
 * How many distinct byte needles a complete audit builds, asserted per run.
 *
 * 14 secrets — 4 SDP markers plus, per page, the capability, the
 * `RoomContextId`, the stable key and the two SDPs — at 11 encodings each
 * (raw, ASCII hex lower and upper, ASCII base64 and base64url, and base64 and
 * base64url at three alignments apiece), less the 6 alignment variants of the
 * 5-byte `v=0\r\n` marker whose stable cores fall under 8 characters:
 * 14 × 11 − 6 = 148.
 */
const EXPECTED_NEEDLE_COUNT = 148;

/**
 * The base64 of `bytes` at each of the three byte alignments, trimmed to the
 * characters that do not depend on the surrounding bytes.
 */
const base64Alignments = (bytes, urlSafe) => {
  const found = [];
  for (let pad = 0; pad < 3; pad += 1) {
    const encoded = Buffer.concat([Buffer.alloc(pad), bytes]).toString(
      urlSafe ? "base64url" : "base64",
    );
    // `pad + 1` leading characters carry bits of the padding; the final quantum
    // carries bits of whatever follows in the real stream.
    const core = encoded.slice(pad === 0 ? 0 : pad + 1, encoded.length - 4);
    if (core.length >= 8) found.push(Buffer.from(core, "ascii"));
  }
  return found;
};

/** Every encoding of one secret the harness will look for. */
const encodingsOf = (bytes) => {
  const hex = bytes.toString("hex");
  const variants = [
    ["raw", bytes],
    ["ascii-hex", Buffer.from(hex, "ascii")],
    ["ascii-HEX", Buffer.from(hex.toUpperCase(), "ascii")],
    ["ascii-base64", Buffer.from(bytes.toString("base64"), "ascii")],
    ["ascii-base64url", Buffer.from(bytes.toString("base64url"), "ascii")],
  ];
  for (const [index, core] of base64Alignments(bytes, false).entries())
    variants.push([`ascii-base64@${index}`, core]);
  for (const [index, core] of base64Alignments(bytes, true).entries())
    variants.push([`ascii-base64url@${index}`, core]);
  return variants.filter(([, buffer]) => buffer.length >= MIN_NEEDLE_BYTES);
};

/**
 * Read one store's body log as the exact byte strings that arrived.
 *
 * A missing or empty file is returned as such rather than as "no hits": a
 * privacy audit that passes because it read nothing is worse than none, so
 * every caller asserts on `bodies.length` before believing a clean result.
 */
const readBodyLog = (logPath) => {
  if (!existsSync(logPath)) return { exists: false, bytes: 0, bodies: [] };
  const bytes = statSync(logPath).size;
  const text = readFileSync(logPath, "utf8");
  const bodies = text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => Buffer.from(line, "hex"));
  return { exists: true, bytes, bodies };
};

const searchBodies = (bodies, needles) => {
  const hits = [];
  for (const { name, encodings } of needles)
    for (const [encoding, buffer] of encodings)
      for (const [index, body] of bodies.entries())
        if (body.indexOf(buffer) >= 0) {
          hits.push(`${name} (${encoding}) in body #${index}`);
          break;
        }
  return hits;
};

/* ------------------------------------------------------------------ *
 * Stores
 * ------------------------------------------------------------------ */

const STORE_SERVER = "src/blindRendezvous/prototype/store/storeServer.ts";
const COHORT_PRELOAD = path.join(dir, "cohortPreload.ts");

const startStore = (workspace, name, port, options, onError) => {
  const env = {
    ...process.env,
    P2PARTY_STORE_PROTOTYPE: "1",
    P2PARTY_STORE_OPEN_ALLOCATION: "1",
    P2PARTY_STORE_PORT: String(port),
    P2PARTY_STORE_DB: path.join(workspace, `${name}.sqlite`),
    P2PARTY_STORE_KEY_FILE: path.join(workspace, `${name}.key`),
    // The client rescales the same pinned profile by the same ratio, so both
    // sides derive one delivery-profile hash — i.e. one bucket.
    P2PARTY_STORE_WINDOW_MS: String(WINDOW_MS),
    P2PARTY_STORE_LOG_BODIES: path.join(workspace, `${name}.bodies.log`),
  };
  if (options.fault !== null) env.P2PARTY_STORE_FAULT = options.fault;
  if (COHORT !== null) env.P2PARTY_BLIND_COHORT = String(COHORT);

  // `--preload` must follow `run`, and its path must be absolute: bun resolves
  // a preload against the module resolver, not against cwd.
  const argv =
    COHORT === null
      ? ["run", STORE_SERVER]
      : ["run", "--preload", COHORT_PRELOAD, STORE_SERVER];
  const child = spawn("bun", argv, {
    cwd: root,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) =>
    say(`  [store ${name}] ${String(chunk).trimEnd()}`),
  );
  child.stderr.on("data", (chunk) =>
    say(`  [store ${name}!] ${String(chunk).trimEnd()}`),
  );
  // Without a listener a spawn failure (no `bun` on PATH, EAGAIN) is an
  // uncaught 'error' on the child: it escapes the scenario's try block, the
  // per-scenario finally never runs, and the sibling store is leaked.
  child.on("error", (error) =>
    onError(`store ${name} could not be spawned: ${error.message}`),
  );
  return child;
};

/**
 * Kill a store and confirm it is gone.
 *
 * Sending the signal is not the same as the process having stopped answering,
 * and the whole scenario after this point is a claim about a store that is not
 * there. Both are observed: the child's exit, and `/health` refusing.
 */
const killStore = async (child, name, port) => {
  const exited = new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once("exit", () => resolve());
  });
  child.kill("SIGKILL");
  await withTimeout(exited, 10_000, `store ${name} to exit after SIGKILL`);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await fetch(`http://127.0.0.1:${port}/health`);
    } catch {
      return; // The port refuses: the store really is gone.
    }
    await sleep(100);
  }
  throw new Error(`store ${name} still answered /health after SIGKILL`);
};

const waitHealthy = async (name, port) => {
  for (let attempt = 0; attempt < 160; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) {
        const body = await response.json();
        say(`store ${name} healthy on ${port} (storeId ${body.storeId})`);
        return body.storeId;
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
 *
 * `bundleFile` is a variable rather than a path because `--cohort` builds a
 * second bundle: `index.html` asks for `./bundle.js` and gets whichever build
 * this run is measuring.
 * ------------------------------------------------------------------ */

let bundleFile = path.join(dir, "bundle.js");

const mime = (name) =>
  name.endsWith(".js")
    ? "text/javascript"
    : name.endsWith(".wasm")
      ? "application/wasm"
      : "text/html";

const pageServer = http.createServer((request, response) => {
  const name = request.url === "/" ? "/index.html" : request.url.split("?")[0];
  const file = name === "/bundle.js" ? bundleFile : path.join(dir, name);
  try {
    response.writeHead(200, { "content-type": mime(name) });
    response.end(readFileSync(file));
  } catch {
    response.writeHead(404);
    response.end("not found");
  }
});

/* ------------------------------------------------------------------ *
 * One scenario
 * ------------------------------------------------------------------ */

const PHASES = [
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
];

/** Reported per page, relative to that page's own `presence-published`. */
const REPORTED_PHASES = [
  "peer-observed",
  "handoff",
  "session-authenticated",
  "message-verified",
];

/** How many `store-missed` lines to print per page before summarising. A dead
 * or withholding store produces one per scheduled event per window; they are
 * what diagnoses a stall, so they are recorded either way. */
const MISSED_PRINT_LIMIT = 3;

const scenarioConfig = {
  healthy: { faultA: null, originsB: "both", killA: false },
  "kill-a": { faultA: null, originsB: "both", killA: true },
  "withhold-a": { faultA: "withhold", originsB: "both", killA: false },
  "unreachable-b-for-one": { faultA: null, originsB: "a-only", killA: false },
};

const runScenario = async (name, index, profileInfo) => {
  const config = scenarioConfig[name];
  const portA = STORE_PORT_BASE + index * 2;
  const portB = portA + 1;
  const originA = `http://127.0.0.1:${portA}`;
  const originB = `http://127.0.0.1:${portB}`;

  const workspace = mkdtempSync(path.join(tmpdir(), `p2party-blind-${name}-`));
  const logPaths = {
    a: path.join(workspace, "a.bodies.log"),
    b: path.join(workspace, "b.bodies.log"),
  };
  const children = [];
  let browser = null;
  const problems = [];
  const events = [];
  const waiters = [];
  const missed = { A: 0, B: 0 };
  const refused = { A: 0, B: 0 };
  const requests = { A: { a: 0, b: 0 }, B: { a: 0, b: 0 } };
  const started = Date.now();
  const stamp = () => seconds(Date.now() - started).padStart(6);

  const note = (message) => problems.push(message);

  const push = (event) => {
    events.push(event);
    if (event.kind === "store-missed") {
      missed[event.page] += 1;
      if (missed[event.page] > MISSED_PRINT_LIMIT) return;
    }
    say(
      `  ${stamp()} [${event.page}] ${event.kind}` +
        (event.detail === undefined ? "" : ` — ${event.detail}`),
    );
  };

  const settleWaiters = () => {
    for (const waiter of [...waiters])
      if (waiter.predicate(events)) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.settle();
      }
  };

  const waitForEvents = (label, predicate, timeoutMs) =>
    new Promise((resolve, reject) => {
      if (predicate(events)) return resolve();
      const waiter = {
        predicate,
        settle: () => {
          clearTimeout(timer);
          resolve();
        },
      };
      const timer = setTimeout(() => {
        const at = waiters.indexOf(waiter);
        if (at >= 0) waiters.splice(at, 1);
        reject(new Error(`TIMEOUT waiting for ${label} (${timeoutMs}ms)`));
      }, timeoutMs);
      waiters.push(waiter);
    });

  const capability = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  const capabilityHex = capability.toString("hex");

  const openPage = async (label, origins) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on("pageerror", (error) =>
      say(`  [${label} pageerror] ${error.message}`),
    );
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      // A killed store refuses every scheduled request for the rest of the run;
      // Chromium logs one line each and they would bury the event stream.
      if (message.text().includes("Failed to load resource")) {
        refused[label] += 1;
        return;
      }
      say(`  [${label} console.error] ${message.text()}`);
    });
    // Counted here rather than at the store, because the store only logs POST
    // bodies: this is the only place the GET reads are visible at all.
    page.on("request", (request) => {
      const url = request.url();
      if (url.startsWith(`${originA}/`)) requests[label].a += 1;
      else if (url.startsWith(`${originB}/`)) requests[label].b += 1;
    });
    await page.exposeFunction("__blindEvent", (json) => {
      push({ page: label, ...JSON.parse(json) });
      settleWaiters();
    });
    await page.goto(`http://localhost:${PAGE_PORT}/`);
    await withTimeout(
      page.waitForFunction("window.__blind !== undefined", null, {
        timeout: 30_000,
      }),
      31_000,
      `${label} bundle load`,
    );
    return { label, context, page, origins };
  };

  const timings = {};
  let connectedMs = null;
  let result = null;

  say("");
  say(
    `=== scenario ${name} (window ${WINDOW_MS}ms, cohort ${profileInfo.cohortAllocationsPerWindow}, ports ${portA}/${portB}) ===`,
  );

  try {
    children.push(
      startStore(workspace, "a", portA, { fault: config.faultA }, note),
    );
    children.push(startStore(workspace, "b", portB, { fault: null }, note));
    const [storeIdA, storeIdB] = await Promise.all([
      waitHealthy("a", portA),
      waitHealthy("b", portB),
    ]);
    if (storeIdA === storeIdB)
      note("both store processes reported the same storeId");

    // `--disable-features=WebRtcHideLocalIpsWithMdns` is required, not
    // cosmetic: Chromium otherwise replaces host candidates with
    // `<uuid>.local` mDNS names this sandbox cannot resolve, and because the
    // blind profile is COMPLETE gathering (one SDP blob, no trickle) an
    // unresolvable candidate is simply dropped — both connections then sit at
    // "new" forever.
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-features=WebRtcHideLocalIpsWithMdns"],
    });

    const originsForA = [originA, originB];
    const originsForB =
      config.originsB === "a-only" ? [originA] : [originA, originB];
    const [a, b] = await Promise.all([
      openPage("A", originsForA),
      openPage("B", originsForB),
    ]);
    say(
      `both pages loaded (capability ${capabilityHex.slice(0, 16)}…; ` +
        `A sees ${originsForA.length} store(s), B sees ${originsForB.length})`,
    );

    const optionsFor = (origins) =>
      JSON.stringify({
        capabilityHex,
        storeOrigins: origins,
        rtcConfig: { iceServers: [] },
        deliveryWindowMs: String(WINDOW_MS),
      });

    const armed = Date.now();
    await Promise.all([
      a.page.evaluate(
        (json) => window.__blind.run(json),
        optionsFor(originsForA),
      ),
      b.page.evaluate(
        (json) => window.__blind.run(json),
        optionsFor(originsForB),
      ),
    ]);
    say(`${stamp()} both endpoints armed; delivery window ${WINDOW_MS}ms`);

    if (config.killA) {
      // The brief's trigger is "both pages have reported presence-published".
      // One more condition is added on purpose: store A must have logged at
      // least one request body, so the privacy statement about A is about
      // bytes A actually received rather than about an empty file.
      await waitForEvents(
        "both pages to publish presence",
        (seen) =>
          ["A", "B"].every((page) =>
            seen.some(
              (event) =>
                event.page === page && event.kind === "presence-published",
            ),
          ),
        60_000,
      );
      const deadline = Date.now() + 30_000;
      while (readBodyLog(logPaths.a).bodies.length === 0) {
        if (Date.now() > deadline)
          throw new Error("store a logged no request body before the kill");
        await sleep(100);
      }
      const carried = readBodyLog(logPaths.a).bodies.length;
      const pid = children[0].pid;
      await killStore(children[0], "a", portA);
      say(
        `${stamp()} SIGKILL store a (pid ${pid}) after both presence-published and ${carried} logged bodies; process exited and ${originA}/health now refuses`,
      );
    }

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
      `${name}: rendezvous and message exchange`,
    );
    connectedMs = Date.now() - armed;

    /*
     * Compared as bytes, not as strings.
     *
     * The page hands back the decoded text, so the comparison re-encodes it as
     * UTF-8 and compares buffers. That is a genuine byte statement rather than
     * a text one: UTF-8 encode/decode is injective on well-formed input, and
     * bytes that were NOT well-formed would have decoded to U+FFFD and
     * re-encoded to EF BF BD, which does not match. Equal buffers therefore
     * mean the plaintext the peer decrypted was the plaintext that was sent.
     * The receiver's own reported byte count is checked below as well.
     */
    const sentAB = Buffer.from(MESSAGE_AB, "utf8");
    const sentBA = Buffer.from(MESSAGE_BA, "utf8");
    if (!Buffer.from(gotAtB, "utf8").equals(sentAB))
      note(
        `A->B was not byte-exact (${Buffer.byteLength(gotAtB, "utf8")} of ${sentAB.length} bytes)`,
      );
    if (!Buffer.from(gotAtA, "utf8").equals(sentBA))
      note(
        `B->A was not byte-exact (${Buffer.byteLength(gotAtA, "utf8")} of ${sentBA.length} bytes)`,
      );

    const [topologies, faults, counters, audits] = await Promise.all([
      Promise.all([
        a.page.evaluate(() => window.__blind.topology()),
        b.page.evaluate(() => window.__blind.topology()),
      ]),
      Promise.all([
        a.page.evaluate(() => window.__blind.faults()),
        b.page.evaluate(() => window.__blind.faults()),
      ]),
      Promise.all([
        a.page.evaluate(() => window.__blind.counters()),
        b.page.evaluate(() => window.__blind.counters()),
      ]),
      Promise.all([
        a.page.evaluate(() => window.__blind.audit()),
        b.page.evaluate(() => window.__blind.audit()),
      ]),
    ]);

    /* ---------------- the privacy audit ---------------- */

    const needles = [
      {
        name: "sdp-marker a=fingerprint",
        encodings: encodingsOf(Buffer.from("a=fingerprint", "utf8")),
      },
      {
        name: "sdp-marker a=candidate",
        encodings: encodingsOf(Buffer.from("a=candidate", "utf8")),
      },
      {
        name: "sdp-marker a=ice-ufrag",
        encodings: encodingsOf(Buffer.from("a=ice-ufrag", "utf8")),
      },
      // `v=0` on its own is three bytes and hits random ciphertext about once
      // per 16 MB; the session line as Chromium emits it is five.
      {
        name: "sdp-marker v=0CRLF",
        encodings: encodingsOf(Buffer.from("v=0\r\n", "utf8")),
      },
    ];
    // A secret that arrived short or empty would be filtered out of the needle
    // set and audited as "not found"; refuse it instead.
    const pushSecret = (label, hex) => {
      const bytes = Buffer.from(hex ?? "", "hex");
      if (bytes.length < 32) {
        note(
          `${label} is ${bytes.length} bytes, not a 32-byte secret to audit`,
        );
        return;
      }
      needles.push({ name: label, encodings: encodingsOf(bytes) });
    };

    for (const [which, audit] of [
      ["A", audits[0]],
      ["B", audits[1]],
    ]) {
      // The one value the harness can confirm independently: it generated it.
      if (audit.capabilityHex !== capabilityHex)
        note(
          `page ${which} audits a capability that is not the one this run generated`,
        );
      pushSecret(`${which} capability`, audit.capabilityHex);
      pushSecret(`${which} roomContextId`, audit.roomContextIdHex);
      pushSecret(`${which} stableKey`, audit.stableKeyHex);
      for (const [label, sdp] of [
        ["sdpLocal", audit.sdpLocalUtf8],
        ["sdpRemote", audit.sdpRemoteUtf8],
      ]) {
        // Symmetric with pushSecret: a null, empty or implausibly short SDP is
        // refused rather than filtered out of the needle set and audited clean.
        // The smallest SDP Chromium emits for one data channel is ~600 bytes.
        const bytes = sdp === null ? null : Buffer.from(sdp, "utf8");
        if (bytes === null || bytes.length < 64) {
          note(
            `page ${which} has no usable ${label} to audit (${bytes === null ? "null" : `${bytes.length} bytes`})`,
          );
          continue;
        }
        needles.push({
          name: `${which} ${label}`,
          encodings: encodingsOf(bytes),
        });
      }
    }
    const needleCount = needles.reduce(
      (total, needle) => total + needle.encodings.length,
      0,
    );
    // Asserted rather than printed: an edit that drops a secret or an encoding
    // would otherwise shrink the search and still report a clean audit.
    if (needleCount !== EXPECTED_NEEDLE_COUNT)
      note(
        `the audit built ${needleCount} needles over ${needles.length} secrets, expected ${EXPECTED_NEEDLE_COUNT}`,
      );

    const control = [
      {
        name: "positive control: deliveryProfileHash",
        encodings: encodingsOf(
          Buffer.from(profileInfo.deliveryProfileHash, "hex"),
        ),
      },
    ];

    const auditLines = [];
    // The corpus the verdict line is allowed to talk about. Counted HERE, from
    // the very buffers that were searched — a second read afterwards would
    // include bodies logged while the audit ran, which nothing searched.
    const audited = { a: 0, b: 0 };
    for (const [which, logPath] of [
      ["a", logPaths.a],
      ["b", logPaths.b],
    ]) {
      const log = readBodyLog(logPath);
      // A log that is missing, empty, or unparsed makes every "not found"
      // below meaningless. Fail, do not pass quietly.
      if (!log.exists) {
        note(`store ${which} wrote no P2PARTY_STORE_LOG_BODIES file`);
        continue;
      }
      if (log.bytes === 0 || log.bodies.length === 0) {
        note(`store ${which} logged zero request bodies; its audit is vacuous`);
        continue;
      }
      if (searchBodies(log.bodies, control).length === 0)
        note(
          `store ${which}: the positive control (deliveryProfileHash) was not found in ${log.bodies.length} bodies — the audit is not reading what it thinks it is`,
        );
      const hits = searchBodies(log.bodies, needles);
      for (const hit of hits) note(`store ${which} received ${hit}`);
      audited[which] = log.bodies.length;
      auditLines.push(
        `  store ${which}: ${log.bodies.length} bodies (${log.bytes} log bytes), ` +
          `${needleCount} needles over ${needles.length} secrets, ${hits.length} found`,
      );
    }

    /* ---------------- assertions ---------------- */

    const has = (page, kind) =>
      events.some((event) => event.page === page && event.kind === kind);
    const detailsOf = (page, kind) =>
      events
        .filter((event) => event.page === page && event.kind === kind)
        .map((event) => event.detail ?? "");

    for (const page of ["A", "B"]) {
      if (!has(page, "message-verified"))
        note(`page ${page} never reported message-verified`);
      if (!has(page, "session-authenticated"))
        note(`page ${page} never reported session-authenticated`);
      // Printed but never asserted before Task 9: a run where both sides
      // reported `dtls-unsupported` used to exit 0.
      if (!has(page, "dtls-verified"))
        note(
          `page ${page} never reported dtls-verified` +
            (has(page, "dtls-unsupported")
              ? " (it reported dtls-unsupported)"
              : ""),
        );
      if (has(page, "failed")) note(`page ${page} reported the phase failed`);
      if (has(page, "session-failed"))
        note(`page ${page} reported session-failed`);
    }

    const connectedCount = (page) => detailsOf(page, "store-connected").length;
    if (connectedCount("A") !== originsForA.length)
      note(
        `page A connected ${connectedCount("A")} stores, expected ${originsForA.length}`,
      );
    if (connectedCount("B") !== originsForB.length)
      note(
        `page B connected ${connectedCount("B")} stores, expected ${originsForB.length}`,
      );

    const faultsAgainst = (which, storeId) =>
      faults[which === "A" ? 0 : 1].filter(
        (fault) => fault.storeIdHex === storeId,
      );
    const allFaults = [...faults[0], ...faults[1]];
    const missedAgainstA = ["A", "B"].some((page) =>
      detailsOf(page, "store-missed").some((detail) =>
        detail.startsWith(storeIdA),
      ),
    );

    if (name === "healthy") {
      for (const [index2, topology] of topologies.entries())
        if (topology !== "multi-store-union")
          note(`page ${"AB"[index2]} topology is ${topology}`);
      if (allFaults.length !== 0)
        note(`healthy run recorded faults: ${JSON.stringify(allFaults)}`);
      for (const page of ["A", "B"])
        if (has(page, "store-unreachable"))
          note(`page ${page} reported store-unreachable on the healthy path`);
    }

    if (name === "kill-a") {
      for (const [index2, topology] of topologies.entries())
        if (topology !== "single-carrier-dependent")
          note(
            `page ${"AB"[index2]} topology is ${topology}, expected single-carrier-dependent`,
          );
      if (
        !missedAgainstA &&
        faultsAgainst("A", storeIdA).length === 0 &&
        faultsAgainst("B", storeIdA).length === 0
      )
        note("no page recorded a fault or an unreachable event for store a");
      // Asserted exactly, and this is now a sharp assertion rather than a
      // permissive one. Since `f1f5aa4` a store that is merely switched off
      // files as fault kind `unreachable`; `signature-invalid` is reserved for
      // an answer that arrived, decoded and carried a signature this client
      // could judge. A SIGKILLed store must therefore produce ONLY
      // `unreachable`, and the honest store b must produce nothing at all — so
      // any other kind here, or any fault naming b, is a real regression.
      const unexpected = allFaults.filter(
        (fault) =>
          fault.storeIdHex !== storeIdA || fault.kind !== "unreachable",
      );
      if (unexpected.length !== 0)
        note(
          `kill-a recorded faults other than "unreachable" against store a: ${JSON.stringify(unexpected)}`,
        );
    }

    if (name === "withhold-a") {
      const breaches = allFaults.filter(
        (fault) =>
          fault.kind === "custody-breach" && fault.storeIdHex === storeIdA,
      );
      if (breaches.length === 0)
        note("no page recorded a custody-breach against store a");
      const unexpected = allFaults.filter(
        (fault) =>
          fault.storeIdHex !== storeIdA || fault.kind !== "custody-breach",
      );
      if (unexpected.length !== 0)
        note(
          `withhold-a recorded faults other than a custody-breach against store a: ${JSON.stringify(unexpected)}`,
        );
      // A custody-breach marks the store inert, and an inert store stops
      // counting towards this page's carriage. That is the observable
      // consequence the harness can assert from outside.
      for (const [index2, topology] of topologies.entries())
        if (topology !== "single-carrier-dependent")
          note(
            `page ${"AB"[index2]} topology is ${topology}, expected single-carrier-dependent after store a went inert`,
          );
    }

    if (name === "unreachable-b-for-one") {
      if (topologies[0] !== "multi-store-union")
        note(`page A topology is ${topologies[0]}, expected multi-store-union`);
      if (topologies[1] !== "single-carrier-dependent")
        note(
          `page B topology is ${topologies[1]}, expected single-carrier-dependent`,
        );
      if (counters[0].backfills < 1)
        note(
          "page A recorded no backfill, so store b was never given page B's operations",
        );
      if (requests.B.b !== 0)
        note(`page B made ${requests.B.b} requests to store b, expected none`);
      if (allFaults.length !== 0)
        note(
          `unreachable-b-for-one recorded faults: ${JSON.stringify(allFaults)}`,
        );
    }

    /* ---------------- report ---------------- */

    const at = (page, kind) => {
      const hit = events.find(
        (event) => event.page === page && event.kind === kind,
      );
      return hit === undefined ? null : hit.atMs;
    };
    for (const page of ["A", "B"]) {
      const base = at(page, "presence-published");
      timings[page] = Object.fromEntries(
        PHASES.map((kind) => {
          const value = at(page, kind);
          return [kind, base === null || value === null ? null : value - base];
        }),
      );
    }

    const cell = (page, kind) => {
      const value = timings[page][kind];
      return value === null ? "—" : seconds(value);
    };
    const widths = REPORTED_PHASES.map((kind) => Math.max(kind.length, 8));
    say("");
    say("time from this page's own presence-published to each milestone");
    say(
      `  page  ${REPORTED_PHASES.map((kind, index) => kind.padStart(widths[index])).join("  ")}`,
    );
    for (const page of ["A", "B"])
      say(
        `     ${page}  ${REPORTED_PHASES.map((kind, index) => cell(page, kind).padStart(widths[index])).join("  ")}`,
      );
    say("");
    say(
      "full per-phase timings (seconds after that page's presence-published)",
    );
    for (const kind of PHASES)
      say(
        `  ${kind.padEnd(24)} A=${cell("A", kind).padStart(7)} B=${cell("B", kind).padStart(7)}`,
      );
    say("");
    say(
      `requests issued by page   A: a=${requests.A.a} b=${requests.A.b}   B: a=${requests.B.a} b=${requests.B.b}`,
    );
    say(
      `store-missed events       A=${missed.A} B=${missed.B}   (browser "failed to load" lines A=${refused.A} B=${refused.B})`,
    );
    // Absence and misbehaviour are separate kinds since `f1f5aa4`, so the two
    // populations are reported separately: a store that stopped answering is
    // not being accused of anything, and neither kind marks a store inert.
    const absent = [...faults[0], ...faults[1]].filter(
      (fault) => fault.kind === "unreachable",
    );
    const blamed = [...faults[0], ...faults[1]].filter(
      (fault) => fault.kind === "signature-invalid",
    );
    if (absent.length > 0 || blamed.length > 0)
      say(
        `note                      ${absent.length} record(s) of kind "unreachable" (a store that did not answer; ` +
          `not an accusation, and does not mark it inert) and ${blamed.length} of "signature-invalid" ` +
          `(an answer that arrived and did not verify)`,
      );
    say("privacy audit of the logged request bodies");
    for (const line of auditLines) say(line);
    say(`topology                  A=${topologies[0]} B=${topologies[1]}`);
    // Grouped: a withholding store produces one custody-breach per breached
    // slot per window, and the wall of JSON hides the one fact that matters.
    const summariseFaults = (list) => {
      if (list.length === 0) return "none";
      const groups = new Map();
      for (const fault of list) {
        const key = `${fault.kind} vs ${fault.storeIdHex.slice(0, 16)}…`;
        groups.set(key, (groups.get(key) ?? 0) + 1);
      }
      return [...groups].map(([key, count]) => `${count}× ${key}`).join(", ");
    };
    say(
      `faults                    A: ${summariseFaults(faults[0])}   B: ${summariseFaults(faults[1])}`,
    );
    for (const [which, list] of [
      ["A", faults[0]],
      ["B", faults[1]],
    ])
      if (list.length > 0)
        say(
          `  ${which} first fault           w${list[0].window}: ${list[0].detail}`,
        );
    say(`counters                  A=${JSON.stringify(counters[0])}`);
    say(`                          B=${JSON.stringify(counters[1])}`);

    result = {
      topologies,
      faults,
      counters,
      requests,
      bodies: audited,
      needleCount,
    };

    await Promise.all([
      a.page.evaluate(() => window.__blind.stop()),
      b.page.evaluate(() => window.__blind.stop()),
    ]);
  } catch (error) {
    note(error.message);
    say("");
    say(`--- event log (${events.length} events) ---`);
    for (const event of events)
      say(
        `  [${event.page}] ${seconds(event.atMs - started).padStart(6)} ${event.kind}` +
          (event.detail === undefined ? "" : ` — ${event.detail}`),
      );
  } finally {
    // Teardown runs on every path, including a thrown assertion: a leaked
    // Chromium or a leaked store would poison the next scenario's ports.
    if (browser !== null) await browser.close().catch(() => undefined);
    for (const child of children) child.kill("SIGKILL");
    rmSync(workspace, { recursive: true, force: true });
  }

  const ok = problems.length === 0;
  say("");
  say(
    ok
      ? `SCENARIO ${name} PASS in ${seconds(connectedMs ?? 0)} — ` +
          `${Buffer.byteLength(MESSAGE_AB)} bytes A→B and ${Buffer.byteLength(MESSAGE_BA)} bytes B→A decrypted byte-exact; ` +
          `topology A=${result.topologies[0]} B=${result.topologies[1]}; ` +
          `0 of ${result.needleCount} needles found in the ${result.bodies.a + result.bodies.b} request bodies the audit searched`
      : `SCENARIO ${name} FAIL — ${problems.join("; ")}`,
  );

  return {
    name,
    ok,
    connectedMs,
    timings,
    problems,
    ...(result ?? {}),
  };
};

/* ------------------------------------------------------------------ *
 * Run
 * ------------------------------------------------------------------ */

/** Bounded, because a `bun` that hangs here hangs the whole harness before a
 * single scenario has started and nothing downstream has a deadline yet. */
const BUN_TOOL_TIMEOUT_MS = 120_000;

const bunJson = (argv, env) =>
  new Promise((resolve, reject) => {
    const child = spawn("bun", argv, {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(
          `TIMEOUT bun ${argv.join(" ")} (${BUN_TOOL_TIMEOUT_MS}ms): ${err.trim()}`,
        ),
      );
    }, BUN_TOOL_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => (out += String(chunk)));
    child.stderr.on("data", (chunk) => (err += String(chunk)));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(
        new Error(`bun ${argv.join(" ")} could not start: ${error.message}`),
      );
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(out);
      else
        reject(
          new Error(`bun ${argv.join(" ")} failed (${code}): ${err.trim()}`),
        );
    });
  });

const PROFILE_TOOL = "docs/e2e/blind-two-store/profileTool.ts";

let failed = false;
try {
  const cohortEnv =
    COHORT === null ? {} : { P2PARTY_BLIND_COHORT: String(COHORT) };
  const profileArgv =
    COHORT === null
      ? ["run", PROFILE_TOOL, "info", `--window-ms=${WINDOW_MS}`]
      : [
          "run",
          "--preload",
          COHORT_PRELOAD,
          PROFILE_TOOL,
          "info",
          `--window-ms=${WINDOW_MS}`,
        ];
  const profileInfo = JSON.parse(await bunJson(profileArgv, cohortEnv));

  // The cohort override is a loader rewrite, not an option: if it silently did
  // not apply, every number this run reports would be attributed to a geometry
  // it never used. The rewrite is only trusted once the rebuilt profile says
  // what was asked for.
  if (COHORT !== null && profileInfo.cohortAllocationsPerWindow !== COHORT)
    throw new Error(
      `--cohort=${COHORT} did not take: the rebuilt profile carries cohortAllocationsPerWindow=${profileInfo.cohortAllocationsPerWindow}`,
    );

  if (COHORT !== null) {
    bundleFile = path.join(dir, `bundle.cohort-${COHORT}.js`);
    await bunJson(
      ["run", PROFILE_TOOL, "build", `--out=${bundleFile}`],
      cohortEnv,
    );
    say(`built ${path.basename(bundleFile)} for cohort ${COHORT}`);
  }
  if (!existsSync(bundleFile))
    throw new Error(`${bundleFile} is missing; run build.sh first`);

  say(
    `delivery profile: window ${profileInfo.deliveryWindowMs}ms, ` +
      `cohort ${profileInfo.cohortAllocationsPerWindow}, ` +
      `chunks/window ${profileInfo.sizeClasses.map((c) => c.publicChunksPerWindow).join("+")}, ` +
      `hash ${profileInfo.deliveryProfileHash.slice(0, 16)}…`,
  );
  say(
    `per client per store per window: appends ${profileInfo.appendedBytesPerWindow} bytes, ` +
      `full scan ${profileInfo.scannedBytesPerWindow} bytes` +
      (COHORT !== null && COHORT !== PINNED_COHORT
        ? "  (NOT the pinned geometry — a measurement profile)"
        : ""),
  );

  await new Promise((resolve) => pageServer.listen(PAGE_PORT, resolve));
  say(`page server on http://localhost:${PAGE_PORT}/`);

  const results = [];
  for (const [index, name] of SELECTED.entries())
    results.push(await runScenario(name, index, profileInfo));

  say("");
  say(
    `=== summary (window ${WINDOW_MS}ms, cohort ${profileInfo.cohortAllocationsPerWindow}, scan ${profileInfo.scannedBytesPerWindow} B/store/window) ===`,
  );
  say(
    "scenario                 verdict   connect   A:peer→verified   B:peer→verified   topology A / B",
  );
  for (const outcome of results) {
    const span = (page) => {
      const observed = outcome.timings?.[page]?.["peer-observed"];
      const verified = outcome.timings?.[page]?.["message-verified"];
      return observed === undefined ||
        observed === null ||
        verified === null ||
        verified === undefined
        ? "—"
        : `${seconds(observed)}→${seconds(verified)}`;
    };
    say(
      `${outcome.name.padEnd(24)} ${(outcome.ok ? "PASS" : "FAIL").padEnd(9)} ` +
        `${seconds(outcome.connectedMs ?? 0).padStart(7)}   ${span("A").padStart(15)}   ${span("B").padStart(15)}   ` +
        `${outcome.topologies === undefined ? "—" : `${outcome.topologies[0]} / ${outcome.topologies[1]}`}`,
    );
  }
  say("");
  for (const outcome of results)
    if (!outcome.ok) {
      failed = true;
      say(`FAIL ${outcome.name}: ${outcome.problems.join("; ")}`);
    }
  say(
    failed
      ? `TWO-STORE E2E FAILURE (${results.filter((r) => !r.ok).length} of ${results.length} scenarios)`
      : `TWO-STORE E2E PASS (${results.length} of ${results.length} scenarios)`,
  );
} catch (error) {
  failed = true;
  say("");
  say(`TWO-STORE E2E FAILURE: ${error.stack ?? error.message}`);
} finally {
  pageServer.close();
}
process.exit(failed ? 1 : 0);
