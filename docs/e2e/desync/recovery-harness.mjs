// Shared real-browser fixture for the remaining recovery regressions. It owns
// every listener/process it starts and archives both success and failure.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { diagnosticProblems } from "./desync-verdict.mjs";

export const dir = path.dirname(fileURLToPath(import.meta.url));
process.env.PLAYWRIGHT_BROWSERS_PATH ??= path.join(
  os.homedir(),
  "Library/Caches/ms-playwright",
);
const playwright = await import(
  new URL(
    "../../../../p2party.com/node_modules/playwright-core/index.js",
    import.meta.url,
  )
);
const { chromium } = playwright.default ?? playwright;
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");
export async function bounded(promise, ms, description) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${description} exceeded ${ms}ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function eventually(
  description,
  sample,
  predicate,
  timeoutMs = 30000,
  intervalMs = 200,
) {
  const start = Date.now();
  let last;
  do {
    last = await bounded(sample(), 8000, `${description}: sample`);
    if (predicate(last)) return { elapsedMs: Date.now() - start, value: last };
    await sleep(intervalMs);
  } while (Date.now() - start < timeoutMs);
  throw new Error(
    `${description} timed out after ${timeoutMs}ms; last=${JSON.stringify(last)}`,
  );
}

export function parseFlags(allowed) {
  const flags = {};
  for (const argument of process.argv.slice(2)) {
    const match = /^--([a-z][a-z0-9-]*)=(.+)$/.exec(argument);
    assert(
      match && allowed.includes(match[1]),
      `Unknown or malformed argument: ${argument}`,
    );
    assert(!(match[1] in flags), `Duplicate flag: ${match[1]}`);
    flags[match[1]] = match[2];
  }
  return flags;
}

export async function fixture(name, flags = {}) {
  assert(
    flags.legacy === undefined || flags.legacy === "receiver",
    "legacy must be receiver when specified",
  );
  assert(
    flags.legacy === undefined || flags.before !== "1",
    "legacy=receiver requires a current sender; use before=1 alone for both archived peers",
  );
  const port = Number(flags.port ?? 5880);
  assert(Number.isInteger(port) && port > 5000 && port < 65000);
  const run = flags.run ?? new Date().toISOString().replaceAll(":", "-");
  assert(/^[a-zA-Z0-9_.-]+$/.test(run));
  const output = path.resolve(dir, "../runs", `${name}-${run}.json`);
  assert(!existsSync(output), `Refusing to overwrite ${output}`);
  mkdirSync(path.dirname(output), { recursive: true });
  const files = Object.fromEntries(
    ["app.html", "app-bundle.js", "worker-inject.js", "libcrypto.wasm"].map(
      (file) => [file, path.join(dir, file)],
    ),
  );
  if (flags.before === "1") {
    for (const file of ["app-bundle.js", "worker-inject.js", "libcrypto.wasm"])
      files[file] = path.resolve(
        dir,
        "../runs/followups-2026-09-08",
        `before-${file}`,
      );
  } else
    assert(
      flags.before === undefined || flags.before === "0",
      "before must be 0 or 1",
    );
  if (flags.legacy === "receiver") {
    // Both versions use the same harness HTML. Its relative script URLs keep
    // every receiver SDK asset under /legacy/, including after page.reload().
    files["legacy/app.html"] = files["app.html"];
    for (const file of ["app-bundle.js", "worker-inject.js", "libcrypto.wasm"])
      files[`legacy/${file}`] = path.resolve(
        dir,
        "../runs/followups-2026-09-08",
        `before-${file}`,
      );
  }
  const inputFiles = {
    ...files,
    "relay.ts": path.join(dir, "relay.ts"),
    "recovery-harness.mjs": fileURLToPath(import.meta.url),
    [path.basename(process.argv[1])]: path.resolve(process.argv[1]),
  };
  const hashes = () =>
    Object.fromEntries(
      Object.entries(inputFiles).map(([name, file]) => [
        name,
        sha256(readFileSync(file)),
      ]),
    );
  const report = {
    scenario: name,
    run,
    flags,
    started: new Date().toISOString(),
    inputs: hashes(),
    events: [],
    pageErrors: [],
    relayLog: [],
    console: {},
    peerAssets: {},
    passed: false,
  };
  const event = (type, data = {}) => {
    const entry = { at: new Date().toISOString(), type, ...data };
    report.events.push(entry);
    console.log(JSON.stringify(entry));
  };
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname.slice(1);
    const name = pathname.endsWith("/")
      ? `${pathname}app.html`
      : pathname || "app.html";
    const file = files[name];
    if (!file) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, {
      "content-type": name.endsWith(".wasm")
        ? "application/wasm"
        : name.endsWith(".js")
          ? "text/javascript"
          : "text/html",
      "cache-control": "no-store",
    });
    res.end(readFileSync(file));
  });
  let relay,
    browser,
    closed = false;
  const peers = [];
  async function close(error) {
    if (closed) return;
    closed = true;
    if (error) report.error = error.stack ?? String(error);
    report.finished = new Date().toISOString();
    report.inputsUnchanged =
      JSON.stringify(hashes()) === JSON.stringify(report.inputs);
    if (!report.inputsUnchanged || report.pageErrors.length)
      report.passed = false;
    await browser?.close().catch(() => undefined);
    if (relay && relay.exitCode === null && !relay.signalCode) {
      const exited = new Promise((resolve) => relay.once("exit", resolve));
      relay.kill("SIGTERM");
      await bounded(exited, 5000, "relay termination").catch(() =>
        relay.kill("SIGKILL"),
      );
    }
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
    console.log(`${report.passed ? "PASS" : "FAIL"}: ${output}`);
    process.exitCode = report.passed ? 0 : 1;
  }
  for (const signal of ["SIGINT", "SIGTERM"])
    process.once(signal, () => {
      void close(new Error(`Interrupted by ${signal}`));
    });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
    relay = spawn("bun", [path.join(dir, "relay.ts")], {
      env: {
        ...process.env,
        RELAY_PORT: String(port + 1),
        RELAY_PEERID_MODE: "stable",
        RELAY_STRIP_SOCKET_GENERATION: "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    for (const stream of [relay.stdout, relay.stderr])
      stream.on("data", (data) => {
        report.relayLog.push(String(data));
      });
    await Promise.race([
      sleep(750),
      new Promise((_, reject) => {
        relay.once("error", reject);
        relay.once("exit", (code, signal) =>
          reject(new Error(`Owned relay exited: ${code}/${signal}`)),
        );
      }),
    ]);
    assert(
      relay.exitCode === null && !relay.signalCode,
      "Owned relay must be alive",
    );
    browser = await chromium.launch({
      headless: true,
      args: ["--disable-features=WebRtcHideLocalIpsWithMdns"],
    });
  } catch (error) {
    await close(error);
    throw error;
  }
  const appUrl = `http://127.0.0.1:${port}`;
  const wsUrl = `ws://127.0.0.1:${port + 1}/ws`;
  const room = randomBytes(32).toString("hex");
  const ctl = async (command) => {
    const response = await fetch(
      `http://127.0.0.1:${port + 1}/ctl/${command}`,
      { method: command === "registry" || command === "log" ? "GET" : "POST" },
    );
    assert(response.ok, `Relay control failed: ${command}: ${response.status}`);
    return response.json();
  };
  async function boot(peer, navigate = true) {
    if (navigate) await peer.page.goto(`${peer.assetUrl}/`);
    await peer.page.waitForFunction(() => !!window.__app, null, {
      timeout: 20000,
    });
    await peer.page.evaluate(
      (url) => window.__app.boot(url),
      `${peer.assetUrl}/libcrypto.wasm`,
    );
  }
  async function createPeer(name, context) {
    context ??= await browser.newContext();
    const page = await context.newPage();
    const legacy = flags.legacy === "receiver" && name === "B";
    const prefix = legacy ? "legacy/" : "";
    const assetUrl = legacy ? `${appUrl}/legacy` : appUrl;
    const peer = { name, context, page, assetUrl };
    report.peerAssets[name] = {
      assetUrl,
      archived: legacy || flags.before === "1",
      inputs: Object.fromEntries(
        ["app.html", "app-bundle.js", "worker-inject.js", "libcrypto.wasm"].map(
          (file) => [file, report.inputs[`${prefix}${file}`]],
        ),
      ),
    };
    report.console[name] = [];
    page.on("pageerror", (error) =>
      report.pageErrors.push({ name, message: error.message }),
    );
    page.on("console", (message) => {
      if (report.console[name].length < 20000)
        report.console[name].push({
          at: Date.now(),
          kind: message.type(),
          text: message.text().slice(0, 700),
        });
    });
    peer.call = (method, ...args) =>
      bounded(
        page.evaluate(({ method, args }) => window.__app[method](...args), {
          method,
          args,
        }),
        method === "send" || method === "resumePendingMessages"
          ? 180000
          : 15000,
        `${name}.${method}`,
      );
    peer.connect = async (options = {}) => {
      await peer.call("connect", room, wsUrl, options);
    };
    peer.dump = () => peer.call("dump", room);
    peer.reload = async (options = {}) => {
      await page.reload();
      await boot(peer, false);
      await peer.connect(options);
    };
    await boot(peer);
    peers.push(peer);
    return peer;
  }
  async function sample() {
    return Promise.all(peers.map((peer) => peer.dump()));
  }
  async function archive() {
    report.final = await sample();
    report.timelines = Object.fromEntries(
      await Promise.all(
        peers.map(async (p) => [p.name, await p.call("timeline")]),
      ),
    );
    report.pcEvents = Object.fromEntries(
      await Promise.all(
        peers.map(async (p) => [p.name, await p.call("pcEvents")]),
      ),
    );
    report.diag = Object.fromEntries(
      await Promise.all(
        peers.map(async (p) => [p.name, await p.call("diag", room)]),
      ),
    );
    // The old two-peer validator's per-side checks apply to every mesh peer.
    for (const p of peers)
      assert.deepEqual(
        diagnosticProblems({ A: report.diag[p.name], B: report.diag[p.name] }),
        [],
        `${p.name} cleanup diagnostics`,
      );
    report.registry = await ctl("registry");
    assert.deepEqual(report.pageErrors, [], "Browser page errors");
  }
  return {
    report,
    event,
    close,
    createPeer,
    peers,
    sample,
    archive,
    ctl,
    room,
    wsUrl,
    appUrl,
    output,
  };
}

export function authenticatedEdge(a, b) {
  const peerId = b.keyPair.peerId;
  const reciprocal = a.keyPair.peerId;
  const pcs = a.pcs.filter(
    (pc) => pc.withPeerId === peerId && pc.connectionState !== "closed",
  );
  const opposite = b.pcs.filter(
    (pc) => pc.withPeerId === reciprocal && pc.connectionState !== "closed",
  );
  return (
    a.room?.handshakeStatusByPeer?.[peerId]?.status === "authenticated" &&
    b.room?.handshakeStatusByPeer?.[reciprocal]?.status === "authenticated" &&
    pcs.length === 1 &&
    opposite.length === 1 &&
    pcs[0].connectionState === "connected" &&
    opposite[0].connectionState === "connected" &&
    !!pcs[0].localFingerprint &&
    !!pcs[0].remoteFingerprint &&
    pcs[0].localFingerprint === opposite[0].remoteFingerprint &&
    pcs[0].remoteFingerprint === opposite[0].localFingerprint
  );
}

export function completeMesh(dumps) {
  return (
    dumps.length >= 2 &&
    dumps.every((a, i) =>
      dumps.every((b, j) => i === j || authenticatedEdge(a, b)),
    )
  );
}
