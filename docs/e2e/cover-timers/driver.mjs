// Cover-timer measurement driver (see docs/e2e/README.md, "cover-timers").
//
// Launches Chrome for Testing directly, with remote debugging and WITHOUT the
// flags browser drivers add to stop background throttling
// (--disable-background-timer-throttling, --disable-backgrounding-occluded-
// windows, --disable-renderer-backgrounding), serves entry.ts's bundle from
// 127.0.0.1, and hides the page for real by opening another tab in front of
// it. It then records, for a page-timer scheduler and a timer-worker
// scheduler running side by side, how late every wake-up landed and which
// cycles lost cells, per phase: visible, hidden 0-60 s, hidden 60-300 s,
// hidden past 300 s (where Chromium's intensive throttling begins), and
// visible again.
//
// With --mode=sealed it drives entry-sealed.ts instead: real CoverRuntimes
// sealing dummy, control and store-backed real cells, and it reports, per
// phase and per kind of cell, how long the cell took from its slot's wake-up
// to channel.send and how far after its slot it left (see entry-sealed.ts).
//
// Usage:
//   bun build docs/e2e/cover-timers/entry.ts --target=browser --outfile=<dir>/bundle.js
//   node docs/e2e/cover-timers/driver.mjs --bundle=<dir>/bundle.js \
//     --profile=<dir>/profile --out=<dir>/raw.json --summary=<file>.json \
//     [--visible=20] [--hidden=390] [--after=10] [--cadence=<ms>] [--chrome=<path>]
// Sealed mode:
//   bun docs/e2e/cover-timers/build-sealed.ts <dir>
//   node docs/e2e/cover-timers/driver.mjs --mode=sealed --bundle=<dir>/bundle.js \
//     --profile=<dir>/profile --out=<dir>/raw.json --summary=<file>.json \
//     [--query=cadence=1000&edges=2] [--wasm=src/cryptography/libcrypto.wasm]
//
// Local only: the page server and the debugging endpoint bind 127.0.0.1 on
// ports above 5000; both are stopped (Chrome by its PID) before exit. Chrome
// resolves no host name but 127.0.0.1 (--host-resolver-rules); it sends every
// request for any address but loopback, a literal IP address included, to a
// proxy port on 127.0.0.1 where nothing listens (--proxy-server; loopback is
// never proxied), so such a request fails; and its background networking and
// component updates are off. The pages use no WebRTC.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { loadavg, release } from "node:os";
import { summariseSealed, writeSealedSummary } from "./summarise-sealed.mjs";

const arg = (name, fallback) => {
  const hit = process.argv.find((value) => value.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const CHROME = arg(
  "chrome",
  `${process.env.HOME}/Library/Caches/ms-playwright/chromium-1255/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
);
const BUNDLE = arg("bundle");
const PROFILE = arg("profile");
const OUT = arg("out");
const SUMMARY = arg("summary");
const VISIBLE_S = Number(arg("visible", "20"));
const HIDDEN_S = Number(arg("hidden", "390"));
const AFTER_S = Number(arg("after", "10"));
const CADENCE_MS = arg("cadence", "");
const MODE = arg("mode", "timers");
const SEALED = MODE === "sealed";
const QUERY = arg("query", CADENCE_MS ? `cadence=${CADENCE_MS}` : "");
const WASM = arg("wasm", "src/cryptography/libcrypto.wasm");
// The code the bundle was built from (a commit, or a commit plus a working
// tree), recorded with the SHA-256 of the bundle and of the entry file.
const CODE = arg("code", "unrecorded");
const ENTRY = arg(
  "entry",
  `docs/e2e/cover-timers/${SEALED ? "entry-sealed.ts" : "entry.ts"}`,
);
// Nothing listens here: Chrome's requests to any address but loopback go to
// it and fail.
const DEAD_PROXY = "127.0.0.1:5919";
// --occluded-visible: keep an occluded window's page visible
// (--disable-backgrounding-occluded-windows), for a host whose screen is
// locked or asleep, where every window is occluded and the page would be
// hidden from the start. The page is still hidden by a tab opened in front,
// which that flag does not govern.
const OCCLUDED_VISIBLE = process.argv.includes("--occluded-visible");
const PAGE_PORT = 5918;
const DEBUG_PORT = 5917;
if (!BUNDLE || !PROFILE || !OUT || !SUMMARY) {
  console.error("--bundle, --profile, --out and --summary are required");
  process.exit(2);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const connectCdp = async (url) => {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let nextId = 0;
  const pending = new Map();
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
    else waiter.resolve(message.result);
  };
  return {
    send: (method, params = {}, sessionId) =>
      new Promise((resolve, reject) => {
        const id = ++nextId;
        pending.set(id, { resolve, reject });
        ws.send(
          JSON.stringify({
            id,
            method,
            params,
            ...(sessionId ? { sessionId } : {}),
          }),
        );
      }),
    close: () => ws.close(),
  };
};

const percentile = (sorted, p) =>
  sorted.length === 0
    ? null
    : sorted[
        Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
      ];

const summarise = (recording, from, to, schedule, tolerance) => {
  const lateness = recording.wakeUps
    .filter(([due]) => due >= from && due < to)
    .map(([due, firedAt]) => firedAt - due)
    .sort((a, b) => a - b);
  const cycleMs = schedule.coverCadenceMs * schedule.coverDurationEpochs;
  const perCycle =
    schedule.coverLanes *
    schedule.coverFramesPerCell *
    schedule.coverDurationEpochs;
  const firstCycle = Math.ceil(from / cycleMs);
  const lastCycle = Math.floor(to / cycleMs) - 1;
  const sent = new Map();
  for (const [deadline] of recording.cells) {
    const cycle = Math.floor(deadline / cycleMs);
    sent.set(cycle, (sent.get(cycle) ?? 0) + 1);
  }
  let cycles = 0;
  let degradedCycles = 0;
  let cellsSent = 0;
  for (let cycle = firstCycle; cycle <= lastCycle; cycle++) {
    cycles += 1;
    const count = sent.get(cycle) ?? 0;
    cellsSent += count;
    if (count < perCycle) degradedCycles += 1;
  }
  return {
    wakeUps: lateness.length,
    latenessMs: {
      p50: percentile(lateness, 50),
      p90: percentile(lateness, 90),
      p99: percentile(lateness, 99),
      max: lateness.length ? lateness[lateness.length - 1] : null,
    },
    lateBeyondToleranceShare:
      lateness.length === 0
        ? null
        : Number(
            (
              lateness.filter((ms) => ms > tolerance).length / lateness.length
            ).toFixed(4),
          ),
    cycles,
    degradedCycles,
    cellsSent,
    cellsExpected: cycles * perCycle,
  };
};

const html = SEALED
  ? `<!doctype html><meta charset="utf-8"><title>cover send time</title><script>window.process = { env: {} };</script><script type="module" src="/bundle.js"></script>`
  : `<!doctype html><meta charset="utf-8"><title>cover timers</title><script src="/bundle.js"></script>`;
const bundle = readFileSync(BUNDLE, "utf8");
const wasm = SEALED ? readFileSync(WASM) : undefined;
const respond = (path) =>
  path === "/bundle.js"
    ? ["text/javascript", Buffer.from(bundle)]
    : wasm && path === "/libcrypto.wasm"
      ? ["application/wasm", wasm]
      : ["text/html", Buffer.from(html)];
const PAGE_URL = `http://127.0.0.1:${PAGE_PORT}/${QUERY ? `?${QUERY}` : ""}`;
const server = createServer((request, response) => {
  const [type, body] = respond(request.url.split("?")[0]);
  response.writeHead(200, { "content-type": type });
  response.end(body);
});
await new Promise((resolve) => server.listen(PAGE_PORT, "127.0.0.1", resolve));

const chromeArgs = [
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${PROFILE}`,
  "--no-first-run",
  "--no-default-browser-check",
  "--window-size=900,700",
  // Nothing but the page server is reachable, and Chrome fetches nothing in
  // the background. Neither flag touches timer throttling.
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
  `--proxy-server=http://${DEAD_PROXY}`,
  "--disable-background-networking",
  "--disable-component-update",
  // Without it a fresh profile asks the macOS Keychain for its cookie key,
  // and every http navigation waits for that prompt.
  "--use-mock-keychain",
  ...(OCCLUDED_VISIBLE ? ["--disable-backgrounding-occluded-windows"] : []),
  PAGE_URL,
];
const chrome = spawn(CHROME, chromeArgs, { stdio: "ignore" });
console.log(`chrome pid ${chrome.pid}`);
const load = [];
try {
  let version;
  for (let i = 0; i < 100 && !version; i++) {
    try {
      version = await (
        await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`)
      ).json();
    } catch {
      await sleep(200);
    }
  }
  if (!version) throw new Error("Chrome's debugging endpoint never answered");
  const cdp = await connectCdp(version.webSocketDebuggerUrl);
  let page;
  for (let i = 0; i < 50 && !page; i++) {
    const { targetInfos } = await cdp.send("Target.getTargets");
    page = targetInfos.find(
      (target) =>
        target.type === "page" &&
        target.url.startsWith(`http://127.0.0.1:${PAGE_PORT}`),
    );
    if (!page) await sleep(200);
  }
  if (!page) throw new Error("the measurement page never appeared");
  const { sessionId } = await cdp.send("Target.attachToTarget", {
    targetId: page.targetId,
    flatten: true,
  });
  const evaluate = async (expression) =>
    (
      await cdp.send(
        "Runtime.evaluate",
        { expression, returnByValue: true, awaitPromise: true },
        sessionId,
      )
    ).result.value;
  let ready = false;
  // Sealed mode stages its messages in IndexedDB before it starts.
  for (let i = 0; i < (SEALED ? 1_500 : 150) && !ready; i++) {
    ready = await evaluate("typeof window.__coverTimers === 'object'");
    const failed = await evaluate("window.__coverTimersError ?? null");
    if (failed) throw new Error(`the measurement page failed: ${failed}`);
    if (!ready && i % 50 === 49)
      console.log(
        `waiting for the page: ${await evaluate(
          "JSON.stringify([location.href, document.readyState, window.__coverTimersProgress ?? null])",
        )}`,
      );
    if (!ready) await sleep(200);
  }
  if (!ready)
    throw new Error(
      `the measurement page never started: ${await evaluate(
        "JSON.stringify([location.href, document.readyState, document.scripts.length])",
      )}`,
    );
  const workerSource = await evaluate("window.__coverTimers.workerSource()");
  console.log(`${version.Browser}; worker clock source: ${workerSource}`);

  const sampleLoad = () => load.push([Date.now(), loadavg()[0]]);
  sampleLoad();
  await sleep(VISIBLE_S * 1000);
  const hiddenAt = Date.now();
  const front = await cdp.send("Target.createTarget", {
    url: "about:blank",
    newWindow: false,
  });
  console.log(
    `hidden at ${new Date(hiddenAt).toISOString()} behind tab ${front.targetId}`,
  );
  for (let elapsed = 0; elapsed < HIDDEN_S; elapsed += 30) {
    await sleep(Math.min(30, HIDDEN_S - elapsed) * 1000);
    sampleLoad();
    console.log(
      `hidden ${Math.min(elapsed + 30, HIDDEN_S)} s: ${await evaluate("document.visibilityState")}`,
    );
  }
  const shownAt = Date.now();
  await cdp.send("Target.activateTarget", { targetId: page.targetId });
  await sleep(AFTER_S * 1000);
  sampleLoad();
  const endedAt = Date.now();

  if (SEALED) await evaluate("window.__coverTimers.sampleClockOffset()");
  const raw = await evaluate("JSON.stringify(window.__coverTimers)");
  writeFileSync(OUT, raw);
  const data = JSON.parse(raw);
  const startedAt = data.startedAt + 2_000; // skip the first cycles' start-up
  // Every hidden window ends when the page is shown again.
  const until = (at) => Math.min(at, shownAt);
  const phases = {
    visible: [startedAt, hiddenAt],
    hidden0to60s: [hiddenAt, until(hiddenAt + 60_000)],
    hidden60to300s: [until(hiddenAt + 60_000), until(hiddenAt + 300_000)],
    hiddenPast300s: [until(hiddenAt + 300_000), shownAt],
    hiddenAll: [hiddenAt, shownAt],
    visibleAgain: [shownAt, endedAt],
  };
  const summary = {
    measuredAt: new Date(hiddenAt).toISOString(),
    code: CODE,
    sha256: {
      bundle: createHash("sha256").update(bundle).digest("hex"),
      [ENTRY]: createHash("sha256").update(readFileSync(ENTRY)).digest("hex"),
    },
    browser: version.Browser,
    userAgent: data.userAgent,
    host: `${process.platform} ${release()} ${process.arch}`,
    chromeArgs: chromeArgs.map((value) =>
      value.startsWith("--user-data-dir=")
        ? "--user-data-dir=<scratch profile>"
        : value,
    ),
    throttlingFlagsRemoved: [
      "--disable-background-timer-throttling",
      ...(OCCLUDED_VISIBLE ? [] : ["--disable-backgrounding-occluded-windows"]),
      "--disable-renderer-backgrounding",
    ],
    hiddenBy: "another tab opened in front (Target.createTarget, same window)",
    visibility: data.visibility.map(([at, state]) => [
      at - data.startedAt,
      state,
    ]),
    schedule: data.schedule,
    maxTimerDriftMs: data.maxTimerDriftMs,
    workerClockSource: workerSource,
    loadAverage1m: load.map(([at, value]) => [at - data.startedAt, value]),
    phasesMs: Object.fromEntries(
      Object.entries(phases).map(([name, [from, to]]) => [
        name,
        [from - data.startedAt, to - data.startedAt],
      ]),
    ),
    ...(SEALED
      ? {
          edges: data.edgesCount,
          idleEdges: data.idleEdges,
          edgePhasesMs: data.edgePhasesMs,
          leavesPerMessage: data.leavesPerMessage,
          proofLevelBuildMs: data.proofLevelBuildMs,
          clockOffsetMs: data.clockOffsetMs,
          poolPerEdge: data.poolPerEdge,
          sealed: {},
        }
      : { pageTimers: {}, timerWorker: {} }),
  };
  for (const [name, [from, to]] of Object.entries(phases)) {
    if (to <= from) continue;
    if (SEALED) {
      summary.sealed[name] = summariseSealed(data, from, to, name);
      continue;
    }
    summary.pageTimers[name] = summarise(
      data.page,
      from,
      to,
      data.schedule,
      data.maxTimerDriftMs,
    );
    summary.timerWorker[name] = summarise(
      data.worker,
      from,
      to,
      data.schedule,
      data.maxTimerDriftMs,
    );
  }
  if (SEALED) writeSealedSummary(SUMMARY, summary);
  else writeFileSync(SUMMARY, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(
    JSON.stringify(
      SEALED
        ? summary.sealed
        : { pageTimers: summary.pageTimers, timerWorker: summary.timerWorker },
      null,
      2,
    ),
  );
  cdp.close();
} finally {
  chrome.kill("SIGTERM");
  server.close();
  console.log(`stopped chrome pid ${chrome.pid} and the page server`);
}
