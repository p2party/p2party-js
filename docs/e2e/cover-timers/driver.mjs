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
// Usage:
//   bun build docs/e2e/cover-timers/entry.ts --target=browser --outfile=<dir>/bundle.js
//   node docs/e2e/cover-timers/driver.mjs --bundle=<dir>/bundle.js \
//     --profile=<dir>/profile --out=<dir>/raw.json --summary=<file>.json \
//     [--visible=20] [--hidden=390] [--after=10] [--cadence=<ms>] [--chrome=<path>]
//
// Local only: the page server and the debugging endpoint bind 127.0.0.1 on
// ports above 5000; both are stopped (Chrome by its PID) before exit.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { loadavg, release } from "node:os";

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

const html = `<!doctype html><meta charset="utf-8"><title>cover timers</title><script src="/bundle.js"></script>`;
const bundle = readFileSync(BUNDLE, "utf8");
const server = createServer((request, response) => {
  if (request.url === "/bundle.js") {
    response.writeHead(200, { "content-type": "text/javascript" });
    response.end(bundle);
  } else {
    response.writeHead(200, { "content-type": "text/html" });
    response.end(html);
  }
});
await new Promise((resolve) => server.listen(PAGE_PORT, "127.0.0.1", resolve));

const chromeArgs = [
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${PROFILE}`,
  "--no-first-run",
  "--no-default-browser-check",
  "--window-size=900,700",
  `http://127.0.0.1:${PAGE_PORT}/${CADENCE_MS ? `?cadence=${CADENCE_MS}` : ""}`,
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
  for (let i = 0; i < 150 && !ready; i++) {
    ready = await evaluate("typeof window.__coverTimers === 'object'");
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
    browser: version.Browser,
    userAgent: data.userAgent,
    host: `${process.platform} ${release()} ${process.arch}`,
    chromeArgs,
    throttlingFlagsRemoved: [
      "--disable-background-timer-throttling",
      "--disable-backgrounding-occluded-windows",
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
    pageTimers: {},
    timerWorker: {},
  };
  for (const [name, [from, to]] of Object.entries(phases)) {
    if (to <= from) continue;
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
  writeFileSync(SUMMARY, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(
    JSON.stringify(
      { pageTimers: summary.pageTimers, timerWorker: summary.timerWorker },
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
