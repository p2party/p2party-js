// What FileSystemDirectoryHandle.removeEntry does to an OPFS file that is in
// use, measured in a real browser rather than read from the standard.
//
// In a dedicated Worker of a page served from 127.0.0.1 it records, for each
// case, whether removeEntry resolves or rejects and with which error name,
// what the directory lists afterwards, and whether the open handle still
// works:
//   1. a file with an open sync access handle, removed from its directory;
//   2. the same, after the handle is closed;
//   3. a directory holding a file with an open sync access handle, removed
//      from its parent with { recursive: true } (the layout db.worker.ts's
//      purge removes: navigator.storage root -> "p2party-reassembled" -> file);
//   4. the same, after the handle is closed;
//   5. a file with an open writable stream (createWritable), removed;
//   6. the same, after the stream is closed;
//   7. a second createSyncAccessHandle on a file whose first one is open.
//
// Usage (the browser defaults to the headless shell of the Chromium build
// whose Chrome for Testing docs/e2e/cover-timers/driver.mjs uses, from the
// same Playwright cache; that Chrome for Testing, run --headless=new, never
// delivered the intercepted page request on this host):
//   node docs/e2e/opfs-remove/probe.mjs --profile=<scratch dir> \
//     --out=docs/e2e/opfs-remove/result-<date>.json [--chrome=<path>] \
//     [--serve=cdp|http]
// --serve=cdp (the default) hands Chrome the page through the debugging
// connection (Fetch interception) for the page's own http://127.0.0.1 URL,
// as the cover-timer driver's cdp mode does, for a host where Chrome's
// loopback connections open but carry no request; --serve=http runs a page
// server on 127.0.0.1 instead. The Worker is made from a Blob URL, so it has
// the page's origin and its own OPFS. Nothing reaches the network either way.
//
// Local only: the debugging endpoint (and with --serve=http the page server)
// binds 127.0.0.1 on ports above 5000; Chrome resolves no host name but
// 127.0.0.1, its background networking is off, and it is stopped by its PID
// before exit.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { writeFileSync } from "node:fs";
import { release } from "node:os";

const arg = (name, fallback) => {
  const hit = process.argv.find((value) => value.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const CHROME = arg(
  "chrome",
  `${process.env.HOME}/Library/Caches/ms-playwright/chromium_headless_shell-1255/chrome-headless-shell-mac-arm64/chrome-headless-shell`,
);
const PROFILE = arg("profile");
const OUT = arg("out");
const SERVE = arg("serve", "cdp");
const PAGE_PORT = 5931;
const DEBUG_PORT = 5930;
if (!PROFILE || !OUT) {
  console.error("--profile and --out are required");
  process.exit(2);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Runs in the Worker: sync access handles exist only in dedicated workers.
const workerSource = `
const list = async (dir) => {
  const names = [];
  try {
    for await (const name of dir.keys()) names.push(name);
  } catch (error) {
    return "listing failed: " + error.name;
  }
  return names.sort();
};
const attempt = async (call) => {
  try {
    await call();
    return { outcome: "resolved" };
  } catch (error) {
    return { outcome: "rejected", error: error.name, message: error.message };
  }
};
const freshDirectory = async (root, name) => {
  await root.removeEntry(name, { recursive: true }).catch(() => undefined);
  return root.getDirectoryHandle(name, { create: true });
};
const handleStillReads = (access) => {
  try {
    const bytes = new Uint8Array(3);
    return { read: access.read(bytes, { at: 0 }), bytes: [...bytes] };
  } catch (error) {
    return { error: error.name };
  }
};
onmessage = async () => {
  const cases = [];
  try {
    const root = await navigator.storage.getDirectory();

    // 1 and 2: a file, its sync access handle open, then closed.
    {
      const dir = await freshDirectory(root, "probe-file");
      const file = await dir.getFileHandle("held", { create: true });
      const access = await file.createSyncAccessHandle();
      access.write(new Uint8Array([1, 2, 3]), { at: 0 });
      access.flush();
      const open = await attempt(() => dir.removeEntry("held"));
      cases.push({
        case: "removeEntry(file) while its sync access handle is open",
        ...open,
        listedAfter: await list(dir),
        handleAfter: handleStillReads(access),
      });
      access.close();
      const closed = await attempt(() => dir.removeEntry("held"));
      cases.push({
        case: "removeEntry(file) after its sync access handle is closed",
        ...closed,
        listedAfter: await list(dir),
      });
    }

    // 3 and 4: the reassembly directory, a sync access handle open inside.
    {
      const dir = await freshDirectory(root, "p2party-reassembled");
      const file = await dir.getFileHandle("held", { create: true });
      const access = await file.createSyncAccessHandle();
      access.write(new Uint8Array([4, 5, 6]), { at: 0 });
      access.flush();
      const open = await attempt(() =>
        root.removeEntry("p2party-reassembled", { recursive: true }),
      );
      cases.push({
        case:
          "removeEntry(directory, { recursive: true }) while a sync access handle inside is open",
        ...open,
        rootListedAfter: await list(root),
        directoryListedAfter: await list(dir),
        handleAfter: handleStillReads(access),
      });
      access.close();
      const closed = await attempt(() =>
        root.removeEntry("p2party-reassembled", { recursive: true }),
      );
      cases.push({
        case:
          "removeEntry(directory, { recursive: true }) after the handle inside is closed",
        ...closed,
        rootListedAfter: await list(root),
      });
    }

    // 5 and 6: a file with an open writable stream, then closed.
    {
      const dir = await freshDirectory(root, "probe-writable");
      const file = await dir.getFileHandle("held", { create: true });
      const writable = await file.createWritable();
      await writable.write(new Uint8Array([7, 8, 9]));
      const open = await attempt(() => dir.removeEntry("held"));
      const record = {
        case: "removeEntry(file) while a writable stream on it is open",
        ...open,
        listedAfter: await list(dir),
      };
      record.writableCloseAfter = await attempt(() => writable.close());
      cases.push(record);
      const closed = await attempt(() => dir.removeEntry("held"));
      cases.push({
        case: "removeEntry(file) after its writable stream is closed",
        ...closed,
        listedAfter: await list(dir),
      });
    }
    // 7: a second sync access handle while the first is open.
    {
      const dir = await freshDirectory(root, "probe-second-handle");
      const file = await dir.getFileHandle("held", { create: true });
      const first = await file.createSyncAccessHandle();
      let second;
      const record = await attempt(async () => {
        second = await file.createSyncAccessHandle();
      });
      second?.close();
      first.close();
      cases.push({
        case: "createSyncAccessHandle while another sync access handle on the file is open",
        ...record,
      });
    }
    postMessage({ cases });
  } catch (error) {
    postMessage({ cases, failed: error.name + ": " + error.message });
  }
};
`;
const html = `<!doctype html><meta charset="utf-8"><title>opfs remove probe</title>
<script type="text/plain" id="worker">${workerSource}</script>
<script>
window.__opfsProbe = new Promise((resolve) => {
  const source = document.getElementById("worker").textContent;
  const worker = new Worker(
    URL.createObjectURL(new Blob([source], { type: "text/javascript" })),
  );
  worker.onmessage = (event) => resolve(event.data);
  worker.onerror = (event) => resolve({ failed: "worker error: " + event.message });
  worker.postMessage("run");
});
</script>`;

const PAGE_URL = `http://127.0.0.1:${PAGE_PORT}/`;
const server =
  SERVE === "http"
    ? createServer((_request, response) => {
        response.writeHead(200, { "content-type": "text/html" });
        response.end(html);
      })
    : undefined;
if (server)
  await new Promise((resolve) =>
    server.listen(PAGE_PORT, "127.0.0.1", resolve),
  );

const connectCdp = async (url) => {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let nextId = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.method) {
      listeners.get(message.method)?.(message.params, message.sessionId);
      return;
    }
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
    on: (method, listener) => listeners.set(method, listener),
    close: () => ws.close(),
  };
};

const chromeArgs = [
  "--headless=new",
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${PROFILE}`,
  "--no-first-run",
  "--no-default-browser-check",
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
  "--disable-background-networking",
  "--disable-component-update",
  server ? PAGE_URL : "about:blank",
];
const chrome = spawn(CHROME, chromeArgs, { stdio: "ignore" });
console.log(`chrome pid ${chrome.pid}`);
try {
  let version;
  for (let i = 0; i < 100 && !version; i++) {
    try {
      version = await (
        await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`, {
          signal: AbortSignal.timeout(2_000),
        })
      ).json();
    } catch {
      await sleep(200);
    }
  }
  if (!version) throw new Error("Chrome's debugging endpoint never answered");
  console.log(version.Browser);
  const cdp = await connectCdp(version.webSocketDebuggerUrl);
  let page;
  for (let i = 0; i < 50 && !page; i++) {
    const { targetInfos } = await cdp.send("Target.getTargets");
    page = targetInfos.find(
      (target) =>
        target.type === "page" &&
        target.url.startsWith(server ? PAGE_URL : "about:blank"),
    );
    if (!page) await sleep(200);
  }
  if (!page) throw new Error("the probe page never appeared");
  console.log(`page target ${page.targetId}`);
  const { sessionId } = await cdp.send("Target.attachToTarget", {
    targetId: page.targetId,
    flatten: true,
  });
  if (!server) {
    cdp.on("Fetch.requestPaused", ({ requestId, request }, from) => {
      console.log(`serving ${request.url}`);
      void cdp.send(
        "Fetch.fulfillRequest",
        {
          requestId,
          responseCode: 200,
          responseHeaders: [{ name: "content-type", value: "text/html" }],
          body: Buffer.from(html).toString("base64"),
        },
        from,
      );
    });
    await cdp.send(
      "Fetch.enable",
      { patterns: [{ urlPattern: `${PAGE_URL}*` }] },
      sessionId,
    );
    await cdp.send("Page.navigate", { url: PAGE_URL }, sessionId);
  }
  console.log("page loading; running the probe");
  const answer = await cdp.send(
    "Runtime.evaluate",
    {
      expression: `(async () => {
        for (let i = 0; i < 600 && !window.__opfsProbe; i++)
          await new Promise((r) => setTimeout(r, 50));
        if (!window.__opfsProbe) return JSON.stringify({ failed: "the page never started" });
        return JSON.stringify(await Promise.race([
          window.__opfsProbe,
          new Promise((r) => setTimeout(() => r({ failed: "the worker never answered" }), 30000)),
        ]));
      })()`,
      awaitPromise: true,
      returnByValue: true,
    },
    sessionId,
  );
  cdp.close();
  if (answer.exceptionDetails) throw new Error(JSON.stringify(answer));
  const measured = JSON.parse(answer.result.value);
  const result = {
    measuredAt: new Date().toISOString(),
    browser: version.Browser,
    userAgent: version["User-Agent"],
    host: `${process.platform} ${release()} ${process.arch}`,
    serve: SERVE,
    chromeArgs: chromeArgs.map((value) =>
      value.startsWith("--user-data-dir=")
        ? "--user-data-dir=<scratch profile>"
        : value,
    ),
    ...measured,
  };
  writeFileSync(OUT, `${JSON.stringify(result, null, 2)}\n`);
  for (const entry of measured.cases ?? [])
    console.log(
      `${entry.case}: ${entry.outcome}${entry.error ? ` (${entry.error})` : ""}`,
    );
  if (measured.failed) console.log(`failed: ${measured.failed}`);
} finally {
  process.kill(chrome.pid, "SIGTERM");
  server?.close();
}
