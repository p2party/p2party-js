// Playwright driver for the WebRTC-provider smoke test of the flagged
// two-store blind-rendezvous prototype.
//
//   bun build docs/e2e/blind-two-store/provider-smoke.ts --target=browser \
//     --outfile=docs/e2e/blind-two-store/provider-smoke-bundle.js \
//     --define:process.env.NODE_ENV='"production"'
//   cp src/cryptography/libcrypto.wasm docs/e2e/blind-two-store/
//   PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
//     node docs/e2e/blind-two-store/provider-smoke.mjs
//
// Serves this directory over http, opens one headless Chromium page, runs
// `window.__providerSmoke.run()`, prints the JSON result and exits non-zero on
// any failure. Everything the test proves happens inside that one page: two
// real RTCPeerConnections, one real DTLS/SCTP data channel, two real
// protocol-v4 sessions.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "../../../../p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
// Project rule: never bind below 5000.
const PORT = Number(process.env.SMOKE_PORT ?? 5921);
const RUN_TIMEOUT_MS = Number(process.env.SMOKE_TIMEOUT_MS ?? 180_000);

const say = (...parts) => process.stdout.write(parts.join(" ") + "\n");

const mime = (name) =>
  name.endsWith(".js")
    ? "text/javascript"
    : name.endsWith(".wasm")
      ? "application/wasm"
      : "text/html";

const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/provider-smoke.html" : req.url.split("?")[0];
  try {
    res.writeHead(200, { "content-type": mime(name) });
    res.end(readFileSync(path.join(dir, name)));
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});
await new Promise((resolve) => server.listen(PORT, resolve));

const withTimeout = (promise, ms, label) =>
  Promise.race([
    promise,
    new Promise((_resolve, reject) =>
      setTimeout(() => reject(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms),
    ),
  ]);

// `--disable-features=WebRtcHideLocalIpsWithMdns` is required, not cosmetic:
// by default Chromium replaces host candidates with `<uuid>.local` mDNS names,
// and this headless sandbox has no mDNS responder to resolve them. Because the
// blind profile is COMPLETE-gathering (the candidates ride inside the one SDP
// blob, there is no trickle), an unresolvable remote candidate is simply
// dropped: both connections then sit at iceConnectionState "new" forever with
// zero candidate pairs. `docs/e2e/desync/probe-ice.mjs` carries the same flag
// for the same reason. On a real LAN the mDNS names resolve and the flag is
// unnecessary.
const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox", "--disable-features=WebRtcHideLocalIpsWithMdns"],
});
let failed = false;
try {
  const page = await browser.newPage();
  page.on("pageerror", (error) => say(`  [pageerror] ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning")
      say(`  [console.${message.type()}] ${message.text()}`);
  });

  await page.goto(`http://localhost:${PORT}/`);
  await withTimeout(
    page.waitForFunction("window.__providerSmoke !== undefined", null, {
      timeout: 15_000,
    }),
    16_000,
    "bundle load",
  );
  say(`window.__providerSmoke present (http://localhost:${PORT}/)`);

  const started = Date.now();
  const result = await withTimeout(
    page.evaluate(() => window.__providerSmoke.run()),
    RUN_TIMEOUT_MS,
    "providerSmoke.run()",
  );
  say(JSON.stringify(result, null, 2));

  const problems = [];
  if (!result.connected)
    problems.push(
      `connectionStates ${JSON.stringify(result.connectionStates)}`,
    );
  if (result.dtls.a !== "verified" && result.dtls.a !== "unsupported")
    problems.push(`dtls.a=${result.dtls.a}`);
  if (result.dtls.b !== "verified" && result.dtls.b !== "unsupported")
    problems.push(`dtls.b=${result.dtls.b}`);
  if (!result.bytesExactAB) problems.push("A->B message was not byte-exact");
  if (!result.bytesExactBA) problems.push("B->A message was not byte-exact");
  if (result.frames.ab < 2 || result.frames.ba < 2)
    problems.push(
      `messages were not multi-chunk (frames ${result.frames.ab}/${result.frames.ba})`,
    );
  if (!result.closeRejectsWaiters.channel)
    problems.push("close() left a pending channel() waiter unsettled");
  if (!result.closeRejectsWaiters.recvApp)
    problems.push("close() left a pending recvApp() waiter unsettled");

  if (problems.length > 0) {
    failed = true;
    say(`PROVIDER SMOKE FAILURE: ${problems.join("; ")}`);
  } else {
    say(
      `PROVIDER SMOKE PASS in ${((Date.now() - started) / 1000).toFixed(1)}s ` +
        `(dtls ${result.dtls.a}/${result.dtls.b}, ` +
        `${result.frames.ab}+${result.frames.ba} chunk frames byte-exact)`,
    );
  }
  await page.close();
} catch (error) {
  failed = true;
  say("PROVIDER SMOKE FAILURE:", error.message);
} finally {
  await browser.close();
  server.close();
}
process.exit(failed ? 1 : 0);
