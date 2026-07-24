// Full headless-Chromium WebRTC mesh E2E for protocol v4, staged + unbuffered.
// Each peer = a real browser page with real RTCPeerConnection + DataChannels.
// Verifies, per edge: real handshake, bidirectional byte-exact (multi-chunk)
// messaging, 64-message threshold, one sparse-PQ healing exchange to epoch 1,
// and a post-heal message under the new epoch. Runs n=2, n=3, n=4.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "/Users/deliberative/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8825;
const say = (...a) => process.stdout.write(a.join(" ") + "\n");
const mime = (p) => p.endsWith(".js") ? "text/javascript" : p.endsWith(".wasm") ? "application/wasm" : "text/html";
const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  try { res.writeHead(200, { "content-type": mime(name) }); res.end(readFileSync(path.join(dir, name))); }
  catch { res.writeHead(404); res.end("nf"); }
});
await new Promise((r) => server.listen(PORT, r));

const withTimeout = (p, ms, label) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms))]);

const inboxes = new Map();

const runMesh = async (browser, ids) => {
  const t0 = Date.now();
  const pages = new Map();
  for (const id of ids) {
    const page = await browser.newPage();
    page.on("pageerror", (e) => say(`    [${id} pageerror] ${e.message}`));
    await page.goto(`http://localhost:${PORT}/`);
    await withTimeout(page.waitForFunction("window.__p2p !== undefined", null, { timeout: 12000 }), 13000, `${id} load`);
    pages.set(id, page); inboxes.set(id, page);
  }
  for (const [id, page] of pages)
    await page.exposeFunction("__relaySignal", async (from, to, payload) => {
      const t = inboxes.get(to); if (!t) return;
      try { await t.evaluate(([s, p, pp]) => window.__p2p.onSignal(s, p, pp), [to, from, payload]); } catch {}
    });
  for (const [id, page] of pages) await page.evaluate((s) => window.__p2p.init(s), id);
  const pubs = new Map();
  for (const [id, page] of pages) pubs.set(id, await page.evaluate((s) => window.__p2p.identityHex(s), id));
  for (const [id, page] of pages) for (const o of ids) if (o !== id)
    await page.evaluate(([s, p, k]) => window.__p2p.registerPeerIdentity(s, p, k), [id, o, pubs.get(o)]);

  const edges = [];
  for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) edges.push([ids[i], ids[j]]);

  // Create every peer connection first, then fire offers (avoids the
  // signal-before-pc race), then handshake all edges concurrently.
  for (const [a, b] of edges) {
    await pages.get(a).evaluate(([s, p]) => window.__p2p.connect(s, p, true), [a, b]);
    await pages.get(b).evaluate(([s, p]) => window.__p2p.connect(s, p, false), [b, a]);
  }
  for (const [a, b] of edges)
    await pages.get(a).evaluate(([s, p]) => window.__p2p.makeOffer(s, p), [a, b]);

  await withTimeout(Promise.all(edges.flatMap(([a, b]) => [
    pages.get(a).evaluate(([s, p]) => window.__p2p.handshake(s, p, true), [a, b]),
    pages.get(b).evaluate(([s, p]) => window.__p2p.handshake(s, p, false), [b, a]),
  ])), 40000, "handshakes");
  for (const [a, b] of edges) {
    const pc = await pages.get(a).evaluate(([s, p]) => window.__p2p.connectionState(s, p), [a, b]);
    if (pc !== "connected") throw new Error(`edge ${a}-${b}: pc=${pc}`);
  }
  say(`    handshakes OK on all ${edges.length} edge(s), all pc=connected`);

  // Bidirectional byte-exact multi-chunk messaging.
  for (const [a, b] of edges) {
    const msgAB = `A->B ${"x".repeat(20000)}`, msgBA = `B->A ${"y".repeat(9000)}`;
    const [gotB] = await withTimeout(Promise.all([
      pages.get(b).evaluate(([s, p]) => window.__p2p.recvMessage(s, p), [b, a]),
      pages.get(a).evaluate(([s, p, m]) => window.__p2p.sendMessage(s, p, m), [a, b, msgAB]),
    ]), 20000, `msg ${a}-${b}`);
    const [gotA] = await withTimeout(Promise.all([
      pages.get(a).evaluate(([s, p]) => window.__p2p.recvMessage(s, p), [a, b]),
      pages.get(b).evaluate(([s, p, m]) => window.__p2p.sendMessage(s, p, m), [b, a, msgBA]),
    ]), 20000, `msg ${b}-${a}`);
    if (gotB !== msgAB || gotA !== msgBA) throw new Error(`edge ${a}-${b}: message mismatch`);
  }
  say(`    bidirectional multi-chunk messaging byte-exact on all edges`);

  // Start control pumps, drive 64 messages to make healing due, then heal.
  for (const [a, b] of edges) {
    await pages.get(a).evaluate(([s, p]) => window.__p2p.startControlPump(s, p), [a, b]);
    await pages.get(b).evaluate(([s, p]) => window.__p2p.startControlPump(s, p), [b, a]);
  }
  for (const [a, b] of edges) {
    await withTimeout(Promise.all([
      pages.get(b).evaluate(([s, p]) => window.__p2p.recvBurst(s, p, 64), [b, a]),
      pages.get(a).evaluate(([s, p]) => window.__p2p.sendBurst(s, p, 64), [a, b]),
    ]), 60000, `burst ${a}-${b}`);
    const healed = await withTimeout(
      pages.get(a).evaluate(([s, p]) => window.__p2p.heal(s, p), [a, b]),
      20000, `heal ${a}-${b}`);
    const peerEpoch = await pages.get(b).evaluate(([s, p]) => window.__p2p.epoch(s, p), [b, a]);
    if (healed !== 1 || peerEpoch !== 1) throw new Error(`edge ${a}-${b}: heal epoch ${healed}/${peerEpoch}`);
    const postMsg = `post-heal ${a}->${b}`;
    const [gotPost] = await withTimeout(Promise.all([
      pages.get(b).evaluate(([s, p]) => window.__p2p.recvMessage(s, p), [b, a]),
      pages.get(a).evaluate(([s, p, m]) => window.__p2p.sendMessage(s, p, m), [a, b, postMsg]),
    ]), 20000, `post-heal ${a}-${b}`);
    if (gotPost !== postMsg) throw new Error(`edge ${a}-${b}: post-heal mismatch`);
    say(`    edge ${a}-${b}: sparse-PQ healing -> epoch 1 (both), post-heal msg OK`);
  }
  for (const page of pages.values()) await page.close();
  return { edges: edges.length, ms: Date.now() - t0 };
};

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
let failed = false;
try {
  for (const ids of [["A", "B"], ["A", "B", "C"], ["A", "B", "C", "D"]]) {
    const n = ids.length;
    say(`=== n=${n} (${(n * (n - 1)) / 2} edge(s)) ===`);
    const r = await runMesh(browser, ids);
    say(`n=${n} PASS: ${r.edges} edge(s) fully verified in ${(r.ms / 1000).toFixed(1)}s\n`);
  }
  say("ALL HEADLESS-CHROMIUM WebRTC E2E GATES PASSED (n=2, n=3, n=4).");
} catch (e) {
  failed = true;
  say("E2E FAILURE:", e.message);
} finally {
  await browser.close(); server.close();
}
process.exit(failed ? 1 : 0);
