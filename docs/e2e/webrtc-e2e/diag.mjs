// Focused n=2 diagnostic: unbuffered, staged, with per-stage timeouts.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "/Users/deliberative/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8824;
const say = (...a) => { process.stdout.write(a.join(" ") + "\n"); };

const mime = (p) => p.endsWith(".js") ? "text/javascript" : p.endsWith(".wasm") ? "application/wasm" : "text/html";
const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  try {
    res.writeHead(200, { "content-type": mime(name) });
    res.end(readFileSync(path.join(dir, name)));
  } catch { res.writeHead(404); res.end("nf"); }
});
await new Promise((r) => server.listen(PORT, r));
say("http server up on", PORT);

const withTimeout = (p, ms, label) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms))]);

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
say("browser launched");
const inboxes = new Map();
let failed = false;
try {
  const ids = ["A", "B"];
  const pages = new Map();
  for (const id of ids) {
    const page = await browser.newPage();
    page.on("pageerror", (e) => say(`  [${id} pageerror] ${e.message}`));
    await page.goto(`http://localhost:${PORT}/`);
    await withTimeout(page.waitForFunction("window.__p2p !== undefined", null, { timeout: 12000 }), 13000, `${id} bundle load`);
    pages.set(id, page); inboxes.set(id, page);
    say(`  ${id}: page ready`);
  }
  for (const [id, page] of pages)
    await page.exposeFunction("__relaySignal", async (from, to, payload) => {
      const t = inboxes.get(to); if (!t) return;
      await t.evaluate(([s, p, pp]) => window.__p2p.onSignal(s, p, pp), [to, from, payload]);
    });
  for (const [id, page] of pages) await page.evaluate((s) => window.__p2p.init(s), id);
  say("  identities initialized");
  const pubs = new Map();
  for (const [id, page] of pages) pubs.set(id, await page.evaluate((s) => window.__p2p.identityHex(s), id));
  for (const [id, page] of pages) for (const o of ids) if (o !== id)
    await page.evaluate(([s, p, k]) => window.__p2p.registerPeerIdentity(s, p, k), [id, o, pubs.get(o)]);
  say("  peer identities exchanged");

  await pages.get("A").evaluate(([s, p]) => window.__p2p.connect(s, p, true), ["A", "B"]);
  await pages.get("B").evaluate(([s, p]) => window.__p2p.connect(s, p, false), ["B", "A"]);
  await pages.get("A").evaluate(([s, p]) => window.__p2p.makeOffer(s, p), ["A", "B"]);
  say("  connect()+makeOffer issued; running handshake over real WebRTC...");

  const [ea, eb] = await withTimeout(Promise.all([
    pages.get("A").evaluate(([s, p]) => window.__p2p.handshake(s, p, true), ["A", "B"]),
    pages.get("B").evaluate(([s, p]) => window.__p2p.handshake(s, p, false), ["B", "A"]),
  ]), 30000, "handshake");
  const pc = await pages.get("A").evaluate(([s, p]) => window.__p2p.connectionState(s, p), ["A", "B"]);
  say(`  HANDSHAKE OK: epoch ${ea}/${eb}, pc=${pc}`);

  const msgAB = "hello B from A " + "x".repeat(20000);
  const [gotB] = await withTimeout(Promise.all([
    pages.get("B").evaluate(([s, p]) => window.__p2p.recvMessage(s, p), ["B", "A"]),
    pages.get("A").evaluate(([s, p, m]) => window.__p2p.sendMessage(s, p, m), ["A", "B", msgAB]),
  ]), 20000, "message A->B");
  say(`  MESSAGE A->B byte-exact: ${gotB === msgAB} (${msgAB.length}B)`);
  if (gotB !== msgAB) throw new Error("A->B mismatch");

  say("ALL DIAG STAGES PASSED");
} catch (e) {
  failed = true;
  say("DIAG FAILURE:", e.message);
} finally {
  await browser.close(); server.close();
}
process.exit(failed ? 1 : 0);
