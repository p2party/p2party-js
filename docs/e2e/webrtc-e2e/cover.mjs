// Drives the real-WebRTC scheduled-cover lane test in headless Chromium.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pw from "/Users/deliberative/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js";
const { chromium } = pw;

const dir = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8826;
const say = (...a) => process.stdout.write(a.join(" ") + "\n");
const mime = (p) => (p.endsWith(".js") ? "text/javascript" : p.endsWith(".wasm") ? "application/wasm" : "text/html");
const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/cover.html" : req.url.split("?")[0];
  try { res.writeHead(200, { "content-type": mime(name) }); res.end(readFileSync(path.join(dir, name))); }
  catch { res.writeHead(404); res.end("nf"); }
});
await new Promise((r) => server.listen(PORT, r));

const inboxes = new Map();
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
let failed = false;
try {
  const ids = ["A", "B"];
  const pages = new Map();
  for (const id of ids) {
    const page = await browser.newPage();
    page.on("pageerror", (e) => say(`  [${id} pageerror] ${e.message}`));
    await page.goto(`http://localhost:${PORT}/`);
    await page.waitForFunction("window.__cover !== undefined", null, { timeout: 15000 });
    pages.set(id, page); inboxes.set(id, page);
  }
  for (const [, page] of pages)
    await page.exposeFunction("__relaySignal", async (from, to, payload) => {
      const t = inboxes.get(to); if (!t) return;
      try { await t.evaluate(([s, p, pp]) => window.__cover.onSignal(s, p, pp), [to, from, payload]); } catch {}
    });

  // A is the cover sender (initiator, opens lanes); B receives + authenticates.
  await pages.get("A").evaluate(() => window.__cover.init("A", true));
  await pages.get("B").evaluate(() => window.__cover.init("B", false));
  await pages.get("A").evaluate(() => window.__cover.connect("A", "B", true));
  await pages.get("B").evaluate(() => window.__cover.connect("B", "A", false));
  await pages.get("A").evaluate(() => window.__cover.makeOffer("A", "B"));
  // Wait for the connection to establish.
  await new Promise((r) => setTimeout(r, 1500));

  // Pair the Double Ratchet across the two pages (B responder first).
  const seed = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
  const bPub = await pages.get("B").evaluate((s) => window.__cover.initRatchetResponder("B", s), seed);
  await pages.get("A").evaluate(([s, p]) => window.__cover.initRatchetInitiator("A", s, p), [seed, bPub]);
  say("paired Double Ratchet across the two pages");

  const schedule = { coverCadenceMs: 400, coverLanes: 2, coverFramesPerCell: 3, coverDurationEpochs: 1 };
  // C×F×D = 2×3×1 = 6 cells per cycle.
  await pages.get("B").evaluate((s) => window.__cover.startCover("B", "A", false, s), schedule);
  await pages.get("A").evaluate((s) => window.__cover.startCover("A", "B", true, s), schedule);
  say("cover runtimes started (C=2, F=3, D=1 → 6 cells/cycle)");

  // Enqueue one authenticated receipt-subtype cover cell...
  await pages.get("A").evaluate(() => window.__cover.enqueueReal("A", "realmsg"));
  // ...and one REAL message chunk (FRAME_TYPE_CHUNK) substituted into a slot.
  const sentChunkB64 = await pages.get("A").evaluate(() => window.__cover.sendRealChunk("A", "hello-scheduled-cover"));

  // Let ~3 cycles run (400ms cadence → ~1.2s; give margin for SCTP open).
  await new Promise((r) => setTimeout(r, 3000));

  const received = await pages.get("B").evaluate(() => window.__cover.received("B"));
  const receivedReal = await pages.get("B").evaluate(() => window.__cover.receivedReal("B"));
  const status = await pages.get("A").evaluate(() => window.__cover.status("A"));
  const statuses = await pages.get("A").evaluate(() => window.__cover.statuses("A"));
  const laneStats = await pages.get("A").evaluate(() => window.__cover.laneStats("A"));
  say("A status transitions: " + JSON.stringify(statuses));
  say("A lane opens=" + laneStats.opens + " sends=" + laneStats.sends);
  const receivedChunks = await pages.get("B").evaluate(() => window.__cover.receivedChunks("B"));
  say(`B authenticated ${received} inbound cover cells over real WebRTC lanes`);
  say(`B dispatched ${receivedReal.length} real (receipt-subtype) substituted cell(s)`);
  say(`B decrypted ${receivedChunks.length} real message chunk(s) from cover slots`);
  const dbg = await pages.get("B").evaluate(() => window.__cover.debug("B"));
  say("B chunk debug: " + JSON.stringify(dbg));
  say(`A cover status: ${status}`);

  // Over ~3 cycles at 6 cells/cycle we expect well over 6 authenticated cells,
  // a real substituted cell dispatched, and the real message chunk decrypted
  // BYTE-EXACT on the receiver.
  if (received < 6) throw new Error(`too few authenticated cover cells: ${received}`);
  if (receivedReal.length < 1) throw new Error("no real substituted cell dispatched");
  if (!receivedChunks.includes(sentChunkB64))
    throw new Error(
      `real message chunk did not decrypt byte-exact over the scheduled cover lane (got ${receivedChunks.length})`,
    );
  say("real message chunk decrypted BYTE-EXACT over the scheduled cover lane");

  for (const id of ids) await pages.get(id).evaluate((i) => window.__cover.stop(i), id);
  say("SCHEDULED-COVER REAL-WebRTC LANE TEST PASSED");
} catch (e) {
  failed = true;
  say("COVER E2E FAILURE:", e.message);
} finally {
  await browser.close(); server.close();
}
process.exit(failed ? 1 : 0);
