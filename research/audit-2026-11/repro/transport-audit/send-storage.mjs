// From the SDK root: bun research/audit-2026-11/repro/transport-audit/send-storage.mjs [baseline-sdk-root]
// Requires a built dependency tree for each checkout and Chromium through the sibling site's Playwright.
// Measures one staged read, first proof binding, and receipt lookup per cell. Setup is outside the timer.
// One local Chromium run with 1,000 cells took 1.398 ms/cell before, 0.833 after.
// An in-process fake-indexeddb run counting both directions at the cloned message boundary found
// 3,000 -> 1 opens; 3,000 -> 3,000 transactions; 3,000 -> 1,000 staged value reads;
// 193,091,000 -> 0 cloned binary bytes. Transferred buffers still cross the worker boundary.
// This excludes disk staging, network, encryption, and receipt persistence at the recipient.
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
const root = process.cwd(),
  dir = mkdtempSync(join(tmpdir(), "p2party-send-storage-"));
const { chromium } = await import(
  resolve(root, "../p2party.com/node_modules/playwright/index.mjs")
);
const browser = await chromium.launch({
  args: [
    "--disable-background-networking",
    "--no-first-run",
    "--disable-dev-shm-usage",
  ],
});
const old = process.argv[2];
try {
  for (const [label, base] of old
    ? [
        ["before", resolve(old)],
        ["after", root],
      ]
    : [["current", root]]) {
    async function bundle(path, define = {}) {
      const result = await Bun.build({
        entrypoints: [path],
        target: "browser",
        format: "iife",
        define: { "process.env.NODE_ENV": '"production"', ...define },
      });
      if (!result.success) throw Error(String(result.logs));
      return await result.outputs[0].text();
    }
    const worker =
      "globalThis.process={env:{}};\n" +
      (await bundle(base + "/src/db/db.worker.ts"));
    const entry = dir + "/page.js";
    writeFileSync(
      entry,
      [
        "import * as api from " + JSON.stringify(base + "/src/db/api.ts") + ";",
        "import {getDB} from " +
          JSON.stringify(base + "/src/db/src/getDB.ts") +
          ";",
        "import {CHUNK_LEN,PROOF_LEN,METADATA_LEN} from " +
          JSON.stringify(base + "/src/utils/constants.ts") +
          ";",
        "Object.assign(window,{api,getDB,CHUNK_LEN,PROOF_LEN,METADATA_LEN});",
      ].join("\n"),
    );
    const script = await bundle(entry, {
      "process.env.INDEXEDDB_WORKER_JS": JSON.stringify(worker),
    });
    const context = await browser.newContext();
    await context.route("https://bench.test/**", (route) =>
      route.fulfill({ contentType: "text/html", body: "<html></html>" }),
    );
    const page = await context.newPage();
    page.on("pageerror", (err) => console.log("page script:", err.message));
    await page.goto("https://bench.test/");
    await page.evaluate(() => {
      window.process = { env: {} };
    });
    await page.addScriptTag({ content: script, type: "module" });
    await page.waitForFunction(
      () => typeof window.getDB === "function",
      undefined,
      { timeout: 4000 },
    );
    const result = await page.evaluate(async () => {
      const n = 1000,
        tid = "11".repeat(32),
        root = "ab".repeat(64),
        sender = "02".repeat(32);
      const { api, getDB, CHUNK_LEN, PROOF_LEN, METADATA_LEN } = window;
      const db = await getDB();
      const tx = db.transaction(["newChunks", "outbox", "meta"], "readwrite");
      await tx
        .objectStore("meta")
        .put(
          {
            pub: new Uint8Array(32).fill(2).buffer,
            wrappedSecret: new ArrayBuffer(80),
            recordRevision: 1n,
          },
          "identityEd25519",
        );
      const size = CHUNK_LEN + METADATA_LEN + 2048;
      const lease = { transferId: tid, owner: "bench", fence: 1 };
      const cells = tx.objectStore("newChunks");
      const body = new ArrayBuffer(CHUNK_LEN),
        meta = new ArrayBuffer(METADATA_LEN),
        proof = new ArrayBuffer(0);
      for (let i = 0; i < n; i++)
        void cells.put({
          transferId: tid,
          chunkIndex: i,
          merkleRoot: "",
          receiptToken: "",
          hash: root,
          leafHash: root,
          data: body,
          metadata: meta,
          merkleProof: proof,
          accountedBytes: size,
        });
      await tx
        .objectStore("outbox")
        .put({
          ...lease,
          senderPublicKey: sender,
          identityRevision: 1n,
          phase: "sending",
          leaseUntil: Date.now() + 600000,
          totalChunks: n,
          writtenBytes: size * n,
          stagedBytes: (size + PROOF_LEN) * n,
        });
      await tx.done;
      db.close();
      const start = performance.now();
      for (let i = 0; i < n; i++) {
        const row = await api.getDBNewChunk(tid, i);
        row.merkleRoot = root;
        row.receiptToken = i.toString(16).padStart(128, "0");
        row.merkleProof = new ArrayBuffer(PROOF_LEN);
        await api.setDBNewChunk(row, lease, true);
        const result = await api.getDBNewChunkByReceipt(root, row.receiptToken);
        if (result?.chunkIndex !== i) throw Error("wrong index");
      }
      return { cells: n, msPerCell: (performance.now() - start) / n };
    });
    console.log(label, JSON.stringify(result));
    await context.close();
  }
} finally {
  await browser.close();
  try {
    unlinkSync(join(dir, "page.js"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  rmdirSync(dir);
}
