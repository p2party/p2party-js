// Build entry-sealed.ts for the browser, with the database worker inlined the
// way the package build inlines it (INDEXEDDB_WORKER_JS), so the real outbox
// store runs in its real worker. Run from the repository root:
//   bun docs/e2e/cover-timers/build-sealed.ts <out dir>
// It writes <out dir>/bundle.js. The WASM is served by driver.mjs.
const outDir = process.argv[2];
if (!outDir)
  throw new Error("usage: bun docs/e2e/cover-timers/build-sealed.ts <out dir>");

const worker = await Bun.build({
  entrypoints: ["src/db/db.worker.ts"],
  target: "browser",
  format: "esm",
});
if (!worker.success)
  throw new AggregateError(worker.logs, "worker build failed");
const workerSource = await worker.outputs[0].text();

const page = await Bun.build({
  entrypoints: ["docs/e2e/cover-timers/entry-sealed.ts"],
  target: "browser",
  format: "esm",
  define: {
    "process.env.INDEXEDDB_WORKER_JS": JSON.stringify(workerSource),
    "process.env.P2PARTY_VERSION": JSON.stringify("0.14.10"),
    "process.env.P2PARTY_LOCAL_WASM": JSON.stringify("true"),
  },
});
if (!page.success) throw new AggregateError(page.logs, "page build failed");
await Bun.write(`${outDir}/bundle.js`, page.outputs[0]);
console.log(
  `wrote ${outDir}/bundle.js (${String(page.outputs[0].size)} bytes; worker ${String(workerSource.length)} bytes)`,
);
