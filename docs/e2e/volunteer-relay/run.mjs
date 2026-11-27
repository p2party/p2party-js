import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";

const require = createRequire(
  resolve(process.env.P2PARTY_RELAY_DEPS ?? ".", "package.json"),
);
const { chromium } = require("playwright");
const pkg = require("p2party/package.json");
assert.equal(
  pkg.version,
  "0.15.1",
  "Use the released P2Party SDK tested by this fixture",
);
const lib = join(dirname(require.resolve("p2party/package.json")), "lib");
const resources = new Map([
  [
    "/peer.mjs",
    ["text/javascript", await readFile(new URL("./peer.mjs", import.meta.url))],
  ],
  [
    "/relay.mjs",
    [
      "text/javascript",
      await readFile(new URL("./relay.mjs", import.meta.url)),
    ],
  ],
  [
    "/session.mjs",
    ["text/javascript", await readFile(join(lib, "session.mjs"))],
  ],
  [
    "/libcrypto.wasm",
    ["application/wasm", await readFile(join(lib, "libcrypto.wasm"))],
  ],
]);
// Playwright fulfills this local origin in memory. There is no signaling,
// TURN or application server listening for a visitor to connect to.
const origin = "http://127.0.0.1:49678";
const browser = await chromium.launch({
  args: [
    "--allow-loopback-in-peer-connection",
    "--disable-features=WebRtcHideLocalIpsWithMdns",
    "--use-fake-device-for-media-stream",
  ],
});
const pages = {};
const external = [],
  errors = [];
const neighbors = { A: { AC: "C", AB: "B" }, B: { AB: "A" }, C: { AC: "A" } };
const watchdog = setTimeout(() => {
  void browser.close();
}, 45_000);
try {
  for (const name of ["A", "B", "C"]) {
    const context = await browser.newContext();
    // Chromium enumerates the loopback interface only with this test permission.
    // No page calls getUserMedia, and Chromium exposes fake media devices only.
    await context.grantPermissions(["microphone"], { origin });
    await context.routeWebSocket("**/*", (socket) => {
      external.push("WebSocket");
      socket.close();
    });
    await context.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== origin || route.request().method() !== "GET") {
        external.push(url.origin);
        return route.abort();
      }
      if (url.pathname === "/") {
        const buttons =
          name === "B"
            ? '<button id="enable">Enable forwarding for two seconds, up to two records</button><button id="stop">Stop forwarding</button>'
            : "";
        return route.fulfill({
          contentType: "text/html",
          body: `<!doctype html><title>Local peer ${name}</title>${buttons}<script type="module" src="/peer.mjs"></script>`,
        });
      }
      const resource = resources.get(url.pathname);
      if (!resource) return route.fulfill({ status: 404 });
      return route.fulfill({ contentType: resource[0], body: resource[1] });
    });
    const page = await context.newPage();
    pages[name] = page;
    page.on("pageerror", (error) => errors.push(error.message));
    await page.exposeFunction("fixtureHandshake", (session, bytes) => {
      const remote = neighbors[name][session];
      assert(remote && bytes.length <= 16_384, "Unexpected local handshake");
      return pages[remote].evaluate((message) => peer.handshakeInput(message), {
        name: session,
        bytes,
      });
    });
    await page.goto(origin + "/#" + name);
    await page.waitForFunction(() => Boolean(window.peer), null, {
      timeout: 5000,
    });
  }
  async function establish(first, second, name) {
    const a = pages[first],
      b = pages[second];
    const [pinA, pinB] = await Promise.all(
      [a, b].map((page) => page.evaluate(() => peer.publicKey)),
    );
    const id = [...randomBytes(16)],
      left = [...randomBytes(32)],
      right = [...randomBytes(32)];
    assert.deepEqual(
      await Promise.all([
        a.evaluate((args) => peer.establish(args), {
          name,
          id,
          side: "initiator",
          pin: pinB,
          local: left,
          remote: right,
        }),
        b.evaluate((args) => peer.establish(args), {
          name,
          id,
          side: "responder",
          pin: pinA,
          local: right,
          remote: left,
        }),
      ]),
      [true, true],
    );
  }
  async function connect(a, b, name) {
    await Promise.all(
      [a, b].map((page) => page.evaluate((link) => peer.openLink(link), name)),
    );
    const signal = (page, remote) =>
      page.evaluate((args) => peer.description(args), { name, remote });
    const offer = await signal(a);
    const answer = await signal(b, offer);
    await signal(a, answer);
    for (const page of [a, b]) {
      await page.waitForFunction((link) => peer.isOpen(link), name, {
        timeout: 6000,
      });
      assert.equal(
        await page.evaluate((link) => peer.loopbackPair(link), name),
        true,
      );
    }
  }
  const { A, B, C } = pages;
  await establish("A", "C", "AC");
  await establish("A", "B", "AB");
  const own = await A.evaluate(() => peer.diagnosticMessage());
  assert.deepEqual(
    await B.evaluate((message) => peer.openDiagnostic(message), own),
    [42],
  );
  await connect(A, B, "AB");
  await connect(B, C, "BC");
  const payload = [...randomBytes(1024)];
  await A.evaluate((input) => peer.prepare(input), payload);
  let attempts = 0;
  async function send(kind, expected) {
    await A.evaluate((k) => peer.send(k), kind);
    await B.waitForFunction(
      (n) => peer.snapshot().verdicts.length === n,
      ++attempts,
      { timeout: 3000 },
    );
    assert.equal(
      await B.evaluate(() => peer.snapshot().verdicts.at(-1)),
      expected,
    );
  }
  const enable = () =>
    B.getByRole("button", { name: /Enable forwarding/ }).click();
  await send("sample", "disabled");
  await enable();
  for (const kind of ["text", "short", "version"])
    await send(kind, "unsupported");
  await send("sample", "forwarded");
  await C.waitForFunction(() => peer.snapshot().received.length === 1);
  assert.deepEqual(
    await C.evaluate(() => peer.snapshot().received[0]),
    payload,
  );
  assert.equal(await B.evaluate(() => peer.canOpenAsVolunteer()), false);
  // Corruption is tested on a fresh envelope, so replay rejection cannot
  // accidentally satisfy the recipient authentication check.
  await A.evaluate(() => peer.prepare([10, 20, 30]));
  await send("tampered", "forwarded");
  await C.waitForFunction(() => peer.snapshot().rejected === 1);
  await send("sample", "exhausted");
  const grantUsage = await B.evaluate(() => peer.snapshot().used);
  assert.equal(grantUsage, 2 * (5 + 64 + 65490));
  await enable();
  await B.getByRole("button", { name: "Stop forwarding" }).click();
  await send("sample", "stopped");
  await enable();
  await B.waitForFunction(() => peer.snapshot().state === "expired", null, {
    timeout: 4000,
  });
  await send("sample", "expired");
  assert.deepEqual(await C.evaluate(() => peer.snapshot().received), [payload]);
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  console.log(
    JSON.stringify(
      {
        chromium: browser.version(),
        sdk: pkg.version,
        loopbackLinks: 2,
        verifiedPlaintextBytes: payload.length,
        forwardedRecordBytes: grantUsage / 2,
        forwardedBytesInGrant: grantUsage,
        relayOpenedMessage: false,
        rejectedTamper: true,
        verdicts: await B.evaluate(() => peer.snapshot().verdicts),
        externalRequests: 0,
      },
      null,
      2,
    ),
  );
} finally {
  clearTimeout(watchdog);
  try {
    await Promise.all(
      Object.values(pages).map((page) =>
        page.evaluate(() => window.peer?.dispose()),
      ),
    );
  } finally {
    await browser.close();
  }
}
