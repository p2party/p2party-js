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
export async function withRelayBrowsers(roles, exercise, timeout = 45_000) {
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
  const neighbors = new Map();
  const watchdog = setTimeout(() => {
    void browser.close();
  }, timeout);
  try {
    for (const name of roles) {
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
            name !== "A" && name !== "C"
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
        const remote = neighbors.get(name + ":" + session);
        assert(remote && bytes.length <= 16_384, "Unexpected local handshake");
        return pages[remote].evaluate(
          (message) => peer.handshakeInput(message),
          {
            name: session,
            bytes,
          },
        );
      });
      await page.goto(origin + "/#" + name);
      await page.waitForFunction(() => Boolean(window.peer), null, {
        timeout: 5000,
      });
    }
    async function establish(first, second, name) {
      neighbors.set(first + ":" + name, second);
      neighbors.set(second + ":" + name, first);
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
        [a, b].map((page) =>
          page.evaluate((link) => peer.openLink(link), name),
        ),
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
    await exercise({
      pages,
      establish,
      connect,
      chromium: browser.version(),
      sdk: pkg.version,
    });
    assert.deepEqual(external, []);
    assert.deepEqual(errors, []);
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
}
