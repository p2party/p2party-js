import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";

export async function openPayerScreen(mode, directory) {
  const automatic = mode !== "--interactive",
    cancel = mode === "--test-ui-cancel";
  const require = createRequire(
    resolve(process.env.P2PARTY_RELAY_DEPS ?? ".", "package.json"),
  );
  const browser = await require("playwright").chromium.launch({
    headless: automatic,
  });
  try {
    const context = await browser.newContext({
      viewport: automatic ? { width: 390, height: 844 } : null,
      serviceWorkers: "block",
    });
    const origin = "http://127.0.0.1:49679";
    const [html, logo] = await Promise.all([
      readFile(new URL("./payer.html", import.meta.url)),
      readFile(new URL("../../assets/p2party-cat.svg", import.meta.url)),
    ]);
    await context.routeWebSocket("**/*", (ws) => ws.close());
    await context.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== origin || route.request().method() !== "GET")
        return route.abort();
      if (url.pathname === "/")
        return route.fulfill({ contentType: "text/html", body: html });
      if (url.pathname === "/cat.svg")
        return route.fulfill({ contentType: "image/svg+xml", body: logo });
      return route.abort();
    });
    const page = await context.newPage();
    await page.exposeFunction("findLocalRoute", (request) =>
      directory.find(request),
    );
    await page.goto(origin);
    let suggestion;
    return {
      async choose() {
        if (mode === "--test-ui-discovery") {
          await page.getByLabel("Maximum total").fill("1");
          await page
            .getByRole("button", { name: "Find a route under my cap" })
            .click();
          await page.getByText("No available route fits this cap.").waitFor();
          await page.getByLabel("Maximum total").fill("2");
          await page
            .getByRole("button", { name: "Find a route under my cap" })
            .click();
          await page.getByText(/^Suggested route:/).waitFor();
          suggestion = await Promise.all(
            ["First relay", "Second relay"].map((l) =>
              page.getByLabel(l).inputValue(),
            ),
          );
          assert.equal(new Set(suggestion).size, 2);
          await page
            .getByRole("button", { name: "Review signed quotes" })
            .click();
        } else if (automatic) {
          await page.getByLabel("First relay").selectOption("B");
          assert(
            await page
              .getByRole("button", { name: "Review signed quotes" })
              .isDisabled(),
          );
          await page.getByLabel("Second relay").selectOption("E");
          await page.getByLabel("Third relay").selectOption("D");
          assert(
            await page
              .getByRole("button", { name: "Review signed quotes" })
              .isDisabled(),
          );
          await page.getByLabel("Maximum total").fill("4");
          await page
            .getByRole("button", { name: "Review signed quotes" })
            .click();
        }
        await page.waitForFunction(() => window.payer.state.selection, null, {
          timeout: 0,
        });
        return page.evaluate(() => window.payer.state.selection);
      },
      async review(q) {
        await page.evaluate((terms) => window.payer.showQuotes(terms), q);
        if (automatic) {
          assert.equal(
            await page
              .getByText(
                suggestion
                  ? ["A", ...suggestion, "C"].join(" → ")
                  : "A → B → E → D → C",
                { exact: true },
              )
              .count(),
            1,
          );
          assert.equal(
            await page
              .getByText(
                suggestion
                  ? "2 test P2PARTY total · Budget 2 P2PARTY"
                  : "3 test P2PARTY total · Budget 4 P2PARTY",
                {
                  exact: true,
                },
              )
              .count(),
            1,
          );
          assert.equal(
            await page.locator("article").count(),
            suggestion?.length ?? 3,
          );
          await page.locator("summary").first().click();
          assert.equal(
            await page.locator("article code").first().textContent(),
            q.id,
          );
          assert(
            await page.evaluate(
              () => document.documentElement.scrollWidth <= innerWidth,
            ),
          );
          await page
            .getByRole("button", {
              name: cancel ? "Cancel purchase" : "Approve purchase",
            })
            .click();
        }
        await page.waitForFunction(() => window.payer.state.decision, null, {
          timeout: Math.max(1, q.until - Date.now()),
        });
        const selected = await page.evaluate(() => window.payer.state.decision);
        if (selected === "cancel") return false;
        assert.equal(selected, q.id);
        if (Date.now() >= q.until) throw Error("Quote expired before approval");
        return true;
      },
      async verified(roles) {
        await page.evaluate((names) => window.payer.verified(names), roles);
      },
      async fail() {
        if (automatic || page.isClosed()) return;
        await page.evaluate(() =>
          window.payer.finish(
            "Purchase stopped. Check the credits shown here and the local driver for details.",
          ),
        );
        await page
          .waitForFunction(() => window.payer.state.done, null, { timeout: 0 })
          .catch(() => {});
      },
      async credit(info) {
        await page.evaluate((c) => window.payer.recordCredit(c), info);
      },
      async finish(message) {
        await page.evaluate((m) => window.payer.finish(m), message);
        if (automatic) {
          if (cancel)
            assert.equal(
              await page.getByText(/Received 1 test P2PARTY/).count(),
              0,
            );
          else {
            assert.equal(
              await page.getByText(/Received 1 test P2PARTY/).count(),
              suggestion?.length ?? 3,
            );
            assert.equal(
              await page
                .getByText("Inspect payment receipt", { exact: true })
                .count(),
              suggestion?.length ?? 3,
            );
          }
          await page.getByRole("button", { name: "Close test wallet" }).click();
        }
        await page.waitForFunction(() => window.payer.state.done, null, {
          timeout: 0,
        });
      },
      close: () => browser.close(),
    };
  } catch (error) {
    await browser.close();
    throw error;
  }
}
