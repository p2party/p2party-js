import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { withRelayBrowsers } from "./browser-fixture.mjs";

await withRelayBrowsers(
  ["A", "B", "C"],
  async ({ pages, establish, connect, chromium, sdk }) => {
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
    assert.deepEqual(await C.evaluate(() => peer.snapshot().received), [
      payload,
    ]);

    console.log(
      JSON.stringify(
        {
          chromium,
          sdk,
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
  },
);
