import assert from "node:assert/strict";
import { paidRecordBytes } from "./payment-protocol.mjs";

// Browser counters count encrypted application bytes accepted by each relay's
// outbound DataChannel. SCTP, UDP overhead and sender transmissions are separate.
export async function refusalTrials({
  pages,
  roles,
  rpc,
  send,
  fundingInputs,
  payees,
}) {
  const snapshots = () =>
    Promise.all(
      roles.map((role) => pages[role].evaluate(() => peer.snapshot())),
    );
  const attempts = [];
  const enable = (role) =>
    pages[role].getByRole("button", { name: /Enable forwarding/ }).click();

  async function refuse(at, withdraw) {
    const before = await snapshots();
    const role = roles[at];
    for (const upstream of roles.slice(0, at).reverse()) await enable(upstream);
    if (withdraw) {
      await enable(role);
      await pages[role]
        .getByRole("button", { name: "Stop forwarding" })
        .click();
    }
    const senderRecordBytes = await send();
    assert.equal(senderRecordBytes, paidRecordBytes);
    const expected = withdraw ? "stopped" : "disabled";
    await pages[role].waitForFunction(
      ({ count, expected }) => {
        const { verdicts } = peer.snapshot();
        return verdicts.length === count + 1 && verdicts.at(-1) === expected;
      },
      { count: before[at].verdicts.length, expected },
      { timeout: 5000 },
    );
    const after = await snapshots();
    const upstreamBytes = {};
    for (const [index, current] of after.entries()) {
      const delta =
        current.totalForwardedBytes - before[index].totalForwardedBytes;
      assert.equal(delta, index < at ? paidRecordBytes : 0);
      assert.equal(
        current.verdicts.length - before[index].verdicts.length,
        index <= at ? 1 : 0,
      );
      if (index < at)
        await pages[roles[index]].evaluate(() => peer.forwardingReceipt());
      upstreamBytes[roles[index]] = delta;
    }
    await assert.rejects(pages[role].evaluate(() => peer.forwardingReceipt()));
    await assert.rejects(pages.C.evaluate(() => peer.acknowledge()));
    assert.equal(
      await pages.C.evaluate(() => peer.snapshot().received.length),
      0,
    );
    const { height } = await rpc("demos_getHead");
    assert.equal(BigInt(height), 0n);
    for (const id of fundingInputs)
      assert.equal((await rpc("demos_getUnit", id)).spentHeight, null);
    const balances = await Promise.all(
      payees.map((handle) => rpc("eth_getBalance", handle, "latest")),
    );
    const paid = balances.reduce(
      (sum, value) => sum + Number(BigInt(value)),
      0,
    );
    assert.equal(paid, 0);
    attempts.push({
      refusedAtHop: at + 1,
      volunteer: role,
      verdict: expected,
      senderRecordBytes,
      forwardedBytesByRelay: upstreamBytes,
      unpaidRelayBytes: Object.values(upstreamBytes).reduce(
        (sum, n) => sum + n,
        0,
      ),
      deliveredRecords: 0,
      paidP2PARTY: paid,
      ledgerHeight: Number(BigInt(height)),
    });
  }
  await refuse(0, false);
  await refuse(0, true);
  for (let index = 1; index < roles.length; index++) await refuse(index, false);
  return attempts;
}

export async function connectOrder({
  pages,
  connect,
  roles,
  id,
  challenge,
  content,
}) {
  const path = ["A", ...roles, "C"];
  for (const [index, role] of roles.entries()) {
    await pages[role].evaluate((grant) => peer.setPaidGrant(grant), {
      bytes: paidRecordBytes,
      id,
      index,
    });
  }
  for (let i = 1; i < path.length; i++) {
    await connect(pages[path[i - 1]], pages[path[i]], path[i - 1] + path[i]);
  }
  const payload = Buffer.concat([Buffer.from(id, "hex"), challenge, content]);
  const recordHash = await pages.A.evaluate(
    (data) => peer.prepare(data),
    [...payload],
  );
  return { path, payload, recordHash };
}
