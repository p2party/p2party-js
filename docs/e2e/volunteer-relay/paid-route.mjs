import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { withRelayBrowsers } from "./browser-fixture.mjs";
import {
  checkQuotes,
  digest,
  paidRecordBytes,
  PayoutJournal,
  providerId,
  routeId,
  signQuote,
  verifyDelivery,
  verifyForwarding,
} from "./payment-protocol.mjs";

const [routeOption = "--via=D,B", capOption = "--max=2"] =
  process.argv.slice(2);
if (
  process.argv.length > 4 ||
  !/^--via=[BDE](,[BDE]){1,2}$/.test(routeOption) ||
  !/^--max=[1-9]\d*$/.test(capOption)
)
  throw Error(
    "Usage: paid-route.mjs --via=D,B --max=2 (choose two or three distinct relays among B,D,E)",
  );
const chosen = routeOption.slice(6).split(","),
  cap = Number(capOption.slice(6));
if (
  !Number.isSafeInteger(cap) ||
  chosen.length !== new Set(chosen).size ||
  chosen.length > cap
)
  throw Error("Duplicate relay or insufficient payer cap");
if (
  !process.env.P2PARTY_RELAY_SERVER ||
  !process.env.P2PARTY_TEST_POSTGRES_URL ||
  !process.env.P2PARTY_TEST_LEDGER_VERIFIER
)
  throw Error(
    "Set fixture paths and the disposable local PostgreSQL URL; see README",
  );
const serverRoot = resolve(process.env.P2PARTY_RELAY_SERVER);
const lib = (name) =>
  import(
    pathToFileURL(join(serverRoot, "clients/evm/dist", name + ".js")).href
  );
const [
  {
    createLedgerTransport,
    readHandle,
    receiveOwner,
    signTransfer,
    transferIds,
  },
  { nodeSigner },
] = await Promise.all([lib("index"), lib("node")]);
const directory = await mkdtemp(join(tmpdir(), "p2party-paid-relays-"));
const makeKey = () => generateKeyPairSync("ml-dsa-65");
const hex = (n) => "0x" + randomBytes(n).toString("hex");
function wallet(algorithm = "ml-dsa-65") {
  const signer = nodeSigner(generateKeyPairSync(algorithm).privateKey),
    nonce = randomBytes(32);
  return { signer, nonce, owner: receiveOwner(signer, nonce) };
}
const chainId = hex(32),
  rpcChainId = 8123;
const providers = chosen.map((role, i) => ({
  role,
  key: makeKey(),
  payee: wallet(i % 2 ? "slh-dsa-sha2-192s" : "ml-dsa-65"),
  funding: wallet(),
  id: hex(64),
}));
const genesisFile = join(directory, "genesis.json");
await writeFile(
  genesisFile,
  JSON.stringify({
    version: 1,
    chainId,
    rpcChainId,
    spendSuites: [1, 2],
    receiveSuites: [1, 2],
    units: providers.map((p) => ({
      id: p.id,
      weight: "0x1",
      ...p.funding.owner,
    })),
  }),
  { mode: 0o600 },
);
const proc = spawn(
  "bun",
  [
    "--no-env-file",
    fileURLToPath(new URL("./fixture-ledger.mjs", import.meta.url)),
    serverRoot,
    genesisFile,
    chainId,
  ],
  {
    stdio: ["pipe", "pipe", "inherit"],
    env: {
      PATH: process.env.PATH,
      P2PARTY_TEST_POSTGRES_URL: process.env.P2PARTY_TEST_POSTGRES_URL,
      P2PARTY_TEST_LEDGER_VERIFIER: process.env.P2PARTY_TEST_LEDGER_VERIFIER,
    },
  },
);
const exit = new Promise((resolve, reject) => {
  proc.once("error", reject);
  proc.once("exit", resolve);
});
const journalPath = join(directory, "payer.sqlite");
let journal, timer;
try {
  const lines = createInterface({ input: proc.stdout });
  const first = await Promise.race([
    lines[Symbol.asyncIterator]().next(),
    exit.then(() => {
      throw Error("Fixture ledger exited before readiness");
    }),
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(Error("Fixture ledger startup timed out")),
        15000,
      );
    }),
  ]);
  clearTimeout(timer);
  lines.close();
  assert(!first.done);
  const { url, genesis } = JSON.parse(first.value);
  assert(/^http:\/\/127\.0\.0\.1:\d+\/rpc$/.test(url));
  const transport = await createLedgerTransport({ url, chainId, rpcChainId });
  const rpc = (method, ...params) => transport.request({ method, params });
  const genesisResponse = await fetch(url, {
    method: "POST",
    redirect: "error",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "demos_getGenesisHash",
      params: [],
    }),
  });
  assert(genesisResponse.ok);
  assert.equal((await genesisResponse.json()).result, "0x" + genesis);
  await withRelayBrowsers(
    ["A", ...chosen, "C"],
    async ({ pages, establish, connect, chromium }) => {
      const browserKey = async (name) =>
        Buffer.from(await pages[name].evaluate(() => peer.publicKey)).toString(
          "hex",
        );
      const challenge = randomBytes(32);
      const content = randomBytes(1024 - 96);
      const hops = await Promise.all(
        providers.map(async (p) => ({
          provider: providerId(p.key.publicKey),
          browserKey: await browserKey(p.role),
          witnessKey: await pages[p.role].evaluate(() => peer.deliveryKey()),
          inputId: p.id,
          ...p.payee.owner,
          reward: 1,
        })),
      );
      const route = {
        chainId,
        genesis,
        nonce: randomBytes(32).toString("hex"),
        payer: await browserKey("A"),
        recipient: await browserKey("C"),
        receiptKey: await pages.C.evaluate(() => peer.deliveryKey()),
        challengeHash: digest("challenge", challenge),
        contentHash: digest("content", content),
        until: Date.now() + 60000,
        expiryHeight: 32,
        budget: cap,
        hops,
      };
      const quotes = providers.map((p, i) =>
        signQuote(route, i, p.key.privateKey),
      );
      const pins = providers.map((p) => p.key.publicKey);
      const id = checkQuotes(route, quotes, pins);
      console.error(
        "Accepted ML-DSA-65 quotes " +
          JSON.stringify({
            route: ["A", ...chosen, "C"],
            capP2PARTY: cap,
            costP2PARTY: hops.length,
            expires: new Date(route.until).toISOString(),
            routeId: id,
            hops: hops.map((h, i) => ({
              role: chosen[i],
              rewardP2PARTY: h.reward,
              grantBytes: paidRecordBytes,
              providerKeyId: h.provider,
              receiveCommitment: h.commitment,
            })),
          }),
      );
      assert.throws(() => routeId({ ...route, budget: hops.length - 1 }));
      assert.throws(() => routeId({ ...route, hops: [hops[0], hops[0]] }));
      assert.throws(() =>
        checkQuotes(
          { ...route, hops: [...hops].reverse() },
          quotes,
          [...pins].reverse(),
        ),
      );
      assert.throws(() =>
        checkQuotes(
          {
            ...route,
            hops: hops.map((h, i) => (i ? h : { ...h, commitment: hex(64) })),
          },
          quotes,
          pins,
        ),
      );
      assert.throws(() =>
        checkQuotes({ ...route, chainId: hex(32) }, quotes, pins),
      );
      assert.throws(() => checkQuotes(route, quotes.slice(1), pins));
      // The test UI asks each selected browser for consent after the quote and
      // checks one preconnected neighbor in each direction. The CLI is the payer.
      await establish("A", "C", "AC");
      const path = ["A", ...chosen, "C"];
      for (const [index, role] of chosen.entries()) {
        await pages[role].evaluate((order) => peer.setPaidGrant(order), {
          bytes: paidRecordBytes,
          id,
          index,
        });
      }
      for (let i = 1; i < path.length; i++)
        await connect(
          pages[path[i - 1]],
          pages[path[i]],
          path[i - 1] + path[i],
        );
      const payload = Buffer.concat([
        Buffer.from(id, "hex"),
        challenge,
        content,
      ]);
      const send = () => pages.A.evaluate(() => peer.send("sample"));
      const recordHash = await pages.A.evaluate(
        (data) => peer.prepare(data),
        [...payload],
      );
      await send();
      await pages[chosen[0]].waitForFunction(
        () => peer.snapshot().verdicts.at(-1) === "disabled",
      );
      await assert.rejects(pages.C.evaluate(() => peer.acknowledge()));
      assert.equal((await rpc("demos_getHead")).height, "0x0");
      // A stopped relay drops even an authentic record.
      await pages[chosen[0]]
        .getByRole("button", { name: /Enable forwarding/ })
        .click();
      await pages[chosen[0]]
        .getByRole("button", { name: "Stop forwarding" })
        .click();
      await send();
      await pages[chosen[0]].waitForFunction(
        () => peer.snapshot().verdicts.at(-1) === "stopped",
      );
      await assert.rejects(pages.C.evaluate(() => peer.acknowledge()));
      // One consenting upstream relay alone cannot authorize a purchase.
      await pages[chosen[0]]
        .getByRole("button", { name: /Enable forwarding/ })
        .click();
      await send();
      await pages[chosen[1]].waitForFunction(
        () => peer.snapshot().verdicts.at(-1) === "disabled",
      );
      assert.equal(
        await pages[chosen[0]].evaluate(() => peer.snapshot().used),
        paidRecordBytes,
      );
      await assert.rejects(pages.C.evaluate(() => peer.acknowledge()));
      assert.equal((await rpc("demos_getHead")).height, "0x0");
      await pages[chosen[0]].evaluate(() => peer.forwardingReceipt());
      await assert.rejects(
        pages[chosen[1]].evaluate(() => peer.forwardingReceipt()),
      );
      for (const role of [...chosen].reverse())
        await pages[role]
          .getByRole("button", { name: /Enable forwarding/ })
          .click();
      await send();
      await pages.C.waitForFunction(
        () => peer.snapshot().received.length === 1,
        null,
        { timeout: 5000 },
      );
      assert.deepEqual(
        Buffer.from(await pages.C.evaluate(() => peer.snapshot().received[0])),
        payload,
      );
      for (const role of chosen) {
        const s = await pages[role].evaluate(() => peer.snapshot());
        assert.equal(s.used, paidRecordBytes);
        assert.equal(s.state, "exhausted");
        assert.equal(
          s.verdicts.filter((x) => x === "forwarded").length,
          role === chosen[0] ? 2 : 1,
        );
      }
      await send();
      await pages[chosen[0]].waitForFunction(
        () => peer.snapshot().verdicts.at(-1) === "exhausted",
      );
      const ack = await pages.C.evaluate(() => peer.acknowledge());
      const witnesses = await Promise.all(
        chosen.map((role) =>
          pages[role].evaluate(() => peer.forwardingReceipt()),
        ),
      );
      verifyDelivery(route, ack, recordHash);
      verifyForwarding(route, recordHash, witnesses);
      assert.throws(() =>
        verifyDelivery(
          route,
          { ...ack, binding: "00".repeat(224) },
          recordHash,
        ),
      );
      assert.throws(() =>
        verifyDelivery(
          route,
          {
            ...ack,
            binding:
              ack.binding.slice(0, 192) +
              "00".repeat(64) +
              ack.binding.slice(320),
          },
          recordHash,
        ),
      );
      assert.throws(() =>
        verifyForwarding(
          { ...route, nonce: randomBytes(32).toString("hex") },
          recordHash,
          witnesses,
        ),
      );
      assert.throws(() => verifyForwarding(route, "00".repeat(64), witnesses));
      const signHop = async (h, i) => {
        const unit = await rpc("demos_getUnit", h.inputId),
          p = providers[i];
        assert.equal(BigInt(unit.weight), BigInt(h.reward));
        return signTransfer(
          {
            chainId,
            input: unit,
            recipient: { suite: h.suite, commitment: h.commitment },
            expiryHeight: BigInt(route.expiryHeight),
          },
          p.funding.signer,
          p.funding.nonce,
        );
      };
      journal = new PayoutJournal(journalPath);
      const auth = { route, quotes, pins, ack, witnesses, recordHash, signHop };
      assert.throws(() => journal.resume(route));
      await assert.rejects(
        journal.prepare({ ...auth, witnesses: witnesses.slice(1) }),
      );
      await assert.rejects(
        journal.prepare({ ...auth, witnesses: [...witnesses].reverse() }),
      );
      await assert.rejects(
        journal.prepare({
          ...auth,
          witnesses: witnesses.map(() => witnesses[0]),
        }),
      );
      await assert.rejects(
        journal.prepare({ ...auth, recordHash: "00".repeat(64) }),
      );
      await assert.rejects(
        journal.prepare({
          ...auth,
          ack: { ...ack, signature: "00".repeat(64) },
        }),
      );
      await assert.rejects(journal.prepare({ ...auth, now: route.until + 1 }));
      const wires = await journal.prepare(auth);
      async function pay(wire, i) {
        const expected = transferIds(wire, chainId);
        assert.equal(expected.inputId, hops[i].inputId);
        // Native v1 signs these fixed-width fields. Check the prepared wire
        // against the agreed terms again before every submission, including retries.
        const body = Buffer.from(wire.slice(2), "hex");
        assert.equal(body.readBigUInt64BE(98), BigInt(hops[i].reward));
        assert.equal(body.readBigUInt64BE(106), BigInt(route.expiryHeight));
        assert.equal(body[115], hops[i].suite);
        assert.equal(
          "0x" + body.subarray(116, 180).toString("hex"),
          hops[i].commitment,
        );
        const move = await rpc("demos_sendRawTransfer", wire);
        assert.equal(move, expected.id);
        const receipt = await rpc("demos_getTransfer", move);
        assert.equal(receipt.outputId, expected.outputId);
        const unit = await rpc("demos_getUnit", receipt.outputId);
        assert.equal(unit.commitment, hops[i].commitment);
        assert.equal(unit.suite, hops[i].suite);
        assert.equal(unit.weight, "0x1");
        return move;
      }
      await assert.rejects(pay(wires[1], 0));
      assert.equal((await rpc("demos_getHead")).height, "0x0");
      await pay(wires[0], 0);
      // Interrupted after the first provider is paid. Reopen without keys/signers.
      journal.close();
      journal = new PayoutJournal(journalPath);
      const approved = journal.resume(route);
      assert.deepEqual(approved, wires);
      for (const [i, wire] of approved.entries()) await pay(wire, i);
      for (const [i, wire] of approved.entries()) await pay(wire, i);
      assert.equal(
        BigInt((await rpc("demos_getHead")).height),
        BigInt(chosen.length),
      );
      const credits = [];
      for (const [i, p] of providers.entries()) {
        assert.equal(
          await rpc("eth_getBalance", readHandle(p.funding.owner), "latest"),
          "0x0",
        );
        assert.equal(
          await rpc("eth_getBalance", readHandle(p.payee.owner), "latest"),
          "0x1",
        );
        const ids = transferIds(approved[i], chainId);
        credits.push({
          role: p.role,
          P2PARTY: 1,
          transferId: ids.id,
          outputId: ids.outputId,
          receiveSuite: p.payee.owner.suite,
          commitment: p.payee.owner.commitment,
        });
      }
      console.log(
        JSON.stringify(
          {
            chromium,
            route: path,
            loopbackLinks: path.length - 1,
            verifiedPlaintextBytes: payload.length,
            forwardedBytesPerRelay: paidRecordBytes,
            paidP2PARTY: chosen.length,
            credits,
            ledgerHeightAfterRetries: chosen.length,
            endpointReceipt: "Ed25519",
            verifiedForwardingReceipts: witnesses.length,
            encryptedRecordHash: recordHash,
            providerQuotes: "ML-DSA-65",
            scope: "disposable local chain",
          },
          null,
          2,
        ),
      );
    },
  );
} finally {
  clearTimeout(timer);
  journal?.close();
  proc.stdin.end();
  const code = await exit;
  await rm(directory, { recursive: true, force: true });
  if (code !== 0) throw Error("Fixture ledger stopped with " + code);
}
