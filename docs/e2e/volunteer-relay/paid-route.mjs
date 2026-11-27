import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { openPayerScreen } from "./payer-screen.mjs";
import { withRelayBrowsers } from "./browser-fixture.mjs";
import { connectOrder, refusalTrials } from "./refusal-trials.mjs";
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

const args = process.argv.slice(2);
const screenMode =
  args.length === 1 &&
  ["--interactive", "--test-ui", "--test-ui-cancel"].includes(args[0])
    ? args[0]
    : null;
function cliSelection() {
  const [via = "--via=D,B", maximum = "--max=2", replaces] = args;
  if (
    args.length > 3 ||
    (replaces !== undefined && !/^--replaces=[BDEF]$/.test(replaces)) ||
    !/^--via=[BDE](,[BDE]){1,2}$/.test(via) ||
    !/^--max=[1-9]\d*$/.test(maximum)
  )
    throw Error(
      "Usage: paid-route.mjs --via=D,B --max=2 [--replaces=E], or --interactive",
    );
  return {
    chosen: via.slice(6).split(","),
    cap: Number(maximum.slice(6)),
    replaces: replaces?.slice("--replaces=".length),
  };
}
async function purchase({ chosen, cap, replaces }, screen) {
  if (
    !Array.isArray(chosen) ||
    chosen.length < 2 ||
    chosen.length > 3 ||
    !chosen.every((r) => ["B", "D", "E"].includes(r)) ||
    (replaces !== undefined &&
      (!["B", "D", "E", "F"].includes(replaces) ||
        chosen.includes(replaces))) ||
    !Number.isSafeInteger(cap) ||
    chosen.length !== new Set(chosen).size ||
    chosen.length > cap
  )
    throw Error("Invalid relay selection or insufficient payer cap");
  let completion;
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
      ["A", ...chosen, ...(replaces ? [replaces] : []), "C"],
      async ({ pages, establish, connect, chromium }) => {
        const browserKey = async (name) =>
          Buffer.from(
            await pages[name].evaluate(() => peer.publicKey),
          ).toString("hex");
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
          until: Date.now() + (screen ? 300_000 : 60_000),
          expiryHeight: 32,
          budget: cap,
          hops,
        };
        const send = () => pages.A.evaluate(() => peer.send("sample"));
        let failures = [],
          abandoned = null;
        if (replaces) {
          await establish("A", "C", "AC");
          const last = hops.length - 1;
          const oldProvider = { key: makeKey(), payee: wallet() };
          const oldRoles = [...chosen.slice(0, -1), replaces];
          const earlierChallenge = randomBytes(32);
          const previous = {
            ...route,
            nonce: randomBytes(32).toString("hex"),
            challengeHash: digest("challenge", earlierChallenge),
            hops: [
              ...hops.slice(0, last),
              {
                ...hops[last],
                ...oldProvider.payee.owner,
                provider: providerId(oldProvider.key.publicKey),
                browserKey: await browserKey(replaces),
                witnessKey: await pages[replaces].evaluate(() =>
                  peer.deliveryKey(),
                ),
              },
            ],
          };
          const oldProviders = [...providers.slice(0, last), oldProvider];
          const previousQuotes = oldProviders.map((provider, index) =>
            signQuote(previous, index, provider.key.privateKey),
          );
          const previousPins = oldProviders.map(
            (provider) => provider.key.publicKey,
          );
          const oldId = checkQuotes(previous, previousQuotes, previousPins);
          const oldOrder = await connectOrder({
            pages,
            connect,
            roles: oldRoles,
            id: oldId,
            challenge: earlierChallenge,
            content,
          });
          failures = await refusalTrials({
            pages,
            roles: oldRoles,
            rpc,
            send,
            fundingInputs: previous.hops.map((h) => h.inputId),
            payees: oldProviders.map((p) => readHandle(p.payee.owner)),
          });
          await Promise.all(
            Object.values(pages).map((p) =>
              p.evaluate(() => peer.abandonRoute()),
            ),
          );
          assert.throws(() => checkQuotes(route, previousQuotes, previousPins));
          abandoned = {
            id: oldId,
            recordHash: oldOrder.recordHash,
            path: oldOrder.path,
            replacedPayeeHandle: readHandle(oldProvider.payee.owner),
          };
        }
        const quotes = providers.map((p, i) =>
          signQuote(route, i, p.key.privateKey),
        );
        const pins = providers.map((p) => p.key.publicKey);
        const id = checkQuotes(route, quotes, pins);
        const terms = {
          id,
          path: ["A", ...chosen, "C"],
          cap,
          cost: hops.length,
          until: route.until,
          hops: hops.map((h, i) => ({
            role: chosen[i],
            bytes: paidRecordBytes,
            provider: h.provider,
            witness: h.witnessKey,
            suite: h.suite,
            reward: h.reward,
            inputId: h.inputId,
            commitment: h.commitment,
            signature: quotes[i],
          })),
        };
        if (screen) {
          if (!(await screen.review(terms))) {
            assert.equal((await rpc("demos_getHead")).height, "0x0");
            completion =
              "Purchase canceled. Zero records forwarded and zero P2PARTY spent.";
            console.log(
              JSON.stringify({
                canceled: true,
                ledgerHeight: 0,
                paidP2PARTY: 0,
              }),
            );
            return;
          }
        } else
          console.error(
            "Accepted ML-DSA-65 quotes " +
              JSON.stringify({
                ...terms,
                hops: terms.hops.map(({ signature, ...summary }) => summary),
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
        if (!abandoned) await establish("A", "C", "AC");
        const { path, payload, recordHash } = await connectOrder({
          pages,
          connect,
          roles: chosen,
          id,
          challenge,
          content,
        });
        if (abandoned) {
          assert.notEqual(id, abandoned.id);
          assert.notEqual(recordHash, abandoned.recordHash);
        } else if (!screen) {
          failures = await refusalTrials({
            pages,
            roles: chosen,
            rpc,
            send,
            fundingInputs: hops.map((h) => h.inputId),
            payees: providers.map((p) => readHandle(p.payee.owner)),
          });
        }
        const bytesBeforeDelivery = await Promise.all(
          chosen.map((role) =>
            pages[role].evaluate(() => peer.snapshot().totalForwardedBytes),
          ),
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
          Buffer.from(
            await pages.C.evaluate(() => peer.snapshot().received[0]),
          ),
          payload,
        );
        for (const [i, role] of chosen.entries()) {
          const s = await pages[role].evaluate(() => peer.snapshot());
          assert.equal(s.used, paidRecordBytes);
          assert.equal(s.state, "exhausted");
          assert.equal(
            s.totalForwardedBytes - bytesBeforeDelivery[i],
            paidRecordBytes,
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
        if (screen) await screen.verified(chosen);
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
        assert.throws(() =>
          verifyForwarding(route, "00".repeat(64), witnesses),
        );
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
        const auth = {
          route,
          quotes,
          pins,
          ack,
          witnesses,
          recordHash,
          signHop,
        };
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
        await assert.rejects(
          journal.prepare({ ...auth, now: route.until + 1 }),
        );
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
        let approved = wires;
        if (!screen) {
          await assert.rejects(pay(wires[1], 0));
          assert.equal((await rpc("demos_getHead")).height, "0x0");
          await pay(wires[0], 0);
          // Interrupt settlement and recover exact native wires without the keys.
          journal.close();
          journal = new PayoutJournal(journalPath);
          approved = journal.resume(route);
          assert.deepEqual(approved, wires);
          for (const [i, wire] of approved.entries()) await pay(wire, i);
        }
        for (const [i, wire] of approved.entries()) {
          await pay(wire, i);
          if (screen) {
            const { id: transferId, outputId } = transferIds(wire, chainId);
            await screen.credit({
              role: chosen[i],
              transferId,
              outputId,
              recordHash,
              witness: witnesses[i],
            });
          }
        }
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
        if (abandoned) {
          assert.equal(
            await rpc(
              "eth_getBalance",
              abandoned.replacedPayeeHandle,
              "latest",
            ),
            "0x0",
          );
        }
        completion =
          "Delivery verified. " +
          chosen.length +
          " volunteers received " +
          chosen.length +
          " test P2PARTY in total.";
        console.log(
          JSON.stringify(
            {
              chromium,
              route: path,
              ...(!screen ? { declinedAttempts: failures } : {}),
              ...(abandoned
                ? {
                    reroute: {
                      abandonedRoute: abandoned.path,
                      acceptedRoute: path,
                      replacedVolunteerBalance: 0,
                      sameSession: true,
                      sameFundingInputs: true,
                    },
                  }
                : {}),
              loopbackLinks: path.length - 1,
              verifiedPlaintextBytes: payload.length,
              forwardedBytesPerRelay: paidRecordBytes,
              paidP2PARTY: chosen.length,
              credits,
              ledgerHeight: chosen.length,
              ...(screen ? {} : { ledgerHeightAfterRetries: chosen.length }),
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
      screen ? 345_000 : 45_000,
    );
  } finally {
    clearTimeout(timer);
    journal?.close();
    proc.stdin.end();
    const code = await exit;
    await rm(directory, { recursive: true, force: true });
    if (code !== 0) throw Error("Fixture ledger stopped with " + code);
  }

  return completion;
}
const screen = screenMode ? await openPayerScreen(screenMode) : null;
try {
  const selection = screen ? await screen.choose() : cliSelection();
  const message = await purchase(selection, screen);
  if (screen) await screen.finish(message);
} catch (error) {
  if (screen) await screen.fail();
  throw error;
} finally {
  if (screen) await screen.close();
}
