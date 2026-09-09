import assert from "node:assert/strict";
import {
  authenticatedEdge,
  completeMesh,
  eventually,
  fixture,
  parseFlags,
  sleep,
} from "./recovery-harness.mjs";

const flags = parseFlags(["port", "run", "before", "observe"]);
const observeMs = Number(flags.observe ?? 60000);
assert(Number.isFinite(observeMs) && observeMs >= 10000 && observeMs <= 300000);
const f = await fixture("mesh-recovery", flags);
try {
  const peers = [];
  for (const name of ["A", "B", "C"]) peers.push(await f.createPeer(name));
  await Promise.all(peers.map((p) => p.connect()));
  let stableSince = null;
  const baseline = await eventually(
    "initial stable three-peer authenticated mesh",
    f.sample,
    (dumps) => {
      if (!completeMesh(dumps)) {
        stableSince = null;
        return false;
      }
      stableSince ??= Date.now();
      return Date.now() - stableSince >= 3000;
    },
    30000,
  );
  f.report.baseline = baseline;
  f.event("baseline-authenticated", { elapsedMs: baseline.elapsedMs });
  const [a, b, c] = baseline.value;
  const healthyTokens = [
    a.pcs.find(
      (pc) =>
        pc.withPeerId === b.keyPair.peerId &&
        pc.connectionState === "connected",
    ).token,
    c.pcs.find(
      (pc) =>
        pc.withPeerId === b.keyPair.peerId &&
        pc.connectionState === "connected",
    ).token,
  ];
  const faultMs = 12000;
  await f.ctl(
    `blackhole-pair?a=${a.keyPair.peerId}&b=${c.keyPair.peerId}&ms=${faultMs}`,
  );
  const faultStart = Date.now();
  const failed = await Promise.all([
    peers[0].page.evaluate(
      (peerId) => window.__failEdge(peerId),
      c.keyPair.peerId,
    ),
    peers[2].page.evaluate(
      (peerId) => window.__failEdge(peerId),
      a.keyPair.peerId,
    ),
  ]);
  assert.deepEqual(
    failed,
    [1, 1],
    "Fault must close exactly the two ends of A-C",
  );
  f.event("pair-failure", { blockedMs: faultMs });
  f.report.samples = [];
  let firstRecoveredMs = null;
  const finish = faultStart + faultMs + observeMs;
  while (Date.now() < finish) {
    const dumps = await f.sample();
    const elapsedMs = Date.now() - faultStart;
    const healthy =
      authenticatedEdge(dumps[0], dumps[1]) &&
      authenticatedEdge(dumps[1], dumps[2]);
    assert(
      healthy,
      "A-B and B-C must stay authenticated while A-C is repaired",
    );
    const tokens = [
      dumps[0].pcs.find(
        (pc) =>
          pc.withPeerId === b.keyPair.peerId &&
          pc.connectionState === "connected",
      )?.token,
      dumps[2].pcs.find(
        (pc) =>
          pc.withPeerId === b.keyPair.peerId &&
          pc.connectionState === "connected",
      )?.token,
    ];
    assert.deepEqual(
      tokens,
      healthyTokens,
      "Healthy edges must not be replaced to repair A-C",
    );
    const recovered = completeMesh(dumps);
    if (elapsedMs < faultMs)
      assert(!recovered, "Pair fault must actually prevent A-C negotiation");
    if (recovered && firstRecoveredMs === null)
      firstRecoveredMs = Math.max(0, elapsedMs - faultMs);
    f.report.samples.push({
      elapsedMs,
      healthy,
      recovered,
      rosters: dumps.map((d) => d.room?.peers?.length),
    });
    await sleep(500);
  }
  f.report.firstRecoveredAfterClearMs = firstRecoveredMs;
  assert(
    firstRecoveredMs !== null && firstRecoveredMs <= observeMs,
    "Missing A-C must recover while its other edges remain healthy",
  );
  assert(
    completeMesh(await f.sample()),
    "Final full mesh must remain authenticated",
  );
  // A send to the recovered mesh must be delivered by both recipients.
  await Promise.all(peers.map((p) => p.call("joinChannel", f.room, "main")));
  const text = `mesh-recovery-${f.report.run}`;
  const sent = await peers[0].call("send", f.room, "main", text);
  assert.equal(sent.outcomes.filter((o) => o.status === "delivered").length, 2);
  for (const peer of [peers[1], peers[2]]) {
    const received = await peer.call("latestIncoming", f.room);
    assert(received);
    assert.equal(await peer.call("read", received.merkleRootHex), text);
  }
  f.report.delivery = sent;
  await f.archive();
  assert(
    f.report.relayLog.join("").includes("DROPPED(pair blackhole)"),
    "The blocked pair must have attempted signaling",
  );
  f.report.passed = true;
  f.event("mesh-recovered", { firstRecoveredAfterClearMs: firstRecoveredMs });
  await f.close();
} catch (error) {
  await f.archive().catch((diagnosticError) => {
    f.report.archiveError = String(diagnosticError);
  });
  await f.close(error);
}
