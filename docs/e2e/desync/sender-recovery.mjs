import assert from "node:assert/strict";
import {
  completeMesh,
  eventually,
  fixture,
  parseFlags,
  sleep,
} from "./recovery-harness.mjs";

// --legacy=receiver serves only B's SDK/worker/WASM from the archived 0.14.8
// assets. --before=1 still serves the archived version to both peers.
const flags = parseFlags([
  "port",
  "run",
  "before",
  "legacy",
  "mode",
  "fault",
  "observe",
]);
const mode = flags.mode ?? "immediate";
const fault = flags.fault ?? "reload";
assert(["immediate", "scheduled"].includes(mode));
assert(["reload", "long-loss", "cancel"].includes(fault));
const observeMs = Number(flags.observe ?? 120000);
assert(Number.isFinite(observeMs) && observeMs >= 10000 && observeMs <= 300000);
const f = await fixture("sender-recovery", flags);
try {
  const sender = await f.createPeer("A");
  const receiver = await f.createPeer("B");
  if (flags.legacy === "receiver") {
    assert.equal(f.report.peerAssets.A.archived, false);
    assert.equal(f.report.peerAssets.B.archived, true);
    assert.equal(new URL(receiver.page.url()).pathname, "/legacy/");
    assert.equal(
      f.report.peerAssets.B.inputs["app-bundle.js"],
      f.report.inputs["legacy/app-bundle.js"],
    );
    f.event("mixed-sdk-versions", {
      sender: "current",
      receiver: "archived-0.14.8",
    });
  }
  const options = { mode, coverCadenceMs: 2000 };
  await Promise.all([sender.connect(options), receiver.connect(options)]);
  await eventually("authenticated transfer edge", f.sample, completeMesh);
  await Promise.all([
    sender.call("joinChannel", f.room, "main"),
    receiver.call("joinChannel", f.room, "main"),
  ]);
  if (mode === "scheduled")
    await eventually("active cover edges", f.sample, (dumps) =>
      dumps.every(
        (d) =>
          Object.values(d.room.coverStatusByPeer).every(
            (status) => status === "active",
          ) && Object.values(d.room.coverStatusByPeer).length === 1,
      ),
    );
  const mib = mode === "scheduled" ? 0.5 : 8;
  const payload = await sender.call("prepareTransfer", "durable", mib);
  f.report.payload = payload;
  // Drop application chunk frames after the first few. Real handshakes,
  // authenticated receipts, PQ control and cover dummy cells still run.
  await sender.page.evaluate(() => {
    const original = RTCDataChannel.prototype.send;
    window.__chunkFault = { seen: 0, dropped: 0, enabled: true };
    RTCDataChannel.prototype.send = function (data) {
      const bytes =
        data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : ArrayBuffer.isView(data)
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : null;
      if (bytes?.length === 65490 && bytes[0] === 2) {
        window.__chunkFault.seen++;
        if (window.__chunkFault.enabled && window.__chunkFault.seen > 4) {
          window.__chunkFault.dropped++;
          return;
        }
      }
      return original.call(this, data);
    };
  });
  const started = await sender.call("startTransfer", f.room, "main", "durable");
  assert.equal(started.started, true);
  f.report.startedTransfer = started;
  const partial = await eventually(
    "receiver has a durable incomplete transfer",
    () => receiver.call("incomingBig", f.room, payload.bytes),
    (value) => value?.savedSize > 0 && value.savedSize < value.totalSize,
    45000,
  );
  f.report.partial = partial;
  await eventually(
    "chunk fault drops real application traffic",
    () => sender.page.evaluate(() => window.__chunkFault),
    (value) => value.dropped > 0,
    20000,
  );
  f.event("partial-retained", {
    root: partial.value.merkleRootHex,
    bytes: partial.value.savedSize,
    total: payload.bytes,
  });
  const supportsOutbox = await sender.page.evaluate(
    () => typeof window.__app.listPendingMessages === "function",
  );
  if (supportsOutbox) {
    f.report.pendingBefore = await sender.call("listPendingMessages", f.room);
    assert(
      f.report.pendingBefore.some(
        (row) =>
          row.transferId === started.transferId &&
          row.merkleRootHex === partial.value.merkleRootHex,
      ),
    );
  }
  const recoveryStarted = Date.now();
  if (fault === "reload") {
    f.report.chunkFault = await sender.page.evaluate(() => window.__chunkFault);
    await sender.reload(options);
    f.event("sender-reloaded");
  } else if (fault === "cancel") {
    assert(supportsOutbox, "Cancel case needs the public durable API");
    await sender.call("cancelPendingMessage", f.room, started.transferId);
    await eventually(
      "explicit cancellation purges receiver partial",
      () => receiver.call("incomingBig", f.room, payload.bytes),
      (value) => value === null,
      15000,
    );
    assert(
      !(await sender.call("listPendingMessages", f.room)).some(
        (row) => row.transferId === started.transferId,
      ),
    );
    f.report.cancelled = true;
    await f.archive();
    f.report.passed = true;
    await f.close();
    process.exit(f.report.passed ? 0 : 1);
  } else {
    const dumps = await f.sample();
    const faultMs = 100000;
    await f.ctl(
      `blackhole-pair?a=${dumps[0].keyPair.peerId}&b=${dumps[1].keyPair.peerId}&ms=${faultMs}`,
    );
    await Promise.all([
      sender.page.evaluate(
        (id) => window.__failEdge(id),
        dumps[1].keyPair.peerId,
      ),
      receiver.page.evaluate(
        (id) => window.__failEdge(id),
        dumps[0].keyPair.peerId,
      ),
    ]);
    await sender.page.evaluate(() => {
      window.__chunkFault.enabled = false;
    });
    f.report.interruptionSamples = [];
    const until = Date.now() + faultMs;
    while (Date.now() < until) {
      f.report.interruptionSamples.push({
        at: Date.now(),
        transfer: await sender.call("transferState", "durable"),
        pending: supportsOutbox
          ? await sender.call("listPendingMessages", f.room)
          : null,
      });
      await sleep(1000);
    }
    const failedAttempt = f.report.interruptionSamples.find(
      (row) => row.transfer.outcome === "rejected",
    );
    assert(
      failedAttempt,
      "The interruption must exceed the original send attempt's retry budget",
    );
    if (supportsOutbox)
      assert(
        failedAttempt.pending.some(
          (row) => row.transferId === started.transferId,
        ),
        "A failed attempt retains the logical pending transfer",
      );
    f.event("long-interruption-ended", { ms: faultMs });
  }
  // Reopening the sender must recover by itself. No sendMessage or manual
  // retry occurs after the fault; the original payload exists only in its DB.
  await eventually(
    "fresh authenticated edge after interruption",
    f.sample,
    completeMesh,
    observeMs,
  );
  const delivered = await eventually(
    "original payload automatically completes",
    () => receiver.call("incomingBig", f.room, payload.bytes),
    (value) => value?.complete === true,
    observeMs,
  );
  assert.equal(
    delivered.value.merkleRootHex,
    partial.value.merkleRootHex,
    "Recovery must reuse the original Merkle commitment",
  );
  const received = await receiver.call(
    "verifyReceived",
    delivered.value.merkleRootHex,
  );
  assert.equal(received.sha256, payload.sha256);
  assert.equal(received.size, payload.bytes);
  f.report.received = received;
  f.report.recoveryMs = Date.now() - recoveryStarted;
  if (supportsOutbox) {
    const empty = await eventually(
      "terminal receipt removes durable sender outbox",
      () => sender.call("listPendingMessages", f.room),
      (rows) => !rows.some((row) => row.transferId === started.transferId),
      20000,
    );
    f.report.pendingAfter = empty.value;
  }
  await f.archive();
  f.report.passed = true;
  f.event("original-transfer-delivered", {
    recoveryMs: f.report.recoveryMs,
    sha256: received.sha256,
  });
  await f.close();
} catch (error) {
  await f.archive().catch((error) => {
    f.report.archiveError = String(error);
  });
  await f.close(error);
}
