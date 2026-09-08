// Real scheduled F16 recovery evidence. Root controls bundle builds and runs.
// node scheduled-recovery.mjs --case=selective --port=5980 --run=final
// node scheduled-recovery.mjs --case=pq --port=5982 --run=final
import assert from "node:assert/strict";
import {
  completeMesh,
  eventually,
  fixture,
  parseFlags,
} from "./recovery-harness.mjs";

const flags = parseFlags(["case", "port", "run", "observe"]);
const scenario = flags.case ?? "selective";
assert(["pq", "selective"].includes(scenario));
const observeMs = Number(flags.observe ?? 120000);
assert(
  Number.isSafeInteger(observeMs) && observeMs >= 30000 && observeMs <= 180000,
);
const f = await fixture(`scheduled-${scenario}`, flags);
const roomOptions = { mode: "scheduled", coverCadenceMs: 4000 };
const state = async (peer, transferId) => {
  const rows = await peer.call("scheduledState", f.room, transferId);
  assert.equal(rows.length, 1, `${peer.name} has one live scheduled edge`);
  return rows[0];
};
const trace = async (peer) => {
  const value = await peer.call("scheduledTrace");
  assert.deepEqual(
    value.problems,
    [],
    `${peer.name} trace correlation is complete`,
  );
  assert(
    value.pendingFrameCopies <= 128,
    "Encrypted trace copies stay bounded",
  );
  return value;
};
async function start(sender, id) {
  const payload = await sender.call("prepareTransfer", id, 0.5);
  const started = await sender.call("startTransfer", f.room, "main", id);
  assert.equal(started.started, true);
  return { id, payload, started };
}
async function verify(sender, receiver, transfer) {
  const delivered = await eventually(
    `${transfer.id} original payload completes`,
    () => receiver.call("incomingBig", f.room, transfer.payload.bytes),
    (value) =>
      value?.complete === true && value.filename === transfer.payload.filename,
    observeMs,
  );
  const received = await receiver.call(
    "verifyReceived",
    delivered.value.merkleRootHex,
  );
  assert.equal(received.sha256, transfer.payload.sha256);
  assert.equal(received.size, transfer.payload.bytes);
  const finished = await eventually(
    `${transfer.id} sender confirms delivery`,
    () => sender.call("transferState", transfer.id),
    (value) =>
      value.outcome === "resolved" &&
      value.outcomes.some((outcome) => outcome.status === "delivered"),
    20000,
  );
  assert.equal(finished.value.merkleRootHex, delivered.value.merkleRootHex);
  await eventually(
    `${transfer.id} durable outbox finishes`,
    () => sender.call("listPendingMessages", f.room),
    (rows) =>
      !rows.some((row) => row.transferId === transfer.started.transferId),
    20000,
  );
  return {
    root: delivered.value.merkleRootHex,
    received,
    finished: finished.value,
  };
}
try {
  const a = await f.createPeer("A"),
    b = await f.createPeer("B");
  for (const peer of [a, b])
    assert(
      await peer.page.evaluate(
        () => typeof window.__app.scheduledTrace === "function",
      ),
      "Scheduled app instrumentation must be installed",
    );
  await Promise.all([a.connect(roomOptions), b.connect(roomOptions)]);
  await eventually("authenticated scheduled edge", f.sample, completeMesh);
  await Promise.all([
    a.call("joinChannel", f.room, "main"),
    b.call("joinChannel", f.room, "main"),
  ]);
  await eventually(
    "active F16 schedulers",
    () => Promise.all([state(a), state(b)]),
    (rows) =>
      rows.every(
        (row) => row.status === "active" && Number.isInteger(row.epoch),
      ),
  );
  f.report.initial = await f.sample();
  f.report.policy = roomOptions;
  if (scenario === "selective") {
    // Let four real frames through, then suppress later application frames.
    // Control/receipt/dummy slots and the fixed schedule continue normally.
    await a.page.evaluate(() => {
      const original = RTCDataChannel.prototype.send;
      window.__scheduledDrop = { seen: 0, dropped: 0, enabled: true };
      RTCDataChannel.prototype.send = function (data) {
        const bytes =
          data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : ArrayBuffer.isView(data)
              ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
              : null;
        if (bytes?.length === 65490 && bytes[0] === 2) {
          window.__scheduledDrop.seen++;
          if (
            window.__scheduledDrop.enabled &&
            window.__scheduledDrop.seen > 4
          ) {
            window.__scheduledDrop.dropped++;
            return;
          }
        }
        return original.call(this, data);
      };
    });
    const transfer = await start(a, "selective");
    f.report.transfer = transfer;
    const receipt = await eventually(
      "authenticated nonzero chunk ACKs before interruption",
      () => state(a, transfer.started.transferId),
      (row) => row.acked.filter((index) => index > 0).length >= 2,
      45000,
      100,
    );
    const beforeTrace = await trace(a);
    const enqueued = beforeTrace.events.find(
      (event) => event.event === "enqueued" && event.jobId.includes("~"),
    );
    assert(enqueued && enqueued.declaredCellCount <= 16);
    const total = enqueued.declaredCellCount;
    const acked = receipt.value.acked;
    assert(
      acked.length > 0 && acked.length < total,
      "Fault must leave both ACKed and missing real chunks",
    );
    const partial = await b.call("incomingBig", f.room, transfer.payload.bytes);
    assert(partial?.savedSize > 0 && partial.savedSize < partial.totalSize);
    const fault = await a.page.evaluate(() => window.__scheduledDrop);
    assert(
      fault.dropped > 0,
      "Selective fault actually suppressed real traffic",
    );
    f.report.preFault = {
      receipt,
      partial,
      total,
      acked,
      fault,
      trace: beforeTrace,
    };
    const mark = await a.call("scheduledMark", "before-edge-interruption");
    const dumps = await f.sample();
    await f.ctl(
      `blackhole-pair?a=${dumps[0].keyPair.peerId}&b=${dumps[1].keyPair.peerId}&ms=3000`,
    );
    const closed = await Promise.all([
      a.page.evaluate((id) => window.__failEdge(id), dumps[1].keyPair.peerId),
      b.page.evaluate((id) => window.__failEdge(id), dumps[0].keyPair.peerId),
    ]);
    assert.deepEqual(
      closed,
      [1, 1],
      "Both concrete old transports were interrupted",
    );
    await a.page.evaluate(() => {
      window.__scheduledDrop.enabled = false;
    });
    f.event("edge-interrupted", { mark, acked, total });
    await eventually(
      "fresh authenticated scheduled edge",
      f.sample,
      completeMesh,
      30000,
    );
    f.report.delivery = await verify(a, b, transfer);
    assert.equal(f.report.delivery.root, partial.merkleRootHex);
    const after = await trace(a);
    const resumed = after.events.filter(
      (event) =>
        event.seq > mark &&
        event.event === "sent" &&
        event.transferId === transfer.started.transferId,
    );
    assert(resumed.length > 0, "Recovery emitted real work");
    assert(
      resumed.every((event) => event.pcId !== receipt.value.pcId),
      "Resumed cells use a replacement transport",
    );
    const missing = Array.from({ length: total }, (_, index) => index).filter(
      (index) => !acked.includes(index),
    );
    assert(
      missing.some((index) => index > 0),
      "A missing nonzero chunk must be delivered",
    );
    assert(
      resumed.every(
        (event) => missing.includes(event.chunkIndex) || event.chunkIndex === 0,
      ),
      "Resumed work excludes every ACKed chunk except the index-zero completion probe",
    );
    assert(
      resumed.length <= missing.length + 1,
      "Actual resumed work is missing chunks plus at most one completion probe",
    );
    for (const index of missing)
      assert(
        resumed.some((event) => event.chunkIndex === index),
        `Missing chunk ${index} was emitted`,
      );
    f.report.selectivity = {
      acked,
      missing,
      emittedIndices: resumed.map((event) => event.chunkIndex),
      completionProbeAllowance: 1,
      resumedRealCells: resumed.length,
      maximumRealCells: missing.length + 1,
    };
  } else {
    const initial = await Promise.all([state(a), state(b)]);
    assert.equal(
      initial.filter((row) => row.nextOfferer === "local").length,
      1,
    );
    const sender = initial[0].nextOfferer === "local" ? a : b;
    const receiver = sender === a ? b : a;
    f.report.localOfferer = sender.name;
    const local = await start(sender, "pq-local-pending");
    const pending = await eventually(
      "local offerer has a pending real job",
      () => state(sender, local.started.transferId),
      (row) => row.pendingReal,
      30000,
      50,
    );
    const forced = await sender.call("forcePqDue", f.room);
    assert(
      forced.before.pendingReal && forced.due,
      "Local healing was forced due while real work was pending",
    );
    assert.equal(
      forced.after.epoch,
      forced.before.epoch,
      "Local due tick defers epoch transition until real work yields",
    );
    const localDelivery = await verify(sender, receiver, local);
    const healed = await eventually(
      "local due exchange advances both durable epochs",
      () => Promise.all([state(sender), state(receiver)]),
      (rows) =>
        rows.every(
          (row) => row.epoch === pending.value.epoch + 1 && !row.blocked,
        ),
      observeMs,
    );
    assert.equal(
      healed.value[0].pcId,
      pending.value.pcId,
      "Healing preserves the authenticated transport",
    );
    f.report.localDue = {
      transfer: local,
      pending,
      forced,
      delivery: localDelivery,
      healed,
    };

    // The just-completed exchange handed the next offer to the receiver.
    // Send again from the former offerer: its incoming OFFER now overlaps its
    // queued/admitted real producer. Both counters become due concurrently;
    // only the legitimate current offerer may initiate the real exchange.
    assert.equal((await state(receiver)).nextOfferer, "local");
    const incoming = await start(sender, "pq-incoming-pending");
    const incomingPending = await eventually(
      "incoming transition target has a pending real job",
      () => state(sender, incoming.started.transferId),
      (row) => row.pendingReal,
      30000,
      50,
    );
    const mark = await sender.call("scheduledMark", "before-incoming-pq");
    const simultaneous = await Promise.all([
      sender.call("forcePqDue", f.room),
      receiver.call("forcePqDue", f.room),
    ]);
    assert.equal(
      simultaneous.filter((result) => result.due).length,
      1,
      "Turn-taking admits only one simultaneous due offer",
    );
    const incomingDelivery = await verify(sender, receiver, incoming);
    const incomingHealed = await eventually(
      "incoming exchange advances both durable epochs",
      () => Promise.all([state(sender), state(receiver)]),
      (rows) =>
        rows.every(
          (row) => row.epoch >= incomingPending.value.epoch + 1 && !row.blocked,
        ),
      observeMs,
    );
    const incomingTrace = await trace(sender);
    const overlap = incomingTrace.events.find(
      (event) =>
        event.seq > mark &&
        event.event === "epoch-change" &&
        event.pendingRealBefore === true &&
        event.epoch === incomingPending.value.epoch + 1,
    );
    assert(
      overlap,
      "The incoming epoch transition actually overlapped pending real work",
    );
    assert.equal(
      overlap.pcId,
      incomingPending.value.pcId,
      "Incoming healing rebinds the same transport",
    );
    const resumed = incomingTrace.events.filter(
      (event) =>
        event.seq > overlap.seq &&
        event.event === "sent" &&
        event.transferId === incoming.started.transferId,
    );
    assert(
      resumed.length > 0 &&
        resumed.every((event) => event.epoch >= overlap.epoch),
      "Retired real producers resume under the new epoch",
    );
    f.report.incomingDue = {
      transfer: incoming,
      pending: incomingPending,
      simultaneous,
      overlap,
      resumed,
      delivery: incomingDelivery,
      healed: incomingHealed,
    };
  }
  f.report.traces = { A: await trace(a), B: await trace(b) };
  await eventually("final authenticated edge", f.sample, completeMesh);
  await f.archive();
  f.report.passed = true;
  await f.close();
} catch (error) {
  f.report.traces = {};
  for (const peer of f.peers)
    f.report.traces[peer.name] = await peer
      .call("scheduledTrace")
      .catch((error) => ({ error: String(error) }));
  await f.archive().catch((error) => {
    f.report.archiveError = String(error);
  });
  await f.close(error);
}
