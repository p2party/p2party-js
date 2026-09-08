import { describe, expect, test } from "bun:test";
import { evaluateOldServerResidual } from "../../docs/e2e/desync/desync-compatibility.mjs";

// Synthetic artifact in the browser driver's actual shape. Negative cases
// preserve the final counter wherever possible, so it cannot be the proof.
const T0 = 1_788_880_000_000;
const A = {
  peerId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  publicKey: "bb".repeat(32),
};
const B = {
  peerId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  publicKey: "55".repeat(32),
};
const ROOM = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const prefix = `p2party: transport with ${B.peerId} in room ${ROOM} never negotiated`;
const entry = () => ({
  stripGeneration: true,
  expectedResidual: true,
  exitCode: 1,
  pass: false,
});
const cleanDiag = () => ({
  t: T0 + 301_104,
  pendingMutations: [],
  roomPeerMutexes: {},
  roomPeerMutexCount: 0,
  dbProbe: "resolved:false",
  dbProbeMs: 1,
  unnegotiatedTransportRebuilds: { [B.peerId]: 3 },
  maxUnnegotiatedTransportRebuilds: 3,
});
const fixture = () => {
  const pcs = [1_000, 16_020, 31_040, 46_060].map((time, i) => ({
    id: i + 1,
    createdAt: time,
    createdAtAbs: T0 + time,
    withPeerId: B.peerId,
    withPeerPublicKey: B.publicKey,
    connectionState: i < 3 ? "closed" : "new",
    signalingState: i < 3 ? "closed" : "stable",
    localFingerprint: null,
    remoteFingerprint: null,
    hasMainChannel: false,
  }));
  const invariant = {
    I1: true,
    I2: false,
    I3: true,
    I5: true,
    I6: true,
    I7: true,
    bothAuthenticated: false,
    fpAgree: null,
  };
  return {
    scenario: "two-tabs",
    role: "responder",
    peerIdMode: "stable",
    connectMode: "immediate",
    observeS: 300,
    startedAt: new Date(T0).toISOString(),
    fault: { clearedAt: "+0.9" },
    baseline: { passed: true },
    failed: true,
    A: { ...A, replacementPage: "P1-tab2" },
    B: { ...B },
    twoTabs: {
      connectAt: "+0.9",
      sharedBrowserContext: true,
      originalIdentity: { ...A },
      replacementIdentity: { ...A },
      replacementPage: "P1-tab2",
    },
    consoles: { names: { A: "P1-tab2", B: "P2" } },
    preFault: {
      Btoken: "original-b",
      Bfp: { local: "BB:BB" },
      Afp: { local: "AA:AA" },
    },
    pageConsoles: {
      A: {
        t0: T0,
        lines: [
          ...[16_000, 31_020, 46_040].map((t) => ({
            t: T0 + t,
            kind: "warn",
            text: `${prefix}; rebuilding`,
          })),
          {
            t: T0 + 61_060,
            kind: "warn",
            text: `${prefix} and its rebuild budget is spent`,
          },
        ],
      },
    },
    pcEvents: {
      A: pcs.map((pc) => ({
        t: pc.createdAtAbs - T0,
        pc: pc.id,
        ev: "created",
      })),
    },
    timelines: { A: [{ t: 900, event: "connect()" }] },
    finalDumps: {
      A: {
        t: T0 + 301_100,
        keyPair: { ...A },
        room: { id: ROOM },
        signalingServer: { isConnected: true, isVerified: true },
        pcs,
      },
      B: {
        t: T0 + 301_101,
        keyPair: { ...B },
        room: { id: ROOM },
        signalingServer: { isConnected: true, isVerified: true },
        pcs: [
          {
            token: "original-b",
            withPeerId: A.peerId,
            connectionState: "connected",
            localFingerprint: "BB:BB",
            remoteFingerprint: "AA:AA",
          },
        ],
      },
    },
    samples: [
      { sinceClear: 1, inv: { ...invariant } },
      { sinceClear: 299.2, inv: { ...invariant } },
    ],
    invariants: {
      firstAuthenticatedSinceClear: null,
      firstSatisfiedSinceClear: { I4: null },
      heldAtEnd: { I4: false },
      finalSample: invariant,
    },
    diag: { A: cleanDiag(), B: cleanDiag() },
    problems: [
      "I2 NEVER held in the 300s observation window",
      "I4 never attempted: I2 (both authenticated) never held during observation",
    ],
  };
};
const check = (result, metadata = entry(), unchanged = true) =>
  evaluateOldServerResidual(result, metadata, unchanged);
const rejected = (result, fragment) => {
  const verdict = check(result);
  expect(verdict.status).toBe("residual-not-established");
  expect(verdict.driverPass).toBe(false);
  expect(verdict.problems).toContainEqual(expect.stringContaining(fragment));
};

describe("pre-generation-server residual evidence", () => {
  test("establishes bounded non-convergence without turning it into a driver pass", () => {
    expect(check(fixture())).toMatchObject({
      status: "residual-established",
      driverPass: false,
      problems: [],
      evidence: {
        rebuilds: 3,
        finalRebuildCount: 3,
        exhaustionEvents: 1,
        observedAfterConnectLowerBoundMs: 300_154,
      },
    });
  });
  test("a fourth attempt cannot hide behind a final counter of three", () => {
    const r = fixture();
    r.pageConsoles.A.lines.splice(3, 0, {
      t: T0 + 55_000,
      kind: "warn",
      text: `${prefix}; rebuilding`,
    });
    rejected(r, "exactly 3");
  });
  test("a final count alone does not prove exhaustion", () => {
    const r = fixture();
    r.pageConsoles.A.lines.pop();
    rejected(r, "budget-exhaustion event");
  });
  test("the final count must be exhausted, not an earlier or unrelated reading", () => {
    const r = fixture();
    r.diag.A.unnegotiatedTransportRebuilds[B.peerId] = 2;
    rejected(r, "Final target rebuild count");
  });
  test("an earlier diagnostic snapshot is not the final rebuild count", () => {
    const r = fixture();
    r.diag.A.t = T0 + 61_061;
    rejected(r, "final diagnostics after the final PC dump");
  });
  test("a changed cap cannot redefine three as the promised limit", () => {
    const r = fixture();
    r.diag.A.maxUnnegotiatedTransportRebuilds = 4;
    rejected(r, "configured cap");
  });
  test("a twenty-second quiet period is insufficient even in a full run", () => {
    const r = fixture();
    r.pageConsoles.A.lines.at(-1).t = r.finalDumps.A.t - 20_000;
    rejected(r, "At least 30 seconds");
  });
  test("declaring 300 seconds cannot disguise a short actual observation", () => {
    const r = fixture();
    r.finalDumps.A.t = T0 + 100_000;
    r.diag.A.t = T0 + 100_004;
    r.samples.at(-1).sinceClear = 99;
    rejected(r, "full 300 seconds");
  });
  test("rounded connect times cannot overstate the proven observation", () => {
    const r = fixture();
    r.finalDumps.A.t = T0 + 300_920;
    r.diag.A.t = T0 + 300_930;
    rejected(r, "full 300 seconds");
    r.diag.A.t = T0 + 300_950;
    expect(check(r).status).toBe("residual-established");
  });
  test("independent page clock origins do not change elapsed wall-clock evidence", () => {
    const r = fixture();
    r.pageConsoles.A.t0 -= 60_000;
    r.timelines.A[0].t = 5;
    for (const pc of r.finalDumps.A.pcs) pc.createdAt += 10_000;
    for (const event of r.pcEvents.A) event.t += 10_000;
    expect(check(r).status).toBe("residual-established");
  });
  test("creation after exhaustion is rejected even with no rebuild warning", () => {
    const r = fixture();
    r.finalDumps.A.pcs.at(-1).createdAtAbs = T0 + 200_000;
    r.pcEvents.A.at(-1).t = 200_000;
    rejected(r, "No PC may be created after");
  });
  test("post-exhaustion rebuilding with another warning cannot escape accounting", () => {
    const r = fixture();
    r.pageConsoles.A.lines.push({
      t: T0 + 80_000,
      kind: "warn",
      text: "first offer was never answered; rebuilding the transport",
    });
    rejected(r, "rebuilt a transport after");
  });
  test("events for another peer cannot substantiate the target's counter", () => {
    const r = fixture();
    r.pageConsoles.A.lines[0].text = r.pageConsoles.A.lines[0].text.replace(
      B.peerId,
      A.peerId,
    );
    rejected(r, "exactly 3");
  });
  test("missing PC creation evidence fails even if final registry has four PCs", () => {
    const r = fixture();
    r.pcEvents.A.pop();
    rejected(r, "independently account");
  });
  test("a recovered or unknown sample cannot count as persistent non-convergence", () => {
    for (const changed of [{ bothAuthenticated: true }, { unknown: true }]) {
      const r = fixture();
      Object.assign(r.samples[0].inv, changed);
      rejected(r, "without authentication or unknown state");
    }
  });
  test("a replacement B transport is a different failure mechanism", () => {
    const r = fixture();
    r.finalDumps.B.pcs[0].token = "replacement";
    rejected(r, "original connected transport");
  });
  test("a crashed driver or failed diagnostics cannot establish the residual", () => {
    const r = fixture();
    r.problems.push("DRIVER FAILURE: page crashed");
    rejected(r, "failures must be limited");
    const pending = fixture();
    pending.diag.A.pendingMutations.push({ endpoint: "setDescription" });
    rejected(pending, "pending RTK mutations");
  });
  test("requires matrix evidence that generations were stripped and inputs unchanged", () => {
    expect(
      check(fixture(), { ...entry(), stripGeneration: false }).status,
    ).toBe("residual-not-established");
    expect(check(fixture(), entry(), false).status).toBe(
      "residual-not-established",
    );
    expect(check(fixture(), { ...entry(), timedOut: true }).status).toBe(
      "residual-not-established",
    );
  });
});
