// Read-only evidence check for the documented pre-generation-server residual.
// Usage: node desync-compatibility.mjs RUN.json MATRIX.json
// A successful check establishes a bounded failure, never a driver PASS.
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { diagnosticProblems } from "./desync-verdict.mjs";

const list = (value) => (Array.isArray(value) ? value : []);
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const finite = (value) => typeof value === "number" && Number.isFinite(value);
const CAP = 3;
const OBSERVATION_MS = 300_000;
const QUIET_MS = 30_000;

// Driver relative timestamps are rounded to one decimal second. Use their
// upper bound, never a page-relative clock: app timeline, PC instrumentation
// and page console each establish their own time origin.
const relativeUpperBound = (start, relative) =>
  finite(Date.parse(start)) &&
  typeof relative === "string" &&
  /^\+\d+\.\d$/.test(relative)
    ? Date.parse(start) + Number(relative) * 1000 + 50
    : NaN;

export function evaluateOldServerResidual(input, matrixEntry, inputsUnchanged) {
  const r = object(input),
    entry = object(matrixEntry);
  const problems = [];
  const require = (condition, message) => {
    if (!condition) problems.push(message);
  };
  require(entry.stripGeneration === true &&
    entry.expectedResidual === true &&
    inputsUnchanged ===
      true, "Completed matrix must attest stripped generations, expected residual, and unchanged harness inputs");
  require(entry.exitCode === 1 &&
    entry.pass === false &&
    !entry.timedOut &&
    !entry.signal, "Driver must finish normally with its non-pass exit, not time out or terminate");
  require(r.scenario === "two-tabs" &&
    r.role === "responder" &&
    r.peerIdMode === "stable" &&
    r.connectMode ===
      "immediate", "Evidence must be the stable-identity two-tabs responder compatibility arm");
  require(r.observeS >= OBSERVATION_MS / 1000 &&
    finite(r.observeS), "Declared observation must cover 300 seconds");
  require(r.baseline?.passed === true &&
    r.failed ===
      true, "Baseline must work and the replacement run must remain a driver failure");

  const a = object(r.finalDumps?.A),
    b = object(r.finalDumps?.B);
  const room = object(a.room),
    peerId = r.B?.peerId,
    publicKey = r.B?.publicKey;
  require(typeof room.id === "string" &&
    room.id.length > 0 &&
    b.room?.id === room.id, "Both final dumps must identify the same room");
  require(typeof peerId === "string" &&
    peerId.length > 0 &&
    typeof publicKey === "string" &&
    publicKey.length > 0 &&
    b.keyPair?.peerId === peerId &&
    b.keyPair?.publicKey ===
      publicKey, "Final B identity must match the watchdog's target");
  require(typeof r.A?.peerId === "string" &&
    r.A.peerId.length > 0 &&
    typeof r.A?.publicKey === "string" &&
    r.A.publicKey.length > 0 &&
    r.twoTabs?.sharedBrowserContext === true &&
    r.twoTabs?.originalIdentity?.publicKey === r.A?.publicKey &&
    r.twoTabs?.replacementIdentity?.publicKey === r.A?.publicKey &&
    r.twoTabs?.originalIdentity?.peerId === r.A?.peerId &&
    r.twoTabs?.replacementIdentity?.peerId === r.A?.peerId &&
    a.keyPair?.peerId === r.A?.peerId &&
    a.keyPair?.publicKey === r.A?.publicKey &&
    typeof r.twoTabs?.replacementPage === "string" &&
    r.twoTabs.replacementPage === r.consoles?.names?.A &&
    r.twoTabs.replacementPage ===
      r.A
        ?.replacementPage, "A evidence must come from the same-identity replacement page");
  for (const [side, dump] of [
    ["A", a],
    ["B", b],
  ])
    require(dump.signalingServer?.isConnected === true &&
      dump.signalingServer?.isVerified ===
        true, `${side} signaling must remain connected and verified`);

  const logs = r.pageConsoles?.A;
  const lines = list(logs?.lines);
  require(Array.isArray(logs?.lines) &&
    finite(
      logs?.t0,
    ), "Replacement page console and its clock origin are required");
  const prefix = `p2party: transport with ${peerId} in room ${room.id} never negotiated`;
  const rebuilds = lines.filter(
    (line) => line.text === `${prefix}; rebuilding`,
  );
  const exhausted = lines.filter(
    (line) => line.text === `${prefix} and its rebuild budget is spent`,
  );
  require(rebuilds.length ===
    CAP, `Expected exactly ${CAP} matching replacement-page rebuild events; found ${rebuilds.length}`);
  require(exhausted.length ===
    1, `Expected one matching budget-exhaustion event; found ${exhausted.length}`);
  const spentAt = exhausted[0]?.t;
  require(finite(spentAt) &&
    [...rebuilds, ...exhausted].every(
      (line) => finite(line.t) && line.kind === "warn",
    ), "Watchdog evidence must have valid in-page warning timestamps");
  require(rebuilds.every(
    (line) => finite(line.t) && line.t < spentAt,
  ), "Every rebuild must precede budget exhaustion");
  require(!lines.some(
    (line) =>
      finite(line.t) &&
      line.t > spentAt &&
      typeof line.text === "string" &&
      /\brebuilding\b/.test(line.text),
  ), "A rebuilt a transport after budget exhaustion");

  const diag = object(r.diag?.A);
  require(diag.maxUnnegotiatedTransportRebuilds === CAP &&
    diag.unnegotiatedTransportRebuilds?.[peerId] ===
      CAP, "Final target rebuild count and configured cap must both equal three");
  require(finite(diag.t) &&
    finite(a.t) &&
    diag.t >=
      a.t, "Rebuild count must come from final diagnostics after the final PC dump");
  problems.push(...diagnosticProblems(r.diag));

  const pcs = list(a.pcs),
    creations = list(r.pcEvents?.A).filter((event) => event.ev === "created");
  require(Array.isArray(a.pcs) &&
    pcs.length === CAP + 1 &&
    pcs.every(
      (pc) => pc.withPeerId === peerId && pc.withPeerPublicKey === publicKey,
    ), "A must retain exactly the initial transport plus three replacements for B");
  require(creations.length === CAP + 1 &&
    new Set(creations.map((event) => event.pc)).size === CAP + 1 &&
    creations.every((event) =>
      pcs.some((pc) => pc.id === event.pc),
    ), "PC creation events must independently account for all four A transports");
  require(pcs.every(
    (pc) => finite(pc.createdAtAbs) && pc.createdAtAbs <= spentAt,
  ) &&
    creations.every((event) => {
      const pc = pcs.find((candidate) => candidate.id === event.pc);
      return (
        finite(event.t) &&
        finite(pc?.createdAt) &&
        event.t >= pc.createdAt &&
        pc.createdAtAbs + event.t - pc.createdAt <= spentAt
      );
    }), "No PC may be created after budget exhaustion");
  const liveA = pcs.filter((pc) => pc.connectionState !== "closed");
  require(liveA.length === 1 &&
    liveA[0].connectionState === "new" &&
    liveA[0].signalingState === "stable" &&
    liveA[0].localFingerprint === null &&
    liveA[0].remoteFingerprint === null &&
    liveA[0].hasMainChannel ===
      false, "Final A transport must remain unnegotiated without SDP or a main channel");
  const liveB = list(b.pcs).filter((pc) => pc.connectionState !== "closed");
  require(liveB.length === 1 &&
    liveB[0].connectionState === "connected" &&
    typeof r.preFault?.Btoken === "string" &&
    liveB[0].token === r.preFault.Btoken &&
    liveB[0].withPeerId === r.A?.peerId &&
    liveB[0].localFingerprint === r.preFault?.Bfp?.local &&
    typeof r.preFault?.Afp?.local === "string" &&
    liveB[0].remoteFingerprint ===
      r.preFault.Afp
        .local, "B must retain its original connected transport and predecessor fingerprint");

  const connections = list(r.timelines?.A).filter(
    (event) => event.event === "connect()",
  );
  const connectAtUpperBound = relativeUpperBound(
    r.startedAt,
    r.twoTabs?.connectAt,
  );
  require(connections.length === 1 &&
    finite(connections[0]?.t) &&
    r.fault?.clearedAt === r.twoTabs?.connectAt &&
    finite(connectAtUpperBound) &&
    finite(diag.t) &&
    diag.t - connectAtUpperBound >=
      OBSERVATION_MS, "Final diagnostics must prove a full 300 seconds after replacement-page connect");
  require(finite(a.t) &&
    finite(spentAt) &&
    a.t - spentAt >=
      QUIET_MS, "At least 30 seconds must be observed after budget exhaustion");
  const samples = list(r.samples);
  require(samples.length >= 2 &&
    finite(samples.at(-1)?.sinceClear) &&
    samples.at(-1).sinceClear >= 299 &&
    samples.every(
      (sample) =>
        !sample.inv?.unknown && sample.inv?.bothAuthenticated === false,
    ), "Live samples must reach the last second of the 300-second window without authentication or unknown state");
  const inv = object(r.invariants),
    final = object(inv.finalSample);
  // The driver serializes unsatisfied historical milestones as "never".
  // null is its internal accumulator, not a completed evidence artifact.
  require(inv.firstAuthenticatedSinceClear === "never" &&
    inv.firstSatisfiedSinceClear?.I4 === "never" &&
    inv.heldAtEnd?.I4 === false &&
    final.bothAuthenticated === false &&
    final.fpAgree ===
      null, "Neither authentication nor successful delivery may establish recovery");
  require(["I1", "I3", "I5", "I6"].every(
    (name) => final[name] === true,
  ), "Final roster, transport accounting, stale-state and registry invariants must remain sound");
  const expectedProblem =
    /^(?:I[24] (?:NEVER held|first held)|I4 never attempted:|both peers are not authenticated in the final sample|DTLS fingerprint agreement is not established in the final sample|replacement tab did not (?:authenticate|exchange messages) within 20s of connect)/;
  require(Array.isArray(r.problems) &&
    r.problems.length > 0 &&
    r.problems.every(
      (problem) => typeof problem === "string" && expectedProblem.test(problem),
    ), "Driver failures must be limited to the expected authentication/delivery residual");

  return {
    status:
      problems.length === 0
        ? "residual-established"
        : "residual-not-established",
    driverPass: false,
    evidence: {
      rebuilds: rebuilds.length,
      configuredCap: diag.maxUnnegotiatedTransportRebuilds ?? null,
      finalRebuildCount: diag.unnegotiatedTransportRebuilds?.[peerId] ?? null,
      exhaustionEvents: exhausted.length,
      observedAfterConnectLowerBoundMs:
        finite(diag.t) && finite(connectAtUpperBound)
          ? diag.t - connectAtUpperBound
          : null,
      observedAfterExhaustionMs:
        finite(a.t) && finite(spentAt) ? a.t - spentAt : null,
    },
    problems,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  try {
    const [artifactPath, matrixPath, ...extra] = process.argv.slice(2);
    if (!artifactPath || !matrixPath || extra.length)
      throw new Error(
        "Usage: node desync-compatibility.mjs RUN.json MATRIX.json",
      );
    const result = JSON.parse(readFileSync(artifactPath, "utf8"));
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    const matching = list(matrix.arms).filter(
      (entry) => entry.artifact === path.basename(artifactPath),
    );
    if (matching.length !== 1)
      throw new Error("Matrix must identify this artifact exactly once");
    const verdict = evaluateOldServerResidual(
      result,
      matching[0],
      matrix.inputsUnchanged,
    );
    console.log(JSON.stringify(verdict, null, 2));
    process.exitCode = verdict.status === "residual-established" ? 0 : 1;
  } catch (error) {
    console.error(
      JSON.stringify({
        status: "residual-not-established",
        driverPass: false,
        problems: [String(error.message)],
      }),
    );
    process.exitCode = 1;
  }
}
