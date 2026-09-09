// The browser driver and regression tests share the same fail-closed verdict.
// I4 is a historical delivery event; every other invariant is current state.
export const STATE_INVARIANTS = ["I1", "I2", "I3", "I5", "I6", "I7"];

export function transportFingerprintAgreement(liveA, liveB) {
  if (liveA.length !== 1 || liveB.length !== 1) return null;
  const a = liveA[0], b = liveB[0];
  const fingerprints = [a.localFingerprint, a.remoteFingerprint, b.localFingerprint, b.remoteFingerprint];
  if (!fingerprints.every((value) => typeof value === "string" && value.length > 0)) return null;
  return a.localFingerprint === b.remoteFingerprint && b.localFingerprint === a.remoteFingerprint;
}

export function endInvariantState(finalSample, i4ok) {
  return Object.fromEntries([
    ...STATE_INVARIANTS.map((key) => [key, finalSample && !finalSample.unknown ? finalSample[key] === true : false]),
    ["I4", i4ok === true],
  ]);
}

export function invariantProblems({ finalSample, firstSatisfiedSinceClear, heldAtEnd, required, scenario, role, observeS, firstAuthenticatedSinceClear }) {
  const problems = [];
  const context = `(scenario ${scenario} role ${role})`;
  for (const key of required) {
    const first = firstSatisfiedSinceClear[key];
    if (typeof first !== "number" || !Number.isFinite(first)) problems.push(`${key} NEVER held in the ${observeS}s observation window ${context}`);
    else if (heldAtEnd[key] !== true) problems.push(`${key} first held at ${first}s but NOT at the end of the observation window ${context}`);
  }
  if (!finalSample || finalSample.unknown) problems.push(`final invariant sample unavailable ${context}`);
  if (scenario !== "pin-typo") {
    if (finalSample?.bothAuthenticated !== true) problems.push(`both peers are not authenticated in the final sample ${context}`);
    if (finalSample?.fpAgree !== true) problems.push(`DTLS fingerprint agreement is not established in the final sample: fpAgree=${String(finalSample?.fpAgree)} ${context}`);
  }
  if (/^(?:proc-freeze-\d+|freeze-\d+|freeze-ws-\d+)$/.test(scenario)) {
    const i2 = firstSatisfiedSinceClear.I2;
    if (typeof i2 !== "number" || i2 > 15) problems.push(`I2 did not recover within 15s of thaw: first=${String(i2)}s ${context}`);
    // I2 also permits two empty rosters. That is consistent state, but it cannot
    // stand in for a restored authenticated edge when measuring recovery.
    if (typeof firstAuthenticatedSinceClear !== "number" || firstAuthenticatedSinceClear > 15) problems.push(`authenticated edge did not recover within 15s of thaw: first=${String(firstAuthenticatedSinceClear)}s ${context}`);
  }
  if (scenario === "two-tabs") {
    if (typeof firstAuthenticatedSinceClear !== "number" || firstAuthenticatedSinceClear > 20) problems.push(`replacement tab did not authenticate within 20s of connect: first=${String(firstAuthenticatedSinceClear)}s ${context}`);
    const i4 = firstSatisfiedSinceClear.I4;
    if (typeof i4 !== "number" || i4 > 20) problems.push(`replacement tab did not exchange messages within 20s of connect: first=${String(i4)}s ${context}`);
  }
  return problems;
}

export function diagnosticProblems(diagnostics) {
  const problems = [];
  for (const side of ["A", "B"]) {
    const diag = diagnostics?.[side];
    if (!diag || typeof diag !== "object" || Array.isArray(diag)) {
      problems.push(`${side} diagnostics unavailable: ${String(diag)}`);
      continue;
    }
    if (!Array.isArray(diag.pendingMutations)) problems.push(`${side} pending RTK mutation diagnostic unavailable`);
    else if (diag.pendingMutations.length) problems.push(`${side} has pending RTK mutations at the end: ${JSON.stringify(diag.pendingMutations)}`);
    if (!diag.roomPeerMutexes || typeof diag.roomPeerMutexes !== "object" || Array.isArray(diag.roomPeerMutexes)) problems.push(`${side} per-peer mutex diagnostic unavailable`);
    else if (Object.values(diag.roomPeerMutexes).some((held) => held !== false)) problems.push(`${side} has held or unknown per-peer mutexes: ${JSON.stringify(diag.roomPeerMutexes)}`);
    // Idle negotiation mutexes remove themselves from the registry. This global
    // count also catches stranded operations for an edge absent from the roster.
    if (diag.roomPeerMutexCount !== 0) problems.push(`${side} negotiation mutex registry did not drain: count=${String(diag.roomPeerMutexCount)}`);
    if (typeof diag.dbProbe !== "string" || !/^resolved:(?:true|false)$/.test(diag.dbProbe)) problems.push(`${side} IndexedDB round trip did not resolve: ${String(diag.dbProbe)}`);
    if (typeof diag.dbProbeMs !== "number" || !Number.isFinite(diag.dbProbeMs) || diag.dbProbeMs >= 3000) problems.push(`${side} IndexedDB round trip exceeded its 3000ms budget: ${String(diag.dbProbeMs)}ms`);
  }
  return problems;
}
