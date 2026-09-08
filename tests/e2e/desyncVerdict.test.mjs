import { describe, expect, test } from "bun:test";
import { diagnosticProblems, transportFingerprintAgreement, endInvariantState, invariantProblems } from "../../docs/e2e/desync/desync-verdict.mjs";

const healthy = () => ({
  scenario: "proc-freeze-20", role: "responder", observeS: 120,
  required: ["I1", "I2", "I3", "I4", "I5", "I6", "I7"],
  firstSatisfiedSinceClear: Object.fromEntries(["I1", "I2", "I3", "I4", "I5", "I6", "I7"].map((key) => [key, 2])),
  finalSample: { I1: true, I2: true, I3: true, I5: true, I6: true, I7: true, bothAuthenticated: true, fpAgree: true },
  firstAuthenticatedSinceClear: 2,
});
const verdict = (input) => invariantProblems({ ...input, heldAtEnd: endInvariantState(input.finalSample, true) });
const cleanDiag = () => ({ pendingMutations: [], roomPeerMutexes: { peer: false }, roomPeerMutexCount: 0, dbProbe: "resolved:false", dbProbeMs: 1 });

describe("desync browser acceptance", () => {
  test("a healed authenticated pair passes with a current final sample", () => expect(verdict(healthy())).toEqual([]));
  test("eventual recovery after the 15-second deadline fails", () => {
    const input = healthy();
    input.firstSatisfiedSinceClear.I2 = 30;
    input.firstAuthenticatedSinceClear = 30;
    expect(verdict(input)).toHaveLength(2);
    expect(verdict(input).every((problem) => problem.includes("within 15s"))).toBe(true);
  });
  test("exactly 15 seconds passes; 15.01 seconds fails", () => {
    const input = healthy();
    input.firstSatisfiedSinceClear.I2 = input.firstAuthenticatedSinceClear = 15;
    expect(verdict(input)).toEqual([]);
    input.firstSatisfiedSinceClear.I2 = input.firstAuthenticatedSinceClear = 15.01;
    expect(verdict(input)).toHaveLength(2);
  });
  test("empty rosters cannot masquerade as prompt recovery", () => {
    const input = healthy();
    input.firstAuthenticatedSinceClear = 30;
    expect(verdict(input)).toEqual([expect.stringContaining("authenticated edge did not recover")]);
  });
  test("an unknown final sample cannot reuse previously true state", () => {
    const input = healthy();
    input.finalSample = { unknown: true };
    expect(endInvariantState(input.finalSample, true)).toEqual({ I1: false, I2: false, I3: false, I4: true, I5: false, I6: false, I7: false });
    expect(verdict(input)).toContainEqual(expect.stringContaining("final invariant sample unavailable"));
  });
  test.each([null, undefined, false])("missing or false fingerprint agreement fails (%s)", (fpAgree) => {
    const input = healthy();
    input.finalSample.fpAgree = fpAgree;
    expect(verdict(input)).toEqual([expect.stringContaining("DTLS fingerprint agreement is not established")]);
  });
  test("missing final authentication fails even when I2 held", () => {
    const input = healthy();
    delete input.finalSample.bothAuthenticated;
    expect(verdict(input)).toEqual([expect.stringContaining("not authenticated in the final sample")]);
  });
  test("only the intentional mismatched-PIN scenario exempts authentication and fingerprints", () => {
    const input = healthy();
    input.scenario = "pin-typo";
    input.required = ["I1", "I5", "I6"];
    input.finalSample.bothAuthenticated = false;
    input.finalSample.fpAgree = null;
    expect(verdict(input)).toEqual([]);
  });
  test("same-identity second tab must authenticate and exchange within 20 seconds", () => {
    const input = healthy();
    input.scenario = "two-tabs";
    input.firstAuthenticatedSinceClear = 20;
    input.firstSatisfiedSinceClear.I4 = 20;
    expect(verdict(input)).toEqual([]);
    input.firstAuthenticatedSinceClear = input.firstSatisfiedSinceClear.I4 = 20.01;
    expect(verdict(input)).toHaveLength(2);
  });
});

describe("desync browser teardown diagnostics", () => {
  test("drained signaling and a successful DB round trip pass", () => expect(diagnosticProblems({ A: cleanDiag(), B: cleanDiag() })).toEqual([]));
  test.each(["TIMEOUT A.diag", null, undefined])("unavailable diagnostics fail (%s)", (value) => {
    expect(diagnosticProblems({ A: value, B: cleanDiag() })).toEqual([expect.stringContaining("A diagnostics unavailable")]);
  });
  test("a stuck RTK mutation fails", () => {
    const diag = cleanDiag();
    diag.pendingMutations = [{ endpointName: "setCandidate", ageMs: 10000 }];
    expect(diagnosticProblems({ A: diag, B: cleanDiag() })).toEqual([expect.stringContaining("pending RTK mutations")]);
  });
  test("a held mutex fails independently of the registry count", () => {
    const diag = cleanDiag();
    diag.roomPeerMutexes.peer = true;
    expect(diagnosticProblems({ A: diag, B: cleanDiag() })).toEqual([expect.stringContaining("held or unknown per-peer mutexes")]);
  });
  test("a registry leak for a peer absent from the roster fails", () => {
    const diag = cleanDiag();
    diag.roomPeerMutexCount = 1;
    expect(diagnosticProblems({ A: diag, B: cleanDiag() })).toEqual([expect.stringContaining("registry did not drain")]);
  });
  test.each(["TIMEOUT 3000ms", "error", undefined])("failed DB round trips fail (%s)", (dbProbe) => {
    const diag = { ...cleanDiag(), dbProbe };
    expect(diagnosticProblems({ A: diag, B: cleanDiag() })).toEqual([expect.stringContaining("IndexedDB round trip did not resolve")]);
  });
  test("a late DB resolution cannot hide the exceeded timeout", () => {
    const diag = { ...cleanDiag(), dbProbeMs: 3000 };
    expect(diagnosticProblems({ A: diag, B: cleanDiag() })).toEqual([expect.stringContaining("exceeded its 3000ms budget")]);
  });
});


describe("DTLS fingerprint evidence", () => {
  test("both pairwise fingerprints are required", () => {
    const a = { localFingerprint: "A", remoteFingerprint: "B" };
    const b = { localFingerprint: "B", remoteFingerprint: "A" };
    expect(transportFingerprintAgreement([a], [b])).toBe(true);
    expect(transportFingerprintAgreement([a], [{ ...b, localFingerprint: "C" }])).toBe(false);
    expect(transportFingerprintAgreement([{}], [{}])).toBe(null);
    expect(transportFingerprintAgreement([{ localFingerprint: "", remoteFingerprint: "" }], [{ localFingerprint: "", remoteFingerprint: "" }])).toBe(null);
    expect(transportFingerprintAgreement([a, a], [b])).toBe(null);
  });
});
