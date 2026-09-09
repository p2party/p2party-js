import { describe, expect, test } from "bun:test";
import { desyncProbeBudget, lateI4Problem } from "../../docs/e2e/desync/desync-probe-budget.mjs";
import { scheduledDeliveryTimeoutMs } from "../../src/handlers/coverTransfer.ts";

describe("browser scheduled probe deadlines", () => {
  test("the immediate path retains its existing budgets", () => {
    expect(desyncProbeBudget("immediate")).toEqual({ roundTripMs: 30000, finalI4DrainMs: 65000 });
  });
  test.each([2000, 10000, 70000, 300000])("scheduled cadence %s gives the SDK receipt bound time to complete", (coverCadenceMs) => {
    const sdkBound = scheduledDeliveryTimeoutMs({ coverCadenceMs, coverLanes: 2, coverFramesPerCell: 16, coverDurationEpochs: 1 });
    const budget = desyncProbeBudget("scheduled", coverCadenceMs);
    expect(budget.roundTripMs).toBe(Math.max(30000, sdkBound + 10000));
    expect(budget.finalI4DrainMs).toBe(budget.roundTripMs + 5000);
  });
  test("the former fixed 30-second deadline is shorter than one legal 70-second cycle", () => {
    const budget = desyncProbeBudget("scheduled", 70000);
    expect(budget.roundTripMs).toBe(173282);
    expect(budget.roundTripMs).toBeGreaterThan(2 * 70000);
  });
  test("waiting for cleanup cannot credit delivery after the observation window", () => {
    expect(lateI4Problem(300, 300)).toBeNull();
    expect(lateI4Problem(300.001, 300)).toContain("outside the 300s observation window");
    expect(lateI4Problem("never", 300)).toBeNull(); // the required-I4 assertion covers never
  });
});
