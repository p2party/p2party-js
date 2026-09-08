// The browser app's scheduled harness preset is two lanes, sixteen cells per
// lane, and one epoch per cycle. A short text probe occupies three cells and
// fits one job. Its terminal receipt waits for the following cycle.
export function desyncProbeBudget(mode, cadenceMs = 2000) {
  if (mode !== "scheduled") return { roundTripMs: 30000, finalI4DrainMs: 65000 };
  if (!Number.isFinite(cadenceMs) || cadenceMs <= 0)
    throw new Error("Scheduled probe cadence must be positive and finite");
  const lanes = 2, frames = 16, epochs = 1;
  // Mirrors coverTransfer.scheduledDeliveryTimeoutMs for that preset. The test
  // compares against the SDK calculation so its margin cannot drift silently.
  const receiptFloorWithMargin = 2 * cadenceMs * epochs +
    Math.ceil((2 * lanes - 1) * cadenceMs / (2 * lanes * frames)) + 20000;
  const roundTripMs = Math.max(30000, receiptFloorWithMargin + 10000);
  return { roundTripMs, finalI4DrainMs: roundTripMs + 5000 };
}

// The final await drains work; it does not extend the observation window.
export function lateI4Problem(firstI4, observeS) {
  return typeof firstI4 === "number" && firstI4 > observeS
    ? `I4 first completed at ${firstI4}s, outside the ${observeS}s observation window`
    : null;
}
