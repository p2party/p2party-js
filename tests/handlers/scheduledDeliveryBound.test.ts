import { describe, expect, test } from "bun:test";

import { scheduledDeliveryTimeoutMs } from "../../src/handlers/coverTransfer";
import { SCHEDULED_DELIVERY_MARGIN_MS } from "../../src/utils/constants";
import { coverSlotSpacingMs } from "../../src/handlers/coverScheduler";

import type { ScheduledDeliveryScheduleShape } from "../../src/handlers/coverTransfer";

// Lanes/frames match the shipped presets in src/roomPolicy.ts (mirrored by
// p2party.com/src/protocol/v4.ts): the "5 min cycles" entry is
// { coverCadenceMs: 300_000, coverLanes: 2, coverFramesPerCell: 64,
// coverDurationEpochs: 1 }. The bound is dominated by the two cycles, so the
// frame count only moves the slot-spacing term.
const preset = (
  coverCadenceMs: number,
  coverFramesPerCell = 16,
): ScheduledDeliveryScheduleShape => ({
  coverCadenceMs,
  coverLanes: 2,
  coverFramesPerCell,
  coverDurationEpochs: 1,
});

/**
 * The scheduler's own slot arithmetic (coverScheduler.slotAt) for the FIRST
 * slot of the LAST lane in a cycle: ordinal `coverLanes - 1`, epoch 0. A job
 * dequeued onto that lane cannot emit its first cell any earlier than this.
 */
const lastLaneFirstSlotMs = (
  schedule: ScheduledDeliveryScheduleShape,
): number =>
  Math.floor(
    ((2 * (schedule.coverLanes - 1) + 1) * schedule.coverCadenceMs) /
      (2 * schedule.coverLanes * schedule.coverFramesPerCell),
  );

/** The same instant rounded away from the scheduler, as a bound must be. */
const lastLaneFirstSlotCeilMs = (
  schedule: ScheduledDeliveryScheduleShape,
): number =>
  Math.ceil(
    ((2 * (schedule.coverLanes - 1) + 1) * schedule.coverCadenceMs) /
      (2 * schedule.coverLanes * schedule.coverFramesPerCell),
  );

/**
 * The worst case of the EARLIEST possible confirmation, measured from the
 * moment `send()` enqueues the job.
 *
 * A job is admitted only at a cycle open, so a send issued just after a
 * boundary waits a whole cycle for admission (`cycleMs`). The receiver's
 * terminal receipt is itself a control job admitted at the NEXT open (a second
 * `cycleMs`), and emits at that job's first lane slot — at worst the last
 * lane's. Anything below this rejects a send that is going to arrive.
 */
const worstCaseEarliestConfirmationMs = (
  schedule: ScheduledDeliveryScheduleShape,
): number =>
  2 * schedule.coverCadenceMs * schedule.coverDurationEpochs +
  lastLaneFirstSlotMs(schedule);

describe("scheduled delivery bound", () => {
  test("covers two full cycles plus the slot the receipt can first reach plus the margin", () => {
    // A job is admitted only at a cycle open, and the receiver's terminal
    // receipt is itself a job admitted at the NEXT open. Two cycles is the
    // floor; anything less rejects a send that is going to arrive.
    //
    // The plan wrote this third term as one slot spacing. That is right only
    // for a single-lane room: lanes are striped across the cycle, so a control
    // job dequeued onto the LAST lane first emits (lanes - 0.5) spacings in.
    // Using the spacing would spend part of the fixed margin covering the
    // stripe, and for a wide-lane room would spend more than all of it. The
    // term is therefore max(spacing, last lane's first slot), which is never
    // smaller than the plan's value.
    for (const cadence of [10_000, 60_000, 300_000]) {
      const schedule = preset(cadence);
      const spacingMs = Math.ceil(
        coverSlotSpacingMs({ ...schedule, phaseOffsetMs: 0 }),
      );
      expect(scheduledDeliveryTimeoutMs(schedule)).toBe(
        2 * cadence * schedule.coverDurationEpochs +
          Math.max(spacingMs, lastLaneFirstSlotCeilMs(schedule)) +
          SCHEDULED_DELIVERY_MARGIN_MS,
      );
      expect(scheduledDeliveryTimeoutMs(schedule)).toBeGreaterThanOrEqual(
        2 * cadence * schedule.coverDurationEpochs +
          spacingMs +
          SCHEDULED_DELIVERY_MARGIN_MS,
      );
    }
  });

  // C3: the shipped "5 min cycles" preset needs 301.2 s minimum. A fixed
  // 120 s bound rejected 100% of sends in such a room.
  test("the 5 min preset gets more than its 301.2 s minimum", () => {
    expect(scheduledDeliveryTimeoutMs(preset(300_000, 64))).toBeGreaterThan(
      301_200,
    );
  });

  test("the 60 s preset clears one boundary-adjacent send", () => {
    expect(scheduledDeliveryTimeoutMs(preset(60_000))).toBeGreaterThan(121_875);
  });

  test("a multi-epoch cycle is counted in cycles, not cadences", () => {
    const schedule = { ...preset(10_000), coverDurationEpochs: 3 };
    expect(scheduledDeliveryTimeoutMs(schedule)).toBeGreaterThan(60_000);
  });

  test("a malformed schedule is rejected rather than silently truncated", () => {
    expect(() => scheduledDeliveryTimeoutMs(preset(0))).toThrow(
      "coverTransfer: cover cadence must be a positive duration",
    );
    expect(() =>
      scheduledDeliveryTimeoutMs({ ...preset(60_000), coverLanes: 0 }),
    ).toThrow("coverTransfer: cover lanes must be a positive count");
    expect(() =>
      scheduledDeliveryTimeoutMs({ ...preset(60_000), coverFramesPerCell: 0 }),
    ).toThrow("coverTransfer: cover frames per cell must be a positive count");
    expect(() =>
      scheduledDeliveryTimeoutMs({ ...preset(60_000), coverDurationEpochs: 0 }),
    ).toThrow("coverTransfer: cover duration epochs must be a positive count");
  });

  // Every schedule the SDK actually ships. Each is checked against the
  // arithmetic worst case derived from the scheduler's own slot formula, not
  // against a number copied from the hunt report.
  test("every shipped preset gets more than its own worst-case earliest confirmation", () => {
    // Verbatim from SCHEDULED_COVER_PRESETS in p2party.com/src/protocol/v4.ts,
    // the only place a user picks a scheduled schedule today.
    const shippedPresets: readonly ScheduledDeliveryScheduleShape[] = [
      {
        coverCadenceMs: 10_000,
        coverLanes: 2,
        coverFramesPerCell: 16,
        coverDurationEpochs: 1,
      },
      {
        coverCadenceMs: 60_000,
        coverLanes: 2,
        coverFramesPerCell: 32,
        coverDurationEpochs: 1,
      },
      {
        coverCadenceMs: 300_000,
        coverLanes: 2,
        coverFramesPerCell: 64,
        coverDurationEpochs: 1,
      },
    ];
    for (const schedule of shippedPresets) {
      expect(scheduledDeliveryTimeoutMs(schedule)).toBeGreaterThan(
        worstCaseEarliestConfirmationMs(schedule),
      );
      // The bound this replaces was a flat 120 s; the 5 min preset alone needs
      // more than five times that.
      if (schedule.coverCadenceMs === 300_000)
        expect(scheduledDeliveryTimeoutMs(schedule)).toBeGreaterThan(600_000);
    }
  });

  // A wide-lane room stripes its lanes across the cycle, so a job dequeued
  // onto the LAST lane emits (lanes - 0.5) slot spacings in, not one. One slot
  // of head-room plus a fixed margin does not cover that on its own, and a
  // bound below the floor is C3 again with a different number.
  test("a wide-lane schedule is never bounded below its own last lane", () => {
    const wide: ScheduledDeliveryScheduleShape = {
      coverCadenceMs: 3_600_000,
      coverLanes: 16,
      coverFramesPerCell: 1,
      coverDurationEpochs: 1,
    };
    expect(lastLaneFirstSlotMs(wide)).toBeGreaterThan(
      Math.ceil(coverSlotSpacingMs({ ...wide, phaseOffsetMs: 0 })) +
        SCHEDULED_DELIVERY_MARGIN_MS,
    );
    expect(scheduledDeliveryTimeoutMs(wide)).toBeGreaterThan(
      worstCaseEarliestConfirmationMs(wide),
    );
  });
});
