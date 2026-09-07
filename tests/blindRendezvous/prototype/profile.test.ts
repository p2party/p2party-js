import { describe, expect, test } from "bun:test";

import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  ProfileGeometryError,
  carrierObjectWireBytes,
  profileGeometry,
  sizeClassForPayloadClass,
  validateDeliveryProfileGeometry,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import { deliveryProfileHash } from "../../../src/blindRendezvous/derivations";

describe("prototype delivery profile", () => {
  test("the shipped constant satisfies every §4.3 inequality", () => {
    expect(() =>
      validateDeliveryProfileGeometry(PROTOTYPE_DELIVERY_PROFILE_V0),
    ).not.toThrow();
  });

  test("hashes canonically", async () => {
    const digest = await deliveryProfileHash(PROTOTYPE_DELIVERY_PROFILE_V0);
    expect(digest.length).toBe(32);
  });

  test("publicChunksPerWindow is minimal for scheduledObjects", () => {
    const p = PROTOTYPE_DELIVERY_PROFILE_V0;
    for (const c of p.sizeClasses) {
      const scheduled =
        p.cohortAllocationsPerWindow *
        p.roomSlotsPerClient *
        c.appendSchedule.length;
      expect(c.publicChunksPerWindow).toBe(
        Math.ceil(scheduled / p.publicChunkObjectCount),
      );
    }
  });

  test("rejects a schedule whose append precedes the allocation budget", () => {
    const bad = {
      ...PROTOTYPE_DELIVERY_PROFILE_V0,
      sizeClasses: PROTOTYPE_DELIVERY_PROFILE_V0.sizeClasses.map((c) => ({
        ...c,
        appendSchedule: c.appendSchedule.map((e, i) =>
          i === 0 ? { ...e, offsetMs: 800n } : e,
        ),
      })),
    };
    expect(() => validateDeliveryProfileGeometry(bad)).toThrow(
      ProfileGeometryError,
    );
  });

  test("rejects a missing identity-bootstrap role in class 0", () => {
    const bad = {
      ...PROTOTYPE_DELIVERY_PROFILE_V0,
      sizeClasses: PROTOTYPE_DELIVERY_PROFILE_V0.sizeClasses.map((c) =>
        c.id === 0
          ? {
              ...c,
              appendSchedule: c.appendSchedule.map((e) => ({
                ...e,
                role: "safety-control" as const,
              })),
            }
          : c,
      ),
    };
    expect(() => validateDeliveryProfileGeometry(bad)).toThrow(
      ProfileGeometryError,
    );
  });

  test("geometry projection and class lookup", () => {
    const g = profileGeometry(PROTOTYPE_DELIVERY_PROFILE_V0);
    expect(g.sizeClasses.map((c) => c.id)).toEqual([0, 1]);
    expect(sizeClassForPayloadClass(PROTOTYPE_DELIVERY_PROFILE_V0, 1).id).toBe(
      1,
    );
  });

  test("wire object length is header plus the class body", async () => {
    const digest = await deliveryProfileHash(PROTOTYPE_DELIVERY_PROFILE_V0);
    expect(
      carrierObjectWireBytes(PROTOTYPE_DELIVERY_PROFILE_V0, 0, digest),
    ).toBe(1 + 32 + 8 + 1 + 32 + 24 + 4 + 8192);
  });

  test("withDeliveryWindowMs scales offsets and stays valid", () => {
    const fast = withDeliveryWindowMs(PROTOTYPE_DELIVERY_PROFILE_V0, 2000n);
    expect(fast.deliveryWindowMs).toBe(2000n);
    expect(fast.chunkFinalizationOffsetMs).toBe(1400n);
    expect(() => validateDeliveryProfileGeometry(fast)).not.toThrow();
  });
});
