import { describe, expect, test } from "bun:test";

import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  ProfileGeometryError,
  carrierObjectWireBytes,
  profileGeometry,
  selectPrototypeDeliveryProfile,
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

  test("pins each named profile with its measured role order and hash", async () => {
    const pinned = selectPrototypeDeliveryProfile();
    const candidate = selectPrototypeDeliveryProfile(
      "experimental-critical-later-v1",
    );
    expect(pinned).toBe(PROTOTYPE_DELIVERY_PROFILE_V0);
    expect(
      candidate.sizeClasses.map((c) =>
        c.appendSchedule.map((slot) => slot.role),
      ),
    ).toEqual([
      ["state-replication", "identity-bootstrap", "safety-control"],
      ["state-replication", "safety-control"],
    ]);
    expect(Buffer.from(await deliveryProfileHash(pinned)).toString("hex")).toBe(
      "83a2261ee4c0f345977e94416591372007578db22619b80afa583d2082c68a38",
    );
    expect(
      Buffer.from(await deliveryProfileHash(candidate)).toString("hex"),
    ).toBe("9728493b6acbc77e9a819a64011fce9f72b12e73b3d3c0951fca275ed3cbef3c");
    expect(
      selectPrototypeDeliveryProfile("experimental-critical-later-v1", 2000n),
    ).toEqual(withDeliveryWindowMs(candidate, 2000n));
    expect(() => selectPrototypeDeliveryProfile("other")).toThrow(
      ProfileGeometryError,
    );
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
