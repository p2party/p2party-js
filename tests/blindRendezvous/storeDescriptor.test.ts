import { describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import {
  chainStartConflict,
  descriptorChainStart,
  descriptorHash,
  descriptorSupportsProfile,
  publicCarrierContextId,
  publicRouteInstanceId,
  routeId,
  storeDescriptorActiveAt,
  storeDescriptorAuthentic,
  storeDescriptorSignedMessage,
  storeId,
  storeRouteActiveAt,
  storeRouteAuthentic,
  storeRouteSignedMessage,
  validateStoreDescriptor,
  validateStoreRoute,
} from "../../src/blindRendezvous/storeDescriptor";

import type {
  StoreDescriptorV1,
  StoreRouteV1,
} from "../../src/blindRendezvous/storeDescriptor";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

const NOW = 1_700_000_000_000n;
const profileA = bytes(0x11);
const profileB = bytes(0x22);
// Supported profiles are sorted bytewise, and chain starts follow that order.
const [firstProfile, secondProfile] =
  hex(profileA) < hex(profileB) ? [profileA, profileB] : [profileB, profileA];

const store = await newKeyPair();
const otherStore = await newKeyPair();

const unsignedDescriptor = {
  version: 1 as const,
  storeIdentityEd25519Key: store.publicKey,
  allocationIssuerPublicKeyDer: Uint8Array.of(0x30, 0x82, 0x01, 0x22),
  descriptorGeneration: 7n,
  compatibilityHash: bytes(0x33),
  supportedDeliveryProfileHashes: [firstProfile, secondProfile],
  checkpointChainStarts: [
    { deliveryProfileHash: firstProfile, chainStartIngressWindow: 100n },
    { deliveryProfileHash: secondProfile, chainStartIngressWindow: 200n },
  ],
  notBeforeUnixMs: NOW - 1000n,
  notAfterUnixMs: NOW + 1_000_000n,
};

const signDescriptor = async (
  fields: typeof unsignedDescriptor,
  signer = store,
): Promise<StoreDescriptorV1> => {
  const draft: StoreDescriptorV1 = {
    ...fields,
    descriptorSignature: new Uint8Array(64),
  };
  return {
    ...draft,
    descriptorSignature: await sign(
      await storeDescriptorSignedMessage(draft),
      signer.secretKey,
    ),
  };
};

const descriptor = await signDescriptor(unsignedDescriptor);

const signRoute = async (
  fields: Omit<StoreRouteV1, "routeSignature">,
  signer = store,
): Promise<StoreRouteV1> => {
  const draft: StoreRouteV1 = { ...fields, routeSignature: new Uint8Array(64) };
  return {
    ...draft,
    routeSignature: await sign(
      await storeRouteSignedMessage(draft),
      signer.secretKey,
    ),
  };
};

const routeFields = async (): Promise<
  Omit<StoreRouteV1, "routeSignature">
> => ({
  version: 1,
  storeId: await storeId(store.publicKey),
  descriptorHash: await descriptorHash(descriptor),
  routeFamily: 1,
  opaqueLocator: new TextEncoder().encode("https://store.example.com"),
  routePublicParameters: new Uint8Array(0),
  notBeforeUnixMs: NOW - 1000n,
  notAfterUnixMs: NOW + 100_000n,
});

const route = await signRoute(await routeFields());

describe("store identity survives rotation", () => {
  test("StoreId depends on the key alone, not the descriptor", async () => {
    const rotated = await signDescriptor({
      ...unsignedDescriptor,
      descriptorGeneration: 8n,
      compatibilityHash: bytes(0x44),
    });
    expect(hex(await storeId(rotated.storeIdentityEd25519Key))).toBe(
      hex(await storeId(descriptor.storeIdentityEd25519Key)),
    );
    // ...while the descriptor hash tracks the change.
    expect(hex(await descriptorHash(rotated))).not.toBe(
      hex(await descriptorHash(descriptor)),
    );
  });

  test("a different store key is a different store", async () => {
    expect(hex(await storeId(otherStore.publicKey))).not.toBe(
      hex(await storeId(store.publicKey)),
    );
  });

  test("a store key must be exactly 32 bytes", async () => {
    await expect(storeId(new Uint8Array(31))).rejects.toThrow(
      "exactly 32 bytes",
    );
  });
});

describe("descriptor validation", () => {
  test("accepts a well-formed, currently valid, correctly signed descriptor", async () => {
    expect((await validateStoreDescriptor(descriptor, NOW)).valid).toBe(true);
  });

  test("separates timeless authenticity from explicit-time activation", async () => {
    expect((await storeDescriptorAuthentic(descriptor)).valid).toBe(true);

    expect(
      (
        await storeDescriptorActiveAt(
          descriptor,
          descriptor.notBeforeUnixMs - 1n,
        )
      ).valid,
    ).toBe(false);
    expect(
      (await storeDescriptorActiveAt(descriptor, descriptor.notAfterUnixMs))
        .valid,
    ).toBe(false);

    // Lease expiry never rewrites whether the signed descriptor is authentic.
    expect((await storeDescriptorAuthentic(descriptor)).valid).toBe(true);
  });

  test("active-at uses one private descriptor snapshot", async () => {
    const mutable: StoreDescriptorV1 = {
      ...descriptor,
      descriptorSignature: Uint8Array.from(descriptor.descriptorSignature),
    };
    const writable = mutable as {
      notAfterUnixMs: bigint;
      descriptorSignature: Uint8Array;
    };

    const pending = storeDescriptorActiveAt(mutable, NOW);
    writable.notAfterUnixMs = NOW;
    writable.descriptorSignature.fill(0);

    expect(await pending).toEqual({ valid: true });
  });

  test("rejects a descriptor outside its validity interval", async () => {
    const before = await validateStoreDescriptor(
      descriptor,
      descriptor.notBeforeUnixMs - 1n,
    );
    expect(before.valid).toBe(false);
    // The end is exclusive.
    const atEnd = await validateStoreDescriptor(
      descriptor,
      descriptor.notAfterUnixMs,
    );
    expect(atEnd.valid).toBe(false);
  });

  test("rejects a non-u64 descriptor activation instant before cryptography", async () => {
    const verdict = await storeDescriptorActiveAt(
      descriptor,
      Number.NaN as unknown as bigint,
    );
    expect(verdict).toEqual({
      valid: false,
      reason: "activation instant must be an unsigned 64-bit integer",
    });
  });

  test("rejects a signature made by another key", async () => {
    const forged = await signDescriptor(unsignedDescriptor, otherStore);
    const verdict = await validateStoreDescriptor(forged, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("signature does not verify");
  });

  test("rejects any mutation of the signed body", async () => {
    for (const mutated of [
      { ...descriptor, descriptorGeneration: 8n },
      { ...descriptor, compatibilityHash: bytes(0x99) },
      { ...descriptor, notAfterUnixMs: descriptor.notAfterUnixMs + 1n },
    ])
      expect((await validateStoreDescriptor(mutated, NOW)).valid).toBe(false);
  });

  test("requires exactly one chain start per profile", async () => {
    const missing = await signDescriptor({
      ...unsignedDescriptor,
      checkpointChainStarts: [unsignedDescriptor.checkpointChainStarts[0]],
    });
    const verdict = await validateStoreDescriptor(missing, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("exactly one chain start");
  });

  test("rejects a chain start for a profile the store does not serve", async () => {
    // Both arrays stay canonically sorted, so the encoder does not catch this:
    // it is the semantic pairing that fails. Otherwise a store could claim an
    // anchor for a profile it never commits to.
    const mismatched = await signDescriptor({
      ...unsignedDescriptor,
      checkpointChainStarts: [
        { deliveryProfileHash: firstProfile, chainStartIngressWindow: 100n },
        { deliveryProfileHash: bytes(0xfe), chainStartIngressWindow: 200n },
      ],
    });
    const verdict = await validateStoreDescriptor(mismatched, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("supported-profile order");
  });

  test("a noncanonical collection is refused rather than encoded", async () => {
    // The encoder rejects an unsorted or duplicated collection before any
    // signature is considered, so such a descriptor cannot even be constructed
    // to be signed. Validation reports that instead of throwing.
    const duplicated: StoreDescriptorV1 = {
      ...unsignedDescriptor,
      supportedDeliveryProfileHashes: [firstProfile, firstProfile],
      checkpointChainStarts: [
        { deliveryProfileHash: firstProfile, chainStartIngressWindow: 100n },
        { deliveryProfileHash: firstProfile, chainStartIngressWindow: 200n },
      ],
      descriptorSignature: new Uint8Array(64),
    };
    const verdict = await validateStoreDescriptor(duplicated, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("duplicate-free");

    await expect(descriptorHash(duplicated)).rejects.toThrow("duplicate-free");
  });

  test("exposes profile support and chain starts", () => {
    expect(descriptorSupportsProfile(descriptor, firstProfile)).toBe(true);
    expect(descriptorSupportsProfile(descriptor, bytes(0xee))).toBe(false);
    expect(descriptorChainStart(descriptor, secondProfile)).toBe(200n);
    expect(descriptorChainStart(descriptor, bytes(0xee))).toBeNull();
  });
});

describe("route validation binds a route to its exact store and descriptor", () => {
  test("accepts a correctly signed, currently leased route", async () => {
    expect((await validateStoreRoute(route, descriptor, NOW)).valid).toBe(true);
  });

  test("separates timeless authenticity from explicit-time activation", async () => {
    expect((await storeRouteAuthentic(route, descriptor)).valid).toBe(true);
    expect(
      (await storeRouteActiveAt(route, descriptor, route.notAfterUnixMs)).valid,
    ).toBe(false);

    // Route expiry never rewrites the signed route's authenticity.
    expect((await storeRouteAuthentic(route, descriptor)).valid).toBe(true);
  });

  test("snapshots the route and descriptor before authentication yields", async () => {
    const mutableRoute: StoreRouteV1 = {
      ...route,
      routeSignature: Uint8Array.from(route.routeSignature),
    };
    const mutableDescriptor: StoreDescriptorV1 = {
      ...descriptor,
      descriptorSignature: Uint8Array.from(descriptor.descriptorSignature),
    };

    const pending = storeRouteAuthentic(mutableRoute, mutableDescriptor);
    mutableRoute.routeSignature.fill(0);
    mutableDescriptor.descriptorSignature.fill(0);

    expect(await pending).toEqual({ valid: true });
  });

  test("active-at applies the lease from its one private route snapshot", async () => {
    const mutableRoute: StoreRouteV1 = {
      ...route,
      routeSignature: Uint8Array.from(route.routeSignature),
    };
    const writable = mutableRoute as {
      notAfterUnixMs: bigint;
      routeSignature: Uint8Array;
    };

    const pending = storeRouteActiveAt(mutableRoute, descriptor, NOW);
    writable.notAfterUnixMs = NOW;
    writable.routeSignature.fill(0);

    expect((await pending).valid).toBe(true);
  });

  test("rejects cheap route failures before descriptor signature work", async () => {
    const forgedDescriptor = await signDescriptor(
      unsignedDescriptor,
      otherStore,
    );

    const emptyLease: StoreRouteV1 = {
      ...route,
      notAfterUnixMs: route.notBeforeUnixMs,
    };
    const semanticVerdict = await storeRouteAuthentic(
      emptyLease,
      forgedDescriptor,
    );
    expect(semanticVerdict).toEqual({
      valid: false,
      reason: "route lease is empty",
    });

    const noncanonical: StoreRouteV1 = {
      ...route,
      storeId: new Uint8Array(31),
    };
    const canonicalVerdict = await storeRouteAuthentic(
      noncanonical,
      forgedDescriptor,
    );
    expect(canonicalVerdict.valid).toBe(false);
    if (canonicalVerdict.valid) throw new Error("unreachable");
    expect(canonicalVerdict.reason).toContain("storeId");
    expect(canonicalVerdict.reason).not.toContain("descriptor signature");
  });

  test("route authenticity includes descriptor authenticity", async () => {
    // The descriptor body is unchanged, so this route still has the exact
    // StoreId/DescriptorHash cross-binding and its own valid store signature.
    // Only the descriptor signature is forged.
    const forgedDescriptor = await signDescriptor(
      unsignedDescriptor,
      otherStore,
    );
    const verdict = await storeRouteAuthentic(route, forgedDescriptor);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("descriptor signature does not verify");
  });

  test("rejects a route lifted onto another descriptor generation", async () => {
    const rotated = await signDescriptor({
      ...unsignedDescriptor,
      descriptorGeneration: 8n,
    });
    const verdict = await validateStoreRoute(route, rotated, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("different descriptor");
  });

  test("rejects a route signed by another store", async () => {
    const forged = await signRoute(await routeFields(), otherStore);
    const verdict = await validateStoreRoute(forged, descriptor, NOW);
    expect(verdict.valid).toBe(false);
    if (verdict.valid) throw new Error("unreachable");
    expect(verdict.reason).toContain("signature does not verify");
  });

  test("rejects an expired or not-yet-valid lease", async () => {
    expect(
      (await validateStoreRoute(route, descriptor, route.notAfterUnixMs)).valid,
    ).toBe(false);
    expect(
      (await validateStoreRoute(route, descriptor, route.notBeforeUnixMs - 1n))
        .valid,
    ).toBe(false);
  });

  test("rejects a non-u64 route activation instant before cryptography", async () => {
    const verdict = await storeRouteActiveAt(
      route,
      descriptor,
      Number.NaN as unknown as bigint,
    );
    expect(verdict).toEqual({
      valid: false,
      reason: "activation instant must be an unsigned 64-bit integer",
    });
  });

  test("rejects a mutated locator", async () => {
    const tampered: StoreRouteV1 = {
      ...route,
      opaqueLocator: new TextEncoder().encode("https://evil.example.com"),
    };
    expect((await validateStoreRoute(tampered, descriptor, NOW)).valid).toBe(
      false,
    );
  });
});

describe("carrier context and route instance scopes", () => {
  test("one store and profile is one context, whatever the route", async () => {
    const context = await publicCarrierContextId(
      await storeId(store.publicKey),
      firstProfile,
    );
    expect(
      hex(
        await publicCarrierContextId(
          await storeId(store.publicKey),
          firstProfile,
        ),
      ),
    ).toBe(hex(context));
    // A different profile is a different wrapping domain.
    expect(
      hex(
        await publicCarrierContextId(
          await storeId(store.publicKey),
          secondProfile,
        ),
      ),
    ).not.toBe(hex(context));
  });

  test("two routes to one store are two instances of one context", async () => {
    const context = await publicCarrierContextId(
      await storeId(store.publicKey),
      firstProfile,
    );
    const secondRoute = await signRoute({
      ...(await routeFields()),
      routeFamily: 2,
    });

    const first = await publicRouteInstanceId(context, await routeId(route));
    const second = await publicRouteInstanceId(
      context,
      await routeId(secondRoute),
    );
    expect(hex(first)).not.toBe(hex(second));
    // Both still derive from the same context, so they cannot become two
    // stores or two chances to publish one object.
    expect(hex(await routeId(route))).not.toBe(hex(await routeId(secondRoute)));
  });
});

describe("chain-start equivocation is permanent for a store and profile", () => {
  test("two descriptors of one store naming different starts conflict", async () => {
    const other = await signDescriptor({
      ...unsignedDescriptor,
      descriptorGeneration: 9n,
      checkpointChainStarts: [
        { deliveryProfileHash: firstProfile, chainStartIngressWindow: 101n },
        { deliveryProfileHash: secondProfile, chainStartIngressWindow: 200n },
      ],
    });

    const result = await chainStartConflict(descriptor, other, firstProfile);
    expect(result.conflicting).toBe(true);
    if (!result.conflicting) throw new Error("unreachable");

    // Canonical order by descriptor hash, so the pair yields one proof rather
    // than two mirror images.
    const reversed = await chainStartConflict(other, descriptor, firstProfile);
    if (!reversed.conflicting) throw new Error("unreachable");
    expect(hex(await descriptorHash(result.canonicalOrder[0]))).toBe(
      hex(await descriptorHash(reversed.canonicalOrder[0])),
    );
    expect(
      hex(await descriptorHash(result.canonicalOrder[0])) <
        hex(await descriptorHash(result.canonicalOrder[1])),
    ).toBe(true);

    // A higher generation cannot clear it: the same pair still conflicts.
    expect(
      (await chainStartConflict(descriptor, other, firstProfile)).conflicting,
    ).toBe(true);
  });

  test("conflict evidence authenticates and owns both descriptors before yielding", async () => {
    const other = await signDescriptor({
      ...unsignedDescriptor,
      descriptorGeneration: 9n,
      checkpointChainStarts: [
        { deliveryProfileHash: firstProfile, chainStartIngressWindow: 101n },
        { deliveryProfileHash: secondProfile, chainStartIngressWindow: 200n },
      ],
    });
    const mutableFirst: StoreDescriptorV1 = {
      ...descriptor,
      storeIdentityEd25519Key: Uint8Array.from(
        descriptor.storeIdentityEd25519Key,
      ),
      descriptorSignature: Uint8Array.from(descriptor.descriptorSignature),
    };
    const mutableSecond: StoreDescriptorV1 = {
      ...other,
      storeIdentityEd25519Key: Uint8Array.from(other.storeIdentityEd25519Key),
      descriptorSignature: Uint8Array.from(other.descriptorSignature),
    };
    const mutableProfile = Uint8Array.from(firstProfile);

    const pending = chainStartConflict(
      mutableFirst,
      mutableSecond,
      mutableProfile,
    );
    mutableFirst.storeIdentityEd25519Key.fill(0);
    mutableSecond.storeIdentityEd25519Key.fill(0xff);
    mutableFirst.descriptorSignature.fill(0);
    mutableSecond.descriptorSignature.fill(0);
    mutableProfile.fill(0xee);

    const result = await pending;
    expect(result.conflicting).toBe(true);
    if (!result.conflicting) throw new Error("unreachable");
    expect(result.canonicalOrder[0]).not.toBe(mutableFirst);
    expect(result.canonicalOrder[1]).not.toBe(mutableSecond);
    expect(
      hex(await storeId(result.canonicalOrder[0].storeIdentityEd25519Key)),
    ).toBe(
      hex(await storeId(result.canonicalOrder[1].storeIdentityEd25519Key)),
    );

    const forged = {
      ...other,
      descriptorSignature: bytes(0xff, 64),
    };
    expect(
      (await chainStartConflict(descriptor, forged, firstProfile)).conflicting,
    ).toBe(false);
  });

  test("an unchanged start, another store, or another profile does not conflict", async () => {
    const sameStart = await signDescriptor({
      ...unsignedDescriptor,
      descriptorGeneration: 9n,
      compatibilityHash: bytes(0x55),
    });
    expect(
      (await chainStartConflict(descriptor, sameStart, firstProfile))
        .conflicting,
    ).toBe(false);

    const different = await signDescriptor(
      { ...unsignedDescriptor, storeIdentityEd25519Key: otherStore.publicKey },
      otherStore,
    );
    expect(
      (await chainStartConflict(descriptor, different, firstProfile))
        .conflicting,
    ).toBe(false);

    expect(
      (await chainStartConflict(descriptor, sameStart, bytes(0xee)))
        .conflicting,
    ).toBe(false);
  });
});
