/**
 * Store identity and routes (Section 4.2).
 *
 * A `StoreId` is stable across compatible descriptor and route rotation, so
 * adding a route or refreshing a lease does not create a different store. What
 * changes with each descriptor is `DescriptorHash` and a monotonic generation.
 *
 * Neither a descriptor nor a route is part of room identity. That separation is
 * the point: a client can add, deny, or replace a store without rekeying a room
 * or reissuing an invitation, and a store learns nothing about the room from
 * either object.
 *
 * The descriptor signature proves possession of the store's identity key, and
 * every route signature is made with that same key — so a route binds the exact
 * `StoreId`, `DescriptorHash`, locator, parameters, family, and lease, and a
 * route cannot be transplanted onto another store or another descriptor.
 */

import { verify } from "../cryptography/ed25519";
import { encodeCanonical } from "./canonicalSchema";
import { concatBytes, domain, sha256 } from "./derivations";
import {
  storeDescriptorUnsignedV1Schema,
  storeDescriptorV1Schema,
  storeRouteUnsignedV1Schema,
  storeRouteV1Schema,
} from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";

export interface StoreCheckpointChainStartV1 {
  deliveryProfileHash: Uint8Array;
  chainStartIngressWindow: bigint;
}

export interface StoreDescriptorV1 {
  version: 1;
  storeIdentityEd25519Key: Uint8Array;
  allocationIssuerPublicKeyDer: Uint8Array;
  descriptorGeneration: bigint;
  compatibilityHash: Uint8Array;
  supportedDeliveryProfileHashes: readonly Uint8Array[];
  checkpointChainStarts: readonly StoreCheckpointChainStartV1[];
  notBeforeUnixMs: bigint;
  notAfterUnixMs: bigint;
  descriptorSignature: Uint8Array;
}

export interface StoreRouteV1 {
  version: 1;
  storeId: Uint8Array;
  descriptorHash: Uint8Array;
  routeFamily: number;
  opaqueLocator: Uint8Array;
  routePublicParameters: Uint8Array;
  notBeforeUnixMs: bigint;
  notAfterUnixMs: bigint;
  routeSignature: Uint8Array;
}

export class StoreDescriptorError extends Error {
  override readonly name = "StoreDescriptorError";

  constructor(message: string) {
    super(`storeDescriptor: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new StoreDescriptorError(message);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return false;
  return true;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++)
    if (left[index] !== right[index]) return left[index] - right[index];
  return left.length - right.length;
};

/* ------------------------------------------------------------------ *
 * Identifiers
 * ------------------------------------------------------------------ */

/**
 * `StoreId = H("p2party/store-id/v1" || storeIdentityEd25519Key)`
 *
 * Derived from the key alone, which is what makes it survive descriptor and
 * route rotation.
 */
export const storeId = async (
  storeIdentityEd25519Key: Uint8Array,
): Promise<Uint8Array> => {
  if (storeIdentityEd25519Key.length !== 32)
    fail("store identity key must be exactly 32 bytes");
  return sha256(
    concatBytes(domain("p2party/store-id/v1"), storeIdentityEd25519Key),
  );
};

/**
 * `DescriptorHash = H("p2party/store-descriptor/v1" ||
 *    Canonical(StoreDescriptorV1 without descriptorSignature))`
 */
export const descriptorHash = async (
  descriptor: StoreDescriptorV1,
): Promise<Uint8Array> => {
  const { descriptorSignature: _signature, ...unsigned } = descriptor;
  return sha256(
    concatBytes(
      domain("p2party/store-descriptor/v1"),
      encodeCanonical(storeDescriptorUnsignedV1Schema, unsigned),
    ),
  );
};

/**
 * `RouteId = H("p2party/store-route/v1" ||
 *    Canonical(StoreRouteV1 without routeSignature))`
 */
export const routeId = async (route: StoreRouteV1): Promise<Uint8Array> => {
  const { routeSignature: _signature, ...unsigned } = route;
  return sha256(
    concatBytes(
      domain("p2party/store-route/v1"),
      encodeCanonical(storeRouteUnsignedV1Schema, unsigned),
    ),
  );
};

/** `"p2party/store-descriptor-signature/v1" || DescriptorHash` */
export const storeDescriptorSignedMessage = async (
  descriptor: StoreDescriptorV1,
): Promise<Uint8Array> =>
  concatBytes(
    domain("p2party/store-descriptor-signature/v1"),
    await descriptorHash(descriptor),
  );

/** `"p2party/store-route-signature/v1" || RouteId` */
export const storeRouteSignedMessage = async (
  route: StoreRouteV1,
): Promise<Uint8Array> =>
  concatBytes(domain("p2party/store-route-signature/v1"), await routeId(route));

/**
 * `PublicCarrierContextId = H("p2party/public-carrier-context/v1" ||
 *    StoreId || DeliveryProfileHash)`
 *
 * This scopes cryptography and store idempotency: one wrapping, allocation and
 * scheduled-work domain per store and profile, no matter how many routes reach
 * it.
 */
export const publicCarrierContextId = async (
  storeIdBytes: Uint8Array,
  deliveryProfileHash: Uint8Array,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-carrier-context/v1"),
      storeIdBytes,
      deliveryProfileHash,
    ),
  );

/**
 * `PublicRouteInstanceId = H("p2party/public-route-instance/v1" ||
 *    PublicCarrierContextId || RouteId)`
 *
 * This scopes path health and assurance evidence. Two routes to one store are
 * two instances of one context — never two stores, and never two chances to
 * publish the same object.
 */
export const publicRouteInstanceId = async (
  carrierContextId: Uint8Array,
  routeIdBytes: Uint8Array,
): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      domain("p2party/public-route-instance/v1"),
      carrierContextId,
      routeIdBytes,
    ),
  );

/* ------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------ */

export type StoreValidity =
  { readonly valid: true } | { readonly valid: false; readonly reason: string };

const invalid = (reason: string): StoreValidity => ({ valid: false, reason });

const isSortedUnique = (values: readonly Uint8Array[]): boolean => {
  for (let index = 1; index < values.length; index++)
    if (compareBytes(values[index - 1], values[index]) >= 0) return false;
  return true;
};

/**
 * Structural and signature validation of a descriptor.
 *
 * `atUnixMs` is explicit rather than read from the clock: historical evidence
 * must be verifiable against the instant it described, and a descriptor that
 * has since expired does not retroactively invalidate a checkpoint it was valid
 * for.
 */
export const validateStoreDescriptor = async (
  descriptor: StoreDescriptorV1,
  atUnixMs: bigint,
  module?: LibCrypto,
): Promise<StoreValidity> => {
  try {
    encodeCanonical(storeDescriptorV1Schema, descriptor);
  } catch (error) {
    return invalid(
      error instanceof Error ? error.message : "descriptor is not canonical",
    );
  }

  if (descriptor.version !== 1)
    return invalid("unsupported descriptor version");
  if (descriptor.notAfterUnixMs <= descriptor.notBeforeUnixMs)
    return invalid("descriptor validity interval is empty");
  if (
    atUnixMs < descriptor.notBeforeUnixMs ||
    atUnixMs >= descriptor.notAfterUnixMs
  )
    return invalid("descriptor is not valid at this instant");

  if (descriptor.supportedDeliveryProfileHashes.length === 0)
    return invalid("descriptor supports no delivery profile");
  if (!isSortedUnique(descriptor.supportedDeliveryProfileHashes))
    return invalid("supported profiles must be sorted and duplicate-free");

  // Exactly one chain start per supported profile, in the same order. A
  // missing entry would leave a profile with no anchor; an extra one would let
  // a store claim a start for a profile it does not serve.
  if (
    descriptor.checkpointChainStarts.length !==
    descriptor.supportedDeliveryProfileHashes.length
  )
    return invalid("every supported profile needs exactly one chain start");
  for (
    let index = 0;
    index < descriptor.checkpointChainStarts.length;
    index++
  ) {
    if (
      !bytesEqual(
        descriptor.checkpointChainStarts[index].deliveryProfileHash,
        descriptor.supportedDeliveryProfileHashes[index],
      )
    )
      return invalid("chain starts must follow the supported-profile order");
  }

  const verified = await verify(
    await storeDescriptorSignedMessage(descriptor),
    descriptor.descriptorSignature,
    descriptor.storeIdentityEd25519Key,
    module,
  );
  if (!verified) return invalid("descriptor signature does not verify");
  return { valid: true };
};

/**
 * Validate a route against the descriptor it claims to belong to.
 *
 * The route's own signature is made with the store's identity key, so a route
 * lifted from another store or another descriptor generation fails here rather
 * than becoming an unauthorized path to this one.
 */
export const validateStoreRoute = async (
  route: StoreRouteV1,
  descriptor: StoreDescriptorV1,
  atUnixMs: bigint,
  module?: LibCrypto,
): Promise<StoreValidity> => {
  try {
    encodeCanonical(storeRouteV1Schema, route);
  } catch (error) {
    return invalid(
      error instanceof Error ? error.message : "route is not canonical",
    );
  }

  if (route.version !== 1) return invalid("unsupported route version");
  if (route.notAfterUnixMs <= route.notBeforeUnixMs)
    return invalid("route lease is empty");
  if (atUnixMs < route.notBeforeUnixMs || atUnixMs >= route.notAfterUnixMs)
    return invalid("route lease does not cover this instant");

  if (
    !bytesEqual(
      route.storeId,
      await storeId(descriptor.storeIdentityEd25519Key),
    )
  )
    return invalid("route names a different store");
  if (!bytesEqual(route.descriptorHash, await descriptorHash(descriptor)))
    return invalid("route names a different descriptor");

  const verified = await verify(
    await storeRouteSignedMessage(route),
    route.routeSignature,
    descriptor.storeIdentityEd25519Key,
    module,
  );
  if (!verified) return invalid("route signature does not verify");
  return { valid: true };
};

/** Whether a descriptor serves a given delivery profile. */
export const descriptorSupportsProfile = (
  descriptor: StoreDescriptorV1,
  deliveryProfileHash: Uint8Array,
): boolean =>
  descriptor.supportedDeliveryProfileHashes.some((hash) =>
    bytesEqual(hash, deliveryProfileHash),
  );

/** The immutable chain start this store declares for a profile, if any. */
export const descriptorChainStart = (
  descriptor: StoreDescriptorV1,
  deliveryProfileHash: Uint8Array,
): bigint | null => {
  const entry = descriptor.checkpointChainStarts.find((start) =>
    bytesEqual(start.deliveryProfileHash, deliveryProfileHash),
  );
  return entry?.chainStartIngressWindow ?? null;
};

/**
 * Two valid descriptors deriving one `StoreId` that name different chain
 * starts for one profile.
 *
 * This is signed equivocation about where the accountability chain begins, and
 * the specification makes it permanent for that store and profile: a higher
 * descriptor generation cannot clear it, because a clean reset requires a new
 * store identity. Canonical order is by descriptor hash, so one fault yields
 * one proof.
 */
export const chainStartConflict = async (
  first: StoreDescriptorV1,
  second: StoreDescriptorV1,
  deliveryProfileHash: Uint8Array,
): Promise<
  | { readonly conflicting: false }
  | {
      readonly conflicting: true;
      readonly canonicalOrder: readonly [StoreDescriptorV1, StoreDescriptorV1];
    }
> => {
  const [firstStore, secondStore] = await Promise.all([
    storeId(first.storeIdentityEd25519Key),
    storeId(second.storeIdentityEd25519Key),
  ]);
  if (!bytesEqual(firstStore, secondStore)) return { conflicting: false };

  if (
    !descriptorSupportsProfile(first, deliveryProfileHash) ||
    !descriptorSupportsProfile(second, deliveryProfileHash)
  )
    return { conflicting: false };

  const firstStart = descriptorChainStart(first, deliveryProfileHash);
  const secondStart = descriptorChainStart(second, deliveryProfileHash);
  if (firstStart === null || secondStart === null || firstStart === secondStart)
    return { conflicting: false };

  const [firstHash, secondHash] = await Promise.all([
    descriptorHash(first),
    descriptorHash(second),
  ]);
  return {
    conflicting: true,
    canonicalOrder:
      compareBytes(firstHash, secondHash) < 0
        ? [first, second]
        : [second, first],
  };
};
