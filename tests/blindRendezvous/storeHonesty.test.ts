/**
 * "Is this store lying to me?" — the descriptor-bound half of Section 4.3.
 *
 * `publicWindow.test.ts` covers the geometry, the RFC 9162 tree, and the
 * inclusion coordinates: everything that can be decided without knowing which
 * key to trust. This file covers what needs a store identity — the checkpoint
 * signature under the descriptor's stable key, the descriptor join, chain
 * succession, and the two equivocations. It is a separate file because it is a
 * separate fixture universe (real Ed25519 keypairs, signed descriptors, signed
 * checkpoint bodies) and a separate question, and because it is the file to
 * open when chasing AC-049's mutation vectors: same-window checkpoint
 * conflict, broken predecessor, chain-start conflict, historical descriptor
 * rotation, wrong descriptor/profile/window, and invalid signature.
 *
 * Every fixture is built with the repository's own Ed25519 and hashing
 * primitives, and every single-branch mutation below is RE-SIGNED with the
 * store's real key. A store that signs its lie must still be caught; a test
 * that merely broke the signature would prove far less.
 */

import { describe, expect, test } from "bun:test";

import { newKeyPair, sign, verify } from "../../src/cryptography/ed25519";
import {
  ZERO32,
  chainValidSuccessor,
  checkpointsConflict,
  profileFinalizedChunkCount,
  publicStoreCheckpointHash,
  publicStoreCheckpointSigningHash,
  structurallyValidCheckpoint,
  verifyStoreCheckpointChain,
} from "../../src/blindRendezvous/publicWindow";
import {
  chainStartConflict,
  descriptorChainStart,
  descriptorHash,
  descriptorSupportsProfile,
  storeDescriptorSignedMessage,
  storeId,
  validateStoreDescriptor,
} from "../../src/blindRendezvous/storeDescriptor";

import type {
  InclusionVerdict,
  ObservedStoreCheckpoint,
  PublicProfileGeometry,
  PublicStoreCheckpointBodyV1,
  PublicStoreCheckpointV1,
} from "../../src/blindRendezvous/publicWindow";
import type { StoreDescriptorV1 } from "../../src/blindRendezvous/storeDescriptor";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytes = (fill: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(fill);

/** The reason a verdict gives, or a loud failure if it was not a rejection. */
const rejection = (verdict: InclusionVerdict): string => {
  if (verdict.valid)
    throw new Error("expected a rejection, got a valid verdict");
  return verdict.reason;
};

const geometry: PublicProfileGeometry = {
  publicChunkObjectCount: 4,
  cohortAllocationsPerWindow: 6,
  roomSlotsPerClient: 2,
  sizeClasses: [
    { id: 0, appendScheduleLength: 3, publicChunksPerWindow: 9 },
    { id: 1, appendScheduleLength: 1, publicChunksPerWindow: 3 },
  ],
};
const FIXED_CHUNK_COUNT = profileFinalizedChunkCount(geometry);

const NOW = 1_700_000_000_000n;
const NOT_BEFORE = NOW - 1_000n;
const NOT_AFTER = NOW + 1_000_000n;

const PROFILE = bytes(0x11);
const UNSUPPORTED_PROFILE = bytes(0xee);
const CHAIN_START = 100n;

const store = await newKeyPair();
const otherStore = await newKeyPair();

const STORE_ID = await storeId(store.publicKey);

type UnsignedDescriptor = Omit<StoreDescriptorV1, "descriptorSignature">;

const descriptorFields: UnsignedDescriptor = {
  version: 1,
  storeIdentityEd25519Key: store.publicKey,
  allocationIssuerPublicKeyDer: Uint8Array.of(0x30, 0x82, 0x01, 0x22),
  descriptorGeneration: 7n,
  compatibilityHash: bytes(0x33),
  supportedDeliveryProfileHashes: [PROFILE],
  checkpointChainStarts: [
    { deliveryProfileHash: PROFILE, chainStartIngressWindow: CHAIN_START },
  ],
  notBeforeUnixMs: NOT_BEFORE,
  notAfterUnixMs: NOT_AFTER,
};

const signDescriptor = async (
  fields: UnsignedDescriptor,
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

const descriptor = await signDescriptor(descriptorFields);
const DESCRIPTOR_HASH = await descriptorHash(descriptor);

const body = (
  overrides: Partial<PublicStoreCheckpointBodyV1> = {},
): PublicStoreCheckpointBodyV1 => ({
  version: 1,
  storeId: STORE_ID,
  descriptorHash: DESCRIPTOR_HASH,
  deliveryProfileHash: PROFILE,
  ingressWindow: CHAIN_START,
  chainStartIngressWindow: CHAIN_START,
  previousCheckpointHash: ZERO32,
  finalizedChunkCount: FIXED_CHUNK_COUNT,
  finalizedChunkRoot: bytes(0x77),
  ...overrides,
});

const signCheckpoint = async (
  fields: PublicStoreCheckpointBodyV1,
  signer = store,
): Promise<PublicStoreCheckpointV1> => ({
  ...fields,
  storeSignature: await sign(
    await publicStoreCheckpointSigningHash(fields),
    signer.secretKey,
  ),
});

/** The chain start: window 100, zero predecessor, honestly signed. */
const head = await signCheckpoint(body());

/** Its successor: window 101, naming the exact hash of the checkpoint above. */
const successor = await signCheckpoint(
  body({
    ingressWindow: CHAIN_START + 1n,
    previousCheckpointHash: await publicStoreCheckpointHash(head),
    finalizedChunkRoot: bytes(0x78),
  }),
);

/** And its successor in turn: window 102, so a run of three exists. */
const third = await signCheckpoint(
  body({
    ingressWindow: CHAIN_START + 2n,
    previousCheckpointHash: await publicStoreCheckpointHash(successor),
    finalizedChunkRoot: bytes(0x79),
  }),
);

describe("a well-formed checkpoint is accepted", () => {
  test("the chain start verifies under its own descriptor", async () => {
    const verdict = await structurallyValidCheckpoint(
      descriptor,
      head,
      geometry,
      NOW,
    );
    expect(verdict.valid).toBe(true);
  });

  test("a later window with a non-zero predecessor verifies too", async () => {
    const verdict = await structurallyValidCheckpoint(
      descriptor,
      successor,
      geometry,
      NOW,
    );
    expect(verdict.valid).toBe(true);
  });

  test("acceptance does not depend on the wall clock, only on the finalization instant", async () => {
    // The descriptor must have been valid WHEN the window was finalized, not
    // now: a store must not escape old evidence by letting a descriptor lapse.
    expect(
      (
        await structurallyValidCheckpoint(
          descriptor,
          head,
          geometry,
          NOT_BEFORE,
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await structurallyValidCheckpoint(
          descriptor,
          head,
          geometry,
          NOT_AFTER - 1n,
        )
      ).valid,
    ).toBe(true);
  });
});

describe("every rejection branch of structurallyValidCheckpoint", () => {
  test("descriptor outside its lease at the finalization instant", async () => {
    // A store presenting a window it finalized after its own descriptor
    // expired, so that lapsed authority looks like live authority.
    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          head,
          geometry,
          NOT_AFTER,
        ),
      ),
    ).toBe("descriptor is not valid at this instant");
    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          head,
          geometry,
          NOT_BEFORE - 1n,
        ),
      ),
    ).toBe("descriptor is not valid at this instant");
  });

  test("descriptor signed by a key that is not the store's", async () => {
    // A store (or anyone) fabricating a descriptor for an identity key it does
    // not hold, to bind checkpoints to someone else's StoreId.
    const forged = await signDescriptor(descriptorFields, otherStore);
    expect(
      rejection(await structurallyValidCheckpoint(forged, head, geometry, NOW)),
    ).toBe("descriptor signature does not verify");
  });

  test("checkpoint names a different descriptor", async () => {
    // Descriptor substitution: pairing a signed checkpoint with a descriptor it
    // was not issued under, so a reader checks the wrong terms.
    const mismatched = await signCheckpoint(
      body({ descriptorHash: bytes(0x44) }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          mismatched,
          geometry,
          NOW,
        ),
      ),
    ).toBe("checkpoint does not name this descriptor");
  });

  test("checkpoint names a different store", async () => {
    // Attributing a window to another store's StoreId — laundering one store's
    // custody record through another store's identity.
    const mismatched = await signCheckpoint(
      body({ storeId: await storeId(otherStore.publicKey) }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          mismatched,
          geometry,
          NOW,
        ),
      ),
    ).toBe("checkpoint does not name this descriptor's store");
  });

  test("descriptor does not support the checkpoint's delivery profile", async () => {
    // Signing checkpoints for a profile the descriptor never committed to
    // serve, claiming custody in a cohort the store is not accountable for.
    const foreign = await signCheckpoint(
      body({ deliveryProfileHash: UNSUPPORTED_PROFILE }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, foreign, geometry, NOW),
      ),
    ).toBe("descriptor does not support this delivery profile");
  });

  test("checkpoint names a different chain start than the descriptor", async () => {
    // Moving the anchor: if the store can restate where its accountability
    // chain begins, an omitted stretch of history stops being missing.
    const moved = await signCheckpoint(
      body({ chainStartIngressWindow: CHAIN_START - 1n }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, moved, geometry, NOW),
      ),
    ).toBe("checkpoint names a different chain start than the descriptor");
  });

  test("checkpoint precedes the declared chain start", async () => {
    // Backdating a window before the anchor, to smuggle in pre-history that no
    // descriptor ever covered.
    const backdated = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START - 1n,
        previousCheckpointHash: bytes(0x55),
      }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, backdated, geometry, NOW),
      ),
    ).toBe("checkpoint precedes the declared chain start");
  });

  test("checkpoint count is not the profile-fixed chunk count", async () => {
    // Committing to fewer chunks than the profile fixes: a window with a chunk
    // quietly left out of the tree, so nothing proves it was ever missing.
    const short = await signCheckpoint(
      body({ finalizedChunkCount: FIXED_CHUNK_COUNT - 1 }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, short, geometry, NOW),
      ),
    ).toBe("checkpoint count is not the profile-fixed chunk count");
  });

  test("the chain start carries a non-zero predecessor hash", async () => {
    // Claiming a predecessor at the very first window, i.e. history before the
    // declared beginning of history.
    const rooted = await signCheckpoint(
      body({ previousCheckpointHash: bytes(0x66) }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, rooted, geometry, NOW),
      ),
    ).toBe("chain start must have a zero predecessor hash");
  });

  test("a later window carries a zero predecessor hash", async () => {
    // Silently restarting the chain mid-stream, which orphans every window
    // before it and makes the gap unprovable.
    const restarted = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 5n,
        previousCheckpointHash: ZERO32,
      }),
    );
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, restarted, geometry, NOW),
      ),
    ).toBe("only the chain start may have a zero predecessor hash");
  });

  test("the signature is not a signature at all", async () => {
    // An unsigned checkpoint dressed as a signed one — the cheapest forgery.
    const unsigned: PublicStoreCheckpointV1 = {
      ...body(),
      storeSignature: new Uint8Array(64),
    };
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, unsigned, geometry, NOW),
      ),
    ).toBe("checkpoint signature does not verify");
  });

  test("the body was edited after the store signed it", async () => {
    // Rewriting what a finalized window committed to while keeping the store's
    // real signature attached to it.
    const edited: PublicStoreCheckpointV1 = {
      ...head,
      finalizedChunkRoot: bytes(0x99),
    };
    expect(
      rejection(
        await structurallyValidCheckpoint(descriptor, edited, geometry, NOW),
      ),
    ).toBe("checkpoint signature does not verify");
  });

  test("a real signature that verifies under the wrong key is still rejected", async () => {
    // A second store signing this store's window: the bytes ARE a valid
    // Ed25519 signature, just not under the descriptor's stable store key.
    const fields = body();
    const misattributed = await signCheckpoint(fields, otherStore);

    const signingHash = await publicStoreCheckpointSigningHash(fields);
    expect(
      await verify(
        signingHash,
        misattributed.storeSignature,
        otherStore.publicKey,
      ),
    ).toBe(true);
    expect(
      await verify(signingHash, misattributed.storeSignature, store.publicKey),
    ).toBe(false);

    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          misattributed,
          geometry,
          NOW,
        ),
      ),
    ).toBe("checkpoint signature does not verify");
  });

  test("the missing-chain-start branch is unreachable behind a valid descriptor", async () => {
    // The twelfth branch, "descriptor declares no chain start for this
    // profile", cannot be driven with a valid descriptor and is kept as
    // defence in depth: descriptor validation already requires exactly one
    // chain start per supported profile, in the same bytewise order, so
    // support implies a start. Both halves of that are asserted here.
    expect((await validateStoreDescriptor(descriptor, NOW)).valid).toBe(true);
    for (const profile of descriptor.supportedDeliveryProfileHashes) {
      expect(descriptorSupportsProfile(descriptor, profile)).toBe(true);
      expect(descriptorChainStart(descriptor, profile)).not.toBeNull();
    }

    // A descriptor that omits the start is rejected at the descriptor gate,
    // before the checkpoint join is ever consulted.
    const startless = await signDescriptor({
      ...descriptorFields,
      checkpointChainStarts: [],
    });
    expect(
      rejection(
        await structurallyValidCheckpoint(startless, head, geometry, NOW),
      ),
    ).toBe("every supported profile needs exactly one chain start");
  });
});

describe("chain succession", () => {
  test("a valid successor is accepted", async () => {
    const verdict = await chainValidSuccessor(
      head,
      descriptor,
      NOW,
      successor,
      descriptor,
      NOW,
      geometry,
    );
    expect(verdict.valid).toBe(true);
  });

  test("a successor that rewrites history is rejected", async () => {
    // The store finalized window 100 twice and then continued from the branch
    // it prefers. Both checkpoints are individually well-formed and signed;
    // what betrays the rewrite is that the successor names the fork's hash,
    // not the predecessor actually held.
    const fork = await signCheckpoint(
      body({ finalizedChunkRoot: bytes(0x7f) }),
    );
    expect(
      (await structurallyValidCheckpoint(descriptor, fork, geometry, NOW))
        .valid,
    ).toBe(true);

    const continued = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 1n,
        previousCheckpointHash: await publicStoreCheckpointHash(fork),
        finalizedChunkRoot: bytes(0x80),
      }),
    );
    expect(
      (await structurallyValidCheckpoint(descriptor, continued, geometry, NOW))
        .valid,
    ).toBe(true);

    expect(
      rejection(
        await chainValidSuccessor(
          head,
          descriptor,
          NOW,
          continued,
          descriptor,
          NOW,
          geometry,
        ),
      ),
    ).toBe("successor does not link to this exact predecessor");

    // ...and it does link to the branch the store preferred, which is what
    // makes this evidence of a fork rather than of a corrupt object.
    expect(
      (
        await chainValidSuccessor(
          fork,
          descriptor,
          NOW,
          continued,
          descriptor,
          NOW,
          geometry,
        )
      ).valid,
    ).toBe(true);
  });

  test("a skipped window is not a successor", async () => {
    // Omitting a window entirely: adjacency is required, so the gap cannot be
    // closed by presenting the two survivors as neighbours.
    const skipped = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 2n,
        previousCheckpointHash: await publicStoreCheckpointHash(head),
      }),
    );
    expect(
      rejection(
        await chainValidSuccessor(
          head,
          descriptor,
          NOW,
          skipped,
          descriptor,
          NOW,
          geometry,
        ),
      ),
    ).toBe("successor does not link to this exact predecessor");
  });

  test("an invalid predecessor and an invalid successor are named separately", async () => {
    const unsignedHead: PublicStoreCheckpointV1 = {
      ...head,
      storeSignature: new Uint8Array(64),
    };
    expect(
      rejection(
        await chainValidSuccessor(
          unsignedHead,
          descriptor,
          NOW,
          successor,
          descriptor,
          NOW,
          geometry,
        ),
      ),
    ).toBe("predecessor: checkpoint signature does not verify");

    const unsignedNext: PublicStoreCheckpointV1 = {
      ...successor,
      storeSignature: new Uint8Array(64),
    };
    expect(
      rejection(
        await chainValidSuccessor(
          head,
          descriptor,
          NOW,
          unsignedNext,
          descriptor,
          NOW,
          geometry,
        ),
      ),
    ).toBe("successor: checkpoint signature does not verify");
  });

  test("succession survives an honest descriptor rotation", async () => {
    // A new descriptor generation keeps the StoreId and the chain start, so
    // history stays verifiable across the rotation. Each checkpoint is joined
    // to the descriptor it was actually finalized under.
    const rotated = await signDescriptor({
      ...descriptorFields,
      descriptorGeneration: 8n,
      compatibilityHash: bytes(0x34),
    });
    expect(hex(await storeId(rotated.storeIdentityEd25519Key))).toBe(
      hex(STORE_ID),
    );
    expect(hex(await descriptorHash(rotated))).not.toBe(hex(DESCRIPTOR_HASH));

    const afterRotation = await signCheckpoint(
      body({
        descriptorHash: await descriptorHash(rotated),
        ingressWindow: CHAIN_START + 1n,
        previousCheckpointHash: await publicStoreCheckpointHash(head),
        finalizedChunkRoot: bytes(0x81),
      }),
    );
    expect(
      (
        await chainValidSuccessor(
          head,
          descriptor,
          NOW,
          afterRotation,
          rotated,
          NOW,
          geometry,
        )
      ).valid,
    ).toBe(true);

    // The rotation is not a licence to mix: the old descriptor no longer joins
    // the new checkpoint.
    expect(
      rejection(
        await chainValidSuccessor(
          head,
          descriptor,
          NOW,
          afterRotation,
          descriptor,
          NOW,
          geometry,
        ),
      ),
    ).toBe("successor: checkpoint does not name this descriptor");
  });
});

describe("equivocation", () => {
  test("same-window equivocation: two signed checkpoints for one window", async () => {
    // The store signed two different bodies for one (store, profile, window).
    // The proof needs both halves to be structurally valid — otherwise it is
    // junk, not evidence — so both are asserted before the conflict is taken.
    const other = await signCheckpoint(
      body({ finalizedChunkRoot: bytes(0x88) }),
    );
    expect(
      (await structurallyValidCheckpoint(descriptor, head, geometry, NOW))
        .valid,
    ).toBe(true);
    expect(
      (await structurallyValidCheckpoint(descriptor, other, geometry, NOW))
        .valid,
    ).toBe(true);

    const conflict = await checkpointsConflict(head, other);
    expect(conflict.conflicting).toBe(true);
    if (!conflict.conflicting) throw new Error("unreachable");

    const [low, high] = await Promise.all([
      publicStoreCheckpointHash(conflict.canonicalOrder[0]),
      publicStoreCheckpointHash(conflict.canonicalOrder[1]),
    ]);
    expect(hex(low) < hex(high)).toBe(true);

    // Neither branch is preferred: presenting the pair the other way round
    // yields the identical proof rather than a mirror image.
    const reversed = await checkpointsConflict(other, head);
    if (!reversed.conflicting) throw new Error("unreachable");
    expect(
      hex(await publicStoreCheckpointHash(reversed.canonicalOrder[0])),
    ).toBe(hex(low));
  });

  test("chain-start equivocation: two signed descriptors, one StoreId, two starts", async () => {
    // The permanent fault. The store signed two descriptors that derive the
    // same StoreId and support the same profile but disagree about where its
    // accountability begins; a later generation cannot clear it, because a
    // clean reset requires a new store identity.
    const moved = await signDescriptor({
      ...descriptorFields,
      descriptorGeneration: 9n,
      checkpointChainStarts: [
        {
          deliveryProfileHash: PROFILE,
          chainStartIngressWindow: CHAIN_START + 50n,
        },
      ],
    });

    const conflict = await chainStartConflict(descriptor, moved, PROFILE);
    expect(conflict.conflicting).toBe(true);
    if (!conflict.conflicting) throw new Error("unreachable");
    const [first, second] = await Promise.all([
      descriptorHash(conflict.canonicalOrder[0]),
      descriptorHash(conflict.canonicalOrder[1]),
    ]);
    expect(hex(first) < hex(second)).toBe(true);

    // What makes it signed equivocation rather than a stale copy: the store
    // finalized a real window under each of the two starts.
    const underMovedStart = await signCheckpoint(
      body({
        descriptorHash: await descriptorHash(moved),
        ingressWindow: CHAIN_START + 50n,
        chainStartIngressWindow: CHAIN_START + 50n,
      }),
    );
    expect(
      (await structurallyValidCheckpoint(descriptor, head, geometry, NOW))
        .valid,
    ).toBe(true);
    expect(
      (await structurallyValidCheckpoint(moved, underMovedStart, geometry, NOW))
        .valid,
    ).toBe(true);

    // Each checkpoint is only valid under its own descriptor; the cross joins
    // both fail, which is why one honest read cannot reveal the fault alone.
    expect(
      rejection(await structurallyValidCheckpoint(moved, head, geometry, NOW)),
    ).toBe("checkpoint does not name this descriptor");
    expect(
      rejection(
        await structurallyValidCheckpoint(
          descriptor,
          underMovedStart,
          geometry,
          NOW,
        ),
      ),
    ).toBe("checkpoint does not name this descriptor");
  });
});

describe("verifyStoreCheckpointChain over an observed run", () => {
  const observed = (
    checkpoint: PublicStoreCheckpointV1,
    storeDescriptor: StoreDescriptorV1 = descriptor,
    finalizationInstantUnixMs: bigint = NOW,
  ): ObservedStoreCheckpoint => ({
    checkpoint,
    descriptor: storeDescriptor,
    finalizationInstantUnixMs,
  });

  test("a continuous run from the chain start verifies", async () => {
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(successor), observed(third)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-verified");
    if (verdict.outcome !== "chain-verified") throw new Error("unreachable");
    expect(verdict.startsAtChainStart).toBe(true);
    expect(verdict.chainStartIngressWindow).toBe(CHAIN_START);
    expect(verdict.firstIngressWindow).toBe(CHAIN_START);
    expect(verdict.headIngressWindow).toBe(CHAIN_START + 2n);
    expect(hex(verdict.headCheckpointHash)).toBe(
      hex(await publicStoreCheckpointHash(third)),
    );
    expect(hex(verdict.storeId)).toBe(hex(STORE_ID));
    expect(hex(verdict.deliveryProfileHash)).toBe(hex(PROFILE));
  });

  test("a run of one checkpoint verifies, and a run that starts later says so", async () => {
    const single = await verifyStoreCheckpointChain([observed(head)], geometry);
    expect(single.outcome).toBe("chain-verified");

    // Positive continuity may start at a pinned head rather than at the chain
    // start; the verdict must not pretend the earlier windows were checked.
    const later = await verifyStoreCheckpointChain(
      [observed(successor), observed(third)],
      geometry,
    );
    expect(later.outcome).toBe("chain-verified");
    if (later.outcome !== "chain-verified") throw new Error("unreachable");
    expect(later.startsAtChainStart).toBe(false);
    expect(later.firstIngressWindow).toBe(CHAIN_START + 1n);
  });

  test("a structurally invalid member is named by index", async () => {
    const unsigned: PublicStoreCheckpointV1 = {
      ...successor,
      storeSignature: new Uint8Array(64),
    };
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(unsigned), observed(third)],
      geometry,
    );
    expect(verdict.outcome).toBe("structurally-invalid-checkpoint");
    if (verdict.outcome !== "structurally-invalid-checkpoint")
      throw new Error("unreachable");
    expect(verdict.index).toBe(1);
    expect(verdict.reason).toBe("checkpoint signature does not verify");
  });

  test("same-window equivocation inside a run is returned as a conflict", async () => {
    const twin = await signCheckpoint(
      body({ finalizedChunkRoot: bytes(0x88) }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(twin)],
      geometry,
    );
    expect(verdict.outcome).toBe("checkpoint-conflict");
    if (verdict.outcome !== "checkpoint-conflict")
      throw new Error("unreachable");
    const [low, high] = await Promise.all([
      publicStoreCheckpointHash(verdict.canonicalOrder[0]),
      publicStoreCheckpointHash(verdict.canonicalOrder[1]),
    ]);
    expect(hex(low) < hex(high)).toBe(true);
  });

  test("two identical checkpoints for one window are a duplicate, not a conflict", async () => {
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed({ ...head }), observed(successor)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-verified");
  });

  test("a broken predecessor inside a run is returned as a chain breach", async () => {
    const fork = await signCheckpoint(
      body({ finalizedChunkRoot: bytes(0x7f) }),
    );
    const continued = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 1n,
        previousCheckpointHash: await publicStoreCheckpointHash(fork),
        finalizedChunkRoot: bytes(0x80),
      }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(continued)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-breach");
    if (verdict.outcome !== "chain-breach") throw new Error("unreachable");
    expect(verdict.previous.ingressWindow).toBe(CHAIN_START);
    expect(verdict.next.ingressWindow).toBe(CHAIN_START + 1n);
  });

  test("a missing window is an unverified gap, not blame", async () => {
    // The specification is explicit that a missing adjacent checkpoint cannot
    // instantiate a breach proof: the client simply has not seen enough. This
    // is the one negative verdict that must never read as a fault.
    const orphan = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 2n,
        previousCheckpointHash: bytes(0x5a),
      }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(orphan)],
      geometry,
    );
    expect(verdict.outcome).toBe("unverified-chain-gap");
    if (verdict.outcome !== "unverified-chain-gap")
      throw new Error("unreachable");
    expect(verdict.afterIngressWindow).toBe(CHAIN_START);
    expect(verdict.beforeIngressWindow).toBe(CHAIN_START + 2n);
  });

  test("blame outranks a gap: a conflict later in the run still surfaces", async () => {
    // A store must not be able to bury an equivocation behind an earlier hole
    // in what the client happened to retain.
    const farA = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 4n,
        previousCheckpointHash: bytes(0x5a),
        finalizedChunkRoot: bytes(0x91),
      }),
    );
    const farB = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 4n,
        previousCheckpointHash: bytes(0x5a),
        finalizedChunkRoot: bytes(0x92),
      }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(farA), observed(farB)],
      geometry,
    );
    expect(verdict.outcome).toBe("checkpoint-conflict");
  });

  test("blame outranks a gap: a broken link adjacent to a hole still surfaces", async () => {
    // The same rule as above, but for the one pairing that distinguishes the
    // two passes: a store hiding a BROKEN LINK behind an earlier retention
    // hole. The run skips 101-103, so 100 -> 104 is a blameless gap, while
    // 104 -> 105 is adjacent and misnamed, which is blame. Reporting the gap
    // here would let the store answer a breach with "you did not keep enough".
    // The same-window conflict above cannot bind this, because a conflict is
    // decided in an earlier pass and would surface under either ordering.
    const afterHole = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 4n,
        previousCheckpointHash: bytes(0x5a),
        finalizedChunkRoot: bytes(0x93),
      }),
    );
    const misnamedPredecessor = await signCheckpoint(
      body({
        ingressWindow: CHAIN_START + 5n,
        previousCheckpointHash: bytes(0x5b),
        finalizedChunkRoot: bytes(0x94),
      }),
    );
    // The link really is broken: 105 does not name the hash of 104.
    expect(hex(misnamedPredecessor.previousCheckpointHash)).not.toBe(
      hex(await publicStoreCheckpointHash(afterHole)),
    );

    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(afterHole), observed(misnamedPredecessor)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-breach");
    if (verdict.outcome !== "chain-breach") throw new Error("unreachable");
    expect(verdict.previous.ingressWindow).toBe(CHAIN_START + 4n);
    expect(verdict.next.ingressWindow).toBe(CHAIN_START + 5n);
  });

  test("a chain-verified verdict owns the bytes it reports", async () => {
    // A verdict is what a client retains after the store's reply is gone. If
    // it aliased the arrays that reply was decoded into, reusing that buffer
    // would silently rewrite what the client believes it verified. The
    // conflict and breach verdicts deliberately still carry the caller's own
    // checkpoint objects, because those are the exact halves a proof is built
    // from; that asymmetry is documented on the function.
    const borrowed = await signCheckpoint(
      body({
        storeId: Uint8Array.from(STORE_ID),
        deliveryProfileHash: Uint8Array.from(PROFILE),
      }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(borrowed)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-verified");
    if (verdict.outcome !== "chain-verified") throw new Error("unreachable");

    borrowed.storeId.fill(0);
    borrowed.deliveryProfileHash.fill(0);
    expect(hex(verdict.storeId)).toBe(hex(STORE_ID));
    expect(hex(verdict.deliveryProfileHash)).toBe(hex(PROFILE));
  });

  test("chain-start equivocation across a run is returned as the permanent fault", async () => {
    const moved = await signDescriptor({
      ...descriptorFields,
      descriptorGeneration: 9n,
      checkpointChainStarts: [
        {
          deliveryProfileHash: PROFILE,
          chainStartIngressWindow: CHAIN_START + 50n,
        },
      ],
    });
    const underMovedStart = await signCheckpoint(
      body({
        descriptorHash: await descriptorHash(moved),
        ingressWindow: CHAIN_START + 50n,
        chainStartIngressWindow: CHAIN_START + 50n,
      }),
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(underMovedStart, moved)],
      geometry,
    );
    expect(verdict.outcome).toBe("chain-start-conflict");
    if (verdict.outcome !== "chain-start-conflict")
      throw new Error("unreachable");
    const [first, second] = await Promise.all([
      descriptorHash(verdict.canonicalOrder[0]),
      descriptorHash(verdict.canonicalOrder[1]),
    ]);
    expect(hex(first) < hex(second)).toBe(true);
  });

  test("two stores are not one chain", async () => {
    const foreignDescriptor = await signDescriptor(
      { ...descriptorFields, storeIdentityEd25519Key: otherStore.publicKey },
      otherStore,
    );
    const foreign = await signCheckpoint(
      body({
        storeId: await storeId(otherStore.publicKey),
        descriptorHash: await descriptorHash(foreignDescriptor),
        ingressWindow: CHAIN_START + 1n,
        previousCheckpointHash: bytes(0x5a),
      }),
      otherStore,
    );
    const verdict = await verifyStoreCheckpointChain(
      [observed(head), observed(foreign, foreignDescriptor)],
      geometry,
    );
    expect(verdict.outcome).toBe("not-one-store-profile-chain");
    if (verdict.outcome !== "not-one-store-profile-chain")
      throw new Error("unreachable");
    expect(verdict.index).toBe(1);
  });

  test("an empty or misordered observation is a caller error, not a verdict", async () => {
    // Ordering the run is the client's own job; a store cannot cause this, so
    // silently "detecting" it would hide a bug rather than a fault.
    await expect(verifyStoreCheckpointChain([], geometry)).rejects.toThrow(
      "nonempty",
    );
    await expect(
      verifyStoreCheckpointChain(
        [observed(successor), observed(head)],
        geometry,
      ),
    ).rejects.toThrow("ordered by ingress window");
  });
});

/**
 * These assert what the code does today so that the gap is on the record and
 * cannot be mistaken for a guarantee. They are not statements that the
 * behaviour is right.
 */
describe("what these checks do not decide", () => {
  const observe = (
    checkpoint: PublicStoreCheckpointV1,
  ): ObservedStoreCheckpoint => ({
    checkpoint,
    descriptor,
    finalizationInstantUnixMs: NOW,
  });

  test("the root half of the profile-fixed count/root condition is not decided here", async () => {
    // Section 4.3 requires "the profile-fixed count/root checks pass". Only
    // the count half is enforced here (driven above); the root half is not,
    // because recomputing finalizedChunkRoot needs the window's chunk hashes
    // and this function is never handed them. That work lives in
    // verifyCheckpointChunkInclusion, and nothing composes the two, so no
    // single call asserts both. A store signing an invented root is therefore
    // structurally valid to this predicate, and to the chain entry point.
    const inventedRoot = await signCheckpoint(
      body({ finalizedChunkRoot: bytes(0xab) }),
    );
    expect(
      (
        await structurallyValidCheckpoint(
          descriptor,
          inventedRoot,
          geometry,
          NOW,
        )
      ).valid,
    ).toBe(true);
    expect(
      (await verifyStoreCheckpointChain([observe(inventedRoot)], geometry))
        .outcome,
    ).toBe("chain-verified");
  });

  test("a checkpoint's version byte is not checked, though a descriptor's is", async () => {
    // The specification's condition list for StructurallyValidCheckpoint does
    // not name a version check; StoreDescriptorAuthentic does name one
    // ("descriptor.version == 1"), and validateStoreDescriptor implements it.
    // Each function follows its own list, so a store can sign a checkpoint
    // body whose version byte is not 1 and have it accepted, including through
    // the chain entry point that a future store client would call on
    // store-supplied bytes. Whether the version byte belongs to structural
    // validity is a question for the specification, not something to decide by
    // changing the predicate under a test; see the TODO in publicWindow.ts.
    const unknownVersion = await signCheckpoint({
      ...body(),
      version: 2,
    } as unknown as PublicStoreCheckpointBodyV1);
    expect(
      (
        await structurallyValidCheckpoint(
          descriptor,
          unknownVersion,
          geometry,
          NOW,
        )
      ).valid,
    ).toBe(true);
    expect(
      (await verifyStoreCheckpointChain([observe(unknownVersion)], geometry))
        .outcome,
    ).toBe("chain-verified");

    const unknownDescriptorVersion = await signDescriptor({
      ...descriptorFields,
      version: 2,
    } as unknown as UnsignedDescriptor);
    expect(
      rejection(
        await structurallyValidCheckpoint(
          unknownDescriptorVersion,
          head,
          geometry,
          NOW,
        ),
      ),
    ).toBe("unsupported descriptor version");
  });
});
