import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import libcrypto from "../../../src/cryptography/libcrypto";
import { newKeyPair, sign, verify } from "../../../src/cryptography/ed25519";
import {
  allocationAppendSignedMessage,
  allocationTokenIssueRequestHash,
  allocationTokenIssueResultSignedMessage,
  deliveryProfileHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
} from "../../../src/blindRendezvous/derivations";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  carrierObjectWireBytes,
  profileGeometry,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import {
  PrototypeStoreCore,
  StoreConfigurationError,
  StoreRequestError,
} from "../../../src/blindRendezvous/prototype/store/storeCore";
import {
  MemoryStorePersistence,
  emptyStoreWindowState,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";
import {
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationResultV1,
  encodePublicStoreCheckpointReadV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import {
  appendSlotCoordinates,
  chainValidSuccessor,
  checkpointLeafEntries,
  ingressWindowStartMs,
  publicChunkHash,
  rfc9162MerkleTreeHash,
  structurallyValidCheckpoint,
} from "../../../src/blindRendezvous/publicWindow";

import type {
  PublicAllocationLeaseV1,
  PublicAllocationRequestV1,
  PublicAppendRequestV1,
  PublicAppendResultV1,
  StoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import type {
  PublicBucketV1,
  PublicStoreCheckpointV1,
} from "../../../src/blindRendezvous/publicWindow";
import type { LibCrypto } from "../../../src/cryptography/libcrypto";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fileBytes = readFileSync(
  new URL("../../../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
new Uint8Array(wasmBinary).set(fileBytes);

const PAGES = 1024;
const cryptoModule = (await libcrypto({
  wasmBinary,
  wasmMemory: new WebAssembly.Memory({ initial: PAGES, maximum: PAGES }),
})) as unknown as LibCrypto;

const profile = withDeliveryWindowMs(PROTOTYPE_DELIVERY_PROFILE_V0, 4_000n);
const geometry = profileGeometry(profile);
const PROFILE_HASH = await deliveryProfileHash(profile);
const OTHER_PROFILE_HASH = new Uint8Array(32).fill(0xab);

/** 1_700_000_000_000 / 4_000 is exact, so the chain starts on a window edge. */
const CHAIN_START = 425_000_000n;
const WINDOW_START = ingressWindowStartMs(
  CHAIN_START,
  profile.deliveryWindowMs,
);
const FINALIZE_AT = WINDOW_START + profile.chunkFinalizationOffsetMs;
const NEXT_FINALIZE_AT = FINALIZE_AT + profile.deliveryWindowMs;

const SEED = new Uint8Array(32).fill(0x5a);

const CLASS_0_OBJECT_BYTES = carrierObjectWireBytes(profile, 0, PROFILE_HASH);

interface Harness {
  readonly core: PrototypeStoreCore;
  readonly persistence: MemoryStorePersistence;
  readonly setNow: (ms: bigint) => void;
}

const harness = async (
  options: {
    fault?: "withhold" | null;
    persistence?: MemoryStorePersistence;
    now?: bigint;
    chainStart?: bigint;
    seed?: Uint8Array;
  } = {},
): Promise<Harness> => {
  let now = options.now ?? WINDOW_START;
  const persistence = options.persistence ?? new MemoryStorePersistence();
  const core = await PrototypeStoreCore.create({
    module: cryptoModule,
    seed: options.seed ?? SEED,
    profile,
    clock: { nowMs: () => now },
    persistence,
    chainStartIngressWindow: options.chainStart ?? CHAIN_START,
    origin: "http://127.0.0.1:5910",
    descriptorValidityMs: 2_592_000_000n,
    fault: options.fault ?? null,
  });
  return {
    core,
    persistence,
    setNow: (ms: bigint) => {
      now = ms;
    },
  };
};

const allocationRequest = (
  allocationEd25519PublicKey: Uint8Array,
  ingressWindow = CHAIN_START,
  deliveryProfile = PROFILE_HASH,
): PublicAllocationRequestV1 => ({
  version: 1,
  deliveryProfileHash: deliveryProfile,
  ingressWindow,
  allocationEd25519PublicKey,
  privacyPassToken: new Uint8Array(32),
});

/** One lease for the store under test, plus the key that must sign appends. */
const leaseFor = async (
  core: PrototypeStoreCore,
  ingressWindow = CHAIN_START,
): Promise<{
  lease: PublicAllocationLeaseV1;
  secretKey: Uint8Array;
}> => {
  const keyPair = await newKeyPair(cryptoModule);
  const result = await core.allocate(
    allocationRequest(keyPair.publicKey, ingressWindow),
  );
  if (result.kind !== "allocated")
    throw new Error(`expected a lease, got ${result.value.status}`);
  return { lease: result.lease, secretKey: keyPair.secretKey };
};

const objectOf = (fill: number, length = CLASS_0_OBJECT_BYTES): Uint8Array =>
  new Uint8Array(length).fill(fill);

const appendRequest = async (
  lease: PublicAllocationLeaseV1,
  secretKey: Uint8Array,
  objectOrdinalWithinAllocation: number,
  exactFixedObject: Uint8Array,
  sizeClass = 0,
): Promise<PublicAppendRequestV1> => {
  const { storeSignature: _storeSignature, ...leaseBody } = lease;
  return {
    version: 1,
    bucket: {
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: lease.ingressWindow,
      sizeClass,
    },
    exactFixedObject,
    admission: {
      version: 1,
      lease,
      objectOrdinalWithinAllocation,
      allocationSignature: await sign(
        await allocationAppendSignedMessage(
          leaseBody,
          sizeClass,
          objectOrdinalWithinAllocation,
          exactFixedObject,
        ),
        secretKey,
        cryptoModule,
      ),
    },
  };
};

const coverRequest = (
  exactFixedObject: Uint8Array,
  ingressWindow = CHAIN_START,
  sizeClass = 0,
): PublicAppendRequestV1 => ({
  version: 1,
  bucket: { deliveryProfileHash: PROFILE_HASH, ingressWindow, sizeClass },
  exactFixedObject,
  admission: null,
});

/** Every append result is signed; no test may read a status it did not check. */
const verifiedStatus = async (
  core: PrototypeStoreCore,
  result: PublicAppendResultV1,
): Promise<PublicAppendResultV1["status"]> => {
  const { storeSignature, ...body } = result;
  const verified = await verify(
    await publicAppendResultSignedMessage(body),
    storeSignature,
    core.descriptor.storeIdentityEd25519Key,
    cryptoModule,
  );
  if (!verified) throw new Error("append result signature does not verify");
  return result.status;
};

const finalizedCheckpoint = async (
  core: PrototypeStoreCore,
  window: bigint,
): Promise<PublicStoreCheckpointV1> => {
  const read = await core.readCheckpoint(PROFILE_HASH, window);
  if (read.kind !== "finalized")
    throw new Error(
      `expected a finalized checkpoint, got ${read.value.status}`,
    );
  return read.checkpoint;
};

const bucketOf = (window: bigint, sizeClass: number): PublicBucketV1 => ({
  deliveryProfileHash: PROFILE_HASH,
  ingressWindow: window,
  sizeClass,
});

describe("prototype store allocation", () => {
  test("hands out ordinals 0..7 and then refuses with capacity-exhausted", async () => {
    const { core } = await harness();

    const ordinals: number[] = [];
    for (let index = 0; index < profile.cohortAllocationsPerWindow; index++) {
      const { lease } = await leaseFor(core);
      ordinals.push(lease.allocationOrdinal);
    }
    expect(ordinals).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);

    const overflow = await newKeyPair(cryptoModule);
    const refused = await core.allocate(allocationRequest(overflow.publicKey));
    if (refused.kind !== "status") throw new Error("expected a signed status");
    expect(refused.value.status).toBe("capacity-exhausted");
    expect(
      await verify(
        await publicAllocationStatusSignedMessage(refused.value),
        refused.storeSignature,
        core.descriptor.storeIdentityEd25519Key,
        cryptoModule,
      ),
    ).toBe(true);
  });

  test("assigns one ordinal per concurrent request", async () => {
    const { core } = await harness();
    const keyPairs = await Promise.all(
      Array.from({ length: profile.cohortAllocationsPerWindow }, () =>
        newKeyPair(cryptoModule),
      ),
    );

    // The HTTP server dispatches these in parallel, and every step between
    // reading the free ordinal and persisting it is an await.
    const results = await Promise.all(
      keyPairs.map((keyPair) =>
        core.allocate(allocationRequest(keyPair.publicKey)),
      ),
    );
    const ordinals = results.map((result) => {
      if (result.kind !== "allocated")
        throw new Error(`expected a lease, got ${result.value.status}`);
      return result.lease.allocationOrdinal;
    });
    expect([...ordinals].sort((a, b) => a - b)).toEqual([
      0, 1, 2, 3, 4, 5, 6, 7,
    ]);
  });

  test("replays a repeated request byte for byte and signs the lease", async () => {
    const { core } = await harness();
    const keyPair = await newKeyPair(cryptoModule);
    const request = allocationRequest(keyPair.publicKey);

    const first = await core.allocate(request);
    const second = await core.allocate(request);
    expect(hex(encodePublicAllocationResultV1(second))).toBe(
      hex(encodePublicAllocationResultV1(first)),
    );

    if (first.kind !== "allocated") throw new Error("expected a lease");
    const { storeSignature, ...leaseBody } = first.lease;
    expect(
      await verify(
        await publicAllocationLeaseSignedMessage(leaseBody),
        storeSignature,
        core.descriptor.storeIdentityEd25519Key,
        cryptoModule,
      ),
    ).toBe(true);
    expect(hex(first.lease.storeId)).toBe(hex(core.storeId));
    expect(first.lease.ingressWindow).toBe(CHAIN_START);
  });

  test("refuses a foreign profile and a window outside the open range", async () => {
    const { core } = await harness();
    const keyPair = await newKeyPair(cryptoModule);

    const foreign = await core.allocate(
      allocationRequest(keyPair.publicKey, CHAIN_START, OTHER_PROFILE_HASH),
    );
    if (foreign.kind !== "status") throw new Error("expected a signed status");
    expect(foreign.value.status).toBe("invalid-token");

    const tooFar = await core.allocate(
      allocationRequest(
        keyPair.publicKey,
        CHAIN_START + BigInt(profile.maxFutureIngressWindows) + 1n,
      ),
    );
    if (tooFar.kind !== "status") throw new Error("expected a signed status");
    expect(tooFar.value.status).toBe("window-closed");

    const past = await core.allocate(
      allocationRequest(keyPair.publicKey, CHAIN_START - 1n),
    );
    if (past.kind !== "status") throw new Error("expected a signed status");
    expect(past.value.status).toBe("window-closed");
  });

  test("accepts every window inside the open range", async () => {
    const { core } = await harness();

    for (
      let ahead = 0n;
      ahead <= BigInt(profile.maxFutureIngressWindows);
      ahead += 1n
    ) {
      const { lease } = await leaseFor(core, CHAIN_START + ahead);
      expect(lease.ingressWindow).toBe(CHAIN_START + ahead);
      expect(lease.allocationOrdinal).toBe(0);
    }
  });

  test("refuses allocation into a finalized window", async () => {
    const { core, setNow } = await harness();
    setNow(FINALIZE_AT);
    expect(await core.finalizeDue()).toEqual([CHAIN_START]);

    const keyPair = await newKeyPair(cryptoModule);
    const refused = await core.allocate(allocationRequest(keyPair.publicKey));
    if (refused.kind !== "status") throw new Error("expected a signed status");
    expect(refused.value.status).toBe("window-closed");
  });

  test("issues an open-mode token without mutating anything", async () => {
    const { core } = await harness();
    const request = {
      version: 1 as const,
      storeId: core.storeId,
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: CHAIN_START,
      privacyPassTokenRequest: new Uint8Array(64).fill(7),
    };

    const result = await core.issueToken(request);
    expect(result.body.kind).toBe("issued");
    if (result.body.kind !== "issued") throw new Error("expected issuance");
    expect(hex(result.body.requestHash)).toBe(
      hex(await allocationTokenIssueRequestHash(request)),
    );
    expect(hex(result.body.privacyPassTokenResponse)).toBe(
      hex(new Uint8Array(32)),
    );
    expect(
      await verify(
        await allocationTokenIssueResultSignedMessage(result.body),
        result.storeSignature,
        core.descriptor.storeIdentityEd25519Key,
        cryptoModule,
      ),
    ).toBe(true);

    const { lease } = await leaseFor(core);
    expect(lease.allocationOrdinal).toBe(0);
  });
});

describe("prototype store append", () => {
  test("binds a slot once and reports the three redemption outcomes", async () => {
    const { core } = await harness();
    const { lease, secretKey } = await leaseFor(core);
    const object = objectOf(0x11);

    const request = await appendRequest(lease, secretKey, 0, object);
    const stored = await core.append(request);
    expect(await verifiedStatus(core, stored)).toBe("stored");
    expect(hex(stored.requestHash)).toBe(
      hex(await publicAppendRequestHash(request)),
    );
    expect(hex(stored.storeId)).toBe(hex(core.storeId));
    expect(hex(stored.descriptorHash)).toBe(hex(core.descriptorHash));

    const again = await core.append(request);
    expect(await verifiedStatus(core, again)).toBe("already-present");

    const conflicting = await appendRequest(
      lease,
      secretKey,
      0,
      objectOf(0x22),
    );
    expect(await verifiedStatus(core, await core.append(conflicting))).toBe(
      "slot-conflict",
    );
  });

  test("accepts an unallocated cover append and discards it", async () => {
    const { core, setNow } = await harness();
    expect(
      await verifiedStatus(core, await core.append(coverRequest(objectOf(9)))),
    ).toBe("unallocated-cover");

    setNow(FINALIZE_AT);
    await core.finalizeDue();
    const read = await core.readChunk(bucketOf(CHAIN_START, 0), 0n);
    if (read.kind !== "finalized") throw new Error("expected a chunk");
    for (const fixedObject of read.chunk.fixedObjects)
      expect(hex(fixedObject)).not.toBe(hex(objectOf(9)));
  });

  test("refuses a window whose finalization instant has passed", async () => {
    const { core, setNow } = await harness();
    const { lease, secretKey } = await leaseFor(core);
    setNow(FINALIZE_AT);

    const request = await appendRequest(lease, secretKey, 0, objectOf(0x33));
    expect(await verifiedStatus(core, await core.append(request))).toBe(
      "window-finalized",
    );
  });

  test("throws on a wrong object length and on a forged admission", async () => {
    const { core } = await harness();
    const { lease, secretKey } = await leaseFor(core);

    const short = await appendRequest(
      lease,
      secretKey,
      0,
      objectOf(1, CLASS_0_OBJECT_BYTES - 1),
    );
    await expect(core.append(short)).rejects.toThrow(StoreRequestError);

    const forged = await appendRequest(lease, secretKey, 0, objectOf(0x44));
    if (forged.admission === null) throw new Error("expected an admission");
    forged.admission.allocationSignature[0] ^= 0xff;
    await expect(core.append(forged)).rejects.toThrow(StoreRequestError);

    const otherStore = await newKeyPair(cryptoModule);
    const tamperedLease = await appendRequest(
      {
        ...lease,
        storeSignature: await sign(
          new Uint8Array(4),
          otherStore.secretKey,
          cryptoModule,
        ),
      },
      secretKey,
      0,
      objectOf(0x55),
    );
    await expect(core.append(tamperedLease)).rejects.toThrow(StoreRequestError);

    const outOfRange = await appendRequest(
      lease,
      secretKey,
      profile.roomSlotsPerClient * profile.sizeClasses[0].appendSchedule.length,
      objectOf(0x66),
    );
    await expect(core.append(outOfRange)).rejects.toThrow(StoreRequestError);

    const foreignProfile = await appendRequest(
      lease,
      secretKey,
      0,
      objectOf(7),
    );
    await expect(
      core.append({
        ...foreignProfile,
        bucket: {
          ...foreignProfile.bucket,
          deliveryProfileHash: OTHER_PROFILE_HASH,
        },
      }),
    ).rejects.toThrow(StoreRequestError);
  });
});

describe("prototype store finalization", () => {
  test("finalizes only when the offset has elapsed and pads every slot", async () => {
    const { core, setNow } = await harness();

    // Four leases so the object under test lands away from the origin slot.
    let last: { lease: PublicAllocationLeaseV1; secretKey: Uint8Array } | null =
      null;
    for (let index = 0; index < 4; index++) last = await leaseFor(core);
    if (last === null) throw new Error("expected a lease");

    const object = objectOf(0x77);
    expect(
      await verifiedStatus(
        core,
        await core.append(
          await appendRequest(last.lease, last.secretKey, 2, object),
        ),
      ),
    ).toBe("stored");

    setNow(FINALIZE_AT - 1n);
    expect(await core.finalizeDue()).toEqual([]);
    setNow(FINALIZE_AT);
    expect(await core.finalizeDue()).toEqual([CHAIN_START]);
    expect(await core.finalizeDue()).toEqual([]);

    const slot = appendSlotCoordinates(
      geometry,
      0,
      last.lease.allocationOrdinal,
      2,
    );
    const chunkRead = await core.readChunk(
      bucketOf(CHAIN_START, 0),
      slot.chunkIndex,
    );
    if (chunkRead.kind !== "finalized") throw new Error("expected a chunk");
    expect(hex(chunkRead.chunk.fixedObjects[slot.objectIndexWithinChunk])).toBe(
      hex(object),
    );

    for (const sizeClass of profile.sizeClasses) {
      const objectBytes = carrierObjectWireBytes(
        profile,
        sizeClass.id,
        PROFILE_HASH,
      );
      for (
        let chunkIndex = 0;
        chunkIndex < sizeClass.publicChunksPerWindow;
        chunkIndex++
      ) {
        const read = await core.readChunk(
          bucketOf(CHAIN_START, sizeClass.id),
          BigInt(chunkIndex),
        );
        if (read.kind !== "finalized") throw new Error("expected a chunk");
        expect(read.chunk.fixedObjects.length).toBe(
          profile.publicChunkObjectCount,
        );
        for (const fixedObject of read.chunk.fixedObjects)
          expect(fixedObject.length).toBe(objectBytes);
      }
    }
  });

  test("places a size class 1 object at its own slot coordinates", async () => {
    const { core, setNow } = await harness();
    const sizeClass = profile.sizeClasses[1];
    const objectBytes = carrierObjectWireBytes(
      profile,
      sizeClass.id,
      PROFILE_HASH,
    );

    // Five leases, so the object lands in the second chunk of the class:
    // globalObjectOrdinal = 4 * 2 + 1 = 9, with publicChunkObjectCount 8.
    let last: { lease: PublicAllocationLeaseV1; secretKey: Uint8Array } | null =
      null;
    for (let index = 0; index < 5; index++) last = await leaseFor(core);
    if (last === null) throw new Error("expected a lease");

    const object = objectOf(0xbb, objectBytes);
    expect(
      await verifiedStatus(
        core,
        await core.append(
          await appendRequest(
            last.lease,
            last.secretKey,
            1,
            object,
            sizeClass.id,
          ),
        ),
      ),
    ).toBe("stored");

    setNow(FINALIZE_AT);
    await core.finalizeDue();

    const slot = appendSlotCoordinates(
      geometry,
      sizeClass.id,
      last.lease.allocationOrdinal,
      1,
    );
    expect(slot.chunkIndex).toBe(1n);
    const read = await core.readChunk(
      bucketOf(CHAIN_START, sizeClass.id),
      slot.chunkIndex,
    );
    if (read.kind !== "finalized") throw new Error("expected a chunk");
    expect(hex(read.chunk.fixedObjects[slot.objectIndexWithinChunk])).toBe(
      hex(object),
    );
  });

  test("signs a checkpoint whose root is the served chunk sequence", async () => {
    const { core, setNow } = await harness();
    setNow(FINALIZE_AT);
    await core.finalizeDue();

    const checkpoint = await finalizedCheckpoint(core, CHAIN_START);
    expect(
      await structurallyValidCheckpoint(
        core.descriptor,
        checkpoint,
        geometry,
        FINALIZE_AT,
        cryptoModule,
      ),
    ).toEqual({ valid: true });

    const hashes = new Map<number, Uint8Array[]>();
    for (const sizeClass of profile.sizeClasses) {
      const list: Uint8Array[] = [];
      for (
        let chunkIndex = 0;
        chunkIndex < sizeClass.publicChunksPerWindow;
        chunkIndex++
      ) {
        const read = await core.readChunk(
          bucketOf(CHAIN_START, sizeClass.id),
          BigInt(chunkIndex),
        );
        if (read.kind !== "finalized") throw new Error("expected a chunk");
        list.push(await publicChunkHash(read.chunk));
      }
      hashes.set(sizeClass.id, list);
    }
    const root = await rfc9162MerkleTreeHash(
      await checkpointLeafEntries(geometry, hashes),
    );
    expect(hex(checkpoint.finalizedChunkRoot)).toBe(hex(root));
  });

  test("chains an all-dummy window onto its predecessor", async () => {
    const { core, setNow } = await harness();
    setNow(NEXT_FINALIZE_AT);
    expect(await core.finalizeDue()).toEqual([CHAIN_START, CHAIN_START + 1n]);

    const first = await finalizedCheckpoint(core, CHAIN_START);
    const second = await finalizedCheckpoint(core, CHAIN_START + 1n);
    expect(
      await chainValidSuccessor(
        first,
        core.descriptor,
        FINALIZE_AT,
        second,
        core.descriptor,
        NEXT_FINALIZE_AT,
        geometry,
        cryptoModule,
      ),
    ).toEqual({ valid: true });
  });
});

describe("prototype store reads", () => {
  test("answers not-final, finalized, and out-of-range with signed statuses", async () => {
    const { core, setNow } = await harness();

    const early = await core.readCheckpoint(PROFILE_HASH, CHAIN_START);
    if (early.kind !== "status") throw new Error("expected a status");
    expect(early.value.status).toBe("not-final");
    expect(
      await verify(
        await publicCheckpointStatusSigningHash(early.value),
        early.storeSignature,
        core.descriptor.storeIdentityEd25519Key,
        cryptoModule,
      ),
    ).toBe(true);

    const beforeStart = await core.readCheckpoint(
      PROFILE_HASH,
      CHAIN_START - 1n,
    );
    if (beforeStart.kind !== "status") throw new Error("expected a status");
    expect(beforeStart.value.status).toBe("out-of-range");

    const foreign = await core.readCheckpoint(OTHER_PROFILE_HASH, CHAIN_START);
    if (foreign.kind !== "status") throw new Error("expected a status");
    expect(foreign.value.status).toBe("chain-unavailable");

    const earlyChunk = await core.readChunk(bucketOf(CHAIN_START, 0), 0n);
    if (earlyChunk.kind !== "status") throw new Error("expected a status");
    expect(earlyChunk.value.status).toBe("not-final");
    expect(
      await verify(
        await publicChunkStatusSigningHash(earlyChunk.value),
        earlyChunk.storeSignature,
        core.descriptor.storeIdentityEd25519Key,
        cryptoModule,
      ),
    ).toBe(true);

    const pastEnd = await core.readChunk(
      bucketOf(CHAIN_START, 0),
      BigInt(profile.sizeClasses[0].publicChunksPerWindow),
    );
    if (pastEnd.kind !== "status") throw new Error("expected a status");
    expect(pastEnd.value.status).toBe("out-of-range");

    const unknownClass = await core.readChunk(bucketOf(CHAIN_START, 9), 0n);
    if (unknownClass.kind !== "status") throw new Error("expected a status");
    expect(unknownClass.value.status).toBe("out-of-range");

    const beforeChainStart = await core.readChunk(
      bucketOf(CHAIN_START - 1n, 0),
      0n,
    );
    if (beforeChainStart.kind !== "status")
      throw new Error("expected a status");
    expect(beforeChainStart.value.status).toBe("out-of-range");

    setNow(FINALIZE_AT);
    await core.finalizeDue();
    expect((await core.readCheckpoint(PROFILE_HASH, CHAIN_START)).kind).toBe(
      "finalized",
    );
    expect((await core.readChunk(bucketOf(CHAIN_START, 0), 0n)).kind).toBe(
      "finalized",
    );
  });

  test("throws on coordinates no signed status could name", async () => {
    const { core } = await harness();

    await expect(
      core.readCheckpoint(PROFILE_HASH.subarray(0, 31), CHAIN_START),
    ).rejects.toThrow(StoreRequestError);
    await expect(core.readCheckpoint(PROFILE_HASH, -1n)).rejects.toThrow(
      StoreRequestError,
    );
    await expect(core.readChunk(bucketOf(CHAIN_START, 0), -1n)).rejects.toThrow(
      StoreRequestError,
    );
  });
});

describe("prototype store withhold fault", () => {
  test("acknowledges an append it never binds", async () => {
    const { core, setNow } = await harness({ fault: "withhold" });
    const { lease, secretKey } = await leaseFor(core);
    const object = objectOf(0x99);

    expect(
      await verifiedStatus(
        core,
        await core.append(await appendRequest(lease, secretKey, 0, object)),
      ),
    ).toBe("stored");

    setNow(FINALIZE_AT);
    await core.finalizeDue();
    const slot = appendSlotCoordinates(geometry, 0, lease.allocationOrdinal, 0);
    const read = await core.readChunk(
      bucketOf(CHAIN_START, 0),
      slot.chunkIndex,
    );
    if (read.kind !== "finalized") throw new Error("expected a chunk");
    expect(hex(read.chunk.fixedObjects[slot.objectIndexWithinChunk])).not.toBe(
      hex(object),
    );
  });
});

describe("prototype store restart", () => {
  test("replays the same descriptor and the same finalized checkpoint", async () => {
    const persistence = new MemoryStorePersistence();
    const first = await harness({ persistence });
    const { lease, secretKey } = await leaseFor(first.core);
    await first.core.append(
      await appendRequest(lease, secretKey, 0, objectOf(0xaa)),
    );
    first.setNow(FINALIZE_AT);
    expect(await first.core.finalizeDue()).toEqual([CHAIN_START]);

    const second = await harness({ persistence, now: FINALIZE_AT });
    expect(
      hex(
        encodePrototypeStoreDescriptorDocumentV1(
          second.core.descriptorDocument(),
        ),
      ),
    ).toBe(
      hex(
        encodePrototypeStoreDescriptorDocumentV1(
          first.core.descriptorDocument(),
        ),
      ),
    );
    expect(await second.core.finalizeDue()).toEqual([]);
    expect(
      hex(
        encodePublicStoreCheckpointReadV1(
          await second.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
        ),
      ),
    ).toBe(
      hex(
        encodePublicStoreCheckpointReadV1(
          await first.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
        ),
      ),
    );
  });

  test("refuses to boot on a chain start the persisted chain contradicts", async () => {
    const persistence = new MemoryStorePersistence();
    const first = await harness({ persistence });
    first.setNow(FINALIZE_AT);
    expect(await first.core.finalizeDue()).toEqual([CHAIN_START]);

    await expect(
      harness({ persistence, now: FINALIZE_AT, chainStart: CHAIN_START + 5n }),
    ).rejects.toThrow(StoreConfigurationError);
    await expect(
      harness({ persistence, now: FINALIZE_AT, chainStart: CHAIN_START - 5n }),
    ).rejects.toThrow(/the persisted chain starts at window/);

    // Same chain start, different identity: the checkpoint's descriptorHash is
    // the half that catches this one.
    await expect(
      harness({
        persistence,
        now: FINALIZE_AT,
        seed: new Uint8Array(32).fill(0x77),
      }),
    ).rejects.toThrow(/signed under a different descriptor/);

    // The same configuration still boots and still serves that checkpoint.
    const resumed = await harness({ persistence, now: FINALIZE_AT });
    expect(
      (await resumed.core.readCheckpoint(PROFILE_HASH, CHAIN_START)).kind,
    ).toBe("finalized");
  });
});

describe("prototype store identity", () => {
  test("hands out copies of the values its signatures are checked against", async () => {
    const { core } = await harness();
    const { lease, secretKey } = await leaseFor(core);

    // Everything an in-process caller can reach, corrupted.
    core.storeId.fill(0xff);
    core.descriptorHash.fill(0xff);
    core.profileHash.fill(0xff);
    core.descriptor.storeIdentityEd25519Key.fill(0xff);
    core.routes[0].opaqueLocator.fill(0xff);

    expect(hex(core.storeId)).not.toBe(hex(new Uint8Array(32).fill(0xff)));
    expect(hex(core.profileHash)).toBe(hex(PROFILE_HASH));
    // The lease check reads the descriptor key, so a mutated copy would have
    // turned this append into a signature failure.
    expect(
      await verifiedStatus(
        core,
        await core.append(
          await appendRequest(lease, secretKey, 0, objectOf(4)),
        ),
      ),
    ).toBe("stored");
  });
});

describe("prototype store persistence", () => {
  test("stores structured copies rather than the caller's buffers", async () => {
    const persistence = new MemoryStorePersistence();
    const state = emptyStoreWindowState(CHAIN_START);
    const object = objectOf(0x5c);
    state.slots.set("0:0:0", {
      objectHash: new Uint8Array(32).fill(1),
      object,
    });
    await persistence.saveWindow(state);

    // Everything the caller still holds a reference to, mutated after the save.
    object[0] ^= 0xff;
    state.slots.set("0:0:1", {
      objectHash: new Uint8Array(32).fill(2),
      object,
    });

    const loaded = await persistence.loadWindow(CHAIN_START);
    if (loaded === null) throw new Error("expected a stored window");
    expect(loaded.slots.size).toBe(1);
    const slot = loaded.slots.get("0:0:0");
    if (slot === undefined) throw new Error("expected the bound slot");
    expect(hex(slot.object)).toBe(hex(objectOf(0x5c)));
  });
});

describe("prototype store witness records", () => {
  test("is idempotent on identical bytes and bounded per window", async () => {
    const { core } = await harness();
    const record: StoreWitnessRecordV1 = {
      version: 1,
      witnessedStoreId: new Uint8Array(32).fill(3),
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: CHAIN_START,
      checkpointHash: new Uint8Array(32).fill(4),
    };

    await core.addWitness(record);
    await core.addWitness(record);
    expect((await core.witnessRecords(CHAIN_START)).length).toBe(1);

    const other: StoreWitnessRecordV1 = {
      ...record,
      checkpointHash: new Uint8Array(32).fill(5),
    };
    await core.addWitness(other);
    expect((await core.witnessRecords(CHAIN_START)).length).toBe(2);
    expect((await core.witnessRecords(CHAIN_START + 1n)).length).toBe(0);
  });
});
