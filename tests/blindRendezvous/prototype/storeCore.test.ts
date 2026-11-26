import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import libcrypto from "../../../src/cryptography/libcrypto";
import {
  PROTOTYPE_READ_BACK_WINDOWS,
  PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS,
  PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH,
  PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY,
  PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW,
  PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
  PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS,
} from "../../../src/utils/constants";
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
  StoreFinalizationPendingError,
  StoreRequestError,
  type PrototypeStoreCoreOptions,
} from "../../../src/blindRendezvous/prototype/store/storeCore";
import { signedStatusProvesFault } from "../../../src/blindRendezvous/prototype/storeClient";
import {
  MemoryStorePersistence,
  emptyStoreWindowState,
  copyStoreWindowState,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";
import { validateStoreDescriptor } from "../../../src/blindRendezvous/storeDescriptor";
import {
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationResultV1,
  encodePublicChunkReadV1,
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
import type {
  StorePersistencePort,
  StoreWindowState,
} from "../../../src/blindRendezvous/prototype/store/storePersistence";

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
  readonly persistence: StorePersistencePort;
  readonly setNow: (ms: bigint) => void;
}

const harness = async (
  options: {
    fault?: "withhold" | null;
    persistence?: StorePersistencePort;
    now?: bigint;
    chainStart?: bigint;
    seed?: Uint8Array;
    allocationAdmission?: PrototypeStoreCoreOptions["allocationAdmission"];
    retentionWindows?: number;
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
    allocationAdmission: options.allocationAdmission,
    retentionWindows: options.retentionWindows,
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

describe("prototype store optional allocation admission", () => {
  const grant = new Uint8Array(32).fill(0x72);
  const requestWith = (
    key: number,
    token = key,
    window = CHAIN_START,
  ): PublicAllocationRequestV1 => ({
    ...allocationRequest(new Uint8Array(32).fill(key), window),
    privacyPassToken: new Uint8Array(32).fill(token),
  });
  const quota = { authorize: (): Uint8Array => grant };

  test("a grant gets one lease per window despite changing tokens or public keys", async () => {
    const { core, persistence } = await harness({ allocationAdmission: quota });
    const request = requestWith(1);
    const first = await core.allocate(request);
    expect(first.kind).toBe("allocated");
    expect(
      encodePublicAllocationResultV1(await core.allocate(request)),
    ).toEqual(encodePublicAllocationResultV1(first));
    for (const varied of [
      requestWith(1, 2),
      requestWith(2, 1),
      requestWith(2, 2),
    ]) {
      const result = await core.allocate(varied);
      if (result.kind !== "status") throw new Error("expected quota refusal");
      expect(result.value.status).toBe("invalid-token");
    }
    expect((await persistence.loadWindow(CHAIN_START))?.allocations.size).toBe(
      1,
    );
    expect(
      (await core.allocate(requestWith(2, 2, CHAIN_START + 1n))).kind,
    ).toBe("allocated");
  });

  test("concurrent variants consume one grant once and exact retries still succeed at capacity", async () => {
    const { core } = await harness({ allocationAdmission: quota });
    const outcomes = await Promise.all(
      Array.from({ length: 12 }, (_, i) => core.allocate(requestWith(i + 1))),
    );
    expect(
      outcomes.filter((result) => result.kind === "allocated"),
    ).toHaveLength(1);
    expect(
      outcomes.filter(
        (result) =>
          result.kind === "status" && result.value.status === "invalid-token",
      ),
    ).toHaveLength(11);

    const full = await harness({
      allocationAdmission: { authorize: (request) => request.privacyPassToken },
    });
    const requests = Array.from(
      { length: profile.cohortAllocationsPerWindow },
      (_, i) => requestWith(i + 1),
    );
    const leases = await Promise.all(
      requests.map((request) => full.core.allocate(request)),
    );
    expect(leases.every((result) => result.kind === "allocated")).toBe(true);
    expect(
      encodePublicAllocationResultV1(await full.core.allocate(requests[0])),
    ).toEqual(encodePublicAllocationResultV1(leases[0]));
    const refused = await full.core.allocate(requestWith(99));
    if (refused.kind !== "status") throw new Error("expected full store");
    expect(refused.value.status).toBe("capacity-exhausted");
  });

  test("authorization fails closed and is checked before an exact retry", async () => {
    let accepted = true;
    const { core } = await harness({
      allocationAdmission: { authorize: () => (accepted ? grant : null) },
    });
    const request = requestWith(1);
    expect((await core.allocate(request)).kind).toBe("allocated");
    accepted = false;
    const revoked = await core.allocate(request);
    if (revoked.kind !== "status")
      throw new Error("expected authorization refusal");
    expect(revoked.value.status).toBe("invalid-token");
    for (const authorize of [
      () => null,
      () => new Uint8Array(31),
      () => {
        throw new Error("invalid grant");
      },
    ]) {
      const invalid = await harness({ allocationAdmission: { authorize } });
      const result = await invalid.core.allocate(request);
      if (result.kind !== "status")
        throw new Error("expected invalid admission");
      expect(result.value.status).toBe("invalid-token");
      expect(await invalid.persistence.loadWindow(CHAIN_START)).toBeNull();
    }
  });

  test("profile and window refusals happen before invoking the authorizer", async () => {
    let calls = 0;
    const { core, setNow } = await harness({
      allocationAdmission: {
        authorize: () => {
          calls += 1;
          return grant;
        },
      },
    });
    await core.allocate({
      ...requestWith(1),
      deliveryProfileHash: OTHER_PROFILE_HASH,
    });
    await core.allocate(requestWith(1, 1, CHAIN_START - 1n));
    await core.allocate(
      requestWith(
        1,
        1,
        CHAIN_START + BigInt(profile.maxFutureIngressWindows) + 1n,
      ),
    );
    setNow(FINALIZE_AT);
    await core.allocate(requestWith(1));
    expect(calls).toBe(0);
  });

  test("admission boundaries copy callback inputs and the retained quota key", async () => {
    const returned = Uint8Array.from(grant);
    const { core, persistence } = await harness({
      allocationAdmission: {
        authorize: (request) => {
          request.allocationEd25519PublicKey.fill(0xff);
          request.deliveryProfileHash.fill(0xff);
          request.privacyPassToken.fill(0xff);
          return returned;
        },
      },
    });
    const request = requestWith(1);
    const result = await core.allocate(request);
    if (result.kind !== "allocated") throw new Error("expected admission");
    expect(result.lease.allocationEd25519PublicKey).toEqual(
      request.allocationEd25519PublicKey,
    );
    expect(result.lease.deliveryProfileHash).toEqual(PROFILE_HASH);
    returned.fill(0xff);
    const loaded = await persistence.loadWindow(CHAIN_START);
    expect(loaded?.allocations.get(0)?.admissionQuotaKey32).toEqual(grant);
    loaded?.allocations.get(0)?.admissionQuotaKey32?.fill(0);
    expect(
      (await persistence.loadWindow(CHAIN_START))?.allocations.get(0)
        ?.admissionQuotaKey32,
    ).toEqual(grant);
  });

  test("failed persistence cannot consume a grant in a cached loaded window", async () => {
    class FailingCache extends MemoryStorePersistence {
      cached = emptyStoreWindowState(CHAIN_START);
      rejectSave = true;
      override async loadWindow(): Promise<StoreWindowState> {
        return this.cached;
      }
      override async saveWindow(state: StoreWindowState): Promise<void> {
        if (this.rejectSave) throw new Error("injected saveWindow failure");
        this.cached = copyStoreWindowState(state);
      }
    }
    const persistence = new FailingCache();
    const { core } = await harness({ persistence, allocationAdmission: quota });
    await expect(core.allocate(requestWith(1))).rejects.toThrow(
      "injected saveWindow failure",
    );
    expect(persistence.cached.allocations.size).toBe(0);
    persistence.rejectSave = false;
    const retried = await core.allocate(requestWith(2));
    if (retried.kind !== "allocated")
      throw new Error("failed write consumed grant");
    expect(retried.lease.allocationOrdinal).toBe(0);
    expect(persistence.cached.allocations.size).toBe(1);
  });

  test("SQLite restart preserves quota enforcement and byte-identical retry", async () => {
    const root = mkdtempSync(join(tmpdir(), "p2party-admission-restart-"));
    const path = join(root, "store.sqlite");
    let db = new SqliteStorePersistence(path);
    try {
      const first = await harness({
        persistence: db,
        allocationAdmission: quota,
      });
      const request = requestWith(1);
      const original = await first.core.allocate(request);
      expect(original.kind).toBe("allocated");
      db.close();
      db = new SqliteStorePersistence(path);
      const restarted = await harness({
        persistence: db,
        allocationAdmission: quota,
      });
      expect(
        encodePublicAllocationResultV1(await restarted.core.allocate(request)),
      ).toEqual(encodePublicAllocationResultV1(original));
      const reused = await restarted.core.allocate(requestWith(2, 3));
      if (reused.kind !== "status")
        throw new Error("restart forgot grant quota");
      expect(reused.value.status).toBe("invalid-token");
      expect(
        (await db.loadWindow(CHAIN_START))?.allocations.get(0)
          ?.admissionQuotaKey32,
      ).toEqual(grant);
    } finally {
      db.close();
      rmSync(root, { recursive: true, force: true });
    }
  });
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
    // Coordinates no window can hold are their own status: `out-of-range`
    // says only that the window is outside what the store keeps.
    if (pastEnd.kind !== "status") throw new Error("expected a status");
    expect(pastEnd.value.status).toBe("no-such-chunk");

    const unknownClass = await core.readChunk(bucketOf(CHAIN_START, 9), 0n);
    if (unknownClass.kind !== "status") throw new Error("expected a status");
    expect(unknownClass.value.status).toBe("no-such-chunk");

    const foreignChunk = await core.readChunk(
      { ...bucketOf(CHAIN_START, 0), deliveryProfileHash: OTHER_PROFILE_HASH },
      0n,
    );
    if (foreignChunk.kind !== "status") throw new Error("expected a status");
    expect(foreignChunk.value.status).toBe("no-such-chunk");

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

  test("a backward step of the clock cannot make an honest store sign against itself", async () => {
    // Armed, the clock reads `decided` once and `stepped` (two windows back)
    // on every later reading: a wall-clock step inside one answer.
    const window = CHAIN_START;
    const decided = ingressWindowStartMs(
      window + BigInt(PROTOTYPE_STORE_MIN_RETENTION_WINDOWS) + 1n,
      profile.deliveryWindowMs,
    );
    const stepped = decided - 2n * profile.deliveryWindowMs;
    let armed = false;
    let readings = 0;
    const core = await PrototypeStoreCore.create({
      module: cryptoModule,
      seed: SEED,
      profile,
      clock: {
        nowMs: () => {
          if (!armed) return WINDOW_START;
          readings += 1;
          return readings === 1 ? decided : stepped;
        },
      },
      persistence: new MemoryStorePersistence(),
      chainStartIngressWindow: CHAIN_START,
      origin: "http://127.0.0.1:5910",
      descriptorValidityMs: 2_592_000_000n,
      retentionWindows: PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
    });
    const reads: (() => Promise<{
      readonly status: string | null;
      readonly storeWindow: bigint | null;
      readonly bytes: Uint8Array;
    }>)[] = [
      async () => {
        const read = await core.readCheckpoint(PROFILE_HASH, window);
        return {
          status: read.kind === "status" ? read.value.status : null,
          storeWindow:
            read.kind === "status" ? read.value.storeIngressWindow : null,
          bytes: encodePublicStoreCheckpointReadV1(read),
        };
      },
      async () => {
        const read = await core.readChunk(bucketOf(window, 0), 0n);
        return {
          status: read.kind === "status" ? read.value.status : null,
          storeWindow:
            read.kind === "status" ? read.value.storeIngressWindow : null,
          bytes: encodePublicChunkReadV1(read),
        };
      },
    ];
    for (const read of reads) {
      armed = true;
      readings = 0;
      const answer = await read();
      armed = false;
      // One reading decided the answer and is the window it states: past
      // the retention, and so no evidence against the store.
      expect(readings).toBe(1);
      expect(answer.status).toBe("out-of-range");
      expect(answer.storeWindow).toBe(
        window + BigInt(PROTOTYPE_STORE_MIN_RETENTION_WINDOWS) + 1n,
      );
      expect(
        await signedStatusProvesFault(
          core.descriptor,
          profile,
          [answer.bytes],
          cryptoModule,
        ),
      ).toBeNull();
    }
  });

  test("no refusal an honest store signs proves a fault, at any window and any clock reading", async () => {
    // What the client's blame rests on, pinned on the store's own code: for
    // the profile its descriptor declares and a chunk that profile defines,
    // the store never signs `chain-unavailable` or `no-such-chunk`, and its
    // `out-of-range` and `not-final` never contradict its descriptor. That
    // holds before the chain start, far ahead, and when its clock is past the
    // descriptor's own validity, which the judgment does not consult.
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const { core, setNow } = await harness({ retentionWindows: retention });
    const startOf = (window: bigint): bigint =>
      ingressWindowStartMs(window, profile.deliveryWindowMs);
    const pastValidity = core.descriptor.notAfterUnixMs;
    const readings = [
      WINDOW_START,
      FINALIZE_AT - 1n,
      FINALIZE_AT,
      startOf(CHAIN_START + 1n),
      startOf(CHAIN_START + BigInt(retention)) + 3_999n,
      startOf(CHAIN_START + BigInt(retention) + 1n),
      pastValidity - 1n,
      pastValidity,
      pastValidity + 1_000_000n,
    ];
    const windows = [
      0n,
      CHAIN_START - 1n,
      CHAIN_START,
      CHAIN_START + 1n,
      CHAIN_START + BigInt(retention) + 1n,
      pastValidity / profile.deliveryWindowMs,
      1n << 40n,
    ];
    let checkpointBeside: Uint8Array | null = null;
    const statuses = new Set<string>();
    for (const reading of readings) {
      setNow(reading);
      await core.finalizeDue();
      for (const window of windows) {
        const checkpoint = await core
          .readCheckpoint(PROFILE_HASH, window)
          .catch(() => null);
        if (checkpoint?.kind === "finalized" && window === CHAIN_START)
          checkpointBeside = encodePublicStoreCheckpointReadV1(checkpoint);
        if (checkpoint?.kind === "status") {
          statuses.add(`checkpoint ${checkpoint.value.status}`);
          expect(
            await signedStatusProvesFault(
              core.descriptor,
              profile,
              [encodePublicStoreCheckpointReadV1(checkpoint)],
              cryptoModule,
            ),
          ).toBeNull();
        }
        const chunk = await core
          .readChunk(bucketOf(window, 0), 0n)
          .catch(() => null);
        if (chunk?.kind === "status") {
          statuses.add(`chunk ${chunk.value.status}`);
          const bytes = encodePublicChunkReadV1(chunk);
          expect(
            await signedStatusProvesFault(
              core.descriptor,
              profile,
              [bytes],
              cryptoModule,
            ),
          ).toBeNull();
          // Nor beside the checkpoint the store signed for the chain start.
          if (checkpointBeside !== null && window === CHAIN_START)
            expect(
              await signedStatusProvesFault(
                core.descriptor,
                profile,
                [checkpointBeside, bytes],
                cryptoModule,
              ),
            ).toBeNull();
        }
      }
    }
    expect(checkpointBeside).not.toBeNull();
    // Every refusal it gave was one of these two, on both routes.
    expect([...statuses].sort()).toEqual([
      "checkpoint not-final",
      "checkpoint out-of-range",
      "chunk not-final",
      "chunk out-of-range",
    ]);
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
    // A witness names a window whose checkpoint can exist: one closed on the
    // clock.
    const { core } = await harness({ now: FINALIZE_AT });
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

/* ------------------------------------------------------------------ *
 * Hardening (audit 2026-11, blind-rendezvous items 2, 6, 7 and 10)
 *
 * Cost is read through a counting persistence port, never through a clock:
 * one unit per port call plus one per record a call hands back.
 * ------------------------------------------------------------------ */

const windowStartOf = (window: bigint): bigint =>
  ingressWindowStartMs(window, profile.deliveryWindowMs);

const finalizeAtOf = (window: bigint): bigint =>
  windowStartOf(window) + profile.chunkFinalizationOffsetMs;

const tokenOf = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

/**
 * The window a witness offer made at `WINDOW_START` names: the one before,
 * closed on the clock and retained, the way the carrier runtime offers one.
 */
const WITNESSED = CHAIN_START - 1n;

const witnessFor = (
  window: bigint,
  first: number,
  second = 0,
): StoreWitnessRecordV1 => ({
  version: 1,
  witnessedStoreId: new Uint8Array(32).fill(3),
  deliveryProfileHash: PROFILE_HASH,
  ingressWindow: window,
  checkpointHash: Uint8Array.from({ length: 32 }, (_, index) =>
    index === 0 ? first : index === 1 ? second : 0x44,
  ),
});

/** Bind every method a proxy hands out, except the ones it overrides. */
const delegate = <T extends object>(
  target: T,
  overrides: Partial<Record<string | symbol, unknown>>,
): T =>
  new Proxy(target, {
    get(inner, property, receiver) {
      if (property in overrides) return overrides[property];
      const value: unknown = Reflect.get(inner, property, receiver);
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(inner)
        : value;
    },
  });

const countedPort = <T extends StorePersistencePort>(
  inner: T,
): {
  readonly port: T;
  readonly calls: () => Record<string, number>;
  readonly cost: () => number;
  readonly reset: () => void;
} => {
  let calls: Record<string, number> = {};
  let recordsReturned = 0;
  const port = new Proxy(inner, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver);
      if (typeof value !== "function") return value;
      return (...args: unknown[]): unknown => {
        const name = String(property);
        calls[name] = (calls[name] ?? 0) + 1;
        const output: unknown = (value as (...a: unknown[]) => unknown).apply(
          target,
          args,
        );
        if (!(output instanceof Promise)) return output;
        return output.then((resolved: unknown) => {
          if (Array.isArray(resolved)) recordsReturned += resolved.length;
          return resolved;
        });
      };
    },
  });
  return {
    port,
    calls: () => ({ ...calls }),
    cost: () =>
      Object.values(calls).reduce((total, count) => total + count, 0) +
      recordsReturned,
    reset: () => {
      calls = {};
      recordsReturned = 0;
    },
  };
};

/**
 * A write-through cache in front of durable rows. `loadWindow` hands back the
 * cached object itself, the way a caching adapter does, and a save reaches the
 * cache only once the durable write succeeded. A restart is a new cache over
 * the same durable rows.
 */
const cachingAdapter = (
  durable: StorePersistencePort,
): {
  readonly port: StorePersistencePort;
  readonly control: { failingSaves: number };
} => {
  const cache = new Map<string, StoreWindowState>();
  const control = { failingSaves: 0 };
  const port = delegate(durable, {
    loadWindow: async (window: bigint): Promise<StoreWindowState | null> => {
      const cached = cache.get(String(window));
      if (cached !== undefined) return cached;
      const loaded = await durable.loadWindow(window);
      if (loaded !== null) cache.set(String(window), loaded);
      return loaded;
    },
    saveWindow: async (state: StoreWindowState): Promise<void> => {
      if (control.failingSaves > 0) {
        control.failingSaves -= 1;
        throw new Error("injected saveWindow failure");
      }
      await durable.saveWindow(state);
      cache.set(String(state.window), copyStoreWindowState(state));
    },
  });
  return { port, control };
};

const storedWindows = async (
  persistence: StorePersistencePort,
  from: bigint,
  through: bigint,
): Promise<bigint[]> => {
  const stored: bigint[] = [];
  for (let window = from; window <= through; window++)
    if ((await persistence.loadWindow(window)) !== null) stored.push(window);
  return stored;
};

const sqliteRoot = mkdtempSync(join(tmpdir(), "p2party-store-hardening-"));
let sqliteCounter = 0;

afterAll(() => {
  rmSync(sqliteRoot, { recursive: true, force: true });
});
const freshSqlite = (): SqliteStorePersistence =>
  new SqliteStorePersistence(
    join(sqliteRoot, `store-${String(sqliteCounter++)}.sqlite`),
  );

const persistenceKinds: readonly (readonly [
  string,
  () => StorePersistencePort & { close?: () => void },
])[] = [
  ["memory", () => new MemoryStorePersistence()],
  ["sqlite", freshSqlite],
];

const grantKey = new Uint8Array(32).fill(0x72);

describe("prototype store append without the mutation queue", () => {
  test("append to a finalized window costs no window load", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core, setNow } = await harness({ persistence: counter.port });
    const { lease, secretKey } = await leaseFor(core);
    const real = await appendRequest(lease, secretKey, 0, objectOf(0x61));
    setNow(FINALIZE_AT);
    expect(await core.finalizeDue()).toEqual([CHAIN_START]);

    counter.reset();
    expect(await verifiedStatus(core, await core.append(real))).toBe(
      "window-finalized",
    );
    expect(
      await verifiedStatus(core, await core.append(coverRequest(objectOf(2)))),
    ).toBe("window-finalized");
    expect(counter.calls()).toEqual({});
  });

  test("an append that needs no state does not wait for the mutation queue", async () => {
    let markEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      markEntered = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const durable = new MemoryStorePersistence();
    const held = delegate<StorePersistencePort>(durable, {
      saveWindow: async (state: StoreWindowState): Promise<void> => {
        markEntered();
        await released;
        await durable.saveWindow(state);
      },
    });
    // The chain-start window is closed on the clock; the next one is open.
    const { core } = await harness({ persistence: held, now: FINALIZE_AT });
    const keyPair = await newKeyPair(cryptoModule);
    const queued = core.allocate(
      allocationRequest(keyPair.publicKey, CHAIN_START + 1n),
    );
    try {
      await entered;
      // The allocation now holds the queue inside its write. None of these
      // answers needs state, so none may wait behind it.
      const beyond = CHAIN_START + BigInt(profile.maxFutureIngressWindows) + 1n;
      expect(
        await verifiedStatus(
          core,
          await core.append(coverRequest(objectOf(1), CHAIN_START)),
        ),
      ).toBe("window-finalized");
      expect(
        await verifiedStatus(
          core,
          await core.append(coverRequest(objectOf(2), CHAIN_START + 1n)),
        ),
      ).toBe("unallocated-cover");
      expect(
        await verifiedStatus(
          core,
          await core.append(coverRequest(objectOf(3), beyond)),
        ),
      ).toBe("capacity-exhausted");
    } finally {
      release();
    }
    expect((await queued).kind).toBe("allocated");
  });

  test("concurrent appends to one slot still bind it once", async () => {
    const { core, persistence } = await harness();
    const { lease, secretKey } = await leaseFor(core);
    const objects = [objectOf(0x91), objectOf(0x92), objectOf(0x91)];
    const requests = await Promise.all(
      objects.map((object) => appendRequest(lease, secretKey, 0, object)),
    );
    // Verification now runs before the queue, so which request reaches the
    // binding first is not fixed; that exactly one binds the slot, and every
    // other answer agrees with what it bound, is.
    const statuses = await Promise.all(
      requests.map(async (request) =>
        verifiedStatus(core, await core.append(request)),
      ),
    );
    const slots = (await persistence.loadWindow(CHAIN_START))?.slots;
    expect(slots?.size).toBe(1);
    const bound = hex([...(slots?.values() ?? [])][0].object);
    expect(statuses.filter((status) => status === "stored")).toHaveLength(1);
    statuses.forEach((status, index) => {
      expect(status).toBe(
        hex(objects[index]) !== bound
          ? "slot-conflict"
          : status === "stored"
            ? "stored"
            : "already-present",
      );
    });
  });

  test("refused appends for finalized, closed and never-existing windows answer alike", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core, setNow } = await harness({ persistence: counter.port });
    setNow(FINALIZE_AT);
    expect(await core.finalizeDue()).toEqual([CHAIN_START]);
    // The next window is now past its finalization instant without having
    // been finalized: the finalizer has simply not run since.
    setNow(NEXT_FINALIZE_AT);

    counter.reset();
    const answers: string[][] = [];
    for (const window of [CHAIN_START, CHAIN_START + 1n, CHAIN_START - 7n]) {
      const result = await core.append(coverRequest(objectOf(0x63), window));
      answers.push([
        await verifiedStatus(core, result),
        hex(result.fixedStatusPadding),
      ]);
    }
    const refusal = ["window-finalized", hex(new Uint8Array(16))];
    expect(answers).toEqual([refusal, refusal, refusal]);
    expect(counter.calls()).toEqual({});
  });
});

describe("prototype store admission on every route", () => {
  test("admission hook is consulted for append and witness", async () => {
    const seen: {
      route: string;
      token: string;
      key: string;
      window: bigint;
    }[] = [];
    const { core } = await harness({
      allocationAdmission: {
        authorize: (request) => {
          seen.push({
            route: request.route,
            token: hex(request.privacyPassToken),
            key: hex(request.allocationEd25519PublicKey),
            window: request.ingressWindow,
          });
          return grantKey;
        },
      },
    });
    const token = tokenOf(0x5e);
    const keyPair = await newKeyPair(cryptoModule);
    const allocation = await core.allocate({
      ...allocationRequest(keyPair.publicKey),
      privacyPassToken: token,
    });
    if (allocation.kind !== "allocated") throw new Error("expected a lease");
    const real = await appendRequest(
      allocation.lease,
      keyPair.secretKey,
      0,
      objectOf(0x64),
    );
    expect(await verifiedStatus(core, await core.append(real, token))).toBe(
      "stored",
    );
    expect(
      await verifiedStatus(
        core,
        await core.append(coverRequest(objectOf(0x65)), token),
      ),
    ).toBe("unallocated-cover");
    expect(await core.addWitness(witnessFor(WITNESSED, 1), token)).toBe(
      "recorded",
    );
    // Presenting nothing is presenting the zero token.
    await core.append(coverRequest(objectOf(0x66)));

    const none = hex(new Uint8Array(32));
    expect(seen).toEqual([
      {
        route: "allocation",
        token: hex(token),
        key: hex(keyPair.publicKey),
        window: CHAIN_START,
      },
      {
        route: "append",
        token: hex(token),
        key: hex(keyPair.publicKey),
        window: CHAIN_START,
      },
      { route: "append", token: hex(token), key: none, window: CHAIN_START },
      { route: "witness", token: hex(token), key: none, window: WITNESSED },
      { route: "append", token: none, key: none, window: CHAIN_START },
    ]);

    // A refusal on either route is its own typed error and leaves no row.
    for (const authorize of [
      (request: { route: string }) =>
        request.route === "allocation" ? grantKey : null,
      (request: { route: string }) =>
        request.route === "allocation" ? grantKey : new Uint8Array(31),
      (request: { route: string }) => {
        if (request.route === "allocation") return grantKey;
        throw new Error("hook failure");
      },
    ]) {
      const refusing = await harness({ allocationAdmission: { authorize } });
      const { lease, secretKey } = await leaseFor(refusing.core);
      const refusedReal = await appendRequest(lease, secretKey, 0, objectOf(7));
      await expect(
        refusing.core.append(refusedReal, token),
      ).rejects.toMatchObject({ name: "StoreAdmissionRefusedError" });
      await expect(
        refusing.core.append(coverRequest(objectOf(8)), token),
      ).rejects.toMatchObject({ name: "StoreAdmissionRefusedError" });
      await expect(
        refusing.core.addWitness(witnessFor(WITNESSED, 2), token),
      ).rejects.toMatchObject({ name: "StoreAdmissionRefusedError" });
      expect(await refusing.persistence.loadWitnessRecords(WITNESSED)).toEqual(
        [],
      );
      expect(
        (await refusing.persistence.loadWindow(CHAIN_START))?.slots.size,
      ).toBe(0);
    }
  });

  test("the admission hook runs after the profile and open-window checks", async () => {
    const routes: string[] = [];
    const { core, setNow } = await harness({
      allocationAdmission: {
        authorize: (request) => {
          routes.push(request.route);
          return grantKey;
        },
      },
    });
    const keyPair = await newKeyPair(cryptoModule);
    const beyond = CHAIN_START + BigInt(profile.maxFutureIngressWindows) + 1n;

    // Allocation: another profile, a closed window, past the horizon.
    for (const request of [
      allocationRequest(keyPair.publicKey, CHAIN_START, OTHER_PROFILE_HASH),
      allocationRequest(keyPair.publicKey, CHAIN_START - 1n),
      allocationRequest(keyPair.publicKey, beyond),
    ])
      expect((await core.allocate(request)).kind).toBe("status");

    // Append: another profile is malformed; a closed window and one past the
    // allocation horizon are answered from the clock.
    const foreign = coverRequest(objectOf(1));
    await expect(
      core.append({
        ...foreign,
        bucket: { ...foreign.bucket, deliveryProfileHash: OTHER_PROFILE_HASH },
      }),
    ).rejects.toThrow(StoreRequestError);
    expect(
      await verifiedStatus(
        core,
        await core.append(coverRequest(objectOf(2), CHAIN_START - 1n)),
      ),
    ).toBe("window-finalized");
    expect(
      await verifiedStatus(
        core,
        await core.append(coverRequest(objectOf(3), beyond)),
      ),
    ).toBe("capacity-exhausted");

    // Witness: another profile, a future window, the current window (open
    // on the clock, so no checkpoint for it can exist), a window past
    // retention.
    expect(
      await core.addWitness({
        ...witnessFor(WITNESSED, 1),
        deliveryProfileHash: OTHER_PROFILE_HASH,
      }),
    ).toBe("not-recorded");
    expect(await core.addWitness(witnessFor(CHAIN_START + 1n, 1))).toBe(
      "not-recorded",
    );
    expect(await core.addWitness(witnessFor(CHAIN_START, 1))).toBe(
      "not-recorded",
    );
    expect(
      await core.addWitness(
        witnessFor(CHAIN_START - BigInt(core.retentionWindows) - 1n, 1),
      ),
    ).toBe("not-recorded");
    expect(routes).toEqual([]);

    // Each route asks the hook exactly once for a request it would serve.
    expect(
      (await core.allocate(allocationRequest(keyPair.publicKey))).kind,
    ).toBe("allocated");
    await core.append(coverRequest(objectOf(4)));
    await core.addWitness(witnessFor(WITNESSED, 2));
    expect(routes).toEqual(["allocation", "append", "witness"]);

    // At the finalization instant the window is closed to both writes.
    setNow(FINALIZE_AT);
    expect(
      (await core.allocate(allocationRequest(keyPair.publicKey))).kind,
    ).toBe("status");
    await core.append(coverRequest(objectOf(5)));
    expect(routes).toEqual(["allocation", "append", "witness"]);
  });
});

describe("prototype store witness bounds", () => {
  test("witness for an unretained window is refused", async () => {
    const persistence = new MemoryStorePersistence();
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const current = CHAIN_START + 300n;
    const { core } = await harness({
      persistence,
      now: windowStartOf(current),
      retentionWindows: retention,
    });
    const outcomes: Record<string, string> = {};
    // Retention is inclusive, as `bucketIsReadable` defines it, and a window
    // is witnessed only once it is closed on the clock.
    const back = BigInt(retention);
    for (const window of [
      current + 500n,
      current + 1n,
      current,
      current - 1n,
      current - back,
      current - back - 1n,
      CHAIN_START,
    ])
      outcomes[String(window - current)] = await core.addWitness(
        witnessFor(window, 1),
      );
    expect(outcomes).toEqual({
      "500": "not-recorded",
      "1": "not-recorded",
      "0": "not-recorded",
      "-1": "recorded",
      [String(-back)]: "recorded",
      [String(-back - 1n)]: "not-recorded",
      "-300": "not-recorded",
    });
    for (const window of [
      current + 500n,
      current + 1n,
      current,
      current - back - 1n,
    ])
      expect(await persistence.loadWitnessRecords(window)).toEqual([]);
  });

  test("a witness for the current window is refused until it closes", async () => {
    const { core, setNow } = await harness();
    expect(await core.addWitness(witnessFor(CHAIN_START, 1))).toBe(
      "not-recorded",
    );
    setNow(FINALIZE_AT - 1n);
    expect(await core.addWitness(witnessFor(CHAIN_START, 1))).toBe(
      "not-recorded",
    );
    setNow(FINALIZE_AT);
    expect(await core.addWitness(witnessFor(CHAIN_START, 1))).toBe("recorded");
  });

  test("witness for the previous window is accepted at its scheduled offset", async () => {
    // The carrier runtime posts its witness for window w-1 at
    // chunkFinalizationOffsetMs - maxScheduleSkewMs into window w.
    const scheduled =
      windowStartOf(CHAIN_START + 1n) +
      profile.chunkFinalizationOffsetMs -
      profile.maxScheduleSkewMs;
    const { core, setNow } = await harness({
      now: scheduled,
      retentionWindows: PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
    });
    expect(await core.addWitness(witnessFor(CHAIN_START, 9))).toBe("recorded");
    // A pair released a window late, skewed, and answered at its deadline.
    setNow(
      windowStartOf(CHAIN_START + 3n) +
        profile.chunkFinalizationOffsetMs +
        profile.maxScheduleSkewMs,
    );
    expect(await core.addWitness(witnessFor(CHAIN_START, 10))).toBe("recorded");
    expect((await core.witnessRecords(CHAIN_START)).length).toBe(2);
  });

  test("witness insert is constant time", async () => {
    for (const [kind, make] of persistenceKinds) {
      const counter = countedPort(make());
      const { core } = await harness({ persistence: counter.port });
      const costs: number[] = [];
      for (let index = 0; index < 96; index++) {
        counter.reset();
        await core.addWitness(witnessFor(WITNESSED, index & 0xff, index >> 8));
        costs.push(counter.cost());
      }
      expect({ kind, costs }).toEqual({
        kind,
        costs: costs.map(() => costs[0]),
      });
      counter.port.close?.();
    }
  });

  test("witness share per admission key is bounded", async () => {
    const share = PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY;
    const { core, persistence } = await harness({
      allocationAdmission: { authorize: (request) => request.privacyPassToken },
    });
    const a = tokenOf(0xa1);
    const b = tokenOf(0xb2);
    const outcomes: string[] = [];
    for (let index = 0; index <= share; index++)
      outcomes.push(await core.addWitness(witnessFor(WITNESSED, index), a));
    expect(outcomes).toEqual([
      ...Array.from({ length: share }, () => "recorded"),
      "not-recorded",
    ]);
    // Another grant has its own share, and re-offering a record already held
    // costs it nothing.
    expect(await core.addWitness(witnessFor(WITNESSED, 0), b)).toBe(
      "already-held",
    );
    expect(await core.addWitness(witnessFor(WITNESSED, share), b)).toBe(
      "recorded",
    );
    // The share is per window.
    expect(await core.addWitness(witnessFor(WITNESSED - 1n, 0), a)).toBe(
      "recorded",
    );
    expect((await persistence.loadWitnessRecords(WITNESSED)).length).toBe(
      share + 1,
    );
  });

  test("concurrent witness inserts never exceed a share", async () => {
    const share = PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY;
    for (const [kind, make] of persistenceKinds) {
      const persistence = make();
      const { core } = await harness({
        persistence,
        allocationAdmission: { authorize: () => grantKey },
      });
      const outcomes = await Promise.all(
        Array.from({ length: share * 3 }, (_, index) =>
          core.addWitness(witnessFor(WITNESSED, index), tokenOf(1)),
        ),
      );
      expect({
        kind,
        recorded: outcomes.filter((outcome) => outcome === "recorded").length,
        held: (await persistence.loadWitnessRecords(WITNESSED)).length,
      }).toEqual({ kind, recorded: share, held: share });
      persistence.close?.();
    }
  });

  test("the window bound refuses the record past it", async () => {
    const bound = PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW;
    const { core, persistence } = await harness();
    for (let index = 0; index < bound; index++)
      if (
        (await core.addWitness(
          witnessFor(WITNESSED, index & 0xff, index >> 8),
        )) !== "recorded"
      )
        throw new Error(`record ${String(index)} was not recorded`);
    expect(await core.addWitness(witnessFor(WITNESSED, 0xff, 0xff))).toBe(
      "not-recorded",
    );
    expect(await core.addWitness(witnessFor(WITNESSED, 0, 0))).toBe(
      "already-held",
    );
    expect((await persistence.loadWitnessRecords(WITNESSED)).length).toBe(
      bound,
    );
  });
});

/**
 * A finalized window row with tiny stand-in chunks. The sweep reads only the
 * window numbers and the tip, so retention tests that need many old rows
 * write them directly instead of finalizing each one.
 */
const syntheticFinalized = (window: bigint): StoreWindowState => ({
  window,
  allocations: new Map(),
  slots: new Map(),
  finalized: {
    chunks: new Map([
      [
        0,
        [
          {
            version: 1,
            bucket: bucketOf(window, 0),
            chunkIndex: 0n,
            previousChunkHash: new Uint8Array(32),
            fixedObjects: [new Uint8Array(8).fill(0x5e)],
            storeSignature: new Uint8Array(64),
          },
        ],
      ],
    ]),
    checkpoint: {
      version: 1,
      storeId: new Uint8Array(32).fill(0x11),
      descriptorHash: new Uint8Array(32).fill(0x12),
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: window,
      chainStartIngressWindow: CHAIN_START,
      previousCheckpointHash: new Uint8Array(32),
      finalizedChunkCount: 1,
      finalizedChunkRoot: new Uint8Array(32),
      storeSignature: new Uint8Array(64),
    },
  },
});

const windowRange = (from: bigint, through: bigint): bigint[] => {
  const windows: bigint[] = [];
  for (let window = from; window <= through; window++) windows.push(window);
  return windows;
};

const RETENTION = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
const BACK = BigInt(RETENTION);

describe("prototype store retention", () => {
  test("sweep bounds stored windows", async () => {
    for (const [kind, make] of persistenceKinds) {
      const persistence = make();
      const { core, setNow } = await harness({
        persistence,
        retentionWindows: RETENTION,
      });
      const last = CHAIN_START + BACK + 11n;
      for (const window of windowRange(CHAIN_START, last))
        await persistence.saveWindow(syntheticFinalized(window));
      setNow(finalizeAtOf(last));
      while ((await core.sweepRetention()).windows > 0);
      // Readable: the retention windows back and the current one. Kept one
      // window longer than readable, so a read that passed its retention
      // check never loads a row the sweep is deleting.
      expect({
        kind,
        stored: await storedWindows(persistence, CHAIN_START, last),
      }).toEqual({ kind, stored: windowRange(last - BACK - 1n, last) });
      persistence.close?.();
    }
  }, 60_000);

  test("one sweep deletes at most one batch", async () => {
    const batch = PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS;
    const persistence = new MemoryStorePersistence();
    const { core, setNow } = await harness({
      persistence,
      retentionWindows: RETENTION,
    });
    const last = CHAIN_START + BACK + 1n + BigInt(batch) + 3n;
    for (const window of windowRange(CHAIN_START, last))
      await persistence.saveWindow(syntheticFinalized(window));
    setNow(finalizeAtOf(last));
    const deleted: number[] = [];
    for (let run = 0; run < 3; run++)
      deleted.push((await core.sweepRetention()).windows);
    // Everything below last - retention - 1 goes, at most one batch per run.
    expect(deleted).toEqual([batch, 3, 0]);
    expect(await storedWindows(persistence, CHAIN_START, last)).toHaveLength(
      RETENTION + 2,
    );
  });

  test("sweep keeps the chain tip and windows the finalizer has not reached", async () => {
    const persistence = new MemoryStorePersistence();
    const { core, setNow } = await harness({
      persistence,
      retentionWindows: RETENTION,
    });
    setNow(finalizeAtOf(CHAIN_START + 2n));
    expect(await core.finalizeDue()).toEqual([
      CHAIN_START,
      CHAIN_START + 1n,
      CHAIN_START + 2n,
    ]);
    // An open window holding a lease, then a finalizer that falls far behind.
    setNow(windowStartOf(CHAIN_START + 3n));
    await leaseFor(core, CHAIN_START + 3n);
    setNow(windowStartOf(CHAIN_START + 3n + BACK + 20n));
    await core.sweepRetention();
    expect(
      await storedWindows(persistence, CHAIN_START, CHAIN_START + 3n),
    ).toEqual([CHAIN_START + 2n, CHAIN_START + 3n]);

    // The chain still extends from the tip the sweep kept.
    setNow(finalizeAtOf(CHAIN_START + 3n));
    expect(await core.finalizeDue()).toEqual([CHAIN_START + 3n]);
    const tip = await persistence.loadWindow(CHAIN_START + 2n);
    const next = await persistence.loadWindow(CHAIN_START + 3n);
    if (tip?.finalized == null || next?.finalized == null)
      throw new Error("expected both windows finalized");
    expect(
      await chainValidSuccessor(
        tip.finalized.checkpoint,
        core.descriptor,
        finalizeAtOf(CHAIN_START + 2n),
        next.finalized.checkpoint,
        core.descriptor,
        finalizeAtOf(CHAIN_START + 3n),
        geometry,
        cryptoModule,
      ),
    ).toEqual({ valid: true });
  });

  test("sweep deletes witness rows and admission bookkeeping with its window", async () => {
    const path = join(
      sqliteRoot,
      `bookkeeping-${String(sqliteCounter++)}.sqlite`,
    );
    const persistence = new SqliteStorePersistence(path);
    try {
      const { core, setNow } = await harness({
        persistence,
        retentionWindows: RETENTION,
        allocationAdmission: {
          authorize: (request) => request.privacyPassToken,
        },
      });
      const keyPair = await newKeyPair(cryptoModule);
      expect(
        (
          await core.allocate({
            ...allocationRequest(keyPair.publicKey),
            privacyPassToken: tokenOf(7),
          })
        ).kind,
      ).toBe("allocated");
      setNow(FINALIZE_AT);
      expect(
        await core.addWitness(witnessFor(CHAIN_START, 1), tokenOf(7)),
      ).toBe("recorded");
      expect(await core.finalizeDue()).toEqual([CHAIN_START]);
      // A later tip, so the window is below both the floor and the tip.
      const tip = CHAIN_START + BACK + 2n;
      await persistence.saveWindow(syntheticFinalized(tip));
      setNow(windowStartOf(tip));
      await core.sweepRetention();
      expect(await persistence.loadWindow(CHAIN_START)).toBeNull();
      expect(await persistence.loadWitnessRecords(CHAIN_START)).toEqual([]);
    } finally {
      persistence.close();
    }

    // No table keeps a row for the swept window, whatever it is called.
    const raw = new Database(path, { readonly: true, safeIntegers: true });
    try {
      const tables = raw
        .query<{ name: string }, []>(
          "SELECT name FROM sqlite_master WHERE type = 'table'",
        )
        .all()
        .map((row) => row.name);
      const leftovers: Record<string, number> = {};
      for (const table of tables) {
        const columns = raw
          .query<{ name: string }, []>(`PRAGMA table_info("${table}")`)
          .all()
          .map((row) => row.name);
        if (!columns.includes("window")) continue;
        leftovers[table] = Number(
          raw
            .query<{ n: bigint }, [bigint]>(
              `SELECT count(*) AS n FROM "${table}" WHERE "window" = ?`,
            )
            .get(CHAIN_START)?.n ?? 0n,
        );
      }
      expect(Object.keys(leftovers).length).toBeGreaterThan(2);
      expect(Object.values(leftovers).every((count) => count === 0)).toBe(true);
    } finally {
      raw.close();
    }
  });

  test("concurrent sweeps and finalization keep the chain intact", async () => {
    const persistence = new MemoryStorePersistence();
    const { core, setNow } = await harness({
      persistence,
      retentionWindows: RETENTION,
    });
    // Rows far below the chain start, which every sweep once the chain has
    // a tip may delete while finalization runs beside it.
    const junk = windowRange(CHAIN_START - 200n, CHAIN_START - 181n);
    for (const window of junk)
      await persistence.saveWindow(emptyStoreWindowState(window));
    const last = CHAIN_START + 9n;
    for (let window = CHAIN_START; window <= last; window++) {
      setNow(finalizeAtOf(window));
      const [finalized, , second] = await Promise.all([
        core.finalizeDue(),
        core.sweepRetention(),
        core.sweepRetention(),
      ]);
      expect(finalized).toEqual([window]);
      // One sweep runs at a time; a call that overlaps it does nothing.
      expect(second).toEqual({ windows: 0, witnessWindows: 0 });
    }
    expect(
      await storedWindows(persistence, CHAIN_START - 200n, CHAIN_START - 1n),
    ).toEqual([]);
    const kept = await storedWindows(persistence, CHAIN_START, last);
    expect(kept).toEqual(windowRange(CHAIN_START, last));
    for (let index = 1; index < kept.length; index++) {
      const previous = await persistence.loadWindow(kept[index - 1]);
      const current = await persistence.loadWindow(kept[index]);
      if (previous?.finalized == null || current?.finalized == null)
        throw new Error("expected finalized windows");
      expect(
        await chainValidSuccessor(
          previous.finalized.checkpoint,
          core.descriptor,
          finalizeAtOf(kept[index - 1]),
          current.finalized.checkpoint,
          core.descriptor,
          finalizeAtOf(kept[index]),
          geometry,
          cryptoModule,
        ),
      ).toEqual({ valid: true });
    }
  }, 60_000);

  test("a failed sweep does not wedge the next one", async () => {
    const durable = new MemoryStorePersistence();
    let failures = 1;
    const flaky = delegate<StorePersistencePort>(durable, {
      deleteWindowsBefore: async (
        window: bigint,
        limit: number,
      ): Promise<number> => {
        if (failures > 0) {
          failures -= 1;
          throw new Error("injected delete failure");
        }
        return durable.deleteWindowsBefore(window, limit);
      },
    });
    const { core, setNow } = await harness({
      persistence: flaky,
      retentionWindows: RETENTION,
    });
    const last = CHAIN_START + BACK + 5n;
    for (const window of windowRange(CHAIN_START, last))
      await durable.saveWindow(syntheticFinalized(window));
    setNow(finalizeAtOf(last));
    await expect(core.sweepRetention()).rejects.toThrow(
      "injected delete failure",
    );
    // Nothing was deleted, and the next call runs rather than finding a
    // sweep still marked in flight.
    expect(await storedWindows(durable, CHAIN_START, last)).toHaveLength(
      RETENTION + 6,
    );
    expect((await core.sweepRetention()).windows).toBe(4);
    expect(await storedWindows(durable, CHAIN_START, last)).toHaveLength(
      RETENTION + 2,
    );
  });

  test("reads past retention answer out-of-range without loading", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core, setNow } = await harness({
      persistence: counter.port,
      retentionWindows: RETENTION,
    });
    setNow(FINALIZE_AT);
    await core.finalizeDue();
    expect(await core.addWitness(witnessFor(CHAIN_START, 1))).toBe("recorded");

    // The last instant the window is retained: still served.
    setNow(windowStartOf(CHAIN_START + BACK + 1n) - 1n);
    expect((await core.readCheckpoint(PROFILE_HASH, CHAIN_START)).kind).toBe(
      "finalized",
    );

    // Past retention it is not served whether or not a sweep has run yet.
    setNow(windowStartOf(CHAIN_START + BACK + 1n));
    counter.reset();
    const checkpoint = await core.readCheckpoint(PROFILE_HASH, CHAIN_START);
    const chunk = await core.readChunk(bucketOf(CHAIN_START, 0), 0n);
    expect([
      checkpoint.kind === "status" ? checkpoint.value.status : "finalized",
      chunk.kind === "status" ? chunk.value.status : "finalized",
      (await core.witnessRecords(CHAIN_START)).length,
    ]).toEqual(["out-of-range", "out-of-range", 0]);
    expect(counter.calls()).toEqual({});
  });

  test("a swept window refuses an append like any closed window", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core, setNow } = await harness({
      persistence: counter.port,
      retentionWindows: RETENTION,
    });
    setNow(FINALIZE_AT);
    await core.finalizeDue();
    const tip = CHAIN_START + BACK + 3n;
    await counter.port.saveWindow(syntheticFinalized(tip));
    setNow(finalizeAtOf(tip));
    await core.sweepRetention();
    expect(await counter.port.loadWindow(CHAIN_START)).toBeNull();
    counter.reset();
    const result = await core.append(coverRequest(objectOf(9), CHAIN_START));
    expect(await verifiedStatus(core, result)).toBe("window-finalized");
    expect(counter.calls()).toEqual({});
  });

  test("retention below the runtime's read-back refuses to start", async () => {
    // The furthest back an honest client's catch-up read lands; one less
    // would answer it out-of-range.
    await expect(
      harness({ retentionWindows: PROTOTYPE_READ_BACK_WINDOWS - 1 }),
    ).rejects.toThrow(StoreConfigurationError);
    expect(
      (await harness({ retentionWindows: PROTOTYPE_READ_BACK_WINDOWS })).core
        .retentionWindows,
    ).toBe(PROTOTYPE_READ_BACK_WINDOWS);
  });

  test("a changed descriptor setting refuses to extend the chain, with a typed error", async () => {
    const persistence = new MemoryStorePersistence();
    const first = await harness({ persistence, retentionWindows: RETENTION });
    first.setNow(FINALIZE_AT);
    expect(await first.core.finalizeDue()).toEqual([CHAIN_START]);
    const refusal = await harness({
      persistence,
      now: FINALIZE_AT,
      retentionWindows: RETENTION + 1,
    }).then(
      () => null,
      (error: unknown) => error as Error,
    );
    expect(refusal?.name).toBe("StoreDescriptorChangedError");
    expect(refusal).toBeInstanceOf(StoreConfigurationError);
    expect(refusal?.message).toContain("retention");
    expect(refusal?.message).toContain("restore the setting");
    expect(refusal?.message).toContain("start a new chain");
    // The original setting still serves the chain.
    const resumed = await harness({
      persistence,
      now: FINALIZE_AT,
      retentionWindows: RETENTION,
    });
    expect(
      (await resumed.core.readCheckpoint(PROFILE_HASH, CHAIN_START)).kind,
    ).toBe("finalized");
  });

  test("retention outside its bounds refuses to start", async () => {
    const minimum = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    for (const retentionWindows of [
      0,
      minimum - 1,
      minimum + 0.5,
      Number.NaN,
      profile.carrierRetentionWindows + 1,
    ])
      await expect(harness({ retentionWindows })).rejects.toThrow(
        StoreConfigurationError,
      );
    expect(
      (await harness({ retentionWindows: minimum })).core.retentionWindows,
    ).toBe(minimum);
    expect((await harness()).core.retentionWindows).toBe(
      PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS,
    );
  });

  test("the signed descriptor states the configured retention", async () => {
    const { core } = await harness({ retentionWindows: RETENTION + 5 });
    expect(core.descriptor.retentionWindows).toBe(RETENTION + 5);
    expect(
      (
        await validateStoreDescriptor(
          core.descriptor,
          WINDOW_START,
          cryptoModule,
        )
      ).valid,
    ).toBe(true);
    // The field is under the signature: changing it breaks the descriptor.
    expect(
      (
        await validateStoreDescriptor(
          { ...core.descriptor, retentionWindows: RETENTION + 6 },
          WINDOW_START,
          cryptoModule,
        )
      ).valid,
    ).toBe(false);
  });
});

describe("prototype store mutation queue", () => {
  test("a refused allocation costs no window load", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core } = await harness({
      persistence: counter.port,
      allocationAdmission: { authorize: () => null },
    });
    counter.reset();
    const keyPair = await newKeyPair(cryptoModule);
    for (const window of [CHAIN_START, CHAIN_START + 1n]) {
      const result = await core.allocate(
        allocationRequest(keyPair.publicKey, window),
      );
      if (result.kind !== "status") throw new Error("expected a refusal");
      expect(result.value.status).toBe("invalid-token");
    }
    expect(counter.calls()).toEqual({});
  });

  test("a capacity-exhausted allocation costs no window load", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core } = await harness({ persistence: counter.port });
    for (let index = 0; index < profile.cohortAllocationsPerWindow; index++)
      await leaseFor(core);
    // The window was loaded once, by the first allocation; the cohort is
    // full now, and the store knows it without loading again.
    expect(counter.calls().loadWindow).toBe(1);
    counter.reset();
    const keyPair = await newKeyPair(cryptoModule);
    const result = await core.allocate(allocationRequest(keyPair.publicKey));
    if (result.kind !== "status") throw new Error("expected a refusal");
    expect(result.value.status).toBe("capacity-exhausted");
    expect(counter.calls()).toEqual({});
  });

  test("a replayed append costs no window load", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core } = await harness({ persistence: counter.port });
    const { lease, secretKey } = await leaseFor(core);
    const request = await appendRequest(lease, secretKey, 0, objectOf(0x81));
    expect(await verifiedStatus(core, await core.append(request))).toBe(
      "stored",
    );
    counter.reset();
    expect(await verifiedStatus(core, await core.append(request))).toBe(
      "already-present",
    );
    expect(
      await verifiedStatus(
        core,
        await core.append(
          await appendRequest(lease, secretKey, 0, objectOf(0x82)),
        ),
      ),
    ).toBe("slot-conflict");
    // And an exact allocation retry replays its lease the same way.
    const keyPair = await newKeyPair(cryptoModule);
    const first = await core.allocate(allocationRequest(keyPair.publicKey));
    counter.reset();
    expect(
      encodePublicAllocationResultV1(
        await core.allocate(allocationRequest(keyPair.publicKey)),
      ),
    ).toEqual(encodePublicAllocationResultV1(first));
    expect(counter.calls()).toEqual({});
  });

  /** Yield turns of the event loop until `ready` holds; bounded in turns. */
  const turnsUntil = async (ready: () => boolean): Promise<void> => {
    for (let turn = 0; turn < 200_000 && !ready(); turn++) await Bun.sleep(0);
    if (!ready()) throw new Error("the condition never held");
  };

  const heldSaves = (): {
    readonly persistence: StorePersistencePort;
    readonly release: () => void;
  } => {
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const durable = new MemoryStorePersistence();
    const persistence = delegate<StorePersistencePort>(durable, {
      saveWindow: async (state: StoreWindowState): Promise<void> => {
        await released;
        await durable.saveWindow(state);
      },
    });
    return { persistence, release };
  };

  /** Start one allocation and record how it settles, without awaiting it. */
  const started = (
    core: PrototypeStoreCore,
    publicKey: Uint8Array,
    window = CHAIN_START,
  ): { readonly done: Promise<void>; outcome: string | null } => {
    const tracked: { done: Promise<void>; outcome: string | null } = {
      done: Promise.resolve(),
      outcome: null,
    };
    tracked.done = core.allocate(allocationRequest(publicKey, window)).then(
      (result) => {
        tracked.outcome =
          result.kind === "allocated" ? "allocated" : result.value.status;
      },
      (error: unknown) => {
        tracked.outcome = (error as Error).name;
      },
    );
    return tracked;
  };

  test("the queue sheds above its depth bound and holds no request body", async () => {
    const { persistence, release } = heldSaves();
    const { core } = await harness({ persistence });
    const bound = PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH;
    // Distinct keys for one open window: each may need a new lease, so each
    // takes a place on the queue until it is full.
    const keys = await Promise.all(
      Array.from({ length: bound + 3 }, () => newKeyPair(cryptoModule)),
    );
    const requests = keys.map((keyPair) => started(core, keyPair.publicKey));
    await turnsUntil(
      () =>
        core.mutationQueueSaturated &&
        requests.filter((request) => request.outcome !== null).length === 3,
    );
    // The three past the bound were refused, and left nothing queued.
    expect(
      requests
        .map((request) => request.outcome)
        .filter((outcome) => outcome !== null),
    ).toEqual(["StoreBusyError", "StoreBusyError", "StoreBusyError"]);
    expect(core.mutationQueueDepth).toBe(bound);
    release();
    await Promise.all(requests.map((request) => request.done));
    expect(
      requests.filter((request) => request.outcome === "allocated"),
    ).toHaveLength(profile.cohortAllocationsPerWindow);
    expect(core.mutationQueueDepth).toBe(0);
  });

  test("an allocation behind 200 queued requests waits at most the queue bound", async () => {
    const { persistence, release } = heldSaves();
    const { core } = await harness({ persistence });
    const bound = PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH;
    // The audit's shape: 200 requests that each need the queue, then one
    // honest allocation. Its wait is counted in queue positions: the requests
    // queued ahead of it.
    const flood = await Promise.all(
      Array.from({ length: 200 }, () => newKeyPair(cryptoModule)),
    );
    const requests = flood.map((keyPair) => started(core, keyPair.publicKey));
    await turnsUntil(
      () =>
        requests.filter((request) => request.outcome !== null).length ===
        200 - bound,
    );
    // At most the bound is ever queued ahead of anything...
    expect(core.mutationQueueDepth).toBe(bound);
    const honestKey = await newKeyPair(cryptoModule);
    const honest = started(core, honestKey.publicKey, CHAIN_START + 1n);
    await honest.done;
    // ...and with the queue full the honest request is answered at once, as
    // one failed request, rather than waiting behind the flood.
    expect(honest.outcome).toBe("StoreBusyError");
    release();
    await Promise.all(requests.map((request) => request.done));
    expect(core.mutationQueueDepth).toBe(0);
    // Once the flood has drained its next attempt is served at once.
    const retried = started(core, honestKey.publicKey, CHAIN_START + 1n);
    await retried.done;
    expect(retried.outcome).toBe("allocated");
  });

  test("a replay and a full-cohort refusal are answered while the queue is blocked", async () => {
    const blockedWindow = CHAIN_START + 1n;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    let markBlocked!: () => void;
    const blocked = new Promise<void>((resolve) => {
      markBlocked = resolve;
    });
    const durable = new MemoryStorePersistence();
    const persistence = delegate<StorePersistencePort>(durable, {
      saveWindow: async (state: StoreWindowState): Promise<void> => {
        if (state.window === blockedWindow) {
          markBlocked();
          await released;
        }
        await durable.saveWindow(state);
      },
    });
    const { core } = await harness({ persistence });
    // A full cohort and one bound slot, committed before the queue blocks.
    const leases: { lease: PublicAllocationLeaseV1; secretKey: Uint8Array }[] =
      [];
    const keys: Uint8Array[] = [];
    for (let index = 0; index < profile.cohortAllocationsPerWindow; index++) {
      const keyPair = await newKeyPair(cryptoModule);
      keys.push(keyPair.publicKey);
      const result = await core.allocate(allocationRequest(keyPair.publicKey));
      if (result.kind !== "allocated") throw new Error("expected a lease");
      leases.push({ lease: result.lease, secretKey: keyPair.secretKey });
    }
    const append = await appendRequest(
      leases[0].lease,
      leases[0].secretKey,
      0,
      objectOf(0x83),
    );
    expect(await verifiedStatus(core, await core.append(append))).toBe(
      "stored",
    );

    // The queue now holds one unit inside a write that does not return.
    const holder = await newKeyPair(cryptoModule);
    const holding = core.allocate(
      allocationRequest(holder.publicKey, blockedWindow),
    );
    await blocked;
    expect(core.mutationQueueDepth).toBe(1);

    const answers: Record<string, string> = {};
    const replay = core.allocate(allocationRequest(keys[3])).then((result) => {
      answers.replay =
        result.kind === "allocated"
          ? `lease ${String(result.lease.allocationOrdinal)}`
          : result.value.status;
    });
    const late = await newKeyPair(cryptoModule);
    const full = core
      .allocate(allocationRequest(late.publicKey))
      .then((result) => {
        answers.full =
          result.kind === "allocated" ? "allocated" : result.value.status;
      });
    const appendReplay = core.append(append).then(async (result) => {
      answers.append = await verifiedStatus(core, result);
    });
    // Bounded in turns of the event loop: a regression that put these behind
    // the queue fails here, by assertion, not by the test's timeout.
    for (
      let turn = 0;
      turn < 200_000 && Object.keys(answers).length < 3;
      turn++
    )
      await Bun.sleep(0);
    expect(answers).toEqual({
      replay: `lease ${String(leases[3].lease.allocationOrdinal)}`,
      full: "capacity-exhausted",
      append: "already-present",
    });
    expect(core.mutationQueueDepth).toBe(1);
    release();
    await Promise.all([holding, replay, full, appendReplay]);
  });

  test("a cover append presents an all-zero allocation key to the admission hook", async () => {
    const keys: string[] = [];
    const { core } = await harness({
      allocationAdmission: {
        authorize: (request) => {
          if (request.route === "append")
            keys.push(hex(request.allocationEd25519PublicKey));
          return grantKey;
        },
      },
    });
    const { lease, secretKey } = await leaseFor(core);
    await core.append(coverRequest(objectOf(0x91)));
    await core.append(await appendRequest(lease, secretKey, 0, objectOf(0x92)));
    // A hook may tell cover from an append under a lease by this field.
    expect(keys).toEqual([
      hex(new Uint8Array(32)),
      hex(lease.allocationEd25519PublicKey),
    ]);
  });

  test("allocations and appends below the chain start are refused from the clock", async () => {
    // A chain that starts in the future: windows before it are open on the
    // clock, but none of them will ever be finalized.
    const counter = countedPort(new MemoryStorePersistence());
    const { core } = await harness({
      persistence: counter.port,
      chainStart: CHAIN_START + 2n,
    });
    counter.reset();
    const keyPair = await newKeyPair(cryptoModule);
    const allocation = await core.allocate(
      allocationRequest(keyPair.publicKey, CHAIN_START + 1n),
    );
    if (allocation.kind !== "status") throw new Error("expected a refusal");
    expect(allocation.value.status).toBe("window-closed");
    expect(
      await verifiedStatus(
        core,
        await core.append(coverRequest(objectOf(1), CHAIN_START + 1n)),
      ),
    ).toBe("window-finalized");
    expect(counter.calls()).toEqual({});
  });
});

describe("prototype store reads of open windows", () => {
  test("reads of an open window answer not-final without loading", async () => {
    const counter = countedPort(new MemoryStorePersistence());
    const { core } = await harness({ persistence: counter.port });
    await leaseFor(core);
    counter.reset();
    const checkpoint = await core.readCheckpoint(PROFILE_HASH, CHAIN_START);
    const chunk = await core.readChunk(bucketOf(CHAIN_START, 0), 0n);
    expect([
      checkpoint.kind === "status" ? checkpoint.value.status : "finalized",
      chunk.kind === "status" ? chunk.value.status : "finalized",
    ]).toEqual(["not-final", "not-final"]);
    expect(counter.calls()).toEqual({});
  });
});

describe("prototype store restart from disk", () => {
  test("failed save leaves append state unchanged in the same process", async () => {
    const durable = new MemoryStorePersistence();
    const first = cachingAdapter(durable);
    const before = await harness({ persistence: first.port });
    const { lease, secretKey } = await leaseFor(before.core);
    const request = await appendRequest(lease, secretKey, 0, objectOf(0x71));
    first.control.failingSaves = 1;
    await expect(before.core.append(request)).rejects.toThrow(
      "injected saveWindow failure",
    );
    // Nothing was committed, so the same process must not now answer as if
    // the slot were bound.
    expect(
      await verifiedStatus(before.core, await before.core.append(request)),
    ).toBe("stored");
  });

  test("failed save leaves append state unchanged after restart", async () => {
    const path = join(sqliteRoot, `restart-${String(sqliteCounter++)}.sqlite`);
    let disk = new SqliteStorePersistence(path);
    try {
      const before = await harness({ persistence: cachingAdapter(disk).port });
      const { lease, secretKey } = await leaseFor(before.core);
      const preFailure = await disk.loadWindow(CHAIN_START);
      const adapter = cachingAdapter(disk);
      const running = await harness({ persistence: adapter.port });
      const request = await appendRequest(lease, secretKey, 0, objectOf(0x73));
      adapter.control.failingSaves = 1;
      await expect(running.core.append(request)).rejects.toThrow(
        "injected saveWindow failure",
      );
      // No retry: the process stops here, and the file is opened again.
      disk.close();
      disk = new SqliteStorePersistence(path);
      const reopened = await disk.loadWindow(CHAIN_START);
      if (preFailure === null || reopened === null)
        throw new Error("expected the window row");
      expect(reopened.slots.size).toBe(0);
      expect(
        [...reopened.allocations.values()].map((record) =>
          hex(record.requestHash),
        ),
      ).toEqual(
        [...preFailure.allocations.values()].map((record) =>
          hex(record.requestHash),
        ),
      );
      const restarted = await harness({ persistence: disk });
      expect(
        await verifiedStatus(
          restarted.core,
          await restarted.core.append(request),
        ),
      ).toBe("stored");
    } finally {
      disk.close();
    }
  });

  test("failed save leaves finalize state unchanged in the same process", async () => {
    const durable = new MemoryStorePersistence();
    const first = cachingAdapter(durable);
    const before = await harness({ persistence: first.port });
    // A lease gives the window a row, which the cache then holds.
    await leaseFor(before.core);
    before.setNow(FINALIZE_AT);
    first.control.failingSaves = 1;
    await expect(before.core.finalizeDue()).rejects.toThrow(
      "injected saveWindow failure",
    );
    // A checkpoint served now and a different one signed after a restart
    // would be the store equivocating, so nothing uncommitted may be served;
    // and the window has closed on the clock, so a signed `not-final` would
    // contradict the store's own clock. The answer is an unsigned busy.
    await expect(
      before.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
    ).rejects.toThrow(StoreFinalizationPendingError);
  });

  test("failed save leaves finalize state unchanged after restart", async () => {
    const path = join(sqliteRoot, `restart-${String(sqliteCounter++)}.sqlite`);
    let disk = new SqliteStorePersistence(path);
    try {
      const adapter = cachingAdapter(disk);
      const before = await harness({ persistence: adapter.port });
      await leaseFor(before.core);
      before.setNow(FINALIZE_AT);
      adapter.control.failingSaves = 1;
      await expect(before.core.finalizeDue()).rejects.toThrow(
        "injected saveWindow failure",
      );
      // No retry: the process stops here, and the file is opened again.
      disk.close();
      disk = new SqliteStorePersistence(path);
      expect((await disk.loadWindow(CHAIN_START))?.finalized).toBeNull();
      expect(await disk.lastFinalizedWindow()).toBeNull();
      const restarted = await harness({ persistence: disk, now: FINALIZE_AT });
      await expect(
        restarted.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
      ).rejects.toThrow(StoreFinalizationPendingError);
      expect(await restarted.core.finalizeDue()).toEqual([CHAIN_START]);
    } finally {
      disk.close();
    }
  });
});
