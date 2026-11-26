import { describe, expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";

import libcrypto from "../../../src/cryptography/libcrypto";
import {
  keyPairFromSeed,
  newKeyPair,
  sign,
} from "../../../src/cryptography/ed25519";
import { sha256 } from "../../../src/cryptography/webCryptoSha256";
import {
  deliveryProfileHash,
  publicAllocationLeaseSignedMessage,
  publicCheckpointStatusSigningHash,
} from "../../../src/blindRendezvous/derivations";
import {
  ingressWindowStartMs,
  publicStoreCheckpointHash,
} from "../../../src/blindRendezvous/publicWindow";
import {
  publicCarrierContextId,
  storeId as computeStoreId,
} from "../../../src/blindRendezvous/storeDescriptor";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  carrierObjectWireBytes,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../../../src/blindRendezvous/prototype/storeRoutes";
import {
  PrototypeStoreClient,
  StoreClientError,
  buildAppendAdmission,
} from "../../../src/blindRendezvous/prototype/storeClient";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import {
  decodeAllocationTokenIssueResultV1,
  decodePublicAllocationRequestV1,
  decodePublicAllocationResultV1,
  decodePublicAppendRequestV1,
  decodePublicChunkReadV1,
  encodeAllocationTokenIssueResultV1,
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationResultV1,
  encodePublicChunkReadV1,
  encodePublicStoreCheckpointReadV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type { LibCrypto } from "../../../src/cryptography/libcrypto";
import type { StoreWitnessRecordV1 } from "../../../src/blindRendezvous/prototype/storeWire";

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
const PROFILE_HASH = await deliveryProfileHash(profile);
const PROFILE_HEX = hex(PROFILE_HASH);

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

/** Σ over classes of publicChunksPerWindow × publicChunkObjectCount. */
const OBJECTS_PER_WINDOW = profile.sizeClasses.reduce(
  (total, sizeClass) =>
    total + sizeClass.publicChunksPerWindow * profile.publicChunkObjectCount,
  0,
);

interface Clock {
  now: bigint;
}

interface StoreProcess {
  readonly core: PrototypeStoreCore;
  readonly origin: string;
  readonly stop: () => void;
}

/**
 * A store on a real ephemeral port. The route the store signs must name the
 * origin the client dials, and the port is only known after `Bun.serve`, so
 * the handler is installed one tick after the socket exists.
 */
const startStore = async (
  clock: Clock,
  options: {
    seed?: Uint8Array;
    fault?: "withhold" | null;
    chainStart?: bigint;
  } = {},
): Promise<StoreProcess> => {
  let handler: ((request: Request) => Promise<Response>) | null = null;
  const server = Bun.serve({
    port: 0,
    fetch: (request: Request): Response | Promise<Response> =>
      handler === null
        ? new Response("not ready", { status: 503 })
        : handler(request),
  });
  const origin = server.url.origin;
  const core = await PrototypeStoreCore.create({
    module: cryptoModule,
    seed: options.seed ?? SEED,
    profile,
    clock: { nowMs: () => clock.now },
    persistence: new MemoryStorePersistence(),
    chainStartIngressWindow: options.chainStart ?? CHAIN_START,
    origin,
    descriptorValidityMs: 2_592_000_000n,
    fault: options.fault ?? null,
  });
  handler = createPrototypeStoreHandler({ core });
  return {
    core,
    origin,
    stop: () => {
      void server.stop(true);
    },
  };
};

const withStore = async (
  run: (store: StoreProcess, clock: Clock) => Promise<void>,
  options: { seed?: Uint8Array; fault?: "withhold" | null } = {},
): Promise<void> => {
  const clock: Clock = { now: WINDOW_START };
  const store = await startStore(clock, options);
  try {
    await run(store, clock);
  } finally {
    store.stop();
  }
};

const connect = async (
  origin: string,
  clock: Clock,
  overrides: { profileHash?: Uint8Array; fetch?: typeof fetch } = {},
): Promise<PrototypeStoreClient> =>
  PrototypeStoreClient.connect({
    origin,
    profile,
    profileHash: overrides.profileHash ?? PROFILE_HASH,
    module: cryptoModule,
    fetch: overrides.fetch,
    nowMs: () => clock.now,
  });

const chunkHeaders = {
  "x-p2party-store": "prototype-v0",
  "content-type": PROTOTYPE_STORE_MEDIA_TYPES.chunk,
};

const headersOf = (mediaType: string): Record<string, string> => ({
  "x-p2party-store": "prototype-v0",
  "content-type": mediaType,
});

/** The store's own signing key: the tests know the seed it was started from. */
const storeSecretKey = async (): Promise<Uint8Array> =>
  (await keyPairFromSeed(Uint8Array.from(SEED), cryptoModule)).secretKey;

/** `lib.dom`'s `BufferSource` is narrower than the codecs' `Uint8Array`. */
const asBody = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

/** Checkpoints from one store, chunks from another: the root cannot match. */
const spliceChunks = (
  checkpointOrigin: string,
  chunkOrigin: string,
): typeof fetch =>
  ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const target = url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.chunk}/`)
      ? chunkOrigin
      : checkpointOrigin;
    return fetch(`${target}${url.pathname}${url.search}`, init);
  }) as typeof fetch;

const leaseFor = async (
  client: PrototypeStoreClient,
  window: bigint,
): Promise<{
  lease: NonNullable<Awaited<ReturnType<PrototypeStoreClient["allocate"]>>>;
  secretKey: Uint8Array;
}> => {
  const keyPair = await newKeyPair(cryptoModule);
  const lease = await client.allocate(window, keyPair);
  if (lease === null) throw new Error("expected a lease");
  return { lease, secretKey: keyPair.secretKey };
};

/** Allocate, admit and append one object, and remember the receipt. */
const appendObject = async (
  client: PrototypeStoreClient,
  window: bigint,
  fill: number,
): Promise<Uint8Array> => {
  const { lease, secretKey } = await leaseFor(client, window);
  const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(fill);
  const admission = await buildAppendAdmission(
    lease,
    secretKey,
    0,
    0,
    object,
    cryptoModule,
  );
  const result = await client.append(window, 0, object, admission);
  if (result === null) throw new Error("expected an append result");
  expect(result.status).toBe("stored");
  client.recordReceipt({
    window,
    sizeClass: 0,
    lease,
    objectOrdinal: 0,
    objectHash: await sha256(object),
    result,
  });
  return object;
};

describe("prototype store client", () => {
  test("pins the store identity from a descriptor it validated", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);

      expect(hex(client.storeId)).toBe(hex(store.core.storeId));
      expect(client.storeIdHex).toBe(hex(store.core.storeId));
      expect(hex(client.descriptor.storeIdentityEd25519Key)).toBe(
        hex(store.core.descriptor.storeIdentityEd25519Key),
      );
      expect(hex(client.carrierContextId)).toBe(
        hex(
          await publicCarrierContextId(
            await computeStoreId(store.core.descriptor.storeIdentityEd25519Key),
            PROFILE_HASH,
          ),
        ),
      );
      expect(client.origin).toBe(store.origin);
      expect(client.inert).toBe(false);
      expect(client.faults).toEqual([]);
    });
  });

  test("refuses a forged descriptor and an incompatible profile", async () => {
    await withStore(async (store, clock) => {
      const forged: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname !== PROTOTYPE_STORE_ROUTES.descriptor)
          return fetch(`${store.origin}${url.pathname}`, init);
        const document = store.core.descriptorDocument();
        const signature = Uint8Array.from(
          document.descriptor.descriptorSignature,
        );
        signature[0] ^= 0x01;
        return new Response(
          asBody(
            encodePrototypeStoreDescriptorDocumentV1({
              ...document,
              descriptor: {
                ...document.descriptor,
                descriptorSignature: signature,
              },
            }),
          ),
          {
            status: 200,
            headers: {
              "x-p2party-store": "prototype-v0",
              "content-type": PROTOTYPE_STORE_MEDIA_TYPES.descriptor,
            },
          },
        );
      }) as typeof fetch;

      await expect(
        connect(store.origin, clock, { fetch: forged }),
      ).rejects.toThrow(StoreClientError);

      // A store that does not advertise this profile's compatibility hash is
      // refused before any window is read, not half-spoken to.
      await expect(
        connect(store.origin, clock, {
          profileHash: new Uint8Array(32).fill(0xab),
        }),
      ).rejects.toThrow(StoreClientError);
    });
  });

  test("issues a token, allocates a lease and stores an admitted append", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);

      expect(await client.issueToken(CHAIN_START)).toBe(true);

      const { lease, secretKey } = await leaseFor(client, CHAIN_START);
      expect(lease.allocationOrdinal).toBe(0);
      expect(lease.ingressWindow).toBe(CHAIN_START);
      expect(hex(lease.storeId)).toBe(hex(store.core.storeId));

      const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x7c);
      const admission = await buildAppendAdmission(
        lease,
        secretKey,
        0,
        0,
        object,
        cryptoModule,
      );
      const result = await client.append(CHAIN_START, 0, object, admission);
      expect(result?.status).toBe("stored");
      expect(client.faults).toEqual([]);
    });
  });

  test("scans not-final before finalization and finalized after", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);
      const object = await appendObject(client, CHAIN_START, 0x7c);

      const pending = await client.scanWindow(CHAIN_START);
      expect(pending.status).toBe("not-final");
      expect(pending.objects).toEqual([]);
      expect(pending.checkpointHash).toBeNull();
      expect(client.faults).toEqual([]);

      clock.now = FINALIZE_AT;
      expect(await store.core.finalizeDue()).toEqual([CHAIN_START]);

      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("finalized");
      expect(scan.objects.length).toBe(OBJECTS_PER_WINDOW);
      // Allocation ordinal 0, object ordinal 0: class 0, chunk 0, object 0.
      expect(hex(scan.objects[0])).toBe(hex(object));
      expect(scan.checkpointHash).not.toBeNull();
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);

      const held = client.checkpointHashFor(CHAIN_START);
      expect(held).not.toBeNull();
      const read = await store.core.readCheckpoint(PROFILE_HASH, CHAIN_START);
      if (read.kind !== "finalized") throw new Error("expected a checkpoint");
      expect(hex(held as Uint8Array)).toBe(
        hex(await publicStoreCheckpointHash(read.checkpoint)),
      );
      expect(client.checkpointHashFor(CHAIN_START + 5n)).toBeNull();
    });
  });

  test("reports a window below the chain start as out-of-range", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);
      const scan = await client.scanWindow(CHAIN_START - 1n);
      expect(scan.status).toBe("out-of-range");
      // Reading before the chain begins is not a fault: no proof attributes it.
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);
    });
  });

  test("detects a withheld object as a custody breach", async () => {
    await withStore(
      async (store, clock) => {
        const client = await connect(store.origin, clock);
        await appendObject(client, CHAIN_START, 0x31);

        clock.now = FINALIZE_AT;
        await store.core.finalizeDue();

        const scan = await client.scanWindow(CHAIN_START);
        // The objects still verify against the checkpoint, so they are still
        // returned; the store is excluded from availability, not from union.
        expect(scan.status).toBe("finalized");
        expect(scan.objects.length).toBe(OBJECTS_PER_WINDOW);
        expect(client.inert).toBe(true);
        expect(client.faults.map((fault) => fault.kind)).toContain(
          "custody-breach",
        );
        expect(client.faults[0].window).toBe(CHAIN_START);
        expect(client.faults[0].storeIdHex).toBe(hex(store.core.storeId));
      },
      { fault: "withhold" },
    );
  });

  test("overlapping custody scans preserve new receipts and consume each receipt once", async () => {
    await withStore(
      async (store, clock) => {
        const client = await connect(store.origin, clock);
        await appendObject(client, CHAIN_START, 0x31);
        clock.now = WINDOW_START + profile.deliveryWindowMs;
        await appendObject(client, CHAIN_START + 1n, 0x32);
        clock.now = NEXT_FINALIZE_AT;
        await store.core.finalizeDue();

        const gates = await Promise.all(
          [CHAIN_START, CHAIN_START + 1n].map(async (window) => {
            const read = await store.core.readChunk(
              {
                deliveryProfileHash: PROFILE_HASH,
                ingressWindow: window,
                sizeClass: 0,
              },
              0n,
            );
            if (read.kind !== "finalized") throw new Error("expected a chunk");
            let entered!: () => void;
            let release!: () => void;
            return {
              objectHex: hex(read.chunk.fixedObjects[0]),
              entered: new Promise<void>((resolve) => {
                entered = resolve;
              }),
              wait: new Promise<void>((resolve) => {
                release = resolve;
              }),
              markEntered: () => entered(),
              release: () => release(),
              held: false,
            };
          }),
        );

        // Pause real WebCrypto only when custody hashes one of these exact
        // public slot objects. Signatures and chunk/checkpoint verification
        // still execute normally; no store-client state is inspected.
        const digest = crypto.subtle.digest.bind(crypto.subtle);
        const digestSpy = spyOn(crypto.subtle, "digest").mockImplementation(
          async (algorithm, data) => {
            const bytes = ArrayBuffer.isView(data)
              ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
              : new Uint8Array(data);
            const gate =
              bytes.length === CLASS_0_OBJECT_BYTES
                ? gates.find(
                    (candidate) =>
                      !candidate.held && candidate.objectHex === hex(bytes),
                  )
                : undefined;
            if (gate !== undefined) {
              gate.held = true;
              gate.markEntered();
              await gate.wait;
            }
            return digest(algorithm, data);
          },
        );
        const scans: ReturnType<PrototypeStoreClient["scanWindow"]>[] = [];
        try {
          const first = client.scanWindow(CHAIN_START);
          scans.push(first);
          await Promise.race([
            gates[0].entered,
            first.then(() => {
              throw new Error("first scan never reached custody hash");
            }),
          ]);
          const second = client.scanWindow(CHAIN_START + 1n);
          scans.push(second);
          await Promise.race([
            gates[1].entered,
            second.then(() => {
              throw new Error("second scan never reached custody hash");
            }),
          ]);

          // The first scan finishes while the second still owns an earlier
          // view of pending receipts. Record another promise in between.
          gates[0].release();
          expect((await first).status).toBe("finalized");
          await appendObject(client, CHAIN_START + 2n, 0x33);
          gates[1].release();
          expect((await second).status).toBe("finalized");

          clock.now = NEXT_FINALIZE_AT + profile.deliveryWindowMs;
          await store.core.finalizeDue();
          expect((await client.scanWindow(CHAIN_START + 2n)).status).toBe(
            "finalized",
          );
          const custodyWindows = () =>
            client.faults
              .filter((fault) => fault.kind === "custody-breach")
              .map((fault) => fault.window);
          const afterNewWindow = custodyWindows();

          // A rescan has no unconsumed promise left to contradict. Restoring
          // receipts from another scan would report duplicate breaches here.
          await client.scanWindow(CHAIN_START);
          await client.scanWindow(CHAIN_START + 1n);
          const expected = [CHAIN_START, CHAIN_START + 1n, CHAIN_START + 2n];
          expect({ afterNewWindow, afterRescan: custodyWindows() }).toEqual({
            afterNewWindow: expected,
            afterRescan: expected,
          });
        } finally {
          for (const gate of gates) gate.release();
          digestSpy.mockRestore();
          await Promise.allSettled(scans);
        }
      },
      { fault: "withhold" },
    );
  }, 30_000);

  test("detects a second checkpoint for one window as a chain fault", async () => {
    const clock: Clock = { now: WINDOW_START };
    const honest = await startStore(clock);
    // The same seed is the same store identity, so both processes sign under
    // one key and produce one storeId — but each fills its dummy slots from
    // its own CSPRNG, so the two checkpoints for one window differ.
    const equivocating = await startStore(clock, { seed: SEED });
    try {
      let branch = honest.origin;
      const switching: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        return fetch(`${branch}${url.pathname}${url.search}`, init);
      }) as typeof fetch;

      const client = await connect(honest.origin, clock, {
        fetch: switching,
      });
      clock.now = FINALIZE_AT;
      await honest.core.finalizeDue();
      await equivocating.core.finalizeDue();

      expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");
      expect(client.inert).toBe(false);
      const honestHash = client.checkpointHashFor(CHAIN_START);
      const honestRead = await honest.core.readCheckpoint(
        PROFILE_HASH,
        CHAIN_START,
      );
      if (honestRead.kind !== "finalized")
        throw new Error("expected a checkpoint");
      expect(hex(honestHash as Uint8Array)).toBe(
        hex(await publicStoreCheckpointHash(honestRead.checkpoint)),
      );

      // The same client now sees the other branch of the same store. Each
      // branch is internally consistent; only holding both proves the fault.
      branch = equivocating.origin;
      const rescan = await client.scanWindow(CHAIN_START);
      expect(rescan.status).toBe("finalized");
      expect(rescan.objects.length).toBe(OBJECTS_PER_WINDOW);
      expect(client.inert).toBe(true);
      expect(client.faults.map((fault) => fault.kind)).toContain("chain-fault");
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("checkpoint-conflict"),
        ),
      ).toBe(true);
      // The hash this client would have witnessed to other stores is the one
      // it saw first; the second branch is evidence, not a replacement.
      expect(hex(client.checkpointHashFor(CHAIN_START) as Uint8Array)).toBe(
        hex(honestHash as Uint8Array),
      );
    } finally {
      honest.stop();
      equivocating.stop();
    }
  });

  test("detects chunks that do not recompute the committed root", async () => {
    const clock: Clock = { now: WINDOW_START };
    const honest = await startStore(clock);
    const other = await startStore(clock, { seed: SEED });
    try {
      clock.now = FINALIZE_AT;
      await honest.core.finalizeDue();
      await other.core.finalizeDue();

      const client = await connect(honest.origin, clock, {
        fetch: spliceChunks(honest.origin, other.origin),
      });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(scan.objects).toEqual([]);
      expect(client.inert).toBe(true);
      expect(client.faults.map((fault) => fault.kind)).toContain(
        "root-mismatch",
      );
    } finally {
      honest.stop();
      other.stop();
    }
  });

  test("refuses a checkpoint served under another store identity", async () => {
    const clock: Clock = { now: WINDOW_START };
    const honest = await startStore(clock);
    const stranger = await startStore(clock, {
      seed: new Uint8Array(32).fill(0x11),
    });
    try {
      clock.now = FINALIZE_AT;
      await honest.core.finalizeDue();
      await stranger.core.finalizeDue();

      const client = await connect(honest.origin, clock, {
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input));
          const target = url.pathname.startsWith(
            `${PROTOTYPE_STORE_ROUTES.checkpoint}/`,
          )
            ? stranger.origin
            : honest.origin;
          return fetch(`${target}${url.pathname}${url.search}`, init);
        }) as typeof fetch,
      });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(client.faults.map((fault) => fault.kind)).toContain(
        "descriptor-invalid",
      );
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("different store identity"),
        ),
      ).toBe(true);
    } finally {
      honest.stop();
      stranger.stop();
    }
  });

  test("refuses a lease whose ordinal names no slot in the geometry", async () => {
    await withStore(async (store, clock) => {
      const secretKey = await storeSecretKey();
      const forging: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        const response = await fetch(
          `${store.origin}${url.pathname}${url.search}`,
          init,
        );
        if (url.pathname !== PROTOTYPE_STORE_ROUTES.allocation) return response;
        const result = decodePublicAllocationResultV1(
          new Uint8Array(await response.arrayBuffer()),
        );
        if (result.kind !== "allocated") throw new Error("expected a lease");
        // One past the cohort capacity. The ordinal is a plain u32 the store
        // picks, and the store signs it properly — so only a bounds check
        // stands between it and `appendSlotCoordinates`, which throws.
        const { storeSignature: _signature, ...leaseBody } = result.lease;
        const forged = {
          ...leaseBody,
          allocationOrdinal: profile.cohortAllocationsPerWindow,
        };
        return new Response(
          asBody(
            encodePublicAllocationResultV1({
              kind: "allocated",
              lease: {
                ...forged,
                storeSignature: await sign(
                  await publicAllocationLeaseSignedMessage(forged),
                  secretKey,
                  cryptoModule,
                ),
              },
            }),
          ),
          {
            status: 200,
            headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.allocationResult),
          },
        );
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: forging });
      const keyPair = await newKeyPair(cryptoModule);
      expect(await client.allocate(CHAIN_START, keyPair)).toBeNull();
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("outside the cohort capacity"),
        ),
      ).toBe(true);
      // A store choosing a bad ordinal is a refusal, not a crash and not proof
      // of a broken custody promise.
      expect(client.inert).toBe(false);
    });
  });

  test("refuses a signed chain-unavailable its own descriptor contradicts", async () => {
    await withStore(async (store, clock) => {
      const value = {
        version: 1 as const,
        storeId: store.core.storeId,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        status: "chain-unavailable" as const,
      };
      const body = encodePublicStoreCheckpointReadV1({
        kind: "status",
        value,
        storeSignature: await sign(
          await publicCheckpointStatusSigningHash(value),
          await storeSecretKey(),
          cryptoModule,
        ),
      });
      const denying: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          return Promise.resolve(
            new Response(asBody(body), {
              status: 200,
              headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
            }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: denying });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("denies a profile chain its own descriptor"),
        ),
      ).toBe(true);
    });
  });

  test("refuses a chunk the store withholds from a window it finalized", async () => {
    await withStore(async (store, clock) => {
      const path = `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(CHAIN_START)}/0/0`;
      // A genuine signed `not-final` for this exact chunk, taken while the
      // window was open and replayed after the store finalized it.
      const pending = new Uint8Array(
        await (await fetch(`${store.origin}${path}`)).arrayBuffer(),
      );
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();

      const withholding: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname === path)
          return Promise.resolve(
            new Response(asBody(pending), {
              status: 200,
              headers: chunkHeaders,
            }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: withholding });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("withholds chunk 0 of class 0"),
        ),
      ).toBe(true);
    });
  });

  test("refuses a checkpoint anchored to another chain start", async () => {
    const clock: Clock = { now: WINDOW_START };
    const honest = await startStore(clock);
    // The same identity key, a chain that claims to begin one window later:
    // a store restarting its own accountability chain.
    const restarted = await startStore(clock, {
      seed: SEED,
      chainStart: CHAIN_START + 1n,
    });
    try {
      clock.now = NEXT_FINALIZE_AT;
      await honest.core.finalizeDue();
      await restarted.core.finalizeDue();

      const client = await connect(honest.origin, clock, {
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input));
          const target = url.pathname.startsWith(
            `${PROTOTYPE_STORE_ROUTES.checkpoint}/`,
          )
            ? restarted.origin
            : honest.origin;
          return fetch(`${target}${url.pathname}${url.search}`, init);
        }) as typeof fetch,
      });
      const scan = await client.scanWindow(CHAIN_START + 1n);
      expect(scan.status).toBe("unreachable");
      expect(client.faults.map((fault) => fault.kind)).toContain(
        "descriptor-invalid",
      );
      // The key is the one this client pinned, so it is the anchor — not the
      // identity — that this answer contradicts.
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("chain start this store did not pin"),
        ),
      ).toBe(true);
    } finally {
      honest.stop();
      restarted.stop();
    }
  });

  test("refuses a chunk whose signature does not verify", async () => {
    await withStore(async (store, clock) => {
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();

      const tampering: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        const response = await fetch(
          `${store.origin}${url.pathname}${url.search}`,
          init,
        );
        if (!url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.chunk}/`))
          return response;
        const bytes = new Uint8Array(await response.arrayBuffer());
        const read = decodePublicChunkReadV1(bytes);
        if (read.kind !== "finalized")
          return new Response(asBody(bytes), {
            status: 200,
            headers: chunkHeaders,
          });
        const storeSignature = Uint8Array.from(read.chunk.storeSignature);
        storeSignature[0] ^= 0x01;
        return new Response(
          asBody(
            encodePublicChunkReadV1({
              kind: "finalized",
              chunk: { ...read.chunk, storeSignature },
            }),
          ),
          { status: 200, headers: chunkHeaders },
        );
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: tampering });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      // Anyone on the path can corrupt bytes; only the store can equivocate,
      // so an unverifiable chunk is not evidence against the store itself.
      expect(client.inert).toBe(false);
      expect(
        client.faults.some((fault) =>
          fault.detail.includes("chunk signature does not verify"),
        ),
      ).toBe(true);
    });
  });

  test("treats a transport failure as unreachable, never as a throw", async () => {
    await withStore(async (store, clock) => {
      const failing: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          return Promise.resolve(new Response("nope", { status: 502 }));
        if (url.pathname === PROTOTYPE_STORE_ROUTES.allocation)
          return Promise.resolve(
            // A 200 without the protocol header is not this store answering.
            new Response(new ArrayBuffer(0), { status: 200 }),
          );
        if (url.pathname === PROTOTYPE_STORE_ROUTES.token)
          return Promise.resolve(
            // Well-formed transport, bytes that are not the canonical encoding
            // of any token result: nothing here is signed, so nothing is usable.
            new Response(asBody(Uint8Array.of(1, 2, 3)), {
              status: 200,
              headers: {
                "x-p2party-store": "prototype-v0",
                "content-type": PROTOTYPE_STORE_MEDIA_TYPES.tokenResult,
              },
            }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: failing });
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(scan.objects).toEqual([]);
      // Unreachable is not evidence of dishonesty: it must not make the store
      // inert, only unusable for this event.
      expect(client.inert).toBe(false);
      // A non-200 status, a missing protocol header and undecodable bytes are
      // all transport-shaped failures, not a signature this client judged and
      // rejected — they must be `unreachable`, never `signature-invalid`.
      expect(client.faults.map((fault) => fault.kind)).toContain("unreachable");
      expect(
        client.faults.every((fault) => fault.kind !== "signature-invalid"),
      ).toBe(true);

      const keyPair = await newKeyPair(cryptoModule);
      expect(await client.allocate(CHAIN_START, keyPair)).toBeNull();
      expect(await client.issueToken(CHAIN_START)).toBe(false);
    });
  });

  test("keeps an unreachable store live so it can come back", async () => {
    await withStore(async (store, clock) => {
      // The client's own transport, toggled from outside: this is what a
      // store being switched off and switched back on again looks like from
      // the browser's side, as opposed to a store that answered and lied.
      let down = false;
      const flaky: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        if (down) return Promise.reject(new TypeError("fetch failed"));
        return fetch(String(input), init);
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: flaky });
      await appendObject(client, CHAIN_START, 0x9a);
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();

      down = true;
      const outage = await client.scanWindow(CHAIN_START);
      expect(outage.status).toBe("unreachable");
      expect(outage.objects).toEqual([]);
      expect(client.inert).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toContain("unreachable");
      expect(
        client.faults.every((fault) => fault.kind !== "signature-invalid"),
      ).toBe(true);

      // The store comes back, and it is still trusted: nothing about the
      // outage was recorded as a breach, so nothing needed to be forgiven.
      down = false;
      const recovered = await client.scanWindow(CHAIN_START);
      expect(recovered.status).toBe("finalized");
      expect(recovered.objects.length).toBe(OBJECTS_PER_WINDOW);
      expect(client.inert).toBe(false);
    });
  });

  test("records a genuinely bad signature as signature-invalid, not unreachable", async () => {
    await withStore(async (store, clock) => {
      // The store answers, on time, over the wire, with its own protocol
      // header — nothing here is a transport failure. Only the signature
      // itself is wrong, which is the one thing `unreachable` cannot cover.
      const tamperingToken: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        const response = await fetch(String(input), init);
        if (url.pathname !== PROTOTYPE_STORE_ROUTES.token) return response;
        const result = decodeAllocationTokenIssueResultV1(
          new Uint8Array(await response.arrayBuffer()),
        );
        const storeSignature = Uint8Array.from(result.storeSignature);
        storeSignature[0] ^= 0x01;
        return new Response(
          asBody(
            encodeAllocationTokenIssueResultV1({
              body: result.body,
              storeSignature,
            }),
          ),
          {
            status: 200,
            headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.tokenResult),
          },
        );
      }) as typeof fetch;

      const client = await connect(store.origin, clock, {
        fetch: tamperingToken,
      });
      expect(await client.issueToken(CHAIN_START)).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "signature-invalid",
      ]);
      // A bad signature is not a custody or chain breach either — it is
      // evidence for the record, not grounds to exclude the store yet.
      expect(client.inert).toBe(false);
    });
  });

  test("posts and reads witness records, and flags a split view", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();
      expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");

      const record: StoreWitnessRecordV1 = {
        version: 1,
        witnessedStoreId: store.core.storeId,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        checkpointHash: new Uint8Array(32).fill(0xc1),
      };
      expect(await client.postWitness(record)).toBe(true);

      const records = await client.readWitnesses(CHAIN_START);
      expect(records.length).toBe(1);
      expect(hex(records[0].checkpointHash)).toBe(hex(record.checkpointHash));
      // Gossip is not proof: a hint must not make the store inert.
      expect(client.inert).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toContain(
        "checkpoint-split-view-hint",
      );

      expect((await client.readWitnesses(CHAIN_START + 1n)).length).toBe(0);
    });
  });

  test("sends the store nothing but public geometry", async () => {
    await withStore(async (store, clock) => {
      const seen: { path: string; body: Uint8Array | null }[] = [];
      const recording: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        const body =
          init?.body === undefined || init.body === null
            ? null
            : new Uint8Array(init.body as ArrayBuffer);
        seen.push({ path: url.pathname, body });
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;

      const client = await connect(store.origin, clock, { fetch: recording });
      await client.issueToken(CHAIN_START);
      await appendObject(client, CHAIN_START, 0x44);
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();
      await client.scanWindow(CHAIN_START);

      const allowed = new RegExp(
        `^(${PROTOTYPE_STORE_ROUTES.descriptor}` +
          `|${PROTOTYPE_STORE_ROUTES.token}` +
          `|${PROTOTYPE_STORE_ROUTES.allocation}` +
          `|${PROTOTYPE_STORE_ROUTES.append}` +
          `|${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/[0-9]+` +
          `|${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/[0-9]+/[0-9]+/[0-9]+` +
          `|${PROTOTYPE_STORE_ROUTES.witness}/${PROFILE_HEX}/[0-9]+)$`,
      );
      for (const request of seen) expect(request.path).toMatch(allowed);

      // Every POST body decodes as its wire type, whose fields are exactly the
      // profile hash, a window, an ordinal, a key and opaque object bytes.
      for (const request of seen) {
        if (request.body === null) continue;
        if (request.path === PROTOTYPE_STORE_ROUTES.allocation) {
          const decoded = decodePublicAllocationRequestV1(request.body);
          expect(hex(decoded.deliveryProfileHash)).toBe(PROFILE_HEX);
          expect(decoded.ingressWindow).toBe(CHAIN_START);
        }
        if (request.path === PROTOTYPE_STORE_ROUTES.append) {
          const decoded = decodePublicAppendRequestV1(request.body);
          expect(hex(decoded.bucket.deliveryProfileHash)).toBe(PROFILE_HEX);
          expect(decoded.exactFixedObject.length).toBe(CLASS_0_OBJECT_BYTES);
        }
      }
    });
  });

  test("verifies a run of windows as one chain, and forgives a gap", async () => {
    await withStore(async (store, clock) => {
      const client = await connect(store.origin, clock);
      clock.now = NEXT_FINALIZE_AT + profile.deliveryWindowMs;
      expect(await store.core.finalizeDue()).toEqual([
        CHAIN_START,
        CHAIN_START + 1n,
        CHAIN_START + 2n,
      ]);

      expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");
      expect((await client.scanWindow(CHAIN_START + 1n)).status).toBe(
        "finalized",
      );
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);

      // A window this client never read is absence, not blame: no proof can
      // attribute a hole in what one reader happened to retain.
      const partial = await connect(store.origin, clock);
      expect((await partial.scanWindow(CHAIN_START)).status).toBe("finalized");
      expect((await partial.scanWindow(CHAIN_START + 2n)).status).toBe(
        "finalized",
      );
      expect(partial.faults).toEqual([]);
      expect(partial.inert).toBe(false);
    });
  });
});
