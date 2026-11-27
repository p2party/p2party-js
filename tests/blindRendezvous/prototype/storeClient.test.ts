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
  publicChunkStatusSigningHash,
} from "../../../src/blindRendezvous/derivations";
import {
  ingressWindowStartMs,
  publicStoreCheckpointHash,
  publicStoreCheckpointSigningHash,
} from "../../../src/blindRendezvous/publicWindow";
import {
  descriptorHash,
  publicCarrierContextId,
  storeDescriptorSignedMessage,
  storeId as computeStoreId,
  storeRouteSignedMessage,
} from "../../../src/blindRendezvous/storeDescriptor";
import {
  PROTOTYPE_READ_BACK_WINDOWS,
  PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS,
  PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
} from "../../../src/utils/constants";
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
  StoreVersionError,
  buildAppendAdmission,
  judgeSignedRefusal,
  signedStatusProvesFault,
} from "../../../src/blindRendezvous/prototype/storeClient";
import {
  PrototypeStoreCore,
  type PrototypeStoreCoreOptions,
} from "../../../src/blindRendezvous/prototype/store/storeCore";
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
  decodePublicStoreCheckpointReadV1,
  encodePublicStoreCheckpointReadV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type { LibCrypto } from "../../../src/cryptography/libcrypto";
import type { PublicStoreCheckpointV1 } from "../../../src/blindRendezvous/publicWindow";
import type { StoreDescriptorV1 } from "../../../src/blindRendezvous/storeDescriptor";
import type {
  PublicAppendResultV1,
  PublicChunkStatusKindV1,
  PublicStoreCheckpointStatusKindV1,
} from "../../../src/blindRendezvous/prototype/storeWire";
import type {
  StoreClientOptions,
  StoreEvidenceFaultKind,
} from "../../../src/blindRendezvous/prototype/storeClient";
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
    retentionWindows?: number;
    /** How far the store's clock runs ahead of the shared clock. */
    aheadMs?: bigint;
    allocationAdmission?: PrototypeStoreCoreOptions["allocationAdmission"];
    /** Wraps the store's handler, e.g. to answer some routes another way. */
    wrap?: (
      handler: (request: Request) => Promise<Response>,
    ) => (request: Request) => Promise<Response>;
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
    clock: { nowMs: () => clock.now + (options.aheadMs ?? 0n) },
    persistence: new MemoryStorePersistence(),
    chainStartIngressWindow: options.chainStart ?? CHAIN_START,
    origin,
    descriptorValidityMs: 2_592_000_000n,
    fault: options.fault ?? null,
    allocationAdmission: options.allocationAdmission,
    retentionWindows: options.retentionWindows,
  });
  const storeHandler = createPrototypeStoreHandler({ core });
  handler =
    options.wrap === undefined ? storeHandler : options.wrap(storeHandler);
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
  overrides: {
    profileHash?: Uint8Array;
    fetch?: typeof fetch;
    admissionTokens?: StoreClientOptions["admissionTokens"];
  } = {},
): Promise<PrototypeStoreClient> =>
  PrototypeStoreClient.connect({
    origin,
    profile,
    profileHash: overrides.profileHash ?? PROFILE_HASH,
    module: cryptoModule,
    fetch: overrides.fetch,
    nowMs: () => clock.now,
    admissionTokens: overrides.admissionTokens,
  });

const chunkHeaders = {
  "x-p2party-store": "prototype-v1",
  "content-type": PROTOTYPE_STORE_MEDIA_TYPES.chunk,
};

const headersOf = (mediaType: string): Record<string, string> => ({
  "x-p2party-store": "prototype-v1",
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

  test("a store of the previous prototype version is refused with a typed version error", async () => {
    await withStore(async (store, clock) => {
      // A prototype-v0 store knows none of this client's paths: it answers
      // each with its 404, which names its version like every answer it
      // gives. And one reached through a proxy that maps the paths answers
      // 200, still naming its version.
      for (const status of [404, 200]) {
        const previous: typeof fetch = (async () =>
          new Response(status === 404 ? "not found" : "", {
            status,
            headers: {
              "x-p2party-store": "prototype-v0",
              "cache-control": "no-store",
              "content-type": "text/plain; charset=utf-8",
            },
          })) as unknown as typeof fetch;
        const refusal = await connect(store.origin, clock, {
          fetch: previous,
        }).then(
          () => null,
          (error: unknown) => error,
        );
        expect(refusal).toBeInstanceOf(StoreVersionError);
        expect(refusal).toBeInstanceOf(StoreClientError);
        expect(refusal).toMatchObject({
          name: "StoreVersionError",
          storeProtocol: "prototype-v0",
          clientProtocol: "prototype-v1",
        });
      }

      // A store of this version is not.
      const client = await connect(store.origin, clock);
      expect(client.faults).toEqual([]);

      // A store that changes version after `connect` is unreachable from
      // then on, and the record says which version it now speaks.
      const changed = await connect(store.origin, clock, {
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input));
          if (url.pathname === PROTOTYPE_STORE_ROUTES.descriptor)
            return fetch(`${store.origin}${url.pathname}`, init);
          return Promise.resolve(
            new Response("not found", {
              status: 404,
              headers: { "x-p2party-store": "prototype-v2" },
            }),
          );
        }) as typeof fetch,
      });
      expect((await changed.scanWindow(CHAIN_START)).status).toBe(
        "unreachable",
      );
      expect(changed.inert).toBe(false);
      expect(changed.faults.length).toBeGreaterThan(0);
      expect(
        changed.faults.every(
          (fault) =>
            fault.kind === "unreachable" &&
            fault.detail.includes("a prototype-v2 store"),
        ),
      ).toBe(true);
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
              "x-p2party-store": "prototype-v1",
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

  test("a signed chain-unavailable for a profile the descriptor declares is a breach a third party can verify", async () => {
    await withStore(async (store, clock) => {
      const denial = async (
        deliveryProfileHashBytes: Uint8Array,
        storeWindow: bigint,
      ): Promise<Uint8Array> => {
        const value = {
          version: 1 as const,
          storeId: store.core.storeId,
          descriptorHash: store.core.descriptorHash,
          deliveryProfileHash: deliveryProfileHashBytes,
          ingressWindow: CHAIN_START,
          storeIngressWindow: storeWindow,
          status: "chain-unavailable" as const,
        };
        return encodePublicStoreCheckpointReadV1({
          kind: "status",
          value,
          storeSignature: await sign(
            await publicCheckpointStatusSigningHash(value),
            await storeSecretKey(),
            cryptoModule,
          ),
        });
      };
      // The store's own code signs this status only for a profile it does not
      // serve, whatever the window and the clock: asked for its own profile
      // below the chain start, far ahead and now, it never does.
      for (const window of [0n, CHAIN_START - 1n, CHAIN_START, 1n << 40n]) {
        const read = await store.core.readCheckpoint(PROFILE_HASH, window);
        expect(read.kind === "status" ? read.value.status : read.kind).not.toBe(
          "chain-unavailable",
        );
      }

      // Stated a thousand windows from this client's clock: no stated window
      // turns the denial into a clock disagreement.
      for (const storeWindow of [CHAIN_START, CHAIN_START + 1_000n]) {
        const body = await denial(PROFILE_HASH, storeWindow);
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
        expect(client.inert).toBe(true);
        expect(client.faults.map((fault) => fault.kind)).toEqual([
          "chain-denial-breach",
        ]);
        const breach = client.faults[0];
        expect((breach.evidence ?? []).map(hex)).toEqual([hex(body)]);
        // From the kept record alone.
        expect(
          await signedStatusProvesFault(
            breach.descriptor ?? ({} as StoreDescriptorV1),
            profile,
            breach.evidence ?? [],
            cryptoModule,
          ),
        ).toBe("chain-denial-breach");
      }

      // What the store honestly signs, for a profile its descriptor does not
      // declare, proves nothing.
      const foreign = new Uint8Array(32).fill(0x44);
      const honest = await store.core.readCheckpoint(foreign, CHAIN_START);
      expect(honest.kind === "status" ? honest.value.status : honest.kind).toBe(
        "chain-unavailable",
      );
      for (const candidate of [profile, withDeliveryWindowMs(profile, 8_000n)])
        expect(
          await signedStatusProvesFault(
            store.core.descriptor,
            candidate,
            [encodePublicStoreCheckpointReadV1(honest)],
            cryptoModule,
          ),
        ).toBeNull();
    });
  });

  test("a not-final replayed for a chunk of a finalized window is a clock disagreement once no store within the skew could say it", async () => {
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

      // Sent one millisecond before the close plus the skew: a store whose
      // clock is the full skew behind this client's still reads before the
      // close, and its checkpoint and chunk answers can race across it. The
      // window is not final at this store yet, and nothing is recorded.
      const early = await connect(store.origin, clock, { fetch: withholding });
      clock.now = FINALIZE_AT + profile.maxScheduleSkewMs - 1n;
      expect((await early.scanWindow(CHAIN_START)).status).toBe("not-final");
      expect(early.faults).toEqual([]);

      // From the close plus the skew on, no such store can say it.
      const late = await connect(store.origin, clock, { fetch: withholding });
      clock.now = FINALIZE_AT + profile.maxScheduleSkewMs;
      const scan = await late.scanWindow(CHAIN_START);
      expect(scan.status).toBe("clock-disagreement");
      expect(late.inert).toBe(false);
      expect(
        late.faults.map((fault) => [fault.kind, fault.window] as const),
      ).toEqual([["store-clock-disagreement", CHAIN_START]]);
      expect(late.faults[0].detail).toContain("chunk 0 of class 0");
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
                "x-p2party-store": "prototype-v1",
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

describe("prototype store client admission tokens", () => {
  const witnessRecordFor = (window: bigint): StoreWitnessRecordV1 => ({
    version: 1,
    witnessedStoreId: new Uint8Array(32).fill(0x91),
    deliveryProfileHash: PROFILE_HASH,
    ingressWindow: window,
    checkpointHash: new Uint8Array(32).fill(0xc5),
  });
  const routeByte = { allocation: 0xa1, append: 0xa2, witness: 0xa3 } as const;

  /** POST paths a client sent, and the authorization header on each. */
  const recordingFetch = (sent: string[]): typeof fetch =>
    ((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST")
        sent.push(
          `${new URL(String(input)).pathname} ${
            new Headers(init.headers).get("authorization") ?? "-"
          }`,
        );
      return fetch(input, init);
    }) as typeof fetch;

  test("client presents provider tokens", async () => {
    const seen: string[] = [];
    const clock: Clock = { now: WINDOW_START };
    const store = await startStore(clock, {
      allocationAdmission: {
        authorize: (request) => {
          seen.push(`${request.route}:${hex(request.privacyPassToken)}`);
          return request.privacyPassToken;
        },
      },
    });
    try {
      const asked: string[] = [];
      const client = await connect(store.origin, clock, {
        admissionTokens: (request) => {
          asked.push(
            `${request.route} ${hex(request.storeId)} ${request.origin} ${String(request.ingressWindow)}`,
          );
          return {
            storeId: request.storeId,
            token: new Uint8Array(32).fill(routeByte[request.route]),
          };
        },
      });
      const { lease, secretKey } = await leaseFor(client, CHAIN_START);
      const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x51);
      const admission = await buildAppendAdmission(
        lease,
        secretKey,
        0,
        0,
        object,
        cryptoModule,
      );
      expect(
        (await client.append(CHAIN_START, 0, object, admission))?.status,
      ).toBe("stored");
      expect((await client.append(CHAIN_START, 0, object, null))?.status).toBe(
        "unallocated-cover",
      );
      expect(await client.postWitness(witnessRecordFor(CHAIN_START - 1n))).toBe(
        true,
      );

      const tokenHex = (route: keyof typeof routeByte): string =>
        hex(new Uint8Array(32).fill(routeByte[route]));
      expect(seen).toEqual([
        `allocation:${tokenHex("allocation")}`,
        `append:${tokenHex("append")}`,
        `append:${tokenHex("append")}`,
        `witness:${tokenHex("witness")}`,
      ]);
      const pinned = `${hex(store.core.storeId)} ${store.origin}`;
      expect(asked).toEqual([
        `allocation ${pinned} ${String(CHAIN_START)}`,
        `append ${pinned} ${String(CHAIN_START)}`,
        `append ${pinned} ${String(CHAIN_START)}`,
        `witness ${pinned} ${String(CHAIN_START - 1n)}`,
      ]);

      // Open admission stays the default: no provider, no header, zero token.
      seen.length = 0;
      const sent: string[] = [];
      const open = await connect(store.origin, clock, {
        fetch: recordingFetch(sent),
      });
      await open.append(CHAIN_START, 0, object, null);
      expect(sent).toEqual([`${PROTOTYPE_STORE_ROUTES.append} -`]);
      expect(seen).toEqual([`append:${hex(new Uint8Array(32))}`]);
    } finally {
      store.stop();
    }
  });

  test("a token issued for another store is never sent", async () => {
    await withStore(async (store, clock) => {
      const sent: string[] = [];
      const client = await connect(store.origin, clock, {
        fetch: recordingFetch(sent),
        admissionTokens: () => ({
          storeId: new Uint8Array(32).fill(0xee),
          token: new Uint8Array(32).fill(1),
        }),
      });
      const keyPair = await newKeyPair(cryptoModule);
      const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x52);
      await expect(client.allocate(CHAIN_START, keyPair)).rejects.toMatchObject(
        { name: "StoreAdmissionTokenError" },
      );
      await expect(
        client.append(CHAIN_START, 0, object, null),
      ).rejects.toMatchObject({ name: "StoreAdmissionTokenError" });
      await expect(
        client.postWitness(witnessRecordFor(CHAIN_START)),
      ).rejects.toMatchObject({ name: "StoreAdmissionTokenError" });
      expect(sent).toEqual([]);
    });
  });

  test("a failing token provider fails the operation instead of sending without a token", async () => {
    await withStore(async (store, clock) => {
      for (const provider of [
        () => {
          throw new Error("provider down");
        },
        () => Promise.reject(new Error("provider down")),
        (request: { storeId: Uint8Array }) => ({
          storeId: request.storeId,
          token: new Uint8Array(31),
        }),
        () => null,
      ] as unknown as NonNullable<StoreClientOptions["admissionTokens"]>[]) {
        const sent: string[] = [];
        const client = await connect(store.origin, clock, {
          fetch: recordingFetch(sent),
          admissionTokens: provider,
        });
        const keyPair = await newKeyPair(cryptoModule);
        const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x53);
        await expect(
          client.allocate(CHAIN_START, keyPair),
        ).rejects.toMatchObject({ name: "StoreAdmissionTokenError" });
        await expect(
          client.append(CHAIN_START, 0, object, null),
        ).rejects.toMatchObject({ name: "StoreAdmissionTokenError" });
        await expect(
          client.postWitness(witnessRecordFor(CHAIN_START)),
        ).rejects.toMatchObject({ name: "StoreAdmissionTokenError" });
        expect(sent).toEqual([]);
      }
    });
  });

  test("a redirect never carries an admission token to another origin", async () => {
    const reached: string[] = [];
    const sink = Bun.serve({
      port: 0,
      fetch: (request: Request): Response => {
        reached.push(`${request.method} ${new URL(request.url).pathname}`);
        return new Response("sink");
      },
    });
    const clock: Clock = { now: WINDOW_START };
    // Every POST is answered with a redirect to another origin; the
    // descriptor and reads are served normally so the client can connect.
    const store = await startStore(clock, {
      wrap: (handler) => async (request) =>
        request.method === "POST"
          ? new Response(null, {
              status: 307,
              headers: {
                location: `${sink.url.origin}${new URL(request.url).pathname}`,
                "x-p2party-store": "prototype-v1",
              },
            })
          : handler(request),
    });
    try {
      const client = await connect(store.origin, clock, {
        admissionTokens: (request) => ({
          storeId: request.storeId,
          token: new Uint8Array(32).fill(0x77),
        }),
      });
      const keyPair = await newKeyPair(cryptoModule);
      const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x54);
      expect(await client.allocate(CHAIN_START, keyPair)).toBeNull();
      expect(await client.append(CHAIN_START, 0, object, null)).toBeNull();
      expect(await client.postWitness(witnessRecordFor(CHAIN_START))).toBe(
        false,
      );
      expect(reached).toEqual([]);
      expect(client.inert).toBe(false);
    } finally {
      store.stop();
      void sink.stop(true);
    }
  });
});

describe("prototype store client late acknowledgements", () => {
  /**
   * The store answers the append at once; the answer is held from the client
   * until released. Nothing about the store's own behaviour is faked.
   */
  const holdAppendAnswers = (): {
    readonly fetch: typeof fetch;
    readonly answered: Promise<void>;
    readonly release: () => void;
  } => {
    let markAnswered!: () => void;
    const answered = new Promise<void>((resolve) => {
      markAnswered = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const holding = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await fetch(input, init);
      if (
        init?.method !== "POST" ||
        new URL(String(input)).pathname !== PROTOTYPE_STORE_ROUTES.append
      )
        return response;
      const bytes = await response.arrayBuffer();
      markAnswered();
      await released;
      return new Response(bytes, {
        status: response.status,
        headers: response.headers,
      });
    }) as typeof fetch;
    return { fetch: holding, answered, release };
  };

  const appendHeldPastScan = async (
    store: StoreProcess,
    clock: Clock,
    fill: number,
  ): Promise<{
    readonly client: PrototypeStoreClient;
    readonly receipt: Parameters<PrototypeStoreClient["recordReceipt"]>[0];
  }> => {
    const held = holdAppendAnswers();
    const client = await connect(store.origin, clock, { fetch: held.fetch });
    const { lease, secretKey } = await leaseFor(client, CHAIN_START);
    const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(fill);
    const admission = await buildAppendAdmission(
      lease,
      secretKey,
      0,
      0,
      object,
      cryptoModule,
    );
    const pending = client.append(CHAIN_START, 0, object, admission);
    await held.answered;

    clock.now = FINALIZE_AT;
    await store.core.finalizeDue();
    expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");
    expect(
      client.faults.map((fault) => [fault.kind, fault.window] as const),
    ).toEqual([["custody-unacknowledged", CHAIN_START]]);
    expect(client.inert).toBe(false);

    held.release();
    const result = await pending;
    if (result === null) throw new Error("expected an append result");
    expect(result.status).toBe("stored");
    return {
      client,
      receipt: {
        window: CHAIN_START,
        sizeClass: 0,
        lease,
        objectOrdinal: 0,
        objectHash: await sha256(object),
        result,
      },
    };
  };

  test("late acknowledgement is reported unacknowledged", async () => {
    await withStore(async (store, clock) => {
      const { client, receipt } = await appendHeldPastScan(store, clock, 0x41);
      // The store did hold the object, so the late receipt checks out.
      client.recordReceipt(receipt);
      expect(client.inert).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "custody-unacknowledged",
      ]);
    });
  });

  test("a slot missing from the scan is evidence when its acknowledgement arrives late", async () => {
    await withStore(
      async (store, clock) => {
        const { client, receipt } = await appendHeldPastScan(
          store,
          clock,
          0x42,
        );
        // No rescan: the receipt is judged against the scan already made.
        client.recordReceipt(receipt);
        expect(client.inert).toBe(true);
        expect(
          client.faults.map((fault) => [fault.kind, fault.window] as const),
        ).toEqual([
          ["custody-unacknowledged", CHAIN_START],
          ["custody-breach", CHAIN_START],
        ]);
      },
      { fault: "withhold" },
    );
  });
});

describe("prototype store client retention", () => {
  /**
   * A checkpoint status the test store's key signs, stating `storeWindow` as
   * now, under the store's descriptor unless another hash is named.
   */
  const signedCheckpointStatus = async (
    store: StoreProcess,
    window: bigint,
    storeWindow: bigint,
    status: PublicStoreCheckpointStatusKindV1,
    descriptorHashBytes: Uint8Array = store.core.descriptorHash,
  ): Promise<Uint8Array> => {
    const secretKey = await storeSecretKey();
    const storeIdBytes = await computeStoreId(
      (await keyPairFromSeed(Uint8Array.from(SEED), cryptoModule)).publicKey,
    );
    const value = {
      version: 1 as const,
      storeId: storeIdBytes,
      descriptorHash: descriptorHashBytes,
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: window,
      storeIngressWindow: storeWindow,
      status,
    };
    return encodePublicStoreCheckpointReadV1({
      kind: "status",
      value,
      storeSignature: await sign(
        await publicCheckpointStatusSigningHash(value),
        secretKey,
        cryptoModule,
      ),
    });
  };

  /** An out-of-range the test store signs, stating `storeWindow` as now. */
  const signedOutOfRange = (
    store: StoreProcess,
    window: bigint,
    storeWindow: bigint,
  ): Promise<Uint8Array> =>
    signedCheckpointStatus(store, window, storeWindow, "out-of-range");

  /** A chunk status the test store's key signs. */
  const signedChunkStatus = async (
    store: StoreProcess,
    window: bigint,
    sizeClass: number,
    chunkIndex: bigint,
    storeWindow: bigint,
    status: PublicChunkStatusKindV1,
  ): Promise<Uint8Array> => {
    const value = {
      version: 1 as const,
      descriptorHash: store.core.descriptorHash,
      bucket: {
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: window,
        sizeClass,
      },
      chunkIndex,
      storeIngressWindow: storeWindow,
      status,
    };
    return encodePublicChunkReadV1({
      kind: "status",
      value,
      storeSignature: await sign(
        await publicChunkStatusSigningHash(value),
        await storeSecretKey(),
        cryptoModule,
      ),
    });
  };

  /** What a third party concludes from the descriptor and the answers alone. */
  const proves = (
    descriptor: StoreDescriptorV1,
    ...evidence: Uint8Array[]
  ): Promise<string | null> =>
    signedStatusProvesFault(descriptor, profile, evidence, cryptoModule);

  /** One chunk route answered with `body`; everything else by the store. */
  const answeringChunk = (
    store: StoreProcess,
    sizeClass: number,
    chunkIndex: number,
    body: Uint8Array,
  ): typeof fetch =>
    ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (
        url.pathname ===
        `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(CHAIN_START)}/${String(sizeClass)}/${String(chunkIndex)}`
      )
        return Promise.resolve(
          new Response(asBody(body), { status: 200, headers: chunkHeaders }),
        );
      return fetch(`${store.origin}${url.pathname}${url.search}`, init);
    }) as typeof fetch;

  /** Checkpoint reads answered with `body`; everything else by the store. */
  const answeringCheckpoints = (
    store: StoreProcess,
    body: Uint8Array,
  ): typeof fetch =>
    ((input: RequestInfo | URL, init?: RequestInit) => {
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

  test("the descriptor states the store's retention and the client checks it", async () => {
    const clock: Clock = { now: WINDOW_START };
    const store = await startStore(clock, {
      retentionWindows: PROTOTYPE_STORE_MIN_RETENTION_WINDOWS + 3,
    });
    try {
      const client = await connect(store.origin, clock);
      expect(client.descriptor.retentionWindows).toBe(
        PROTOTYPE_STORE_MIN_RETENTION_WINDOWS + 3,
      );

      // The same store, signing a descriptor that states one window less
      // than this client reads back, and a route bound to it.
      const secretKey = await storeSecretKey();
      const document = store.core.descriptorDocument();
      const shortDraft = {
        ...document.descriptor,
        retentionWindows: PROTOTYPE_READ_BACK_WINDOWS - 1,
      };
      const short = {
        ...shortDraft,
        descriptorSignature: await sign(
          await storeDescriptorSignedMessage(shortDraft),
          secretKey,
          cryptoModule,
        ),
      };
      const routeDraft = {
        ...document.routes[0],
        descriptorHash: await descriptorHash(short),
      };
      const route = {
        ...routeDraft,
        routeSignature: await sign(
          await storeRouteSignedMessage(routeDraft),
          secretKey,
          cryptoModule,
        ),
      };
      const serving = (descriptorBytes: Uint8Array): typeof fetch =>
        ((input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input));
          if (url.pathname === PROTOTYPE_STORE_ROUTES.descriptor)
            return Promise.resolve(
              new Response(asBody(descriptorBytes), {
                status: 200,
                headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.descriptor),
              }),
            );
          return fetch(`${store.origin}${url.pathname}${url.search}`, init);
        }) as typeof fetch;
      await expect(
        connect(store.origin, clock, {
          fetch: serving(
            encodePrototypeStoreDescriptorDocumentV1({
              descriptor: short,
              routes: [route],
            }),
          ),
        }),
      ).rejects.toMatchObject({ name: "StoreRetentionError" });

      // A retention changed without the store's signature is no descriptor.
      await expect(
        connect(store.origin, clock, {
          fetch: serving(
            encodePrototypeStoreDescriptorDocumentV1({
              ...document,
              descriptor: {
                ...document.descriptor,
                retentionWindows: PROTOTYPE_STORE_MIN_RETENTION_WINDOWS + 99,
              },
            }),
          ),
        }),
      ).rejects.toThrow(StoreClientError);
    } finally {
      store.stop();
    }
  });

  test("an out-of-range inside the store's own stated retention is a breach a third party can verify", async () => {
    await withStore(async (store, clock) => {
      // Signed one window after the window it refuses: by the store's own
      // two statements, well inside the retention its descriptor states.
      const refusal = await signedOutOfRange(
        store,
        CHAIN_START,
        CHAIN_START + 1n,
      );
      const client = await connect(store.origin, clock, {
        fetch: answeringCheckpoints(store, refusal),
      });
      await appendObject(client, CHAIN_START, 0x61);
      clock.now = NEXT_FINALIZE_AT;
      await store.core.finalizeDue();

      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("unreachable");
      expect(client.inert).toBe(true);
      const breach = client.faults.find(
        (fault) => fault.kind === "retention-breach",
      );
      expect(breach?.window).toBe(CHAIN_START);
      expect((breach?.evidence ?? []).map(hex)).toEqual([hex(refusal)]);
      // Kept with the descriptor the answer names.
      expect(
        hex(await descriptorHash(breach?.descriptor ?? store.core.descriptor)),
      ).toBe(hex(store.core.descriptorHash));
      // The receipt held for the window is reported, not dropped.
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "retention-breach",
        "custody-unchecked",
      ]);

      // Anyone holding the descriptor and the evidence reaches the same
      // verdict, with no clock: the store's own statements convict it.
      const descriptor = breach?.descriptor ?? store.core.descriptor;
      const evidence = breach?.evidence?.[0] ?? new Uint8Array(0);
      expect(await proves(descriptor, evidence)).toBe("retention-breach");
      // Not with an altered answer, nor against another store's descriptor.
      const altered = Uint8Array.from(evidence);
      altered[altered.length - 70] ^= 0x01;
      expect(await proves(descriptor, altered)).toBeNull();
      const other = await startStore(clock, {
        seed: new Uint8Array(32).fill(0x6b),
      });
      try {
        expect(await proves(other.core.descriptor, evidence)).toBeNull();
      } finally {
        other.stop();
      }
    });
  });

  test("an honest store whose clock runs ahead is not blamed", async () => {
    // The re-review's case: the minimum retention, a last-chance catch-up
    // read of W = c - 65 answered during window c + 1, and a store clock two
    // window numbers ahead, which sees the window 68 back and honestly
    // refuses it.
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const current = CHAIN_START + 70n;
    const read = current - 65n;
    const clock: Clock = {
      now: WINDOW_START + 70n * profile.deliveryWindowMs + 100n,
    };
    const store = await startStore(clock, {
      retentionWindows: retention,
      aheadMs: 2n * profile.deliveryWindowMs,
    });
    try {
      while ((await store.core.finalizeDue()).length > 0);
      const answeredNextWindow: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          clock.now += profile.deliveryWindowMs;
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;
      const client = await connect(store.origin, clock, {
        fetch: answeredNextWindow,
      });
      const scan = await client.scanWindow(read);
      expect(scan.status).toBe("clock-disagreement");
      expect(client.inert).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "store-clock-disagreement",
      ]);
      expect(current).toBe(read + 65n);
    } finally {
      store.stop();
    }
  });

  test("a store that states a window far from the client's clock is a clock disagreement, not a breach", async () => {
    await withStore(async (store, clock) => {
      clock.now = NEXT_FINALIZE_AT;
      await store.core.finalizeDue();
      // A refusal for a window one back, excused by a current window a
      // thousand windows ahead: past the retention by the store's own words,
      // but nowhere near this client's clock.
      const excuse = await signedOutOfRange(
        store,
        CHAIN_START,
        CHAIN_START + 1_000n,
      );
      let answered = 0;
      const once: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (
          url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`) &&
          answered++ === 0
        )
          return Promise.resolve(
            new Response(asBody(excuse), {
              status: 200,
              headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
            }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;
      const client = await connect(store.origin, clock, { fetch: once });
      expect((await client.scanWindow(CHAIN_START)).status).toBe(
        "clock-disagreement",
      );
      expect(client.inert).toBe(false);
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "store-clock-disagreement",
      ]);
      expect(await proves(store.core.descriptor, excuse)).toBeNull();
      // Not excluded: the next read of the same window is served.
      expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");
    });
  });

  test("the same out-of-range bytes cannot be replayed as evidence for another time", async () => {
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const clock: Clock = { now: FINALIZE_AT };
    const store = await startStore(clock, { retentionWindows: retention });
    try {
      await store.core.finalizeDue();
      const refusedAt = async (storeWindow: bigint): Promise<Uint8Array> => {
        clock.now = ingressWindowStartMs(storeWindow, profile.deliveryWindowMs);
        return encodePublicStoreCheckpointReadV1(
          await store.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
        );
      };
      // An honest store's expiry, asked twice: two different statements,
      // each naming when it was given, and neither proves anything.
      const first = await refusedAt(CHAIN_START + BigInt(retention) + 1n);
      const later = await refusedAt(CHAIN_START + BigInt(retention) + 9n);
      expect(hex(first)).not.toBe(hex(later));
      for (const bytes of [first, later])
        expect(await proves(store.core.descriptor, bytes)).toBeNull();
      // A refusal the same store signs while the window is retained is a
      // different statement again, and that one does prove withholding.
      const withheld = await signedOutOfRange(
        store,
        CHAIN_START,
        CHAIN_START + 1n,
      );
      expect(hex(withheld)).not.toBe(hex(first));
      expect(await proves(store.core.descriptor, withheld)).toBe(
        "retention-breach",
      );
    } finally {
      store.stop();
    }
  });

  test("a refusal for a chunk that does not exist is not evidence of withholding", async () => {
    // The re-review's two calls, against a real core, for the window one
    // back: an index one past class 0's count, and a class the profile does
    // not define.
    const clock: Clock = { now: NEXT_FINALIZE_AT };
    const store = await startStore(clock);
    try {
      while ((await store.core.finalizeDue()).length > 0);
      const count = BigInt(
        profile.sizeClasses.find((sizeClass) => sizeClass.id === 0)
          ?.publicChunksPerWindow ?? 0,
      );
      const bucket = (sizeClass: number) => ({
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        sizeClass,
      });
      const reads = [
        await store.core.readChunk(bucket(0), count),
        await store.core.readChunk(bucket(9), 0n),
      ];
      for (const read of reads) {
        expect(read.kind === "status" ? read.value.status : read.kind).toBe(
          "no-such-chunk",
        );
        expect(
          await proves(store.core.descriptor, encodePublicChunkReadV1(read)),
        ).toBeNull();
      }
      // The same coordinates refused as `out-of-range` under the store's key,
      // as the store signed them before: still nothing, since the profile
      // defines no such chunk.
      for (const [sizeClass, index] of [
        [0, count],
        [9, 0n],
      ] as const)
        expect(
          await proves(
            store.core.descriptor,
            await signedChunkStatus(
              store,
              CHAIN_START,
              sizeClass,
              index,
              CHAIN_START + 1n,
              "out-of-range",
            ),
          ),
        ).toBeNull();
      // While a chunk that does exist, refused that way, is withheld.
      expect(
        await proves(
          store.core.descriptor,
          await signedChunkStatus(
            store,
            CHAIN_START,
            0,
            count - 1n,
            CHAIN_START + 1n,
            "out-of-range",
          ),
        ),
      ).toBe("retention-breach");
    } finally {
      store.stop();
    }
  });

  test("out-of-range for a chunk inside the stated retention is a breach a third party can verify", async () => {
    await withStore(async (store, clock) => {
      const refusal = await signedChunkStatus(
        store,
        CHAIN_START,
        0,
        0n,
        CHAIN_START + 1n,
        "out-of-range",
      );
      const client = await connect(store.origin, clock, {
        fetch: answeringChunk(store, 0, 0, refusal),
      });
      clock.now = NEXT_FINALIZE_AT;
      await store.core.finalizeDue();

      expect((await client.scanWindow(CHAIN_START)).status).toBe("unreachable");
      expect(client.inert).toBe(true);
      const breach = client.faults.find(
        (fault) => fault.kind === "retention-breach",
      );
      expect((breach?.evidence ?? []).map(hex)).toEqual([hex(refusal)]);
      const descriptor = breach?.descriptor ?? store.core.descriptor;
      expect(hex(await descriptorHash(descriptor))).toBe(
        hex(store.core.descriptorHash),
      );
      expect(await proves(descriptor, refusal)).toBe("retention-breach");
      const altered = Uint8Array.from(refusal);
      altered[altered.length - 66] ^= 0x01;
      expect(await proves(descriptor, altered)).toBeNull();
    });
  });

  test("a signed denial of a chunk the signed checkpoint lists is a breach a third party can verify", async () => {
    await withStore(async (store, clock) => {
      const denial = await signedChunkStatus(
        store,
        CHAIN_START,
        0,
        0n,
        CHAIN_START + 1n,
        "no-such-chunk",
      );
      const client = await connect(store.origin, clock, {
        fetch: answeringChunk(store, 0, 0, denial),
      });
      await appendObject(client, CHAIN_START, 0x62);
      clock.now = NEXT_FINALIZE_AT + profile.deliveryWindowMs;
      while ((await store.core.finalizeDue()).length > 0);
      const servedCheckpoint = encodePublicStoreCheckpointReadV1(
        await store.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
      );

      expect((await client.scanWindow(CHAIN_START)).status).toBe("unreachable");
      // Blame under its own name, and the receipt for the window reported.
      expect(client.inert).toBe(true);
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "chunk-denial-breach",
        "custody-unchecked",
      ]);
      const breach = client.faults[0];
      expect(breach.window).toBe(CHAIN_START);
      expect(breach.detail).toContain("chunk 0 of class 0");
      // Both signed statements: the checkpoint that commits to the chunk,
      // then the status that denies it, with the descriptor they name.
      expect((breach.evidence ?? []).map(hex)).toEqual([
        hex(servedCheckpoint),
        hex(denial),
      ]);
      const kept = breach.descriptor ?? ({} as StoreDescriptorV1);
      expect(hex(await descriptorHash(kept))).toBe(
        hex(store.core.descriptorHash),
      );

      // A third party, from the record alone.
      expect(await proves(kept, ...(breach.evidence ?? []))).toBe(
        "chunk-denial-breach",
      );
      // The denial alone proves it too: the descriptor declares the
      // profile, and the profile defines the chunk. The checkpoint alone, or
      // the two in the other order, prove nothing.
      expect(await proves(kept, denial)).toBe("chunk-denial-breach");
      expect(await proves(kept, servedCheckpoint)).toBeNull();
      expect(await proves(kept, denial, servedCheckpoint)).toBeNull();
      // Not with an altered denial or an altered checkpoint.
      const alteredDenial = Uint8Array.from(denial);
      alteredDenial[alteredDenial.length - 66] ^= 0x01;
      expect(await proves(kept, servedCheckpoint, alteredDenial)).toBeNull();
      const alteredCheckpoint = Uint8Array.from(servedCheckpoint);
      alteredCheckpoint[alteredCheckpoint.length - 1] ^= 0x01;
      expect(await proves(kept, alteredCheckpoint, denial)).toBeNull();
      // Not with the checkpoint of another window, which commits to other
      // chunks than the one denied.
      const nextCheckpoint = encodePublicStoreCheckpointReadV1(
        await store.core.readCheckpoint(PROFILE_HASH, CHAIN_START + 1n),
      );
      expect(decodePublicStoreCheckpointReadV1(nextCheckpoint).kind).toBe(
        "finalized",
      );
      expect(await proves(kept, nextCheckpoint, denial)).toBeNull();
      // Not for a chunk the profile does not define, which the store denies
      // honestly: the real core's own answer, beside the real checkpoint.
      const count = BigInt(
        profile.sizeClasses.find((sizeClass) => sizeClass.id === 0)
          ?.publicChunksPerWindow ?? 0,
      );
      const honest = await store.core.readChunk(
        {
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START,
          sizeClass: 0,
        },
        count,
      );
      expect(honest.kind === "status" ? honest.value.status : honest.kind).toBe(
        "no-such-chunk",
      );
      expect(
        await proves(kept, servedCheckpoint, encodePublicChunkReadV1(honest)),
      ).toBeNull();
      // Not against another store's descriptor.
      const other = await startStore(clock, {
        seed: new Uint8Array(32).fill(0x6c),
      });
      try {
        expect(
          await proves(other.core.descriptor, servedCheckpoint, denial),
        ).toBeNull();
      } finally {
        other.stop();
      }
    });
  });

  test("evidence cannot be disputed with a second descriptor", async () => {
    const clock: Clock = { now: WINDOW_START };
    const store = await startStore(clock, { retentionWindows: 100 });
    try {
      const first = store.core.descriptor;
      // A second descriptor under the same key: another generation, and a
      // retention short enough to make the refusal below an honest expiry.
      const draft = {
        ...first,
        descriptorGeneration: 2n,
        retentionWindows: PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
      };
      const second: StoreDescriptorV1 = {
        ...draft,
        descriptorSignature: await sign(
          await storeDescriptorSignedMessage(draft),
          await storeSecretKey(),
          cryptoModule,
        ),
      };

      // Eighty windows back: inside the first descriptor's 100, past the
      // second's 67.
      const storeWindow = CHAIN_START + 80n;
      const refusal = await signedOutOfRange(store, CHAIN_START, storeWindow);
      clock.now = ingressWindowStartMs(storeWindow, profile.deliveryWindowMs);
      const client = await connect(store.origin, clock, {
        fetch: answeringCheckpoints(store, refusal),
      });
      expect((await client.scanWindow(CHAIN_START)).status).toBe("unreachable");
      const breach = client.faults.find(
        (fault) => fault.kind === "retention-breach",
      );
      const kept = breach?.descriptor ?? second;
      expect(hex(await descriptorHash(kept))).toBe(
        hex(await descriptorHash(first)),
      );
      expect(await proves(kept, refusal)).toBe("retention-breach");

      // The second descriptor is authentic, and the answer names the first:
      // judged against the second it proves nothing, but it does not stop
      // proving against the first.
      expect(await proves(second, refusal)).toBeNull();
      // The store's own answer naming the second is another statement, and
      // under the second it is an honest expiry.
      const recast = await signedCheckpointStatus(
        store,
        CHAIN_START,
        storeWindow,
        "out-of-range",
        await descriptorHash(second),
      );
      expect(await proves(second, recast)).toBeNull();
      expect(await proves(first, recast)).toBeNull();
      expect(await proves(first, refusal)).toBe("retention-breach");
    } finally {
      store.stop();
    }
  });

  test("a not-final for a window the store's own clock says must be final is a breach a third party can verify", async () => {
    await withStore(async (store, clock) => {
      clock.now = NEXT_FINALIZE_AT;
      await store.core.finalizeDue();
      // Signed at the store's window after the one it calls not final: its
      // whole window lies past that window's finalization instant.
      const stalling = await signedCheckpointStatus(
        store,
        CHAIN_START,
        CHAIN_START + 1n,
        "not-final",
      );
      const client = await connect(store.origin, clock, {
        fetch: answeringCheckpoints(store, stalling),
      });
      expect((await client.scanWindow(CHAIN_START)).status).toBe("unreachable");
      expect(client.inert).toBe(true);
      const breach = client.faults.find(
        (fault) => fault.kind === "finalization-breach",
      );
      expect((breach?.evidence ?? []).map(hex)).toEqual([hex(stalling)]);
      expect(
        await proves(breach?.descriptor ?? store.core.descriptor, stalling),
      ).toBe("finalization-breach");
      // A chunk status is held to the same rule.
      expect(
        await proves(
          store.core.descriptor,
          await signedChunkStatus(
            store,
            CHAIN_START,
            1,
            0n,
            CHAIN_START + 1n,
            "not-final",
          ),
        ),
      ).toBe("finalization-breach");
    });
  });

  test("an honest store at the finalization boundary is not blamed", async () => {
    await withStore(async (store, clock) => {
      // The last instant before the close: the store honestly says not final,
      // stating the window itself, and nothing proves otherwise.
      clock.now = FINALIZE_AT - 1n;
      const checkpoint = await store.core.readCheckpoint(
        PROFILE_HASH,
        CHAIN_START,
      );
      const chunk = await store.core.readChunk(
        {
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START,
          sizeClass: 0,
        },
        0n,
      );
      if (checkpoint.kind !== "status" || chunk.kind !== "status")
        throw new Error("expected statuses");
      expect([checkpoint.value.status, chunk.value.status]).toEqual([
        "not-final",
        "not-final",
      ]);
      expect(checkpoint.value.storeIngressWindow).toBe(CHAIN_START);
      expect(
        await proves(
          store.core.descriptor,
          encodePublicStoreCheckpointReadV1(checkpoint),
        ),
      ).toBeNull();
      expect(
        await proves(store.core.descriptor, encodePublicChunkReadV1(chunk)),
      ).toBeNull();
      const client = await connect(store.origin, clock);
      expect((await client.scanWindow(CHAIN_START)).status).toBe("not-final");
      expect(client.faults).toEqual([]);

      // At the close itself, before the finalizer has run, the store signs
      // nothing: an unsigned 503, one unreachable answer, no blame.
      clock.now = FINALIZE_AT;
      await expect(
        store.core.readCheckpoint(PROFILE_HASH, CHAIN_START),
      ).rejects.toMatchObject({ name: "StoreFinalizationPendingError" });
      expect((await client.scanWindow(CHAIN_START)).status).toBe("unreachable");
      expect(client.inert).toBe(false);
      expect(client.faults.every((fault) => fault.kind === "unreachable")).toBe(
        true,
      );
      // The 503 began the client's back-off: it asks again once that is over.
      expect(client.backoffUntilMs).toBe(
        FINALIZE_AT + BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS),
      );
      await store.core.finalizeDue();
      clock.now = FINALIZE_AT + BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS);
      expect((await client.scanWindow(CHAIN_START)).status).toBe("finalized");
      expect(client.backoffUntilMs).toBeNull();
    });
  });

  test("receipts kept after a clock disagreement are reported unchecked when they are evicted", async () => {
    await withStore(async (store, clock) => {
      let answered = 0;
      const disagreeingOnce: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (
          url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`) &&
          answered++ === 0
        )
          return signedOutOfRange(
            store,
            CHAIN_START,
            CHAIN_START + 1_000n,
          ).then(
            (body) =>
              new Response(asBody(body), {
                status: 200,
                headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
              }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;
      const client = await connect(store.origin, clock, {
        fetch: disagreeingOnce,
      });
      await appendObject(client, CHAIN_START, 0x52);
      clock.now = NEXT_FINALIZE_AT;
      await store.core.finalizeDue();
      expect((await client.scanWindow(CHAIN_START)).status).toBe(
        "clock-disagreement",
      );
      // Kept for a read that may come: nothing is reported yet.
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "store-clock-disagreement",
      ]);

      // No read of that window comes, and newer receipts fill the client's
      // room for them: the oldest is pushed out, and said to be unchecked.
      const { lease } = await leaseFor(client, CHAIN_START + 2n);
      for (let index = 0; index < 1_024; index++) {
        const window = CHAIN_START + 10n + BigInt(index);
        client.recordReceipt({
          window,
          sizeClass: 0,
          lease: { ...lease, ingressWindow: window },
          objectOrdinal: 0,
          objectHash: new Uint8Array(32).fill(0x53),
          result: {} as PublicAppendResultV1,
        });
      }
      const unchecked = client.faults.filter(
        (fault) => fault.kind === "custody-unchecked",
      );
      expect(unchecked.map((fault) => fault.window)).toEqual([CHAIN_START]);
      expect(unchecked[0]?.detail).toContain("was not checked");
      expect(client.inert).toBe(false);
    });
  });

  test("the oldest window a catch-up reads is served and the one before it is beyond retention", async () => {
    // The floor's derivation: a catch-up read reaches 65 back, its answer
    // may arrive a window later, and the store's clock may be the skew
    // ahead, which near the end of a window is one window number ahead. So
    // the store sees it 67 back, the minimum retention, and serves it. One
    // window further is 68 back: honest expiry, within the skew.
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const current = CHAIN_START + 70n;
    // Half the skew before the end of this client's window `current`.
    const start =
      WINDOW_START +
      71n * profile.deliveryWindowMs -
      profile.maxScheduleSkewMs / 2n;
    const clock: Clock = { now: start };
    const store = await startStore(clock, {
      retentionWindows: retention,
      aheadMs: profile.maxScheduleSkewMs,
    });
    try {
      while ((await store.core.finalizeDue()).length > 0);
      const answeredNextWindow: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (url.pathname.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          clock.now += profile.deliveryWindowMs;
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;
      const client = await connect(store.origin, clock, {
        fetch: answeredNextWindow,
      });
      clock.now = start;
      expect((await client.scanWindow(current - 65n)).status).toBe("finalized");
      clock.now = start;
      expect((await client.scanWindow(current - 66n)).status).toBe(
        "beyond-retention",
      );
      expect(client.inert).toBe(false);
      expect(client.faults).toEqual([]);
    } finally {
      store.stop();
    }
  });

  test("out-of-range beyond the stated retention is a distinct scan result", async () => {
    const clock: Clock = { now: WINDOW_START };
    const retention = PROTOTYPE_STORE_MIN_RETENTION_WINDOWS;
    const store = await startStore(clock, { retentionWindows: retention });
    try {
      const client = await connect(store.origin, clock);
      await appendObject(client, CHAIN_START, 0x71);
      clock.now = FINALIZE_AT;
      await store.core.finalizeDue();
      // Past the retention the store states, on both clocks.
      clock.now =
        WINDOW_START + BigInt(retention + 1) * profile.deliveryWindowMs;
      const scan = await client.scanWindow(CHAIN_START);
      expect(scan.status).toBe("beyond-retention");
      expect(scan.objects).toEqual([]);
      expect(client.inert).toBe(false);
      // The receipt held for that window is reported, not dropped.
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "custody-unchecked",
      ]);
    } finally {
      store.stop();
    }
  });

  test("a breach record is never dropped because of unacknowledged reports", async () => {
    await withStore(
      async (store, clock) => {
        // The first 600 appends this client sends are never answered; each is
        // reported unacknowledged at its window's scan, past the fault cap.
        let held = 600;
        const holding: typeof fetch = ((
          input: RequestInfo | URL,
          init?: RequestInit,
        ) => {
          const url = new URL(String(input));
          if (
            init?.method === "POST" &&
            url.pathname === PROTOTYPE_STORE_ROUTES.append &&
            held > 0
          ) {
            held -= 1;
            return new Promise<Response>(() => undefined);
          }
          return fetch(`${store.origin}${url.pathname}${url.search}`, init);
        }) as typeof fetch;
        const client = await connect(store.origin, clock, { fetch: holding });
        const { lease, secretKey } = await leaseFor(client, CHAIN_START);
        const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x81);
        const admission = await buildAppendAdmission(
          lease,
          secretKey,
          0,
          0,
          object,
          cryptoModule,
        );
        for (let index = 0; index < 600; index++)
          void client.append(CHAIN_START, 0, object, admission);
        while (held > 0) await Bun.sleep(0);

        // Then a withheld object in the next window, answered `stored`.
        clock.now = WINDOW_START + profile.deliveryWindowMs;
        await appendObject(client, CHAIN_START + 1n, 0x82);
        clock.now = NEXT_FINALIZE_AT;
        await store.core.finalizeDue();
        await client.scanWindow(CHAIN_START);
        await client.scanWindow(CHAIN_START + 1n);

        const kinds = client.faults.map((fault) => fault.kind);
        expect(
          kinds.filter((kind) => kind === "custody-unacknowledged").length,
        ).toBeGreaterThan(500);
        expect(client.inert).toBe(true);
        expect(
          client.faults.filter((fault) => fault.kind === "custody-breach"),
        ).toEqual([expect.objectContaining({ window: CHAIN_START + 1n })]);
      },
      { fault: "withhold" },
    );
  });

  test("a busy store's 503 is an unreachable answer, not misbehaviour", async () => {
    await withStore(async (store, clock) => {
      const busy: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (init?.method === "POST")
          return Promise.resolve(
            new Response("busy", {
              status: 503,
              headers: headersOf("text/plain; charset=utf-8"),
            }),
          );
        return fetch(`${store.origin}${url.pathname}${url.search}`, init);
      }) as typeof fetch;
      const client = await connect(store.origin, clock, { fetch: busy });
      const keyPair = await newKeyPair(cryptoModule);
      const object = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(0x91);
      // The runtime already handles both: a missing lease and an unanswered
      // append are reported missed, and the entry waits for its next slot.
      // The append is asked once the 503's back-off has passed.
      expect(await client.allocate(CHAIN_START, keyPair)).toBeNull();
      clock.now += BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS);
      expect(await client.append(CHAIN_START, 0, object, null)).toBeNull();
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "unreachable",
        "unreachable",
      ]);
      expect(client.inert).toBe(false);
    });
  });
});

/**
 * Every signed refusal of a read, judged by one order
 * (`judgeSignedRefusal`). No socket is opened here: the client's transport is
 * a stub over a real core's finalized window and statuses signed with that
 * core's key, so each test states the store's window, the descriptor's
 * validity and this client's clock exactly.
 */
describe("prototype store client signed refusals", () => {
  const L = profile.deliveryWindowMs;
  const F = profile.chunkFinalizationOffsetMs;
  const SKEW = profile.maxScheduleSkewMs;
  const READ_OFFSET = profile.publicReadOffsetMs;
  /** The window every read here asks for: the chain start. */
  const W = CHAIN_START;
  const R = BigInt(PROTOTYPE_STORE_MIN_RETENTION_WINDOWS);
  const startOf = (window: bigint): bigint => window * L;
  /** The instant W is final from, by the profile. */
  const FIN = startOf(W) + F;
  const ORIGIN = "http://store.invalid:5999";
  const CLASS_0_CHUNKS = BigInt(
    profile.sizeClasses.find((sizeClass) => sizeClass.id === 0)
      ?.publicChunksPerWindow ?? 0,
  );

  type Route = "checkpoint" | "chunk";
  type DescriptorDocument = ReturnType<
    PrototypeStoreCore["descriptorDocument"]
  >;

  /** A real core at the minimum retention, with W finalized. */
  const buildServed = async (aheadMs = 0n) => {
    const clock: Clock = { now: FIN };
    const core = await PrototypeStoreCore.create({
      module: cryptoModule,
      seed: SEED,
      profile,
      clock: { nowMs: () => clock.now + aheadMs },
      persistence: new MemoryStorePersistence(),
      chainStartIngressWindow: W,
      origin: ORIGIN,
      descriptorValidityMs: 2_592_000_000n,
      retentionWindows: Number(R),
    });
    return { core, clock, handler: createPrototypeStoreHandler({ core }) };
  };

  let memo: Promise<{
    readonly core: PrototypeStoreCore;
    readonly clock: Clock;
    readonly checkpoint: Uint8Array;
    readonly chunks: ReadonlyMap<string, Uint8Array>;
  }> | null = null;
  /** One core for the block, with what it serves for W once finalized. */
  const served = (): NonNullable<typeof memo> =>
    (memo ??= (async () => {
      const { core, clock } = await buildServed();
      await core.finalizeDue();
      const chunks = new Map<string, Uint8Array>();
      for (const sizeClass of profile.sizeClasses)
        for (let index = 0; index < sizeClass.publicChunksPerWindow; index++)
          chunks.set(
            `${String(sizeClass.id)}/${String(index)}`,
            encodePublicChunkReadV1(
              await core.readChunk(
                {
                  deliveryProfileHash: PROFILE_HASH,
                  ingressWindow: W,
                  sizeClass: sizeClass.id,
                },
                BigInt(index),
              ),
            ),
          );
      return {
        core,
        clock,
        checkpoint: encodePublicStoreCheckpointReadV1(
          await core.readCheckpoint(PROFILE_HASH, W),
        ),
        chunks,
      };
    })());

  /**
   * The served store's descriptor with another validity, and a route bound
   * to it, both signed with the store's key: what a client pins.
   */
  const documentValid = async (
    notBeforeUnixMs: bigint,
    notAfterUnixMs: bigint,
    retentionWindows = Number(R),
  ): Promise<DescriptorDocument> => {
    const base = (await served()).core.descriptorDocument();
    const secretKey = await storeSecretKey();
    const draft = {
      ...base.descriptor,
      retentionWindows,
      notBeforeUnixMs,
      notAfterUnixMs,
    };
    const descriptor = {
      ...draft,
      descriptorSignature: await sign(
        await storeDescriptorSignedMessage(draft),
        secretKey,
        cryptoModule,
      ),
    };
    const routeDraft = {
      ...base.routes[0],
      descriptorHash: await descriptorHash(descriptor),
      notBeforeUnixMs: 0n,
      notAfterUnixMs: 1n << 62n,
    };
    return {
      descriptor,
      routes: [
        {
          ...routeDraft,
          routeSignature: await sign(
            await storeRouteSignedMessage(routeDraft),
            secretKey,
            cryptoModule,
          ),
        },
      ],
    };
  };

  /** A validity that covers every window and instant these tests use. */
  const wideDocument = (): Promise<DescriptorDocument> =>
    documentValid(startOf(W - 5_000n), startOf(W + 50_000n));

  /** A status about W signed with the store's key. */
  const signedStatus = async (
    route: Route,
    status: string,
    storeWindow: bigint,
    descriptorHashBytes: Uint8Array,
    chunk: { sizeClass: number; chunkIndex: bigint } = {
      sizeClass: 0,
      chunkIndex: 0n,
    },
  ): Promise<Uint8Array> => {
    const secretKey = await storeSecretKey();
    if (route === "checkpoint") {
      const value = {
        version: 1 as const,
        storeId: (await served()).core.storeId,
        descriptorHash: descriptorHashBytes,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: W,
        storeIngressWindow: storeWindow,
        status: status as PublicStoreCheckpointStatusKindV1,
      };
      return encodePublicStoreCheckpointReadV1({
        kind: "status",
        value,
        storeSignature: await sign(
          await publicCheckpointStatusSigningHash(value),
          secretKey,
          cryptoModule,
        ),
      });
    }
    const value = {
      version: 1 as const,
      descriptorHash: descriptorHashBytes,
      bucket: {
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: W,
        sizeClass: chunk.sizeClass,
      },
      chunkIndex: chunk.chunkIndex,
      storeIngressWindow: storeWindow,
      status: status as PublicChunkStatusKindV1,
    };
    return encodePublicChunkReadV1({
      kind: "status",
      value,
      storeSignature: await sign(
        await publicChunkStatusSigningHash(value),
        secretKey,
        cryptoModule,
      ),
    });
  };

  /**
   * A transport that serves `document`, the finalized window W, and
   * `answer` in place of W's checkpoint (`route` "checkpoint") or of chunk 0
   * of class 0 (`route` "chunk").
   */
  const transport = async (
    document: DescriptorDocument,
    route: Route | null,
    answer: Uint8Array | null,
    onRequest: () => void = () => undefined,
  ): Promise<typeof fetch> => {
    const { checkpoint, chunks } = await served();
    const respond = (bytes: Uint8Array, mediaType: string): Promise<Response> =>
      Promise.resolve(
        new Response(asBody(bytes), {
          status: 200,
          headers: headersOf(mediaType),
        }),
      );
    return ((input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === PROTOTYPE_STORE_ROUTES.descriptor)
        return respond(
          encodePrototypeStoreDescriptorDocumentV1(document),
          PROTOTYPE_STORE_MEDIA_TYPES.descriptor,
        );
      onRequest();
      if (path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
        return respond(
          route === "checkpoint" && answer !== null ? answer : checkpoint,
          PROTOTYPE_STORE_MEDIA_TYPES.checkpoint,
        );
      const parts = path.split("/");
      const key = `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
      return respond(
        route === "chunk" && answer !== null && key === "0/0"
          ? answer
          : (chunks.get(key) ?? new Uint8Array(0)),
        PROTOTYPE_STORE_MEDIA_TYPES.chunk,
      );
    }) as typeof fetch;
  };

  /**
   * One scan of W at `readMs` on this client's clock, by a client that pinned
   * `document` at an instant inside its validity. `answeredAfterMs` is how
   * much later the answers arrive.
   */
  const scanAt = async (
    document: DescriptorDocument,
    route: Route | null,
    answer: Uint8Array | null,
    readMs: bigint,
    answeredAfterMs = 0n,
  ) => {
    const { notBeforeUnixMs, notAfterUnixMs } = document.descriptor;
    const clock: Clock = {
      now:
        readMs >= notAfterUnixMs
          ? notAfterUnixMs - 1n
          : readMs < notBeforeUnixMs
            ? notBeforeUnixMs
            : readMs,
    };
    let advanced = false;
    const client = await PrototypeStoreClient.connect({
      origin: ORIGIN,
      profile,
      profileHash: PROFILE_HASH,
      module: cryptoModule,
      fetch: await transport(document, route, answer, () => {
        if (!advanced) clock.now += answeredAfterMs;
        advanced = true;
      }),
      nowMs: () => clock.now,
    });
    clock.now = readMs;
    const scan = await client.scanWindow(W);
    return {
      client,
      scan,
      kinds: client.faults.map((fault) => fault.kind),
    };
  };

  /** What a third party concludes from a fault record alone. */
  const provedBy = (
    fault: { evidence?: readonly Uint8Array[]; descriptor?: StoreDescriptorV1 },
    withProfile = profile,
  ): Promise<string | null> =>
    signedStatusProvesFault(
      fault.descriptor ?? ({} as StoreDescriptorV1),
      withProfile,
      fault.evidence ?? [],
      cryptoModule,
    );

  const SCHEDULED_READ = startOf(W + 1n) + READ_OFFSET;

  test("a not-final from a store inside the allowed skew is accepted at the boundary", async () => {
    // A real core whose clock is `aheadMs` from this client's, read through
    // its own HTTP handler at every instant around the close. Whatever the
    // offset inside the skew, and whenever the read is made, nothing is
    // recorded against it.
    const offsets = [-SKEW, -SKEW / 2n, 0n, SKEW / 2n, SKEW];
    const instants: bigint[] = [];
    for (let at = FIN - SKEW - 250n; at <= FIN + SKEW + 250n; at += 50n)
      instants.push(at);
    instants.push(FIN - SKEW - 1n, FIN - 1n, FIN + SKEW - 1n, FIN + SKEW);
    instants.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));

    let boundaryAnswer: Uint8Array | null = null;
    for (const aheadMs of offsets) {
      const { core, clock, handler } = await buildServed(aheadMs);
      let lastCheckpoint: Uint8Array | null = null;
      const throughHandler: typeof fetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const response = await handler(new Request(String(input), init));
        if (
          new URL(String(input)).pathname.startsWith(
            `${PROTOTYPE_STORE_ROUTES.checkpoint}/`,
          )
        )
          lastCheckpoint = new Uint8Array(await response.clone().arrayBuffer());
        return response;
      }) as typeof fetch;
      clock.now = instants[0];
      const client = await PrototypeStoreClient.connect({
        origin: ORIGIN,
        profile,
        profileHash: PROFILE_HASH,
        module: cryptoModule,
        fetch: throughHandler,
        nowMs: () => clock.now,
      });
      for (const at of instants) {
        clock.now = at;
        // The finalizer runs as soon as the store's own clock allows.
        await core.finalizeDue();
        const scan = await client.scanWindow(W);
        // The store's clock decides the answer; this client accepts either.
        expect([String(at), String(aheadMs), scan.status]).toEqual([
          String(at),
          String(aheadMs),
          at + aheadMs < FIN ? "not-final" : "finalized",
        ]);
        if (aheadMs === -SKEW && at === FIN + SKEW - 1n)
          boundaryAnswer = lastCheckpoint;
      }
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);
    }

    // The boundary itself. The last `not-final` an honest store the full
    // skew behind can sign is for a request sent at the close plus the skew
    // less one millisecond; it was accepted above. The same signed answer
    // for a request sent one millisecond later is one no store within the
    // skew could give.
    if (boundaryAnswer === null) throw new Error("no boundary answer");
    const decoded = decodePublicStoreCheckpointReadV1(boundaryAnswer);
    expect(decoded.kind === "status" ? decoded.value.status : null).toBe(
      "not-final",
    );
    const document = (await served()).core.descriptorDocument();
    const accepted = await scanAt(
      document,
      "checkpoint",
      boundaryAnswer,
      FIN + SKEW - 1n,
    );
    expect([accepted.scan.status, accepted.kinds]).toEqual(["not-final", []]);
    const refused = await scanAt(
      document,
      "checkpoint",
      boundaryAnswer,
      FIN + SKEW,
    );
    expect([refused.scan.status, refused.kinds, refused.client.inert]).toEqual([
      "clock-disagreement",
      ["store-clock-disagreement"],
      false,
    ]);
  });

  test("an honest store inside the allowed skew is never reported at the retention edge", async () => {
    // The same sweep at the other boundary a clock decides: the instant W
    // leaves the store's retention. Before it the store serves W, after it
    // the store honestly refuses, and this client records nothing either way.
    const edge = startOf(W + R + 1n);
    for (const aheadMs of [-SKEW, -SKEW / 2n, 0n, SKEW / 2n, SKEW]) {
      const { core, clock, handler } = await buildServed(aheadMs);
      // Finalized once the store's own clock is past the close.
      clock.now = FIN + SKEW;
      expect(await core.finalizeDue()).toEqual([W]);
      const throughHandler: typeof fetch = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => handler(new Request(String(input), init))) as typeof fetch;
      clock.now = edge - SKEW - 250n;
      const client = await PrototypeStoreClient.connect({
        origin: ORIGIN,
        profile,
        profileHash: PROFILE_HASH,
        module: cryptoModule,
        fetch: throughHandler,
        nowMs: () => clock.now,
      });
      const instants: bigint[] = [];
      for (let at = edge - SKEW - 250n; at <= edge + SKEW + 250n; at += 50n)
        instants.push(at);
      instants.push(edge - SKEW - 1n, edge - 1n, edge + SKEW - 1n, edge + SKEW);
      for (const at of instants) {
        clock.now = at;
        const scan = await client.scanWindow(W);
        expect([String(at), String(aheadMs), scan.status]).toEqual([
          String(at),
          String(aheadMs),
          at + aheadMs < edge ? "finalized" : "beyond-retention",
        ]);
      }
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);
    }
  });

  test("a not-final is never accepted at a read the carrier runtime makes", async () => {
    // The profile puts the read of W after W's finalization instant plus the
    // skew, so at the scheduled read and every catch-up read after it a
    // `not-final` is a disagreement or a breach, whatever window it states.
    expect(F + SKEW < L + READ_OFFSET).toBe(true);
    const document = await wideDocument();
    const hash = await descriptorHash(document.descriptor);
    for (const route of ["checkpoint", "chunk"] as const)
      for (const readMs of [
        SCHEDULED_READ,
        startOf(W + 10n) + READ_OFFSET,
        startOf(W + 60n) + READ_OFFSET,
      ])
        for (const storeWindow of [
          W - 1_000n,
          W - 1n,
          W,
          W + 1n,
          readMs / L,
          readMs / L + 1n,
        ]) {
          const { scan, kinds, client } = await scanAt(
            document,
            route,
            await signedStatus(route, "not-final", storeWindow, hash),
            readMs,
          );
          expect(scan.status).not.toBe("not-final");
          expect(kinds).toEqual([
            storeWindow > W
              ? "finalization-breach"
              : "store-clock-disagreement",
          ]);
          expect(client.inert).toBe(storeWindow > W);
        }
  });

  test("out-of-range inside the named descriptor's retention is a breach whatever window the store states", async () => {
    const runs = [
      {
        // The descriptor runs out at the start of W + 10, and the store
        // states W + 12. This client's own clock is still inside validity:
        // from its end on, this client asks the store nothing at all.
        name: "stated past notAfter",
        notAfter: startOf(W + 10n),
        storeWindow: W + 12n,
        readMs: startOf(W + 10n) - 1n,
      },
      {
        // Validity ends in the middle of W + 5, the window the store states;
        // this client's clock is in that window and still inside validity.
        name: "validity ending mid-window, the client's clock still inside",
        notAfter: startOf(W + 5n) + 2_000n,
        storeWindow: W + 5n,
        readMs: startOf(W + 5n) + READ_OFFSET,
      },
      {
        // And before validity begins, by the same rule.
        name: "stated before notBefore",
        notBefore: startOf(W + 3n),
        notAfter: startOf(W + 50_000n),
        storeWindow: W + 1n,
        readMs: startOf(W + 3n) + READ_OFFSET,
      },
    ];
    for (const run of runs)
      for (const route of ["checkpoint", "chunk"] as const) {
        const document = await documentValid(
          run.notBefore ?? startOf(W - 5_000n),
          run.notAfter,
        );
        const refusal = await signedStatus(
          route,
          "out-of-range",
          run.storeWindow,
          await descriptorHash(document.descriptor),
        );
        // W is inside the retention of the descriptor the refusal names.
        expect(run.storeWindow - W <= R).toBe(true);
        const { client, scan, kinds } = await scanAt(
          document,
          route,
          refusal,
          run.readMs,
        );
        expect([run.name, route, scan.status, kinds, client.inert]).toEqual([
          run.name,
          route,
          "unreachable",
          ["retention-breach"],
          true,
        ]);
        const breach = client.faults[0];
        expect(breach.window).toBe(W);
        expect((breach.evidence ?? []).map(hex)).toEqual([hex(refusal)]);
        // From the kept record alone, with no clock.
        expect(await provedBy(breach)).toBe("retention-breach");
      }
  });

  test("a status stated outside the descriptor's validity that proves nothing is reported, not accepted", async () => {
    const pastRetention = W + R + 1n;
    const runs = [
      {
        // By the store's own words W has expired, which would be believed,
        // but the window it states is one the descriptor ends inside.
        name: "out-of-range stated in the window validity ends in",
        status: "out-of-range",
        notAfter: startOf(pastRetention) + 2_000n,
        storeWindow: pastRetention,
        readMs: startOf(pastRetention) + READ_OFFSET,
      },
      {
        // Stated in the first window wholly past notAfter, by a store whose
        // clock is just ahead of this client's, which is still inside.
        name: "out-of-range stated in the window after validity ends",
        status: "out-of-range",
        notAfter: startOf(pastRetention),
        storeWindow: pastRetention,
        readMs: startOf(pastRetention) - SKEW / 2n,
      },
      {
        name: "not-final stated in the window validity ends in",
        status: "not-final",
        notAfter: FIN + 100n,
        storeWindow: W,
        readMs: FIN - 1n,
      },
      {
        name: "not-final stated in the window validity begins in",
        status: "not-final",
        notBefore: startOf(W) + 1_000n,
        notAfter: startOf(W + 50_000n),
        storeWindow: W,
        readMs: FIN - 1n,
      },
    ];
    for (const run of runs)
      for (const route of ["checkpoint", "chunk"] as const) {
        const document = await documentValid(
          run.notBefore ?? startOf(W - 5_000n),
          run.notAfter,
        );
        // This client's own clock is inside validity for the whole read.
        expect(
          document.descriptor.notBeforeUnixMs <= run.readMs &&
            run.readMs < document.descriptor.notAfterUnixMs,
        ).toBe(true);
        const refusal = await signedStatus(
          route,
          run.status,
          run.storeWindow,
          await descriptorHash(document.descriptor),
        );
        const { client, scan, kinds } = await scanAt(
          document,
          route,
          refusal,
          run.readMs,
        );
        expect([run.name, route, scan.status, kinds, client.inert]).toEqual([
          run.name,
          route,
          "descriptor-out-of-validity",
          ["descriptor-out-of-validity"],
          false,
        ]);
        expect(client.faults[0].window).toBe(W);
        expect(client.faults[0].evidence).toBeUndefined();
        // It proves nothing to a third party either.
        expect(
          await signedStatusProvesFault(
            document.descriptor,
            profile,
            [refusal],
            cryptoModule,
          ),
        ).toBeNull();

        // The same answer under a descriptor that covers the stated window
        // is the benign one, so the report above is the validity's doing.
        const covering = await wideDocument();
        const benign = await scanAt(
          covering,
          route,
          await signedStatus(
            route,
            run.status,
            run.storeWindow,
            await descriptorHash(covering.descriptor),
          ),
          run.readMs,
        );
        expect([benign.scan.status, benign.kinds]).toEqual([
          run.status === "out-of-range" ? "beyond-retention" : "not-final",
          [],
        ]);
      }
  });

  test("a read after the pinned descriptor expires on the client's clock is reported, not served", async () => {
    const notAfter = startOf(W + 20n) + 1_234n;
    const document = await documentValid(startOf(W - 5_000n), notAfter);
    const hash = await descriptorHash(document.descriptor);

    // A window the store serves whole. One millisecond before the
    // descriptor's end it is read; from the end on it is not.
    const before = await scanAt(document, null, null, notAfter - 1n);
    expect(before.scan.status).toBe("finalized");
    expect(before.scan.objects.length).toBe(OBJECTS_PER_WINDOW);
    expect(before.kinds).toEqual([]);
    // From the end on, nothing is asked: the client stops using the store,
    // once, and records nothing per read.
    for (const readMs of [notAfter, notAfter + 40n * L]) {
      const { client, scan, kinds } = await scanAt(
        document,
        null,
        null,
        readMs,
      );
      expect(scan.status).toBe("stopped");
      expect(scan.objects).toEqual([]);
      expect(scan.checkpointHash).toBeNull();
      expect(kinds).toEqual([]);
      expect(client.stopped?.reason).toBe("descriptor-expired");
      expect(client.inert).toBe(false);
    }
    // The answers arriving after the end count as the read being outside.
    const straddling = await scanAt(document, null, null, notAfter - 1n, 1n);
    expect([straddling.scan.status, straddling.kinds]).toEqual([
      "descriptor-out-of-validity",
      ["descriptor-out-of-validity"],
    ]);

    // A refusal that would otherwise be believed is not believed either: an
    // honest expiry (W + R + 1, past the retention), stated within the skew
    // of this client's clock, under a descriptor whose end that clock has
    // passed. Read after the end, it is not even asked for. Sent before the
    // end and answered at it, the stated window lies wholly inside the
    // validity, so it is this client's own clock alone that decides.
    const past = W + R + 1n;
    const lapses = [
      {
        name: "the end inside the stated window, read after it",
        notAfter: startOf(past) + READ_OFFSET - 10n,
        readMs: startOf(past) + READ_OFFSET,
        answeredAfterMs: 0n,
        want: ["stopped", []],
      },
      {
        name: "the end at the stated window's own end, read just after it",
        notAfter: startOf(past + 1n),
        readMs: startOf(past + 1n) + SKEW / 2n,
        answeredAfterMs: 0n,
        want: ["stopped", []],
      },
      {
        name: "sent before the end, answered at it",
        notAfter: startOf(past + 1n),
        readMs: startOf(past + 1n) - 1n,
        answeredAfterMs: 1n,
        want: ["descriptor-out-of-validity", ["descriptor-out-of-validity"]],
      },
    ];
    for (const lapse of lapses)
      for (const route of ["checkpoint", "chunk"] as const) {
        const short = await documentValid(startOf(W - 5_000n), lapse.notAfter);
        const { client, scan, kinds } = await scanAt(
          short,
          route,
          await signedStatus(
            route,
            "out-of-range",
            past,
            await descriptorHash(short.descriptor),
          ),
          lapse.readMs,
          lapse.answeredAfterMs,
        );
        expect([
          lapse.name,
          route,
          scan.status,
          kinds as string[],
          client.inert,
        ]).toEqual([lapse.name, route, ...lapse.want, false]);
      }
    // The same expiry read and answered one millisecond inside the end is
    // believed, so each report above is the lapse's doing.
    for (const route of ["checkpoint", "chunk"] as const) {
      const whole = await documentValid(
        startOf(W - 5_000n),
        startOf(past + 1n),
      );
      const believed = await scanAt(
        whole,
        route,
        await signedStatus(
          route,
          "out-of-range",
          past,
          await descriptorHash(whole.descriptor),
        ),
        startOf(past + 1n) - 1n,
      );
      expect([route, believed.scan.status, believed.kinds]).toEqual([
        route,
        "beyond-retention",
        [],
      ]);
    }

    // What the store signs is evidence whatever window it states: a refusal
    // that contradicts the store's own words is blamed when it states a
    // window past the descriptor's end too.
    const breach = await scanAt(
      document,
      "checkpoint",
      await signedStatus("checkpoint", "out-of-range", W + 30n, hash),
      notAfter - 1n,
    );
    expect([breach.scan.status, breach.kinds, breach.client.inert]).toEqual([
      "unreachable",
      ["retention-breach"],
      true,
    ]);
  });

  test("receipts for a window read after the descriptor's end are reported unchecked, not held", async () => {
    const { core, clock: storeClock, handler } = await buildServed();
    const base = core.descriptorDocument();
    // The store's own descriptor: the client's clock passes its end.
    const notAfter = base.descriptor.notAfterUnixMs;
    const clock: Clock = { now: startOf(W) };
    const refusal = async (): Promise<Uint8Array> =>
      signedStatus(
        "checkpoint",
        "out-of-range",
        notAfter / L + 1n,
        core.descriptorHash,
      );
    let refuse = false;
    const client = await PrototypeStoreClient.connect({
      origin: ORIGIN,
      profile,
      profileHash: PROFILE_HASH,
      module: cryptoModule,
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        storeClock.now = clock.now;
        const path = new URL(String(input)).pathname;
        if (refuse && path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          return new Response(asBody(await refusal()), {
            status: 200,
            headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
          });
        return handler(new Request(String(input), init));
      }) as typeof fetch,
      nowMs: () => clock.now,
    });
    await appendObject(client, W, 0x77);
    // Long after: W is past the store's retention, and the descriptor ended.
    refuse = true;
    clock.now = startOf(notAfter / L + 1n) + READ_OFFSET;
    expect(clock.now >= notAfter).toBe(true);
    // Nothing is asked after the end: the client stops using the store, and
    // the receipts no read will now check are reported then.
    expect((await client.scanWindow(W)).status).toBe("stopped");
    expect(client.stopped?.reason).toBe("descriptor-expired");
    expect(client.faults.map((fault) => fault.kind)).toEqual([
      "custody-unchecked",
    ]);
    expect(client.faults[0].window).toBe(W);
    expect(client.inert).toBe(false);
  });

  // One test for each route, so neither hides the other.
  for (const route of ["checkpoint", "chunk"] as const)
    test(`a status naming another descriptor is refused (${route} status)`, async () => {
      const pinned = await wideDocument();
      // A second authentic descriptor of the same store: another generation,
      // with a longer retention.
      const other = await documentValid(
        startOf(W - 5_000n),
        startOf(W + 50_000n),
        Number(R) + 40,
      );
      const otherHash = await descriptorHash(other.descriptor);
      expect(hex(otherHash)).not.toBe(
        hex(await descriptorHash(pinned.descriptor)),
      );

      const runs = [
        {
          // Judged under the pinned descriptor this would be the store
          // refusing a window inside its retention: blame, and wrongly, for
          // a statement made under a descriptor this client does not hold.
          name: "out-of-range one window on",
          status: "out-of-range",
          storeWindow: W + 1n,
          readMs: SCHEDULED_READ,
        },
        {
          // Judged under the pinned descriptor this would be believed as
          // expiry, with nothing recorded.
          name: "out-of-range past the pinned retention",
          status: "out-of-range",
          storeWindow: W + R + 1n,
          readMs: startOf(W + R + 1n) + READ_OFFSET,
        },
        {
          // And this would be believed as a window not yet final.
          name: "not-final before the close",
          status: "not-final",
          storeWindow: W,
          readMs: FIN - 1n,
        },
        {
          // A denial is blame under the pinned descriptor too.
          name: "a denial",
          status:
            route === "checkpoint" ? "chain-unavailable" : "no-such-chunk",
          storeWindow: W + 1n,
          readMs: SCHEDULED_READ,
        },
      ];
      for (const run of runs) {
        const answer = await signedStatus(
          route,
          run.status,
          run.storeWindow,
          otherHash,
        );
        const { client, scan, kinds } = await scanAt(
          pinned,
          route,
          answer,
          run.readMs,
        );
        expect([run.name, scan.status, kinds, client.inert]).toEqual([
          run.name,
          "unreachable",
          ["signature-invalid"],
          false,
        ]);
        expect(client.faults[0].detail).toContain(
          "names a descriptor other than the one this client pinned",
        );
        // The answer verified under the pinned key: it is kept, beside the
        // pinned descriptor, and proves nothing.
        expect((client.faults[0].evidence ?? []).map(hex)).toEqual([
          hex(answer),
        ]);
        expect(client.faults[0].descriptor).toEqual(pinned.descriptor);
        // Nor is it evidence under the pinned descriptor for anyone else,
        // alone or beside the window's checkpoint.
        for (const evidence of [
          [answer],
          [(await served()).checkpoint, answer],
        ])
          expect(
            await signedStatusProvesFault(
              pinned.descriptor,
              profile,
              evidence,
              cryptoModule,
            ),
          ).toBeNull();
      }
    });

  test("a status with no benign meaning has no benign outcome, whatever is passed to the decision", async () => {
    // What the client never passes, the function still decides: a profile
    // the descriptor declares no chain for, a chunk the profile does not
    // define. None of them is ever one of the two benign outcomes. A denial
    // of a chunk the profile defines is a breach by itself.
    const { descriptor } = await wideDocument();
    const undeclared = new Uint8Array(32).fill(0x11);
    const span = { sentMs: FIN - 1n, receivedMs: FIN - 1n };
    const windows = { window: W, storeWindow: W };
    const outcomeOf = (
      statement: Parameters<typeof judgeSignedRefusal>[0],
    ): string =>
      judgeSignedRefusal(statement, descriptor, profile, span).outcome;

    // The declared profile at this instant: the two benign answers, and the
    // two denials as breaches.
    expect(
      (["not-final", "out-of-range", "chain-unavailable"] as const).map(
        (status) =>
          outcomeOf({
            route: "checkpoint",
            status,
            deliveryProfileHash: PROFILE_HASH,
            window: W,
            storeWindow: status === "out-of-range" ? W + R + 1n : W,
          }),
      ),
    ).toEqual(["not-final", "store-clock-disagreement", "chain-denial-breach"]);

    for (const status of [
      "not-final",
      "out-of-range",
      "chain-unavailable",
    ] as const)
      expect([
        status,
        outcomeOf({
          route: "checkpoint",
          status,
          deliveryProfileHash: undeclared,
          ...windows,
        }),
      ]).toEqual([status, "no-benign-meaning"]);
    for (const status of [
      "not-final",
      "out-of-range",
      "no-such-chunk",
    ] as const)
      expect([
        status,
        outcomeOf({
          route: "chunk",
          status,
          deliveryProfileHash: undeclared,
          ...windows,
          sizeClass: 0,
          chunkIndex: 0n,
        }),
      ]).toEqual([status, "no-benign-meaning"]);

    // A `no-such-chunk` is a breach for a chunk the profile defines, by
    // itself; otherwise it is the truth, and not an answer to a read: never
    // benign.
    const denial = (chunkIndex: bigint, sizeClass = 0) =>
      ({
        route: "chunk",
        status: "no-such-chunk",
        deliveryProfileHash: PROFILE_HASH,
        ...windows,
        sizeClass,
        chunkIndex,
      }) as const;
    expect([
      outcomeOf(denial(0n)),
      outcomeOf(denial(CLASS_0_CHUNKS)),
      outcomeOf(denial(0n, 250)),
    ]).toEqual([
      "chunk-denial-breach",
      "no-benign-meaning",
      "no-benign-meaning",
    ]);
  });

  test("the verifier refuses evidence when given another profile", async () => {
    const document = await wideDocument();
    const hash = await descriptorHash(document.descriptor);
    // The same geometry at another window length, and the same window length
    // with another finalization instant: two profiles that are not the one
    // the signed answers name by hash.
    const others = [
      withDeliveryWindowMs(profile, 8_000n),
      {
        ...profile,
        chunkFinalizationOffsetMs: profile.chunkFinalizationOffsetMs + 1n,
      },
    ];
    for (const other of others)
      expect(hex(await deliveryProfileHash(other))).not.toBe(PROFILE_HEX);

    const cases: [Route, string, bigint, StoreEvidenceFaultKind][] = [
      ["checkpoint", "out-of-range", W + 1n, "retention-breach"],
      ["chunk", "out-of-range", W + 1n, "retention-breach"],
      ["checkpoint", "not-final", W + 1n, "finalization-breach"],
      ["chunk", "not-final", W + 1n, "finalization-breach"],
      ["checkpoint", "chain-unavailable", W + 1n, "chain-denial-breach"],
      ["chunk", "no-such-chunk", W + 1n, "chunk-denial-breach"],
    ];
    for (const [route, status, storeWindow, kind] of cases) {
      const { client, kinds } = await scanAt(
        document,
        route,
        await signedStatus(route, status, storeWindow, hash),
        SCHEDULED_READ,
      );
      expect(kinds).toEqual([kind]);
      const fault = client.faults[0];
      // The record holds no profile; the signed answers name it by hash.
      expect(Object.keys(fault).sort()).toEqual([
        "descriptor",
        "detail",
        "evidence",
        "kind",
        "storeIdHex",
        "window",
      ]);
      expect(await provedBy(fault)).toBe(kind);
      for (const other of others)
        expect(await provedBy(fault, other)).toBeNull();
    }
  });

  test("no stated values end in a benign outcome outside the table", async () => {
    const { core, clock: storeClock, checkpoint } = await served();

    const STATED: [string, bigint][] = [
      ["far before W", W - 1_000n],
      ["W - 1", W - 1n],
      ["W", W],
      ["W + 1", W + 1n],
      ["inside retention", W + R],
      ["just outside retention", W + R + 1n],
      ["far ahead", W + R + 1_000n],
    ];
    const READS: [string, bigint][] = [
      ["before the close", FIN - 1n],
      [
        "the last instant a store within the skew reads before the close",
        FIN + SKEW - 1n,
      ],
      ["the first instant none does", FIN + SKEW],
      ["the scheduled read", SCHEDULED_READ],
      ["a catch-up shortly after", startOf(W + 10n) + READ_OFFSET],
      ["a catch-up long after", startOf(W + 60n) + READ_OFFSET],
      [
        "the last instant no store within the skew is past retention",
        startOf(W + R + 1n) - SKEW - 1n,
      ],
      ["the first instant one is", startOf(W + R + 1n) - SKEW],
      ["after the window left retention", startOf(W + R + 1n) + READ_OFFSET],
      [
        "just past a window's end, where a store within the skew still states it",
        startOf(W + R + 2n) + SKEW - 1n,
      ],
    ];
    const VALIDITY = [
      "inside",
      "straddling notBefore",
      "straddling notAfter",
      "expired",
    ] as const;
    const STATUSES: { route: Route; status: string; listed: boolean }[] = [
      { route: "checkpoint", status: "not-final", listed: true },
      { route: "checkpoint", status: "out-of-range", listed: true },
      { route: "checkpoint", status: "chain-unavailable", listed: true },
      { route: "chunk", status: "not-final", listed: true },
      { route: "chunk", status: "out-of-range", listed: true },
      { route: "chunk", status: "no-such-chunk", listed: true },
      // An answer naming a chunk the checkpoint does not list (an index one
      // past the class's count), in place of the chunk that was asked for.
      { route: "chunk", status: "not-final", listed: false },
      { route: "chunk", status: "out-of-range", listed: false },
      { route: "chunk", status: "no-such-chunk", listed: false },
    ];

    /** The validity each configuration gives, around one stated window and read. */
    const validityFor = (
      kind: (typeof VALIDITY)[number],
      stated: bigint,
      readMs: bigint,
    ): { notBefore: bigint; notAfter: bigint } => {
      const first = stated * L < readMs ? stated * L : readMs;
      const last = (stated + 1n) * L > readMs ? (stated + 1n) * L : readMs + 1n;
      if (kind === "inside")
        return { notBefore: first - L, notAfter: last + L };
      if (kind === "straddling notBefore")
        return { notBefore: stated * L + L / 2n, notAfter: last + L };
      if (kind === "straddling notAfter")
        return { notBefore: first - L, notAfter: stated * L + L / 2n };
      // Half-open: at `notAfter` itself the descriptor is no longer valid.
      return { notBefore: first - L, notAfter: readMs };
    };

    /**
     * The table, from the profile's numbers and the descriptor's alone: the
     * step that ends the cell and the outcome's name. W is the chain start,
     * so every window asked for is at or after it.
     */
    const tabled = (cell: {
      route: Route;
      status: string;
      listed: boolean;
      stated: bigint;
      readMs: bigint;
      notBefore: bigint;
      notAfter: bigint;
    }): { step: number; scan: string; kinds: string[]; inert: boolean } => {
      const { status, stated, readMs, notBefore, notAfter } = cell;
      // 0. This client's clock has reached the descriptor's end: it asks
      // the store nothing, and stops using it once, with no record per read.
      if (readMs >= notAfter)
        return { step: 0, scan: "stopped", kinds: [], inert: false };
      const blame = (kind: string) => ({
        step: 3,
        scan: "unreachable",
        kinds: [kind],
        inert: true,
      });
      const report = (step: number, kind: string, scan: string) => ({
        step,
        scan,
        kinds: [kind],
        inert: false,
      });
      // 1. Not the chunk that was asked for.
      if (!cell.listed) return report(1, "signature-invalid", "unreachable");
      // 3. The store's own statements.
      if (status === "chain-unavailable") return blame("chain-denial-breach");
      if (status === "no-such-chunk") return blame("chunk-denial-breach");
      if (status === "out-of-range" && (W > stated || stated - W <= R))
        return blame("retention-breach");
      if (status === "not-final" && stated * L >= W * L + F)
        return blame("finalization-breach");
      // 4. No instant within the skew of the read lies in the stated window.
      if ((stated + 1n) * L <= readMs - SKEW || stated * L > readMs + SKEW)
        return report(4, "store-clock-disagreement", "clock-disagreement");
      // 5. The descriptor does not cover the stated window and the read.
      if (
        notBefore > stated * L ||
        (stated + 1n) * L > notAfter ||
        readMs < notBefore ||
        readMs >= notAfter
      )
        return report(
          5,
          "descriptor-out-of-validity",
          "descriptor-out-of-validity",
        );
      // 6. Sent when no store within the skew still reads before the close.
      if (status === "not-final" && readMs >= W * L + F + SKEW)
        return report(6, "store-clock-disagreement", "clock-disagreement");
      // 7.
      return {
        step: 7,
        scan: status === "out-of-range" ? "beyond-retention" : "not-final",
        kinds: [],
        inert: false,
      };
    };

    /**
     * Every answer the real core signs for this read at a clock reading
     * within the skew of `readMs`, as `status@storeWindow@reading`.
     */
    const honest = new Map<
      string,
      { status: string; stated: bigint; atMs: bigint }[]
    >();
    for (const [, readMs] of READS)
      for (const route of ["checkpoint", "chunk"] as const) {
        const answers: { status: string; stated: bigint; atMs: bigint }[] = [];
        for (let atMs = readMs - SKEW; atMs <= readMs + SKEW; atMs++) {
          storeClock.now = atMs;
          const read = await (route === "checkpoint"
            ? core.readCheckpoint(PROFILE_HASH, W)
            : core.readChunk(
                {
                  deliveryProfileHash: PROFILE_HASH,
                  ingressWindow: W,
                  sizeClass: 0,
                },
                0n,
              ));
          if (read.kind === "status")
            answers.push({
              status: read.value.status,
              stated: read.value.storeIngressWindow,
              atMs,
            });
        }
        honest.set(`${route}@${String(readMs)}`, answers);
      }
    storeClock.now = FIN;

    const documents = new Map<string, DescriptorDocument>();
    const endedAt = new Map<number, number>();
    const benign = new Map<string, number>();
    const seenKinds = new Set<string>();
    const wrong: string[] = [];
    let cells = 0;
    for (const { route, status, listed } of STATUSES)
      for (const [statedName, stated] of STATED)
        for (const [readName, readMs] of READS)
          for (const validity of VALIDITY) {
            cells += 1;
            const { notBefore, notAfter } = validityFor(
              validity,
              stated,
              readMs,
            );
            const key = `${String(notBefore)}:${String(notAfter)}`;
            const document =
              documents.get(key) ?? (await documentValid(notBefore, notAfter));
            documents.set(key, document);
            const answer = await signedStatus(
              route,
              status,
              stated,
              await descriptorHash(document.descriptor),
              listed
                ? { sizeClass: 0, chunkIndex: 0n }
                : { sizeClass: 0, chunkIndex: CLASS_0_CHUNKS },
            );
            const { client, scan, kinds } = await scanAt(
              document,
              route,
              answer,
              readMs,
            );
            const expected = tabled({
              route,
              status,
              listed,
              stated,
              readMs,
              notBefore,
              notAfter,
            });
            const name = `${route} ${status}${listed ? "" : " (unlisted chunk)"} | stated ${statedName} | read at ${readName} | validity ${validity}`;
            const got = `${scan.status} [${kinds.join(",")}] inert=${String(client.inert)}`;
            const want = `${expected.scan} [${expected.kinds.join(",")}] inert=${String(expected.inert)}`;
            if (got !== want) wrong.push(`${name}: got ${got}, want ${want}`);
            endedAt.set(expected.step, (endedAt.get(expected.step) ?? 0) + 1);
            for (const kind of kinds) seenKinds.add(kind);

            // Blame is provable from the kept record alone, and nothing
            // else is evidence.
            const proved =
              client.faults.length === 1
                ? await provedBy(client.faults[0])
                : null;
            if (proved !== (expected.step === 3 ? expected.kinds[0] : null))
              wrong.push(`${name}: the verifier said ${String(proved)}`);
            // Where the client did not blame, the answer itself (beside
            // W's checkpoint, for a chunk) proves nothing to anyone either;
            // an answer to a request never made is not judged at all.
            if (expected.step !== 3 && expected.step !== 0) {
              const direct = await signedStatusProvesFault(
                document.descriptor,
                profile,
                route === "chunk" ? [checkpoint, answer] : [answer],
                cryptoModule,
              );
              if (direct !== null)
                wrong.push(`${name}: unblamed, yet it proves ${direct}`);
            }

            // An honest store whose clock is within the skew of this
            // client's, under a descriptor valid at that reading.
            const producible =
              listed &&
              (honest.get(`${route}@${String(readMs)}`) ?? []).some(
                (candidate) =>
                  candidate.status === status &&
                  candidate.stated === stated &&
                  notBefore <= candidate.atMs &&
                  candidate.atMs < notAfter,
              );
            const isBenign =
              scan.status === "beyond-retention" || scan.status === "not-final";
            if (isBenign)
              benign.set(scan.status, (benign.get(scan.status) ?? 0) + 1);
            // The only benign cells are ones such a store can produce.
            if (isBenign && (!producible || kinds.length > 0 || client.inert))
              wrong.push(
                `${name}: benign, and no honest store within the skew signs it`,
              );
            // And with the descriptor valid throughout, every answer such a
            // store can produce is benign: it is never reported.
            if (validity === "inside" && producible && !isBenign)
              wrong.push(
                `${name}: an honest store within the skew signs it, got ${got}`,
              );
          }

    expect(wrong).toEqual([]);
    expect(cells).toBe(
      STATUSES.length * STATED.length * READS.length * VALIDITY.length,
    );
    // Not vacuous: every step ends some cell, both benign outcomes occur,
    // and every outcome the table names was seen.
    expect([...endedAt.keys()].sort()).toEqual([0, 1, 3, 4, 5, 6, 7]);
    expect((benign.get("not-final") ?? 0) > 0).toBe(true);
    expect((benign.get("beyond-retention") ?? 0) > 0).toBe(true);
    expect([...seenKinds].sort()).toEqual([
      "chain-denial-breach",
      "chunk-denial-breach",
      "descriptor-out-of-validity",
      "finalization-breach",
      "retention-breach",
      "signature-invalid",
      "store-clock-disagreement",
    ]);
  }, 120_000);
});

/* ------------------------------------------------------------------ *
 * The verified run
 *
 * What a scan costs this client, counted rather than timed: Ed25519
 * verifications through a module that counts every `_verify` call, and the
 * SHA-256 of carrier objects through WebCrypto. Both are the real module;
 * nothing of the client is replaced.
 * ------------------------------------------------------------------ */

describe("prototype store client verified run", () => {
  const CHUNKS_PER_WINDOW = profile.sizeClasses.reduce(
    (total, sizeClass) => total + sizeClass.publicChunksPerWindow,
    0,
  );
  /** Every chunk signature, and the descriptor's and the checkpoint's own
   * signature in the checkpoint's structural check: what any finalized scan
   * verifies of its own answers. */
  const OWN_VERIFICATIONS = CHUNKS_PER_WINDOW + 2;
  /** What the full chain verifier adds per observation it re-verifies. */
  const PER_REVERIFIED_OBSERVATION = 2;

  const OBJECT_BYTES = new Set(
    profile.sizeClasses.map((sizeClass) =>
      carrierObjectWireBytes(profile, sizeClass.id, PROFILE_HASH),
    ),
  );

  /** `cryptoModule`, with every Ed25519 verification counted. */
  const countingModule = (): {
    readonly module: LibCrypto;
    readonly take: () => number;
  } => {
    let count = 0;
    const module = new Proxy(cryptoModule, {
      get(target, property, receiver) {
        const value: unknown = Reflect.get(target, property, receiver);
        if (property !== "_verify" || typeof value !== "function") return value;
        return (...args: unknown[]): unknown => {
          count += 1;
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
    return {
      module,
      take: () => {
        const taken = count;
        count = 0;
        return taken;
      },
    };
  };

  /** One scan, with the verifications it made and the carrier objects it
   * hashed (a SHA-256 over exactly one object's wire length). */
  const countedScan = async (
    client: PrototypeStoreClient,
    counting: ReturnType<typeof countingModule>,
    window: bigint,
  ): Promise<{
    readonly status: string;
    readonly verifications: number;
    readonly objectHashes: number;
  }> => {
    counting.take();
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    let objectHashes = 0;
    const spy = spyOn(crypto.subtle, "digest").mockImplementation(
      async (algorithm, data) => {
        const length = ArrayBuffer.isView(data)
          ? data.byteLength
          : (data as ArrayBuffer).byteLength;
        if (OBJECT_BYTES.has(length)) objectHashes += 1;
        return digest(algorithm, data);
      },
    );
    try {
      const scan = await client.scanWindow(window);
      return {
        status: scan.status,
        verifications: counting.take(),
        objectHashes,
      };
    } finally {
      spy.mockRestore();
    }
  };

  const connectCounting = async (
    origin: string,
    clock: Clock,
    counting: ReturnType<typeof countingModule>,
    fetchOverride?: typeof fetch,
  ): Promise<PrototypeStoreClient> =>
    PrototypeStoreClient.connect({
      origin,
      profile,
      profileHash: PROFILE_HASH,
      module: counting.module,
      fetch: fetchOverride,
      nowMs: () => clock.now,
    });

  /** Finalize every window from the chain start through `last`. */
  const finalizeThrough = async (
    store: StoreProcess,
    clock: Clock,
    last: bigint,
  ): Promise<void> => {
    clock.now = FINALIZE_AT + (last - CHAIN_START) * profile.deliveryWindowMs;
    while ((await store.core.finalizeDue()).length > 0);
  };

  test("scan verifies only new checkpoints", async () => {
    await withStore(async (store, clock) => {
      const counting = countingModule();
      const client = await connectCounting(store.origin, clock, counting);
      const WINDOWS = 6;
      await finalizeThrough(store, clock, CHAIN_START + BigInt(WINDOWS - 1));

      const scans = [];
      for (let offset = 0; offset < WINDOWS; offset++)
        scans.push(
          await countedScan(client, counting, CHAIN_START + BigInt(offset)),
        );
      // The first scan builds the run with the full verifier over its one
      // observation; every later one checks its own answers and how its
      // checkpoint links to the run, by the hashes kept for it. Before the
      // run was kept, scan n re-verified all n observations.
      expect(scans).toEqual(
        Array.from({ length: WINDOWS }, (_, offset) => ({
          status: "finalized",
          verifications:
            OWN_VERIFICATIONS + (offset === 0 ? PER_REVERIFIED_OBSERVATION : 0),
          objectHashes: OBJECTS_PER_WINDOW,
        })),
      );

      // A window read again: its answers are checked again, its checkpoint
      // is already in the run, and its objects are not hashed again.
      for (const offset of [0, WINDOWS - 1])
        expect(
          await countedScan(client, counting, CHAIN_START + BigInt(offset)),
        ).toEqual({
          status: "finalized",
          verifications: OWN_VERIFICATIONS,
          objectHashes: 0,
        });
      expect(client.faults).toEqual([]);
      expect(client.inert).toBe(false);
    });
  });

  test("a checkpoint that does not link to its neighbour in the verified run is a chain fault", async () => {
    // Two processes holding one key are one store with two branches: each
    // fills its unoccupied slots from its own CSPRNG, so their chains differ
    // from the chain start on, and each is consistent on its own.
    const clock: Clock = { now: WINDOW_START };
    const first = await startStore(clock);
    const second = await startStore(clock);
    try {
      clock.now = FINALIZE_AT + profile.deliveryWindowMs;
      await first.core.finalizeDue();
      await second.core.finalizeDue();
      // The run holds the predecessor, then the successor.
      for (const [held, added] of [
        [CHAIN_START, CHAIN_START + 1n],
        [CHAIN_START + 1n, CHAIN_START],
      ] as const) {
        let origin = first.origin;
        const branch = ((input: RequestInfo | URL, init?: RequestInit) =>
          fetch(
            `${origin}${new URL(String(input)).pathname}`,
            init,
          )) as typeof fetch;
        const client = await connect(first.origin, clock, { fetch: branch });
        expect((await client.scanWindow(held)).status).toBe("finalized");
        expect(client.faults).toEqual([]);
        origin = second.origin;
        expect((await client.scanWindow(added)).status).toBe("finalized");
        expect(client.inert).toBe(true);
        expect(client.faults.map((fault) => fault.kind)).toEqual([
          "chain-fault",
        ]);
        expect(client.faults[0].detail).toContain("chain-breach");
      }
    } finally {
      first.stop();
      second.stop();
    }
  });

  /* ---------------------------------------------------------------- *
   * Overlapping scans
   *
   * Two scans of one store can be out at once, and the full chain
   * verification awaits. These hold chosen verifications and release them
   * in a chosen order, through the production entry point.
   * ---------------------------------------------------------------- */

  /**
   * Two processes holding the store's key, so one store with two branches,
   * whose window 0 is the same on both: every slot of it carries the same
   * appended object, so nothing in it is random cover, and every signature
   * over it is the same. Windows 1 and 2 hold cover from each process's own
   * CSPRNG, so each branch's window 1 links to the shared window 0 and the
   * two differ: an equivocation over window 1, and window 2 of one branch
   * does not link to window 1 of the other.
   */
  const twoBranches = async (): Promise<{
    readonly clock: Clock;
    readonly first: StoreProcess;
    readonly second: StoreProcess;
    readonly stop: () => void;
  }> => {
    const clock: Clock = { now: WINDOW_START };
    const first = await startStore(clock);
    const second = await startStore(clock);
    for (
      let ordinal = 0;
      ordinal < profile.cohortAllocationsPerWindow;
      ordinal++
    ) {
      const keyPair = await newKeyPair(cryptoModule);
      const request = {
        version: 1 as const,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        allocationEd25519PublicKey: keyPair.publicKey,
        privacyPassToken: new Uint8Array(32),
      };
      const leases = await Promise.all(
        [first, second].map(async (store) => {
          const result = await store.core.allocate(request);
          if (result.kind !== "allocated") throw new Error("expected a lease");
          return result.lease;
        }),
      );
      expect(leases[0].allocationOrdinal).toBe(ordinal);
      expect(leases[1].allocationOrdinal).toBe(ordinal);
      for (const sizeClass of profile.sizeClasses)
        for (let entry = 0; entry < sizeClass.appendSchedule.length; entry++) {
          const object = new Uint8Array(
            carrierObjectWireBytes(profile, sizeClass.id, PROFILE_HASH),
          ).fill(0x10 + ordinal * 8 + entry);
          for (const [index, store] of [first, second].entries()) {
            const result = await store.core.append({
              version: 1,
              bucket: {
                deliveryProfileHash: PROFILE_HASH,
                ingressWindow: CHAIN_START,
                sizeClass: sizeClass.id,
              },
              exactFixedObject: object,
              admission: await buildAppendAdmission(
                leases[index],
                keyPair.secretKey,
                sizeClass.id,
                entry,
                object,
                cryptoModule,
              ),
            });
            expect(result.status).toBe("stored");
          }
        }
    }
    clock.now = FINALIZE_AT + 2n * profile.deliveryWindowMs;
    for (const store of [first, second])
      expect(await store.core.finalizeDue()).toEqual([
        CHAIN_START,
        CHAIN_START + 1n,
        CHAIN_START + 2n,
      ]);
    const hashOf = async (store: StoreProcess, window: bigint) =>
      hex(await publicStoreCheckpointHash(await checkpointOf(store, window)));
    expect(await hashOf(first, CHAIN_START)).toBe(
      await hashOf(second, CHAIN_START),
    );
    expect(await hashOf(first, CHAIN_START + 1n)).not.toBe(
      await hashOf(second, CHAIN_START + 1n),
    );
    return {
      clock,
      first,
      second,
      stop: () => {
        first.stop();
        second.stop();
      },
    };
  };

  const checkpointOf = async (
    store: StoreProcess,
    window: bigint,
  ): Promise<PublicStoreCheckpointV1> => {
    const read = await store.core.readCheckpoint(PROFILE_HASH, window);
    if (read.kind !== "finalized") throw new Error("expected a checkpoint");
    return read.checkpoint;
  };

  /** A transport that reads each window from the branch the test names. */
  const routedBy = (
    branches: Map<bigint, string>,
    fallback: string,
  ): typeof fetch =>
    ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const window = /\/(\d+)(?:\/\d+\/\d+)?$/.exec(url.pathname);
      const origin =
        window === null
          ? fallback
          : (branches.get(BigInt(window[1])) ?? fallback);
      return fetch(`${origin}${url.pathname}`, init);
    }) as typeof fetch;

  /**
   * Hold a scan's full chain verification at its last await, until released.
   *
   * A scan hashes its own checkpoint once before it decides the chain, and
   * the full verifier hashes the run's head again as its last step before it
   * returns a verified run: so the second digest whose output is that
   * checkpoint's hash is the verifier finishing. Holding it there, the run
   * it verified is decided, and what the client does with it waits.
   */
  const verifierGate = (): {
    readonly hold: (checkpointHash: Uint8Array) => {
      readonly entered: Promise<void>;
      readonly release: () => void;
    };
    readonly restore: () => void;
  } => {
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    const armed: {
      readonly target: string;
      seen: number;
      readonly enter: () => void;
      readonly wait: Promise<void>;
    }[] = [];
    const spy = spyOn(crypto.subtle, "digest").mockImplementation(
      async (algorithm, data) => {
        const output = await digest(algorithm, data);
        const outputHex = hex(new Uint8Array(output));
        const holding = armed.find((entry) => entry.target === outputHex);
        if (holding !== undefined) {
          holding.seen += 1;
          if (holding.seen === 2) {
            armed.splice(armed.indexOf(holding), 1);
            holding.enter();
            await holding.wait;
          }
        }
        return output;
      },
    );
    return {
      hold: (checkpointHash) => {
        let enter!: () => void;
        let release!: () => void;
        const entered = new Promise<void>((resolve) => {
          enter = resolve;
        });
        const wait = new Promise<void>((resolve) => {
          release = resolve;
        });
        armed.push({ target: hex(checkpointHash), seen: 0, enter, wait });
        return { entered, release };
      },
      restore: () => spy.mockRestore(),
    };
  };

  /** Wait until a scan's verification is held, or fail if the scan ends first. */
  const heldOrFail = async (
    held: { readonly entered: Promise<void> },
    scan: Promise<unknown>,
  ): Promise<void> => {
    await Promise.race([
      held.entered,
      scan.then(() => {
        throw new Error("the scan ended without its verification being held");
      }),
    ]);
  };

  /**
   * Window 0 and window 1 of the first branch scanned at once, each scan's
   * full verification held: the first holds a snapshot of window 0 alone,
   * the second one of both.
   */
  const overlapped = async (
    client: PrototypeStoreClient,
    counting: ReturnType<typeof countingModule>,
    gate: ReturnType<typeof verifierGate>,
    branch: StoreProcess,
  ) => {
    counting.take();
    const olderHeld = gate.hold(
      await publicStoreCheckpointHash(await checkpointOf(branch, CHAIN_START)),
    );
    const older = client.scanWindow(CHAIN_START);
    await heldOrFail(olderHeld, older);
    // The overlap is real, not assumed: each scan is held after its full
    // verifier has checked its snapshot, and the counts say which snapshot
    // that was. The older one verified window 0 alone (its own answers and
    // one observation); the newer one, started while the older was held,
    // verified windows 0 and 1. Neither has returned.
    expect(counting.take()).toBe(
      OWN_VERIFICATIONS + PER_REVERIFIED_OBSERVATION,
    );
    const newerHeld = gate.hold(
      await publicStoreCheckpointHash(
        await checkpointOf(branch, CHAIN_START + 1n),
      ),
    );
    const newer = client.scanWindow(CHAIN_START + 1n);
    await heldOrFail(newerHeld, newer);
    expect(counting.take()).toBe(
      OWN_VERIFICATIONS + 2 * PER_REVERIFIED_OBSERVATION,
    );
    return { older, olderHeld, newer, newerHeld };
  };

  test("a run verified from a snapshot that an overlapping scan has outgrown is not kept", async () => {
    const world = await twoBranches();
    const gate = verifierGate();
    try {
      const branches = new Map<bigint, string>();
      const counting = countingModule();
      const client = await connectCounting(
        world.first.origin,
        world.clock,
        counting,
        routedBy(branches, world.first.origin),
      );
      const { older, olderHeld, newer, newerHeld } = await overlapped(
        client,
        counting,
        gate,
        world.first,
      );
      // The verification of window 0 alone finishes while window 1 has been
      // observed meanwhile: what it verified is not the run any more.
      olderHeld.release();
      expect((await older).status).toBe("finalized");
      // Window 2 of the second branch does not link to the observed window
      // 1. A run kept from the outgrown snapshot (window 0 alone) has no
      // window 1 to hold it against, so it would take window 2 unchecked.
      branches.set(CHAIN_START + 2n, world.second.origin);
      expect((await client.scanWindow(CHAIN_START + 2n)).status).toBe(
        "finalized",
      );
      expect(client.inert).toBe(true);
      expect(client.faults.map((fault) => fault.kind)).toEqual(["chain-fault"]);
      expect(client.faults[0].detail).toContain("chain-breach");
      newerHeld.release();
      await newer;
    } finally {
      gate.restore();
      world.stop();
    }
  });

  test("an older verification that finishes last does not replace a newer run", async () => {
    const world = await twoBranches();
    const gate = verifierGate();
    try {
      const branches = new Map<bigint, string>();
      const counting = countingModule();
      const client = await connectCounting(
        world.first.origin,
        world.clock,
        counting,
        routedBy(branches, world.first.origin),
      );
      const { older, olderHeld, newer, newerHeld } = await overlapped(
        client,
        counting,
        gate,
        world.first,
      );
      // The newer verification (windows 0 and 1) finishes first and is the
      // run; the older one (window 0 alone) finishes after it.
      newerHeld.release();
      expect((await newer).status).toBe("finalized");
      olderHeld.release();
      expect((await older).status).toBe("finalized");
      expect(client.faults).toEqual([]);
      // The run still holds window 1, so window 2 of the other branch is
      // held against it and refused.
      branches.set(CHAIN_START + 2n, world.second.origin);
      await client.scanWindow(CHAIN_START + 2n);
      expect(client.inert).toBe(true);
      expect(client.faults.map((fault) => fault.kind)).toEqual(["chain-fault"]);
      expect(client.faults[0].detail).toContain("chain-breach");
    } finally {
      gate.restore();
      world.stop();
    }
  });

  test("a second checkpoint for a window already observed never takes the fast path, and the store is blamed for equivocation", async () => {
    for (const order of ["older first", "newer first"] as const) {
      const world = await twoBranches();
      const gate = verifierGate();
      try {
        const counting = countingModule();
        const branches = new Map<bigint, string>();
        const client = await connectCounting(
          world.first.origin,
          world.clock,
          counting,
          routedBy(branches, world.first.origin),
        );
        const { older, olderHeld, newer, newerHeld } = await overlapped(
          client,
          counting,
          gate,
          world.first,
        );
        if (order === "older first") {
          olderHeld.release();
          await older;
        } else {
          newerHeld.release();
          await newer;
          olderHeld.release();
          await older;
        }
        // Window 1 of the other branch: the same predecessor, another
        // checkpoint. It goes to the full verifier, which re-verifies the
        // three observations it then holds, and names the equivocation.
        branches.set(CHAIN_START + 1n, world.second.origin);
        counting.take();
        await client.scanWindow(CHAIN_START + 1n);
        expect([order, counting.take()]).toEqual([
          order,
          OWN_VERIFICATIONS + 3 * PER_REVERIFIED_OBSERVATION,
        ]);
        expect([order, client.inert]).toEqual([order, true]);
        expect(client.faults.map((fault) => fault.kind)).toEqual([
          "chain-fault",
        ]);
        expect(client.faults[0].detail).toContain("checkpoint-conflict");
        if (order === "older first") {
          newerHeld.release();
          await newer;
        }
      } finally {
        gate.restore();
        world.stop();
      }
    }
  });

  test("a run verified across a blame is not kept", async () => {
    await withStore(async (store, clock) => {
      await finalizeThrough(store, clock, CHAIN_START + 4n);
      // A blame that observes nothing: a signed out-of-range for window 3,
      // inside the stated retention.
      const value = {
        version: 1 as const,
        storeId: store.core.storeId,
        descriptorHash: store.core.descriptorHash,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START + 3n,
        storeIngressWindow: CHAIN_START + 4n,
        status: "out-of-range" as const,
      };
      const refusal = encodePublicStoreCheckpointReadV1({
        kind: "status",
        value,
        storeSignature: await sign(
          await publicCheckpointStatusSigningHash(value),
          await storeSecretKey(),
          cryptoModule,
        ),
      });
      const refusingWindow3 = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (
          url.pathname ===
          `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(CHAIN_START + 3n)}`
        )
          return Promise.resolve(
            new Response(asBody(refusal), {
              status: 200,
              headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
            }),
          );
        return fetch(`${store.origin}${url.pathname}`, init);
      }) as typeof fetch;
      const counting = countingModule();
      const client = await connectCounting(
        store.origin,
        clock,
        counting,
        refusingWindow3,
      );
      const gate = verifierGate();
      try {
        const held = gate.hold(
          await publicStoreCheckpointHash(
            await checkpointOf(store, CHAIN_START),
          ),
        );
        counting.take();
        const first = client.scanWindow(CHAIN_START);
        await heldOrFail(held, first);
        // Held after its full verifier checked window 0, not before.
        expect(counting.take()).toBe(
          OWN_VERIFICATIONS + PER_REVERIFIED_OBSERVATION,
        );
        expect((await client.scanWindow(CHAIN_START + 3n)).status).toBe(
          "unreachable",
        );
        expect(client.faults.map((fault) => fault.kind)).toEqual([
          "retention-breach",
        ]);
        held.release();
        expect((await first).status).toBe("finalized");
      } finally {
        gate.restore();
      }
      // Verified before the blame and finished after it: not kept, so the
      // next scan verifies everything observed.
      counting.take();
      await client.scanWindow(CHAIN_START + 1n);
      expect(counting.take()).toBe(
        OWN_VERIFICATIONS + 2 * PER_REVERIFIED_OBSERVATION,
      );
    });
  });

  test("the verified run is dropped on blame, on a changed descriptor and on reconnect", async () => {
    // Blame: a store that acknowledges an append it never binds.
    await withStore(
      async (store, clock) => {
        const counting = countingModule();
        const client = await connectCounting(store.origin, clock, counting);
        await finalizeThrough(store, clock, CHAIN_START + 2n);
        for (let offset = 0n; offset < 3n; offset++)
          await countedScan(client, counting, CHAIN_START + offset);

        clock.now = WINDOW_START + 3n * profile.deliveryWindowMs;
        await appendObject(client, CHAIN_START + 3n, 0x41);
        await finalizeThrough(store, clock, CHAIN_START + 4n);
        expect(
          (await countedScan(client, counting, CHAIN_START + 3n)).verifications,
        ).toBe(OWN_VERIFICATIONS);
        expect(client.inert).toBe(true);
        expect(client.faults.map((fault) => fault.kind)).toEqual([
          "custody-breach",
        ]);
        // Distrusted now: the next scan re-verifies the whole run of five,
        // and the one after it extends the rebuilt run again.
        expect(
          (await countedScan(client, counting, CHAIN_START + 4n)).verifications,
        ).toBe(OWN_VERIFICATIONS + 5 * PER_REVERIFIED_OBSERVATION);
        await finalizeThrough(store, clock, CHAIN_START + 5n);
        expect(
          (await countedScan(client, counting, CHAIN_START + 5n)).verifications,
        ).toBe(OWN_VERIFICATIONS);
      },
      { fault: "withhold" },
    );

    // Blame on the store's own signed words: an `out-of-range` for window 3,
    // signed at window 4, inside the retention its descriptor states.
    await withStore(async (store, clock) => {
      await finalizeThrough(store, clock, CHAIN_START + 4n);
      const value = {
        version: 1 as const,
        storeId: store.core.storeId,
        descriptorHash: store.core.descriptorHash,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START + 3n,
        storeIngressWindow: CHAIN_START + 4n,
        status: "out-of-range" as const,
      };
      const refusal = encodePublicStoreCheckpointReadV1({
        kind: "status",
        value,
        storeSignature: await sign(
          await publicCheckpointStatusSigningHash(value),
          await storeSecretKey(),
          cryptoModule,
        ),
      });
      const refusingWindow3 = ((
        input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        const url = new URL(String(input));
        if (
          url.pathname ===
          `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(CHAIN_START + 3n)}`
        )
          return Promise.resolve(
            new Response(asBody(refusal), {
              status: 200,
              headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
            }),
          );
        return fetch(`${store.origin}${url.pathname}`, init);
      }) as typeof fetch;
      const counting = countingModule();
      const client = await connectCounting(
        store.origin,
        clock,
        counting,
        refusingWindow3,
      );
      for (let offset = 0n; offset < 3n; offset++)
        await countedScan(client, counting, CHAIN_START + offset);
      expect(
        (await countedScan(client, counting, CHAIN_START + 3n)).status,
      ).toBe("unreachable");
      expect(client.faults.map((fault) => fault.kind)).toEqual([
        "retention-breach",
      ]);
      // Windows 0 to 2 and 4: the whole run again.
      expect(
        (await countedScan(client, counting, CHAIN_START + 4n)).verifications,
      ).toBe(OWN_VERIFICATIONS + 4 * PER_REVERIFIED_OBSERVATION);
    });

    // A changed descriptor, and a reconnect.
    await withStore(async (store, clock) => {
      await finalizeThrough(store, clock, CHAIN_START + 3n);
      const secretKey = await storeSecretKey();
      // A second descriptor under the same key, and window 3's checkpoint
      // signed again under it: the same chunks and the same predecessor, so
      // the chain stays one chain across the change.
      const draft = { ...store.core.descriptor, descriptorGeneration: 2n };
      const second: StoreDescriptorV1 = {
        ...draft,
        descriptorSignature: await sign(
          await storeDescriptorSignedMessage(draft),
          secretKey,
          cryptoModule,
        ),
      };
      const served = await store.core.readCheckpoint(
        PROFILE_HASH,
        CHAIN_START + 3n,
      );
      if (served.kind !== "finalized") throw new Error("expected a checkpoint");
      const { storeSignature: _signature, ...body } = served.checkpoint;
      const resignedBody = {
        ...body,
        descriptorHash: await descriptorHash(second),
      };
      const resigned = encodePublicStoreCheckpointReadV1({
        kind: "finalized",
        descriptor: second,
        checkpoint: {
          ...resignedBody,
          storeSignature: await sign(
            await publicStoreCheckpointSigningHash(resignedBody),
            secretKey,
            cryptoModule,
          ),
        },
      });
      const underSecond = ((input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input));
        if (
          url.pathname ===
          `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(CHAIN_START + 3n)}`
        )
          return Promise.resolve(
            new Response(asBody(resigned), {
              status: 200,
              headers: headersOf(PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
            }),
          );
        return fetch(`${store.origin}${url.pathname}`, init);
      }) as typeof fetch;

      const counting = countingModule();
      const client = await connectCounting(
        store.origin,
        clock,
        counting,
        underSecond,
      );
      for (let offset = 0n; offset < 3n; offset++)
        await countedScan(client, counting, CHAIN_START + offset);
      // Window 3 under the second descriptor: the run of four is verified
      // again in full, then held under that descriptor.
      expect(await countedScan(client, counting, CHAIN_START + 3n)).toEqual({
        status: "finalized",
        verifications: OWN_VERIFICATIONS + 4 * PER_REVERIFIED_OBSERVATION,
        objectHashes: OBJECTS_PER_WINDOW,
      });
      expect(
        (await countedScan(client, counting, CHAIN_START + 3n)).verifications,
      ).toBe(OWN_VERIFICATIONS);
      expect(client.faults).toEqual([]);

      // A reconnect is a new client: nothing the first one verified carries
      // over, so its first scan of a window the first client holds builds a
      // run of its own.
      const reconnecting = countingModule();
      const reconnected = await connectCounting(
        store.origin,
        clock,
        reconnecting,
      );
      expect(
        (await countedScan(reconnected, reconnecting, CHAIN_START + 1n))
          .verifications,
      ).toBe(OWN_VERIFICATIONS + PER_REVERIFIED_OBSERVATION);
      expect(
        (await countedScan(reconnected, reconnecting, CHAIN_START + 2n))
          .verifications,
      ).toBe(OWN_VERIFICATIONS);
    });
  });
});
