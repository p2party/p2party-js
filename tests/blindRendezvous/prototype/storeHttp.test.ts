import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import libcrypto from "../../../src/cryptography/libcrypto";
import { newKeyPair, sign } from "../../../src/cryptography/ed25519";
import {
  allocationAppendSignedMessage,
  deliveryProfileHash,
} from "../../../src/blindRendezvous/derivations";
import { ingressWindowStartMs } from "../../../src/blindRendezvous/publicWindow";
import { validateStoreDescriptor } from "../../../src/blindRendezvous/storeDescriptor";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  PROTOTYPE_MEDIA_TYPE,
  PROTOTYPE_STORE_PROTOCOL,
  carrierObjectWireBytes,
  withDeliveryWindowMs,
} from "../../../src/blindRendezvous/prototype/profile";
import {
  PrototypeStoreCore,
  type PrototypeStoreCoreOptions,
} from "../../../src/blindRendezvous/prototype/store/storeCore";
import { PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH } from "../../../src/utils/constants";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
  createPrototypeStoreHandler,
} from "../../../src/blindRendezvous/prototype/store/storeHttp";
import {
  decodeAllocationTokenIssueResultV1,
  decodePrototypeStoreDescriptorDocumentV1,
  decodePublicAllocationResultV1,
  decodePublicAppendResultV1,
  decodePublicChunkReadV1,
  decodePublicStoreCheckpointReadV1,
  decodeStoreWitnessRecordsV1,
  encodeAllocationTokenIssueRequestV1,
  encodePublicAllocationRequestV1,
  encodePublicAppendRequestV1,
  encodeStoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type { PublicAllocationLeaseV1 } from "../../../src/blindRendezvous/prototype/storeWire";
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
const PROFILE_HASH = await deliveryProfileHash(profile);
const PROFILE_HEX = hex(PROFILE_HASH);

const CHAIN_START = 425_000_000n;
const WINDOW_START = ingressWindowStartMs(
  CHAIN_START,
  profile.deliveryWindowMs,
);
const FINALIZE_AT = WINDOW_START + profile.chunkFinalizationOffsetMs;

const SEED = new Uint8Array(32).fill(0x5a);
const CLASS_0_OBJECT_BYTES = carrierObjectWireBytes(profile, 0, PROFILE_HASH);

const IMMUTABLE = "public, max-age=31536000, immutable";

const logRoot = mkdtempSync(join(tmpdir(), "p2party-store-http-"));
let logCounter = 0;

afterAll(() => {
  rmSync(logRoot, { recursive: true, force: true });
});

/**
 * A message with the shape of a real storage failure: a path, and a word the
 * refusal vocabulary also uses. Neither may appear in the response or the log.
 */
const EXPLOSION_DETAIL =
  "sqlite: disk image is malformed at /var/secret/p2party-store.sqlite";

/**
 * Reads fail the way a corrupt file does — with a plain `Error`, not a
 * `StoreRequestError` and not a `CanonicalSchemaError`. That is the only way
 * to reach the handler's last-resort branch.
 */
class ExplodingStorePersistence extends MemoryStorePersistence {
  override async loadWindow(): Promise<never> {
    throw new Error(EXPLOSION_DETAIL);
  }
}

interface Harness {
  readonly core: PrototypeStoreCore;
  readonly base: string;
  readonly setNow: (ms: bigint) => void;
  readonly stop: () => void;
}

interface HarnessOptions {
  readonly logBodiesPath?: string;
  readonly allocationAdmission?: PrototypeStoreCoreOptions["allocationAdmission"];
  readonly persistence?: PrototypeStoreCoreOptions["persistence"];
}

const harness = async (options: HarnessOptions = {}): Promise<Harness> => {
  let now = WINDOW_START;
  const core = await PrototypeStoreCore.create({
    module: cryptoModule,
    seed: SEED,
    profile,
    clock: { nowMs: () => now },
    persistence: options.persistence ?? new MemoryStorePersistence(),
    chainStartIngressWindow: CHAIN_START,
    origin: "http://127.0.0.1:5910",
    descriptorValidityMs: 2_592_000_000n,
    allocationAdmission: options.allocationAdmission,
  });
  // A real socket on an ephemeral port: the routing, the header set and the
  // body limits are all properties of the server, not of the handler alone.
  const server = Bun.serve({
    port: 0,
    fetch: createPrototypeStoreHandler({
      core,
      logBodiesPath: options.logBodiesPath,
    }),
  });
  return {
    core,
    base: server.url.origin,
    setNow: (ms: bigint) => {
      now = ms;
    },
    stop: () => {
      void server.stop(true);
    },
  };
};

const withHarness = async (
  run: (harness: Harness) => Promise<void>,
  options: HarnessOptions = {},
): Promise<void> => {
  const active = await harness(options);
  try {
    await run(active);
  } finally {
    active.stop();
  }
};

/** `lib.dom`'s `BufferSource` is `ArrayBufferView<ArrayBuffer>`, and the
 * canonical codecs are typed with the wider `Uint8Array<ArrayBufferLike>`. */
const asBody = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const post = async (
  base: string,
  path: string,
  mediaType: string,
  body: Uint8Array,
  extraHeaders: Record<string, string> = {},
): Promise<Response> =>
  fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": mediaType, ...extraHeaders },
    body: asBody(body),
  });

const bodyBytes = async (response: Response): Promise<Uint8Array> =>
  new Uint8Array(await response.arrayBuffer());

/** Every response, on every route, must be attributable to this protocol. */
const expectStoreHeader = (response: Response): void => {
  expect(response.headers.get("x-p2party-store")).toBe("prototype-v1");
};

const leaseFor = async (
  base: string,
  ingressWindow: bigint,
): Promise<{ lease: PublicAllocationLeaseV1; secretKey: Uint8Array }> => {
  const keyPair = await newKeyPair(cryptoModule);
  const response = await post(
    base,
    PROTOTYPE_STORE_ROUTES.allocation,
    PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
    encodePublicAllocationRequestV1({
      version: 1,
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow,
      allocationEd25519PublicKey: keyPair.publicKey,
      privacyPassToken: new Uint8Array(32),
    }),
  );
  expect(response.status).toBe(200);
  const result = decodePublicAllocationResultV1(await bodyBytes(response));
  if (result.kind !== "allocated")
    throw new Error(`expected a lease, got ${result.value.status}`);
  return { lease: result.lease, secretKey: keyPair.secretKey };
};

const appendBody = async (
  lease: PublicAllocationLeaseV1,
  secretKey: Uint8Array,
  objectOrdinalWithinAllocation: number,
  fill: number,
): Promise<Uint8Array> => {
  const { storeSignature: _storeSignature, ...leaseBody } = lease;
  const exactFixedObject = new Uint8Array(CLASS_0_OBJECT_BYTES).fill(fill);
  return encodePublicAppendRequestV1({
    version: 1,
    bucket: {
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: lease.ingressWindow,
      sizeClass: 0,
    },
    exactFixedObject,
    admission: {
      version: 1,
      lease,
      objectOrdinalWithinAllocation,
      allocationSignature: await sign(
        await allocationAppendSignedMessage(
          leaseBody,
          0,
          objectOrdinalWithinAllocation,
          exactFixedObject,
        ),
        secretKey,
        cryptoModule,
      ),
    },
  });
};

describe("prototype store HTTP handler", () => {
  test("serves a descriptor document that validates under its own key", async () => {
    await withHarness(async ({ base, core }) => {
      const response = await fetch(
        `${base}${PROTOTYPE_STORE_ROUTES.descriptor}`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        "application/p2party-store-descriptor-prototype-v1",
      );
      // The descriptor is re-signed on every start, so a cache would hand a
      // client a store identity the running process no longer answers under.
      expect(response.headers.get("cache-control")).toBe("no-store");
      expectStoreHeader(response);

      const document = decodePrototypeStoreDescriptorDocumentV1(
        await bodyBytes(response),
      );
      expect(hex(document.descriptor.storeIdentityEd25519Key)).toBe(
        hex(core.descriptor.storeIdentityEd25519Key),
      );
      const validity = await validateStoreDescriptor(
        document.descriptor,
        WINDOW_START,
        cryptoModule,
      );
      expect(validity.valid).toBe(true);
      expect(document.routes.length).toBe(1);
    });
  });

  test("issues an open-mode allocation token", async () => {
    await withHarness(async ({ base, core }) => {
      const response = await post(
        base,
        PROTOTYPE_STORE_ROUTES.token,
        PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
        encodeAllocationTokenIssueRequestV1({
          version: 1,
          storeId: core.storeId,
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START,
          privacyPassTokenRequest: new Uint8Array(32),
        }),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        PROTOTYPE_STORE_MEDIA_TYPES.tokenResult,
      );
      expect(response.headers.get("cache-control")).toBe("no-store");
      expectStoreHeader(response);

      const result = decodeAllocationTokenIssueResultV1(
        await bodyBytes(response),
      );
      expect(result.body.kind).toBe("issued");
    });
  });

  test("allocates a lease and stores an append into it", async () => {
    await withHarness(async ({ base }) => {
      const { lease, secretKey } = await leaseFor(base, CHAIN_START);
      expect(lease.allocationOrdinal).toBe(0);

      const response = await post(
        base,
        PROTOTYPE_STORE_ROUTES.append,
        PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        await appendBody(lease, secretKey, 0, 0x7c),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        PROTOTYPE_STORE_MEDIA_TYPES.appendResult,
      );
      expectStoreHeader(response);
      expect(decodePublicAppendResultV1(await bodyBytes(response)).status).toBe(
        "stored",
      );
    });
  });

  test("refuses a POST whose media type is not the exact one", async () => {
    await withHarness(async ({ base, core }) => {
      const body = encodeAllocationTokenIssueRequestV1({
        version: 1,
        storeId: core.storeId,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        privacyPassTokenRequest: new Uint8Array(32),
      });
      for (const mediaType of [
        "application/octet-stream",
        PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
        "",
      ]) {
        const response = await post(
          base,
          PROTOTYPE_STORE_ROUTES.token,
          mediaType,
          body,
        );
        expect(response.status).toBe(400);
        expect(await response.text()).toBe("malformed");
        expectStoreHeader(response);
      }
    });
  });

  test("refuses a malformed body with one constant 400", async () => {
    await withHarness(async ({ base }) => {
      for (const [path, mediaType] of [
        [
          PROTOTYPE_STORE_ROUTES.token,
          PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
        ],
        [
          PROTOTYPE_STORE_ROUTES.allocation,
          PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
        ],
        [
          PROTOTYPE_STORE_ROUTES.append,
          PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        ],
        [
          PROTOTYPE_STORE_ROUTES.witness,
          PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
        ],
      ] as const) {
        const response = await post(
          base,
          path,
          mediaType,
          Uint8Array.of(1, 2, 3),
        );
        expect(response.status).toBe(400);
        expect(await response.text()).toBe("malformed");
        expect(response.headers.get("cache-control")).toBe("no-store");
        expectStoreHeader(response);
      }
    });
  });

  test("refuses a body past the one-request cap", async () => {
    await withHarness(async ({ base }) => {
      const response = await post(
        base,
        PROTOTYPE_STORE_ROUTES.append,
        PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        new Uint8Array(1024 * 1024 + 4096 + 1),
      );
      expect(response.status).toBe(400);
      expect(await response.text()).toBe("malformed");
    });
  });

  test("answers not-final before finalization and finalized after", async () => {
    await withHarness(async ({ base, core, setNow }) => {
      const path = `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(CHAIN_START)}`;

      const before = await fetch(`${base}${path}`);
      expect(before.status).toBe(200);
      expect(before.headers.get("content-type")).toBe(
        PROTOTYPE_STORE_MEDIA_TYPES.checkpoint,
      );
      // A status answer is about *now*; caching it would freeze a window as
      // permanently unfinished for whoever holds the cache.
      expect(before.headers.get("cache-control")).toBe("no-store");
      expectStoreHeader(before);
      const pending = decodePublicStoreCheckpointReadV1(
        await bodyBytes(before),
      );
      expect(pending.kind).toBe("status");
      if (pending.kind === "status")
        expect(pending.value.status).toBe("not-final");

      setNow(FINALIZE_AT);
      expect(await core.finalizeDue()).toEqual([CHAIN_START]);

      const after = await fetch(`${base}${path}`);
      expect(after.status).toBe(200);
      // A finalized checkpoint is immutable by construction: re-signing one is
      // a fault proof, so it can be cached forever.
      expect(after.headers.get("cache-control")).toBe(IMMUTABLE);
      const finalized = decodePublicStoreCheckpointReadV1(
        await bodyBytes(after),
      );
      expect(finalized.kind).toBe("finalized");
      if (finalized.kind === "finalized")
        expect(finalized.checkpoint.ingressWindow).toBe(CHAIN_START);
    });
  });

  test("serves a finalized chunk with the immutable cache header", async () => {
    await withHarness(async ({ base, core, setNow }) => {
      setNow(FINALIZE_AT);
      await core.finalizeDue();

      const response = await fetch(
        `${base}${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(CHAIN_START)}/0/1`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        PROTOTYPE_STORE_MEDIA_TYPES.chunk,
      );
      expect(response.headers.get("cache-control")).toBe(IMMUTABLE);
      expectStoreHeader(response);

      const read = decodePublicChunkReadV1(await bodyBytes(response));
      expect(read.kind).toBe("finalized");
      if (read.kind === "finalized") {
        expect(read.chunk.chunkIndex).toBe(1n);
        expect(read.chunk.bucket.sizeClass).toBe(0);
        expect(read.chunk.fixedObjects.length).toBe(
          profile.publicChunkObjectCount,
        );
      }

      // An index past the class's count is a signed status, not a transport
      // error, and it is `no-such-chunk`, never `out-of-range`.
      const over = await fetch(
        `${base}${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(CHAIN_START)}/0/3`,
      );
      expect(over.status).toBe(200);
      expect(over.headers.get("cache-control")).toBe("no-store");
      const status = decodePublicChunkReadV1(await bodyBytes(over));
      expect(status.kind).toBe("status");
      if (status.kind === "status")
        expect(status.value.status).toBe("no-such-chunk");
    });
  });

  test("refuses path coordinates that are not their canonical spelling", async () => {
    await withHarness(async ({ base }) => {
      const paths = [
        // A leading zero is a second spelling of the same window.
        `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/01/0/0`,
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/01`,
        // Uppercase hex is a second spelling of the same profile hash.
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX.toUpperCase()}/${String(CHAIN_START)}`,
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX.slice(0, 62)}/1`,
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/-1`,
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/+1`,
        // Wider than the u64 the signed status body can carry.
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/18446744073709551616`,
        // Wider than the u8 a size class is.
        `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/1/256/0`,
        // Percent-encoding is a second spelling of a decimal digit.
        `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/%31`,
      ];
      for (const path of paths) {
        const response = await fetch(`${base}${path}`);
        expect(response.status).toBe(400);
        expect(await response.text()).toBe("malformed");
        expectStoreHeader(response);
      }
    });
  });

  test("a client of the previous prototype version is refused with a typed version error", async () => {
    // What a prototype-v0 client sends: its descriptor read first, then its
    // routes and media types, all under the v0 names.
    const persistence = new MemoryStorePersistence();
    await withHarness(
      async ({ base, core }) => {
        const v0 = "/p2party/prototype-v0";
        const keyPair = await newKeyPair(cryptoModule);
        const requests: [string, RequestInit][] = [
          ["/.well-known/p2party-store/prototype-v0", {}],
          [`${v0}/checkpoint/${PROFILE_HEX}/${String(CHAIN_START)}`, {}],
          [`${v0}/chunk/${PROFILE_HEX}/${String(CHAIN_START)}/0/0`, {}],
          [
            `${v0}/allocation`,
            {
              method: "POST",
              headers: {
                "content-type":
                  "application/p2party-allocation-request-prototype-v0",
              },
              body: asBody(
                encodePublicAllocationRequestV1({
                  version: 1,
                  deliveryProfileHash: PROFILE_HASH,
                  ingressWindow: CHAIN_START,
                  allocationEd25519PublicKey: keyPair.publicKey,
                  privacyPassToken: new Uint8Array(32),
                }),
              ),
            },
          ],
          // Any other version of the family, not only the one before.
          ["/.well-known/p2party-store/prototype-v7", {}],
        ];
        for (const [path, init] of requests) {
          const response = await fetch(`${base}${path}`, init);
          expect([path, response.status]).toEqual([path, 426]);
          expectStoreHeader(response);
          expect(response.headers.get("x-p2party-store")).toBe(
            PROTOTYPE_STORE_PROTOCOL,
          );
          expect(response.headers.get("upgrade")).toBe(
            PROTOTYPE_STORE_PROTOCOL,
          );
          expect(response.headers.get("cache-control")).toBe("no-store");
          expect(await response.text()).toBe(
            `this store speaks ${PROTOTYPE_STORE_PROTOCOL}`,
          );
        }
        // Refused before anything of it was read: no allocation was made.
        expect(await persistence.loadWindow(CHAIN_START)).toBeNull();
        expect(core.mutationQueueDepth).toBe(0);

        // This version's own descriptor read is still served.
        const own = await fetch(`${base}${PROTOTYPE_STORE_ROUTES.descriptor}`);
        expect(own.status).toBe(200);
      },
      { persistence },
    );
  });

  test("answers 404 for anything outside the route family", async () => {
    await withHarness(async ({ base }) => {
      const paths = [
        "/",
        "/p2party",
        "/p2party/prototype-v1",
        "/p2party/prototype-v1/",
        "/p2party/prototype-v1/checkpoint",
        `/p2party/prototype-v1/checkpoint/${PROFILE_HEX}/1/extra`,
        "/.well-known/p2party-store",
        "/health/../admin",
      ];
      for (const path of paths) {
        const response = await fetch(`${base}${path}`);
        expect(response.status).toBe(404);
        expect(await response.text()).toBe("not found");
        expectStoreHeader(response);
      }

      // A method the route family does not define is not a hint about which
      // methods it does define.
      const wrongMethod = await fetch(
        `${base}${PROTOTYPE_STORE_ROUTES.descriptor}`,
        { method: "POST" },
      );
      expect(wrongMethod.status).toBe(404);
      const getOnPost = await fetch(`${base}${PROTOTYPE_STORE_ROUTES.append}`);
      expect(getOnPost.status).toBe(404);
    });
  });

  test("records and serves witness observations", async () => {
    await withHarness(async ({ base, core, setNow }) => {
      // Witnessed once closed on the clock, when its checkpoint can exist.
      setNow(FINALIZE_AT);
      const record = {
        version: 1 as const,
        witnessedStoreId: new Uint8Array(32).fill(0x91),
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: CHAIN_START,
        checkpointHash: new Uint8Array(32).fill(0xc1),
      };
      for (let attempt = 0; attempt < 2; attempt++) {
        const posted = await post(
          base,
          PROTOTYPE_STORE_ROUTES.witness,
          PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
          encodeStoreWitnessRecordV1(record),
        );
        expect(posted.status).toBe(200);
        expect((await bodyBytes(posted)).length).toBe(0);
        expectStoreHeader(posted);
      }
      expect((await core.witnessRecords(CHAIN_START)).length).toBe(1);

      const response = await fetch(
        `${base}${PROTOTYPE_STORE_ROUTES.witness}/${PROFILE_HEX}/${String(CHAIN_START)}`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        PROTOTYPE_STORE_MEDIA_TYPES.witness,
      );
      expect(response.headers.get("cache-control")).toBe("no-store");
      const records = decodeStoreWitnessRecordsV1(await bodyBytes(response));
      expect(records.length).toBe(1);
      expect(hex(records[0].checkpointHash)).toBe(hex(record.checkpointHash));
    });
  });

  test("reports health without naming anything room-derived", async () => {
    await withHarness(async ({ base, core }) => {
      const response = await fetch(`${base}${PROTOTYPE_STORE_ROUTES.health}`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        "application/json; charset=utf-8",
      );
      expect(response.headers.get("cache-control")).toBe("no-store");
      expectStoreHeader(response);

      const body = (await response.json()) as Record<string, unknown>;
      expect(body).toEqual({
        status: "ok",
        role: "store-prototype",
        protocol: "prototype-v1",
        storeId: hex(core.storeId),
        window: String(CHAIN_START),
      });
    });
  });

  test("answers one constant 500 when the failure is not a parse failure", async () => {
    const core = await PrototypeStoreCore.create({
      module: cryptoModule,
      seed: SEED,
      profile,
      // Past the finalization instant, so the read has to reach the row.
      clock: { nowMs: () => FINALIZE_AT },
      persistence: new ExplodingStorePersistence(),
      chainStartIngressWindow: CHAIN_START,
      origin: "http://127.0.0.1:5910",
      descriptorValidityMs: 2_592_000_000n,
    });
    const server = Bun.serve({
      port: 0,
      fetch: createPrototypeStoreHandler({ core }),
    });

    // Captured rather than silenced: the log line is half of what is under
    // test, and letting it through would also dirty the suite's output.
    const logged: string[] = [];
    const realConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      logged.push(args.map((arg) => String(arg)).join(" "));
    };

    try {
      const response = await fetch(
        `${server.url.origin}${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(CHAIN_START)}`,
      );
      expect(response.status).toBe(500);
      // Not "malformed": telling a client its encoder is wrong when the store's
      // own disk failed sends it hunting for a bug it does not have.
      expect(await response.text()).toBe("error");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expectStoreHeader(response);
    } finally {
      console.error = realConsoleError;
      void server.stop(true);
    }

    // Nothing about the failure reaches the client, and the log carries the
    // error's name and the route class but never its message — a message can
    // quote the bytes the store was handling.
    expect(logged.length).toBe(1);
    expect(logged[0]).toContain("Error");
    expect(logged[0]).toContain("checkpoint");
    expect(logged[0]).not.toContain(EXPLOSION_DETAIL);
    expect(logged[0]).not.toContain("secret");
  });

  test("writes one hex line per POST only under the harness log path", async () => {
    const logPath = join(logRoot, `bodies-${String(logCounter++)}.log`);
    let tokenBody: Uint8Array = new Uint8Array(0);
    let witnessBody: Uint8Array = new Uint8Array(0);

    await withHarness(
      async ({ base, core }) => {
        tokenBody = encodeAllocationTokenIssueRequestV1({
          version: 1,
          storeId: core.storeId,
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START,
          privacyPassTokenRequest: new Uint8Array(32),
        });
        // A witness names a window closed on the clock: the one before.
        witnessBody = encodeStoreWitnessRecordV1({
          version: 1,
          witnessedStoreId: new Uint8Array(32).fill(0x91),
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START - 1n,
          checkpointHash: new Uint8Array(32).fill(0xc1),
        });

        expect(
          (
            await post(
              base,
              PROTOTYPE_STORE_ROUTES.token,
              PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
              tokenBody,
            )
          ).status,
        ).toBe(200);
        expect(
          (
            await post(
              base,
              PROTOTYPE_STORE_ROUTES.witness,
              PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
              witnessBody,
            )
          ).status,
        ).toBe(200);
        // A GET carries no body, so it must not add a line.
        await fetch(`${base}${PROTOTYPE_STORE_ROUTES.health}`);
      },
      { logBodiesPath: logPath },
    );

    const lines = readFileSync(logPath, "utf8").split("\n").filter(Boolean);
    expect(lines).toEqual([hex(tokenBody), hex(witnessBody)]);
  });

  test("writes no body log at all without the harness path", async () => {
    const logPath = join(logRoot, `bodies-${String(logCounter++)}.log`);
    await withHarness(async ({ base, core }) => {
      await post(
        base,
        PROTOTYPE_STORE_ROUTES.token,
        PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
        encodeAllocationTokenIssueRequestV1({
          version: 1,
          storeId: core.storeId,
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: CHAIN_START,
          privacyPassTokenRequest: new Uint8Array(32),
        }),
      );
    });
    expect(() => readFileSync(logPath)).toThrow();
  });

  test("routes are exactly the prototype-v1 family", () => {
    expect(PROTOTYPE_STORE_ROUTES).toEqual({
      descriptor: "/.well-known/p2party-store/prototype-v1",
      token: "/p2party/prototype-v1/allocation-token",
      allocation: "/p2party/prototype-v1/allocation",
      append: "/p2party/prototype-v1/append",
      checkpoint: "/p2party/prototype-v1/checkpoint",
      chunk: "/p2party/prototype-v1/chunk",
      witness: "/p2party/prototype-v1/witness",
      health: "/health",
    });
    expect(PROTOTYPE_STORE_MEDIA_TYPES.descriptor).toBe(
      PROTOTYPE_MEDIA_TYPE("store-descriptor"),
    );
  });
});

describe("prototype store HTTP admission", () => {
  const coverBody = (window = CHAIN_START, fill = 0x2c): Uint8Array =>
    encodePublicAppendRequestV1({
      version: 1,
      bucket: {
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: window,
        sizeClass: 0,
      },
      exactFixedObject: new Uint8Array(CLASS_0_OBJECT_BYTES).fill(fill),
      admission: null,
    });
  const witnessBody = (window = CHAIN_START - 1n, fill = 0xc4): Uint8Array =>
    encodeStoreWitnessRecordV1({
      version: 1,
      witnessedStoreId: new Uint8Array(32).fill(0x91),
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: window,
      checkpointHash: new Uint8Array(32).fill(fill),
    });
  const bearer = (token: Uint8Array): Record<string, string> => ({
    authorization: `Bearer ${hex(token)}`,
  });

  test("append and witness present the bearer token to the admission hook", async () => {
    const seen: string[] = [];
    await withHarness(
      async ({ base }) => {
        const token = new Uint8Array(32).fill(0x3d);
        const appended = await post(
          base,
          PROTOTYPE_STORE_ROUTES.append,
          PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
          coverBody(),
          bearer(token),
        );
        expect(appended.status).toBe(200);
        expect(
          decodePublicAppendResultV1(await bodyBytes(appended)).status,
        ).toBe("unallocated-cover");
        const witnessed = await post(
          base,
          PROTOTYPE_STORE_ROUTES.witness,
          PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
          witnessBody(),
          bearer(token),
        );
        expect(witnessed.status).toBe(200);
        await witnessed.arrayBuffer();
        // No header is the zero token, not an error.
        const bare = await post(
          base,
          PROTOTYPE_STORE_ROUTES.append,
          PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
          coverBody(CHAIN_START, 0x2d),
        );
        expect(bare.status).toBe(200);
        await bare.arrayBuffer();
        expect(seen).toEqual([
          `append:${hex(token)}`,
          `witness:${hex(token)}`,
          `append:${hex(new Uint8Array(32))}`,
        ]);
      },
      {
        allocationAdmission: {
          authorize: (request) => {
            seen.push(`${request.route}:${hex(request.privacyPassToken)}`);
            return request.privacyPassToken;
          },
        },
      },
    );
  });

  test("a malformed admission header is the one constant 400", async () => {
    let calls = 0;
    await withHarness(
      async ({ base }) => {
        const valid = hex(new Uint8Array(32).fill(0x3d));
        for (const authorization of [
          `Bearer ${valid.toUpperCase()}`,
          `Bearer ${valid.slice(2)}`,
          `Bearer ${valid}00`,
          `bearer ${valid}`,
          `Basic ${valid}`,
          `Bearer  ${valid}`,
          `Bearer ${valid}, Bearer ${valid}`,
        ])
          for (const [path, mediaType, body] of [
            [
              PROTOTYPE_STORE_ROUTES.append,
              PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
              coverBody(),
            ],
            [
              PROTOTYPE_STORE_ROUTES.witness,
              PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
              witnessBody(),
            ],
          ] as const) {
            const response = await post(base, path, mediaType, body, {
              authorization,
            });
            expect({ authorization, status: response.status }).toEqual({
              authorization,
              status: 400,
            });
            expect(await response.text()).toBe("malformed");
          }
        expect(calls).toBe(0);
      },
      {
        allocationAdmission: {
          authorize: () => {
            calls += 1;
            return new Uint8Array(32).fill(1);
          },
        },
      },
    );
  });

  test("an admission refusal is a 403 and an unrecorded witness a 409", async () => {
    await withHarness(
      async ({ base, core }) => {
        for (const [path, mediaType, body] of [
          [
            PROTOTYPE_STORE_ROUTES.append,
            PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
            coverBody(),
          ],
          [
            PROTOTYPE_STORE_ROUTES.witness,
            PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
            witnessBody(),
          ],
        ] as const) {
          const refused = await post(base, path, mediaType, body);
          expect(refused.status).toBe(403);
          expect(await refused.text()).toBe("refused");
          expect(refused.headers.get("cache-control")).toBe("no-store");
          expectStoreHeader(refused);
        }
        expect(await core.witnessRecords(CHAIN_START)).toEqual([]);

        // A future window is not one this store retains, whoever asks.
        const future = await post(
          base,
          PROTOTYPE_STORE_ROUTES.witness,
          PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
          witnessBody(CHAIN_START + 1n),
          bearer(new Uint8Array(32).fill(0x3d)),
        );
        expect(future.status).toBe(409);
        expect(await future.text()).toBe("not recorded");
        expectStoreHeader(future);
      },
      {
        allocationAdmission: {
          authorize: (request) =>
            request.privacyPassToken[0] === 0x3d
              ? request.privacyPassToken
              : null,
        },
      },
    );
  });

  test("the preflight admits the authorization header", async () => {
    await withHarness(async ({ base }) => {
      const response = await fetch(`${base}${PROTOTYPE_STORE_ROUTES.append}`, {
        method: "OPTIONS",
      });
      expect(response.status).toBe(204);
      expect(
        (response.headers.get("access-control-allow-headers") ?? "")
          .split(",")
          .map((name) => name.trim()),
      ).toEqual(["content-type", "authorization"]);
    });
  });
});

describe("prototype store HTTP load shedding", () => {
  test("a full mutation queue answers 503 before reading the body", async () => {
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    class HeldSaves extends MemoryStorePersistence {
      override async saveWindow(
        state: Parameters<MemoryStorePersistence["saveWindow"]>[0],
      ): Promise<void> {
        await released;
        return super.saveWindow(state);
      }
    }
    await withHarness(
      async ({ base, core }) => {
        // Fill the queue in process: distinct keys, one open window, every
        // write held.
        const pending = await Promise.all(
          Array.from({ length: PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH }, () =>
            newKeyPair(cryptoModule),
          ),
        ).then((keys) =>
          keys.map((keyPair) =>
            core
              .allocate({
                version: 1,
                deliveryProfileHash: PROFILE_HASH,
                ingressWindow: CHAIN_START,
                allocationEd25519PublicKey: keyPair.publicKey,
                privacyPassToken: new Uint8Array(32),
              })
              .catch(() => null),
          ),
        );
        // Bounded in turns of the event loop, never in time.
        for (
          let turn = 0;
          turn < 200_000 && !core.mutationQueueSaturated;
          turn++
        )
          await Bun.sleep(0);
        expect(core.mutationQueueSaturated).toBe(true);

        // A body that never finishes: an answer can only come from a handler
        // that did not wait to read it.
        let pulls = 0;
        const endless = new ReadableStream<Uint8Array>({
          pull: async (controller) => {
            pulls += 1;
            controller.enqueue(new Uint8Array(1024));
            await Bun.sleep(5);
          },
        });
        const response = await fetch(
          `${base}${PROTOTYPE_STORE_ROUTES.append}`,
          {
            method: "POST",
            headers: {
              "content-type": PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
            },
            body: endless,
            duplex: "half",
          } as RequestInit,
        );
        expect(response.status).toBe(503);
        expect(await response.text()).toBe("busy");
        expect(response.headers.get("cache-control")).toBe("no-store");
        expectStoreHeader(response);
        await endless.cancel().catch(() => undefined);
        expect(core.mutationQueueDepth).toBe(
          PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH,
        );
        expect(pulls).toBeLessThan(1024);
        release();
        await Promise.all(pending);
      },
      { persistence: new HeldSaves() },
    );
  });
});
