/**
 * The store's write path and the descriptor's lifetime, from the client's
 * side and the store's: every signed allocation and append answer judged by
 * the one decision order (`judgeSignedRefusal`), the escalation that stops a
 * store after repeated non-blame reports, the descriptor's end, the back-off
 * after a 503, the retention cap, the per-answer receive time, and the lone
 * chunk denial.
 *
 * No socket is opened: a client's transport is a stub over statuses signed
 * with a real store's key, or a real core's own HTTP handler called in
 * process. Every clock is a variable the test sets; nothing waits on the
 * wall clock.
 */
import { describe, expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";

import libcrypto from "../../../src/cryptography/libcrypto";
import {
  keyPairFromSeed,
  newKeyPair,
  sign,
} from "../../../src/cryptography/ed25519";
import {
  deliveryProfileHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationRequestHash,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
} from "../../../src/blindRendezvous/derivations";
import {
  descriptorHash,
  storeDescriptorSignedMessage,
  storeId as computeStoreId,
  storeRouteSignedMessage,
} from "../../../src/blindRendezvous/storeDescriptor";
import {
  PROTOTYPE_STORE_CLIENT_BACKOFF_MAX_MS,
  PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS,
  PROTOTYPE_STORE_DISAGREEMENT_LIMIT,
  PROTOTYPE_STORE_MAX_RETENTION_WINDOWS,
  PROTOTYPE_STORE_MIN_RETENTION_WINDOWS,
} from "../../../src/utils/constants";
import {
  PROTOTYPE_DELIVERY_PROFILE_V0,
  carrierObjectWireBytes,
} from "../../../src/blindRendezvous/prototype/profile";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../../../src/blindRendezvous/prototype/storeRoutes";
import {
  PrototypeStoreClient,
  buildAppendAdmission,
  signedStatusProvesFault,
} from "../../../src/blindRendezvous/prototype/storeClient";
import { PrototypeStoreCore } from "../../../src/blindRendezvous/prototype/store/storeCore";
import { MemoryStorePersistence } from "../../../src/blindRendezvous/prototype/store/storePersistence";
import { SqliteStorePersistence } from "../../../src/blindRendezvous/prototype/store/storeSqlite";
import { createPrototypeStoreHandler } from "../../../src/blindRendezvous/prototype/store/storeHttp";
import {
  decodePublicAllocationRequestV1,
  decodePublicAllocationResultV1,
  decodePublicAppendRequestV1,
  decodePublicAppendResultV1,
  encodeAllocationTokenIssueRequestV1,
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationRequestV1,
  encodePublicAllocationResultV1,
  encodePublicAppendRequestV1,
  encodePublicAppendResultV1,
  encodePublicChunkReadV1,
  encodePublicStoreCheckpointReadV1,
  encodeStoreWitnessRecordV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

import type { LibCrypto } from "../../../src/cryptography/libcrypto";
import type { CarrierTimers } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type { StoreDescriptorV1 } from "../../../src/blindRendezvous/storeDescriptor";
import type {
  StoreClientOptions,
  StoreFaultRecord,
  StoreStopEvent,
} from "../../../src/blindRendezvous/prototype/storeClient";
import type {
  PublicAllocationRequestV1,
  PublicAllocationStatusKindV1,
  PublicAppendAdmissionV1,
  PublicAppendRequestV1,
  PublicAppendStatusV1,
  PublicChunkStatusKindV1,
  PublicStoreCheckpointStatusKindV1,
} from "../../../src/blindRendezvous/prototype/storeWire";

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

const profile = PROTOTYPE_DELIVERY_PROFILE_V0;
const PROFILE_HASH = await deliveryProfileHash(profile);
const PROFILE_HEX = hex(PROFILE_HASH);
const L = profile.deliveryWindowMs;
const F = profile.chunkFinalizationOffsetMs;
const SKEW = profile.maxScheduleSkewMs;
const H = BigInt(profile.maxFutureIngressWindows);
const READ_OFFSET = profile.publicReadOffsetMs;
const ALLOCATION_OFFSET = profile.allocationRequestOffsetMs;
/** 1_700_000_000_000 / 4_000 is exact: the chain starts on a window edge. */
const C = 425_000_000n;
const R = BigInt(PROTOTYPE_STORE_MIN_RETENTION_WINDOWS);
const LIMIT = PROTOTYPE_STORE_DISAGREEMENT_LIMIT;
const startOf = (window: bigint): bigint => window * L;
const finOf = (window: bigint): bigint => window * L + F;
const SEED = new Uint8Array(32).fill(0x5a);
const ORIGIN = "http://store.invalid:5998";
const OBJECT_BYTES = carrierObjectWireBytes(profile, 0, PROFILE_HASH);

const STORE_SECRET = (
  await keyPairFromSeed(Uint8Array.from(SEED), cryptoModule)
).secretKey;

/** `lib.dom`'s `BufferSource` is narrower than the codecs' `Uint8Array`. */
const asBody = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const headersOf = (mediaType: string): Record<string, string> => ({
  "x-p2party-store": "prototype-v1",
  "content-type": mediaType,
});

const answer = (bytes: Uint8Array, mediaType: string): Response =>
  new Response(asBody(bytes), { status: 200, headers: headersOf(mediaType) });

const unsigned = (status: number, text: string): Response =>
  new Response(text, {
    status,
    headers: headersOf("text/plain; charset=utf-8"),
  });

interface Clock {
  now: bigint;
}

/** A real core whose clock is `clock`, at the minimum retention. */
const coreAt = async (
  clock: Clock,
  options: { validityMs?: bigint; persistence?: SqliteStorePersistence } = {},
): Promise<PrototypeStoreCore> =>
  PrototypeStoreCore.create({
    module: cryptoModule,
    seed: SEED,
    profile,
    clock: { nowMs: () => clock.now },
    persistence: options.persistence ?? new MemoryStorePersistence(),
    chainStartIngressWindow: C,
    origin: ORIGIN,
    descriptorValidityMs: options.validityMs ?? 2_592_000_000n,
    retentionWindows: Number(R),
  });

/** One core for the file, with chain-start window C finalized. */
const servedClock: Clock = { now: finOf(C) };
const servedCore = await coreAt(servedClock);
await servedCore.finalizeDue();
const SERVED_CHECKPOINT = encodePublicStoreCheckpointReadV1(
  await servedCore.readCheckpoint(PROFILE_HASH, C),
);
const SERVED_CHUNKS = new Map<string, Uint8Array>();
for (const sizeClass of profile.sizeClasses)
  for (let index = 0; index < sizeClass.publicChunksPerWindow; index++)
    SERVED_CHUNKS.set(
      `${String(sizeClass.id)}/${String(index)}`,
      encodePublicChunkReadV1(
        await servedCore.readChunk(
          {
            deliveryProfileHash: PROFILE_HASH,
            ingressWindow: C,
            sizeClass: sizeClass.id,
          },
          BigInt(index),
        ),
      ),
    );
const STORE_ID = servedCore.storeId;
const BASE_DOCUMENT = servedCore.descriptorDocument();

type DescriptorDocument = typeof BASE_DOCUMENT;

/** The served store's descriptor with another validity, and a route for it. */
const documentValid = async (
  notBeforeUnixMs: bigint,
  notAfterUnixMs: bigint,
  retentionWindows = Number(R),
): Promise<DescriptorDocument> => {
  const draft = {
    ...BASE_DOCUMENT.descriptor,
    retentionWindows,
    notBeforeUnixMs,
    notAfterUnixMs,
  };
  const descriptor = {
    ...draft,
    descriptorSignature: await sign(
      await storeDescriptorSignedMessage(draft),
      STORE_SECRET,
      cryptoModule,
    ),
  };
  const routeDraft = {
    ...BASE_DOCUMENT.routes[0],
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
          STORE_SECRET,
          cryptoModule,
        ),
      },
    ],
  };
};

const WIDE = await documentValid(startOf(C - 5_000n), startOf(C + 50_000n));
const WIDE_HASH = await descriptorHash(WIDE.descriptor);

/** An allocation status for `request`, signed with the store's key. */
const allocationStatus = async (
  request: PublicAllocationRequestV1,
  status: PublicAllocationStatusKindV1,
  storeWindow: bigint,
  descriptorHashBytes: Uint8Array,
): Promise<Uint8Array> => {
  const value = {
    version: 1 as const,
    storeId: STORE_ID,
    descriptorHash: descriptorHashBytes,
    deliveryProfileHash: request.deliveryProfileHash,
    ingressWindow: request.ingressWindow,
    requestHash: await publicAllocationRequestHash(request),
    storeIngressWindow: storeWindow,
    status,
    fixedErrorPadding: new Uint8Array(32),
  };
  return encodePublicAllocationResultV1({
    kind: "status",
    value,
    storeSignature: await sign(
      await publicAllocationStatusSignedMessage(value),
      STORE_SECRET,
      cryptoModule,
    ),
  });
};

/** An append result for `request`, signed with the store's key. */
const appendResult = async (
  request: PublicAppendRequestV1,
  status: PublicAppendStatusV1,
  storeWindow: bigint,
  descriptorHashBytes: Uint8Array,
): Promise<Uint8Array> => {
  const body = {
    version: 1 as const,
    storeId: STORE_ID,
    descriptorHash: descriptorHashBytes,
    bucket: request.bucket,
    requestHash: await publicAppendRequestHash(request),
    storeIngressWindow: storeWindow,
    status,
    fixedStatusPadding: new Uint8Array(16),
  };
  return encodePublicAppendResultV1({
    ...body,
    storeSignature: await sign(
      await publicAppendResultSignedMessage(body),
      STORE_SECRET,
      cryptoModule,
    ),
  });
};

/** A read status about `window`, signed with the store's key. */
const readStatus = async (
  route: "checkpoint" | "chunk",
  window: bigint,
  status: string,
  storeWindow: bigint,
  descriptorHashBytes: Uint8Array,
  chunk = { sizeClass: 0, chunkIndex: 0n },
): Promise<Uint8Array> => {
  if (route === "checkpoint") {
    const value = {
      version: 1 as const,
      storeId: STORE_ID,
      descriptorHash: descriptorHashBytes,
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: window,
      storeIngressWindow: storeWindow,
      status: status as PublicStoreCheckpointStatusKindV1,
    };
    return encodePublicStoreCheckpointReadV1({
      kind: "status",
      value,
      storeSignature: await sign(
        await publicCheckpointStatusSigningHash(value),
        STORE_SECRET,
        cryptoModule,
      ),
    });
  }
  const value = {
    version: 1 as const,
    descriptorHash: descriptorHashBytes,
    bucket: {
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: window,
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
      STORE_SECRET,
      cryptoModule,
    ),
  });
};

interface Sent {
  readonly path: string;
  readonly method: string;
  readonly body: Uint8Array | null;
}

type Answerer = (sent: Sent) => Response | Promise<Response>;

/**
 * A stub store: the descriptor document, then `answerer` for every other
 * request, each logged with its body.
 */
const stubFetch = (
  document: DescriptorDocument,
  answerer: Answerer,
  log: Sent[],
): typeof fetch =>
  (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    if (path === PROTOTYPE_STORE_ROUTES.descriptor)
      return answer(
        encodePrototypeStoreDescriptorDocumentV1(document),
        PROTOTYPE_STORE_MEDIA_TYPES.descriptor,
      );
    const body =
      init?.body === undefined || init.body === null
        ? null
        : new Uint8Array(init.body as ArrayBuffer);
    const sent = { path, method: init?.method ?? "GET", body };
    log.push(sent);
    return answerer(sent);
  }) as typeof fetch;

/** The paths of one scan of C's chunks, in the order the client asks. */
const CHUNK_PATHS = [...profile.sizeClasses]
  .sort((left, right) => left.id - right.id)
  .flatMap((sizeClass) =>
    Array.from(
      { length: sizeClass.publicChunksPerWindow },
      (_, index) =>
        `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(C)}/${String(sizeClass.id)}/${String(index)}`,
    ),
  );
/** A scan asks for the checkpoint first (request 0), then the chunks. */
const chunkPathOf = (requestIndex: number): string =>
  CHUNK_PATHS[requestIndex - 1];

/** The served finalized window C, for every read. */
const servedRead: Answerer = (sent) => {
  if (sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
    return answer(SERVED_CHECKPOINT, PROTOTYPE_STORE_MEDIA_TYPES.checkpoint);
  const parts = sent.path.split("/");
  return answer(
    SERVED_CHUNKS.get(
      `${parts[parts.length - 2]}/${parts[parts.length - 1]}`,
    ) ?? new Uint8Array(0),
    PROTOTYPE_STORE_MEDIA_TYPES.chunk,
  );
};

const connectClient = async (
  document: DescriptorDocument,
  answerer: Answerer,
  connectMs: bigint,
  extra: {
    timers?: CarrierTimers;
    admissionTokens?: StoreClientOptions["admissionTokens"];
  } = {},
): Promise<{
  client: PrototypeStoreClient;
  clock: Clock;
  log: Sent[];
  stops: StoreStopEvent[];
}> => {
  const clock: Clock = { now: connectMs };
  const log: Sent[] = [];
  const stops: StoreStopEvent[] = [];
  const client = await PrototypeStoreClient.connect({
    origin: ORIGIN,
    profile,
    profileHash: PROFILE_HASH,
    module: cryptoModule,
    fetch: stubFetch(document, answerer, log),
    nowMs: () => clock.now,
    timers: extra.timers,
    admissionTokens: extra.admissionTokens,
    onStopped: (event) => stops.push(event),
  });
  return { client, clock, log, stops };
};

const KEY_PAIR = await newKeyPair(cryptoModule);
const OBJECT = new Uint8Array(OBJECT_BYTES).fill(0x41);

/** An admission the client sends as it is: the stub never checks it. */
const admissionFor = (window: bigint): PublicAppendAdmissionV1 => ({
  version: 1,
  lease: {
    version: 1,
    storeId: STORE_ID,
    deliveryProfileHash: PROFILE_HASH,
    ingressWindow: window,
    requestHash: new Uint8Array(32),
    allocationOrdinal: 0,
    allocationEd25519PublicKey: KEY_PAIR.publicKey,
    storeSignature: new Uint8Array(64),
  },
  objectOrdinalWithinAllocation: 0,
  allocationSignature: new Uint8Array(64),
});

/** Answer every allocation with `status` stating `storeWindow`. */
const allocationAnswerer =
  (
    status: PublicAllocationStatusKindV1,
    storeWindow: bigint,
    descriptorHashBytes: Uint8Array = WIDE_HASH,
    keep?: (bytes: Uint8Array) => void,
  ): Answerer =>
  async (sent) => {
    if (sent.body === null) return unsigned(404, "not found");
    const bytes = await allocationStatus(
      decodePublicAllocationRequestV1(sent.body),
      status,
      storeWindow,
      descriptorHashBytes,
    );
    keep?.(bytes);
    return answer(bytes, PROTOTYPE_STORE_MEDIA_TYPES.allocationResult);
  };

/** Answer every append with `status` stating `storeWindow`. */
const appendAnswerer =
  (
    status: PublicAppendStatusV1,
    storeWindow: bigint,
    descriptorHashBytes: Uint8Array = WIDE_HASH,
    keep?: (bytes: Uint8Array) => void,
  ): Answerer =>
  async (sent) => {
    if (sent.body === null) return unsigned(404, "not found");
    const bytes = await appendResult(
      decodePublicAppendRequestV1(sent.body),
      status,
      storeWindow,
      descriptorHashBytes,
    );
    keep?.(bytes);
    return answer(bytes, PROTOTYPE_STORE_MEDIA_TYPES.appendResult);
  };

const kindsOf = (client: PrototypeStoreClient): string[] =>
  client.faults.map((fault) => fault.kind);

/** What a third party concludes from a fault record alone. */
const provedBy = (fault: StoreFaultRecord): Promise<string | null> =>
  signedStatusProvesFault(
    fault.descriptor ?? ({} as StoreDescriptorV1),
    profile,
    fault.evidence ?? [],
    cryptoModule,
  );

/**
 * Promises a test resolves in the order it chooses: `hold()` gives one to
 * hand back from a transport, `release(index, value)` settles it.
 */
const holder = <T>() => {
  const pending: { resolve: (value: T) => void; settled: boolean }[] = [];
  return {
    hold: (): Promise<T> =>
      new Promise<T>((resolve) => {
        pending.push({ resolve, settled: false });
      }),
    release: (index: number, value: T): void => {
      const entry = pending[index];
      if (entry.settled)
        throw new Error(`answer ${String(index)} released twice`);
      entry.settled = true;
      entry.resolve(value);
    },
    get count(): number {
      return pending.length;
    },
  };
};

/** Bounded event-loop turns, never a wall-clock wait. */
const turns = async (rounds = 50): Promise<void> => {
  for (let round = 0; round < rounds; round += 1)
    await new Promise<void>((resolve) => setImmediate(resolve));
};

/* ------------------------------------------------------------------ *
 * The write table
 * ------------------------------------------------------------------ */

describe("store write path: one decision order", () => {
  test("no stated values end in a benign outcome outside the write table", async () => {
    type Route = "allocation" | "append";
    const STATUSES: {
      route: Route;
      status: string;
      admitted: boolean;
    }[] = [
      ...(
        [
          "window-closed",
          "invalid-token",
          "token-spent",
          "capacity-exhausted",
        ] as const
      ).map((status) => ({
        route: "allocation" as const,
        status,
        admitted: false,
      })),
      ...[true, false].flatMap((admitted) =>
        (
          [
            "stored",
            "already-present",
            "slot-conflict",
            "unallocated-cover",
            "window-finalized",
            "capacity-exhausted",
          ] as const
        ).map((status) => ({ route: "append" as const, status, admitted })),
      ),
    ];
    const TARGETS: [string, bigint][] = [
      ["at or after the chain start", C + 10n],
      ["below the chain start", C - 1n],
    ];
    const statedFor = (W: bigint): [string, bigint][] => [
      ["far before W", W - 1_000n],
      ["W - 3", W - 3n],
      ["W - 2", W - 2n],
      ["W - 1", W - 1n],
      ["W", W],
      ["W + 1", W + 1n],
      ["far after W", W + 1_000n],
    ];
    const timesFor = (W: bigint): [string, bigint][] => [
      ["three windows early, past the horizon", startOf(W - 3n) + 700n],
      ["W's allocation instant", startOf(W - 1n) + ALLOCATION_OFFSET],
      [
        "the last instant no store within the skew is in W",
        startOf(W) - SKEW - 1n,
      ],
      ["the first instant one is", startOf(W) - SKEW],
      ["W's first append", startOf(W) + 1_300n],
      ["fin(W) - skew - 1", finOf(W) - SKEW - 1n],
      ["fin(W) - skew", finOf(W) - SKEW],
      ["fin(W) - 1", finOf(W) - 1n],
      ["fin(W)", finOf(W)],
      [
        "the last instant a store within the skew reads before fin(W)",
        finOf(W) + SKEW - 1n,
      ],
      ["the first instant none does", finOf(W) + SKEW],
      [
        "just past W's end, where a store within the skew still states W",
        startOf(W + 1n) + SKEW - 1n,
      ],
      ["the first instant none does any more", startOf(W + 1n) + SKEW],
      ["the next window's read", startOf(W + 1n) + READ_OFFSET],
      ["long after", startOf(W + 50n)],
    ];
    const VALIDITY = [
      "inside",
      "straddling notBefore",
      "straddling notAfter",
      "expired",
    ] as const;
    const validityFor = (
      kind: (typeof VALIDITY)[number],
      stated: bigint,
      sentMs: bigint,
    ): { notBefore: bigint; notAfter: bigint } => {
      const first = stated * L < sentMs ? stated * L : sentMs;
      const last = (stated + 1n) * L > sentMs ? (stated + 1n) * L : sentMs + 1n;
      if (kind === "inside")
        return { notBefore: first - L, notAfter: last + L };
      if (kind === "straddling notBefore")
        return { notBefore: stated * L + L / 2n, notAfter: last + L };
      if (kind === "straddling notAfter")
        return { notBefore: first - L, notAfter: stated * L + L / 2n };
      // Half-open: at `notAfter` itself the descriptor is no longer valid.
      return { notBefore: first - L, notAfter: sentMs };
    };

    type Outcome =
      | "stopped"
      | "write-window-breach"
      | "store-clock-disagreement"
      | "descriptor-out-of-validity"
      | "benign"
      | "promise"
      | "cover-accepted"
      | "write-refusal"
      | "signature-invalid";

    /**
     * The table, from the profile's numbers and the descriptor's alone: the
     * step that ends the cell, and what it ends in. No helper of the client
     * is called. The answer arrives at the instant it was asked.
     */
    const tabled = (cell: {
      route: Route;
      status: string;
      admitted: boolean;
      W: bigint;
      S: bigint;
      sentMs: bigint;
      notBefore: bigint;
      notAfter: bigint;
    }): { step: number; outcome: Outcome } => {
      const { route, status, admitted, W, S, sentMs, notBefore, notAfter } =
        cell;
      // 0. Nothing is asked once this client's clock reaches the end.
      if (sentMs >= notAfter) return { step: 0, outcome: "stopped" };
      // 3. The store's own window contradicts the status: each is signed
      // only where its window is closed, past the horizon, or still open.
      const fin = finOf(W);
      const closedStatus =
        status === "window-closed" || status === "window-finalized";
      const beyondStatus =
        route === "append" && status === "capacity-exhausted";
      const contradicted = closedStatus
        ? !(
            W < C ||
            (S + 1n) * L > fin ||
            (route === "allocation" && (W < S || W > S + H))
          )
        : beyondStatus
          ? !(W >= C && W > S + H)
          : !(W >= C && W <= S + H && S * L < fin);
      if (contradicted) return { step: 3, outcome: "write-window-breach" };
      // 4. No instant within the skew of the request lies in S.
      if ((S + 1n) * L <= sentMs - SKEW || S * L > sentMs + SKEW)
        return { step: 4, outcome: "store-clock-disagreement" };
      // 5. The descriptor does not cover S and the request.
      if (
        notBefore > S * L ||
        (S + 1n) * L > notAfter ||
        sentMs < notBefore ||
        sentMs >= notAfter
      )
        return { step: 5, outcome: "descriptor-out-of-validity" };
      // 6. Closed only by the clock, and in before a store within the skew
      // read the close; or open, and sent after every such store read it.
      if (
        closedStatus &&
        W >= C &&
        S * L < fin &&
        !(route === "allocation" && W > S + H) &&
        sentMs + SKEW < fin
      )
        return { step: 6, outcome: "store-clock-disagreement" };
      if (!closedStatus && !beyondStatus && sentMs >= fin + SKEW)
        return { step: 6, outcome: "store-clock-disagreement" };
      // 7.
      if (route === "allocation")
        return {
          step: 7,
          outcome: status === "window-closed" ? "benign" : "write-refusal",
        };
      if (status === "window-finalized") return { step: 7, outcome: "benign" };
      if (status === "capacity-exhausted")
        return { step: 7, outcome: "benign" };
      if (status === "stored" || status === "already-present")
        return {
          step: 7,
          outcome: admitted ? "promise" : "signature-invalid",
        };
      if (status === "slot-conflict")
        return {
          step: 7,
          outcome: admitted ? "write-refusal" : "signature-invalid",
        };
      return {
        step: 7,
        outcome: admitted ? "signature-invalid" : "cover-accepted",
      };
    };

    /** What the client records, and whether it hands the answer back. */
    const observed = (
      outcome: Outcome,
      route: Route,
      status: string,
      admitted: boolean,
    ): { kinds: string[]; returned: boolean; inert: boolean } => {
      const promise =
        route === "append" &&
        admitted &&
        (status === "stored" || status === "already-present");
      switch (outcome) {
        case "stopped":
          return { kinds: [], returned: false, inert: false };
        case "write-window-breach":
          return { kinds: [outcome], returned: false, inert: true };
        case "store-clock-disagreement":
        case "descriptor-out-of-validity":
          return { kinds: [outcome], returned: promise, inert: false };
        case "write-refusal":
          return {
            kinds: [outcome],
            returned: route === "append",
            inert: false,
          };
        case "signature-invalid":
          return { kinds: [outcome], returned: false, inert: false };
        default:
          return { kinds: [], returned: route === "append", inert: false };
      }
    };

    /**
     * What a real core signs for one request at one reading of its clock:
     * an allocation's status, or a cover append's result, with the window it
     * states. A cover append that is accepted stands for an admitted one too:
     * the core accepts both on the same clock condition.
     */
    const honestClock: Clock = { now: startOf(C) };
    const honest = await coreAt(honestClock);
    const honestAnswers = new Map<string, { status: string; stated: bigint }>();
    const honestAt = async (
      route: Route,
      W: bigint,
      atMs: bigint,
    ): Promise<{ status: string; stated: bigint }> => {
      const key = `${route}@${String(W)}@${String(atMs)}`;
      const held = honestAnswers.get(key);
      if (held !== undefined) return held;
      honestClock.now = atMs;
      let found: { status: string; stated: bigint };
      if (route === "allocation") {
        const result = await honest.allocate({
          version: 1,
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: W,
          allocationEd25519PublicKey: (await newKeyPair(cryptoModule))
            .publicKey,
          privacyPassToken: new Uint8Array(32),
        });
        found =
          result.kind === "status"
            ? {
                status: result.value.status,
                stated: result.value.storeIngressWindow,
              }
            : { status: "lease", stated: -1n };
      } else {
        const result = await honest.append({
          version: 1,
          bucket: {
            deliveryProfileHash: PROFILE_HASH,
            ingressWindow: W,
            sizeClass: 0,
          },
          exactFixedObject: OBJECT,
          admission: null,
        });
        found = { status: result.status, stated: result.storeIngressWindow };
      }
      honestAnswers.set(key, found);
      return found;
    };
    /** Whether a store within the skew, valid at its reading, signs it. */
    const producible = async (cell: {
      route: Route;
      status: string;
      admitted: boolean;
      W: bigint;
      S: bigint;
      sentMs: bigint;
      notBefore: bigint;
      notAfter: bigint;
    }): Promise<boolean> => {
      const { route, status, admitted, W, S, sentMs } = cell;
      const wanted =
        route === "append" &&
        admitted &&
        (status === "stored" || status === "already-present")
          ? "unallocated-cover"
          : route === "append" && admitted && status === "unallocated-cover"
            ? null
            : status;
      if (wanted === null) return false;
      const low = [sentMs - SKEW, S * L, cell.notBefore].reduce((a, b) =>
        a > b ? a : b,
      );
      const high = [
        sentMs + SKEW,
        (S + 1n) * L - 1n,
        cell.notAfter - 1n,
      ].reduce((a, b) => (a < b ? a : b));
      if (low > high) return false;
      // The core's answer changes only at a window's edge and at fin(W).
      const candidates = [low, high, finOf(W) - 1n, finOf(W)].filter(
        (atMs) => atMs >= low && atMs <= high,
      );
      for (const atMs of candidates) {
        const found = await honestAt(route, W, atMs);
        if (found.status === wanted && found.stated === S) return true;
      }
      return false;
    };

    const documents = new Map<string, DescriptorDocument>();
    const endedAt = new Map<number, number>();
    const outcomes = new Map<string, number>();
    const seenKinds = new Set<string>();
    const wrong: string[] = [];
    let cells = 0;
    for (const { route, status, admitted } of STATUSES)
      for (const [targetName, W] of TARGETS)
        for (const [statedName, S] of statedFor(W))
          for (const [timeName, sentMs] of timesFor(W))
            for (const validity of VALIDITY) {
              cells += 1;
              const { notBefore, notAfter } = validityFor(validity, S, sentMs);
              const key = `${String(notBefore)}:${String(notAfter)}`;
              const document =
                documents.get(key) ??
                (await documentValid(notBefore, notAfter));
              documents.set(key, document);
              const pinnedHash = await descriptorHash(document.descriptor);
              let signed: Uint8Array | null = null;
              const keep = (bytes: Uint8Array): void => {
                signed = bytes;
              };
              const { client, clock, log, stops } = await connectClient(
                document,
                route === "allocation"
                  ? allocationAnswerer(
                      status as PublicAllocationStatusKindV1,
                      S,
                      pinnedHash,
                      keep,
                    )
                  : appendAnswerer(
                      status as PublicAppendStatusV1,
                      S,
                      pinnedHash,
                      keep,
                    ),
                sentMs >= notAfter
                  ? notAfter - 1n
                  : sentMs < notBefore
                    ? notBefore
                    : sentMs,
              );
              clock.now = sentMs;
              const returned =
                route === "allocation"
                  ? await client.allocate(W, KEY_PAIR)
                  : await client.append(
                      W,
                      0,
                      OBJECT,
                      admitted ? admissionFor(W) : null,
                    );
              const cell = {
                route,
                status,
                admitted,
                W,
                S,
                sentMs,
                notBefore,
                notAfter,
              };
              const expected = tabled(cell);
              const want = observed(expected.outcome, route, status, admitted);
              const kinds = kindsOf(client);
              const name = `${route} ${status}${route === "append" ? (admitted ? " (admitted)" : " (cover)") : ""} | W ${targetName} | stated ${statedName} | sent at ${timeName} | validity ${validity}`;
              const got = `[${kinds.join(",")}] returned=${String(returned !== null)} inert=${String(client.inert)} requests=${String(log.length)}`;
              const wantText = `[${want.kinds.join(",")}] returned=${String(want.returned)} inert=${String(want.inert)} requests=${String(expected.step === 0 ? 0 : 1)}`;
              if (got !== wantText)
                wrong.push(`${name}: got ${got}, want ${wantText}`);
              if (
                expected.step === 0 &&
                stops[0]?.reason !== "descriptor-expired"
              )
                wrong.push(`${name}: no expiry event`);
              if (expected.step !== 0 && stops.length !== 0)
                wrong.push(`${name}: stopped after one answer`);
              endedAt.set(expected.step, (endedAt.get(expected.step) ?? 0) + 1);
              outcomes.set(
                expected.outcome,
                (outcomes.get(expected.outcome) ?? 0) + 1,
              );
              for (const kind of kinds) seenKinds.add(kind);

              // Blame is provable from the kept record alone, and nothing
              // else is evidence.
              const blame = client.faults.find(
                (fault) => fault.kind === "write-window-breach",
              );
              if (expected.step === 3) {
                if (
                  blame === undefined ||
                  (await provedBy(blame)) !== expected.outcome
                )
                  wrong.push(
                    `${name}: the kept record does not prove the breach`,
                  );
              } else if (signed !== null) {
                const direct = await signedStatusProvesFault(
                  document.descriptor,
                  profile,
                  [signed],
                  cryptoModule,
                );
                if (direct !== null)
                  wrong.push(`${name}: unblamed, yet it proves ${direct}`);
              }

              // The only benign cells are ones an honest store within the
              // skew signs, under a descriptor valid at that reading; and with
              // the descriptor valid throughout, every such answer is benign.
              const isBenign =
                expected.outcome === "benign" ||
                expected.outcome === "promise" ||
                expected.outcome === "cover-accepted";
              const canSign = await producible(cell);
              if (isBenign && !canSign)
                wrong.push(
                  `${name}: benign, and no honest store within the skew signs it`,
                );
              if (
                validity === "inside" &&
                canSign &&
                !isBenign &&
                expected.outcome !== "write-refusal"
              )
                wrong.push(
                  `${name}: an honest store within the skew signs it, and it is ${expected.outcome}`,
                );
            }

    expect(wrong.slice(0, 40)).toEqual([]);
    expect(wrong.length).toBe(0);
    expect(cells).toBe(
      STATUSES.length * TARGETS.length * 7 * 15 * VALIDITY.length,
    );
    // Not vacuous: every step ends some cell, and every outcome occurs.
    expect([...endedAt.keys()].sort()).toEqual([0, 3, 4, 5, 6, 7]);
    expect([...outcomes.keys()].sort()).toEqual([
      "benign",
      "cover-accepted",
      "descriptor-out-of-validity",
      "promise",
      "signature-invalid",
      "stopped",
      "store-clock-disagreement",
      "write-refusal",
      "write-window-breach",
    ]);
    expect([...seenKinds].sort()).toEqual([
      "descriptor-out-of-validity",
      "signature-invalid",
      "store-clock-disagreement",
      "write-refusal",
      "write-window-breach",
    ]);
  }, 300_000);

  test("an allocation refusal stated outside the allowed skew is a clock disagreement", async () => {
    const W = C + 10n;
    // Sent at W's allocation instant, when this client's window is W - 1.
    const sentMs = startOf(W - 1n) + ALLOCATION_OFFSET;
    const cases: {
      status: PublicAllocationStatusKindV1;
      stated: bigint;
      want: string[];
    }[] = [
      // A full cohort the store dates two windows back, and one dated at W:
      // windows in which W is still open for allocation, so nothing it
      // signed is contradicted, but no clock within the skew of this
      // request showed either.
      {
        status: "capacity-exhausted",
        stated: W - 2n,
        want: ["store-clock-disagreement"],
      },
      {
        status: "capacity-exhausted",
        stated: W,
        want: ["store-clock-disagreement"],
      },
      // A closed window, dated far enough back that W is past that window's
      // horizon: closed by the store's own rule, and no such clock either.
      {
        status: "window-closed",
        stated: W - 1_000n,
        want: ["store-clock-disagreement"],
      },
      {
        status: "invalid-token",
        stated: W - 2n,
        want: ["store-clock-disagreement"],
      },
      // One millisecond past the skew is enough.
      { status: "token-spent", stated: W, want: ["store-clock-disagreement"] },
      // The same refusals dated within the skew are reported as refusals.
      { status: "capacity-exhausted", stated: W - 1n, want: ["write-refusal"] },
      { status: "token-spent", stated: W - 1n, want: ["write-refusal"] },
      // And a refusal its own window contradicts is blamed before any clock
      // is looked at: a full cohort dated after W's close.
      {
        status: "capacity-exhausted",
        stated: W + 4n,
        want: ["write-window-breach"],
      },
    ];
    for (const { status, stated, want } of cases) {
      const { client, clock, log } = await connectClient(
        WIDE,
        allocationAnswerer(status, stated),
        sentMs,
      );
      // W starts SKEW + 1 ms after this request at the latest.
      clock.now =
        status === "token-spent" && stated === W
          ? startOf(W) - SKEW - 1n
          : sentMs;
      expect(await client.allocate(W, KEY_PAIR)).toBeNull();
      expect([status, String(stated - W), kindsOf(client)]).toEqual([
        status,
        String(stated - W),
        want,
      ]);
      expect(log.length).toBe(1);
      expect(client.inert).toBe(want[0] === "write-window-breach");
      expect(client.stopped).toBeNull();
      // A report is not evidence; blame keeps the signed answer.
      if (want[0] === "write-window-breach")
        expect(await provedBy(client.faults[0])).toBe("write-window-breach");
      else expect(client.faults[0].evidence).toBeUndefined();
      if (want[0] === "store-clock-disagreement")
        expect(client.faults[0].detail).toContain(
          `at its own window ${String(stated)}`,
        );
    }
  });

  test("an honest store is never blamed on the write path at any clock offset within the allowed skew", async () => {
    const W = C + 5n;
    const instants = new Set<bigint>();
    for (let at = startOf(W - 3n); at <= startOf(W + 2n); at += 100n)
      instants.add(at);
    for (const edge of [startOf(W - 1n), startOf(W), startOf(W + 1n), finOf(W)])
      for (const delta of [-SKEW - 1n, -SKEW, -1n, 0n, 1n, SKEW - 1n, SKEW])
        instants.add(edge + delta);
    const sorted = [...instants].sort((left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
    const other = new Uint8Array(OBJECT_BYTES).fill(0x42);
    const seen = new Set<string>();
    for (const aheadMs of [-SKEW, -SKEW / 2n, 0n, SKEW / 2n, SKEW]) {
      const clock: Clock = { now: startOf(W - 4n) };
      const core = await PrototypeStoreCore.create({
        module: cryptoModule,
        seed: SEED,
        profile,
        clock: { nowMs: () => clock.now + aheadMs },
        persistence: new MemoryStorePersistence(),
        chainStartIngressWindow: C,
        origin: ORIGIN,
        descriptorValidityMs: 2_592_000_000n,
        retentionWindows: Number(R),
      });
      const handler = createPrototypeStoreHandler({ core });
      // What the store answered, read off the wire beside the client.
      const statuses: string[] = [];
      const client = await PrototypeStoreClient.connect({
        origin: ORIGIN,
        profile,
        profileHash: PROFILE_HASH,
        module: cryptoModule,
        fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
          const response = await handler(new Request(String(input), init));
          const path = new URL(String(input)).pathname;
          const bytes = new Uint8Array(await response.clone().arrayBuffer());
          if (path === PROTOTYPE_STORE_ROUTES.allocation) {
            const result = decodePublicAllocationResultV1(bytes);
            statuses.push(
              `allocation ${result.kind === "status" ? result.value.status : "lease"}`,
            );
          }
          if (path === PROTOTYPE_STORE_ROUTES.append)
            statuses.push(`append ${decodePublicAppendResultV1(bytes).status}`);
          return response;
        }) as typeof fetch,
        nowMs: () => clock.now,
      });
      // A lease for W, taken at W's allocation instant.
      clock.now = startOf(W - 1n) + ALLOCATION_OFFSET;
      const held = await client.allocate(W, KEY_PAIR);
      if (held === null) throw new Error("expected a lease");
      const admitted = async (object: Uint8Array) =>
        client.append(
          W,
          0,
          object,
          await buildAppendAdmission(
            held,
            KEY_PAIR.secretKey,
            0,
            0,
            object,
            cryptoModule,
          ),
        );
      for (const at of sorted) {
        clock.now = at;
        await core.finalizeDue();
        const lease = await client.allocate(W, await newKeyPair(cryptoModule));
        const cover = await client.append(W, 0, OBJECT, null);
        const same = await admitted(OBJECT);
        const conflicting = await admitted(other);
        // Every honest answer is believed: none comes back unanswered.
        if ([cover, same, conflicting].includes(null))
          throw new Error(`an append to W at ${String(at)} was not believed`);
        expect(lease === null).toBe(
          statuses[statuses.length - 4] !== "allocation lease",
        );
      }
      for (const status of statuses) seen.add(status);
      // Never blamed, never inert, never stopped. The one report is the
      // refusal an honest store gives and nothing it signed contradicts: a
      // full cohort, a slot bound to other bytes.
      const refusals = statuses.filter(
        (status) =>
          status === "allocation capacity-exhausted" ||
          status === "append slot-conflict",
      ).length;
      expect(client.inert).toBe(false);
      expect(client.stopped).toBeNull();
      expect([String(aheadMs), [...new Set(kindsOf(client))]]).toEqual([
        String(aheadMs),
        ["write-refusal"],
      ]);
      expect(kindsOf(client).length).toBe(refusals);
    }
    // Not vacuous: every answer an honest store gives on the write path.
    expect([...seen].sort()).toEqual([
      "allocation capacity-exhausted",
      "allocation lease",
      "allocation window-closed",
      "append already-present",
      "append capacity-exhausted",
      "append slot-conflict",
      "append stored",
      "append unallocated-cover",
      "append window-finalized",
    ]);
  }, 120_000);
});

/* ------------------------------------------------------------------ *
 * Steps 1 and 2: a signed answer to another question is kept
 * ------------------------------------------------------------------ */

/** A lease for `request`, signed with the store's key. */
const leaseAnswer = async (
  request: PublicAllocationRequestV1,
): Promise<Uint8Array> => {
  const leaseBody = {
    version: 1 as const,
    storeId: STORE_ID,
    deliveryProfileHash: request.deliveryProfileHash,
    ingressWindow: request.ingressWindow,
    requestHash: await publicAllocationRequestHash(request),
    allocationOrdinal: 0,
    allocationEd25519PublicKey: request.allocationEd25519PublicKey,
  };
  return encodePublicAllocationResultV1({
    kind: "allocated",
    lease: {
      ...leaseBody,
      storeSignature: await sign(
        await publicAllocationLeaseSignedMessage(leaseBody),
        STORE_SECRET,
        cryptoModule,
      ),
    },
  });
};

const leaseAnswerer: Answerer = async (sent) =>
  answer(
    await leaseAnswer(
      decodePublicAllocationRequestV1(sent.body ?? new Uint8Array(0)),
    ),
    PROTOTYPE_STORE_MEDIA_TYPES.allocationResult,
  );

/** The scheduled read of window C, made in the window after it. */
const SCHEDULED_READ = startOf(C + 1n) + READ_OFFSET;

/** The served window C, with its checkpoint answered by `checkpoint`. */
const checkpointAnswerer =
  (checkpoint: () => Response | Promise<Response>): Answerer =>
  (sent) =>
    sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`)
      ? checkpoint()
      : servedRead(sent);

const checkpointBytes = (bytes: Uint8Array) => (): Response =>
  answer(bytes, PROTOTYPE_STORE_MEDIA_TYPES.checkpoint);

describe("store client: signed answers to another question", () => {
  test("a status naming another descriptor keeps the signed answer as evidence", async () => {
    // A second authentic descriptor of the same store, another retention.
    const other = await documentValid(
      startOf(C - 5_000n),
      startOf(C + 50_000n),
      Number(R) + 40,
    );
    const otherHash = await descriptorHash(other.descriptor);
    expect(hex(otherHash)).not.toBe(hex(WIDE_HASH));
    const W = C + 10n;
    const writeAt = startOf(W - 1n) + ALLOCATION_OFFSET;

    // Each answer would be blame under the pinned descriptor; named under
    // another, it proves nothing this client can check, and is kept.
    const runs: {
      route: string;
      run: (kept: (bytes: Uint8Array) => void) => Promise<PrototypeStoreClient>;
    }[] = [
      {
        route: "checkpoint status",
        run: async (kept) => {
          const bytes = await readStatus(
            "checkpoint",
            C,
            "out-of-range",
            C + 1n,
            otherHash,
          );
          kept(bytes);
          const { client, clock } = await connectClient(
            WIDE,
            checkpointAnswerer(checkpointBytes(bytes)),
            SCHEDULED_READ,
          );
          clock.now = SCHEDULED_READ;
          expect((await client.scanWindow(C)).status).toBe("unreachable");
          return client;
        },
      },
      {
        route: "chunk status",
        run: async (kept) => {
          const bytes = await readStatus(
            "chunk",
            C,
            "no-such-chunk",
            C + 1n,
            otherHash,
          );
          kept(bytes);
          const { client, clock } = await connectClient(
            WIDE,
            (sent) =>
              sent.path.endsWith("/0/0") &&
              sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.chunk}/`)
                ? answer(bytes, PROTOTYPE_STORE_MEDIA_TYPES.chunk)
                : servedRead(sent),
            SCHEDULED_READ,
          );
          clock.now = SCHEDULED_READ;
          expect((await client.scanWindow(C)).status).toBe("unreachable");
          return client;
        },
      },
      {
        route: "allocation status",
        run: async (kept) => {
          const { client, clock } = await connectClient(
            WIDE,
            allocationAnswerer("window-closed", W - 1n, otherHash, kept),
            writeAt,
          );
          clock.now = writeAt;
          expect(await client.allocate(W, KEY_PAIR)).toBeNull();
          return client;
        },
      },
      {
        route: "append result",
        run: async (kept) => {
          const { client, clock } = await connectClient(
            WIDE,
            appendAnswerer("window-finalized", W - 1n, otherHash, kept),
            writeAt,
          );
          clock.now = writeAt;
          expect(await client.append(W, 0, OBJECT, admissionFor(W))).toBeNull();
          return client;
        },
      },
    ];
    for (const { route, run } of runs) {
      let served: Uint8Array | null = null;
      const client = await run((bytes) => {
        served = bytes;
      });
      expect([route, kindsOf(client), client.inert]).toEqual([
        route,
        ["signature-invalid"],
        false,
      ]);
      const record = client.faults[0];
      expect(record.detail).toContain(
        "names a descriptor other than the one this client pinned",
      );
      // The signed answer as it came, beside the descriptor this client
      // pinned (the key it verified under).
      expect((record.evidence ?? []).map(hex)).toEqual([
        hex(served ?? new Uint8Array(0)),
      ]);
      expect(record.descriptor).toEqual(WIDE.descriptor);
      // It proves nothing from the record, as kept.
      expect(await provedBy(record)).toBeNull();
    }

    // And it counts: one store answering appends with another descriptor
    // is stopped like one whose clock disagrees.
    const { client, clock, stops } = await connectClient(
      WIDE,
      appendAnswerer("stored", W, otherHash),
      writeAt,
    );
    clock.now = startOf(W) + 1_300n;
    for (let index = 0; index < LIMIT; index++)
      expect(await client.append(W, 0, OBJECT, admissionFor(W))).toBeNull();
    expect(stops).toEqual([
      {
        reason: "disagreement-limit",
        storeIdHex: client.storeIdHex,
        route: "append",
        disagreement: "signed-mismatch",
        count: LIMIT,
      },
    ]);
  });
});

/* ------------------------------------------------------------------ *
 * Escalation
 * ------------------------------------------------------------------ */

/** A `not-final` for C dated a hundred windows back: never a breach, and
 * no clock within the skew of the scheduled read shows that window. */
const disagreeing = await readStatus(
  "checkpoint",
  C,
  "not-final",
  C - 100n,
  WIDE_HASH,
);
const disagree = checkpointBytes(disagreeing);

describe("store client escalation", () => {
  test("repeated clock disagreements stop the store and emit one event", async () => {
    const held = holder<Response>();
    let token = holder<void>();
    const { client, clock, log, stops } = await connectClient(
      WIDE,
      (sent) => {
        if (sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`))
          return held.hold();
        if (sent.method === "POST") return leaseAnswerer(sent);
        return servedRead(sent);
      },
      SCHEDULED_READ,
      {
        admissionTokens: async (request) => {
          await token.hold();
          return {
            storeId: request.storeId,
            token: new Uint8Array(32).fill(1),
          };
        },
      },
    );
    clock.now = SCHEDULED_READ;

    // LIMIT - 1 disagreements in a row: reported, the store still used.
    for (let index = 0; index < LIMIT - 1; index++) {
      const scan = client.scanWindow(C);
      await turns();
      held.release(index, disagree());
      expect((await scan).status).toBe("clock-disagreement");
    }
    expect(client.stopped).toBeNull();
    expect(stops).toEqual([]);
    expect(kindsOf(client)).toEqual(
      Array.from({ length: LIMIT - 1 }, () => "store-clock-disagreement"),
    );

    // Two scans out at once, and an allocation waiting for its admission
    // token. The answers come back in the order the store chooses: the
    // later scan's first.
    const first = client.scanWindow(C);
    const second = client.scanWindow(C);
    const waiting = client.allocate(C + 10n, KEY_PAIR);
    await turns();
    expect(held.count).toBe(LIMIT + 1);
    held.release(LIMIT, disagree());
    expect((await second).status).toBe("clock-disagreement");
    // The limit was reached by that answer: one event, naming the store,
    // the kind, the route and the count.
    expect(stops).toEqual([
      {
        reason: "disagreement-limit",
        storeIdHex: client.storeIdHex,
        route: "read",
        disagreement: "store-clock-disagreement",
        count: LIMIT,
      },
    ]);
    // The earlier scan's answer is still judged and recorded, and changes
    // nothing more.
    held.release(LIMIT - 1, disagree());
    expect((await first).status).toBe("clock-disagreement");
    expect(stops.length).toBe(1);
    expect(kindsOf(client).length).toBe(LIMIT + 1);
    // The allocation that was waiting when the store stopped sends nothing.
    token.release(0, undefined);
    expect(await waiting).toBeNull();
    const requestsAtStop = log.length;
    expect(log.some((sent) => sent.method === "POST")).toBe(false);

    // From now on nothing is asked of the store, on any route, and no
    // operation adds a report.
    token = holder<void>();
    expect((await client.scanWindow(C)).status).toBe("stopped");
    expect(await client.allocate(C + 10n, KEY_PAIR)).toBeNull();
    expect(await client.append(C + 10n, 0, OBJECT, null)).toBeNull();
    expect(await client.issueToken(C + 10n)).toBe(false);
    expect(log.length).toBe(requestsAtStop);
    expect(stops.length).toBe(1);
    expect(kindsOf(client).length).toBe(LIMIT + 1);
    expect(client.inert).toBe(false);
  });

  test("a benign answer resets the disagreement count", async () => {
    let mode: "disagree" | "serve" = "disagree";
    const { client, clock, stops } = await connectClient(
      WIDE,
      (sent) => {
        if (sent.method === "POST") return leaseAnswerer(sent);
        return mode === "disagree"
          ? checkpointAnswerer(disagree)(sent)
          : servedRead(sent);
      },
      SCHEDULED_READ,
    );
    clock.now = SCHEDULED_READ;
    const disagreements = async (count: number): Promise<void> => {
      mode = "disagree";
      for (let index = 0; index < count; index++)
        expect((await client.scanWindow(C)).status).toBe("clock-disagreement");
    };

    await disagreements(LIMIT - 1);
    // A believed read: the read route's count starts again.
    mode = "serve";
    expect((await client.scanWindow(C)).status).toBe("finalized");
    await disagreements(LIMIT - 1);
    expect(client.stopped).toBeNull();

    // A believed answer on another route does not: leases, however many.
    for (let index = 0; index < 3; index++) {
      clock.now = startOf(C + 1n) + ALLOCATION_OFFSET;
      expect(await client.allocate(C + 2n, KEY_PAIR)).not.toBeNull();
    }
    clock.now = SCHEDULED_READ;
    expect(client.stopped).toBeNull();
    await disagreements(1);
    expect(stops).toEqual([
      {
        reason: "disagreement-limit",
        storeIdHex: client.storeIdHex,
        route: "read",
        disagreement: "store-clock-disagreement",
        count: LIMIT,
      },
    ]);
  });

  test("the count follows the order answers arrive in", async () => {
    // LIMIT - 1 disagreements, then a believed scan and a disagreeing one
    // out together. Whichever answer the store lets in first decides.
    for (const believedFirst of [true, false]) {
      const held = holder<Response>();
      const { client, clock, stops } = await connectClient(
        WIDE,
        (sent) =>
          sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`)
            ? held.hold()
            : servedRead(sent),
        SCHEDULED_READ,
      );
      clock.now = SCHEDULED_READ;
      for (let index = 0; index < LIMIT - 1; index++) {
        const scan = client.scanWindow(C);
        await turns();
        held.release(index, disagree());
        await scan;
      }
      const believed = client.scanWindow(C);
      const refused = client.scanWindow(C);
      await turns();
      const [believedIndex, refusedIndex] = [LIMIT - 1, LIMIT];
      if (believedFirst) {
        held.release(believedIndex, checkpointBytes(SERVED_CHECKPOINT)());
        expect((await believed).status).toBe("finalized");
        held.release(refusedIndex, disagree());
        expect((await refused).status).toBe("clock-disagreement");
        expect(stops).toEqual([]);
      } else {
        held.release(refusedIndex, disagree());
        expect((await refused).status).toBe("clock-disagreement");
        held.release(believedIndex, checkpointBytes(SERVED_CHECKPOINT)());
        // Judged and served: what the store signed is still verified.
        expect((await believed).status).toBe("finalized");
        expect(stops.map((stop) => stop.reason)).toEqual([
          "disagreement-limit",
        ]);
      }
    }
  });
});

/* ------------------------------------------------------------------ *
 * The descriptor's lifetime
 * ------------------------------------------------------------------ */

/** A descriptor that ends inside window C + 20. */
const T = startOf(C + 20n) + 1_234n;
const SHORT = await documentValid(startOf(C - 5_000n), T);
const SHORT_HASH = await descriptorHash(SHORT.descriptor);

describe("store descriptor lifetime", () => {
  test("a write after the pinned descriptor expires is refused before any request is made", async () => {
    let tokens = 0;
    const { client, clock, log, stops } = await connectClient(
      SHORT,
      (sent) => {
        if (sent.path === PROTOTYPE_STORE_ROUTES.allocation)
          return leaseAnswerer(sent);
        if (sent.path === PROTOTYPE_STORE_ROUTES.append)
          return appendAnswerer("stored", C + 20n, SHORT_HASH)(sent);
        return unsigned(404, "not found");
      },
      T - 5_000n,
      {
        admissionTokens: (request) => {
          tokens += 1;
          return {
            storeId: request.storeId,
            token: new Uint8Array(32).fill(7),
          };
        },
      },
    );
    // One millisecond before the end, a write is made.
    clock.now = T - 1n;
    expect(await client.allocate(C + 21n, KEY_PAIR)).not.toBeNull();
    expect(log.map((sent) => sent.path)).toEqual([
      PROTOTYPE_STORE_ROUTES.allocation,
    ]);
    const asked = tokens;

    // At the end, none is: not even the admission token is asked for.
    clock.now = T;
    expect(await client.allocate(C + 21n, KEY_PAIR)).toBeNull();
    expect(
      await client.append(C + 20n, 0, OBJECT, admissionFor(C + 20n)),
    ).toBeNull();
    expect(await client.append(C + 20n, 0, OBJECT, null)).toBeNull();
    expect(await client.issueToken(C + 21n)).toBe(false);
    expect(
      await client.postWitness({
        version: 1,
        witnessedStoreId: new Uint8Array(32).fill(3),
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: C + 19n,
        checkpointHash: new Uint8Array(32).fill(4),
      }),
    ).toBe(false);
    clock.now = T + 100n * L;
    expect(await client.allocate(C + 122n, KEY_PAIR)).toBeNull();
    expect(log.length).toBe(1);
    expect(tokens).toBe(asked);
    // Said once, by the event, and never per request.
    expect(stops).toEqual([
      {
        reason: "descriptor-expired",
        storeIdHex: client.storeIdHex,
        notAfterUnixMs: T,
        atMs: T,
      },
    ]);
    expect(kindsOf(client)).toEqual([]);
    expect(client.stopped).toEqual(stops[0]);

    // A write that was waiting for its token when the end came sends
    // nothing either.
    const late = holder<void>();
    const second = await connectClient(
      SHORT,
      appendAnswerer("stored", C + 20n, SHORT_HASH),
      T - 5_000n,
      {
        admissionTokens: async (request) => {
          await late.hold();
          return {
            storeId: request.storeId,
            token: new Uint8Array(32).fill(7),
          };
        },
      },
    );
    second.clock.now = T - 1n;
    const pending = second.client.append(
      C + 20n,
      0,
      OBJECT,
      admissionFor(C + 20n),
    );
    await turns();
    second.clock.now = T;
    late.release(0, undefined);
    expect(await pending).toBeNull();
    expect(second.log).toEqual([]);
    expect(second.stops.map((stop) => stop.reason)).toEqual([
      "descriptor-expired",
    ]);
  });

  test("an expired pinned descriptor emits one reconnect event, not one report per read", async () => {
    const held = holder<Response>();
    const fresh = startOf(C + 19n) + READ_OFFSET;
    let straddle = false;
    const { client, clock, log, stops } = await connectClient(
      SHORT,
      (sent) => {
        if (sent.method === "POST")
          return appendAnswerer("stored", C + 19n, SHORT_HASH)(sent);
        if (
          straddle &&
          sent.path.startsWith(`${PROTOTYPE_STORE_ROUTES.checkpoint}/`)
        )
          return held.hold();
        return servedRead(sent);
      },
      fresh,
    );
    // A receipt held for a window no read will now check.
    clock.now = startOf(C + 19n) + 1_300n;
    const admission = admissionFor(C + 19n);
    const result = await client.append(C + 19n, 0, OBJECT, admission);
    if (result === null) throw new Error("expected a receipt");
    client.recordReceipt({
      window: C + 19n,
      sizeClass: 0,
      lease: admission.lease,
      objectOrdinal: 0,
      objectHash: new Uint8Array(32).fill(9),
      result,
    });

    // A read sent before the end and answered after it: that one read is
    // reported, as the descriptor did not cover it.
    straddle = true;
    clock.now = T - 1n;
    const across = client.scanWindow(C);
    await turns();
    clock.now = T + 1n;
    held.release(0, checkpointBytes(SERVED_CHECKPOINT)());
    expect((await across).status).toBe("descriptor-out-of-validity");
    expect(kindsOf(client)).toEqual(["descriptor-out-of-validity"]);
    const requests = log.length;

    // Two reads at once, the first after the end, then a read a window for
    // twenty windows: one event, no request, and no report per read.
    const [one, two] = await Promise.all([
      client.scanWindow(C),
      client.scanWindow(C),
    ]);
    expect([one.status, two.status]).toEqual(["stopped", "stopped"]);
    for (let index = 0n; index < 20n; index++) {
      clock.now = T + 1n + index * L;
      const scan = await client.scanWindow(C);
      expect([scan.status, scan.objects.length, scan.checkpointHash]).toEqual([
        "stopped",
        0,
        null,
      ]);
    }
    expect(log.length).toBe(requests);
    expect(stops).toEqual([
      {
        reason: "descriptor-expired",
        storeIdHex: client.storeIdHex,
        notAfterUnixMs: T,
        atMs: T + 1n,
      },
    ]);
    // The one read report, and the receipt reported unchecked when the store
    // was given up, once.
    expect(kindsOf(client)).toEqual([
      "descriptor-out-of-validity",
      "custody-unchecked",
    ]);
    expect(client.faults[1].window).toBe(C + 19n);
  });

  test("a store past its descriptor's validity refuses with one message", async () => {
    const clock: Clock = { now: finOf(C) };
    const persistence = new SqliteStorePersistence(":memory:");
    // Valid from a minute before the chain start for 20 windows.
    const core = await coreAt(clock, { validityMs: 20n * L, persistence });
    const notAfter = core.descriptor.notAfterUnixMs;
    expect(notAfter).toBe(startOf(C) - 60_000n + 20n * L);
    const handler = createPrototypeStoreHandler({ core });
    await core.finalizeDue();
    const checkpointPath = `${PROTOTYPE_STORE_ROUTES.checkpoint}/${PROFILE_HEX}/${String(C)}`;
    const get = (path: string): Promise<Response> =>
      handler(new Request(`${ORIGIN}${path}`));
    // Before the end the finalized window is served, from its stored row.
    expect((await get(checkpointPath)).status).toBe(200);

    const errors = spyOn(console, "error").mockImplementation(() => undefined);
    try {
      clock.now = notAfter;
      const post = (path: string, mediaType: string, body: Uint8Array) =>
        handler(
          new Request(`${ORIGIN}${path}`, {
            method: "POST",
            headers: { "content-type": mediaType },
            body: asBody(body),
          }),
        );
      const allocation = encodePublicAllocationRequestV1({
        version: 1,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: C + 1n,
        allocationEd25519PublicKey: KEY_PAIR.publicKey,
        privacyPassToken: new Uint8Array(32),
      });
      const append = encodePublicAppendRequestV1({
        version: 1,
        bucket: {
          deliveryProfileHash: PROFILE_HASH,
          ingressWindow: C + 1n,
          sizeClass: 0,
        },
        exactFixedObject: OBJECT,
        admission: null,
      });
      const token = encodeAllocationTokenIssueRequestV1({
        version: 1,
        storeId: STORE_ID,
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: C + 1n,
        privacyPassTokenRequest: new Uint8Array(32),
      });
      const witness = encodeStoreWitnessRecordV1({
        version: 1,
        witnessedStoreId: new Uint8Array(32).fill(3),
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: C,
        checkpointHash: new Uint8Array(32).fill(4),
      });
      const answers = [
        await get(PROTOTYPE_STORE_ROUTES.descriptor),
        await get(checkpointPath),
        await get(
          `${PROTOTYPE_STORE_ROUTES.chunk}/${PROFILE_HEX}/${String(C)}/0/0`,
        ),
        await get(
          `${PROTOTYPE_STORE_ROUTES.witness}/${PROFILE_HEX}/${String(C)}`,
        ),
        await post(
          PROTOTYPE_STORE_ROUTES.allocation,
          PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
          allocation,
        ),
        await post(
          PROTOTYPE_STORE_ROUTES.append,
          PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
          append,
        ),
        await post(
          PROTOTYPE_STORE_ROUTES.token,
          PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
          token,
        ),
        await post(
          PROTOTYPE_STORE_ROUTES.witness,
          PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
          witness,
        ),
      ];
      // One distinct unsigned status, the same body, on every route: the
      // stored row of a finalized window included.
      expect(answers.map((response) => response.status)).toEqual(
        Array.from({ length: answers.length }, () => 410),
      );
      expect(
        await Promise.all(answers.map((response) => response.text())),
      ).toEqual(
        Array.from({ length: answers.length }, () => "descriptor expired"),
      );
      for (const response of answers)
        expect(response.headers.get("x-p2party-store")).toBe("prototype-v1");
      // And one sentence for the operator, however many requests were refused.
      clock.now = notAfter + 40n * L;
      expect((await get(checkpointPath)).status).toBe(410);
      expect(errors.mock.calls.length).toBe(1);
      const message = String(errors.mock.calls[0][0]);
      expect(message).toContain(
        `the store descriptor expired at ${new Date(Number(notAfter)).toISOString()}`,
      );
      expect(message).toContain("P2PARTY_STORE_DB");
      expect(message).toContain("P2PARTY_STORE_KEY_FILE");
      // Health says so, and the core refuses in process too.
      const health = (await (
        await get(PROTOTYPE_STORE_ROUTES.health)
      ).json()) as {
        status: string;
      };
      expect(health.status).toBe("descriptor-expired");
      await expect(
        core.readCheckpointEncoded(PROFILE_HASH, C),
      ).rejects.toMatchObject({ name: "StoreDescriptorExpiredError" });
      // Nothing is signed from the end on: no window whose finalization
      // instant is at or after it.
      const finalized = await core.finalizeDue();
      expect(finalized.length).toBeGreaterThan(0);
      for (const window of finalized)
        expect(finOf(window) < notAfter).toBe(true);
      expect(await core.finalizeDue()).toEqual([]);
    } finally {
      errors.mockRestore();
      persistence.close();
    }
  });
});

/* ------------------------------------------------------------------ *
 * Back-off, retention cap, receive time, the lone denial, deadlines
 * ------------------------------------------------------------------ */

describe("store client back-off and bounds", () => {
  test("the client backs off on 503 and resets on an answer", async () => {
    let held = holder<Response>();
    let mode: "hold" | "busy" | "serve" = "hold";
    const { client, clock, log } = await connectClient(
      WIDE,
      (sent) => {
        if (mode === "hold") return held.hold();
        if (mode === "busy") return unsigned(503, "busy");
        return servedRead(sent);
      },
      SCHEDULED_READ,
    );
    const busy = (): Response => unsigned(503, "busy");
    const t0 = SCHEDULED_READ;
    clock.now = t0;

    // One scan's six requests, all answered 503, the store choosing the
    // order: the delay starts once, not six times.
    const first = client.scanWindow(C);
    await turns();
    expect(held.count).toBe(6);
    for (const index of [3, 0, 5, 1, 4, 2]) held.release(index, busy());
    expect((await first).status).toBe("unreachable");
    const delayOf = () => (client.backoffUntilMs ?? clock.now) - clock.now;
    expect(delayOf()).toBe(BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS));
    expect(
      client.faults.some((fault) =>
        fault.detail.includes(
          `nothing for ${String(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS)} ms`,
        ),
      ),
    ).toBe(true);
    const reports = client.faults.length;

    // While it lasts, nothing is sent, on any route, and nothing is added.
    const sent = log.length;
    clock.now = t0 + BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS) - 1n;
    expect((await client.scanWindow(C)).status).toBe("unreachable");
    expect(await client.allocate(C + 3n, KEY_PAIR)).toBeNull();
    expect(await client.append(C + 2n, 0, OBJECT, null)).toBeNull();
    expect(log.length).toBe(sent);
    expect(client.faults.length).toBe(reports);

    // Each further 503 doubles the delay, up to the bound.
    mode = "busy";
    const delays: number[] = [];
    for (let attempt = 0; attempt < 10; attempt++) {
      clock.now = client.backoffUntilMs ?? clock.now;
      expect((await client.scanWindow(C)).status).toBe("unreachable");
      delays.push(Number(delayOf()));
    }
    expect(delays).toEqual([
      500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 32_000, 32_000, 32_000,
    ]);
    expect(Math.max(...delays)).toBe(PROTOTYPE_STORE_CLIENT_BACKOFF_MAX_MS);

    // An answer ends it, and the next 503 starts from the bottom again.
    mode = "serve";
    clock.now = client.backoffUntilMs ?? clock.now;
    expect((await client.scanWindow(C)).status).toBe("finalized");
    expect(client.backoffUntilMs).toBeNull();
    mode = "busy";
    expect((await client.scanWindow(C)).status).toBe("unreachable");
    expect(delayOf()).toBe(BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS));

    // An answer to a request sent before a 503 arrived does not end the
    // back-off that 503 began, whichever order the store answers in.
    for (const busyFirst of [true, false]) {
      mode = "serve";
      clock.now = client.backoffUntilMs ?? clock.now;
      expect((await client.scanWindow(C)).status).toBe("finalized");
      expect(client.backoffUntilMs).toBeNull();
      held = holder<Response>();
      mode = "hold";
      const scan = client.scanWindow(C);
      await turns();
      const chunks = [1, 2, 3, 4, 5];
      if (busyFirst) {
        held.release(0, busy());
        for (const index of chunks)
          held.release(
            index,
            servedRead({
              path: chunkPathOf(index),
              method: "GET",
              body: null,
            }) as Response,
          );
      } else {
        for (const index of chunks)
          held.release(
            index,
            servedRead({
              path: chunkPathOf(index),
              method: "GET",
              body: null,
            }) as Response,
          );
        held.release(0, busy());
      }
      expect((await scan).status).toBe("unreachable");
      expect(delayOf()).toBe(BigInt(PROTOTYPE_STORE_CLIENT_BACKOFF_MIN_MS));
    }
  });

  test("a descriptor stating more retention than the cap is refused at connect", async () => {
    const window = [startOf(C - 5_000n), startOf(C + 50_000n)] as const;
    const over = await documentValid(
      ...window,
      PROTOTYPE_STORE_MAX_RETENTION_WINDOWS + 1,
    );
    await expect(
      connectClient(over, servedRead, SCHEDULED_READ),
    ).rejects.toMatchObject({ name: "StoreRetentionError" });
    await expect(
      connectClient(over, servedRead, SCHEDULED_READ),
    ).rejects.toThrow(
      `more than the ${String(PROTOTYPE_STORE_MAX_RETENTION_WINDOWS)} this client accepts`,
    );
    // The cap itself is accepted.
    const at = await documentValid(
      ...window,
      PROTOTYPE_STORE_MAX_RETENTION_WINDOWS,
    );
    const { client } = await connectClient(at, servedRead, SCHEDULED_READ);
    expect(client.descriptor.retentionWindows).toBe(
      PROTOTYPE_STORE_MAX_RETENTION_WINDOWS,
    );
  });

  test("a stalled chunk does not widen the clock tolerance of the checkpoint status", async () => {
    // The store states the first window past W's retention: honest only
    // within the skew of that window's start.
    const past = C + R + 1n;
    const sentMs = startOf(past) - SKEW - 1_000n;
    const refusal = await readStatus(
      "checkpoint",
      C,
      "out-of-range",
      past,
      WIDE_HASH,
    );
    for (const stalled of ["chunk", "checkpoint"] as const) {
      const held = holder<Response>();
      const { client, clock } = await connectClient(
        WIDE,
        (sent) => {
          const isCheckpoint = sent.path.startsWith(
            `${PROTOTYPE_STORE_ROUTES.checkpoint}/`,
          );
          if (isCheckpoint && stalled === "chunk")
            return answer(refusal, PROTOTYPE_STORE_MEDIA_TYPES.checkpoint);
          if (isCheckpoint || sent.path.endsWith("/0/0")) return held.hold();
          return servedRead(sent);
        },
        sentMs,
      );
      clock.now = sentMs;
      const scan = client.scanWindow(C);
      await turns();
      // The held answer comes in once a store within the skew could state
      // `past`.
      clock.now = startOf(past) - SKEW + 5n;
      held.release(
        0,
        stalled === "chunk"
          ? (servedRead({
              path: chunkPathOf(1),
              method: "GET",
              body: null,
            }) as Response)
          : answer(refusal, PROTOTYPE_STORE_MEDIA_TYPES.checkpoint),
      );
      if (stalled === "checkpoint")
        held.release(
          1,
          servedRead({
            path: chunkPathOf(1),
            method: "GET",
            body: null,
          }) as Response,
        );
      const result = await scan;
      if (stalled === "chunk") {
        // The checkpoint status was in at `sentMs`: judged against that, no
        // clock within the skew showed `past`, however long the chunk took.
        expect([result.status, kindsOf(client)]).toEqual([
          "clock-disagreement",
          ["store-clock-disagreement"],
        ]);
        expect(client.faults[0].detail).toContain(
          `${String(sentMs)} to ${String(sentMs)} ms`,
        );
      } else {
        // The control: the same refusal, itself in at the later instant, is
        // the honest expiry.
        expect([result.status, kindsOf(client)]).toEqual([
          "beyond-retention",
          [],
        ]);
      }
    }
  });

  test("a lone signed denial of a defined coordinate is verifiable", async () => {
    const descriptor = servedCore.descriptor;
    const denial = await readStatus(
      "chunk",
      C,
      "no-such-chunk",
      C + 1n,
      servedCore.descriptorHash,
    );
    // The denial, the descriptor it names and the profile suffice.
    expect(
      await signedStatusProvesFault(
        descriptor,
        profile,
        [denial],
        cryptoModule,
      ),
    ).toBe("chunk-denial-breach");
    // The pair form keeps working, and still refuses a checkpoint that does
    // not commit to the denied window.
    expect(
      await signedStatusProvesFault(
        descriptor,
        profile,
        [SERVED_CHECKPOINT, denial],
        cryptoModule,
      ),
    ).toBe("chunk-denial-breach");
    const elsewhere = await readStatus(
      "chunk",
      C + 3n,
      "no-such-chunk",
      C + 4n,
      servedCore.descriptorHash,
    );
    expect(
      await signedStatusProvesFault(
        descriptor,
        profile,
        [SERVED_CHECKPOINT, elsewhere],
        cryptoModule,
      ),
    ).toBeNull();
    expect(
      await signedStatusProvesFault(
        descriptor,
        profile,
        [elsewhere],
        cryptoModule,
      ),
    ).toBe("chunk-denial-breach");
    // A coordinate the profile does not define is denied honestly: the real
    // core's own answer proves nothing, alone or as forged under its key.
    const count = BigInt(
      profile.sizeClasses.find((sizeClass) => sizeClass.id === 0)
        ?.publicChunksPerWindow ?? 0,
    );
    const honest = encodePublicChunkReadV1(
      await servedCore.readChunk(
        { deliveryProfileHash: PROFILE_HASH, ingressWindow: C, sizeClass: 0 },
        count,
      ),
    );
    for (const bytes of [
      honest,
      await readStatus(
        "chunk",
        C,
        "no-such-chunk",
        C + 1n,
        servedCore.descriptorHash,
        {
          sizeClass: 0,
          chunkIndex: count,
        },
      ),
      await readStatus(
        "chunk",
        C,
        "no-such-chunk",
        C + 1n,
        servedCore.descriptorHash,
        {
          sizeClass: 77,
          chunkIndex: 0n,
        },
      ),
    ])
      expect(
        await signedStatusProvesFault(
          descriptor,
          profile,
          [bytes],
          cryptoModule,
        ),
      ).toBeNull();
    // Not one byte changed, not another descriptor, not another profile.
    const altered = Uint8Array.from(denial);
    altered[altered.length - 66] ^= 0x01;
    expect(
      await signedStatusProvesFault(
        descriptor,
        profile,
        [altered],
        cryptoModule,
      ),
    ).toBeNull();
    expect(
      await signedStatusProvesFault(
        WIDE.descriptor,
        profile,
        [denial],
        cryptoModule,
      ),
    ).toBeNull();
    expect(
      await signedStatusProvesFault(
        descriptor,
        { ...profile, chunkFinalizationOffsetMs: F + 1n },
        [denial],
        cryptoModule,
      ),
    ).toBeNull();
  });

  test("a request deadline fires on the injected timers", async () => {
    const pending = new Map<number, () => void>();
    let nextId = 0;
    const timers: CarrierTimers = {
      setTimeout: (callback, delayMs) => {
        expect(delayMs).toBe(Number(L));
        nextId += 1;
        pending.set(nextId, callback);
        return nextId;
      },
      clearTimeout: (handle) => {
        pending.delete(handle as number);
      },
    };
    // A store that accepts the connection and never answers a read: each
    // request settles only when its own deadline aborts it.
    const clock: Clock = { now: SCHEDULED_READ };
    const client = await PrototypeStoreClient.connect({
      origin: ORIGIN,
      profile,
      profileHash: PROFILE_HASH,
      module: cryptoModule,
      fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
        if (
          new URL(String(input)).pathname === PROTOTYPE_STORE_ROUTES.descriptor
        )
          return Promise.resolve(
            answer(
              encodePrototypeStoreDescriptorDocumentV1(WIDE),
              PROTOTYPE_STORE_MEDIA_TYPES.descriptor,
            ),
          );
        return new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        });
      }) as typeof fetch,
      nowMs: () => clock.now,
      timers,
    });
    // The descriptor fetch armed its deadline on these timers and cleared it.
    expect(nextId).toBe(1);
    expect(pending.size).toBe(0);
    clock.now = SCHEDULED_READ;
    let settled = false;
    const scan = client.scanWindow(C).then((result) => {
      settled = true;
      return result;
    });
    await turns();
    // One deadline per request, on the injected pair, and nothing else ends
    // the scan.
    expect(pending.size).toBe(6);
    expect(settled).toBe(false);
    for (const fire of [...pending.values()]) fire();
    expect((await scan).status).toBe("unreachable");
    expect(client.faults[0].detail).toContain(
      `no answer within the ${String(L)} ms request deadline`,
    );
  });
});

/* ------------------------------------------------------------------ *
 * The store's own write decisions
 * ------------------------------------------------------------------ */

describe("store core write decisions", () => {
  test("a backward step of the clock cannot make an honest store sign a write refusal against itself", async () => {
    const clock: Clock = { now: startOf(C) + ALLOCATION_OFFSET };
    const core = await coreAt(clock);
    const W = C + 1n;
    const request = (key: Uint8Array): PublicAllocationRequestV1 => ({
      version: 1,
      deliveryProfileHash: PROFILE_HASH,
      ingressWindow: W,
      allocationEd25519PublicKey: key,
      privacyPassToken: new Uint8Array(32),
    });
    const leased = await core.allocate(request(KEY_PAIR.publicKey));
    if (leased.kind !== "allocated") throw new Error("expected a lease");
    const admission = await buildAppendAdmission(
      leased.lease,
      KEY_PAIR.secretKey,
      0,
      0,
      OBJECT,
      cryptoModule,
    );
    // W finalized, then the clock steps back to before W's close.
    clock.now = finOf(W);
    await core.finalizeDue();
    clock.now = startOf(W) + 100n;
    const appendRequest: PublicAppendRequestV1 = {
      version: 1,
      bucket: {
        deliveryProfileHash: PROFILE_HASH,
        ingressWindow: W,
        sizeClass: 0,
      },
      exactFixedObject: OBJECT,
      admission,
    };
    // Its reading says W is open, its rows say W is final: no signed answer
    // could state both, so it signs none (the transport's 503).
    await expect(
      core.allocate(request((await newKeyPair(cryptoModule)).publicKey)),
    ).rejects.toMatchObject({ name: "StoreBusyError" });
    await expect(core.append(appendRequest)).rejects.toMatchObject({
      name: "StoreBusyError",
    });
    // And at every reading around W, whatever it signs on the write path
    // proves nothing against it.
    const readings: bigint[] = [];
    for (let at = startOf(W - 3n); at <= startOf(W + 2n); at += 250n)
      readings.push(at);
    readings.push(finOf(W) - 1n, finOf(W), startOf(W) - 1n, startOf(W));
    const sweepClock: Clock = { now: startOf(W - 3n) };
    const sweep = await coreAt(sweepClock);
    let signed = 0;
    for (const at of readings.sort((left, right) => (left < right ? -1 : 1))) {
      sweepClock.now = at;
      await sweep.finalizeDue();
      const allocation = await sweep.allocate(
        request((await newKeyPair(cryptoModule)).publicKey),
      );
      const cover = await sweep.append({ ...appendRequest, admission: null });
      for (const bytes of [
        ...(allocation.kind === "status"
          ? [encodePublicAllocationResultV1(allocation)]
          : []),
        encodePublicAppendResultV1(cover),
      ]) {
        signed += 1;
        expect(
          await signedStatusProvesFault(
            sweep.descriptor,
            profile,
            [bytes],
            cryptoModule,
          ),
        ).toBeNull();
      }
    }
    expect(signed).toBeGreaterThan(readings.length);
  });
});
