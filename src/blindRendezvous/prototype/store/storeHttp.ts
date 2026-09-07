/**
 * The prototype store's transport: routing, coordinate parsing, and canonical
 * serialization. Nothing else.
 *
 * Everything this file can name is public geometry — a delivery-profile hash,
 * an ingress window, a size class, and two ordinals. There is no room, member,
 * peer or invitation value in any path, header or body, and no request carries
 * one, which is what lets unrelated rooms share a bucket and cover for each
 * other. The one deliberate exception is `logBodiesPath`, a harness-only file
 * sink that exists precisely so the E2E can *prove* that claim by hexdumping
 * every body the store parsed; a store run for real never sets it.
 *
 * Three properties this layer is responsible for:
 *
 * - **One constant refusal.** A wrong media type, an oversized body, a body
 *   that is not the unique canonical encoding of its value, and a path
 *   coordinate spelled in a second way all answer `400 malformed` with no
 *   further detail. A refusal that described *what* was wrong would be an
 *   oracle for probing what this store holds.
 * - **Protocol answers are 200.** `not-final`, `out-of-range`,
 *   `window-closed`, `slot-conflict` and friends are signed statements from
 *   the store, not transport errors, so they travel as ordinary bodies. A
 *   reader that trusted HTTP status codes would be trusting an unsigned value.
 * - **Only immutable things are cacheable.** A finalized chunk or checkpoint
 *   can never be re-signed, so it gets a year of `immutable`. Everything else
 *   — the descriptor, every status, health — is `no-store`.
 *
 * Configuration lives in `storeServer.ts`; this file reads no environment.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
 * registry.
 */

import { appendFileSync } from "node:fs";

import { CanonicalSchemaError } from "../../canonicalSchema";
import { PROTOTYPE_ROUTE_PREFIX, PROTOTYPE_STORE_PROTOCOL } from "../profile";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "../storeRoutes";
import {
  decodeAllocationTokenIssueRequestV1,
  decodePublicAllocationRequestV1,
  decodePublicAppendRequestV1,
  decodeStoreWitnessRecordV1,
  encodeAllocationTokenIssueResultV1,
  encodePrototypeStoreDescriptorDocumentV1,
  encodePublicAllocationResultV1,
  encodePublicAppendResultV1,
  encodePublicChunkReadV1,
  encodePublicStoreCheckpointReadV1,
  encodeStoreWitnessRecordsV1,
} from "../storeWire";
import { StoreRequestError } from "./storeCore";

import type { PrototypeStoreCore } from "./storeCore";

export interface StoreHttpOptions {
  readonly core: PrototypeStoreCore;
  /**
   * Harness only. When set, every POST body the store parses is appended as
   * one hex line, so the E2E can assert the store never received a
   * room-derived value. Never set this on a store anyone relies on.
   */
  readonly logBodiesPath?: string;
}

/**
 * Re-exported from `../storeRoutes`, where the browser-side client can import
 * them without pulling this file's `node:fs` dependency in with them.
 */
export { PROTOTYPE_STORE_MEDIA_TYPES, PROTOTYPE_STORE_ROUTES };

/**
 * The largest body any prototype request has, plus headroom. The biggest is an
 * append of the largest size class (73 728 payload bytes plus the envelope and
 * admission), so a megabyte is generous; the cap exists so a request cannot be
 * turned into a memory bill.
 */
export const PROTOTYPE_STORE_MAX_REQUEST_BODY_BYTES = 1024 * 1024 + 4096;

const ROUTE_PREFIX = `${PROTOTYPE_ROUTE_PREFIX}/`;

const NO_STORE = "no-store";
/** A finalized chunk or checkpoint can never be re-signed, so it never
 * changes; anything else is a statement about now. */
const IMMUTABLE = "public, max-age=31536000, immutable";

const PLAIN_TEXT = "text/plain; charset=utf-8";
const JSON_MEDIA_TYPE = "application/json; charset=utf-8";

/** No leading `+`/`-`, no leading zeros: one spelling per coordinate. */
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const LOWERCASE_HEX_32 = /^[0-9a-f]{64}$/;
const MAX_U64 = (1n << 64n) - 1n;

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return false;
  return true;
};

const parseProfileHash = (value: string): Uint8Array | null => {
  if (!LOWERCASE_HEX_32.test(value)) return null;
  const output = new Uint8Array(32);
  for (let index = 0; index < 32; index++)
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return output;
};

const parseU64 = (value: string): bigint | null => {
  if (!DECIMAL.test(value)) return null;
  const parsed = BigInt(value);
  return parsed > MAX_U64 ? null : parsed;
};

const parseU8 = (value: string): number | null => {
  if (!DECIMAL.test(value)) return null;
  const parsed = Number(value);
  return parsed > 0xff ? null : parsed;
};

/**
 * `lib.dom`'s `BufferSource` is `ArrayBufferView<ArrayBuffer>`, while the
 * canonical codecs are typed with the wider `Uint8Array<ArrayBufferLike>`. The
 * `instanceof` is a real narrowing rather than a cast — it also excludes a
 * `SharedArrayBuffer`, which must never become a response body, since another
 * thread could rewrite a signed chunk after the signature was attached. The
 * copy is the fallback for a view that does not own its whole buffer.
 */
const responseBody = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = bytes.buffer;
  if (
    buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === buffer.byteLength
  )
    return buffer;
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
};

const headersFor = (
  mediaType: string | null,
  cacheControl: string,
): Record<string, string> => ({
  // Every answer, on every route and every status, is attributable to this
  // protocol: an operator debugging a proxy must never have to guess whether
  // a 404 came from the store or from something in front of it.
  "x-p2party-store": PROTOTYPE_STORE_PROTOCOL,
  "cache-control": cacheControl,
  ...(mediaType === null ? {} : { "content-type": mediaType }),
});

const canonicalResponse = (
  body: Uint8Array,
  mediaType: string,
  cacheControl: string,
): Response =>
  new Response(responseBody(body), {
    status: 200,
    headers: headersFor(mediaType, cacheControl),
  });

const textResponse = (status: number, body: string): Response =>
  new Response(body, { status, headers: headersFor(PLAIN_TEXT, NO_STORE) });

const malformed = (): Response => textResponse(400, "malformed");
const notFound = (): Response => textResponse(404, "not found");
const internalError = (): Response => textResponse(500, "error");

const mediaTypeMatches = (request: Request, expected: string): boolean => {
  const header = request.headers.get("content-type");
  if (header === null) return false;
  // Parameters are not part of the type, but the type itself must be exactly
  // this one — not a prefix, not another case, not a near neighbour.
  return header.split(";")[0].trim().toLowerCase() === expected;
};

/**
 * Read at most one request's worth of body.
 *
 * `content-length` is checked before anything is buffered so an oversized
 * declared body costs nothing; the length is checked again afterwards because
 * a chunked request declares nothing. `storeServer.ts` also caps the socket at
 * the same number, so the second check is the belt to that server-level brace.
 */
const readCappedBody = async (request: Request): Promise<Uint8Array | null> => {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    if (!DECIMAL.test(declared)) return null;
    if (Number(declared) > PROTOTYPE_STORE_MAX_REQUEST_BODY_BYTES) return null;
  }
  const body = new Uint8Array(await request.arrayBuffer());
  return body.length > PROTOTYPE_STORE_MAX_REQUEST_BODY_BYTES ? null : body;
};

const POST_MEDIA_TYPES = new Map<string, string>([
  ["allocation-token", PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest],
  ["allocation", PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest],
  ["append", PROTOTYPE_STORE_MEDIA_TYPES.appendRequest],
  ["witness", PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord],
]);

export const createPrototypeStoreHandler = (
  options: StoreHttpOptions,
): ((request: Request) => Promise<Response>) => {
  const { core, logBodiesPath } = options;

  const health = (): Response =>
    new Response(
      JSON.stringify({
        status: "ok",
        role: "store-prototype",
        protocol: PROTOTYPE_STORE_PROTOCOL,
        storeId: hexOf(core.storeId),
        window: String(core.currentWindow()),
      }),
      { status: 200, headers: headersFor(JSON_MEDIA_TYPE, NO_STORE) },
    );

  const descriptor = (): Response =>
    canonicalResponse(
      encodePrototypeStoreDescriptorDocumentV1(core.descriptorDocument()),
      PROTOTYPE_STORE_MEDIA_TYPES.descriptor,
      // The descriptor is re-signed at every start, so a cached copy would
      // pin a client to an identity this process no longer answers under.
      NO_STORE,
    );

  const get = async (kind: string, rest: string[]): Promise<Response> => {
    if (kind === "checkpoint") {
      if (rest.length !== 2) return notFound();
      const profileHash = parseProfileHash(rest[0]);
      const window = parseU64(rest[1]);
      if (profileHash === null || window === null) return malformed();
      const read = await core.readCheckpoint(profileHash, window);
      return canonicalResponse(
        encodePublicStoreCheckpointReadV1(read),
        PROTOTYPE_STORE_MEDIA_TYPES.checkpoint,
        read.kind === "finalized" ? IMMUTABLE : NO_STORE,
      );
    }

    if (kind === "chunk") {
      if (rest.length !== 4) return notFound();
      const profileHash = parseProfileHash(rest[0]);
      const ingressWindow = parseU64(rest[1]);
      const sizeClass = parseU8(rest[2]);
      const chunkIndex = parseU64(rest[3]);
      if (
        profileHash === null ||
        ingressWindow === null ||
        sizeClass === null ||
        chunkIndex === null
      )
        return malformed();
      const read = await core.readChunk(
        { deliveryProfileHash: profileHash, ingressWindow, sizeClass },
        chunkIndex,
      );
      return canonicalResponse(
        encodePublicChunkReadV1(read),
        PROTOTYPE_STORE_MEDIA_TYPES.chunk,
        read.kind === "finalized" ? IMMUTABLE : NO_STORE,
      );
    }

    if (kind === "witness") {
      if (rest.length !== 2) return notFound();
      const profileHash = parseProfileHash(rest[0]);
      const window = parseU64(rest[1]);
      if (profileHash === null || window === null) return malformed();
      // The core keys the witness log by window alone, so scoping to the
      // profile the caller named happens here; a witness log is peer-supplied
      // and must not let one profile's observations answer another's read.
      const records = (await core.witnessRecords(window)).filter((record) =>
        bytesEqual(record.deliveryProfileHash, profileHash),
      );
      return canonicalResponse(
        encodeStoreWitnessRecordsV1(records),
        PROTOTYPE_STORE_MEDIA_TYPES.witness,
        NO_STORE,
      );
    }

    return notFound();
  };

  const post = async (
    request: Request,
    kind: string,
    rest: string[],
  ): Promise<Response> => {
    const expected = POST_MEDIA_TYPES.get(kind);
    if (expected === undefined || rest.length !== 0) return notFound();
    if (!mediaTypeMatches(request, expected)) return malformed();
    const body = await readCappedBody(request);
    if (body === null) return malformed();
    // Before parsing, so the audit sees exactly the bytes that arrived rather
    // than a re-encoding of what the store made of them.
    if (logBodiesPath !== undefined)
      appendFileSync(logBodiesPath, `${hexOf(body)}\n`);

    switch (kind) {
      case "allocation-token":
        return canonicalResponse(
          encodeAllocationTokenIssueResultV1(
            await core.issueToken(decodeAllocationTokenIssueRequestV1(body)),
          ),
          PROTOTYPE_STORE_MEDIA_TYPES.tokenResult,
          NO_STORE,
        );
      case "allocation":
        return canonicalResponse(
          encodePublicAllocationResultV1(
            await core.allocate(decodePublicAllocationRequestV1(body)),
          ),
          PROTOTYPE_STORE_MEDIA_TYPES.allocationResult,
          NO_STORE,
        );
      case "append":
        return canonicalResponse(
          encodePublicAppendResultV1(
            await core.append(decodePublicAppendRequestV1(body)),
          ),
          PROTOTYPE_STORE_MEDIA_TYPES.appendResult,
          NO_STORE,
        );
      case "witness":
        await core.addWitness(decodeStoreWitnessRecordV1(body));
        // A witness offer is an observation, not a query: there is nothing to
        // say back that the offering store does not already know.
        return new Response(null, {
          status: 200,
          headers: headersFor(null, NO_STORE),
        });
      default:
        return notFound();
    }
  };

  return async (request: Request): Promise<Response> => {
    const method = request.method;
    const path = new URL(request.url).pathname;
    try {
      if (method === "GET") {
        if (path === PROTOTYPE_STORE_ROUTES.health) return health();
        if (path === PROTOTYPE_STORE_ROUTES.descriptor) return descriptor();
      }
      if (!path.startsWith(ROUTE_PREFIX)) return notFound();
      const segments = path.slice(ROUTE_PREFIX.length).split("/");
      const kind = segments[0];
      const rest = segments.slice(1);
      if (method === "GET") return await get(kind, rest);
      if (method === "POST") return await post(request, kind, rest);
      // A method this family does not define is not a hint about the ones it
      // does; it is simply not a route.
      return notFound();
    } catch (error) {
      if (
        error instanceof StoreRequestError ||
        error instanceof CanonicalSchemaError
      )
        return malformed();
      // Deliberately not the message: an internal failure can quote the bytes
      // it was handling, and those bytes are exactly what must never be
      // logged. The name and the route class are enough to find the bug.
      console.error(
        `p2party store: ${
          error instanceof Error ? error.name : "unknown error"
        } while handling ${method} ${path.startsWith(ROUTE_PREFIX) ? path.slice(ROUTE_PREFIX.length).split("/")[0] : "(off-family)"}`,
      );
      return internalError();
    }
  };
};
