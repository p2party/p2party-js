/**
 * The `prototype-v1` route paths and media types: constants, nothing else.
 *
 * These strings are the one contract the store server and the browser-side
 * client must agree on letter for letter, so they live in a file both can
 * import. They were in `store/storeHttp.ts`, which is where the handler that
 * requires them lives — but that file imports `node:fs` for its body-audit
 * sink, and the client is bundled for the browser, where pulling a Node
 * builtin in is not a size problem but a build failure. Splitting the
 * constants out is what lets the client name the same strings instead of
 * repeating the literals and drifting from them.
 *
 * Status: PROTOTYPE. This is the `prototype-v1` route family, not a frozen
 * registry.
 */

import {
  PROTOTYPE_DESCRIPTOR_PATH,
  PROTOTYPE_MEDIA_TYPE,
  PROTOTYPE_ROUTE_PREFIX,
} from "./profile";

export const PROTOTYPE_STORE_ROUTES = {
  descriptor: PROTOTYPE_DESCRIPTOR_PATH,
  token: `${PROTOTYPE_ROUTE_PREFIX}/allocation-token`,
  allocation: `${PROTOTYPE_ROUTE_PREFIX}/allocation`,
  append: `${PROTOTYPE_ROUTE_PREFIX}/append`,
  checkpoint: `${PROTOTYPE_ROUTE_PREFIX}/checkpoint`,
  chunk: `${PROTOTYPE_ROUTE_PREFIX}/chunk`,
  witness: `${PROTOTYPE_ROUTE_PREFIX}/witness`,
  health: "/health",
} as const;

/**
 * One media type per wire type, exported so the client adapter names the same
 * strings this handler requires rather than repeating the literals.
 */
export const PROTOTYPE_STORE_MEDIA_TYPES = {
  descriptor: PROTOTYPE_MEDIA_TYPE("store-descriptor"),
  tokenRequest: PROTOTYPE_MEDIA_TYPE("allocation-token-request"),
  tokenResult: PROTOTYPE_MEDIA_TYPE("allocation-token-result"),
  allocationRequest: PROTOTYPE_MEDIA_TYPE("allocation-request"),
  allocationResult: PROTOTYPE_MEDIA_TYPE("allocation-result"),
  appendRequest: PROTOTYPE_MEDIA_TYPE("append-request"),
  appendResult: PROTOTYPE_MEDIA_TYPE("append-result"),
  checkpoint: PROTOTYPE_MEDIA_TYPE("checkpoint"),
  chunk: PROTOTYPE_MEDIA_TYPE("chunk"),
  witnessRecord: PROTOTYPE_MEDIA_TYPE("witness-record"),
  witness: PROTOTYPE_MEDIA_TYPE("witness"),
} as const;
