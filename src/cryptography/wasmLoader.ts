import libcrypto from "./libcrypto";
import { secureRandomUint32 } from "./random";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

const wasmVersion = process.env.P2PARTY_VERSION ?? "0.15.1";
const defaultWasmUrl = new URL(
  `https://cdn.p2party.com/@${wasmVersion}/libcrypto.wasm`,
);
let wasmUrl = defaultWasmUrl;
let wasmLoadStarted = false;
let wasmSourcePinned = false;

/**
 * The pinned digest of this release's exact WASM, and the single place it is
 * written: scripts/updateWasmIntegrity.mjs rewrites this `integrity:` property
 * after every rebuild. Both load paths below check against it, so keep it in
 * one object rather than duplicating the literal.
 */
const cdnRequest = {
  integrity:
    "sha384-vDjnb66aoxATbFGr+3bH1k6zuofJfgPMrEBXnVIPO9iRUIVoIoeyGpT7ZrXtaHis",
};

/** `sha384-<base64>` of `bytes`, by this runtime's WebCrypto. */
const sha384Integrity = async (bytes: BufferSource): Promise<string> => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-384", bytes));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return `sha384-${btoa(binary)}`;
};

/** True iff `bytes` are this release's WASM: their SHA-384 is the pinned one. */
const isPinnedWasm = async (bytes: BufferSource): Promise<boolean> =>
  (await sha384Integrity(bytes)) === cdnRequest.integrity;

// Never a WASM source, even on a page served under the same scheme: these
// name inline or locally fabricated bytes, or a local file, not a server.
const REFUSED_WASM_SOURCE_SCHEMES: ReadonlySet<string> = new Set([
  "data:",
  "blob:",
  "javascript:",
  "file:",
]);

/**
 * Scheme and host of the document running the loader (in a worker, of the
 * worker's script URL). Node and Bun have none. The URL standard gives a
 * non-special scheme such as capacitor: an opaque `origin`, so the pair is
 * compared rather than `origin`.
 */
const runningOrigin = (): { protocol: string; host: string } | null => {
  const location = (
    globalThis as { location?: { protocol?: unknown; host?: unknown } }
  ).location;
  if (
    typeof location?.protocol !== "string" ||
    typeof location.host !== "string" ||
    location.host === ""
  )
    return null;
  return { protocol: location.protocol, host: location.host };
};

// A loopback name or address, as the URL parser canonicalizes it: localhost,
// 127.0.0.0/8 in dotted decimal, or [::1].
const isLoopbackHostname = (hostname: string): boolean =>
  hostname === "localhost" ||
  hostname === "[::1]" ||
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);

/**
 * https: from any host; any scheme on the running page's own origin (the
 * Capacitor iOS shell serves its page from capacitor://localhost); plain
 * http: otherwise only from a loopback host, so local stacks and tests work
 * where there is no page origin. The scheme does not protect integrity:
 * every source is fetched and its SHA-384 checked against the pinned digest.
 * Plain http: elsewhere is refused because the fetch itself would be readable
 * on the network, and an https: page cannot load it anyway.
 */
const isAcceptedWasmSource = (candidate: URL): boolean => {
  if (REFUSED_WASM_SOURCE_SCHEMES.has(candidate.protocol)) return false;
  if (candidate.protocol === "https:") return true;
  const own = runningOrigin();
  if (
    own !== null &&
    candidate.protocol === own.protocol &&
    candidate.host === own.host
  )
    return true;
  return (
    candidate.protocol === "http:" && isLoopbackHostname(candidate.hostname)
  );
};

/**
 * Point the browser root at a self-hosted copy of this release's exact WASM:
 * an https: URL, a URL on the page's own origin whatever its scheme, or a
 * plain http: URL on a loopback host. data:, blob:, javascript: and file:
 * URLs are refused. The build-pinned SHA-384 is still enforced. Configure
 * once, before connect() or any other operation first loads cryptography.
 */
export const setWasmSourceUrl = (source: string | URL): void => {
  if (wasmLoadStarted)
    throw new Error("WASM source cannot change after cryptography has loaded");
  const candidate =
    source instanceof URL ? new URL(source.href) : new URL(source);
  if (!isAcceptedWasmSource(candidate))
    throw new TypeError(
      "WASM source must be https:, the page's own origin, or http: on a loopback host",
    );
  wasmUrl = candidate;
  wasmSourcePinned = true;
};

/**
 * Compiled out of the browser bundle. rollup replaces this with the literal
 * "false" for the browser root, so terser folds the branch and drops
 * readLocalWasm — see the note in rollup.config.ts. Undefined when running the
 * TypeScript sources directly (Bun, Vitest, a checkout), where local loading is
 * exactly what is wanted.
 */
const localWasmEnabled = process.env.P2PARTY_LOCAL_WASM !== "false";

const isNodeLike = (): boolean =>
  typeof process !== "undefined" && Boolean(process.versions?.node);

/**
 * Read this release's WASM from the installed package instead of the network.
 *
 * Node, Bun and offline deployments already have these bytes on disk next to
 * the bundle; fetching them from a CDN would make a cryptography library need
 * the network to start, leak usage to the CDN, and fail in an air-gapped or
 * offline build. The browser has no filesystem and keeps using fetch + SRI.
 *
 * A file read has no `fetch` integrity option, so this hashes the bytes
 * against the same pinned SHA-384. A local copy is a convenience, never a
 * reason to accept unverified cryptography: a mismatch returns null and the
 * caller falls back to the integrity-checked CDN.
 *
 * Keeping node: builtins out of browser bundles is the build flag above, not
 * the indirection below: terser constant-folds an indirect specifier straight
 * back into `import("node:fs/promises")`. The variable and ignore comments
 * only help consumers who bundle these sources unminified.
 */
const readLocalWasm = async (): Promise<ArrayBuffer | null> => {
  const fsSpecifier = "node:fs/promises";
  try {
    const { readFile } = await (import(
      /* @vite-ignore */ /* webpackIgnore: true */ fsSpecifier
    ) as Promise<typeof import("node:fs/promises")>);
    const bytes = await readFile(new URL("./libcrypto.wasm", import.meta.url));
    if (!(await isPinnedWasm(bytes))) return null;
    return bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
  } catch {
    return null;
  }
};

/**
 * Fetch the WASM and check its SHA-384 here, before instantiation, on every
 * runtime. The `integrity` option is passed too, but it is not the check:
 * browsers enforce it, Bun ignores it.
 */
const fetchWasm = async (): Promise<ArrayBuffer> => {
  const resp = await fetch(wasmUrl, cdnRequest);
  if (!resp.ok)
    throw new Error(
      `Unable to load p2party ${wasmVersion} WASM: HTTP ${String(resp.status)}`,
    );
  const bytes = await resp.arrayBuffer();
  if (!(await isPinnedWasm(bytes)))
    throw new Error(
      `p2party ${wasmVersion} WASM from ${wasmUrl.href} failed its SHA-384 integrity check`,
    );
  return bytes;
};

export const wasmLoader = async (wasmMemory: WebAssembly.Memory) => {
  wasmLoadStarted = true;
  // An explicit setWasmSourceUrl() is an instruction, not a hint: honour it
  // even on Node rather than silently preferring the packaged copy.
  const bytes =
    (localWasmEnabled && !wasmSourcePinned && isNodeLike()
      ? await readLocalWasm()
      : null) ?? (await fetchWasm());

  return await libcrypto({
    wasmBinary: bytes,
    wasmMemory,
    getRandomValue: secureRandomUint32,
  });
};
