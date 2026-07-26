import libcrypto from "./libcrypto";
import { secureRandomUint32 } from "./random";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

const wasmVersion = process.env.P2PARTY_VERSION ?? "0.14.3";
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
    "sha384-pBMyUqQ3KBztxgeJMgDFZeohfj9QlAFNwt4/gRlqT0vlZ2kbkKxv+q5DwbZOBuUP",
};

/**
 * Point the browser root at a self-hosted copy of this release's exact WASM.
 * The build-pinned SRI is still enforced. Configure once, before connect() or
 * any other operation first loads cryptography.
 */
export const setWasmSourceUrl = (source: string | URL): void => {
  if (wasmLoadStarted)
    throw new Error("WASM source cannot change after cryptography has loaded");
  const candidate =
    source instanceof URL ? new URL(source.href) : new URL(source);
  if (candidate.protocol !== "https:" && candidate.protocol !== "http:")
    throw new TypeError("WASM source must use http: or https:");
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
 * `fetch(url, { integrity })` cannot verify a file read, so this hashes the
 * bytes against the same pinned SHA-384. A local copy is a convenience, never
 * a reason to accept unverified cryptography: a mismatch returns null and the
 * caller falls back to the integrity-checked CDN.
 *
 * Keeping node: builtins out of browser bundles is the build flag above, not
 * the indirection below: terser constant-folds an indirect specifier straight
 * back into `import("node:fs/promises")`. The variables and ignore comments
 * only help consumers who bundle these sources unminified.
 */
const readLocalWasm = async (): Promise<ArrayBuffer | null> => {
  const fsSpecifier = "node:fs/promises";
  const cryptoSpecifier = "node:crypto";
  try {
    const [{ readFile }, { createHash }] = await Promise.all([
      import(
        /* @vite-ignore */ /* webpackIgnore: true */ fsSpecifier
      ) as Promise<typeof import("node:fs/promises")>,
      import(
        /* @vite-ignore */ /* webpackIgnore: true */ cryptoSpecifier
      ) as Promise<typeof import("node:crypto")>,
    ]);
    const bytes = await readFile(new URL("./libcrypto.wasm", import.meta.url));
    const digest = `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
    if (digest !== cdnRequest.integrity) return null;
    return bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
  } catch {
    return null;
  }
};

const fetchWasm = async (): Promise<ArrayBuffer> => {
  const resp = await fetch(wasmUrl, cdnRequest);
  if (!resp.ok)
    throw new Error(
      `Unable to load p2party ${wasmVersion} WASM: HTTP ${String(resp.status)}`,
    );
  return await resp.arrayBuffer();
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
