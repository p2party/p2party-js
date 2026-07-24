import libcrypto from "./libcrypto";
import { secureRandomUint32 } from "./random";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

const wasmVersion = process.env.P2PARTY_VERSION ?? "0.12.0";
const defaultWasmUrl = new URL(
  `https://cdn.p2party.com/@${wasmVersion}/libcrypto.wasm`,
);
let wasmUrl = defaultWasmUrl;
let wasmLoadStarted = false;

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
};

export const wasmLoader = async (wasmMemory: WebAssembly.Memory) => {
  wasmLoadStarted = true;
  const resp = await fetch(wasmUrl, {
    integrity:
      "sha384-gHNbEQ3KIbsYpXGbpz6O62xI1CjZDVeD8FnYA//PWGAHxKDuN2pMVpQvDopV6Qcg",
  });
  if (!resp.ok)
    throw new Error(
      `Unable to load p2party ${wasmVersion} WASM: HTTP ${String(resp.status)}`,
    );
  const bytes = await resp.arrayBuffer();

  return await libcrypto({
    wasmBinary: bytes,
    wasmMemory,
    getRandomValue: secureRandomUint32,
  });
};
