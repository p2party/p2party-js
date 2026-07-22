import { readFileSync } from "node:fs";

import libcrypto from "./libcrypto";

import type { LibCrypto } from "./libcrypto";

// The emscripten glue is built ENVIRONMENT=web,worker. Aliasing `window` selects
// its web branch so in-wasm entropy resolves via globalThis.crypto (Bun global),
// matching the alias precedent in cryptography/utils.test.ts.
(globalThis as unknown as { window: typeof globalThis }).window = globalThis;

/**
 * Instantiate the locally-built libcrypto.wasm for unit tests, bypassing the
 * CDN + SRI fetch in wasmLoader.ts. 32 pages == 2 MiB == INITIAL_MEMORY; growth
 * is off so every op fits the largest-single-op budget.
 */
export const loadTestModule = async (): Promise<LibCrypto> => {
  const fileBytes = readFileSync(new URL("./libcrypto.wasm", import.meta.url));
  // The emscripten factory's wasmBinary is typed ArrayBuffer; readFileSync
  // returns a Buffer, so copy the bytes into a fresh ArrayBuffer (type-correct
  // for `tsc`, and WebAssembly.instantiate accepts an ArrayBuffer at runtime).
  const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
  new Uint8Array(wasmBinary).set(fileBytes);
  const wasmMemory = new WebAssembly.Memory({ initial: 32, maximum: 32 });

  return (await libcrypto({ wasmBinary, wasmMemory })) as LibCrypto;
};
