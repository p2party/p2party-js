import libcrypto from "./libcrypto";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

const wasmVersion = process.env.P2PARTY_VERSION ?? "0.10.0";

export const wasmLoader = async (wasmMemory: WebAssembly.Memory) => {
  const url = new URL(`https://cdn.p2party.com/@${wasmVersion}/libcrypto.wasm`);
  const resp = await fetch(url, {
    integrity:
      "sha384-3pPvDIa/rnUpDq7QgRsNMP+mAF7FE2LPqdKL4x2Wg3fGLRcEuvDru6P7r9zM1GoL",
  });
  const bytes = await resp.arrayBuffer();

  return await libcrypto({
    wasmBinary: bytes,
    wasmMemory,
  });
};
