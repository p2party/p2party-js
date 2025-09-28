import libcrypto from "./libcrypto";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

export const wasmLoader = async (wasmMemory: WebAssembly.Memory) => {
  const url = new URL("https://cdn.p2party.com/@0.7.11/libcrypto.wasm");
  const resp = await fetch(url, {
    integrity:
      "sha384-iCNxnyD3ho2bH3H868svpjRIZTRA66sPJDwbi4loPTBIAsYlghPXQFThc96d5jIC",
  });
  const bytes = await resp.arrayBuffer();

  return await libcrypto({
    wasmBinary: bytes,
    wasmMemory,
  });
};
