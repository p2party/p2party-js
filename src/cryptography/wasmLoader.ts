import libcrypto from "./libcrypto";

if (typeof WebAssembly != "object") {
  throw new Error("no native wasm support detected");
}

const wasmVersion = process.env.P2PARTY_VERSION ?? "0.10.0";

export const wasmLoader = async (wasmMemory: WebAssembly.Memory) => {
  const url = new URL(`https://cdn.p2party.com/@${wasmVersion}/libcrypto.wasm`);
  const resp = await fetch(url, {
    integrity:
      "sha384-N/YT0GhVKVBWk5TRotqM0Hu+fos8xRq+AyFnRmqFQgQMyVm8edPWIZiSIDqqcG87",
  });
  const bytes = await resp.arrayBuffer();

  return await libcrypto({
    wasmBinary: bytes,
    wasmMemory,
  });
};
