import { crypto_auth_hmacsha512_BYTES } from "./interfaces";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

// HKDF-Extract: PRK = HMAC-SHA512(key = salt, msg = ikm) -> 64 bytes.
// Salt can itself be secret in a robust hybrid combiner, and IKM is secret by
// definition, so every staged input and output is zeroFree'd, not merely freed.
export const hkdfExtract = (
  salt: Uint8Array,
  ikm: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const saltAllocLen = Math.max(salt.length, 1);
  const ikmAllocLen = Math.max(ikm.length, 1);
  const prkPtr = module._malloc(crypto_auth_hmacsha512_BYTES);
  const saltPtr = module._malloc(saltAllocLen);
  const ikmPtr = module._malloc(ikmAllocLen);

  try {
    new Uint8Array(module.wasmMemory.buffer, saltPtr, salt.length).set(salt);
    new Uint8Array(module.wasmMemory.buffer, ikmPtr, ikm.length).set(ikm);

    const r = module._hkdf_sha512_extract(
      prkPtr,
      saltPtr,
      salt.length,
      ikmPtr,
      ikm.length,
    );
    if (r !== 0) throw new Error("hkdf_sha512_extract failed");
    return Uint8Array.from(
      new Uint8Array(
        module.wasmMemory.buffer,
        prkPtr,
        crypto_auth_hmacsha512_BYTES,
      ),
    );
  } finally {
    zeroFree(
      module,
      new Uint8Array(
        module.wasmMemory.buffer,
        prkPtr,
        crypto_auth_hmacsha512_BYTES,
      ),
    );
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, saltPtr, saltAllocLen),
    );
    zeroFree(
      module,
      new Uint8Array(module.wasmMemory.buffer, ikmPtr, ikmAllocLen),
    );
  }
};

// HKDF-Expand: OKM = T(1) | T(2) | ... truncated to outLen.
// Both the PRK (input) and the derived OKM (output) are secrets and are
// zeroFree'd; info/scratch buffers are not secret and are plain-freed.
export const hkdfExpand = (
  prk: Uint8Array,
  info: Uint8Array,
  outLen: number,
  module: LibCrypto,
): Uint8Array => {
  const outPtr = module._malloc(outLen);
  const prkPtr = module._malloc(crypto_auth_hmacsha512_BYTES);
  const infoPtr = module._malloc(Math.max(info.length, 1));

  try {
    new Uint8Array(
      module.wasmMemory.buffer,
      prkPtr,
      crypto_auth_hmacsha512_BYTES,
    ).set(prk);
    new Uint8Array(module.wasmMemory.buffer, infoPtr, info.length).set(info);

    const r = module._hkdf_sha512_expand(
      outPtr,
      outLen,
      prkPtr,
      infoPtr,
      info.length,
    );
    if (r !== 0) throw new Error("hkdf_sha512_expand failed");
    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outPtr, outLen),
    );
  } finally {
    zeroFree(module, new Uint8Array(module.wasmMemory.buffer, outPtr, outLen));
    zeroFree(
      module,
      new Uint8Array(
        module.wasmMemory.buffer,
        prkPtr,
        crypto_auth_hmacsha512_BYTES,
      ),
    );
    module._free(infoPtr);
  }
};
