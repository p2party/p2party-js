import { crypto_auth_hmacsha512_BYTES } from "./interfaces";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

// HKDF-Extract: PRK = HMAC-SHA512(key = salt, msg = ikm) -> 64 bytes.
// PRK is a secret (an intermediate key); it is zeroFree'd, not merely freed.
export const hkdfExtract = (
  salt: Uint8Array,
  ikm: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const prkPtr = module._malloc(crypto_auth_hmacsha512_BYTES);
  const saltPtr = module._malloc(Math.max(salt.length, 1));
  const ikmPtr = module._malloc(Math.max(ikm.length, 1));

  new Uint8Array(module.wasmMemory.buffer, saltPtr, salt.length).set(salt);
  new Uint8Array(module.wasmMemory.buffer, ikmPtr, ikm.length).set(ikm);

  const r = module._hkdf_sha512_extract(
    prkPtr,
    saltPtr,
    salt.length,
    ikmPtr,
    ikm.length,
  );

  const prk =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            prkPtr,
            crypto_auth_hmacsha512_BYTES,
          ),
        )
      : null;

  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      prkPtr,
      crypto_auth_hmacsha512_BYTES,
    ),
  );
  module._free(saltPtr);
  module._free(ikmPtr);

  if (!prk) throw new Error("hkdf_sha512_extract failed");
  return prk;
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

  const out =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(module.wasmMemory.buffer, outPtr, outLen),
        )
      : null;

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

  if (!out) throw new Error("hkdf_sha512_expand failed");
  return out;
};
