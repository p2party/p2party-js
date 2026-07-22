import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
  crypto_core_ristretto255_BYTES,
  crypto_core_ristretto255_HASHBYTES,
  crypto_core_ristretto255_SCALARBYTES,
} from "./interfaces";
import { CPACE_DOMAIN } from "../utils/constants";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

const CPACE_DOMAIN_BYTES = new TextEncoder().encode(CPACE_DOMAIN);

// SHA-512 over the ordered concatenation of the parts, streamed through the wasm
// incremental hash. Returns the 64-byte digest as an owned copy.
const sha512Concat = (module: LibCrypto, parts: Uint8Array[]): Uint8Array => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  try {
    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");

    for (const part of parts) {
      if (part.length === 0) continue;
      const p = module._malloc(part.length);
      new Uint8Array(module.wasmMemory.buffer, p, part.length).set(part);
      const r = module._sha512_update(statePtr, p, part.length);
      module._free(p);
      if (r !== 0) throw new Error("sha512_update failed");
    }

    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("sha512_final failed");

    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outPtr, crypto_hash_sha512_BYTES),
    );
  } finally {
    module._free(statePtr);
    module._free(outPtr);
  }
};

/**
 * G = ristretto255_from_hash( SHA512(CPACE_DOMAIN || PRS || sid || CI) ).
 * Both parties feed identical (PRS, sid, CI) and get the identical generator.
 */
export const deriveGenerator = (
  pin: Uint8Array,
  sid: Uint8Array,
  channelInput: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const h = sha512Concat(module, [CPACE_DOMAIN_BYTES, pin, sid, channelInput]);

  const hPtr = module._malloc(crypto_core_ristretto255_HASHBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  new Uint8Array(
    module.wasmMemory.buffer,
    hPtr,
    crypto_core_ristretto255_HASHBYTES,
  ).set(h);

  module._cpace_ristretto255_from_hash(gPtr, hPtr);

  const G = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      gPtr,
      crypto_core_ristretto255_BYTES,
    ),
  );
  module._free(hPtr);
  module._free(gPtr);
  return G;
};

/** y <- random scalar; Y = y*G. */
export const cpaceStart = (
  G: Uint8Array,
  module: LibCrypto,
): { y: Uint8Array; Y: Uint8Array } => {
  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const YPtr = module._malloc(crypto_core_ristretto255_BYTES);

  module._cpace_ristretto255_scalar_random(yPtr);
  new Uint8Array(
    module.wasmMemory.buffer,
    gPtr,
    crypto_core_ristretto255_BYTES,
  ).set(G);

  const r = module._cpace_ristretto255_scalarmult(YPtr, yPtr, gPtr);

  const y =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            yPtr,
            crypto_core_ristretto255_SCALARBYTES,
          ),
        )
      : null;
  const Y =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            YPtr,
            crypto_core_ristretto255_BYTES,
          ),
        )
      : null;

  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      yPtr,
      crypto_core_ristretto255_SCALARBYTES,
    ),
  );
  module._free(gPtr);
  module._free(YPtr);

  if (!y || !Y) throw new Error("cpace: Y is the identity point");
  return { y, Y };
};

/** K = y * Ypeer (the shared secret point). */
export const cpaceShared = (
  y: Uint8Array,
  Ypeer: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const YpeerPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const KPtr = module._malloc(crypto_core_ristretto255_BYTES);

  new Uint8Array(
    module.wasmMemory.buffer,
    yPtr,
    crypto_core_ristretto255_SCALARBYTES,
  ).set(y);
  new Uint8Array(
    module.wasmMemory.buffer,
    YpeerPtr,
    crypto_core_ristretto255_BYTES,
  ).set(Ypeer);

  const r = module._cpace_ristretto255_scalarmult(KPtr, yPtr, YpeerPtr);

  const K =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            KPtr,
            crypto_core_ristretto255_BYTES,
          ),
        )
      : null;

  // Both y (the caller's private scalar) and the K buffer hold secret material:
  // K is the CPace shared secret that seeds the Stage-4 ratchet root, so its
  // WASM-heap copy must be wiped, not merely freed. Ypeer is public scratch.
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      yPtr,
      crypto_core_ristretto255_SCALARBYTES,
    ),
  );
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      KPtr,
      crypto_core_ristretto255_BYTES,
    ),
  );
  module._free(YpeerPtr);

  if (!K) throw new Error("cpace: shared point is the identity");
  return K;
};
