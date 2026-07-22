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

// A transcript field for sha512Concat. `secret` marks fields that carry key
// material (the PRS/PIN) so their wasm-heap staging buffer is wiped with
// zeroFree instead of plain _free.
type TranscriptPart = { data: Uint8Array; secret?: boolean };

// SHA-512 over the lv_cat (length-value concatenation) of the parts, streamed
// through the wasm incremental hash.
//
// Per IRTF draft-irtf-cfrg-cpace, every field fed into the generator hash MUST
// be length-prefixed (lv_cat) rather than bare-concatenated: each part is
// preceded by its own byte length, encoded here as a fixed-width 8-byte
// little-endian integer, before its bytes are hashed. This makes the map
// (DOMAIN, PRS, sid, CI) -> digest injective in the field boundaries, not just
// in the concatenated byte string — without it, two different splits (e.g.
// PRS="ab" || CI="cd" vs. PRS="a" || CI="bcd") could hash to the same
// generator once CI carries variable-length data, which would amplify online
// PIN-guessing power.
//
// Returns the 64-byte digest as an owned copy.
const sha512Concat = (
  module: LibCrypto,
  parts: TranscriptPart[],
): Uint8Array => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  try {
    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");

    for (const { data, secret } of parts) {
      // len8: fixed-width 8-byte little-endian length prefix (the "L" in lv_cat).
      const lenBuf = new Uint8Array(8);
      new DataView(lenBuf.buffer).setBigUint64(0, BigInt(data.length), true);

      const lenPtr = module._malloc(8);
      new Uint8Array(module.wasmMemory.buffer, lenPtr, 8).set(lenBuf);
      let r = module._sha512_update(statePtr, lenPtr, 8);
      module._free(lenPtr);
      if (r !== 0) throw new Error("sha512_update failed");

      if (data.length === 0) continue;

      const p = module._malloc(data.length);
      const view = new Uint8Array(module.wasmMemory.buffer, p, data.length);
      view.set(data);
      r = module._sha512_update(statePtr, p, data.length);
      // The PRS/PIN is the crown-jewel PAKE secret: wipe its wasm-heap staging
      // buffer before free rather than leaving it to linger. Non-secret fields
      // (DOMAIN, sid, CI) are public and may be freed directly.
      if (secret) {
        zeroFree(module, view);
      } else {
        module._free(p);
      }
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
 * G = ristretto255_from_hash( SHA512(lv_cat(CPACE_DOMAIN, PRS, sid, CI)) ).
 * Both parties feed identical (PRS, sid, CI) and get the identical generator.
 * lv_cat length-prefixes each field (see sha512Concat) so the transcript
 * encoding is injective in the field boundaries per IRTF draft-irtf-cfrg-cpace.
 */
export const deriveGenerator = (
  pin: Uint8Array,
  sid: Uint8Array,
  channelInput: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const h = sha512Concat(module, [
    { data: CPACE_DOMAIN_BYTES },
    { data: pin, secret: true },
    { data: sid },
    { data: channelInput },
  ]);

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
