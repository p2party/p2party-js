import {
  crypto_scalarmult_curve25519_BYTES,
  crypto_scalarmult_curve25519_SCALARBYTES,
} from "./interfaces";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

export interface X25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export const x25519Keypair = (module: LibCrypto): X25519KeyPair => {
  const pkPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);
  const skPtr = module._malloc(crypto_scalarmult_curve25519_SCALARBYTES);

  const r = module._x25519_keypair(pkPtr, skPtr);
  if (r !== 0) {
    module._free(pkPtr);
    zeroFree(
      module,
      new Uint8Array(
        module.wasmMemory.buffer,
        skPtr,
        crypto_scalarmult_curve25519_SCALARBYTES,
      ),
    );
    throw new Error("x25519_keypair failed");
  }

  const publicKey = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      pkPtr,
      crypto_scalarmult_curve25519_BYTES,
    ),
  );
  const secretKey = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );

  module._free(pkPtr);
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );

  return { publicKey, secretKey };
};

export const x25519Dh = (
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const shPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);
  const skPtr = module._malloc(crypto_scalarmult_curve25519_SCALARBYTES);
  const pkPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);

  new Uint8Array(
    module.wasmMemory.buffer,
    skPtr,
    crypto_scalarmult_curve25519_SCALARBYTES,
  ).set(secretKey);
  new Uint8Array(
    module.wasmMemory.buffer,
    pkPtr,
    crypto_scalarmult_curve25519_BYTES,
  ).set(publicKey);

  const r = module._x25519_dh(shPtr, skPtr, pkPtr);

  const shared =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            shPtr,
            crypto_scalarmult_curve25519_BYTES,
          ),
        )
      : null;

  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      shPtr,
      crypto_scalarmult_curve25519_BYTES,
    ),
  );
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );
  module._free(pkPtr);

  if (!shared) throw new Error("x25519_dh failed (identity point)");
  return shared;
};
