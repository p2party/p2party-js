import memory from "./memory";
import { wasmLoader } from "./wasmLoader";

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

/**
 * Async, optional-module wrapper over `x25519Keypair`, mirroring `ed25519.newKeyPair`:
 * self-loads a LibCrypto module (sizing its own fixed 2 MiB heap) when none is passed,
 * so identity-generation call sites can mint the dedicated X25519 identity keypair the
 * same way they call `newKeyPair()`. The keypair is random (`_x25519_keypair` draws its
 * own entropy); `x25519Keypair` copies the secret out and zero-frees the wasm scratch.
 */
export const newX25519KeyPair = async (
  module?: LibCrypto,
): Promise<X25519KeyPair> => {
  const wasmMemory = module?.wasmMemory ?? memory.identityX25519KeypairMemory();
  const cryptoModule = module ?? (await wasmLoader(wasmMemory));

  return x25519Keypair(cryptoModule);
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
