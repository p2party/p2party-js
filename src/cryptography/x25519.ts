import memory from "./memory";
import { wasmLoader } from "./wasmLoader";

import { snapshotByteInput } from "./byteInput";
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

/**
 * The peer-supplied u-coordinate produced the prohibited all-zero X25519
 * shared secret (for example, a low-order point).
 *
 * This is distinct from allocation/module failures so protocol receivers can
 * classify attacker-controlled invalid KEM input as a closed no-match without
 * hiding cryptographic infrastructure faults.
 */
export class X25519RejectedPublicPointError extends Error {
  override readonly name = "X25519RejectedPublicPointError";

  constructor() {
    super("x25519_dh failed (identity point)");
  }
}

const RFC7748_X25519_BASE_POINT = (() => {
  const basePoint = new Uint8Array(crypto_scalarmult_curve25519_BYTES);
  basePoint[0] = 9;
  return basePoint;
})();

const checkedMalloc = (
  module: LibCrypto,
  length: number,
  operation: string,
): number => {
  const pointer = module._malloc(length);
  if (pointer === 0) throw new Error(`${operation} failed (allocation)`);
  return pointer;
};

const heapView = (
  module: LibCrypto,
  pointer: number,
  length: number,
): Uint8Array => new Uint8Array(module.wasmMemory.buffer, pointer, length);

export const x25519Keypair = (module: LibCrypto): X25519KeyPair => {
  let pkPtr: number | undefined;
  let skPtr: number | undefined;
  try {
    pkPtr = checkedMalloc(
      module,
      crypto_scalarmult_curve25519_BYTES,
      "x25519_keypair",
    );
    skPtr = checkedMalloc(
      module,
      crypto_scalarmult_curve25519_SCALARBYTES,
      "x25519_keypair",
    );

    if (module._x25519_keypair(pkPtr, skPtr) !== 0)
      throw new Error("x25519_keypair failed");

    return {
      publicKey: Uint8Array.from(
        heapView(module, pkPtr, crypto_scalarmult_curve25519_BYTES),
      ),
      secretKey: Uint8Array.from(
        heapView(module, skPtr, crypto_scalarmult_curve25519_SCALARBYTES),
      ),
    };
  } finally {
    try {
      if (skPtr !== undefined)
        zeroFree(
          module,
          heapView(module, skPtr, crypto_scalarmult_curve25519_SCALARBYTES),
        );
    } finally {
      if (pkPtr !== undefined) module._free(pkPtr);
    }
  }
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
  const privateSecretKey = snapshotByteInput(secretKey, "secretKey", {
    exactLength: crypto_scalarmult_curve25519_SCALARBYTES,
  });

  // Snapshot before `_malloc`: growing this same module's memory can detach
  // caller views that point into its previous ArrayBuffer.
  let shPtr: number | undefined;
  let skPtr: number | undefined;
  let pkPtr: number | undefined;
  try {
    const privatePublicKey = snapshotByteInput(publicKey, "publicKey", {
      exactLength: crypto_scalarmult_curve25519_BYTES,
    });
    shPtr = checkedMalloc(
      module,
      crypto_scalarmult_curve25519_BYTES,
      "x25519_dh",
    );
    skPtr = checkedMalloc(module, privateSecretKey.length, "x25519_dh");
    pkPtr = checkedMalloc(module, privatePublicKey.length, "x25519_dh");

    heapView(module, skPtr, privateSecretKey.length).set(privateSecretKey);
    heapView(module, pkPtr, privatePublicKey.length).set(privatePublicKey);

    if (module._x25519_dh(shPtr, skPtr, pkPtr) !== 0)
      throw new X25519RejectedPublicPointError();
    return Uint8Array.from(
      heapView(module, shPtr, crypto_scalarmult_curve25519_BYTES),
    );
  } finally {
    try {
      try {
        if (shPtr !== undefined)
          zeroFree(
            module,
            heapView(module, shPtr, crypto_scalarmult_curve25519_BYTES),
          );
      } finally {
        try {
          if (skPtr !== undefined)
            zeroFree(module, heapView(module, skPtr, privateSecretKey.length));
        } finally {
          if (pkPtr !== undefined) module._free(pkPtr);
        }
      }
    } finally {
      privateSecretKey.fill(0);
    }
  }
};

/**
 * Derive an X25519 public key by scalar-multiplying the RFC 7748 u=9 base
 * point. The canonical base point stays module-owned so callers cannot mutate
 * protocol input shared by later derivations.
 */
export const x25519PublicFromSecret = (
  secretKey: Uint8Array,
  module: LibCrypto,
): Uint8Array => x25519Dh(secretKey, RFC7748_X25519_BASE_POINT, module);
