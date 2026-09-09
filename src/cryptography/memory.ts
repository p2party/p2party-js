import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_scalarmult_curve25519_BYTES,
  crypto_scalarmult_curve25519_SCALARBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
} from "./interfaces";

/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
const WASM_RUNTIME_OVERHEAD_BYTES = 1024 * 1024;

const memoryLenToPages = (
  memoryLen: number,
  minPages?: number,
  maxPages?: number,
): number => {
  minPages = minPages ?? 32; // 8 = 512kb // 48 = 3mb // 256 = 16mb // 6 = 384kb
  maxPages = maxPages ?? 16384; // 81920 = 5gb; // 32768 = 2gb // 16384 = 1gb
  const pageSize = 64 * 1024;
  // Operation helpers describe their live allocations, not Emscripten's stack,
  // static data, allocator metadata, or short-lived C scratch. Reserve 1 MiB so
  // a correctly operation-sized imported memory does not still OOM at its exact
  // arithmetic boundary.
  const ceil = Math.ceil(
    (memoryLen + WASM_RUNTIME_OVERHEAD_BYTES) / pageSize,
  );
  if (ceil > maxPages)
    throw new Error(
      `Memory required is ${String(ceil * pageSize)} bytes while declared maximum is ${String(
        maxPages * pageSize,
      )} bytes`,
    );

  return ceil < minPages ? minPages : ceil;
};

const newKeyPairMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const identityX25519KeypairMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_scalarmult_curve25519_BYTES +
      crypto_scalarmult_curve25519_SCALARBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const keyPairFromSeedMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES +
      crypto_sign_ed25519_SECRETKEYBYTES +
      crypto_sign_ed25519_SEEDBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const keyPairFromSecretKeyMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const signMemory = (messageLen: number): WebAssembly.Memory => {
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_BYTES +
      crypto_sign_ed25519_SECRETKEYBYTES +
      crypto_hash_sha512_BYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const verifyMemory = (messageLen: number): WebAssembly.Memory => {
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_BYTES +
      crypto_sign_ed25519_PUBLICKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

/**
 * Protocol-v3 crypto runs on a fixed 2 MiB heap. Chunk AEAD allocates and frees
 * only transient plaintext/ciphertext/AAD buffers; handshake and ratchet
 * primitives use the same bounded profile. Fixed growth makes allocator
 * mistakes fail closed.
 */
const protocolV3Memory = (): WebAssembly.Memory => {
  const pages = memoryLenToPages(0);
  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const getMerkleRootMemory = (leavesLen: number): WebAssembly.Memory => {
  const memoryLen = (2 * leavesLen + 3) * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const getMerkleProofMemory = (leavesLen: number): WebAssembly.Memory => {
  const memoryLen =
    leavesLen * crypto_hash_sha512_BYTES +
    leavesLen * (crypto_hash_sha512_BYTES + 1) +
    3 * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const verifyMerkleProofMemory = (proofLen: number): WebAssembly.Memory => {
  const memoryLen =
    proofLen * Uint8Array.BYTES_PER_ELEMENT + 4 * crypto_hash_sha512_BYTES;

  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const argon2Memory = (mnemonicLen: number): WebAssembly.Memory => {
  const memoryLen =
    (75 * 1024 * 1024 +
      mnemonicLen +
      crypto_sign_ed25519_SEEDBYTES +
      crypto_pwhash_argon2id_SALTBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  newKeyPairMemory,
  identityX25519KeypairMemory,
  keyPairFromSeedMemory,
  keyPairFromSecretKeyMemory,
  signMemory,
  verifyMemory,
  protocolV3Memory,
  getMerkleRootMemory,
  getMerkleProofMemory,
  verifyMerkleProofMemory,
  argon2Memory,
};
