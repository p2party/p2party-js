import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_box_x25519_NONCEBYTES,
  crypto_box_x25519_PUBLICKEYBYTES,
  crypto_box_x25519_SECRETKEYBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  getEncryptedLen,
  getDecryptedLen,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
} from "./interfaces";

/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
const memoryLenToPages = (
  memoryLen: number,
  minPages?: number,
  maxPages?: number,
): number => {
  minPages = minPages ?? 8; // 512kb // 48 = 3mb // 256 = 16mb // 6 = 384kb
  maxPages = maxPages ?? 32768; // 2gb // 16384 = 1gb
  const pageSize = 64 * 1024;
  const ceil = Math.ceil(memoryLen / pageSize);
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

const encryptAsymmetricMemory = (
  messageLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const sealedBoxLen = getEncryptedLen(messageLen);
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_PUBLICKEYBYTES +
      additionalDataLen +
      sealedBoxLen +
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES +
      1 * (messageLen + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
      2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
      2 * crypto_box_x25519_SECRETKEYBYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const decryptAsymmetricMemory = (
  encryptedLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const decryptedLen = getDecryptedLen(encryptedLen);
  const memoryLen =
    (encryptedLen +
      crypto_sign_ed25519_SECRETKEYBYTES +
      additionalDataLen +
      decryptedLen +
      2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES + // malloc'd
      crypto_box_x25519_SECRETKEYBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

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
  const memoryLen = proofLen + 5 * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

export default {
  newKeyPairMemory,
  keyPairFromSeedMemory,
  keyPairFromSecretKeyMemory,
  signMemory,
  verifyMemory,
  encryptAsymmetricMemory,
  decryptAsymmetricMemory,
  getMerkleRootMemory,
  getMerkleProofMemory,
  verifyMerkleProofMemory,
};
