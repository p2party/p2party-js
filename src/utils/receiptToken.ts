import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

/**
 * Chunk receipts are deliberately not raw Merkle leaf hashes. Binding the
 * receipt to the message root and leaf position prevents an identical leaf in
 * another transfer from acknowledging the wrong outbound chunk.
 */
export const CHUNK_RECEIPT_DOMAIN = new TextEncoder().encode(
  "p2party/protocol-v3/chunk-receipt/v1\u0000",
);

export const createChunkReceiptToken = async (
  merkleRoot: Uint8Array,
  chunkIndex: number,
  leafHash: Uint8Array,
): Promise<Uint8Array> => {
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error("Chunk receipt Merkle root must be 64 bytes");
  if (leafHash.length !== crypto_hash_sha512_BYTES)
    throw new Error("Chunk receipt leaf hash must be 64 bytes");
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0)
    throw new Error("Chunk receipt index must be a safe unsigned integer");

  const input = new Uint8Array(
    CHUNK_RECEIPT_DOMAIN.length +
      merkleRoot.length +
      8 +
      leafHash.length,
  );
  let offset = 0;
  input.set(CHUNK_RECEIPT_DOMAIN, offset);
  offset += CHUNK_RECEIPT_DOMAIN.length;
  input.set(merkleRoot, offset);
  offset += merkleRoot.length;
  new DataView(input.buffer).setBigUint64(offset, BigInt(chunkIndex), false);
  offset += 8;
  input.set(leafHash, offset);

  return new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-512", input),
  );
};
