// Merkle leaf domain byte (0x00). Internal nodes use 0x01 (in merkle.c), so an
// internal-node hash can never be reinterpreted as a leaf (CVE-2012-2459 class).
// This leaf value is also the read-receipt token (realChunkHash), so the sender
// (splitToChunks), the receiver's proof leaf (utils.c receive_message), and the
// receiver's receipt hash (handleReceiveMessage) must all compute it the same.
export const MERKLE_LEAF_DOMAIN = 0x00;

export const hashMerkleLeaf = async (
  chunk: Uint8Array,
): Promise<Uint8Array> => {
  const buf = new Uint8Array(1 + chunk.length);
  buf[0] = MERKLE_LEAF_DOMAIN;
  buf.set(chunk, 1);
  const digest = await window.crypto.subtle.digest(
    "SHA-512",
    buf as Uint8Array<ArrayBuffer>,
  );

  return new Uint8Array(digest);
};
