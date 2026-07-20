/**
 * Whether a sender-declared real-data range is safe to slice out of a decrypted
 * chunk and store. The indices come from attacker-controllable metadata, so they
 * must be validated before use: `chunk.slice()` is memory-safe but out-of-range
 * or inverted indices would silently store the wrong bytes and corrupt reassembly
 * (savedSize accounting). Decoy chunks are detected separately (their
 * end - start exceeds totalSize) and never reach this check.
 */
export const isStorableChunkRange = (
  chunkStartIndex: number,
  chunkEndIndex: number,
  chunkLength: number,
): boolean =>
  Number.isSafeInteger(chunkStartIndex) &&
  Number.isSafeInteger(chunkEndIndex) &&
  chunkStartIndex >= 0 &&
  chunkEndIndex >= chunkStartIndex &&
  chunkEndIndex <= chunkLength;
