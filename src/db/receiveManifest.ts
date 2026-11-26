import { CHUNK_LEN } from "../utils/constants";

/**
 * A received chunk refused for what it claims (bounds, layout, metadata,
 * ownership, cancellation fence), as opposed to a storage fault. The worker
 * rethrows these unchanged; anything else thrown while storing is reported as
 * a typed storage failure.
 */
export class ReceiveChunkRejectedError extends Error {}

/**
 * Running summary of the distinct chunks held for one received transfer. It is
 * kept on the transfer's messageData row and rewritten in the same transaction
 * as every chunk insert, so a new chunk is validated against it in constant
 * time instead of by re-reading every chunk record already held.
 *
 * Rows written by 0.14.10 have no manifest; it is rebuilt once from the chunk
 * records (`buildReceiveManifest`) and persisted with the next insert.
 */
export interface ReceiveManifest {
  version: 1;
  /** Number of distinct chunk indices held. */
  count: number;
  /**
   * Sum of their real lengths. It must equal the row's savedSize: a row
   * rewritten by code that does not maintain the manifest (0.14.10 drops the
   * field, but a stale copy must never be trusted) is rebuilt instead.
   */
  savedSize: number;
  /** Real bytes in every chunk but the last; 0 while not yet determined. */
  uniformSize: number;
  /** The one chunk held while uniformSize is undetermined. */
  pendingIndex?: number;
  pendingRealLen?: number;
}

export interface ReceiveProgress {
  savedSize: number;
  complete: boolean;
}

export const EMPTY_RECEIVE_MANIFEST: ReceiveManifest = {
  version: 1,
  count: 0,
  savedSize: 0,
  uniformSize: 0,
};

const reject = (message: string): never => {
  throw new ReceiveChunkRejectedError(message);
};

// The canonical layout for a uniform size: every chunk but the last carries
// uniformSize real bytes, the last carries the remainder.
const assertCanonicalChunk = (
  chunkIndex: number,
  realLen: number,
  uniformSize: number,
  totalSize: number,
): void => {
  const expectedCount = Math.ceil(totalSize / uniformSize);
  const finalIndex = expectedCount - 1;
  if (chunkIndex >= expectedCount)
    reject("receive chunk index exceeds canonical manifest");
  const expectedLength =
    chunkIndex === finalIndex
      ? totalSize - uniformSize * finalIndex
      : uniformSize;
  if (realLen !== expectedLength)
    reject("receive chunk length conflicts with manifest");
};

/**
 * Full validation of a set of held chunk records, and the manifest that
 * describes them. This is the layout check 0.14.10 ran on every chunk; it now
 * runs only to rebuild a missing or stale manifest.
 */
export const buildReceiveManifest = (
  records: ReadonlyArray<{ chunkIndex: number; realLen?: number }>,
  totalSize: number,
): ReceiveManifest => {
  const ordered = records
    .map((record) => ({
      chunkIndex: record.chunkIndex,
      realLen: record.realLen ?? 0,
    }))
    .sort((a, b) => a.chunkIndex - b.chunkIndex);
  let savedSize = 0;
  for (let i = 0; i < ordered.length; i++) {
    const record = ordered[i];
    if (
      !Number.isSafeInteger(record.chunkIndex) ||
      record.chunkIndex < 0 ||
      !Number.isSafeInteger(record.realLen) ||
      record.realLen <= 0 ||
      record.realLen > CHUNK_LEN ||
      record.realLen > totalSize ||
      record.chunkIndex >= totalSize ||
      (i > 0 && ordered[i - 1].chunkIndex === record.chunkIndex)
    )
      reject("invalid receive chunk layout");
    savedSize += record.realLen;
    if (!Number.isSafeInteger(savedSize) || savedSize > totalSize)
      reject("receive chunks exceed declared total");
  }

  const zero = ordered.find((record) => record.chunkIndex === 0);
  let uniformSize = 0;
  if (zero) uniformSize = zero.realLen;
  else if (ordered.length >= 2)
    for (const record of ordered)
      uniformSize = Math.max(uniformSize, record.realLen);

  if (uniformSize > 0) {
    for (const record of ordered)
      assertCanonicalChunk(
        record.chunkIndex,
        record.realLen,
        uniformSize,
        totalSize,
      );
    const manifest: ReceiveManifest = {
      version: 1,
      count: ordered.length,
      savedSize,
      uniformSize,
    };
    receiveProgress(manifest, totalSize);
    return manifest;
  }

  // One non-zero out-of-order chunk cannot establish the uniform size. It is
  // valid partial progress, but can never by itself claim completion.
  if (savedSize === totalSize)
    reject("receive completion is missing chunk zero");
  return ordered.length === 0
    ? { ...EMPTY_RECEIVE_MANIFEST }
    : {
        version: 1,
        count: 1,
        savedSize,
        uniformSize: 0,
        pendingIndex: ordered[0].chunkIndex,
        pendingRealLen: ordered[0].realLen,
      };
};

/**
 * The manifest after adding one chunk index not yet held. Throws
 * ReceiveChunkRejectedError exactly when `buildReceiveManifest` over the held
 * records plus this one would; constant time and no record reads.
 *
 * The chunk's own bounds (safe integers, realLen <= CHUNK_LEN and <= totalSize,
 * chunkIndex < totalSize) are the caller's entry check.
 */
export const advanceReceiveManifest = (
  manifest: ReceiveManifest,
  totalSize: number,
  chunkIndex: number,
  realLen: number,
): ReceiveManifest => {
  const savedSize = manifest.savedSize + realLen;
  if (!Number.isSafeInteger(savedSize) || savedSize > totalSize)
    reject("receive chunks exceed declared total");

  if (manifest.uniformSize > 0) {
    // Every held chunk already conforms to this uniform size, so a chunk that
    // conforms too cannot change it, and one that does not is refused.
    assertCanonicalChunk(chunkIndex, realLen, manifest.uniformSize, totalSize);
    const next: ReceiveManifest = {
      version: 1,
      count: manifest.count + 1,
      savedSize,
      uniformSize: manifest.uniformSize,
    };
    receiveProgress(next, totalSize);
    return next;
  }

  if (manifest.count === 0) {
    if (chunkIndex === 0) {
      // Chunk zero fixes the uniform size (and conforms to it by definition).
      const next: ReceiveManifest = {
        version: 1,
        count: 1,
        savedSize,
        uniformSize: realLen,
      };
      receiveProgress(next, totalSize);
      return next;
    }
    if (savedSize === totalSize)
      reject("receive completion is missing chunk zero");
    return {
      version: 1,
      count: 1,
      savedSize,
      uniformSize: 0,
      pendingIndex: chunkIndex,
      pendingRealLen: realLen,
    };
  }

  // Exactly one non-zero chunk is pending. Two chunks fix the uniform size:
  // chunk zero's length if this is it, otherwise the larger of the two (only
  // the last chunk is short). Both must then conform.
  const pendingIndex = manifest.pendingIndex!;
  const pendingRealLen = manifest.pendingRealLen!;
  const uniformSize =
    chunkIndex === 0 ? realLen : Math.max(pendingRealLen, realLen);
  assertCanonicalChunk(pendingIndex, pendingRealLen, uniformSize, totalSize);
  assertCanonicalChunk(chunkIndex, realLen, uniformSize, totalSize);
  const next: ReceiveManifest = {
    version: 1,
    count: 2,
    savedSize,
    uniformSize,
  };
  receiveProgress(next, totalSize);
  return next;
};

/**
 * Distinct-byte progress for a manifest. Every held chunk conforms to the
 * canonical layout, so holding all expected indices and holding totalSize
 * bytes are the same fact; a manifest where they disagree is refused.
 */
export const receiveProgress = (
  manifest: ReceiveManifest,
  totalSize: number,
): ReceiveProgress => {
  const complete =
    manifest.uniformSize > 0 &&
    manifest.count === Math.ceil(totalSize / manifest.uniformSize);
  if ((manifest.savedSize === totalSize) !== complete)
    reject("receive completion has a chunk-index gap");
  return { savedSize: manifest.savedSize, complete };
};

const isCount = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

/**
 * True when `value` is a well-formed manifest that matches the row it was read
 * from. Anything else (absent on a 0.14.10 row, malformed, or out of step with
 * savedSize) is rebuilt from the chunk records rather than trusted.
 */
export const isCurrentReceiveManifest = (
  value: unknown,
  savedSize: number,
  totalSize: number,
): value is ReceiveManifest => {
  if (typeof value !== "object" || value === null) return false;
  const manifest = value as Partial<ReceiveManifest>;
  if (
    manifest.version !== 1 ||
    !isCount(manifest.count) ||
    !isCount(manifest.savedSize) ||
    !isCount(manifest.uniformSize) ||
    manifest.savedSize !== savedSize ||
    manifest.savedSize > totalSize ||
    manifest.uniformSize > CHUNK_LEN ||
    manifest.uniformSize > totalSize
  )
    return false;
  if (manifest.uniformSize > 0) {
    // `count` canonical chunks hold count × uniformSize bytes, or one less
    // full chunk plus the final remainder when the final chunk is among them.
    const expectedCount = Math.ceil(totalSize / manifest.uniformSize);
    const finalLength = totalSize - manifest.uniformSize * (expectedCount - 1);
    return (
      manifest.pendingIndex === undefined &&
      manifest.pendingRealLen === undefined &&
      manifest.count >= 1 &&
      manifest.count <= expectedCount &&
      (manifest.savedSize === manifest.count * manifest.uniformSize ||
        manifest.savedSize ===
          (manifest.count - 1) * manifest.uniformSize + finalLength)
    );
  }
  if (manifest.count === 0)
    return (
      manifest.savedSize === 0 &&
      manifest.pendingIndex === undefined &&
      manifest.pendingRealLen === undefined
    );
  return (
    manifest.count === 1 &&
    isCount(manifest.pendingIndex) &&
    manifest.pendingIndex > 0 &&
    manifest.pendingIndex < totalSize &&
    isCount(manifest.pendingRealLen) &&
    manifest.pendingRealLen > 0 &&
    manifest.pendingRealLen === manifest.savedSize
  );
};
