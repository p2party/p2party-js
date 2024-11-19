export interface BasicMetadata {
  messageType: number; // 1 byte
  size: number; // 8 bytes, number of bytes, max file size 10GB
  name: string; // 256 bytes, serialized string
  lastModified: Date; // 8 bytes, Date object
  chunkStartIndex: number; // 4 bytes, uint32
  chunkEndIndex: number; // 4 bytes, uint32
  totalChunks: number; // 4 bytes, uint32
}

export interface Metadata extends BasicMetadata {
  chunkIndex: number; // 4 bytes, uint32
}

export const METADATA_LEN =
  1 + // messageType (1 byte)
  8 + // size (8 bytes)
  256 + // name (256 bytes)
  8 + // lastModified (8 bytes)
  4 + // chunkStartIndex (4 bytes)
  4 + // chunkEndIndex (4 bytes)
  4 + // chunkIndex (4 bytes)
  4; // totalChunks (4 bytes)

export const formatSize = (size: number): string => {
  if (size >= 1 << 30) {
    return (size / (1 << 30)).toFixed(2) + " GB";
  } else if (size >= 1 << 20) {
    return (size / (1 << 20)).toFixed(2) + " MB";
  } else if (size >= 1 << 10) {
    return (size / (1 << 10)).toFixed(2) + " KB";
  } else {
    return size + " bytes";
  }
};

export const serializeMetadata = (metadata: Metadata): Uint8Array => {
  const buffer = new Uint8Array(METADATA_LEN);
  let offset = 0;

  // messageType (1 byte)
  buffer[offset] = metadata.messageType;
  offset += 1;

  // size (8 bytes)
  const sizeView = new DataView(buffer.buffer, offset, 8);
  sizeView.setBigUint64(0, BigInt(metadata.size), false); // Big-endian
  offset += 8;

  // name (256 bytes)
  const nameBytes = new TextEncoder().encode(metadata.name);
  const namePadded = new Uint8Array(256);
  namePadded.set(nameBytes.subarray(0, Math.min(256, nameBytes.length)));
  buffer.set(namePadded, offset);
  offset += 256;

  // lastModified (8 bytes)
  const lastModifiedTime = BigInt(metadata.lastModified.getTime());
  const lastModifiedView = new DataView(buffer.buffer, offset, 8);
  lastModifiedView.setBigUint64(0, lastModifiedTime, false); // Big-endian
  offset += 8;

  // chunkStartIndex (4 bytes)
  const chunkStartIndexView = new DataView(buffer.buffer, offset, 4);
  chunkStartIndexView.setUint32(0, metadata.chunkStartIndex, false); // Big-endian
  offset += 4;

  // chunkEndIndex (4 bytes)
  const chunkEndIndexView = new DataView(buffer.buffer, offset, 4);
  chunkEndIndexView.setUint32(0, metadata.chunkEndIndex, false); // Big-endian
  offset += 4;

  // chunkIndex (4 bytes)
  const chunkIndexView = new DataView(buffer.buffer, offset, 4);
  chunkIndexView.setUint32(0, metadata.chunkIndex, false); // Big-endian
  offset += 4;

  // totalChunks (4 bytes)
  const totalChunksView = new DataView(buffer.buffer, offset, 4);
  totalChunksView.setUint32(0, metadata.totalChunks, false); // Big-endian

  return buffer;
};

export const deserializeMetadata = (buffer: Uint8Array): Metadata => {
  if (buffer.length !== METADATA_LEN) {
    throw new Error("Invalid metadata buffer size");
  }

  let offset = 0;

  // messageType (1 byte)
  const messageType = buffer[offset];
  offset += 1;

  // size (8 bytes)
  const sizeView = new DataView(buffer.buffer, buffer.byteOffset + offset, 8);
  const size = Number(sizeView.getBigUint64(0, false)); // Big-endian
  offset += 8;

  // name (256 bytes)
  const nameBytes = buffer.slice(offset, offset + 256);
  const name = new TextDecoder().decode(nameBytes).replace(/\0+$/, "");
  offset += 256;

  // lastModified (8 bytes)
  const lastModifiedView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const lastModifiedTime = Number(lastModifiedView.getBigUint64(0, false)); // Big-endian
  const lastModified = new Date(lastModifiedTime);
  offset += 8;

  // chunkStartIndex (4 bytes)
  const chunkStartIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    4,
  );
  const chunkStartIndex = chunkStartIndexView.getUint32(0, false); // Big-endian
  offset += 4;

  // chunkEndIndex (4 bytes)
  const chunkEndIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    4,
  );
  const chunkEndIndex = chunkEndIndexView.getUint32(0, false); // Big-endian
  offset += 4;

  // chunkIndex (4 bytes)
  const chunkIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    4,
  );
  const chunkIndex = chunkIndexView.getUint32(0, false); // Big-endian
  offset += 4;

  // totalChunks (4 bytes)
  const totalChunksView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    4,
  );
  const totalChunks = totalChunksView.getUint32(0, false); // Big-endian

  return {
    messageType,
    size,
    name,
    lastModified,
    chunkStartIndex,
    chunkEndIndex,
    chunkIndex,
    totalChunks,
  };
};
