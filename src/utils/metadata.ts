// import { MessageType } from "./messageTypes";

export interface BasicMetadata {
  schemaVersion: number; // 8 bytes
  messageType: number; // MessageType; // 1 byte
  totalSize: number; // 8 bytes, number of bytes, max file totalSize 10GB
  date: Date; // 8 bytes
  name: string; // 256 bytes, serialized string
  chunkStartIndex: number; // 8 bytes, uint64
  chunkEndIndex: number; // 8 bytes, uint64
}

export interface Metadata extends BasicMetadata {
  chunkIndex: number; // 8 bytes, uint64
}

export const METADATA_LEN =
  8 + // schemaVersion (8 bytes)
  1 + // messageType (1 byte)
  8 + // totalSize (8 bytes)
  8 + // date (8 bytes)
  256 + // name (256 bytes)
  8 + // chunkStartIndex (8 bytes)
  8 + // chunkEndIndex (8 bytes)
  8; // chunkIndex (8 bytes)

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

  // schemaVersion (8 bytes)
  const schemaVersionView = new DataView(buffer.buffer, offset, 8);
  schemaVersionView.setBigUint64(0, BigInt(metadata.schemaVersion), false); // Big-endian
  offset += 8;

  // messageType (1 byte)
  buffer[offset] = metadata.messageType;
  offset += 1;

  // totalSize (8 bytes)
  const totalSizeView = new DataView(buffer.buffer, offset, 8);
  totalSizeView.setBigUint64(0, BigInt(metadata.totalSize), false); // Big-endian
  offset += 8;

  const dateView = new DataView(buffer.buffer, offset, 8);
  dateView.setBigInt64(0, BigInt(metadata.date.getTime()), false);
  offset += 8;

  // name (256 bytes)
  const nameBytes = new TextEncoder().encode(metadata.name);
  const namePadded = new Uint8Array(256);
  namePadded.set(nameBytes.subarray(0, Math.min(256, nameBytes.length)));
  buffer.set(namePadded, offset);
  offset += 256;

  // chunkStartIndex (8 bytes)
  const chunkStartIndexView = new DataView(buffer.buffer, offset, 8);
  chunkStartIndexView.setBigUint64(0, BigInt(metadata.chunkStartIndex), false); // Big-endian
  offset += 8;

  // chunkEndIndex (8 bytes)
  const chunkEndIndexView = new DataView(buffer.buffer, offset, 8);
  chunkEndIndexView.setBigUint64(0, BigInt(metadata.chunkEndIndex), false); // Big-endian
  offset += 8;

  // chunkIndex (8 bytes)
  const chunkIndexView = new DataView(buffer.buffer, offset, 8);
  chunkIndexView.setBigUint64(0, BigInt(metadata.chunkIndex), false); // Big-endian
  offset += 8;

  return buffer;
};

export const deserializeMetadata = (buffer: Uint8Array): Metadata => {
  if (buffer.length !== METADATA_LEN) {
    throw new Error("Invalid metadata buffer totalSize");
  }

  let offset = 0;

  // schemaVersion (8 bytes)
  const schemaVersionView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const schemaVersion = Number(schemaVersionView.getBigUint64(0, false)); // Big-endian
  offset += 8;

  // messageType (1 byte)
  const messageType = buffer[offset];
  offset += 1;

  // totalSize (8 bytes)
  const totalSizeView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const totalSize = Number(totalSizeView.getBigUint64(0, false)); // Big-endian
  offset += 8;

  // lastModified (8 bytes)
  const dateView = new DataView(buffer.buffer, buffer.byteOffset + offset, 8);
  const dateTime = Number(dateView.getBigUint64(0, false)); // Big-endian
  const date = new Date(dateTime);
  offset += 8;

  // name (256 bytes)
  const nameBytes = buffer.slice(offset, offset + 256);
  const name = new TextDecoder().decode(nameBytes).replace(/\0+$/, "");
  offset += 256;

  // chunkStartIndex (8 bytes)
  const chunkStartIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const chunkStartIndex = Number(chunkStartIndexView.getBigUint64(0, false)); // Big-endian
  offset += 8;

  // chunkEndIndex (8 bytes)
  const chunkEndIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const chunkEndIndex = Number(chunkEndIndexView.getBigUint64(0, false)); // Big-endian
  offset += 8;

  // chunkIndex (8 bytes)
  const chunkIndexView = new DataView(
    buffer.buffer,
    buffer.byteOffset + offset,
    8,
  );
  const chunkIndex = Number(chunkIndexView.getBigUint64(0, false)); // Big-endian

  return {
    schemaVersion,
    messageType,
    totalSize,
    date,
    name,
    chunkStartIndex,
    chunkEndIndex,
    chunkIndex,
  };
};
