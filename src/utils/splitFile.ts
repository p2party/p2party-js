export default async function splitFile(
  file: File,
  chunkSize: number,
  callback: (chunk: Uint8Array, sequenceNumber: number) => Promise<void>,
  transformer?: (chunk: Uint8Array, chunkIndex: number) => any,
) {
  const fileSize = file.size;
  let offset = 0;

  const readChunk = () => {
    const r = new FileReader();
    const blob = file.slice(offset, chunkSize + offset);
    r.onload = readEventHandler;
    r.readAsArrayBuffer(blob);
  };

  const readEventHandler = async (evt: any) => {
    if (evt.target.error == null) {
      const sequenceNumber = (offset / chunkSize);
      offset += evt.target.result.byteLength;
      let data = new Uint8Array(evt.target.result);

      if (transformer) {
        data = await transformer(data, sequenceNumber);
      }

      await callback(data, sequenceNumber);
    } else {
      console.error(evt.target.error);
      // Read error.
      return;
    }

    if (offset >= fileSize) {
      // Done reading file.
      return;
    }

    // Off to the next chunk.
    readChunk();
  };

  // Let's start reading the first block.
  readChunk();
}

