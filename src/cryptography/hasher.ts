export class Hasher {
  private encoder: TextEncoder;
  private data: Uint8Array[];

  private constructor() {
    this.encoder = new TextEncoder();
    this.data = [];
  }

  static createHash(): Hasher {
    return new Hasher();
  }

  update(data: string | Uint8Array): Hasher {
    if (typeof data === "string") {
      this.data.push(this.encoder.encode(data));
    } else {
      this.data.push(data);
    }
    return this; // Enables method chaining like Node.js API
  }

  async digest(encoding: "hex" | "base64" = "hex"): Promise<string> {
    const combinedData = this.concatUint8Arrays(this.data);
    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      combinedData as Uint8Array<ArrayBuffer>,
    );
    return this.encodeBuffer(hashBuffer, encoding);
  }

  private concatUint8Arrays(chunks: Uint8Array[]): Uint8Array {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    return combined;
  }

  private encodeBuffer(
    buffer: ArrayBuffer,
    encoding: "hex" | "base64",
  ): string {
    const byteArray = new Uint8Array(buffer);
    if (encoding === "hex") {
      return [...byteArray]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } else if (encoding === "base64") {
      return btoa(String.fromCharCode(...byteArray));
    }
    throw new Error("Unsupported encoding");
  }
}
