/**
 * Fill any Uint8Array — including a view into WebAssembly.Memory — without
 * handing its backing buffer to WebCrypto.
 *
 * Chromium 147/149 rejects BufferSource inputs backed by resizable
 * WebAssembly memory. A fresh length-constructed Uint8Array always owns an
 * ordinary fixed ArrayBuffer, so WebCrypto fills that temporary and we copy
 * into the caller's destination. Randomness is secret key material at every
 * current call site; wipe the temporary on success and failure.
 *
 * The optional filler exists for deterministic boundary tests and is not a
 * protocol entropy-injection API.
 */
export const fillRandomBytesInto = (
  destination: Uint8Array,
  fill: (temporary: Uint8Array) => void = (temporary) => {
    globalThis.crypto.getRandomValues(temporary);
  },
): void => {
  if (!(destination instanceof Uint8Array))
    throw new TypeError("random: destination must be a Uint8Array");

  const temporary = new Uint8Array(destination.byteLength);
  try {
    fill(temporary);
    destination.set(temporary);
  } finally {
    temporary.fill(0);
  }
};
