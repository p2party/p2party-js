import { zeroFree } from "../utils/zeroFree";

import { snapshotByteInput } from "./byteInput";

import type { LibCrypto } from "./libcrypto";

export const SHA3_256_BYTES = 32;

/**
 * The one-shot bound proved by the pinned mlkem-native FIPS 202 backend.
 *
 * WASM uses a 32-bit size_t, so this is `(SIZE_MAX >> 12)` from mlkem768.h.
 */
export const FIPS202_MAX_BUFFER_BYTES = 0x000f_ffff;

type Fips202Function = (
  outputPointer: number,
  outputLength: number,
  inputPointer: number,
  inputLength: number,
) => number;

const requireOutputLength = (length: number): void => {
  if (!Number.isSafeInteger(length))
    throw new TypeError("outputLength must be a safe integer");
  if (length < 0 || length > FIPS202_MAX_BUFFER_BYTES)
    throw new RangeError("outputLength exceeds the FIPS 202 one-shot limit");
};

const heapView = (
  module: LibCrypto,
  pointer: number,
  length: number,
): Uint8Array => new Uint8Array(module.wasmMemory.buffer, pointer, length);

const checkedMalloc = (
  module: LibCrypto,
  length: number,
  operation: string,
): number => {
  const pointer = module._malloc(length);
  if (pointer === 0) throw new Error(`${operation} failed (allocation)`);
  return pointer;
};

const snapshotInput = (input: Uint8Array): Uint8Array => {
  try {
    return snapshotByteInput(input, "input", {
      maximumLength: FIPS202_MAX_BUFFER_BYTES,
    });
  } catch (error) {
    if (
      error instanceof RangeError &&
      error.message === "input exceeds the supported length"
    )
      throw new RangeError("input exceeds the FIPS 202 one-shot limit", {
        cause: error,
      });
    throw error;
  }
};

const oneShot = (
  input: Uint8Array,
  outputLength: number,
  module: LibCrypto,
  operation: string,
  primitive: Fips202Function,
): Uint8Array => {
  // Snapshot before `_malloc`: memory growth can detach a caller view backed
  // by this same WASM module. Inputs can be secret X-Wing seeds, so wipe the
  // private copy on every exit.
  const privateInput = snapshotInput(input);
  const inputAllocationBytes = Math.max(1, privateInput.length);
  let outputAllocationBytes: number | undefined;
  let inputPointer: number | undefined;
  let outputPointer: number | undefined;

  try {
    requireOutputLength(outputLength);
    outputAllocationBytes = Math.max(1, outputLength);

    outputPointer = checkedMalloc(module, outputAllocationBytes, operation);
    inputPointer = checkedMalloc(module, inputAllocationBytes, operation);
    heapView(module, inputPointer, privateInput.length).set(privateInput);

    if (
      primitive(
        outputPointer,
        outputLength,
        inputPointer,
        privateInput.length,
      ) !== 0
    )
      throw new Error(`${operation} failed`);

    return Uint8Array.from(heapView(module, outputPointer, outputLength));
  } finally {
    try {
      if (outputPointer !== undefined && outputAllocationBytes !== undefined)
        zeroFree(
          module,
          heapView(module, outputPointer, outputAllocationBytes),
        );
    } finally {
      try {
        if (inputPointer !== undefined)
          zeroFree(
            module,
            heapView(module, inputPointer, inputAllocationBytes),
          );
      } finally {
        privateInput.fill(0);
      }
    }
  }
};

export const shake256 = (
  input: Uint8Array,
  outputLength: number,
  module: LibCrypto,
): Uint8Array =>
  oneShot(
    input,
    outputLength,
    module,
    "SHAKE256",
    module._fips202_shake256.bind(module),
  );

export const sha3_256 = (input: Uint8Array, module: LibCrypto): Uint8Array =>
  oneShot(
    input,
    SHA3_256_BYTES,
    module,
    "SHA3-256",
    (outputPointer, _outputLength, inputPointer, inputLength) =>
      module._fips202_sha3_256(outputPointer, inputPointer, inputLength),
  );
