import { zeroFree } from "../utils/zeroFree";

import { snapshotByteInput } from "./byteInput";

import type { LibCrypto } from "./libcrypto";

export const WASM_AEAD_MAX_BYTES = 0x7fff_ffff;

type AeadPrimitive = (
  module: LibCrypto,
  output: number,
  input: number,
  inputLength: number,
  key: number,
  nonce: number,
  associatedData: number,
  associatedDataLength: number,
) => number;

export interface WasmAeadSuite {
  readonly name: string;
  readonly keyBytes: number;
  readonly nonceBytes: number;
  readonly tagBytes: number;
  readonly encrypt: AeadPrimitive;
  readonly decrypt: AeadPrimitive;
}

export class WasmAeadError extends Error {
  override readonly name = "WasmAeadError";
}

export const maxAeadPlaintextBytes = (suite: WasmAeadSuite): number =>
  WASM_AEAD_MAX_BYTES - suite.tagBytes;

const error = (suite: WasmAeadSuite, message: string): WasmAeadError =>
  new WasmAeadError(`${suite.name}: ${message}`);

const checkedCiphertextLength = (
  suite: WasmAeadSuite,
  plaintextLength: number,
): number => {
  const length = plaintextLength + suite.tagBytes;
  if (!Number.isSafeInteger(length) || length > WASM_AEAD_MAX_BYTES)
    throw new RangeError(
      `${suite.name}: ciphertext length exceeds the supported range`,
    );
  return length;
};

const checkedMalloc = (
  module: LibCrypto,
  suite: WasmAeadSuite,
  length: number,
  name: string,
): number => {
  const pointer = module._malloc(length);
  if (pointer === 0) throw error(suite, `failed to allocate ${name}`);
  return pointer;
};

const heapView = (
  module: LibCrypto,
  pointer: number,
  length: number,
): Uint8Array => new Uint8Array(module.wasmMemory.buffer, pointer, length);

const publicFree = (module: LibCrypto, pointer: number | undefined): void => {
  if (pointer !== undefined) module._free(pointer);
};

const secretFree = (
  module: LibCrypto,
  pointer: number | undefined,
  length: number,
): void => {
  if (pointer !== undefined)
    zeroFree(module, heapView(module, pointer, length));
};

const sealPrivate = (
  suite: WasmAeadSuite,
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  outputLength: number,
): Uint8Array => {
  const plaintextAllocationLength = Math.max(1, plaintext.length);
  const aadAllocationLength = Math.max(1, associatedData.length);
  let keyPointer: number | undefined;
  let noncePointer: number | undefined;
  let aadPointer: number | undefined;
  let plaintextPointer: number | undefined;
  let outputPointer: number | undefined;

  try {
    keyPointer = checkedMalloc(module, suite, key.length, "key");
    noncePointer = checkedMalloc(module, suite, nonce.length, "nonce");
    aadPointer = checkedMalloc(
      module,
      suite,
      aadAllocationLength,
      "associated data",
    );
    plaintextPointer = checkedMalloc(
      module,
      suite,
      plaintextAllocationLength,
      "plaintext",
    );
    outputPointer = checkedMalloc(module, suite, outputLength, "ciphertext");

    // All allocations are complete. Refresh once after any memory growth.
    const heap = new Uint8Array(module.wasmMemory.buffer);
    heap.set(key, keyPointer);
    heap.set(nonce, noncePointer);
    heap.set(associatedData, aadPointer);
    heap.set(plaintext, plaintextPointer);

    const result = suite.encrypt(
      module,
      outputPointer,
      plaintextPointer,
      plaintext.length,
      keyPointer,
      noncePointer,
      aadPointer,
      associatedData.length,
    );
    if (result !== 0) throw error(suite, "encryption failed");

    // A primitive is not expected to allocate, but custom suites and future
    // builds must not make output copying depend on that assumption.
    const outputHeap = new Uint8Array(module.wasmMemory.buffer);
    return Uint8Array.from(
      outputHeap.subarray(outputPointer, outputPointer + outputLength),
    );
  } finally {
    try {
      secretFree(module, keyPointer, suite.keyBytes);
    } finally {
      try {
        publicFree(module, noncePointer);
      } finally {
        try {
          publicFree(module, aadPointer);
        } finally {
          try {
            secretFree(module, plaintextPointer, plaintextAllocationLength);
          } finally {
            secretFree(module, outputPointer, outputLength);
          }
        }
      }
    }
  }
};

export const sealWasmAead = (
  suite: WasmAeadSuite,
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array => {
  // Snapshot each borrowed view before its metadata is used for WASM. This
  // prevents shadowed properties, proxies, and memory growth from invalidating
  // the allocation/copy agreement.
  let privateKey: Uint8Array | undefined;
  let privatePlaintext: Uint8Array | undefined;
  try {
    privateKey = snapshotByteInput(key, `${suite.name}: key`, {
      exactLength: suite.keyBytes,
    });
    const privateNonce = snapshotByteInput(nonce, `${suite.name}: nonce`, {
      exactLength: suite.nonceBytes,
    });
    privatePlaintext = snapshotByteInput(
      plaintext,
      `${suite.name}: plaintext`,
      { maximumLength: maxAeadPlaintextBytes(suite) },
    );
    const privateAssociatedData = snapshotByteInput(
      associatedData,
      `${suite.name}: associatedData`,
      { maximumLength: WASM_AEAD_MAX_BYTES },
    );

    const plaintextLength = privatePlaintext.length;
    const outputLength = checkedCiphertextLength(suite, plaintextLength);

    return sealPrivate(
      suite,
      module,
      privateKey,
      privateNonce,
      privatePlaintext,
      privateAssociatedData,
      outputLength,
    );
  } finally {
    try {
      privateKey?.fill(0);
    } finally {
      privatePlaintext?.fill(0);
    }
  }
};

const openPrivate = (
  suite: WasmAeadSuite,
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  associatedData: Uint8Array,
  plaintextLength: number,
): Uint8Array | null => {
  const aadAllocationLength = Math.max(1, associatedData.length);
  const plaintextAllocationLength = Math.max(1, plaintextLength);
  let keyPointer: number | undefined;
  let noncePointer: number | undefined;
  let aadPointer: number | undefined;
  let ciphertextPointer: number | undefined;
  let plaintextPointer: number | undefined;

  try {
    keyPointer = checkedMalloc(module, suite, key.length, "key");
    noncePointer = checkedMalloc(module, suite, nonce.length, "nonce");
    aadPointer = checkedMalloc(
      module,
      suite,
      aadAllocationLength,
      "associated data",
    );
    ciphertextPointer = checkedMalloc(
      module,
      suite,
      ciphertextAndTag.length,
      "ciphertext",
    );
    plaintextPointer = checkedMalloc(
      module,
      suite,
      plaintextAllocationLength,
      "plaintext",
    );

    const heap = new Uint8Array(module.wasmMemory.buffer);
    heap.set(key, keyPointer);
    heap.set(nonce, noncePointer);
    heap.set(associatedData, aadPointer);
    heap.set(ciphertextAndTag, ciphertextPointer);
    heap
      .subarray(plaintextPointer, plaintextPointer + plaintextAllocationLength)
      .fill(0);

    const result = suite.decrypt(
      module,
      plaintextPointer,
      ciphertextPointer,
      ciphertextAndTag.length,
      keyPointer,
      noncePointer,
      aadPointer,
      associatedData.length,
    );
    if (result !== 0) return null;

    const outputHeap = new Uint8Array(module.wasmMemory.buffer);
    return Uint8Array.from(
      outputHeap.subarray(plaintextPointer, plaintextPointer + plaintextLength),
    );
  } finally {
    try {
      secretFree(module, keyPointer, suite.keyBytes);
    } finally {
      try {
        publicFree(module, noncePointer);
      } finally {
        try {
          publicFree(module, aadPointer);
        } finally {
          try {
            publicFree(module, ciphertextPointer);
          } finally {
            secretFree(module, plaintextPointer, plaintextAllocationLength);
          }
        }
      }
    }
  }
};

export const openWasmAead = (
  suite: WasmAeadSuite,
  module: LibCrypto,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array | null => {
  let privateKey: Uint8Array | undefined;
  try {
    privateKey = snapshotByteInput(key, `${suite.name}: key`, {
      exactLength: suite.keyBytes,
    });
    const privateNonce = snapshotByteInput(nonce, `${suite.name}: nonce`, {
      exactLength: suite.nonceBytes,
    });
    const privateCiphertext = snapshotByteInput(
      ciphertextAndTag,
      `${suite.name}: ciphertextAndTag`,
      { maximumLength: WASM_AEAD_MAX_BYTES },
    );
    const privateAssociatedData = snapshotByteInput(
      associatedData,
      `${suite.name}: associatedData`,
      { maximumLength: WASM_AEAD_MAX_BYTES },
    );

    const ciphertextLength = privateCiphertext.length;
    if (ciphertextLength < suite.tagBytes) return null;
    const plaintextLength = ciphertextLength - suite.tagBytes;

    return openPrivate(
      suite,
      module,
      privateKey,
      privateNonce,
      privateCiphertext,
      privateAssociatedData,
      plaintextLength,
    );
  } finally {
    privateKey?.fill(0);
  }
};
