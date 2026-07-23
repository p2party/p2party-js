import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
  crypto_core_ristretto255_BYTES,
  crypto_core_ristretto255_HASHBYTES,
  crypto_core_ristretto255_SCALARBYTES,
} from "./interfaces";
import {
  CPACE_RISTRETTO255_DSI,
  CPACE_RISTRETTO255_ISK_DSI,
} from "../utils/constants";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

const textEncoder = new TextEncoder();
const CPACE_DSI_BYTES = textEncoder.encode(CPACE_RISTRETTO255_DSI);
const CPACE_ISK_DSI_BYTES = textEncoder.encode(CPACE_RISTRETTO255_ISK_DSI);
const SHA512_INPUT_BLOCK_BYTES = 128;
const EMPTY = new Uint8Array(0);

type TranscriptPart = { data: Uint8Array; secret?: boolean };

const assertLength = (
  name: string,
  value: Uint8Array,
  expected: number,
): void => {
  if (value.length !== expected)
    throw new Error(`cpace: ${name} must be ${expected} bytes`);
};

/**
 * CPace draft-21 prepend_len(): unsigned LEB128 byte length followed by value.
 * Exported so the standards KAT can freeze the transcript encoding independently
 * of the group operation.
 */
export const encodeCpaceLength = (length: number): Uint8Array => {
  if (!Number.isSafeInteger(length) || length < 0)
    throw new Error("cpace: invalid transcript field length");

  const encoded: number[] = [];
  let remaining = length;
  do {
    let byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    if (remaining !== 0) byte |= 0x80;
    encoded.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(encoded);
};

const sha512Update = (
  module: LibCrypto,
  statePtr: number,
  data: Uint8Array,
  secret = false,
): void => {
  if (data.length === 0) return;

  const ptr = module._malloc(data.length);
  const view = new Uint8Array(module.wasmMemory.buffer, ptr, data.length);
  try {
    view.set(data);
    if (module._sha512_update(statePtr, ptr, data.length) !== 0)
      throw new Error("sha512_update failed");
  } finally {
    if (secret) zeroFree(module, view);
    else module._free(ptr);
  }
};

const sha512UpdateLvField = (
  module: LibCrypto,
  statePtr: number,
  part: TranscriptPart,
): void => {
  sha512Update(module, statePtr, encodeCpaceLength(part.data.length));
  sha512Update(module, statePtr, part.data, part.secret);
};

/**
 * SHA-512(lv_cat(parts...)). The state and digest buffers are wiped because
 * generator transcripts contain the low-entropy PRS and their digest can be
 * used to test password guesses if recovered.
 */
const sha512LvConcat = (
  module: LibCrypto,
  parts: TranscriptPart[],
): Uint8Array => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  const stateView = new Uint8Array(
    module.wasmMemory.buffer,
    statePtr,
    crypto_hash_sha512_STATEBYTES,
  );
  const outView = new Uint8Array(
    module.wasmMemory.buffer,
    outPtr,
    crypto_hash_sha512_BYTES,
  );

  try {
    stateView.fill(0);
    outView.fill(0);
    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");
    for (const part of parts)
      sha512UpdateLvField(module, statePtr, part);
    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("sha512_final failed");
    return Uint8Array.from(outView);
  } finally {
    zeroFree(module, stateView);
    zeroFree(module, outView);
  }
};

/**
 * CPACE-RISTR255-SHA512 generator from draft-irtf-cfrg-cpace-21:
 *
 * generator_string =
 *   lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
 *
 * where len_zpad fills the first SHA-512 input block after DSI and PRS.
 */
export const deriveGenerator = (
  pin: Uint8Array,
  sid: Uint8Array,
  channelInput: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const lenZpad = Math.max(
    0,
    SHA512_INPUT_BLOCK_BYTES -
      1 -
      (encodeCpaceLength(CPACE_DSI_BYTES.length).length +
        CPACE_DSI_BYTES.length) -
      (encodeCpaceLength(pin.length).length + pin.length),
  );
  const h = sha512LvConcat(module, [
    { data: CPACE_DSI_BYTES },
    { data: pin, secret: true },
    { data: new Uint8Array(lenZpad) },
    { data: channelInput },
    { data: sid },
  ]);

  const hPtr = module._malloc(crypto_core_ristretto255_HASHBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const hView = new Uint8Array(
    module.wasmMemory.buffer,
    hPtr,
    crypto_core_ristretto255_HASHBYTES,
  );
  const gView = new Uint8Array(
    module.wasmMemory.buffer,
    gPtr,
    crypto_core_ristretto255_BYTES,
  );

  try {
    hView.set(h);
    gView.fill(0);
    module._cpace_ristretto255_from_hash(gPtr, hPtr);
    return Uint8Array.from(gView);
  } finally {
    // h is password-dependent even though the resulting generator is public.
    h.fill(0);
    zeroFree(module, hView);
    module._free(gPtr);
  }
};

/** y <- uniform non-zero ristretto255 scalar; Y = y*G. */
export const cpaceStart = (
  generator: Uint8Array,
  module: LibCrypto,
): { y: Uint8Array; Y: Uint8Array } => {
  assertLength("generator", generator, crypto_core_ristretto255_BYTES);

  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const sharePtr = module._malloc(crypto_core_ristretto255_BYTES);
  const yView = new Uint8Array(
    module.wasmMemory.buffer,
    yPtr,
    crypto_core_ristretto255_SCALARBYTES,
  );
  const gView = new Uint8Array(
    module.wasmMemory.buffer,
    gPtr,
    crypto_core_ristretto255_BYTES,
  );
  const shareView = new Uint8Array(
    module.wasmMemory.buffer,
    sharePtr,
    crypto_core_ristretto255_BYTES,
  );

  try {
    yView.fill(0);
    shareView.fill(0);
    gView.set(generator);
    module._cpace_ristretto255_scalar_random(yPtr);
    if (
      module._cpace_ristretto255_scalarmult(sharePtr, yPtr, gPtr) !== 0
    )
      throw new Error("cpace: public share is the identity");
    return {
      y: Uint8Array.from(yView),
      Y: Uint8Array.from(shareView),
    };
  } finally {
    zeroFree(module, yView);
    module._free(gPtr);
    module._free(sharePtr);
  }
};

export interface CpaceFinishParams {
  /** Caller's one-use private scalar. */
  y: Uint8Array;
  /** Remote party's encoded Ristretto255 share. */
  peerShare: Uint8Array;
  /** Shared CPace session identifier. */
  sid: Uint8Array;
  /** Initiator and responder shares in protocol order. */
  initiatorShare: Uint8Array;
  responderShare: Uint8Array;
  /** Optional associated data; identities are already role-bound in CI here. */
  initiatorAssociatedData?: Uint8Array;
  responderAssociatedData?: Uint8Array;
}

/**
 * Finish draft-21 CPace and return only ISK. The intermediate shared point K
 * never enters JavaScript and is wiped in WASM before return, as required by
 * draft §10.3.
 */
export const cpaceFinish = (
  params: CpaceFinishParams,
  module: LibCrypto,
): Uint8Array => {
  const {
    y,
    peerShare,
    sid,
    initiatorShare,
    responderShare,
    initiatorAssociatedData = EMPTY,
    responderAssociatedData = EMPTY,
  } = params;

  assertLength("private scalar", y, crypto_core_ristretto255_SCALARBYTES);
  assertLength("peer share", peerShare, crypto_core_ristretto255_BYTES);
  assertLength(
    "initiator share",
    initiatorShare,
    crypto_core_ristretto255_BYTES,
  );
  assertLength(
    "responder share",
    responderShare,
    crypto_core_ristretto255_BYTES,
  );

  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const peerPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const kPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  const yView = new Uint8Array(
    module.wasmMemory.buffer,
    yPtr,
    crypto_core_ristretto255_SCALARBYTES,
  );
  const peerView = new Uint8Array(
    module.wasmMemory.buffer,
    peerPtr,
    crypto_core_ristretto255_BYTES,
  );
  const kView = new Uint8Array(
    module.wasmMemory.buffer,
    kPtr,
    crypto_core_ristretto255_BYTES,
  );
  const stateView = new Uint8Array(
    module.wasmMemory.buffer,
    statePtr,
    crypto_hash_sha512_STATEBYTES,
  );
  const outView = new Uint8Array(
    module.wasmMemory.buffer,
    outPtr,
    crypto_hash_sha512_BYTES,
  );

  try {
    yView.set(y);
    peerView.set(peerShare);
    kView.fill(0);
    stateView.fill(0);
    outView.fill(0);

    if (module._cpace_ristretto255_scalarmult(kPtr, yPtr, peerPtr) !== 0)
      throw new Error("cpace: peer share is invalid or the identity");

    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");
    sha512UpdateLvField(module, statePtr, { data: CPACE_ISK_DSI_BYTES });
    sha512UpdateLvField(module, statePtr, { data: sid });
    sha512Update(
      module,
      statePtr,
      encodeCpaceLength(crypto_core_ristretto255_BYTES),
    );
    // Hash K directly from WASM; never copy it into the JavaScript heap.
    if (
      module._sha512_update(
        statePtr,
        kPtr,
        crypto_core_ristretto255_BYTES,
      ) !== 0
    )
      throw new Error("sha512_update failed");

    // transcript_ir(Ya, ADa, Yb, ADb)
    sha512UpdateLvField(module, statePtr, { data: initiatorShare });
    sha512UpdateLvField(module, statePtr, {
      data: initiatorAssociatedData,
    });
    sha512UpdateLvField(module, statePtr, { data: responderShare });
    sha512UpdateLvField(module, statePtr, {
      data: responderAssociatedData,
    });

    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("sha512_final failed");
    return Uint8Array.from(outView);
  } finally {
    zeroFree(module, yView);
    module._free(peerPtr);
    zeroFree(module, kView);
    zeroFree(module, stateView);
    zeroFree(module, outView);
  }
};
