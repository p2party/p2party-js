/// <reference types="emscripten" />

export interface LibCrypto extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;

  _keypair(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array
  ): number;

  _keypair_from_seed(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    seed: number, // Uint8Array,
  ): number;
  _keypair_from_secret_key(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
  ): number;

  _sign(
    DATA_LEN: number,
    data: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    signature: number, // Uint8Array,
  ): number;
  _verify(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    signature: number, // Uint8Array,
  ): number;

  _encrypt_chachapoly_asymmetric(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    nonce: number,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    encrypted: number, // Uint8Array,
  ): number;

  _decrypt_chachapoly_asymmetric(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
  ): number;
}

declare const libcrypto: EmscriptenModuleFactory<LibCrypto>;
export default libcrypto;
