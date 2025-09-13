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

  _get_merkle_root(
    LEAVES_LEN: number,
    leaves_hashed: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
  ): number;
  _get_merkle_proof(
    LEAVES_LEN: number,
    leaves_hashed: number, // Uint8Array.byteOffset
    element_hash: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;
  _get_merkle_root_from_proof(
    PROOF_LEN: number,
    element_hash: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
  ): number;
  _verify_merkle_proof(
    PROOF_LEN: number,
    element_hash: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;

  _argon2(
    MNEMONIC_LEN: number,
    seed: number,
    mnemonic: number,
    salt: number,
  ): number;

  // P2Party
  _receive_message(
    decrypted: number, // Uint8Array.byteOffset
    message: number, // Uint8Array.byteOffset
    merkle_root: number, // Uint8Array.byteOffset
    sender_public_key: number, // Uint8Array.byteOffset
    receiver_secret_key: number, // Uint8Array.byteOffset
  ): number;
}

declare const libcrypto: EmscriptenModuleFactory<LibCrypto>;
export default libcrypto;
