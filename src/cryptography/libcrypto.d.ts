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

  // Streaming SHA-512 (plain, no domain separation) — state is a heap
  // crypto_hash_sha512_state (208 bytes) allocated by JS.
  _sha512_init(
    state: number, // Uint8Array.byteOffset (208-byte state)
  ): number;
  _sha512_update(
    state: number, // Uint8Array.byteOffset
    in_data: number, // Uint8Array.byteOffset
    in_len: number,
  ): number;
  _sha512_final(
    state: number, // Uint8Array.byteOffset
    out: number, // Uint8Array.byteOffset (64 bytes)
  ): number;

  // P2Party
  _receive_message(
    decrypted: number, // Uint8Array.byteOffset
    message: number, // Uint8Array.byteOffset
    merkle_root: number, // Uint8Array.byteOffset
    sender_public_key: number, // Uint8Array.byteOffset
    receiver_secret_key: number, // Uint8Array.byteOffset
  ): number;

  // v3 PAKE + ratchet primitives (pake_ratchet.c)
  _cpace_ristretto255_from_hash(out: number, hash: number): void;
  _cpace_ristretto255_scalarmult(
    out: number,
    scalar: number,
    point: number,
  ): number;
  _cpace_ristretto255_scalar_random(out: number): void;
  _x25519_keypair(pk: number, sk: number): number;
  _x25519_dh(shared: number, sk: number, pk: number): number;
  _hkdf_sha512_extract(
    prk: number,
    salt: number,
    salt_len: number,
    ikm: number,
    ikm_len: number,
  ): number;
  _hkdf_sha512_expand(
    out: number,
    out_len: number,
    prk: number,
    info: number,
    info_len: number,
  ): number;
  _encrypt_chachapoly_symmetric(
    out: number,
    data: number,
    data_len: number,
    key: number,
    nonce: number,
    aad: number,
    aad_len: number,
  ): number;
  _decrypt_chachapoly_symmetric(
    out: number,
    ciphertext: number,
    ciphertext_len: number,
    key: number,
    nonce: number,
    aad: number,
    aad_len: number,
  ): number;
  _receive_message_with_key(
    decrypted: number,
    message: number,
    merkle_root: number,
    message_key: number,
  ): number;
}

declare const libcrypto: EmscriptenModuleFactory<LibCrypto>;
export default libcrypto;
