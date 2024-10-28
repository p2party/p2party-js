#include "chacha20poly1305.h"

/* Returns (nonce || encrypted_data || auth tag) */
int
encrypt_chachapoly_asymmetric(
    const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t receiver_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t sender_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext = (uint8_t *)malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL) return -1;

  uint8_t *sender_x25519_pk = (uint8_t *)malloc(
      sizeof(uint8_t[crypto_aead_chacha20poly1305_KEYBYTES]));
  if (sender_x25519_pk == NULL)
  {
    free(ciphertext);

    return -2;
  }

  uint8_t *sender_x25519_sk = (uint8_t *)sodium_malloc(
      sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (sender_x25519_sk == NULL)
  {
    free(ciphertext);
    free(sender_x25519_pk);

    return -3;
  }

  int converted_sk = crypto_sign_ed25519_sk_to_curve25519(sender_x25519_sk,
                                                          sender_secret_key);
  if (converted_sk != 0)
  {
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -4;
  }

  crypto_scalarmult_curve25519_base(sender_x25519_pk, sender_x25519_sk);

  uint8_t *receiver_x25519_pk
      = malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (receiver_x25519_pk == NULL)
  {
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -5;
  }

  int converted_pk = crypto_sign_ed25519_pk_to_curve25519(receiver_x25519_pk,
                                                          receiver_public_key);
  if (converted_pk != 0)
  {
    free(receiver_x25519_pk);
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -6;
  }

  uint8_t *server_tx
      = sodium_malloc(sizeof(uint8_t[crypto_kx_SESSIONKEYBYTES]));
  if (server_tx == NULL)
  {
    free(receiver_x25519_pk);
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -7;
  }

  int created = crypto_kx_server_session_keys(
      NULL, server_tx, sender_x25519_pk, sender_x25519_sk, receiver_x25519_pk);
  // free(sender_x25519_pk);
  free(receiver_x25519_pk);
  free(sender_x25519_pk);
  sodium_free(sender_x25519_sk);
  if (created != 0)
  {
    sodium_free(server_tx);
    free(ciphertext);

    return -8;
  }

  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, server_tx);
  sodium_free(server_tx);

  memcpy(encrypted, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  memcpy(encrypted + crypto_aead_chacha20poly1305_ietf_NPUBBYTES, ciphertext,
         CIPHERTEXT_LEN);
  free(ciphertext);

  return 0;
}

int
decrypt_chachapoly_asymmetric(
    const unsigned int ENCRYPTED_LEN,
    const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t sender_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long DATA_LEN
      = ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
        - crypto_aead_chacha20poly1305_ietf_ABYTES - crypto_sign_ed25519_BYTES;

  uint8_t *receiver_x25519_pk = (uint8_t *)malloc(
      sizeof(uint8_t[crypto_aead_chacha20poly1305_KEYBYTES]));
  if (receiver_x25519_pk == NULL) return -1;

  uint8_t *receiver_x25519_sk = (uint8_t *)sodium_malloc(
      sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (receiver_x25519_sk == NULL)
  {
    free(receiver_x25519_pk);

    return -2;
  }

  int converted_sk = crypto_sign_ed25519_sk_to_curve25519(receiver_x25519_sk,
                                                          receiver_secret_key);
  if (converted_sk != 0)
  {
    free(receiver_x25519_pk);
    sodium_free(receiver_x25519_sk);

    return -3;
  }

  crypto_scalarmult_curve25519_base(receiver_x25519_pk, receiver_x25519_sk);

  uint8_t *sender_x25519_pk
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (receiver_x25519_pk == NULL)
  {
    free(receiver_x25519_pk);
    sodium_free(receiver_x25519_sk);

    return -4;
  }

  int converted_pk = crypto_sign_ed25519_pk_to_curve25519(sender_x25519_pk,
                                                          sender_public_key);
  if (converted_pk != 0)
  {
    free(sender_x25519_pk);
    free(receiver_x25519_pk);
    sodium_free(receiver_x25519_sk);

    return -5;
  }

  uint8_t *client_tx
      = (uint8_t *)sodium_malloc(sizeof(uint8_t[crypto_kx_SESSIONKEYBYTES]));
  if (client_tx == NULL)
  {
    free(sender_x25519_pk);
    free(receiver_x25519_pk);
    sodium_free(receiver_x25519_sk);

    return -6;
  }

  int created
      = crypto_kx_client_session_keys(client_tx, NULL, receiver_x25519_pk,
                                      receiver_x25519_sk, sender_x25519_pk);
  // free(sender_x25519_pk);
  free(sender_x25519_pk);
  free(receiver_x25519_pk);
  sodium_free(receiver_x25519_sk);
  if (created != 0)
  {
    sodium_free(client_tx);

    return -7;
  }

  uint8_t *ephemeral_x25519_pk
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (ephemeral_x25519_pk == NULL) return -1;

  int CIPHERTEXT_LEN
      = ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  uint8_t *ciphertext = (uint8_t *)malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL)
  {
    sodium_free(client_tx);

    return -7;
  }

  memcpy(ciphertext,
         encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
         CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, encrypted_data, client_tx);

  free(ciphertext);
  sodium_free(client_tx);

  if (decrypted == 0) return 0;

  return -8;
}
