#include "dgtotp_prf.h"
#include "common.h"
#include <string.h>
#include <stdio.h>

// Function to create a random key
int create_key(unsigned char *key)
{
  if (RAND_bytes(key, AES_KEY_SIZE) != 1)
  {
    handle_errors();
    return -1;
  }
  return 0;
}

// Function to encrypt plaintext using AES-128 in ECB mode, PKCS7 padding
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len;
  int ciphertext_len;

  if (!ctx)
  {
    handle_errors();
    return -1;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)
  {
    handle_errors();
    return -1;
  }

  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
  {
    handle_errors();
    return -1;
  }
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
  {
    handle_errors();
    return -1;
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// Function to decrypt ciphertext using AES-128 in ECB mode
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len;
  int plaintext_len;

  if (!ctx)
  {
    handle_errors();
    return -1;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)
  {
    handle_errors();
    return -1;
  }

  if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
  {
    handle_errors();
    return -1;
  }
  plaintext_len = len;

  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
  {
    handle_errors();
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

// Function to handle OpenSSL errors
void handle_errors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

// ASE encryption
int ASE_enc(const unsigned char *plaintext, int plaintext_len,
            const unsigned char *key, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher;
  int len, ciphertext_len;

  cipher = EVP_aes_128_gcm();

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();

  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
    handle_errors();

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    handle_errors();

  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, pms.iv))
    handle_errors();

  if (pms.aad_len > 0)
  {
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, pms.aad, pms.aad_len))
      handle_errors();
  }

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handle_errors();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handle_errors();
  ciphertext_len += len;

  int TAG_SIZE = 16;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ciphertext + ciphertext_len))
    handle_errors();
  ciphertext_len += TAG_SIZE;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int ASE_dec(const unsigned char *ciphertext, int ciphertext_len,
            const unsigned char *key, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher;
  int len, plaintext_len;
  int ret;

  cipher = EVP_aes_128_gcm();

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();

  if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
    handle_errors();

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    handle_errors();

  if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, pms.iv))
    handle_errors();

  if (pms.aad_len > 0)
  {
    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, pms.aad, pms.aad_len))
      handle_errors();
  }

  int TAG_SIZE = 16;
  int enc_data_len = ciphertext_len - TAG_SIZE;
  if (enc_data_len < 0)
  {
    fprintf(stderr, "Ciphertext length is too short.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, enc_data_len))
    handle_errors();
  plaintext_len = len;

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                               (void *)(ciphertext + enc_data_len)))
    handle_errors();

  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  if (ret > 0)
  {
    plaintext_len += len;
  }
  else
  {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}