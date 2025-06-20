
#ifndef DGTOTP_PRF_H
#define DGTOTP_PRF_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Define the key size and block size for AES-128
#define AES_KEY_SIZE 16   // 128 bits
#define AES_BLOCK_SIZE 16 // 16 bytes

// Function declarations
int create_key(unsigned char *key);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext);
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext);
int ASE_enc(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext);
int ASE_dec(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext);
void handle_errors(void);

#endif // DGTOTP_PRF_H
