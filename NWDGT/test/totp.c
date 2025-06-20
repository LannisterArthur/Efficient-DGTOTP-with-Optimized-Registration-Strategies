#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "totp.h"

// Sha256 Hash function (from byte array)
void Hash_Sha256(const unsigned char *input, size_t len, unsigned char *output)
{
  SHA256_CTX sha256_ctx;
  SHA256_Init(&sha256_ctx);
  SHA256_Update(&sha256_ctx, input, len);
  SHA256_Final(output, &sha256_ctx);
}

void byte2hexTOTP(const unsigned char *bytes, size_t len, char *hexstr)
{
  for (size_t i = 0; i < len; ++i)
  {
    sprintf(hexstr + (i * 2), "%02x", bytes[i]);
  }
  hexstr[len * 2] = '\0';
}

void hex2byteTOTP(const char *hexstr, unsigned char *bytes)
{
  size_t len = strlen(hexstr) / 2;
  for (size_t i = 0; i < len; ++i)
  {
    sscanf(hexstr + 2 * i, "%02x", &bytes[i]);
  }
}

// just for test
void totpgetSeed(TOTP *totp, const char *key)
{
  const char *test = "testing";
  unsigned char hash[SHA256_DIGEST_LENGTH];
  Hash_Sha256((const unsigned char *)test, strlen(test), hash);
  byte2hexTOTP(hash, SHA256_DIGEST_LENGTH, totp->SK_SEED);
}

// just for test
void totpSetup(TOTP *totp, int k, long START_TIME, long END_TIME, long PASS_GEN)
{
  totp->N = (int)((END_TIME - START_TIME) / PASS_GEN);
}

// initialize TOTP, generate vp
void totpPInit(TOTP *totp)
{
  unsigned char cache_byte[SHA256_DIGEST_LENGTH];
  hex2byteTOTP(totp->SK_SEED, cache_byte);

  for (int i = 1; i <= totp->N; ++i)
  {
    Hash_Sha256(cache_byte, SHA256_DIGEST_LENGTH, cache_byte);
  }

  byte2hexTOTP(cache_byte, SHA256_DIGEST_LENGTH, totp->VERIFY_POINT);
}

// generate TOTP pw, inverse from 0 to N-1
void totpPGen(TOTP *totp, long pw_sequence, char *password)
{
  unsigned char cache_byte[SHA256_DIGEST_LENGTH];
  hex2byteTOTP(totp->SK_SEED, cache_byte);

  for (int i = 0; i < totp->N - pw_sequence - 1; ++i)
  {
    Hash_Sha256(cache_byte, SHA256_DIGEST_LENGTH, cache_byte);
  }

  byte2hexTOTP(cache_byte, SHA256_DIGEST_LENGTH, password);
}

// verify TOTP pw
int totpVerify(TOTP *totp, const char *password, long pw_sequence)
{
  unsigned char cache_byte[SHA256_DIGEST_LENGTH];
  hex2byteTOTP(password, cache_byte);

  for (int i = 0; i < pw_sequence + 1; ++i)
  {
    Hash_Sha256(cache_byte, SHA256_DIGEST_LENGTH, cache_byte);
  }

  char generated_verify_point[65];
  byte2hexTOTP(cache_byte, SHA256_DIGEST_LENGTH, generated_verify_point);

  return strcmp(generated_verify_point, totp->VERIFY_POINT) == 0;
}
