#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <sys/time.h>
#include <string.h>

// #define OUTPUT

typedef struct
{
    int power_U;
    int U;           // number of group members
    int E;           // number of TOTP protocol instances
    long start_time; // start time
    long end_time;   // end time
    int delta_e;     // verify epoch
    int delta_s;     // password generation epoch
    int N;
    unsigned char iv[12]; // aes_gcm IV, fixed 12 bytes
    unsigned char aad[32];
    int aad_len;
} params;

extern params pms;

long long getTime(void);
void paramInit(void);
void printParams(void);
void byte_print_hex(const char *label, const unsigned char *data, size_t len);
void hex_print_hex(const char *label, const char *hexstr);
int hex2byte(char *str, unsigned char *out, int hexlen);
void byte2hex(unsigned char *byteArray, char *charArray, int bytelen);
void int2byte(const int IntValue, unsigned char *Chars);

#endif
