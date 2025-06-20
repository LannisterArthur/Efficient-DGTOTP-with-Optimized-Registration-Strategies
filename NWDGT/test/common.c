#include "common.h"
#include "../params.h"

params pms;

long long getTime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long milliseconds = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    printf("Current time: %ld milliseconds since the Epoch\n", milliseconds);
    return milliseconds;
}

void paramInit(void)
{
    pms.power_U = 14;
    pms.U = 1 << pms.power_U;
    pms.E = 1; // 105120 * 2
    pms.delta_e = 300000;
    pms.delta_s = 5000;
    pms.N = pms.delta_e / pms.delta_s;
    pms.start_time = getTime();
    pms.end_time = pms.start_time + pms.E * pms.delta_e;

    unsigned char fixed_iv[12] = {
        0xA1, 0xA2, 0xA3, 0xA4,
        0xA5, 0xA6, 0xA7, 0xA8,
        0xA9, 0xAA, 0xAB, 0xAC};
    memcpy(pms.iv, fixed_iv, 12);

    const char *fixed_aad = "FixedAAD";
    pms.aad_len = (int)strlen(fixed_aad);
    memset(pms.aad, 0, sizeof(pms.aad));
    memcpy(pms.aad, fixed_aad, pms.aad_len);
}

void printParams(void)
{
    printf("pms.U = %d\n", pms.U);
    printf("pms.E = %d\n", pms.E);
    printf("pms.delta_e = %d\n", pms.delta_e);
    printf("pms.delta_s = %d\n", pms.delta_s);
    printf("pms.N = %d\n", pms.N);
    printf("pms.start_time = %ld\n", pms.start_time);
    printf("pms.end_time = %ld\n", pms.end_time);
}

void byte_print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void hex_print_hex(const char *label, const char *hexstr)
{
    printf("%s: %s\n", label, hexstr);
}

int hex2byte(char *str, unsigned char *out, int hexlen)
{
    char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p), cnt = 0;
    while (cnt < (hexlen / 2))
    {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
        low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if (tmplen % 2 != 0)
        out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

    return tmplen / 2 + tmplen % 2;
}

void byte2hex(unsigned char *byteArray, char *charArray, int bytelen)
{
    int length = 32 * 2;
    for (int i = 0; i < bytelen; ++i)
    {
        sprintf(charArray + i * 2, "%02X", byteArray[i]);
    }
}

void int2byte(const int IntValue, unsigned char *Chars)
{
    int numBytes = sizeof(int);
    for (int i = 0; i < numBytes; ++i)
    {
        Chars[i] = (IntValue >> (8 * (numBytes - 1 - i))) & 255;
    }
}