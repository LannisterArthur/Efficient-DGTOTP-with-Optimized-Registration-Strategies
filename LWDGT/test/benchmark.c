#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#include "../thash.h"
#include "../api.h"
#include "../fors.h"
#include "../wotsx1.h"
#include "../params.h"
#include "../randombytes.h"
#include "cycles.h"

#define SPX_MLEN 32
#define NTESTS 1

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx *ctx,
                          uint32_t addr[8]);

static int cmp_llu(const void *a, const void *b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b)
        return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for (i = 0; i < llen - 1; i++)
    {
        l[i] = l[i + 1] - l[i];
    }
}

static void printfcomma(unsigned long long n)
{
    if (n < 1000)
    {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf(",%03llu", n % 1000);
}

static void printfalignedcomma(unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9)
    {
        len -= 1;
        ncopy /= 10;
        i += 1; // to account for commas
    }
    i = i / 3 - 1; // to account for commas
    for (; i < len; i++)
    {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul * med, 12);
    printf(" cycles\n");
}

static void save_result(FILE *fp, const char *preamble, unsigned long long *l, size_t llen)
{
    size_t i;

    fprintf(fp, "%s", preamble);
    for (i = 0; i < llen; i++)
        fprintf(fp, " %llu ", l[i]);
    fprintf(fp, "\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)      \
    printf(TEXT);                                     \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);  \
    for (i = 0; i < NTESTS; i++)                      \
    {                                                 \
        t[i] = cpucycles() / CORR;                    \
        FNCALL;                                       \
    }                                                 \
    t[NTESTS] = cpucycles();                          \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);   \
    result = ((stop.tv_sec - start.tv_sec) * 1e6 +    \
              (stop.tv_nsec - start.tv_nsec) / 1e3) / \
             (double)CORR;                            \
    display_result(result, t, NTESTS, MUL);
#define MEASURT(TEXT, MUL, FNCALL)         \
    MEASURE_GENERIC(                       \
        TEXT, MUL,                         \
        do {                               \
            for (int j = 0; j < 1000; j++) \
            {                              \
                FNCALL;                    \
            }                              \
        } while (0);                       \
        ,                                  \
        1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);
    init_cpucycles();

    spx_ctx ctx;

    unsigned char pk_myots[SPX_PK_BYTES];
    unsigned char sk_myots[SPX_SK_BYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm_myots = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout_myots = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *sm = malloc((SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +
                                SPX_FULL_HEIGHT * SPX_N + (SPX_D * COUNTER_SIZE)) +
                               COUNTER_SIZE + SPX_MLEN);
    unsigned char *mout = malloc((SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +
                                  SPX_FULL_HEIGHT * SPX_N + (SPX_D * COUNTER_SIZE)) +
                                 COUNTER_SIZE + SPX_MLEN);

    unsigned char fors_pk[SPX_FORS_PK_BYTES];
    unsigned char fors_m[SPX_FORS_MSG_BYTES];
    unsigned char fors_sig[SPX_FORS_BYTES];
    unsigned char addr[SPX_ADDR_BYTES];
    unsigned char block[SPX_N];

    unsigned char wots_pk[SPX_WOTS_PK_BYTES];

    unsigned long long smlen;
    unsigned long long mlen;
    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    unsigned int i;
    unsigned int fors_bits = 0;

    char filename[100];
    FILE *fp;
#define str(s) #s
#define xstr(s) str(s)

    printf("%s\n", xstr(PARAMS));
    randombytes(m, SPX_MLEN);
    randombytes(addr, SPX_ADDR_BYTES);
#ifdef SPX_FORS_ZERO_LAST_BITS
    fors_bits = SPX_FORS_ZERO_LAST_BITS;
#endif
    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d, t' = %d, size = %d\n",
           SPX_N, MYOTS_FULL_HEIGHT, MYOTS_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W, fors_bits, ALL_BYTES);
    sprintf(filename, "%s", xstr(PARAMS));

    fp = fopen(filename, "w+");
    fprintf(fp, "n= %d h = %d d= %d b= %d k= %d w= %d tprime= %d size= %d\n",
            SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
            SPX_WOTS_W, fors_bits, SPX_BYTES);
    printf("Running %d iterations.\n", NTESTS);

    // OTS-tree test
    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair_myots(pk_myots, sk_myots));
    save_result(fp, "Generate", t, NTESTS);
    MEASURE("  - WOTS pk gen..    ", (1 << MYOTS_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, (uint32_t *)addr));
    MEASURE("Signing..            ", 1, crypto_sign_myots(sm_myots, &smlen, m, SPX_MLEN, sk_myots));
    save_result(fp, "Sign", t, NTESTS);
    // MEASURE("  - WOTS pk gen..    ", MYOTS_D * (1 << MYOTS_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, (uint32_t *)addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open_myots(mout_myots, &mlen, sm_myots, smlen, pk_myots));
    save_result(fp, "Verifying", t, NTESTS);

    /* Added sanity checks for OTS-tree. */
    crypto_sign_keypair_myots(pk_myots, sk_myots);
    printf("testing sign, return value %d\n", crypto_sign_myots(sm_myots, &smlen, m, SPX_MLEN, sk_myots));
    printf("testing verify, return value %d\n", crypto_sign_open_myots(mout_myots, &mlen, sm_myots, smlen, pk_myots));

    // SPHINCS+C test
    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair(pk, sk));
    save_result(fp, "Generate", t, NTESTS);
    MEASURE("  - WOTS pk gen..    ", (1 << SPX_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, (uint32_t *)addr));
    MEASURE("Signing..            ", 1, crypto_sign(sm, &smlen, m, SPX_MLEN, sk));
    save_result(fp, "Sign", t, NTESTS);
    MEASURE("  - FORS signing..   ", 1, fors_sign(fors_sig, fors_pk, fors_m, &ctx, (uint32_t *)addr));
    save_result(fp, "ForsSign", t, NTESTS);
    MEASURE("  - WOTS pk gen..    ", SPX_D * (1 << SPX_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, (uint32_t *)addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open(mout, &mlen, sm, smlen, pk));

    /* Added sanity checks for SPHINCS+C. */
    crypto_sign_keypair(pk, sk);
    printf("testing sign, return value %d\n", crypto_sign(sm, &smlen, m, SPX_MLEN, sk));
    printf("testing verify, return value %d\n", crypto_sign_open(mout, &mlen, sm, smlen, pk));
    fprintf(fp, "Size %d\n", SPX_BYTES);

    printf("Signature size: %d (%.2f KiB)\n", SPX_BYTES, SPX_BYTES / 1024.0);
    printf("Public key size: %d (%.2f KiB)\n", SPX_PK_BYTES, SPX_PK_BYTES / 1024.0);
    printf("Secret key size: %d (%.2f KiB)\n", SPX_SK_BYTES, SPX_SK_BYTES / 1024.0);

    free(m);
    free(sm);
    free(mout);
    fclose(fp);

    return 0;
}

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx *ctx,
                          uint32_t addr[8])
{
    struct leaf_info_x1 leaf;
    unsigned steps[SPX_WOTS_LEN] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    wots_gen_leafx1(pk, ctx, 0, &leaf);
}
