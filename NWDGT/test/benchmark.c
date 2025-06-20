#define _POSIX_C_SOURCE 199309L
#pragma once

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

#include <sys/time.h>
#include "common.h"
#include "totp.h"
#include "merkle_tree.h"
#include "dgtotp_prf.h"
#include "member.h"
#include "RA.h"

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

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx *ctx,
                          uint32_t addr[8])
{
    struct leaf_info_x1 leaf;
    unsigned steps[SPX_WOTS_LEN] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    wots_gen_leafx1(pk, ctx, 0, &leaf);
}

// TOTP test
void totp_test()
{
    TOTP totp;

    // params init
    totpSetup(&totp, 20, 0, 180, 60); // k=20, start_time=0, end_time=180, pass_gen=60
    totpgetSeed(&totp, "secret_key");

    // password generation
    char password[65];
    totpPGen(&totp, 1, password);
    printf("Generated Password 1: %s\n", password);

    totpPGen(&totp, 2, password);
    printf("Generated Password 2: %s\n", password);

    // totp init and password verification
    totpPInit(&totp);
    printf("Verify Point: %s\n", totp.VERIFY_POINT);

    int result = totpVerify(&totp, password, 2);
    printf("Verification result: %s\n", (result == 1) ? "Success" : "Failure");
}

// Merkle tree test
void merkle_tree_test()
{
    // Example transactions (hashed for simplicity)
    char transactions[4][HASH_LENGTH + 1] = {
        "a5f4b6c47f5a9bdfdfb992f5ae6e9a5b01",
        "9f9f4e6f67f7f59f5e59ff9f4a6a9c5eaa", // 90ab8ddd856d1fdc6496e5c2ac7aaec791ebbf9c2662ddf89420d92dbeb20398
        "c2a5f49c35e94f5b52f49c67c67a5a97ff",
        "f5f4b9e6e6a5b6b5b9e6c9f9a6c9f7f7ff"}; // d0223b97196dcfd5db13a955aeb229918267ed641499ff679c69caefbbd2c69b

    // char label[64];
    // for (int i = 0; i < 4; i++)
    // {
    //     sprintf(label, "leaf[%d] is", i);
    //     hex_print_hex(label, transactions[i]);
    // }

    int test_index = 2;
    // Initialize the Merkle tree
    MerkleTree tree;
    init_merkle_tree(&tree, transactions, 4);

    // Build the Merkle tree
    build_merkle_tree(&tree);

    // Get the root
    printf("Merkle Root: %s\n", get_merkle_root(&tree));

    // Get proof for a specific transaction
    char proof[10][HASH_LENGTH + 1]; // Assuming proof size can be up to 10
    get_proof(proof, &tree, transactions[test_index], test_index);

    // Output Merkle proof
    printf("Merkle Proof for transaction %d:\n", test_index);
    for (int i = 0; i < 2; i++)
    {
        printf("Proof[%d]: %s\n", i, proof[i]);
    }

    // Verify the proof
    int valid = verify_merkle_proof(proof, 2, transactions[test_index], get_merkle_root(&tree), test_index);
    printf("Verification result: %s\n", valid ? "Valid" : "Invalid");
}

int prf_test()
{
    unsigned char key[AES_KEY_SIZE];
    unsigned char plaintext[] = "Hello, this is a test message!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    // Create AES key
    if (create_key(key) != 0)
    {
        printf("Failed to create key\n");
        return -1;
    }

    // Print the generated key
    printf("AES Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Encrypt the plaintext
    int ciphertext_len = aes_encrypt(plaintext, strlen((char *)plaintext), key, ciphertext);

    if (ciphertext_len < 0)
    {
        printf("Encryption failed\n");
        return -1;
    }

    printf("Ciphertext (hex): ");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, decryptedtext);

    if (decryptedtext_len < 0)
    {
        printf("Decryption failed\n");
        return -1;
    }

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted Text: %s\n", decryptedtext);
}

void ASE_test(member m)
{
    unsigned char ciphertext[16 + 16];
    int ciphertext_len = ASE_enc(m.ID, 16, m.key, ciphertext);
    if (ciphertext_len < 0)
    {
        fprintf(stderr, "Encryption failed\n");
        exit(EXIT_FAILURE);
    }
    byte_print_hex("ASE encrypted ID(include tag)", ciphertext, 32);

    unsigned char decryptedtext[16];
    int decryptedtext_len = ASE_dec(ciphertext, ciphertext_len, m.key, decryptedtext);
    if (decryptedtext_len < 0)
    {
        fprintf(stderr, "Decryption failed\n");
        exit(EXIT_FAILURE);
    }
    byte_print_hex("decrypted ID", decryptedtext, 16);
}

void PM_test()
{
    // E times permutationn
    for (int j = 0; j < pms.E; j++)
    {
        unsigned int *cur_table = ra.per_table + j * pms.U;

        for (int i = 0; i < pms.U; i++)
        {
            cur_table[i] = i;
        }

        srand(ra.PM_seed[j]);
        permutation(cur_table, pms.U);
    }

    for (int j = 0; j < pms.E; j++)
    {
        printf("Permutation %d: ", j + 1);
        for (int i = 0; i < pms.U; i++)
        {
            printf("%u ", ra.per_table[j * pms.U + i]);
        }
        printf("\n");
    }
}

int Findindex(unsigned int *pm_table, int i)
{
    int j;
    for (j = 0; j < pms.U; j++)
        if (pm_table[j] == i)
        {
            printf("%d in permutation's index is %d\n", i, j);
            return j;
        }
}

void Minit_test()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);
    init_cpucycles();

    paramInit();
    printParams();

    member m;
    TOTP totp;
    totp.N = pms.N;

    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    unsigned int i;

    MEASURE("Member init..               ", 1, Minit(&totp, &m));
}

// verifier, leaf not used
int Verify(TOTP totp, char *totppwd, int sequence, unsigned char *Ax, char *proof, int leafindex, char *pk, unsigned char *sk, unsigned char *sm, unsigned long long smlen, MerkleTree *tree)
{
    // TODO: generate updated vp
    char tempvp[64 + 32 * 2 + sizeof(int)]; // vp + ID cipher + i
    char hash[HASH_LENGTH + 1];

    memcpy(tempvp, totp.VERIFY_POINT, 64);
    byte2hex(Ax, tempvp + 64, 32);
    int2byte(0, tempvp + 64 + 32 * 2);

#ifdef OUTPUT
    hex_print_hex("In verify() preimage of updated vp is", tempvp);
#endif
    compute_sha256_hex(tempvp, hash);

    // verify totp password
    int result = totpVerify(&totp, totppwd, sequence);
#ifdef OUTPUT
    printf("totp password Verification result: %s\n", (result == 1) ? "Success" : "Failure");
#endif

    // Verify merkle proof
    int valid1 = verify_merkle_proof(proof, pms.power_U, hash, get_merkle_root(tree), leafindex);
#ifdef OUTPUT
    printf("merkle proof Verification result: %s\n", valid1 ? "Valid" : "Invalid");
#endif

    unsigned long long mlen;
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    int valid2 = crypto_sign_open(mout, &mlen, sm, smlen, pk);
#ifdef OUTPUT
    printf("testing hypertree verify, return value %d\n", valid2);
#endif

    free(mout);

    if (result != 1 || valid1 != 1 || valid2 != 0)
        return 0;
    return 1;
}

void test()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);
    init_cpucycles();

    spx_ctx ctx;

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *msg = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);

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

#ifdef SPX_FORS_ZERO_LAST_BITS
    fors_bits = SPX_FORS_ZERO_LAST_BITS;
#endif

    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d, t' = %d, size = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W, fors_bits, SPX_BYTES);

    char label[64];

    /***  runtime  ***/
    /*
        setup
    */
    paramInit();
    printParams();
    member m[pms.U];
    TOTP totp;
    static MerkleTree tree;
    tree.num_transactions = pms.U;
    totp.N = pms.N;

    // output, test member initialization
    for (int i = 0; i < pms.U; i++)
    {
        Minit(&totp, &m[i]);

#ifdef OUTPUT
        sprintf(label, "member[%d] key is", i);
        byte_print_hex(label, m[i].key, AES_KEY_SIZE);

        sprintf(label, "ID[%d] is", i);
        byte_print_hex(label, m[i].ID, AES_KEY_SIZE);
#endif
    }
    // output, test permutation, make sure setupRA first
    RASetup();
    GMUPdate();
    // gpk generation
    MEASURE("Generating keypair(Setup).. ", 1, crypto_sign_keypair(pk, sk));

    /*
        Join
    */
    // test join, part of password: id ciphertext
    unsigned char Ax[pms.U][32];
    for (int i = 0; i < pms.U; i++)
        Join(m[i].ID, m[i].vp, 0, Ax[i]);
    MEASURE("Join..                      ", 1, Join(m[0].ID, m[0].vp, 0, Ax[0]));

    char tempvp[64 + 32 * 2 + sizeof(int)]; // vp + ID cipher + i
    for (int i = 0; i < pms.U; i++)
    {
        // determine poisition by permutation, bind identity ciphertext
        memcpy(tempvp, m[ra.per_table[i]].vp, 64);
        byte2hex(Ax[ra.per_table[i]], tempvp + 64, 32);
        int2byte(0, tempvp + 64 + 32 * 2);

#ifdef OUTPUT
        hex_print_hex("preimage of updated vp is", tempvp);
#endif
        compute_sha256_hex(tempvp, tree.transactions[i]);
    }
    // output, leaf nodes
#ifdef OUTPUT
    for (int i = 0; i < pms.U; i++)
    {
        sprintf(label, "leaf[%d] is", i);
        hex_print_hex(label, tree.transactions[i]);
    }
#endif

    /*
        vp tree build, hypertree sign the root
    */
    // Build the Merkle tree
    build_merkle_tree(&tree);
    // output, Get the root
#ifdef OUTPUT
    printf("Merkle Root: %s\n", get_merkle_root(&tree));
#endif

    // Get proof for a specific transaction, part of password: merkle proof
    int test_index = Findindex(ra.per_table, pms.U - 1); // set index to the last member's position
    char proof[30][HASH_LENGTH + 1];                     // Assuming proof size can be up to 30
    // get_proof(proof, &tree, tree.transactions[test_index], test_index);
    MEASURE("Signing..                   ", 1, get_proof(proof, &tree, tree.transactions[test_index], test_index));
    // Output Merkle proof
#ifdef OUTPUT
    printf("Merkle Proof for transaction %d:\n", test_index);
    for (int i = 0; i < 2; i++)
    {
        printf("Proof[%d]: %s\n", i, proof[i]);
    }
#endif

    MEASURE("Signing..                   ", 1, crypto_sign(sm, &smlen, msg, SPX_MLEN, sk));

    /*
        verify
    */
    char totppassword[65];
    totpPGen(&totp, pms.N - 1, totppassword);
    printf("verifyer result is %d\n", Verify(totp, totppassword, pms.N - 1, Ax[pms.U - 1], proof, test_index, pk, sk, sm, smlen, &tree));
    MEASURE("Verify..                    ", 1, Verify(totp, totppassword, pms.N - 1, Ax[pms.U - 1], proof, test_index, pk, sk, sm, smlen, &tree));

    /*
        open without verify
    */
    Open(Ax[0]);
    MEASURE("Open..                      ", 1, Open(Ax[0]));
}

int main()
{
    test();
    // Minit_test();
    return 0;
}