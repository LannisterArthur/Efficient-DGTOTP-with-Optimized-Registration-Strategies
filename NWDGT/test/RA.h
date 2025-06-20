
#ifndef RA_H
#define RA_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include "dgtotp_prf.h"
#include "common.h"

typedef struct
{
    unsigned char *RL;        // revocation list
    unsigned int *PM_seed;    // permutation seed
    unsigned char key_ra[16]; // secret key of RA, byte
    unsigned int *per_table;  // permutataion result
    unsigned char *mvp;       // member vps
    unsigned char *mid;       // member IDs

} RA;

RA ra;

void RASetup()
{
    // initialize revocation list
    ra.RL = (unsigned char *)malloc(pms.U * sizeof(unsigned char));
    for (int i = 0; i < pms.U; i++)
        ra.RL[i] = 1;

    // initialize permutation seed
    srand(time(NULL));
    ra.PM_seed = (unsigned int *)malloc(pms.E * sizeof(unsigned int));
    for (int i = 0; i < pms.E; i++)
        ra.PM_seed[i] = rand();

    // generate secret key of RA
    create_key(ra.key_ra);

    // initialize pm result
    ra.per_table = (unsigned int *)malloc(pms.U * pms.E * sizeof(unsigned int));
}

void permutation(unsigned int *array, int n)
{
    for (int i = n - 1; i > 0; i--)
    {
        int idx = rand() % (i + 1);
        unsigned int temp = array[i];
        array[i] = array[idx];
        array[idx] = temp;
    }
}

void GMUPdate()
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

#ifdef OUTPUT
    for (int j = 0; j < pms.E; j++)
    {
        printf("Permutation %d: ", j + 1);
        for (int i = 0; i < pms.U; i++)
        {
            printf("%u ", ra.per_table[j * pms.U + i]);
        }
        printf("\n");
    }
#endif

    // group management message(ID cipher)       TODO
}

// take ID and its vp in one epoch, return auxilary information
void Join(unsigned char *ID, unsigned char *vp, long long time, unsigned char *Ax)
{
    // need time
    int ciphertext_len = ASE_enc(ID, 16, ra.key_ra, Ax);
    if (ciphertext_len < 0)
    {
        fprintf(stderr, "Encryption failed\n");
        exit(EXIT_FAILURE);
    }

#ifdef OUTPUT
    byte_print_hex("ASE encrypted ID(include tag)", Ax, 32);
#endif

    // // test decrypt
    // unsigned char decryptedtext[16];
    // int decryptedtext_len = ASE_dec(Ax, ciphertext_len, ra.key_ra, decryptedtext);
    // if (decryptedtext_len < 0)
    // {
    //     fprintf(stderr, "Decryption failed\n");
    //     exit(EXIT_FAILURE);
    // }
    // byte_print_hex("decrypted ID", decryptedtext, 16);
}

void Open(unsigned char *Ax)
{
    // test decrypt
    unsigned char decryptedtext[16];
    int decryptedtext_len = ASE_dec(Ax, 32, ra.key_ra, decryptedtext);
    if (decryptedtext_len < 0)
    {
        fprintf(stderr, "Decryption failed\n");
        exit(EXIT_FAILURE);
    }

#ifdef OUTPUT
    byte_print_hex("decrypted ID", decryptedtext, 16);
#endif
}

#endif