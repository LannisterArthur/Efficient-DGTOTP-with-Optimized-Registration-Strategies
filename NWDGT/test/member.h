
#ifndef MEMBER_H
#define MEMBER_H

#include <stddef.h>
#include <arpa/inet.h> // for htonl
#include "dgtotp_prf.h"
#include "common.h"

typedef struct
{
    unsigned char key[16];      // member secret key or its PRF key, byte
    unsigned char ID[16];       // for simplicity,call PRF creaet_key to set the ID, byte
    unsigned char *vp;          // verify points, hex
    unsigned char merkle_proof; // merkle proof, hex, (TODO)

} member;

void Minit(TOTP *totp, member *m)
{
    // m->merkle_proof = malloc(pms.E * sizeof(unsigned char *));
    m->vp = malloc(pms.E * 65);

    // set secret key and ID
    create_key(m->key);
    create_key(m->ID);

#ifdef OUTPUT
    byte_print_hex("m->key", m->key, 16);
    byte_print_hex("m->ID", m->ID, 16);
#endif

    // totp sk seed
    unsigned char tempIn[16 + sizeof(int)];
    unsigned char tempOut[2 * 16];
    memcpy(tempIn, m->ID, 16);

    int net_i;
    // generate vp
    // set to 1024, note make sure E>1024
    for (int i = 0; i < 1; i++) // only init one epoch vp, when test Minit set to pms.E
    {
        // add i behind ID
        net_i = htonl(i);
        memcpy(tempIn + 16, &net_i, sizeof(int));
#ifdef OUTPUT
        byte_print_hex("totp.sk_seed tempIn after appending index", tempIn, 16 + sizeof(int));
#endif

        // totp.sk_seed = F(sk_ID,ID||i)
        aes_encrypt(tempIn, 16 + sizeof(int), m->key, tempOut);
        byte2hex(tempOut, totp->SK_SEED, 32);
#ifdef OUTPUT
        hex_print_hex("totp->SK_SEED", totp->SK_SEED);
#endif

        // // test decrypt
        // unsigned char decryptedtext[32];
        // aes_decrypt(tempOut, 32, m->key, decryptedtext);
        // byte_print_hex("decrypted", decryptedtext, 32);

        totpPInit(totp);
#ifdef OUTPUT
        hex_print_hex("totp->VERIFY_POINT", totp->VERIFY_POINT);
#endif

        memcpy(m->vp + i * 65, totp->VERIFY_POINT, 65);

        // // test totpverify
        // int result = totpVerify(totp, totp->SK_SEED, 0);
        // printf("Verification result: %s\n", (result == 1) ? "Success" : "Failure");
    }
}

// seed hex[65]
void GetSD(member *m, long long time, unsigned char *seed)
{
    int chain_index = (int)((time - pms.start_time) / pms.delta_e);

    // totp sk seed
    unsigned char tempIn[16 + sizeof(int)];
    unsigned char tempOut[2 * 16];
    memcpy(tempIn, m->ID, 16);
    int net_i = htonl(chain_index);
    memcpy(tempIn + 16, &net_i, sizeof(int));

    aes_encrypt(tempIn, 16 + sizeof(int), m->key, tempOut);
    byte2hex(tempOut, seed, 32);
}

#endif
