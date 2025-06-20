#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <openssl/sha.h>

#define MAX_TRANSACTIONS 1 << 20
#define HASH_LENGTH 64 // SHA256 hex output length

typedef struct
{
    char transactions[MAX_TRANSACTIONS][HASH_LENGTH + 1];
    char root[HASH_LENGTH + 1];
    int num_transactions;
} MerkleTree;

// Function declarations
void init_merkle_tree(MerkleTree *tree, char transactions[][HASH_LENGTH + 1], int num);
void build_merkle_tree(MerkleTree *tree);
char *compute_sha256_hex(const char *str, char outputBuffer[HASH_LENGTH + 1]);
char *get_merkle_root(MerkleTree *tree);
int verify_merkle_proof(char proof[][HASH_LENGTH + 1], int proof_size, const char *verify_point, const char *root, int index);
void get_proof(char proof[][HASH_LENGTH + 1], MerkleTree *tree, const char *node, int index);

#endif
