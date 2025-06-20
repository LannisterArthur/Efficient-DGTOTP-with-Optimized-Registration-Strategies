#include "merkle_tree.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"

// Initialize the Merkle Tree with transactions
void init_merkle_tree(MerkleTree *tree, char transactions[][HASH_LENGTH + 1], int num)
{
  tree->num_transactions = num;
  for (int i = 0; i < num; i++)
  {
    strncpy(tree->transactions[i], transactions[i], HASH_LENGTH);
  }
}

// Compute the SHA-256 hash and return it as a hex string
char *compute_sha256_hex(const char *str, char outputBuffer[HASH_LENGTH + 1])
{
  unsigned char hash[SHA256_DIGEST_LENGTH], temp[2 * SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  hex2byte(str, temp, 2 * HASH_LENGTH);
  SHA256_Update(&sha256, temp, 2 * SHA256_DIGEST_LENGTH);
  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    // sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    byte2hex(hash, outputBuffer, HASH_LENGTH / 2);
  }
  outputBuffer[HASH_LENGTH] = '\0';

#ifdef OUTPUT
  printf("SHA-256 hash: %s\n", outputBuffer);
#endif

  return outputBuffer;
}

// Build the Merkle tree
void build_merkle_tree(MerkleTree *tree)
{
  int num = tree->num_transactions;
  static temp[MAX_TRANSACTIONS][HASH_LENGTH + 1];

  // Copy transactions into the temp array
  for (int i = 0; i < num; i++)
  {
    strncpy(temp[i], tree->transactions[i], HASH_LENGTH);
  }

  while (num > 1)
  {
    int new_num = 0;

    for (int i = 0; i < num; i += 2)
    {
      char concatenated[2 * HASH_LENGTH + 1];
      char left[HASH_LENGTH + 1], right[HASH_LENGTH + 1];

      // Left node
      strncpy(left, temp[i], HASH_LENGTH);
      if (i + 1 < num)
      {
        // Right node
        strncpy(right, temp[i + 1], HASH_LENGTH);
      }
      else
      {
        // If no right node, right = left (duplicate)
        strncpy(right, left, HASH_LENGTH);
      }

      // Concatenate left and right
      // snprintf(concatenated, sizeof(concatenated), "%s%s", left, right);
      memcpy(concatenated, left, HASH_LENGTH);
      memcpy(concatenated + HASH_LENGTH, right, HASH_LENGTH);

      // Hash the concatenated string and store in the new layer
      compute_sha256_hex(concatenated, temp[new_num]);
      new_num++;
    }
    num = new_num;
  }
  // The last remaining element is the root
  strncpy(tree->root, temp[0], HASH_LENGTH);
  tree->root[HASH_LENGTH] = '\0';
}

// Get the Merkle root
char *get_merkle_root(MerkleTree *tree)
{
  return tree->root;
}

// Verify Merkle proof
int verify_merkle_proof(char proof[][HASH_LENGTH + 1], int proof_size, const char *verify_point, const char *root, int index)
{
  char hash[HASH_LENGTH + 1];
  strncpy(hash, verify_point, HASH_LENGTH);

  for (int i = 0; i < proof_size; i++)
  {
    char temp[2 * HASH_LENGTH + 1];

    if (index % 2 == 0)
    {
      // Concatenate hash + proof[i]
      // snprintf(temp, sizeof(temp), "%s%s", hash, proof[i]);
      memcpy(temp, hash, HASH_LENGTH);
      memcpy(temp + HASH_LENGTH, proof[i], HASH_LENGTH);
    }
    else
    {
      // Concatenate proof[i] + hash
      // snprintf(temp, sizeof(temp), "%s%s", proof[i], hash);
      memcpy(temp, proof[i], HASH_LENGTH);
      memcpy(temp + HASH_LENGTH, hash, HASH_LENGTH);
    }
    // Compute new hash
    compute_sha256_hex(temp, hash);
    index /= 2;
  }

  // Compare with the root
  return memcmp(hash, root, HASH_LENGTH) == 0;
}

// Get proof for a specific transaction
void get_proof(char proof[][HASH_LENGTH + 1], MerkleTree *tree, const char *node, int index)
{
  int current_level_size = tree->num_transactions;
  int proof_index = 0;
  static current_level[MAX_TRANSACTIONS][HASH_LENGTH + 1];

  // Copy transactions to current level
  for (int i = 0; i < current_level_size; i++)
  {
    strncpy(current_level[i], tree->transactions[i], HASH_LENGTH);
  }

  // Traverse up the tree
  while (current_level_size > 1)
  {
    int new_level_size = 0;
    char new_level[MAX_TRANSACTIONS][HASH_LENGTH + 1];

    for (int i = 0; i < current_level_size; i += 2)
    {
      char concatenated[2 * HASH_LENGTH + 1];
      char left[HASH_LENGTH + 1], right[HASH_LENGTH + 1];

      // Left node
      strncpy(left, current_level[i], HASH_LENGTH);
      if (i + 1 < current_level_size)
      {
        // Right node
        strncpy(right, current_level[i + 1], HASH_LENGTH);
      }
      else
      {
        // No right node, so duplicate left node
        strncpy(right, left, HASH_LENGTH);
      }

      // Concatenate left and right nodes
      // snprintf(concatenated, sizeof(concatenated), "%s%s", left, right);
      memcpy(concatenated, left, HASH_LENGTH);
      memcpy(concatenated + HASH_LENGTH, right, HASH_LENGTH);

      // Compute new hash for the next level
      compute_sha256_hex(concatenated, new_level[new_level_size]);
      new_level_size++;

      // If the current node is part of the proof, add its sibling to the proof list
      if (i == index || i + 1 == index)
      {
        if (i == index)
        {
          strncpy(proof[proof_index], right, HASH_LENGTH);
        }
        else
        {
          strncpy(proof[proof_index], left, HASH_LENGTH);
        }
        proof[proof_index][HASH_LENGTH] = '\0';
        proof_index++;
      }
    }

    // Update index for the next level
    index /= 2;
    current_level_size = new_level_size;

    // Copy new level back to current level
    for (int i = 0; i < current_level_size; i++)
    {
      strncpy(current_level[i], new_level[i], HASH_LENGTH);
    }
  }
}
