#if !defined(MERKLE_H_)
#define MERKLE_H_

#include <stdint.h>

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf, uint32_t *counter_out);

/* Compute the root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx);

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
void merkle_sign_myots(uint8_t *sig, unsigned char *root,
                       const spx_ctx *ctx,
                       uint32_t wots_addr[8], uint32_t tree_addr[8],
                       uint32_t idx_leaf, uint32_t *counter_out);

/* Compute the root node of the top-most subtree. */
void merkle_gen_root_myots(unsigned char *root, const spx_ctx *ctx);

#endif /* MERKLE_H_ */
