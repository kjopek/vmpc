#ifndef _VMPC_ENCRYPT_H
#define _VMPC_ENCRYPT_H

#include <stdint.h>

#define VMPC_OK	        0x00000000
#define VMPC_NO_MEM     0x00000001
#define VMPC_CTX_ERR    0x00000002

struct vmpc_ctx {
    uint8_t P[256];
    uint8_t s;
    uint8_t n;
};

struct vmpc_ctx *vmpc_ksa(uint8_t c, uint8_t *K, uint8_t z, uint8_t *V);
int vmpc_clean(struct vmpc_ctx *ctx);
uint8_t vmpc_yield(struct vmpc_ctx *ctx);
int vmpc_encrypt(struct vmpc_ctx *ctx, uint8_t *input, uint8_t *output, size_t len);

#endif /* !_VMPC_ENCRYPT_H */
