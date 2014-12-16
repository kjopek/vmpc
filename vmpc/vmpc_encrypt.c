#include <stdint.h>
#include <stdlib.h>

#include "vmpc_encrypt.h"

int
vmpc_clean(struct vmpc_ctx *ctx)
{
	int i = 0;

	if (ctx == NULL)
		return VMPC_CTX_ERR;

	free((void*) ctx);
	return VMPC_OK;
}

struct vmpc_ctx *
vmpc_ksa(uint8_t key_len, uint8_t *key, uint8_t iv_len, uint8_t *iv)
{
	uint8_t n = 0;
	uint8_t tmp = 0;
	uint16_t m = 0;

	int i = 0;

    struct vmpc_ctx *ctx = (struct vmpc_ctx *) malloc(sizeof(struct vmpc_ctx));

    if (ctx == NULL)
		return NULL;

    ctx->s = 0;
    ctx->n = 0;

	for (i=0; i<256; ++i)
        ctx->P[i] = (uint8_t) i;

	for (m=0; m<768; ++m) {
        n = m & 0xff;
        ctx->s = ctx->P[(ctx->s+ctx->P[n]+key[m % key_len]) & 0xff];
        tmp = ctx->P[n];
        ctx->P[n] = ctx->P[ctx->s];
        ctx->P[ctx->s] = tmp;
	}

    if (16 <= iv_len && iv_len <= 64) {
		for (m=0; m<=768; ++m) {
            n = m & 0xff;
            ctx->s = ctx->P[(ctx->s + ctx->P[n] + iv[m % iv_len]) & 0xff];
            tmp = ctx->P[n];
            ctx->P[n] = ctx->P[ctx->s];
            ctx->P[ctx->s] = tmp;
		}
	}

    return ctx;
}

uint8_t
vmpc_yield(struct vmpc_ctx *context)
{
	uint8_t tmp;
	uint8_t ret;

    context->s = context->P[(context->s+context->P[context->n]) & 0xff];
    ret = context->P[(context->P[context->P[context->s]] + 1) & 0xff];

    tmp = context->P[context->n];
	context->P[context->n] = context->P[context->s];
	context->P[context->s] = tmp;
    context->n = (context->n + 1) & 0xff;
	return ret;
}

int
vmpc_encrypt(struct vmpc_ctx *context, uint8_t *input, uint8_t *output, size_t len)
{
	size_t i = 0;

	if (context == NULL)
		return VMPC_NO_MEM;

	for (i=0; i<len; ++i) {
        output[i] = input[i] ^ vmpc_yield(context);
	}
	return VMPC_OK;
}
