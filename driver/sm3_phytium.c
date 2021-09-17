/*
 * File Name:sm3_phytium.c - Phytium SDK for SM3
 *
 * Copyright (C) 2020 Phytium Technology Co.,Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <asm/memory.h>
#include <linux/delay.h>
#include <crypto/internal/hash.h>
#include <crypto/hash.h>
#include <linux/io.h>
#include <linux/crypto.h>
#include <asm/cacheflush.h>
#include "smx_common.h"
#include "sm3_phytium.h"
#include "phytium_scto.h"

#if SCTO_KERNEL_MODE


static void sm3_init(struct sm3_context *ctx)
{
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x7380166F;
	ctx->state[1] = 0x4914B2B9;
	ctx->state[2] = 0x172442D7;
	ctx->state[3] = 0xDA8A0600;
	ctx->state[4] = 0xA96F30BC;
	ctx->state[5] = 0x163138AA;
	ctx->state[6] = 0xE38DEE4D;
	ctx->state[7] = 0xB0FB0E4E;
}
static void sm3_process(struct sm3_context *ctx, const u8 data[64])
{
	u32 SS1, SS2, TT1, TT2, W[68], W1[64];
	u32 A, B, C, D, E, F, G, H;
	u32 T[64];
	u32 Temp1, Temp2, Temp3, Temp4, Temp5;
	int j;

	for (j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for (j = 16; j < 64; j++)
		T[j] = 0x7A879D8A;

	GET_UINT32_BE(W[0], data,  0);
	GET_UINT32_BE(W[1], data,  4);
	GET_UINT32_BE(W[2], data,  8);
	GET_UINT32_BE(W[3], data, 12);
	GET_UINT32_BE(W[4], data, 16);
	GET_UINT32_BE(W[5], data, 20);
	GET_UINT32_BE(W[6], data, 24);
	GET_UINT32_BE(W[7], data, 28);
	GET_UINT32_BE(W[8], data, 32);
	GET_UINT32_BE(W[9], data, 36);
	GET_UINT32_BE(W[10], data, 40);
	GET_UINT32_BE(W[11], data, 44);
	GET_UINT32_BE(W[12], data, 48);
	GET_UINT32_BE(W[13], data, 52);
	GET_UINT32_BE(W[14], data, 56);
	GET_UINT32_BE(W[15], data, 60);

#define FF0(x, y, z)	((x) ^ (y) ^ (z))
#define FF1(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z)	((x) ^ (y) ^ (z))
#define GG1(x, y, z)	(((x) & (y)) | ((~(x)) & (z)))

#define SHL(x, n)	((x) << (n))
#define ROTL(x, n)	(SHL((x), (n) & 0x1F) | ((x) >> (32 - ((n) & 0x1F))))

#define P0(x)	((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x)	((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

	for (j = 16; j < 68; j++) {
		/*
		 * W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^
		 *        ROTL(W[j - 13],7 ) ^ W[j-6];
		 */

		Temp1 = W[j - 16] ^ W[j - 9];
		Temp2 = ROTL(W[j - 3], 15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13], 7) ^ W[j - 6];
		W[j] = Temp4 ^ Temp5;
	}

	for (j =  0; j < 64; j++)
		W1[j] = W[j] ^ W[j + 4];

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];

	for (j = 0; j < 16; j++) {
		SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
		SS2 = SS1 ^ ROTL(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {
		SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
		SS2 = SS1 ^ ROTL(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F, 19);
		F = E;
		E = P0(TT2);
	}

	ctx->state[0] ^= A;
	ctx->state[1] ^= B;
	ctx->state[2] ^= C;
	ctx->state[3] ^= D;
	ctx->state[4] ^= E;
	ctx->state[5] ^= F;
	ctx->state[6] ^= G;
	ctx->state[7] ^= H;
}

static void sm3_update(struct sm3_context *ctx, const u8 *input, size_t ilen)
{
	size_t fill;
	size_t left;

	if (!ilen)
		return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += ilen;

	if (ctx->total[0] < ilen)
		ctx->total[1]++;

	if (left && ilen >= fill) {
		memcpy(ctx->buffer + left, input, fill);
		sm3_process(ctx, ctx->buffer);
		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64) {
		sm3_process(ctx, input);
		input += 64;
		ilen -= 64;
	}

	if (ilen > 0)
		memcpy(ctx->buffer + left, input, ilen);
}
static const u8 sm3_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void sm3_final(struct sm3_context *ctx, u8 output[32])
{
	u32 last, padn;
	u32 high, low;
	u8 msglen[8];

	high = (ctx->total[0] >> 29) | (ctx->total[1] <<  3);
	low  = ctx->total[0] << 3;

	PUT_UINT32_BE(high, msglen, 0);
	PUT_UINT32_BE(low,  msglen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	sm3_update(ctx, sm3_padding, padn);
	sm3_update(ctx, msglen, 8);

	PUT_UINT32_BE(ctx->state[0], output,  0);
	PUT_UINT32_BE(ctx->state[1], output,  4);
	PUT_UINT32_BE(ctx->state[2], output,  8);
	PUT_UINT32_BE(ctx->state[3], output, 12);
	PUT_UINT32_BE(ctx->state[4], output, 16);
	PUT_UINT32_BE(ctx->state[5], output, 20);
	PUT_UINT32_BE(ctx->state[6], output, 24);
	PUT_UINT32_BE(ctx->state[7], output, 28);
}

//set the input iterator data 
static inline void sm3_set_data(u32 *data)
{
	scto.hash_reg->hash_in[0] = data[0];
	scto.hash_reg->hash_in[1] = data[1];
	scto.hash_reg->hash_in[2] = data[2];
	scto.hash_reg->hash_in[3] = data[3];
	scto.hash_reg->hash_in[4] = data[4];
	scto.hash_reg->hash_in[5] = data[5];
	scto.hash_reg->hash_in[6] = data[6];
	scto.hash_reg->hash_in[7] = data[7];
}

static inline void sm3_dma(long in, long out, u32 byteLen)
{
	//src addr
	scto.dma_reg->saddr0 = (in >> 2) & 0xFFFFFFFF;
	scto.dma_reg->saddr1 = (in >> 34) & 0x0FFF;

	//dst addr
	scto.dma_reg->daddr0 = (out >> 2) & 0xFFFFFFFF;
	scto.dma_reg->daddr1 = (out >>34) & 0x0FFF;

	//data word length
	scto.dma_reg->len = (byteLen >> 2);

	//clear flag
	scto.smx_reg->sr_2 = 2;

	//store cfg
	scto.smx_reg->cmd = 2;

	dsb(sy);
	//start
	scto.smx_reg->cr = 1;

	do{
		dsb(sy);
	}while(!(scto.smx_reg->sr_2 & 2));
}

static inline void sm3_reverse_word(u32 *in, u32 *out)
{
	out[0] = in[3];
	out[1] = in[2];
	out[2] = in[1];
	out[3] = in[0];
	out[4] = in[7];
	out[5] = in[6];
	out[6] = in[5];
	out[7] = in[4];
}


static int phytium_sm3_dma_init(struct shash_desc *desc)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	sm3_init(&ctx->sm3_ctx);
	ctx->v_dma_buf = (u32*)(((long)(ctx->dma_buf + 64) >> 6) << 6);
	ctx->dma_paddr = virt_to_phys(ctx->v_dma_buf);

	return 0;
}



static int phytium_sm3_dma_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	u32 left, fill, count, *src;
	u32 calclen = 0, offset = 0, buf_len;
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	if(unlikely(0 == len)){
		return 0;
	}

	if(unlikely((len < 128) || ((len < 1024) && (atomic_read(&scto.wait_count) > 1)))){
		sm3_update(&ctx->sm3_ctx, data, len);
		return 0;
	}

	if(unlikely(ctx->v_dma_buf == NULL)){
		ctx->v_dma_buf = (u32*)(((long)(ctx->dma_buf + 64) >> 6) << 6);
		ctx->dma_paddr = virt_to_phys(ctx->v_dma_buf);
	}
	
	left = ctx->sm3_ctx.total[0] & 0x3F;
	fill = SM3_BLOCK_BYTE_LEN - left;

	//update total byte length 
	ctx->sm3_ctx.total[0] += len;
	if(ctx->sm3_ctx.total[0] < len)
		ctx->sm3_ctx.total[1]++;

	if(unlikely(left)){
		if(len >= fill){
			memcpy(ctx->sm3_ctx.buffer + left, data, fill);
			len -= fill;
			data += fill;
		}else{
			memcpy(ctx->sm3_ctx.buffer + left, data, len);
			return 0;
		}
	}

	//process some blocks
	count = len >> 6;

	if(unlikely(left)){
		src = (u32*)((long)(ctx->sm3_ctx.buffer));
		smx_dma_reverse_word(src, ctx->v_dma_buf, SM3_BLOCK_BYTE_LEN);
		left = SM3_BLOCK_BYTE_LEN;
	}

	calclen = count << 6;

	atomic_inc(&scto.wait_count);
	while(calclen || left){	
		if(likely(calclen <= (PHYTIUM_DMA_BUF_SIZE - left))){
			buf_len = calclen + left;
		}else{
			buf_len = PHYTIUM_DMA_BUF_SIZE;
		}

		src = (u32*)((long)data + offset);

		smx_dma_reverse_word(src, ctx->v_dma_buf + (left >> 2), (buf_len - left) >> 2);
		dma_sync_single_for_device(scto.dev, ctx->dma_paddr, buf_len, DMA_BIDIRECTIONAL);
		mutex_lock(&scto.scto_lock);
		sm3_set_data(ctx->sm3_ctx.state);
		sm3_dma(ctx->dma_paddr, ctx->dma_paddr, buf_len);
		mutex_unlock(&scto.scto_lock);
		dsb(sy);
		sm3_reverse_word(ctx->v_dma_buf, ctx->sm3_ctx.state);
		offset += (buf_len - left);
		calclen -= (buf_len - left);
		left = 0;
	}
	atomic_dec(&scto.wait_count);

	//process the remainder
	data += count << 6;
	len = len & 0x3F;
	if(len){
		memcpy(ctx->sm3_ctx.buffer, data, len);
	}

	return 0;
}

static int phytium_sm3_dma_final(struct shash_desc *desc, u8 *out)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	sm3_final(&ctx->sm3_ctx, out);

	return 0;
}

static int phytium_sm3_dma_finup(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{	
	phytium_sm3_dma_update(desc, data, len);

	phytium_sm3_dma_final(desc, out);

	return 0;
}

static int phytium_sm3_dma_digest(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{
	phytium_sm3_dma_init(desc);

	phytium_sm3_dma_finup(desc, data, len, out);

	return 0;
}
static int phytium_sm3_dma_export(struct shash_desc *desc, void *out)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	memcpy(out, ctx->sm3_ctx.state, SM3_DIGEST_BYTE_LEN);

	return 0;
}
static int phytium_sm3_dma_import(struct shash_desc *desc, const void *in)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	memcpy(ctx->sm3_ctx.state, in, SM3_DIGEST_BYTE_LEN);

	return 0;
}

static struct shash_alg sm3_dma_phytium_alg = {
	.digestsize	= SM3_DIGEST_BYTE_LEN,
	.init		= phytium_sm3_dma_init,
	.update		= phytium_sm3_dma_update,
	.final		= phytium_sm3_dma_final,
	.finup		= phytium_sm3_dma_finup,
	.digest     = phytium_sm3_dma_digest,
	.export     = phytium_sm3_dma_export,
	.import     = phytium_sm3_dma_import,
	.statesize  = SM3_DIGEST_BYTE_LEN,
	.base		= {
		.cra_name		= "sm3",
		.cra_driver_name	= "sm3-phytium",
		.cra_priority           = 300,
		.cra_blocksize		= SM3_BLOCK_BYTE_LEN,
		.cra_ctxsize		= sizeof(phytium_sm3_context),
		.cra_module		= THIS_MODULE,
	}
};

#define HMAC_IPAD_VALUE 0x36
#define HMAC_OPAD_VALUE 0x5c

static int phytium_hmac_sm3_dma_setkey(struct crypto_shash *tfm, const u8 *key, unsigned int keylen)
{
	struct shash_desc desc;
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	int i;

	desc.tfm = tfm;

	if (keylen > SM3_BLOCK_BYTE_LEN) {
		phytium_sm3_dma_digest(&desc, key, keylen, ctx->ipad);
		keylen = SM3_DIGEST_BYTE_LEN;
	} else
		memcpy(ctx->ipad, key, keylen);

	memset(ctx->ipad + keylen, 0, SM3_BLOCK_BYTE_LEN - keylen);
	memcpy(ctx->opad, ctx->ipad, SM3_BLOCK_BYTE_LEN);

	for (i = 0; i < SM3_BLOCK_BYTE_LEN; i++) {
		ctx->ipad[i] ^= HMAC_IPAD_VALUE;
		ctx->opad[i] ^= HMAC_OPAD_VALUE;
	}

	return phytium_sm3_dma_init(&desc) ?:
	       phytium_sm3_dma_update(&desc, ctx->ipad, SM3_BLOCK_BYTE_LEN) ?:
	       phytium_sm3_dma_export(&desc, ctx->ipad) ?:
	       phytium_sm3_dma_init(&desc) ?:
	       phytium_sm3_dma_update(&desc, ctx->opad, SM3_BLOCK_BYTE_LEN) ?:
	       phytium_sm3_dma_export(&desc, ctx->opad);
}

static int phytium_hmac_sm3_dma_init(struct shash_desc *desc)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));

	return phytium_sm3_dma_import(desc, ctx->ipad);
}

static int phytium_hmac_sm3_dma_final(struct shash_desc *desc, u8 *out)
{
	phytium_sm3_context *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));
	
	return phytium_sm3_dma_final(desc, out) ?:
	       phytium_sm3_dma_import(desc, ctx->opad) ?:
	       phytium_sm3_dma_finup(desc, out, SM3_DIGEST_BYTE_LEN, out);
}

static int phytium_hmac_sm3_dma_finup(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{	
	phytium_sm3_dma_update(desc, data, len);

	phytium_hmac_sm3_dma_final(desc, out);

	return 0;
}

static struct shash_alg hmac_sm3_dma_phytium_alg = {
	.digestsize	= SM3_DIGEST_BYTE_LEN,
	.init		= phytium_hmac_sm3_dma_init,
	.update		= phytium_sm3_dma_update,
	.final		= phytium_hmac_sm3_dma_final,
	.finup		= phytium_hmac_sm3_dma_finup,
	.export     = phytium_sm3_dma_export,
	.import     = phytium_sm3_dma_import,
	.setkey     = phytium_hmac_sm3_dma_setkey,
	.statesize  = SM3_DIGEST_BYTE_LEN,
	.base		= {
		.cra_name		= "hmac(sm3)",
		.cra_driver_name	= "sm3-hmac-phytium",
		.cra_priority           = 300,
		.cra_blocksize		= SM3_BLOCK_BYTE_LEN,
		.cra_ctxsize		= sizeof(phytium_sm3_context),
		.cra_module		= THIS_MODULE,
	}
};


int sm3_phytium_dma_algs_register(void)
{
	int ret;
	
	ret = crypto_register_shash(&sm3_dma_phytium_alg);
	if(ret)
		return -1;
	ret = crypto_register_shash(&hmac_sm3_dma_phytium_alg);
	if(ret){
		crypto_unregister_shash(&sm3_dma_phytium_alg);
		return -1;
	}

	return 0;
}

void sm3_phytium_dma_algs_unregister(void)
{
	crypto_unregister_shash(&sm3_dma_phytium_alg);
	crypto_unregister_shash(&hmac_sm3_dma_phytium_alg);
}

#endif
