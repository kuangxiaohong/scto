/*
 * File Name:sm4_phytium.c - Phytium SDK for SM4
 *
 * Copyright (C) 2020 Phytium Technology Co.,Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */


#include <linux/io.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <crypto/internal/skcipher.h>
#include <crypto/skcipher.h>
#include "smx_common.h"
#include "sm4_phytium.h"
#include "phytium_scto.h"

#if SCTO_KERNEL_MODE



extern struct scto_dev scto;

#define SHL(x, n)	(((x) & 0xFFFFFFFF) << (n))
#define ROTL(x, n)	(SHL((x), (n)) | ((x) >> (32 - (n))))

#define SWAP(a, b)	{ u32 t = a; a = b; b = t; t = 0; }

/*
 * Expanded SM4 S-boxes
 */
static const u8 SboxTable[16][16] =  {
	{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
	{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
	{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
	{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
	{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
	{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
	{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
	{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
	{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
	{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
	{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
	{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
	{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
	{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
	{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
	{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
};

/* System parameter */
static const u32 FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* Fixed parameter */
static const u32 CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static inline u8 sm4Sbox(u8 inch)
{
	u8 *tab = (u8 *)SboxTable;

	return tab[inch];
}

static inline u32 sm4Lt(u32 ka)
{
	u32 bb = 0;
	u8 a[4];
	u8 b[4];

	PUT_UINT32_BE(ka, a, 0);
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_UINT32_BE(bb, b, 0);

	return bb ^ ROTL(bb, 2) ^ ROTL(bb, 10) ^ ROTL(bb, 18) ^ ROTL(bb, 24);
}

static inline u32 sm4F(u32 x0, u32 x1, u32 x2, u32 x3,
		     u32 rk)
{
	return x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk);
}

static u32 sm4CalciRK(u32 ka)
{
	u32 bb = 0;
	u8 a[4];
	u8 b[4];

	PUT_UINT32_BE(ka, a, 0);
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_UINT32_BE(bb, b, 0);

	return bb ^ ROTL(bb, 13) ^ ROTL(bb, 23);
}

static void sm4_setkey(u32 SK[32], const u8 key[16])
{
	u32 MK[4];
	u32 k[36];
	u32 i = 0;

	GET_UINT32_BE(MK[0], key, 0);
	GET_UINT32_BE(MK[1], key, 4);
	GET_UINT32_BE(MK[2], key, 8);
	GET_UINT32_BE(MK[3], key, 12);

	k[0] = MK[0] ^ FK[0];
	k[1] = MK[1] ^ FK[1];
	k[2] = MK[2] ^ FK[2];
	k[3] = MK[3] ^ FK[3];

	for (i = 0; i < 32; i++) {
		k[i + 4] = k[i] ^ sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^
					     CK[i]);
		SK[i] = k[i + 4];
	}
}

static inline void sm4_one_round(u32 sk[32], const u8 input[16],
			  u8 output[16])
{
	u32 i = 0;
	u32 ulbuf[36];

	memset(ulbuf, 0, sizeof(ulbuf));

	GET_UINT32_BE(ulbuf[0], input, 0);
	GET_UINT32_BE(ulbuf[1], input, 4);
	GET_UINT32_BE(ulbuf[2], input, 8);
	GET_UINT32_BE(ulbuf[3], input, 12);

	for (i = 0; i < 32; i++)
		ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2],
				    ulbuf[i + 3], sk[i]);

	PUT_UINT32_BE(ulbuf[35], output, 0);
	PUT_UINT32_BE(ulbuf[34], output, 4);
	PUT_UINT32_BE(ulbuf[33], output, 8);
	PUT_UINT32_BE(ulbuf[32], output, 12);
}

void sm4_setkey_enc(phytium_sm4_context *ctx, const u8 key[16])
{
	sm4_setkey(ctx->encsk, key);
}

void sm4_setkey_dec(phytium_sm4_context *ctx, const u8 key[16])
{
	int i;

	sm4_setkey(ctx->decsk, key);

	for (i = 0; i < 16; i++)
		SWAP(ctx->decsk[i], ctx->decsk[31 - i]);
}

void sm4_crypt_ecb_enc(phytium_sm4_context *ctx, size_t length, u8 iv[16], const u8 *input, u8 *output)
{
	while (length > 0) {
		sm4_one_round(ctx->encsk, input, output);
		input  += 16;
		output += 16;
		length -= 16;
	}
}

void sm4_crypt_ecb_dec(phytium_sm4_context *ctx, size_t length, u8 iv[16], const u8 *input, u8 *output)
{
	while (length > 0) {
		sm4_one_round(ctx->decsk, input, output);
		input  += 16;
		output += 16;
		length -= 16;
	}
}

void sm4_crypt_cbc_enc(phytium_sm4_context *ctx, size_t length, u8 iv[16],
		   const u8 *input, u8 *output)
{
	int i;

	while (length > 0) {
		for (i = 0; i < 16; i++)
			output[i] = (u8)(input[i] ^ iv[i]);
		sm4_one_round(ctx->encsk, output, output);
		memcpy(iv, output, 16);
		input  += 16;
		output += 16;
		length -= 16;
	}

}

void sm4_crypt_cbc_dec(phytium_sm4_context *ctx, size_t length, u8 iv[16],
		   const u8 *input, u8 *output)
{
	int i;
	u8 temp[16];

	while (length > 0) {
		memcpy(temp, input, 16);
		sm4_one_round(ctx->decsk, input, output);
		for (i = 0; i < 16; i++)
			output[i] = (u8)(output[i] ^ iv[i]);
		memcpy(iv, temp, 16);
		input  += 16;
		output += 16;
		length -= 16;
	}
}


void sm4_crypt_ctr(phytium_sm4_context *ctx, size_t length, u8 ctr[16],
		   const u8 *input, u8 *output)
{
	int i;
	u8 temp[16];

	while (length > 0) {
		memcpy(temp, ctr, 16);
		sm4_one_round(ctx->encsk, ctr, ctr);
		for (i = 0; i < 16; i++)
			output[i] = (u8)(input[i] ^ ctr[i]);
		memcpy(ctr, temp, 16);
		for (i = 16; i > 0; i--)
			if (++ctr[i - 1])
				break;
		input  += 16;
		output += 16;
		length -= 16;
	}
}

int sm4_sg_crypt(struct scatterlist *sgl, unsigned int nents, void *buf,
		      size_t buflen, off_t skip, phytium_sm4_context *ctx, u8* iv,
		      void (*fn)(phytium_sm4_context *, size_t, u8* ,const u8 *, u8 *))
{
	unsigned int offset = 0;
	struct sg_mapping_iter miter;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;

	sg_miter_start(&miter, sgl, nents, sg_flags);

	if(unlikely(!sg_miter_skip(&miter, skip)))
		return false;

	while ((offset < buflen) && sg_miter_next(&miter)) {
		unsigned int len;

		len = min(miter.length, buflen - offset);

		fn(ctx, len, iv, miter.addr, buf + offset);

		offset += len;
	}

	sg_miter_stop(&miter);

	return offset;
}

static inline void sm4_set_key(u32 key[SM4_KEY_WORD_LEN])
{
	scto.ske_reg->key[0] = key[0];
	scto.ske_reg->key[1] = key[1];
	scto.ske_reg->key[2] = key[2];
	scto.ske_reg->key[3] = key[3];
}

static inline void sm4_set_iv(u32 iv[SM4_BLOCK_WORD_LEN])
{
	scto.ske_reg->iv[0] = iv[0];
	scto.ske_reg->iv[1] = iv[1];
	scto.ske_reg->iv[2] = iv[2];
	scto.ske_reg->iv[3] = iv[3];
}

static inline int sm4_init(sm4_mode_e mode, int crypto, u32 *key, u8 *iv)
{
	u32 scto_iv[4];
	u32 cfg = 0;

	//set iv or nonce
	if(likely(mode != SM4_MODE_ECB)){
		smx_reverse_word(iv, scto_iv, SM4_BLOCK_WORD_LEN);
		sm4_set_iv(scto_iv);
		cfg |= (1<<SKE_UPDATE_IV_OFFSET);
	}
	
	//config and check
	cfg |= (mode << SKE_MODE_OFFSET) | (crypto << SKE_CRYPTO_OFFSET);
	scto.ske_reg->cfg = cfg;

	//set key
	sm4_set_key(key);
	
	return SM4_SUCCESS;
}

void sm4_dma(long in, long out, u32 byteLen)
{
	//src addr
	scto.dma_reg->saddr0 = (in >> 2)&0xFFFFFFFF;
	scto.dma_reg->saddr1 = (in >> 34)&0x0FFF;

	//dst addr
	scto.dma_reg->daddr0 = (out >> 2)&0xFFFFFFFF;
	scto.dma_reg->daddr1 = (out >>34)&0x0FFF;

	//data word length
	scto.dma_reg->len = (byteLen >> 2);

	//clear flag
	scto.smx_reg->sr_2 = 1;

	//store cfg
	scto.smx_reg->cmd = 1;

	dsb(sy);
	//start
	scto.smx_reg->cr = 1;

	do{
		dsb(sy);
	}while(!(scto.smx_reg->sr_2 & 1));
}

int phytium_sm4_setkey(struct crypto_skcipher *tfm, const u8 *key, unsigned int keylen)
{	
	phytium_sm4_context *ctx = crypto_skcipher_ctx(tfm);

	if(keylen != 16){
		return -1;
	}

	sm4_setkey_enc(ctx, key);
	sm4_setkey_dec(ctx, key);

	memcpy(ctx->scto_key, key, sizeof(ctx->scto_key));
	smx_reverse_word(ctx->scto_key, ctx->scto_key, SM4_KEY_WORD_LEN);

	ctx->v_dma_buf = (u32*)(((long)(ctx->dma_buf + 64) >> 6) << 6);
	ctx->dma_paddr = virt_to_phys(ctx->v_dma_buf);
	ctx->total_len = 0;
	mutex_init(&ctx->ctx_lock);

	return 0;
}

size_t phytium_dma_sg_copy_buffer(struct scatterlist *sgl, unsigned int nents, void *buf,
		      size_t buflen, off_t skip, bool to_buffer)
{
	unsigned int offset = 0;
	struct sg_mapping_iter miter;
	unsigned int sg_flags = SG_MITER_ATOMIC;

	if (to_buffer)
		sg_flags |= SG_MITER_FROM_SG;
	else
		sg_flags |= SG_MITER_TO_SG;

	sg_miter_start(&miter, sgl, nents, sg_flags);

	if(unlikely(!sg_miter_skip(&miter, skip)))
		return false;

	while ((offset < buflen) && sg_miter_next(&miter)) {
		unsigned int len;

		len = min(miter.length, buflen - offset);

		if (to_buffer)
			smx_dma_reverse_word(miter.addr, buf + offset, len >> 2);
		else
			smx_dma_reverse_word(buf + offset, miter.addr, len >> 2);

		offset += len;
	}

	sg_miter_stop(&miter);

	return offset;
}

int phytium_dma_sg_len_align_detect(struct scatterlist *sgl, unsigned int nents)
{
	for (; sgl; sgl = sg_next(sgl)){
		if(sgl->length & 0xf)
			return 0;
	}

	return 1;
}

int sm4_crypt(struct skcipher_request *req, void (*fn)(phytium_sm4_context *, size_t, u8* ,const u8 *, u8 *))
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	phytium_sm4_context *ctx = crypto_skcipher_ctx(tfm);
	long offset = 0, buf_len, len;
	struct scatterlist *src, *dst;
	u8 *iv;
	int src_align_flag, src_nents, dst_nents, left, fill;
	u8 temp[16], tempiv[16];

	len = req->cryptlen;
	iv = req->iv;
	src = req->src;
	dst =  req->dst;
	src_nents = sg_nents(src);
	dst_nents = sg_nents(dst);
	src_align_flag = phytium_dma_sg_len_align_detect(src, src_nents);

	mutex_lock(&ctx->ctx_lock);
	left = ctx->total_len & 0xf;
	fill = 16 - left;
	ctx->total_len += len;
	if(unlikely(left)){
		if(len >= fill){
			sg_copy_buffer(src, src_nents, temp + left, fill, offset, true);
			fn(ctx, 16, iv, temp, temp);
			sg_copy_buffer(dst, dst_nents, temp + left, fill, offset, false);
			len -= fill;
			offset += fill;
		}else{
			memcpy(tempiv, iv, 16);
			sg_copy_buffer(src, src_nents, temp + left, len, offset, true);
			fn(ctx, 16, tempiv, temp, temp);
			sg_copy_buffer(dst, dst_nents, temp + left, len, offset, false);
			mutex_unlock(&ctx->ctx_lock);
			return 0;
		}
	}

	left = len & 0xf;
	len -= left;

	while(len){	
		if(likely(len <= PHYTIUM_SM4_DMA_BUF_SIZE)){
			buf_len = len;
		}else{
			buf_len = PHYTIUM_SM4_DMA_BUF_SIZE;
		}

		if(likely(src_align_flag)){
			sm4_sg_crypt(src, src_nents, ctx->dma_buf, buf_len, offset, ctx, iv, fn);
		}else{
			sg_copy_buffer(src, src_nents, ctx->dma_buf, buf_len, offset, true);
			fn(ctx, buf_len, iv, ctx->dma_buf, ctx->dma_buf);
		}

		sg_copy_buffer(dst, dst_nents, ctx->dma_buf, buf_len, offset, false);
	
		len -= buf_len;
		offset += buf_len; 
	}

	if(left){
		memcpy(tempiv, iv, 16);
		sg_copy_buffer(src, src_nents, temp, left, offset, true);
		fn(ctx, 16, tempiv, temp, temp);
		sg_copy_buffer(dst, dst_nents, temp, left, offset, false);
	}
	mutex_unlock(&ctx->ctx_lock);

	return 0;
}

int phytium_sm4_ecb(struct skcipher_request *req, int cryptomode)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	phytium_sm4_context *ctx = crypto_skcipher_ctx(tfm);
	long offset, buf_len, len;
	int src_align_flag, dst_align_flag, src_nents, dst_nents;

	len = req->cryptlen;
	if(unlikely((len == 0) || (len & 0xf))){
		return -1;
	}

	if(unlikely(ctx->v_dma_buf == NULL)){
		return -1;
	}

	if(unlikely((len < 128) || ((len < 1024) && (atomic_read(&scto.wait_count) > 1)))){
		if(cryptomode == SM4_CRYPTO_ENCRYPT)
			sm4_crypt(req, sm4_crypt_ecb_enc);
		else
			sm4_crypt(req, sm4_crypt_ecb_dec);
		return 0;
	}

	src_nents = sg_nents(req->src);
	dst_nents = sg_nents(req->dst);
	src_align_flag = phytium_dma_sg_len_align_detect(req->src, src_nents);
	dst_align_flag = phytium_dma_sg_len_align_detect(req->dst, dst_nents);

	offset = 0;
	atomic_inc(&scto.wait_count);
	mutex_lock(&ctx->ctx_lock);
	while(len){	
		if(likely(len <= PHYTIUM_SM4_DMA_BUF_SIZE)){
			buf_len = len;
		}else{
			buf_len = PHYTIUM_SM4_DMA_BUF_SIZE;
		}

		if(likely(src_align_flag)){
			phytium_dma_sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
		}else{
			sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
		}

		dma_sync_single_for_device(scto.dev, ctx->dma_paddr, buf_len, DMA_BIDIRECTIONAL);

		mutex_lock(&scto.scto_lock);
		sm4_init(SM4_MODE_ECB, cryptomode, ctx->scto_key, NULL);
		sm4_dma(ctx->dma_paddr, ctx->dma_paddr, buf_len);
		mutex_unlock(&scto.scto_lock);
		dsb(sy);

		if(likely(dst_align_flag)){
			phytium_dma_sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}else{	
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
			sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}
	
		len -= buf_len;
		offset += buf_len; 
	}
	atomic_dec(&scto.wait_count);
	mutex_unlock(&ctx->ctx_lock);

	return 0;
}


int phytium_sm4_ecb_encrypt(struct skcipher_request *req)
{
	return phytium_sm4_ecb(req, SM4_CRYPTO_ENCRYPT);
}

int phytium_sm4_ecb_decrypt(struct skcipher_request *req)
{
	return phytium_sm4_ecb(req, SM4_CRYPTO_DECRYPT);
}

int phytium_sm4_cbc(struct skcipher_request *req, int cryptomode)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	phytium_sm4_context *ctx = crypto_skcipher_ctx(tfm);
	long offset, buf_len, len;
	int src_align_flag, dst_align_flag, src_nents, dst_nents;

	len = req->cryptlen;
	if(unlikely((len == 0) || (len & 0xf))){
		return -1;
	}
	
	if(unlikely(ctx->v_dma_buf == NULL)){
		return -1;
	}

	if(unlikely((len < 128) || ((len < 1024) && (atomic_read(&scto.wait_count) > 1)))){
		if(cryptomode == SM4_CRYPTO_ENCRYPT)
			sm4_crypt(req, sm4_crypt_cbc_enc);
		else
			sm4_crypt(req, sm4_crypt_cbc_dec);
		return 0;
	}

	src_nents = sg_nents(req->src);
	dst_nents = sg_nents(req->dst);
	src_align_flag = phytium_dma_sg_len_align_detect(req->src, src_nents);
	dst_align_flag = phytium_dma_sg_len_align_detect(req->dst, dst_nents);

	offset = 0;
	atomic_inc(&scto.wait_count);
	mutex_lock(&ctx->ctx_lock);
	while(len){	
		if(len <= PHYTIUM_SM4_DMA_BUF_SIZE){
			buf_len = len;
		}else{
			buf_len = PHYTIUM_SM4_DMA_BUF_SIZE;
		}

		if(likely(src_align_flag)){
			phytium_dma_sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
		}else{
			sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
		}

		if(cryptomode)
			memcpy(ctx->iv, (void*)((long)(ctx->v_dma_buf) + buf_len - 16), 16);
		dma_sync_single_for_device(scto.dev, ctx->dma_paddr, buf_len, DMA_BIDIRECTIONAL);

		mutex_lock(&scto.scto_lock);
		sm4_init(SM4_MODE_CBC, cryptomode, ctx->scto_key, req->iv);
		sm4_dma(ctx->dma_paddr, ctx->dma_paddr, buf_len);
		mutex_unlock(&scto.scto_lock);
		dsb(sy);

		if(!cryptomode)
			smx_dma_reverse_word((void*)((long)(ctx->v_dma_buf) + buf_len - 16), req->iv, 4);
		else
			smx_dma_reverse_word(ctx->iv, req->iv, 4);

		if(likely(dst_align_flag)){
			phytium_dma_sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}else{	
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
			sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}

		len -= buf_len;
		offset += buf_len;
	}
	atomic_dec(&scto.wait_count);
	mutex_unlock(&ctx->ctx_lock);

	return 0;
}

int phytium_sm4_cbc_encrypt(struct skcipher_request *req)
{
	return phytium_sm4_cbc(req, SM4_CRYPTO_ENCRYPT);
}

int phytium_sm4_cbc_decrypt(struct skcipher_request *req)
{
	return phytium_sm4_cbc(req, SM4_CRYPTO_DECRYPT);
}

int phytium_sm4_ctr(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	phytium_sm4_context *ctx = crypto_skcipher_ctx(tfm);
	long offset = 0, buf_len, len, ctr_len, i;
	u8 tmp;
	int src_align_flag, dst_align_flag, src_nents, dst_nents, left, fill;
	u8 temp[16], tempiv[16];

	len = req->cryptlen;
	if(unlikely(len == 0)){
		return -1;
	}

	if(unlikely(ctx->v_dma_buf == NULL)){
		return -1;
	}

	if(unlikely((len < 128) || ((len < 1024) && (atomic_read(&scto.wait_count) > 1)))){
		sm4_crypt(req, sm4_crypt_ctr);
		return 0;
	}

	src_nents = sg_nents(req->src);
	dst_nents = sg_nents(req->dst);
	src_align_flag = phytium_dma_sg_len_align_detect(req->src, src_nents);
	dst_align_flag = phytium_dma_sg_len_align_detect(req->dst, dst_nents);

	mutex_lock(&ctx->ctx_lock);
	left = ctx->total_len & 0xf;
	fill = 16 - left;
	ctx->total_len += len;
	if(unlikely(left)){
		if(len >= fill){
			sg_copy_buffer(req->src, src_nents, temp + left, fill, offset, true);
			sm4_crypt_ctr(ctx, 16, req->iv, temp, temp);
			sg_copy_buffer(req->dst, dst_nents, temp + left, fill, offset, false);
			len -= fill;
			offset += fill;
		}else{
			memcpy(tempiv, req->iv, 16);
			sg_copy_buffer(req->src, src_nents, temp + left, len, offset, true);
			sm4_crypt_ctr(ctx, 16, tempiv, temp, temp);
			sg_copy_buffer(req->dst, dst_nents, temp + left, len, offset, false);
			mutex_unlock(&ctx->ctx_lock);
			return 0;
		}
	}

	left = len & 0xf;
	len -= left;

	atomic_inc(&scto.wait_count);
	while(len){	
		if(likely(len <= PHYTIUM_SM4_DMA_BUF_SIZE)){
			buf_len = len;
		}else{
			buf_len = PHYTIUM_SM4_DMA_BUF_SIZE;
		}

		if(likely(src_align_flag)){
			phytium_dma_sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
		}else{
			sg_copy_buffer(req->src, src_nents, ctx->v_dma_buf, buf_len, offset, true);
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
		}

		dma_sync_single_for_device(scto.dev, ctx->dma_paddr, buf_len, DMA_BIDIRECTIONAL);

		mutex_lock(&scto.scto_lock);
		sm4_init(SM4_MODE_CTR, SM4_CRYPTO_ENCRYPT, ctx->scto_key, req->iv);

		ctr_len = buf_len >> 4;
		for (i = 15; i >= 0; i--){
			tmp = req->iv[i];
			if(ctr_len){
				req->iv[i] += ctr_len;
				ctr_len >>= 8;
			}

			if(tmp > req->iv[i]){
				ctr_len ++;
			}else if(!ctr_len){
				break;
			}
		}
		if(unlikely(ctr_len)){
			ctr_len = swap32(*((u32*)&req->iv[12]));
			ctr_len <<= 4;
			*((u32*)&req->iv[12]) = 0;
			sm4_dma(ctx->dma_paddr, ctx->dma_paddr, buf_len - ctr_len);
			if(ctr_len){
				sm4_set_iv((u32*)req->iv);
				sm4_dma(ctx->dma_paddr + buf_len - ctr_len, ctx->dma_paddr + buf_len - ctr_len, ctr_len);
				ctr_len >>= 4;
				*((u32*)&req->iv[12]) = swap32(ctr_len);
			}
		}else{
			sm4_dma(ctx->dma_paddr, ctx->dma_paddr, buf_len);
		}
		mutex_unlock(&scto.scto_lock);
		dsb(sy);

		if(likely(dst_align_flag)){
			phytium_dma_sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}else{	
			smx_dma_reverse_word(ctx->v_dma_buf, ctx->v_dma_buf, buf_len >> 2);
			sg_copy_buffer(req->dst, dst_nents, ctx->v_dma_buf, buf_len, offset, false);
		}

		len -= buf_len;
		offset += buf_len;
	}
	atomic_dec(&scto.wait_count);

	if(left){
		memcpy(tempiv, req->iv, 16);
		sg_copy_buffer(req->src, src_nents, temp, left, offset, true);
		sm4_crypt_ctr(ctx, 16, tempiv, temp, temp);
		sg_copy_buffer(req->dst, dst_nents, temp, left, offset, false);
	}
	mutex_unlock(&ctx->ctx_lock);

	return 0;
}

static struct skcipher_alg sm4_phytium_dma_algs[] = {
	{
		.base = {
			.cra_name		= "ecb(sm4)",
			.cra_driver_name	= "sm4-ecb-phytium",
			.cra_priority		= 300,
			.cra_blocksize		= 16,
			.cra_ctxsize		= sizeof(phytium_sm4_context),
			.cra_module 	= THIS_MODULE,
		},
		.min_keysize	= 16,
		.max_keysize	= 16,
		.ivsize 	= 0,
		.setkey 	= phytium_sm4_setkey,
		.encrypt	= phytium_sm4_ecb_encrypt,
		.decrypt	= phytium_sm4_ecb_decrypt,
	},
	{
		.base = {
			.cra_name		= "cbc(sm4)",
			.cra_driver_name	= "sm4-cbc-phytium",
			.cra_priority		= 300,
			.cra_blocksize		= 16,
			.cra_ctxsize		= sizeof(phytium_sm4_context),
			.cra_module 	= THIS_MODULE,
		},
		.min_keysize	= 16,
		.max_keysize	= 16,
		.ivsize 	= 16,
		.setkey 	= phytium_sm4_setkey,
		.encrypt	= phytium_sm4_cbc_encrypt,
		.decrypt	= phytium_sm4_cbc_decrypt,
	},
	{
		.base = {
			.cra_name		= "ctr(sm4)",
			.cra_driver_name	= "sm4-ctr-phytium",
			.cra_priority		= 300,
			.cra_blocksize		= 16,
			.cra_ctxsize		= sizeof(phytium_sm4_context),
			.cra_module 	= THIS_MODULE,
		},
		.min_keysize	= 16,
		.max_keysize	= 16,
		.ivsize 	= 16,
		.setkey 	= phytium_sm4_setkey,
		.encrypt	= phytium_sm4_ctr,
		.decrypt	= phytium_sm4_ctr,
	},
};

int sm4_phytium_dma_algs_register(void)
{
	int ret;
	
	ret = crypto_register_skciphers(sm4_phytium_dma_algs,
			ARRAY_SIZE(sm4_phytium_dma_algs));
	if (ret)
		return -1;

	return 0;
}

void sm4_phytium_dma_algs_unregister(void)
{
	crypto_unregister_skciphers(sm4_phytium_dma_algs,
			ARRAY_SIZE(sm4_phytium_dma_algs));
}
#endif
