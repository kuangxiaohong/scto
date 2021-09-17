#include "lib_smx_common.h"
#include "lib_sm4_phytium.h"
#include "lib_phytium_scto.h"


/*some register offset*/
#define SKE_MODE_OFFSET           (9)
#define SKE_CRYPTO_OFFSET         (8)
#define SKE_UPDATE_IV_OFFSET      (18)
#define SKE_ERR_CFG_OFFSET        (8)

#define SM4_BLOCK_BYTE_LEN  (16)
#define SM4_BLOCK_WORD_LEN  (4)
#define SM4_KEY_BYTE_LEN    (16)
#define SM4_KEY_WORD_LEN    (4)


static int phytium_sm4_ecb(int desc_id, uint8_t*in, uint32_t len, uint8_t*out)
{
	long offset, buf_len;
	phytium_sm4_context *ctx = &phytium_desc_start[desc_id / (0x400000 / sizeof(phytium_scto_context))][desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].psm4_ctx;

	if(unlikely((len == 0) || (len & 0xf))){
		return -1;
	}

	if((len < 256) || __atomic_load_n(ctx->user_count, __ATOMIC_SEQ_CST)){
		ctx->evp_cipher_ctx.cipher->do_cipher(&ctx->evp_cipher_ctx, out, in, len);
		return 0;
	}

	offset = 0;
	while(len){	
		if(likely(len <= PER_DESC_DMA_BUF_SIZE)){
			buf_len = len;
		}else{
			buf_len = PER_DESC_DMA_BUF_SIZE;
		}

		smx_dma_reverse_word(in + offset, ctx->v_dma_buf, buf_len >> 2);

		ioctl(phytium_scto_fd, SCTO_SM4, ((long)desc_id << 32) | buf_len);

		smx_dma_reverse_word(ctx->v_dma_buf, out + offset, buf_len >> 2);
	
		len -= buf_len;
		offset += buf_len; 
	}

	return 0;
}

static int phytium_sm4_cbc(int desc_id, uint8_t*in, uint32_t len, uint8_t*out)
{
	long offset, buf_len;
	phytium_sm4_context *ctx = &phytium_desc_start[desc_id / (0x400000 / sizeof(phytium_scto_context))][desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].psm4_ctx;

	if(unlikely((len == 0) || (len & 0xf))){
		return -1;
	}

	if((len < 256) || __atomic_load_n(ctx->user_count, __ATOMIC_SEQ_CST)){
		ctx->evp_cipher_ctx.cipher->do_cipher(&ctx->evp_cipher_ctx, out, in, len);
		return 0;
	}

	offset = 0;
	while(len){	
		if(len <= PER_DESC_DMA_BUF_SIZE){
			buf_len = len;
		}else{
			buf_len = PER_DESC_DMA_BUF_SIZE;
		}

		smx_dma_reverse_word(in + offset, ctx->v_dma_buf, buf_len >> 2);

		ioctl(phytium_scto_fd, SCTO_SM4, ((long)desc_id << 32) | buf_len);

		if(ctx->cryptomode)
			memcpy(ctx->evp_cipher_ctx.iv, in + offset + buf_len - 16, 16);
		smx_dma_reverse_word(ctx->v_dma_buf, out + offset, buf_len >> 2);

		len -= buf_len;
		offset += buf_len;
		
		if(!ctx->cryptomode)
			memcpy(ctx->evp_cipher_ctx.iv, out + offset - 16, 16);
	}

	return 0;
}

static int phytium_sm4_ctr(int desc_id, uint8_t*in, uint32_t len, uint8_t*out)
{
	long offset = 0, buf_len, ctr_len, i;
	uint8_t tmp, *iv;
	uint32_t num;
	phytium_sm4_context *ctx = &phytium_desc_start[desc_id / (0x400000 / sizeof(phytium_scto_context))][desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].psm4_ctx;

	if(unlikely(len == 0)){
		return 0;
	}

	if((len < 256) || __atomic_load_n(ctx->user_count, __ATOMIC_SEQ_CST)){
		ctx->evp_cipher_ctx.cipher->do_cipher(&ctx->evp_cipher_ctx, out, in, len);
    	return 0;
	}
	
	if(unlikely(ctx->evp_cipher_ctx.num)){	
		len -= (16 - ctx->evp_cipher_ctx.num);
		offset += (16 - ctx->evp_cipher_ctx.num);
		ctx->evp_cipher_ctx.cipher->do_cipher(&ctx->evp_cipher_ctx, out, in, (16 - ctx->evp_cipher_ctx.num));
	}

	num = len & 0xf;
	len -= num;

	while(len){	
		if(likely(len <= PER_DESC_DMA_BUF_SIZE)){
			buf_len = len;
		}else{
			buf_len = PER_DESC_DMA_BUF_SIZE;
		}

		smx_dma_reverse_word(in + offset, ctx->v_dma_buf, buf_len >> 2);

		ioctl(phytium_scto_fd, SCTO_SM4, ((long)desc_id << 32) | buf_len);

		iv = (uint8_t*)ctx->evp_cipher_ctx.iv;
		ctr_len = buf_len >> 4;
		for (i = 15; i >= 0; i--){
			tmp = iv[i];
			if(ctr_len){
				iv[i] += ctr_len;
				ctr_len >>= 8;
			}

			if(tmp > iv[i]){
				ctr_len ++;
			}else if(!ctr_len){
				break;
			}
		}
		if(unlikely(ctr_len)){
			ctr_len = swap32(*(uint32_t*)(&iv[12]));
			ctr_len <<= 4;
			*(uint32_t*)(&iv[12]) = 0;
			smx_dma_reverse_word(ctx->v_dma_buf, out + offset, (buf_len - ctr_len) >> 2);
			if(ctr_len){
				smx_dma_reverse_word(in + offset + (buf_len - ctr_len), ctx->v_dma_buf, ctr_len >> 2);
				ioctl(phytium_scto_fd, SCTO_SM4, ((long)desc_id << 32) | ctr_len);
				smx_dma_reverse_word(ctx->v_dma_buf, out + offset + (buf_len - ctr_len), ctr_len >> 2);
				ctr_len >>= 4;
				*(uint32_t*)(&iv[12]) = swap32(ctr_len);
			}
		}else{
			smx_dma_reverse_word(ctx->v_dma_buf, out + offset, buf_len >> 2);
		}

		len -= buf_len;
		offset += buf_len;
	}

	if(num){
		ctx->evp_cipher_ctx.cipher->do_cipher(&ctx->evp_cipher_ctx, out + offset, in + offset, num);
	}

	return 0;
}


int phytium_sm4_init(int *desc_id, uint32_t mode, uint32_t cryptomode, const uint8_t *key, const uint8_t*iv)
{	
	phytium_sm4_context *ctx;
	void *dma_buf = NULL;

	if((mode != SM4_MODE_ECB) && (mode != SM4_MODE_CBC) && (mode != SM4_MODE_CTR))
		return -1;
	if(cryptomode > SM4_CRYPTO_DECRYPT)
		return -1;

	if(*desc_id <= 0){
		dma_buf = mem_alloc(desc_id);
		if(dma_buf == NULL){
			return -1;
		}
	}

	phytium_desc_start[*desc_id / (0x400000 / sizeof(phytium_scto_context))][*desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].alg = ALG_SM4;
	ctx = &phytium_desc_start[*desc_id / (0x400000 / sizeof(phytium_scto_context))][*desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].psm4_ctx;
	switch(mode){
		case SM4_MODE_ECB:
			ctx->evp_cipher_ctx.cipher = EVP_sm4_ecb();
			break;
		case SM4_MODE_CBC:
			ctx->evp_cipher_ctx.cipher = EVP_sm4_cbc();
			break;
		case SM4_MODE_CTR:
			ctx->evp_cipher_ctx.cipher = EVP_sm4_ctr();
			break;
		default:
			break;
	}

	ctx->evp_cipher_ctx.encrypt = !cryptomode;
	ctx->evp_cipher_ctx.cipher_data = ctx->data;
	ctx->evp_cipher_ctx.key_len = 16;
	if(iv)
		memcpy(ctx->evp_cipher_ctx.oiv, iv, 16);
	memcpy(ctx->evp_cipher_ctx.iv, ctx->evp_cipher_ctx.oiv, 16);
	ctx->evp_cipher_ctx.num = 0;

	ctx->evp_cipher_ctx.buf_len = 0;
	ctx->evp_cipher_ctx.final_used = 0;
	ctx->evp_cipher_ctx.block_mask = ctx->evp_cipher_ctx.cipher->block_size - 1;
	ctx->evp_cipher_ctx.cipher->init(&ctx->evp_cipher_ctx, key, iv, !cryptomode);
	ctx->mode = mode;
	ctx->cryptomode = cryptomode;

	memcpy(ctx->scto_key, key, sizeof(ctx->scto_key));
	smx_reverse_word(ctx->scto_key, ctx->scto_key, SM4_KEY_WORD_LEN);
	if(dma_buf)
		ctx->v_dma_buf = dma_buf;
	ctx->user_count = (volatile int*)((long)phytium_common_info_start + SCTO_DESC_NUM * 8 + 128);

	return 0;
}

int phytium_sm4_update(int desc_id, uint8_t*in, uint32_t len, uint8_t*out)
{
	phytium_sm4_context *ctx = &phytium_desc_start[desc_id / (0x400000 / sizeof(phytium_scto_context))][desc_id & ((0x400000 / sizeof(phytium_scto_context)) - 1)].psm4_ctx;

	switch(ctx->mode){
		case SM4_MODE_ECB:
			return phytium_sm4_ecb(desc_id, in, len, out);
		case SM4_MODE_CBC:
			return phytium_sm4_cbc(desc_id, in, len, out);
		case SM4_MODE_CTR:
			return phytium_sm4_ctr(desc_id, in, len, out);
		default:
			break;
	}

	return -1; 
}
