#include "lib_smx_common.h"
#include "lib_sm3_phytium.h"
#include "lib_phytium_scto.h"

/*SM3 digest and block length*/
#define SM3_DIGEST_WORD_LEN   (8)
#define SM3_DIGEST_BYTE_LEN   (32)
#define SM3_BLOCK_WORD_LEN    (16)
#define SM3_BLOCK_BYTE_LEN    (64)

static inline void sm3_reverse_word(uint32_t *in, SM3_CTX *sm3_ctx)
{
	sm3_ctx->A = in[3];
	sm3_ctx->B = in[2];
	sm3_ctx->C = in[1];
	sm3_ctx->D = in[0];
	sm3_ctx->E = in[7];
	sm3_ctx->F = in[6];
	sm3_ctx->G = in[5];
	sm3_ctx->H = in[4];
}


int phytium_sm3_dma_init(int *desc_id)
{
	void *dma_buf = NULL;
	phytium_sm3_context *ctx;

	if(*desc_id <= 0){
		dma_buf = mem_alloc(desc_id);
		if(dma_buf == NULL){
			printf("desc_id alloc fail!\n");
			return -1;
		}
	}

	desc_start[*desc_id].alg = ALG_SM3;
	ctx = &desc_start[*desc_id].psm3_ctx;

	ctx->evp_md_ctx.digest = EVP_sm3();
	ctx->evp_md_ctx.md_data = &ctx->sm3_ctx;

	ctx->evp_md_ctx.digest->init(&ctx->evp_md_ctx);

	if(dma_buf)
		ctx->v_dma_buf = dma_buf;
	ctx->user_count = (volatile int*)((long)common_info_start + 0x10000);

	return 0;
}



int phytium_sm3_dma_update(int desc_id, const uint8_t *data, unsigned int len)
{
	uint32_t left, fill, count, *src;
	uint32_t calclen = 0, offset = 0, buf_len;
	phytium_sm3_context *ctx;
	long l;

	if(unlikely(0 == len)){
		return 0;
	}

	ctx = &desc_start[desc_id].psm3_ctx;

	if((len < 448) || __atomic_load_n(ctx->user_count, __ATOMIC_SEQ_CST)){
		ctx->evp_md_ctx.digest->update(&ctx->evp_md_ctx, data, len);
		return 0;
	}
	
	left = ctx->sm3_ctx.num;
	fill = SM3_BLOCK_BYTE_LEN - left;

	//update total byte length 
	l = (ctx->sm3_ctx.Nl + (((long) len) << 3)) & 0xffffffffUL;
	if (l < ctx->sm3_ctx.Nl)              /* overflow */
		ctx->sm3_ctx.Nh++;
	ctx->sm3_ctx.Nh += (long) (len >> 29);
	ctx->sm3_ctx.Nl = l;

	if(unlikely(left)){
		if(len >= fill){
			memcpy((uint8_t*)(ctx->sm3_ctx.data) + left, data, fill);
			len -= fill;
			data += fill;
		}else{
			memcpy((uint8_t*)(ctx->sm3_ctx.data) + left, data, len);
			ctx->sm3_ctx.num += len;
			return 0;
		}
	}

	//process some blocks
	count = len >> 6;

	if(unlikely(left)){
		smx_dma_reverse_word(ctx->sm3_ctx.data, ctx->v_dma_buf, SM3_BLOCK_BYTE_LEN);
		left = SM3_BLOCK_BYTE_LEN;
	}

	calclen = count << 6;

	while(calclen || left){	
		if(likely(calclen <= (PHYTIUM_DMA_BUF_SIZE - left))){
			buf_len = calclen + left;
		}else{
			buf_len = PHYTIUM_DMA_BUF_SIZE;
		}

		src = (uint32_t*)((long)data + offset);

		smx_dma_reverse_word(src, (uint8_t*)(ctx->v_dma_buf) + left, (buf_len - left) >> 2);

		ioctl(scto_fd, SCTO_SM3, ((long)desc_id << 32) | buf_len);
		
		sm3_reverse_word(ctx->v_dma_buf, &ctx->sm3_ctx);
		offset += (buf_len - left);
		calclen -= (buf_len - left);
		left = 0;
	}

	//process the remainder
	data += count << 6;
	len = len & 0x3F;
	if(len){
		memcpy(ctx->sm3_ctx.data, data, len);
		ctx->sm3_ctx.num = len;
	}else{
		ctx->sm3_ctx.num = 0;
	}

	return 0;
}

int phytium_sm3_dma_final(int desc_id, uint8_t *out)
{
	phytium_sm3_context *ctx;

	ctx = &desc_start[desc_id].psm3_ctx;

	ctx->evp_md_ctx.digest->final(&ctx->evp_md_ctx, out);

	return 0;
}
