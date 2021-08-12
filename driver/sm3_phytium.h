/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SM3_PHYTIUM_H__
#define __SM3_PHYTIUM_H__

/*SM3 digest and block length*/
#define SM3_DIGEST_WORD_LEN   (8)
#define SM3_DIGEST_BYTE_LEN   (SM3_DIGEST_WORD_LEN << 2)
#define SM3_BLOCK_WORD_LEN    (16)
#define SM3_BLOCK_BYTE_LEN    (SM3_BLOCK_WORD_LEN << 2)

extern struct scto_dev scto;

/*some register offset*/
#define HASH_LAST_OFFSET           (24)

/*SM3 return code*/
enum SM3_RET_CODE {
	SM3_SUCCESS = 0,
	SM3_BUFFER_NULL,
	SM3_INPUT_INVALID,
	SM3_LEN_OVERFLOW,
};

/*HASH register struct*/
typedef struct {
	uint32_t hash_ctrl;
	uint32_t hash_cfg;
	uint32_t hash_sr_1;
	uint32_t hash_sr_2;
	uint32_t rev_1[4];
	uint32_t hash_pcr_len[2];
	uint32_t rev_2[2];
	uint32_t hash_out[8];
	uint32_t rev_3[8];
	uint32_t hash_in[8];
	uint32_t rev_4[8];
	uint32_t hash_version;
	uint32_t rev_5[19];
	uint32_t hash_m_din[16];
} hash_reg_t;

struct sm3_context {
	u32 total[2];   /* number of bytes processed */
	u32 state[8];   /* intermediate digest state */
	u8 buffer[64];  /* data block being processed */
};

typedef struct
{
	struct sm3_context sm3_ctx;
	u32 *v_dma_buf;
	long dma_paddr;
	u8 ipad[64];
	u8 opad[64];
	u8 dma_buf[PHYTIUM_DMA_BUF_SIZE + 256];
} phytium_sm3_context;

/*API*/
int sm3_phytium_dma_algs_register(void);

void sm3_phytium_dma_algs_unregister(void);

#endif
