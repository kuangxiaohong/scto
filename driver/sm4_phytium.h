/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SM4_PHYTIUM_H_
#define _SM4_PHYTIUM_H_

/*some register offset*/
#define SKE_MODE_OFFSET           (9)
#define SKE_CRYPTO_OFFSET         (8)
#define SKE_UPDATE_IV_OFFSET      (18)
#define SKE_ERR_CFG_OFFSET        (8)


/*SKE register struct*/
typedef struct {
	u32 ctrl;
	u32 cfg;
	u32 sr_1;
	u32 sr_2;
	u32 rev1[24];
	u32 iv[4];
	u32 key[4];
	u32 rev3[44];
	u32 ske_version;
	u32 rev6[47];
	u32 m_din[4];
	u32 m_dout[4];
} ske_reg_t;

typedef struct{
	u32 encsk[32];  /* SM4 subkeys */
	u32 decsk[32];  /* SM4 subkeys */
	u32 iv[4];
	u32 scto_key[4];
	u64 total_len;
	u32 *v_dma_buf;
	long dma_paddr;
	u8 dma_buf[PHYTIUM_DMA_BUF_SIZE + 256];
}phytium_sm4_context;

#define SM4_BLOCK_BYTE_LEN  (16)
#define SM4_BLOCK_WORD_LEN  (4)
#define SM4_KEY_BYTE_LEN    SM4_BLOCK_BYTE_LEN
#define SM4_KEY_WORD_LEN    SM4_BLOCK_WORD_LEN

enum SM4_RET_CODE {
	SM4_SUCCESS = 0,
	SM4_BUFFER_NULL,
	SM4_CONFIG_INVALID,
	SM4_INPUT_INVALID,
};

typedef enum {
	SM4_MODE_ECB = 0,
	SM4_MODE_CBC,
	SM4_MODE_CFB,
	SM4_MODE_OFB,
	SM4_MODE_CTR,
} sm4_mode_e;

typedef enum {
	SM4_CRYPTO_ENCRYPT = 0,
	SM4_CRYPTO_DECRYPT,
} sm4_crypto_e;


int sm4_phytium_dma_algs_register(void);

void sm4_phytium_dma_algs_unregister(void);

#endif
