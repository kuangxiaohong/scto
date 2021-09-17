/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PHYTIUM_SCTO_H__
#define __PHYTIUM_SCTO_H__

#include <crypto/hash.h>
#include <crypto/akcipher.h>
#include <linux/ioctl.h>
#include "sm3_phytium.h"
#include "sm4_phytium.h"


#define MAGIC_NUM    'p'
#define SCTO_SM3     _IO(MAGIC_NUM, 0)
#define SCTO_SM4     _IO(MAGIC_NUM, 1)




typedef struct {
	u32 cfg;
	u32 sr;
	u32 to_thers;
	u32 revsev0;
	u32 saddr0;
	u32 saddr1;
	u32 reseve1[2];
	u32 daddr0;
	u32 daddr1;
	u32 reseve2[2];
	u32 len;
	u32 resev3[3];
	u32 cfg_aw;
	u32 resev4[3];
	u32 cfg_ar;
} dma_reg_t;

typedef struct {
    u32 cr;
    u32 cmd; 
    u32 cfg; 
	u32 rev0;
    u32 sr_1;                     
    u32 sr_2;
    u32 reseve1[2];
    u32 cmd_sr;                     
    u32 resere2[3];                                  
    u32 version;
} smx_reg_t;

typedef struct {
	u32 cr;
	u32 rtcr;
	u32 sr;
	u32 dr;
	u32 rev1[4];
	u32 fifo_cr;
	u32 fifo_sr;	
	u32 rev2[18];
	u32 ht_sr;
	u32 rev3[3];
	u32 ro_cr;
	u32 ro_cr2;
	u32 ro_cr3;
}trng_reg_t;


struct scto_dev {
	void __iomem *regs;
	volatile hash_reg_t *hash_reg;
	volatile ske_reg_t *ske_reg;
	volatile dma_reg_t *dma_reg;
	volatile smx_reg_t *smx_reg;
	volatile trng_reg_t *trng_reg;
	struct device *dev;
	atomic_t     wait_count;
	struct mutex rng_lock;
	struct mutex scto_lock;
};

enum{
	ALG_SM3 = 0x20200730,
	ALG_SM4
};

typedef struct SM3state_st {
   u32 A, B, C, D, E, F, G, H;
   u32 Nl, Nh;
   u32 data[16];
   unsigned int num;
} SM3_CTX;

typedef struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int *init;
    int *update;
    int *final;
    int *copy;
    int *cleanup;
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int *md_ctrl;
} EVP_MD;

typedef struct evp_md_ctx_st {
    const void *digest;
    void *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    void *pctx;
    /* Update function: usually copied from EVP_MD */
    int *update;
}EVP_MD_CTX;

typedef struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int *init;
    /* encrypt/decrypt data */
    int *do_cipher;
    /* cleanup ctx */
    int *cleanup;
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int *set_asn1_parameters;
    /* Get parameters from a ASN1_TYPE */
    int *get_asn1_parameters;
    /* Miscellaneous operations */
    int *ctrl;
    /* Application data */
    void *app_data;
}EVP_CIPHER;


typedef struct evp_cipher_ctx_st {
    const void *cipher;
    void *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[16]; /* original iv */
    unsigned char iv[16]; /* working iv */
    unsigned char buf[32]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[32]; /* possible final block */
}EVP_CIPHER_CTX;



typedef struct{
	volatile int *user_count;
	u32 *v_dma_buf;
	EVP_MD_CTX evp_md_ctx;
	SM3_CTX sm3_ctx;
} lib_phytium_sm3_context;

typedef struct{
	u32 scto_key[4];
	u32 mode;
	u32 cryptomode;
	volatile int *user_count;
	u32 *v_dma_buf;
	EVP_CIPHER_CTX evp_cipher_ctx;
	char data[128];
}lib_phytium_sm4_context;

typedef struct{
	int alg;
	union{
		lib_phytium_sm3_context psm3_ctx;
		lib_phytium_sm4_context psm4_ctx;
	};
}__attribute__((aligned(512))) phytium_scto_context;

typedef struct {
	u32 counter;
}__attribute__((aligned(64))) mepool_t;
#endif
