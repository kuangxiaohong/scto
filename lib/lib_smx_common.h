#ifndef _LIB_SMX_COMMON_H_
#define _LIB_SMX_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/evp.h"


//256, 512, 1024, 2048, 4096, 8192, 16384, 32768
#define SCTO_DESC_NUM	(16384)
//256,4096, 8192, 16384, 32768, 65536
#define PER_DESC_DMA_BUF_SIZE	(65536)

#define PHYTIUM_SM3_DMA_SIZE	(PER_DESC_DMA_BUF_SIZE)
#ifdef D2000
#define PHYTIUM_SM4_DMA_SIZE	(PER_DESC_DMA_BUF_SIZE)
#else
#define PHYTIUM_SM4_DMA_SIZE	(256)
#endif

#define MAGIC_NUM    'p'
#define SCTO_SM3     _IO(MAGIC_NUM, 0)
#define SCTO_SM4     _IO(MAGIC_NUM, 1)

#define unlikely(x)    (__builtin_expect(!!(x), 0))
#define likely(x)    (__builtin_expect(!!(x), 1))

enum{
	ALG_SM3 = 0x20200730,
	ALG_SM4
};

typedef struct SM3state_st {
   uint32_t A, B, C, D, E, F, G, H;
   uint32_t Nl, Nh;
   uint32_t data[16];
   unsigned int num;
} SM3_CTX;
typedef struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} EVP_MD;

typedef struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
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
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
}EVP_CIPHER;


typedef struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
}EVP_CIPHER_CTX;

typedef struct{
	volatile int *user_count;
	uint32_t *v_dma_buf;
	EVP_MD_CTX evp_md_ctx;
	SM3_CTX sm3_ctx;
} phytium_sm3_context;

typedef struct{
	uint32_t scto_key[4];
	uint32_t mode;
	uint32_t cryptomode;
	volatile int *user_count;
	uint32_t *v_dma_buf;
	EVP_CIPHER_CTX evp_cipher_ctx;
	char data[128];
}phytium_sm4_context;

typedef struct{
	int alg;
	union{
		phytium_sm3_context psm3_ctx;
		phytium_sm4_context psm4_ctx;
	};
}__attribute__((aligned(512))) phytium_scto_context;

typedef struct{
	uint32_t counter;
}__attribute__((aligned(64))) mepool_t;

typedef struct{
	uint32_t num;
	uint32_t alloc_index;
	uint32_t free_index;
	uint32_t counter[0];
}per_thread_mepool_t;

extern int phytium_scto_fd;
extern uint64_t *phytium_common_info_start;
extern phytium_scto_context *phytium_desc_start[];
extern int phytium_per_desc_dma_buf_size;


static inline uint32_t swap32(uint32_t val)
{
	__asm__("rev %w[dst], %w[src]":[dst]"=r"(val):[src]"r"(val));
	return val;
}

#define GET_UINT32_BE(n, b, i)				\
	do {						\
		(n) = swap32(*((uint32_t*)&(b)[(i)]));\
	} while (0)

#define PUT_UINT32_BE(n, b, i)				\
	do {						\
		*((uint32_t*)&(b)[(i)]) = swap32((n));		\
	} while (0)


static inline void smx_reverse_word(const void *in, void *out, uint32_t wordlen)
{
	uint32_t i;
	const uint32_t *input = in;
	uint32_t *output = out;

	for(i = 0; i < wordlen; i++)
		output[i] = swap32(input[i]);
}

static inline void smx_dma_reverse_word(const void *in, void *out, uint32_t wordlen)
{
	uint32_t i, j, tmp;
	const uint32_t *input = in;
	uint32_t *output = out;

	for (i = 0; i < wordlen; i += 4){
		for(j = 0; j < 2; j++){
			tmp = input[i + j];
			output[i + j] = swap32(input[i + 0x3 - j]);
			output[i + 0x3 - j] = swap32(tmp);
		}
	}
}

#endif
