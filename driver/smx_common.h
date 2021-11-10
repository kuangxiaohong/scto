/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SMX_H_
#define _SMX_H_


//0-use ACPI table; 1-register platform device PHYTSCTO
#define SCTO_REGISTER_SELF	(1)
//0-user space mode; 1-kernel space mode
#define SCTO_KERNEL_MODE	(0)

#if SCTO_KERNEL_MODE
#define SCTO_DESC_NUM	(1)
#define PER_DESC_DMA_BUF_SIZE	(4096)
#else
//256, 512, 1024, 2048, 4096, 8192, 16384, 32768
#define SCTO_DESC_NUM	(16384)
//256,4096, 8192, 16384, 32768, 65536
#define PER_DESC_DMA_BUF_SIZE	(65536)
#endif




/*SMX register base address*/
#define SMX_BASE_ADDR				(0x28220000UL)
/*SMX DMA register base address*/
#define DMA_BASE_ADDR				(0x100)
/*SM4 register base address*/
#define SKE_BASE_ADDR				(0x1000)
/*SM3 register base address*/
#define HASH_BASE_ADDR				(0x2000)
/*TRNG register base address*/
#define TRNG_BASE_ADDR				(0x3000)
/*PKE register base address*/
#define PKE_BASE_ADDR				(0x5000)


#define PHYTIUM_SM3_DMA_BUF_SIZE             (0x100000)
#ifdef D2000
#define PHYTIUM_SM4_DMA_BUF_SIZE             (0x100000)
#else
#define PHYTIUM_SM4_DMA_BUF_SIZE             (0x100)
#endif

static inline u32 swap32(u32 val)
{
	__asm__("rev %w[dst], %w[src]":[dst]"=r"(val):[src]"r"(val));
	return val;
}

#define GET_UINT32_BE(n, b, i)				\
	do {						\
		(n) = swap32(*((u32*)&(b)[(i)]));\
	} while (0)

#define PUT_UINT32_BE(n, b, i)				\
	do {						\
		*((u32*)&(b)[(i)]) = swap32((n));		\
	} while (0)


static inline void smx_reverse_word(const void *in, void *out, u32 wordlen)
{
	u32 i;
	const u32 *input = in;
	u32 *output = out;

	for(i = 0; i < wordlen; i++)
		output[i] = swap32(input[i]);
}

static inline void smx_dma_reverse_word(const void *in, void *out, u32 wordlen)
{
	u32 i, j, tmp;
	const u32 *input = in;
	u32 *output = out;

	for (i = 0; i < wordlen; i += 4){
		for(j = 0; j < 2; j++){
			tmp = input[i + j];
			output[i + j] = swap32(input[i + 0x3 - j]);
			output[i + 0x3 - j] = swap32(tmp);
		}
	}
}
#endif

