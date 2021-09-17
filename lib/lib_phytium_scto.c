/*
 * File Name:phytium_scto.c - Phytium driver for SDK
 *
 * Copyright (C) 2020 Phytium Technology Co.,Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include "lib_smx_common.h"
#include "lib_sm4_phytium.h"
#include "lib_sm3_phytium.h"
#include "lib_phytium_scto.h"

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


int phytium_scto_fd = -1;
static void *regs = NULL;
uint64_t *phytium_common_info_start = NULL;
phytium_scto_context *phytium_desc_start[(SCTO_DESC_NUM + 1) * sizeof(phytium_scto_context) / 0x400000 + 1] = {NULL};
static volatile mepool_t *mepool[(SCTO_DESC_NUM + 1) * sizeof(mepool_t) / 0x400000 + 1] = {NULL};
static void *dma_buf[SCTO_DESC_NUM + 1] = {NULL};

void *mem_alloc(int *desc_id)
{
	int id = 0, alloc_offset;
	
	alloc_offset = __atomic_fetch_add(&mepool[(SCTO_DESC_NUM + 1) * sizeof(mepool_t) / 0x400000][(0x400000 / sizeof(mepool_t)) - 1].counter, 1, __ATOMIC_SEQ_CST) & (SCTO_DESC_NUM - 1);

	id = __atomic_exchange_n(&mepool[alloc_offset / (0x400000 / sizeof(mepool_t))][alloc_offset & ((0x400000 / sizeof(mepool_t)) - 1)].counter, 0, __ATOMIC_SEQ_CST);
	
	if(id == alloc_offset + 1){
		*desc_id = id;
		return dma_buf[id];
	}else{
		if(unlikely(id))
			printf("error!id:%d, offset:%d\n", id, alloc_offset);
		return NULL;
	}
}

void mem_free(int desc_id)
{	
	if(unlikely((desc_id > SCTO_DESC_NUM) || (desc_id <= 0))){
		printf("mem_free error! desc_id:0x%x\n", desc_id);
		return;
	}

	mepool[(desc_id - 1) / (0x400000 / sizeof(mepool_t))][(desc_id - 1) & ((0x400000 / sizeof(mepool_t)) - 1)].counter = desc_id;
}

int lib_scto_init(void)
{
	uint64_t i;
	uint64_t pagesize = getpagesize();

	phytium_scto_fd = open("/dev/scto", O_RDWR|O_SYNC);
	if(phytium_scto_fd < 0){
		printf("open scto fail!\n");
		return -1;
	}

	regs = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, phytium_scto_fd, 0);
	if(regs == MAP_FAILED){
		printf("mmap regs fail!\n");
		return -1;
	}

	phytium_common_info_start = mmap(NULL, SCTO_DESC_NUM * 8 + 1024, PROT_READ, MAP_SHARED, phytium_scto_fd, pagesize);
	if(phytium_common_info_start == MAP_FAILED){
		printf("mmap common_info_start fail!\n");
		return -1;
	}

	for(i = 0; i < (SCTO_DESC_NUM + 1) * sizeof(phytium_scto_context) / 0x400000 + 1; i++){
		phytium_desc_start[i] = mmap(NULL, 0x400000, PROT_READ|PROT_WRITE, MAP_SHARED, phytium_scto_fd, ((0x2ul) | (i << 2)) * pagesize);
		if(phytium_desc_start[i] == MAP_FAILED){
			printf("mmap desc_start %lu fail!\n", i);
			return -1;
		}
	}

	for(i = 0; i < (SCTO_DESC_NUM + 1) * sizeof(mepool_t) / 0x400000 + 1; i++){
		mepool[i] = mmap(NULL, 0x400000, PROT_READ|PROT_WRITE, MAP_SHARED, phytium_scto_fd, ((0x3ul) | (i << 2)) * pagesize);
		if(mepool[i] == MAP_FAILED){
			printf("mmap mepool %lu fail!\n", i);
			return -1;
		}
	}

	for(i = 1; i <= SCTO_DESC_NUM; i++){
		dma_buf[i] = mmap(NULL, PER_DESC_DMA_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, phytium_scto_fd, phytium_common_info_start[i]);
		if(dma_buf[i] == MAP_FAILED){
			printf("mmap dma_buf[%lu] fail!\n", i);
			return -1;
		}
	}

	return 0;
}

int get_rand_data(unsigned char *buf, int len)
{
	int ret_bytes = 0,loop = 0, offset = 0,retry_cnt = 0;
	if (buf)
	{
		while (offset < len)
		{
retry:
			//printf("offset is:%d\n",offset);
			ret_bytes = read(phytium_scto_fd, buf + offset, len - offset);
			if (ret_bytes > 0)
				offset += ret_bytes;
			else if (ret_bytes == 0)
			{
				retry_cnt++;
				if (retry_cnt >= 10000)
					return offset;
				goto retry;
			}
			else
				return offset;
		}
	}
	return offset;
}

