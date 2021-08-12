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

int scto_fd = -1;
void *regs = NULL;
uint64_t *common_info_start = NULL;
phytium_scto_context *desc_start = NULL;
volatile mepool_t *mepool = NULL;
volatile int mepool_offset = 0;
void *dma_buf[257] = {NULL};
pthread_key_t pkey;

void *mem_alloc(int *desc_id)
{
	int id = 0, alloc_offset;
	int cpuid, *cpu;

	cpu = pthread_getspecific(pkey);
	if(unlikely(cpu == NULL)){
		read(scto_fd, &cpuid, 4);
		cpu = malloc(64);
		if(cpu){
			*cpu = cpuid;
			pthread_setspecific(pkey, cpu);
		}
	}else{
		cpuid = *cpu;
	}

CONTINUE:	
	alloc_offset = __atomic_fetch_add(&mepool[1024 + cpuid].counter, 1, __ATOMIC_SEQ_CST) & 0x1F;

	id = __atomic_exchange_n(&mepool[alloc_offset + cpuid * 32].counter, 0, __ATOMIC_SEQ_CST);
	
	if((id > 0) && (id <= 256)){
		*desc_id = id;
		return dma_buf[id];
	}else{
		goto CONTINUE;
	}
}

void mem_free(int desc_id)
{
	if(unlikely((desc_id > 256) || (desc_id <= 0))){
		printf("mem_free error! desc_id:0x%x\n", desc_id);
		return;
	}

	mepool[desc_id - 1].counter = desc_id;
}



int lib_scto_init(void)
{
	int i;
	scto_fd = open("/dev/scto", O_RDWR|O_SYNC);
	if(scto_fd < 0){
		printf("open scto fail!\n");
		return -1;
	}

	regs = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, scto_fd, 0);
	if(regs == MAP_FAILED){
		printf("mmap regs fail!\n");
		return -1;
	}

	common_info_start = mmap(NULL, 0x40000, PROT_READ, MAP_SHARED, scto_fd, getpagesize());
	if(common_info_start == MAP_FAILED){
		printf("mmap common_info_start fail!\n");
		return -1;
	}

	desc_start = mmap(NULL, 0x40000, PROT_READ|PROT_WRITE, MAP_SHARED, scto_fd, 2 * getpagesize());
	if(desc_start == MAP_FAILED){
		printf("mmap desc_start fail!\n");
		return -1;
	}

	mepool = mmap(NULL, 0x40000, PROT_READ|PROT_WRITE, MAP_SHARED, scto_fd, 3 * getpagesize());
	if(mepool == MAP_FAILED){
		printf("mmap mepool fail!\n");
		return -1;
	}

	for(i = 1; i <= 256; i++){
		dma_buf[i] = mmap(NULL, 0x40000, PROT_READ|PROT_WRITE, MAP_SHARED, scto_fd, common_info_start[i]);
		if(dma_buf[i] == MAP_FAILED){
			printf("mmap dma_buf[%d] fail!\n", i);
			return -1;
		}
	}

	if(pthread_key_create(&pkey, NULL)){
		printf("pkey create fail!\n");
		return -1;
	}

	return 0;
}



