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

#include <linux/module.h>
#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/acpi.h>
#include <crypto/internal/hash.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/akcipher.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include "smx_common.h"
#include "sm4_phytium.h"
#include "sm3_phytium.h"
#include "phytium_scto.h"

static u32 kernel_mode = 0;
struct scto_dev scto;
static struct resource *scto_resource = NULL;
static u64 *common_info_vaddr = NULL;
static phytium_scto_context *desc_vaddr = NULL;
static dma_addr_t paddr[256];
static void *vaddr[256] = {NULL};
static mepool_t *mepool = NULL;

//set the input iterator data 
static inline void lib_sm3_set_data(SM3_CTX *sm3_ctx)
{
	scto.hash_reg->hash_in[0] = sm3_ctx->A;
	scto.hash_reg->hash_in[1] = sm3_ctx->B;
	scto.hash_reg->hash_in[2] = sm3_ctx->C;
	scto.hash_reg->hash_in[3] = sm3_ctx->D;
	scto.hash_reg->hash_in[4] = sm3_ctx->E;
	scto.hash_reg->hash_in[5] = sm3_ctx->F;
	scto.hash_reg->hash_in[6] = sm3_ctx->G;
	scto.hash_reg->hash_in[7] = sm3_ctx->H;
}

static inline void lib_sm3_dma(long in, long out, uint32_t byteLen)
{
	int count = 0;

	//src addr
	scto.dma_reg->saddr0 = (in >> 2) & 0xFFFFFFFF;
	scto.dma_reg->saddr1 = (in >> 34) & 0x0FFF;

	//dst addr
	scto.dma_reg->daddr0 = (out >> 2) & 0xFFFFFFFF;
	scto.dma_reg->daddr1 = (out >>34) & 0x0FFF;

	//data word length
	scto.dma_reg->len = (byteLen >> 2);

	//clear flag
	scto.smx_reg->sr_2 = 2;

	//store cfg
	scto.smx_reg->cmd = 2;

	dsb(sy);
	//start
	scto.smx_reg->cr = 1;

	do{
		dsb(sy);
		if(unlikely(count++ > 1024))
			schedule();
		if(unlikely(count > 65536))
			break;
	}while(!(scto.smx_reg->sr_2 & 2));
}

static inline void lib_sm4_set_key(uint32_t *key)
{
	scto.ske_reg->key[0] = key[0];
	scto.ske_reg->key[1] = key[1];
	scto.ske_reg->key[2] = key[2];
	scto.ske_reg->key[3] = key[3];
}

static inline void lib_sm4_set_iv(uint32_t *iv)
{
	scto.ske_reg->iv[0] = iv[0];
	scto.ske_reg->iv[1] = iv[1];
	scto.ske_reg->iv[2] = iv[2];
	scto.ske_reg->iv[3] = iv[3];
}

static inline int lib_sm4_init(sm4_mode_e mode, int crypto, uint32_t *key, uint32_t *iv)
{
	uint32_t scto_iv[4];
	uint32_t cfg = 0;

	//set iv or nonce
	if(likely(mode != SM4_MODE_ECB)){
		smx_reverse_word(iv, scto_iv, SM4_BLOCK_WORD_LEN);
		lib_sm4_set_iv(scto_iv);
		cfg |= (1<<SKE_UPDATE_IV_OFFSET);
	}
	
	//config and check
	cfg |= (mode << SKE_MODE_OFFSET) | (crypto << SKE_CRYPTO_OFFSET);
	scto.ske_reg->cfg = cfg;

	//set key
	lib_sm4_set_key(key);
	
	return 0;
}

static void lib_sm4_dma(long in, long out, uint32_t byteLen)
{
	int count = 0;

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
		if(unlikely(count++ > 1024))
			schedule();
		if(unlikely(count > 65536))
			break;
	}while(!(scto.smx_reg->sr_2 & 1));
}




static void phytium_algs_unregister(void)
{
	sm3_phytium_dma_algs_unregister();
	sm4_phytium_dma_algs_unregister();
}

static int phytium_algs_register(struct scto_dev *scto)
{
	int ret;

	ret = sm3_phytium_dma_algs_register();
	if(ret)
		return -1;
	
	ret = sm4_phytium_dma_algs_register();
	if(ret){
		sm3_phytium_dma_algs_unregister();
		return -1;
	}

	return 0;
}

int scto_open(struct inode *inode, struct file *filep)
{
	return 0;
}

int scto_release(struct inode *inode, struct file *filep)
{
	return 0;
}

ssize_t scto_read(struct file *filep, char __user *buf, size_t len, loff_t *offset)
{
	int cpuid = smp_processor_id() & 0x7;

	if(unlikely(len < 4))
		return -1;

	if(unlikely(copy_to_user(buf, &cpuid, 4)))
		return -1;
	else
		return 4;
}

long  scto_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	phytium_scto_context *ctx;
	volatile int *user_count = (volatile int*)((long)common_info_vaddr + 0x10000);
	int desc_id, buf_len;

	if(unlikely((cmd != SCTO_SM3) && (cmd != SCTO_SM4)))
		return -1;

	__atomic_fetch_add(user_count, 1, __ATOMIC_SEQ_CST);

	desc_id = arg >> 32;
	buf_len = arg & 0xFFFFFFFF;
	ctx = &desc_vaddr[desc_id];
	
	mutex_lock(&scto.scto_lock);

	if(cmd == SCTO_SM3){
		lib_sm3_set_data(&ctx->psm3_ctx.sm3_ctx);
		lib_sm3_dma(common_info_vaddr[desc_id], common_info_vaddr[desc_id], buf_len);
	}else if(cmd == SCTO_SM4){
		lib_sm4_init(ctx->psm4_ctx.mode, ctx->psm4_ctx.cryptomode, ctx->psm4_ctx.scto_key, (u32*)ctx->psm4_ctx.evp_cipher_ctx.iv);
		lib_sm4_dma(common_info_vaddr[desc_id], common_info_vaddr[desc_id], buf_len);
	}

	mutex_unlock(&scto.scto_lock);

	__atomic_fetch_sub(user_count, 1, __ATOMIC_SEQ_CST);
	
	return 0;
}

int scto_mmap(struct file *filep, struct vm_area_struct *vma)
{
	unsigned long mmap_flag = vma->vm_pgoff;
	unsigned long pfn = vma->vm_pgoff;

	switch(mmap_flag){
		case 0:
			pfn = scto_resource->start >> PAGE_SHIFT;
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			break;
		case 1:
			pfn = virt_to_phys(common_info_vaddr) >> PAGE_SHIFT;
			break;
		case 2:
			pfn = virt_to_phys(desc_vaddr) >> PAGE_SHIFT;
			break;
		case 3:
			pfn = virt_to_phys(mepool) >> PAGE_SHIFT;
			break;
		default:
			break;
			
	}
	return remap_pfn_range(vma,
			       vma->vm_start,
			       pfn,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static const struct file_operations scto_fops = {
	.owner		= THIS_MODULE,
	.open		= scto_open,
	.release	= scto_release,
	.read		= scto_read,
	.mmap		= scto_mmap,
	.unlocked_ioctl		= scto_ioctl,
};

static struct cdev scto_pcdev;
static struct class *scto_pclass;
static dev_t scto_dev = 0;

static int scto_cdev_register(void)
{
	int ret;	

	ret = alloc_chrdev_region(&scto_dev, 0, 1, "scto");
	if(ret < 0){
        printk(KERN_ERR"alloc_chrdev_region fail\n");
        return -1;
	}

	cdev_init(&scto_pcdev, &scto_fops);
 
	ret = cdev_add(&scto_pcdev, scto_dev, 1);
	if (ret) {
        printk(KERN_ERR"cdev_add error!\n");
        goto err_0;
	}
 
	scto_pclass = class_create(THIS_MODULE, "scto");
	if(IS_ERR(scto_pclass)){
		printk(KERN_ERR "class_create fail!\n");
        goto err_1;
	}
 
	if(IS_ERR(device_create(scto_pclass, NULL, scto_dev, NULL, "scto"))){
		printk(KERN_ERR "device_create fail!\n\n");
		goto err_2;
	}
 
	return 0;
err_2:
		class_destroy(scto_pclass);
err_1:
        cdev_del(&scto_pcdev);
err_0:
        unregister_chrdev_region(scto_dev, 1);
        return -1;
}

static void scto_cdev_unregister(void)
{
 	device_destroy(scto_pclass, scto_dev);
	class_destroy(scto_pclass);
    cdev_del(&scto_pcdev);
    unregister_chrdev_region(scto_dev, 1);
}


static int scto_probe(struct platform_device *pdev)
{
	const struct acpi_device_id *match;
	struct device *dev = &pdev->dev;
	int err = 0;
	int i;

	if (has_acpi_companion(dev)) {
		match = acpi_match_device(dev->driver->acpi_match_table, dev);
		if (!match) {
			dev_err(dev, "Error ACPI match data is missing\n");
			return -ENODEV;
		}
		if(kernel_mode)
			acpi_dma_configure(dev, DEV_DMA_NON_COHERENT);
		else
			acpi_dma_configure(dev, DEV_DMA_COHERENT);
		dma_set_mask_and_coherent(dev, DMA_BIT_MASK(48));
	}

	scto_resource = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	scto.regs = devm_ioremap_resource(&pdev->dev, scto_resource);
	if (IS_ERR(scto.regs))
		return PTR_ERR(scto.regs);
	
	scto.hash_reg = (hash_reg_t *)(scto.regs + HASH_BASE_ADDR);
	scto.ske_reg = (ske_reg_t *)(scto.regs + SKE_BASE_ADDR);
	scto.dma_reg = (dma_reg_t *)(scto.regs + DMA_BASE_ADDR);
	scto.smx_reg = (smx_reg_t *)(scto.regs);

	scto.hash_reg->hash_cfg = 0;
	scto.hash_reg->hash_ctrl = 0x10000;
	scto.ske_reg->cfg = 0;
	scto.ske_reg->ctrl = 0x10000;
	scto.dma_reg->cfg |= 0x7;
	scto.dma_reg->cfg_aw = 0x01000270;
	scto.dma_reg->cfg_ar = 0x010002b0;
	scto.smx_reg->cfg = 0;

	atomic_set(&scto.sm3_wait_count, 0);
	atomic_set(&scto.sm4_wait_count, 0);
	mutex_init(&scto.scto_lock);
	mutex_init(&scto.dma_lock);
	mutex_init(&scto.sm2_lock);
	mutex_init(&scto.sm3_lock);
	mutex_init(&scto.sm4_lock);

	scto.dev = dev;

	common_info_vaddr = kzalloc(0x40000, GFP_KERNEL);
	if(common_info_vaddr == NULL){
		printk(KERN_ERR"kzalloc fail!\n");
		goto err;
	}

	desc_vaddr = kzalloc(0x40000, GFP_KERNEL);
	if(desc_vaddr == NULL){
		printk(KERN_ERR"kzalloc fail!\n");
		goto err;
	}

	mepool = kzalloc(0x40000, GFP_KERNEL);
	if(mepool == NULL){
		printk(KERN_ERR"kzalloc fail!\n");
		goto err;
	}

	for(i = 0; i < 256; i++){
		vaddr[i] = dma_alloc_coherent(dev, 0x40000, &paddr[i], GFP_KERNEL);
		if(vaddr[i] == NULL){
			printk(KERN_ERR"dma_alloc_coherent fail!\n");
			goto err;
		}
	}

	if(kernel_mode){
		err = phytium_algs_register(&scto);
		if(err){
			printk(KERN_ERR"phytium_algs_register fail!\n");
			goto err;
		}
	}else{
		err = scto_cdev_register();
		if(err){
			printk(KERN_ERR"scto_cdev_register fail!\n");
			goto err;
		}
	}

	for(i = 0; i < 256; i++){
		common_info_vaddr[i + 1] = virt_to_phys(vaddr[i]);
		mepool[i].counter = i + 1;
	}

	platform_set_drvdata(pdev, &scto);

	printk(KERN_INFO"scto probe success!\n");

	return 0;

err:

	if(common_info_vaddr)
		kfree(common_info_vaddr);

	if(desc_vaddr)
		kfree(desc_vaddr);

	if(mepool)
		kfree(mepool);

	for(i = 0; i < 256; i++){
		if(vaddr[i])
			dma_free_coherent(scto.dev, 0x40000, vaddr[i], paddr[i]);
	}
	
	return -1;
}

static int scto_remove(struct platform_device *pdev)
{
	int i;

	if(kernel_mode)
		phytium_algs_unregister();
	else
		scto_cdev_unregister();

	if(common_info_vaddr)
		kfree(common_info_vaddr);

	if(desc_vaddr)
		kfree(desc_vaddr);

	if(mepool)
			kfree(mepool);

	for(i = 0; i < 256; i++){
		if(vaddr[i])
			dma_free_coherent(scto.dev, 0x40000, vaddr[i], paddr[i]);
	}

	platform_set_drvdata(pdev, NULL);

	printk(KERN_INFO"scto remove!\n");
	return 0;
}

static const struct of_device_id scto_dma_of_match[] = {
	{ .compatible = "scto, scto_dma" },
	{}
};
MODULE_DEVICE_TABLE(of, scto_dma_of_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id phytium_scto_acpi_ids[] = {
		{ .id = "PHYT0012" },
		{}
};

MODULE_DEVICE_TABLE(acpi, phytium_scto_acpi_ids);
#else
#define phytium_scto_acpi_ids NULL
#endif

static struct platform_driver scto_driver = {
	.probe = scto_probe,
	.remove = scto_remove,
	.driver = {
	    .name = "scto_dma",
	    .of_match_table = scto_dma_of_match,
	    .acpi_match_table = phytium_scto_acpi_ids,
	}
};

module_platform_driver(scto_driver);
module_param(kernel_mode, uint, 0);
MODULE_DESCRIPTION("PHYTIUM SCTO");
MODULE_LICENSE("GPL");
