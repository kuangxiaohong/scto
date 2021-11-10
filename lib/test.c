#define _GNU_SOURCE
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
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
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_alg.h>


#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/evp.h"


#include "lib_smx_common.h"
#include "lib_phytium_scto.h"
#include "lib_sm3_phytium.h"
#include "lib_sm4_phytium.h"



#define BUF_SIZE   (1024*1024)
pthread_t tid[16];
uint8_t randomdata[8][BUF_SIZE] = {0};

volatile int multestsize = 0;
volatile long multestnum[8][8] = {{0}};
volatile int running = 1;

int test_sm2_en = 0;
int test_sm2_de = 0;
int test_sm2_sign = 0;
int test_sm2_verify = 0;
int test_sm3_dgst = 0;
int test_sm3_hmac = 0;
int test_sm4_cbc = 0;
int test_sm4_ecb = 0;
int test_sm4_ctr = 0;
int test_kernel_sm4_cbc = 0;

int test_time = 0;
int thread_num = 1;
int test_num = 1;
int start_size = 1;
int test_size = 64;
int printf_data = 0;
void cpu_bind(pthread_t tid, int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	
	if(pthread_setaffinity_np(tid, sizeof(set), &set))
		printf("cpu_bind failed\n");
}

static int get_random_data(void *buf, uint32_t size)
{
	long len, offset;

restart:
	offset = 0;
	do{
		len = get_rand_data(buf + offset, size - offset);
		offset += len;
	}while((offset < size) && (len >= 0));
	
	if(offset != (long)size){
		printf("read random dev fail!offset:%ld size;%u\n", offset, size);
		return -1;
	}

	for(offset = 0; offset < size; offset ++){
		if(*((uint8_t*)buf + offset))
			break;
	}
	if(offset == size)
		goto restart;

	if(printf_data){
		printf("%s\n", __func__);
		for(offset = 0; offset < size; offset ++){
			printf("0x%02x ", *((uint8_t*)buf + offset));
			if((offset & 0xf) == 0xf)
				printf("\n");
		}
		printf("\n");
	}

	return 0;
}

static long get_gmssl_result(const char *cmd, void *buf, uint32_t size)
{
	long len, offset = 0;
	FILE *fd;

	fd = popen(cmd, "r");
	if(fd == NULL){
		printf("%s cmd:%s fail!\n", __func__, cmd);
		return -1;
	}

	do{
		len = fread(buf + offset, 1, size, fd);
		if(len > 0)
			offset += len;
	}while(len > 0);

	pclose(fd);

	if(printf_data){
		printf("%s\n", __func__);
		for(len = 0; len < offset; len ++){
			printf("0x%02x ", *((uint8_t*)buf + len));
			if((len & 0xf) == 0xf)
				printf("\n");
		}
		printf("\n");
	}
	
	return offset;
}

#if 1
int sm3_dgst_test(int testsize, int cpuid)
{
	int sm3_desc_id = -1;
	struct timeval start, end;
	unsigned long time;
	int len, i;
	char input[BUF_SIZE] = {0}, output[BUF_SIZE] = {0}, cmpbuf[BUF_SIZE] = {0};
	char cmd[1024];
	EVP_MD_CTX *ctx = NULL;
	int size, offset;

	memcpy(input, randomdata[cpuid], testsize);
	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm3_desc_id = -1;
			while(phytium_sm3_dma_init(&sm3_desc_id)){
			}
			phytium_sm3_dma_update(sm3_desc_id, input, testsize);
			phytium_sm3_dma_final(sm3_desc_id, output);
			if(sm3_desc_id > 0)
				mem_free(sm3_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto dgst success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
			sm3_desc_id = -1;
			while(phytium_sm3_dma_init(&sm3_desc_id)){
			}
			size = testsize;
			offset = 0;
			i = 0;
			while(size){
				get_random_data(&i, 2);
				if(i > size)
					i = size;
				phytium_sm3_dma_update(sm3_desc_id, input + offset, i);
				size -= i;
				offset += i;
			}
			phytium_sm3_dma_final(sm3_desc_id, output);
			if(sm3_desc_id > 0)
				mem_free(sm3_desc_id);
	}
	ctx = EVP_MD_CTX_new();
	if(ctx == NULL){
		printf("EVP_MD_CTX_new fail!\n");
		return -1;
	}
	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, input, testsize);
	EVP_DigestFinal_ex(ctx, cmpbuf, NULL);
	EVP_MD_CTX_free(ctx);

	if(memcmp(output, cmpbuf, 32)){
		printf("sm3 dgst error!\n");
		goto out;
	}

	return 0;

out:

	return -1;

}

int sm4_cbc_test(int testsize, int cpuid)
{
	int sm4_desc_id = -1;
	struct timeval start, end;
	unsigned long time;
	uint8_t input[BUF_SIZE] = {0}, output[BUF_SIZE] = {0}, cmpbuf[BUF_SIZE] = {0};
	uint8_t std_key[16] = {
		0xE0, 0x70, 0x99, 0xF1, 0xBF, 0xAF, 0xFD, 0x7F, 0x24, 0x0C, 0xD7, 0x90, 0xCA, 0x4F, 0xE1, 0x34
	};			
	uint8_t std_iv[16] = {
		0xC7, 0x2B, 0x65, 0x91, 0xA0, 0xD7, 0xDE, 0x8F, 0x6B, 0x40, 0x72, 0x33, 0xAD, 0x35, 0x81, 0xD6
	};
	int i;
	phytium_sm4_context ctx;
	EVP_CIPHER_CTX *ectx;
	int size, offset;

	memcpy(input, randomdata[cpuid], testsize);
	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CBC, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){
			}
			phytium_sm4_update(sm4_desc_id, input, testsize, output);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto cbc enc success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CBC, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){
		}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			i &= 0xFFF0;
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, input + offset, i, output + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}	
	ectx = EVP_CIPHER_CTX_new();
	if(ectx == NULL){
		printf("EVP_CIPHER_CTX_new fail!\n");
		return -1;
	}
	EVP_CipherInit_ex(ectx, EVP_sm4_cbc(), NULL, std_key, std_iv, 1);
	EVP_CipherUpdate(ectx, cmpbuf, &i, input, testsize);
	EVP_CipherFinal(ectx, cmpbuf + testsize, &i);
	EVP_CIPHER_CTX_free(ectx);

	if(memcmp(output, cmpbuf, testsize)){
		printf("sm4 cbc encrypt error!\n");
		return -1;
	}

	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CBC, SM4_CRYPTO_DECRYPT, std_key, std_iv)){
			}
			phytium_sm4_update(sm4_desc_id, output, testsize, cmpbuf);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto cbc dec success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CBC, SM4_CRYPTO_DECRYPT, std_key, std_iv)){
		}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			i &= 0xFFF0;
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, output + offset, i, cmpbuf + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}	
	
	if(memcmp(input, cmpbuf, testsize)){
		printf("sm4 cbc decrypt error!\n");
		return -1;
	}

	return 0;
}

int sm4_ecb_test(int testsize, int cpuid)
{
	phytium_sm4_context ctx;
	struct timeval start, end;
	unsigned long time;
	uint8_t input[BUF_SIZE] = {0}, output[BUF_SIZE] = {0}, cmpbuf[BUF_SIZE] = {0};	
	uint8_t std_key[16] = {
		0xE0, 0x70, 0x99, 0xF1, 0xBF, 0xAF, 0xFD, 0x7F, 0x24, 0x0C, 0xD7, 0x90, 0xCA, 0x4F, 0xE1, 0x34
	};			
	int i;
	int sm4_desc_id = -1;
	EVP_CIPHER_CTX *ectx;
	int size, offset;

	memcpy(input, randomdata[cpuid], testsize);
	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_ECB, SM4_CRYPTO_ENCRYPT, std_key, NULL)){}
			phytium_sm4_update(sm4_desc_id, input, testsize, output);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("TA ecb enc success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_ECB, SM4_CRYPTO_ENCRYPT, std_key, NULL)){}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			i &= 0xFFF0;
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, input + offset, i, output + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}
	
	ectx = EVP_CIPHER_CTX_new();
	if(ectx == NULL){
		printf("EVP_CIPHER_CTX_new fail!\n");
		return -1;
	}
	EVP_CipherInit_ex(ectx, EVP_sm4_ecb(), NULL, std_key, NULL, 1);
	EVP_CipherUpdate(ectx, cmpbuf, &i, input, testsize);
	EVP_CipherFinal(ectx, cmpbuf + testsize, &i);
	EVP_CIPHER_CTX_free(ectx);
	if(memcmp(output, cmpbuf, testsize)){
		printf("sm4 ecb encrypt error!\n");
		return -1;
	}

	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_ECB, SM4_CRYPTO_DECRYPT, std_key, NULL)){}
			phytium_sm4_update(sm4_desc_id, output, testsize, cmpbuf);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto ecb dec success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_ECB, SM4_CRYPTO_DECRYPT, std_key, NULL)){}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			i &= 0xFFF0;
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, output + offset, i, cmpbuf + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}	
	
	if(memcmp(input, cmpbuf, testsize)){
		printf("sm4 ecb decrypt error!\n");
		return -1;
	}

	return 0;
}


int sm4_ctr_test(int testsize, int cpuid)
{
	phytium_sm4_context ctx;
	struct timeval start, end;
	unsigned long time;
	uint8_t input[BUF_SIZE] = {0}, output[BUF_SIZE] = {0}, cmpbuf[BUF_SIZE] = {0};	
	uint8_t std_key[16] = {
		0xE0, 0x70, 0x99, 0xF1, 0xBF, 0xAF, 0xFD, 0x7F, 0x24, 0x0C, 0xD7, 0x90, 0xCA, 0x4F, 0xE1, 0x34
	};			
	uint8_t std_iv[16] = {
		0xC7, 0x2B, 0x65, 0x91, 0xA0, 0xD7, 0xDE, 0x8F, 0x6B, 0x40, 0x72, 0x33, 0xAD, 0x35, 0x81, 0xD6
	};
	int i;
	int sm4_desc_id = -1;
	EVP_CIPHER_CTX *ectx;
	int size, offset;

	//memset(std_iv, 0xff, 16);
	memcpy(input, randomdata[cpuid], testsize);
	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CTR, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){}
			phytium_sm4_update(sm4_desc_id, input, testsize, output);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );


		time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
		      + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto ctr enc success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CTR, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, input + offset, i, output + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}	
	
	ectx = EVP_CIPHER_CTX_new();
	if(ectx == NULL){
		printf("EVP_CIPHER_CTX_new fail!\n");
		return -1;
	}
	EVP_CipherInit_ex(ectx, EVP_sm4_ctr(), NULL, std_key, std_iv, 1);
	EVP_CipherUpdate(ectx, cmpbuf, &i, input, testsize);
	EVP_CipherFinal(ectx, cmpbuf + testsize, &i);
	EVP_CIPHER_CTX_free(ectx);

	if(memcmp(output, cmpbuf, testsize)){
		printf("sm4 ctr encrypt error!\n");
		return -1;
	}

	if(multestsize){
		gettimeofday( &start, NULL );
		for(i = 0; i < test_num; i++){
			sm4_desc_id = -1;
			while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CTR, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){}
			phytium_sm4_update(sm4_desc_id, output, testsize, cmpbuf);
			if(sm4_desc_id > 0)
				mem_free(sm4_desc_id);
			multestnum[cpuid][0]++;
		}
		gettimeofday( &end, NULL );
		
	    time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
	          + ( end.tv_usec - start.tv_usec );

		if(test_time)
			printf("scto ctr dec success, testnum:%d, testsize:%d, speed；%ld MBps\n", test_num, testsize, (long)test_num * testsize/time);
	}else{
		sm4_desc_id = -1;
		while(phytium_sm4_init(&sm4_desc_id, SM4_MODE_CTR, SM4_CRYPTO_ENCRYPT, std_key, std_iv)){}
		size = testsize;
		offset = 0;
		i = 0;
		while(size){
			get_random_data(&i, 2);
			if(i > size)
				i = size;
			phytium_sm4_update(sm4_desc_id, output + offset, i, cmpbuf + offset);
			size -= i;
			offset += i;
		}
		if(sm4_desc_id > 0)
			mem_free(sm4_desc_id);
	}	
	
	if(memcmp(input, cmpbuf, testsize)){
		printf("sm4 ctr decrypt error!\n");
		return -1;
	}

	return 0;
}

int kernel_sm4_cbc_test(int testsize, int cpuid, int op_fd)
{
	struct timeval start, end;
	unsigned long time;
	uint8_t input[BUF_SIZE] = {0}, output[BUF_SIZE] = {0}, cmpbuf[BUF_SIZE] = {0};
	uint8_t std_key[16] = {
		0xE0, 0x70, 0x99, 0xF1, 0xBF, 0xAF, 0xFD, 0x7F, 0x24, 0x0C, 0xD7, 0x90, 0xCA, 0x4F, 0xE1, 0x34
	};			
	uint8_t std_iv[16] = {
		0xC7, 0x2B, 0x65, 0x91, 0xA0, 0xD7, 0xDE, 0x8F, 0x6B, 0x40, 0x72, 0x33, 0xAD, 0x35, 0x81, 0xD6
	};
	int i, tmp;
	EVP_CIPHER_CTX *ectx;
	int size, offset;
	memcpy(input, randomdata[cpuid], testsize);

	struct af_alg_iv *alg_iv;
	struct cmsghdr *header;
	uint32_t *type;
	struct iovec iov;
	int iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + 16);
	char buffer[CMSG_SPACE(sizeof(*type)) + iv_msg_size];
	struct msghdr msg;


	size = testsize;
	offset = 0;
	i = 0;
	while(size){
		get_random_data(&i, 2);
		i &= 0xFFF0;
		if(i > size)
			i = size;

		memset(buffer, 0, sizeof(buffer));

		iov.iov_base = input + offset,
		iov.iov_len = i,

		msg.msg_control = buffer,
		msg.msg_controllen = sizeof(buffer),
		msg.msg_iov = &iov,
		msg.msg_iovlen = 1,

		/* Set encrypt/decrypt operation */
		header = CMSG_FIRSTHDR(&msg);
		if (!header)
			return -EINVAL;

		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_OP;
		header->cmsg_len = CMSG_LEN(sizeof(*type));
		type = (void*)CMSG_DATA(header);
		*type = ALG_OP_ENCRYPT;

		/* Set IV */
		header = CMSG_NXTHDR(&msg, header);
		if (!header)
			return -EINVAL;

		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = 16;
		if(offset == 0){
			memcpy(alg_iv->iv, std_iv, 16);
		}else{
			memcpy(alg_iv->iv, output + offset - 16, 16);
		}


		tmp = sendmsg(op_fd, &msg, 0);
		if(tmp != i)
			return -1;
		else{
			tmp = read(op_fd, output + offset, i);
			if(tmp != i)
				return -1;
		}

		size -= i;
		offset += i;
	}

		
	ectx = EVP_CIPHER_CTX_new();
	if(ectx == NULL){
		printf("EVP_CIPHER_CTX_new fail!\n");
		return -1;
	}
	EVP_CipherInit_ex(ectx, EVP_sm4_cbc(), NULL, std_key, std_iv, 1);
	EVP_CipherUpdate(ectx, cmpbuf, &i, input, testsize);
	EVP_CipherFinal(ectx, cmpbuf + testsize, &i);
	EVP_CIPHER_CTX_free(ectx);

	if(memcmp(output, cmpbuf, testsize)){
		printf("sm4 kernel cbc encrypt error!\n");
		return -1;
	}

	size = testsize;
	offset = 0;
	i = 0;
	while(size){
		get_random_data(&i, 2);
		i &= 0xFFF0;
		if(i > size)
			i = size;

		memset(buffer, 0, sizeof(buffer));

		iov.iov_base = output + offset,
		iov.iov_len = i,

		msg.msg_control = buffer,
		msg.msg_controllen = sizeof(buffer),
		msg.msg_iov = &iov,
		msg.msg_iovlen = 1,

		/* Set encrypt/decrypt operation */
		header = CMSG_FIRSTHDR(&msg);
		if (!header)
			return -EINVAL;

		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_OP;
		header->cmsg_len = CMSG_LEN(sizeof(*type));
		type = (void*)CMSG_DATA(header);
		*type = ALG_OP_DECRYPT;

		/* Set IV */
		header = CMSG_NXTHDR(&msg, header);
		if (!header)
			return -EINVAL;

		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = 16;
		if(offset == 0){
			memcpy(alg_iv->iv, std_iv, 16);
		}else{
			memcpy(alg_iv->iv, output + offset - 16, 16);
		}


		tmp = sendmsg(op_fd, &msg, 0);
		if(tmp != i)
			return -1;
		else{
			tmp = read(op_fd, cmpbuf + offset, i);
			if(tmp != i)
				return -1;
		}

		size -= i;
		offset += i;
	}
	
	if(memcmp(input, cmpbuf, testsize)){
		printf("sm4 kernel cbc decrypt error!\n");
		return -1;
	}

	return 0;
}

#endif

long count[8] = {0};

void * test(void*arg)
{
	long i = (long)arg;
	cpu_bind(tid[i], (i + 1) & 7);
	int size = start_size;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(sm4)",
	};
	int tfm_fd = -1, op_fd;
	uint8_t std_key[16] = {
		0xE0, 0x70, 0x99, 0xF1, 0xBF, 0xAF, 0xFD, 0x7F, 0x24, 0x0C, 0xD7, 0x90, 0xCA, 0x4F, 0xE1, 0x34
	};

	get_random_data(randomdata[i], test_size);

	if(test_kernel_sm4_cbc){
		tfm_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
		if(tfm_fd < 0) {
			return NULL;
		}
		if(bind(tfm_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0){
			return NULL;
		}

		if(setsockopt(tfm_fd, SOL_ALG, ALG_SET_KEY, std_key, 16) < 0){
			return NULL;
		}
		
		op_fd = accept(tfm_fd, NULL, 0);
		if(op_fd < 0){
			return NULL;
		}
	}

	while(running){
		if(multestsize)
			size = multestsize;
		if(test_sm3_dgst && sm3_dgst_test(size, i))
			break;
#if 1
		if(test_sm4_cbc && sm4_cbc_test((size + 0xF) & 0xFFFFFFF0, i))
			break;
		if(test_sm4_ecb && sm4_ecb_test((size + 0xF) & 0xFFFFFFF0, i))
			break;
		if(test_sm4_ctr && sm4_ctr_test(size, i))
			break;
		if(test_kernel_sm4_cbc){
			if(kernel_sm4_cbc_test((size + 0xF) & 0xFFFFFFF0, i, op_fd))
				break;
		}
#endif
		size ++;
		if(size > test_size){
			get_random_data(randomdata[i], test_size);
			size = start_size;
		}
		count[i]++;	
	}

	if(test_kernel_sm4_cbc){
		close(tfm_fd);
		close(op_fd);
	}

	test_num = 0;
	running = 0;

	return NULL;
}

void * print(void*arg)
{
	struct timeval start, end;
	unsigned long time, startcount, endcount;
	int i;
	while(running){
		startcount = 0;
		endcount = 0;
		printf("count:%ld %ld %ld %ld %ld %ld %ld %ld\n",
				count[0],
				count[1],
				count[2],
				count[3],
				count[4],
				count[5],
				count[6],
				count[7]);
		gettimeofday( &start, NULL );
		for(i = 0; i < 8; i++)
			startcount += multestnum[i][0];
		sleep(2);
		gettimeofday( &end, NULL );
		for(i = 0; i < 8; i++)
			endcount += multestnum[i][0];
		time = ( end.tv_sec  - start.tv_sec  ) * 1000000ul
          + ( end.tv_usec - start.tv_usec );
		if(multestsize)
			printf("multestsize:%d, startcount:0x%lx speed:%ld MBps\n", multestsize, startcount, (endcount - startcount) * multestsize/time);
	}

}

void print_help(void)
{
	printf("-s (1-12)  1:sm2_en 2:sm2_de 3:sm2_sign 4:sm2_verify 5:sm3_dgst 6:sm3_hmac 7:sm4_cbc 8:sm4_ecb 9:sm4_ctr 10:kernel_sm4_cbc\n");
	printf("-t          test_time\n");
	printf("-n  num     test_num\n");
	printf("-l          test_size\n");
	printf("-a  num     thread_num(1-8)\n");
	printf("example: ./scto -s 5 -l 10000 -a 1\n");
}

static void signal_handler(int signal)
{
	printf("signal:%d SIGINT:%d\n", signal, SIGINT);

	test_num = 0;
	running = 0;
}



//DEBUG_INIT  0xC2000F06  0  1

int main(int argc, char *argv[])
{
	
	long i, ret;
	pthread_t ltid;
	int flag = 1, sflag = 0;

	int ch;
	while ((ch = getopt(argc, argv, "m:s:tn:l:a:hp")) != -1){
		switch(ch){
			case 'm':
				i = atol(optarg);
				multestsize = i;
				break;
			case 's':
				i = atol(optarg);
				switch(i){
					case 1: test_sm2_en = 1;break;
					case 2: test_sm2_de = 1;break;
					case 3: test_sm2_sign = 1;break;
					case 4: test_sm2_verify = 1;break;
					case 5: test_sm3_dgst = 1;break;
					case 6: test_sm3_hmac = 1;break;
					case 7: test_sm4_cbc = 1;break;
					case 8: test_sm4_ecb = 1;break;
					case 9: test_sm4_ctr = 1;break;
					case 10:test_kernel_sm4_cbc = 1;break;
					default:break;
				}
				flag = 0;
				break;
			case 't':
				test_time = 1;
				break;
			case 'n':
				i = atol(optarg);
				test_num = i;
				break;
			case 'l':
				i = atol(optarg);
				if(sflag == 0){
					test_size = i;
					sflag = 1;
				}else if(sflag == 1){
					if(test_size < i){
						start_size = test_size;
						test_size = i;
					}else{
						start_size = i;
					}
					sflag = 2;
				}
				break;
			case 'a':
				i = atol(optarg);
				thread_num = i % 9;
				break;
			case 'h':
				print_help();
				return 0;
			case 'p':
				printf_data = 1;
				break;
			default:
				break;
		}
	}

	if(flag){
		test_sm3_dgst = 1;
		test_sm4_cbc = 1;
		test_sm4_ecb = 1;
		test_sm4_ctr = 1;
	}

	signal(SIGINT, signal_handler);

	ret = lib_scto_init();
	if(ret < 0)
		return -1;

	ERR_load_BIO_strings();
	ENGINE_load_builtin_engines();
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);


	for(i = 0; i < thread_num; i++){
		ret = pthread_create(&tid[i], NULL, test, (void*)i);
		if(ret){
			printf("pthread create failed!\n");
			return ret;
		}
	}

	ret = pthread_create(&ltid, NULL, print, (void*)i);
	if(ret){
		printf("pthread create failed!\n");
		return ret;
	}

	while(running){
		sleep(1);
	}
	return 0;
}


