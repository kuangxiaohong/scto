#ifndef _LIB_SM4_PHYTIUM_H_
#define _LIB_SM4_PHYTIUM_H_

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

int phytium_sm4_init(int *desc_id, uint32_t mode, uint32_t cryptomode, const uint8_t *key, const uint8_t*iv);
int phytium_sm4_update(int desc_id, uint8_t*in, uint32_t len, uint8_t*out);

#endif
