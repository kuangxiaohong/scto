#ifndef __LIB_SM3_PHYTIUM_H__
#define __LIB_SM3_PHYTIUM_H__

/*API*/
int phytium_sm3_dma_init(int *desc_id);
int phytium_sm3_dma_update(int desc_id, const uint8_t *data, unsigned int len);
int phytium_sm3_dma_final(int desc_id, uint8_t *out);
#endif
