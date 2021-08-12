#ifndef __LIB_PHYTIUM_SCTO_H__
#define __LIB_PHYTIUM_SCTO_H__
void *mem_alloc(int *desc_id);
void mem_free(int desc_id);
int lib_scto_init(void);
#endif
