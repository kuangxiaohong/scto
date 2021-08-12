KERN_DIR=/lib/modules/$(shell uname -r)/build
  
all:
	make -C $(KERN_DIR) M=`pwd` modules 
  
clean:
	make -C $(KERN_DIR) M=`pwd` modules clean
	rm -rf modules.order
  
obj-m    += scto.o
scto-objs := phytium_scto.o sm3_phytium.o sm4_phytium.o
