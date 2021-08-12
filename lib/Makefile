CFLAG += -I ${PWD}/../../openssl/openssl-1.1.1d/include/openssl
CFLAG += -I ${PWD}/../../openssl/openssl-1.1.1d/crypto/include/internal
CFLAG += -I ${PWD}/../../openssl/openssl-1.1.1d/include

LFLAG += ${PWD}/../../openssl/openssl-1.1.1d/libcrypto.so



all:dynamic
static:
	gcc -g -I${PWD}/../include/ -c lib_phytium_scto.c -o lib_phytium_scto.o -O3 ${CFLAG}
	gcc -g -I${PWD}/../include/ -c lib_sm3_phytium.c -o lib_sm3_phytium.o -O3 ${CFLAG}
	gcc -g -I${PWD}/../include/ -c lib_sm4_phytium.c -o lib_sm4_phytium.o -O3 ${CFLAG}
	ar rcu libscto.a lib_phytium_scto.o lib_sm3_phytium.o lib_sm4_phytium.o
	gcc -g -I${PWD}/../include/ test.c -o sctotest -lpthread libscto.a -O3 -ldl ${CFLAG} ${LFLAG}
dynamic:  
	gcc -g  -I${PWD}/../include/ -c -fPIC   lib_phytium_scto.c -o lib_phytium_scto.o -O3 ${CFLAG}
	gcc -g  -I${PWD}/../include/ -c -fPIC lib_sm3_phytium.c -o lib_sm3_phytium.o -O3 ${CFLAG}
	gcc -g  -I${PWD}/../include/ -c -fPIC  lib_sm4_phytium.c -o lib_sm4_phytium.o -O3 ${CFLAG}
	gcc -g  -I${PWD}/../include/ -shared  -o libscto.so lib_phytium_scto.o lib_sm3_phytium.o lib_sm4_phytium.o ${LFLAG}
	gcc -g -I${PWD}/../include/ test.c -o sctotest -lpthread ./libscto.so -O3  -ldl ${CFLAG} ${LFLAG}
clean:
	rm -f *.o *.a *.so sctotest
