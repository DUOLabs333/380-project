#define AES_KEY_LEN 32
#define AES_IV_LEN 16

#include <stdlib.h>
void aes_encrypt(unsigned char* keyBuf, unsigned char* inBuf, size_t inLen, unsigned char* outBuf);

int aes_decrypt(unsigned char* keyBuf, unsigned char* outBuf, unsigned char* inBuf, size_t inLen);
