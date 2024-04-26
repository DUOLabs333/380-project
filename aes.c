#include "prf.h"
#include "aes.h"
#include <openssl/evp.h>
#include <string.h>

void aes_encrypt(unsigned char* keyBuf, unsigned char* inBuf, size_t inLen, unsigned char* outBuf){
	size_t size=0;

	unsigned char IV[AES_IV_LEN];
	randBytes(IV, AES_IV_LEN);
	
	memcpy(outBuf, IV, AES_IV_LEN);
	size+=AES_IV_LEN;

	int encryptedSize=0;
	int final_size=0;

	EVP_CIPHER_CTX *ctx;
	ctx=EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_padding(ctx,0); //We don't want any padding

	EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, keyBuf, IV);

	EVP_EncryptUpdate(ctx, outBuf+size, &encryptedSize, inBuf, inLen);
	size+=encryptedSize;

	EVP_EncryptFinal_ex(ctx, outBuf+size, &final_size);
	EVP_CIPHER_CTX_free(ctx);
}


int aes_decrypt(unsigned char* keyBuf, unsigned char* outBuf, unsigned char* inBuf, size_t inLen){

	 EVP_CIPHER_CTX *ctx;
     ctx = EVP_CIPHER_CTX_new();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, keyBuf, outBuf)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int size=0;
    size+=AES_IV_LEN;

    int decryptedSize=0;
    if (1 != EVP_DecryptUpdate(ctx, inBuf, &decryptedSize, outBuf+size, inLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    size+=decryptedSize;
    int final_len = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, inBuf+size, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    return 0;
}
