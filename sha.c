#include <openssl/hmac.h>

#define HMAC_KEY_LEN 32

char hmacKey[HMAC_KEY_LEN]="09134335359628506054549175336619"; //I want the hash to be deterministic
void sha256_hash(char* inBuf, size_t inLen, char* hashBuf, int hashLen){
	const EVP_MD *md = EVP_sha256();
	HMAC(md, hmacKey, hashLen, (unsigned char*)inBuf, inLen, (unsigned char*)hashBuf, NULL);
}


