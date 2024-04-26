//Originally, I was going to use OpenSSL to do RSA; however, trying to understand the manpages enough to only use non-deprecated functions was so complicated, I decided to just copy my code from Project 1

#include "z.h"

typedef struct _RSA_KEY {
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t e;
	mpz_t d;
} RSA_KEY;

void rsa_generate_keys(char* fn_prefix, size_t n_lower_bound);
/* NOTE: inBuf, when interpreted as a integer, must be less than K->n */
void rsa_encrypt(RSA_KEY* K,  char* inBuf, size_t len,  char* outBuf);

void rsa_decrypt(RSA_KEY* K, char* outBuf, size_t outLen,  char* inBuf, size_t inLen);

int rsa_load_keys(char* keyPath, RSA_KEY* key, size_t n_lower_bound, int priv);
