#pragma once
#include <gmp.h>
#include <math.h>

#define KEYBYTES ceil((mpz_sizeinbase(K->n, 2)*1.0)/CHAR_BIT)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define ISPRIME(x) mpz_probab_prime_p(x,10)

typedef struct _RSA_KEY {
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t e;
	mpz_t d;
} RSA_KEY;

int rsa_keyGen(RSA_KEY *K);
int rsa_generate_keys(int generate, const char *dh_p);
int rsa_load_keys(RSA_KEY *key, int private_key);
int rsa_encrypt(RSA_KEY *key, const unsigned char *plaintext_buf, size_t plaintext_len, unsigned char *encrypted_buf, size_t *encrypted_len);
int rsa_decrypt(RSA_KEY *key, const unsigned char *encrypted_buf, size_t encrypted_len, unsigned char *plaintext_buf, size_t *plaintext_len);
