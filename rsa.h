/* interface for plain RSA.
 * NOTE: this is *INSECURE* for almost any application other
 * than the KEM to which we apply it.  Don't use it alone. */
#pragma once
#include <gmp.h>

typedef struct _RSA_KEY
{
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
