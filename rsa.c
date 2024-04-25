// Originally, I was going to use OpenSSL to do RSA; however, trying to understand the manpages enough to only use non-deprecated functions was so complicated, I decided to just copy my code from Project 1

#include "rsa.h"
#include "prf.h"

char *rsa_get_full_file_name(const char *fn, int public)
{
    char *suffix;
    if (public)
    {
        suffix = ".pub";
    }
    else
    {
        suffix = "";
    }

    int fn_len = strlen(fn);
    int suffix_len = strlen(suffix);

    char *filename = malloc(fn_len + suffix_len + 1); // While filenames on Linux are limited to 255 bytes, the full paths are not. So, we allocate enough space for basenames (filenames without extensions) that are 255, so we can fit the rest in.

    memcpy(filename, fn, fn_len);
    memcpy(filename + fn_len, suffix, suffix_len);
    filename[fn_len + suffix_len] = 0;

    return filename;
}

int rsa_initKey(RSA_KEY *K)
{
    mpz_init(K->d);
    mpz_set_ui(K->d, 0);
    mpz_init(K->e);
    mpz_set_ui(K->e, 0);
    mpz_init(K->p);
    mpz_set_ui(K->p, 0);
    mpz_init(K->q);
    mpz_set_ui(K->q, 0);
    mpz_init(K->n);
    mpz_set_ui(K->n, 0);
    return 0;
}

#define KEYBITS 2048 // This should be strong enough

int rsa_keyGen(RSA_KEY *K)
{
    rsa_initKey(K); // Initialize key

    mpz_t *keys[2] = {&K->p, &K->q}; // Has to be an array of pointers; in C, arrays (which is what mpz_t is under the hood) are not assignable

    NEWZ(p_q); //|p-q|

    int keyBytes = (KEYBYTES / CHAR_BIT) / 2; //"key size" refers to the size of the modulus (n), not the p and q

    // Compare p and q
    unsigned char *buf = malloc(keyBytes);
    for (int i = 0; i < 2; i++)
    {
        while (1)
        {
            randBytes(buf, keyBytes);
            BYTES2Z(*keys[i], buf, keyBytes);

            mpz_sub(p_q, K->p, K->q);
            mpz_abs(p_q, p_q);
            if ((ISPRIME(*keys[i]) > 0) && (mpz_cmp_ui(p_q, 100000) > 0))
            { // Technically, we should check that ==2, but it will likely take a long time to get a probable pime. Additionally, the distance between p and q could be set higher.
                break;
            }
        }
    }

    mpz_mul(K->n, K->p, K->q); // n=p*q

    NEWZ(p_1); // p-1
    mpz_sub_ui(p_1, K->p, 1);

    NEWZ(q_1); // q-1
    mpz_sub_ui(q_1, K->q, 1);

    NEWZ(totient); // totient(n)=lcm(totient(p),totient(q))=lcm(p-1,q-1); totient(n)=(p-1)(q-1) will also work (since it is divisible by lcm(p-1,q-1))
    mpz_lcm(totient, p_1, q_1);

    // Generating e
    NEWZ(modulus); //((totient-1)-3+1)=totient-3
    mpz_sub_ui(modulus, totient, 3);

    NEWZ(gcd_e_tot); // gcd(e, totient)
    while (1)
    {
        randBytes(buf, keyBytes);
        BYTES2Z(K->e, buf, keyBytes); // 2 < e < totient -> 3 <= e <= totient-1 -> (rand()%((totient-1)-3+1))+3
        mpz_mod(K->e, K->e, modulus);
        mpz_add_ui(K->e, K->e, 3);

        mpz_gcd(gcd_e_tot, K->e, totient);
        if (mpz_cmp_ui(gcd_e_tot, 1) == 0)
        { // gcd(e, totient)==1. We could just just hardcode e=3, but that could lose some entropy
            break;
        }
    }

    // Computing d
    // Since e and totient were specifically chosen to be co-prime, then e*d+totient*t=1 (due to Bézout's identity). This means that e*d =1 mod n -> d=e^(-1) mod n
    mpz_gcdext(NULL, K->d, NULL, K->e, totient); // a*s+b*t=g

    while (mpz_cmp_si(K->d, 0) <= 0)
    { // Forces d to be positive. Not the most efficient, but given the unwieldy C interface, this is easier to reason about
        mpz_add(K->d, K->d, totient);
    }

    free(buf);
    return 0;
}

#include <openssl/err.h>

int rsa_encrypt(RSA_KEY *key, const unsigned char *plaintext_buf, size_t plaintext_len, unsigned char *encrypted_buf, size_t *encrypted_len)
{
    if (!key || !plaintext_buf || !encrypted_buf || !encrypted_len)
    {
        fprintf(stderr, "Invalid parameters for RSA encryption.\n");
        return 0;
    }

    BIGNUM *n_bn = BN_new();
    BIGNUM *e_bn = BN_new();
    BN_gmp_export(n_bn, 0, key->n);
    BN_gmp_export(e_bn, 0, key->e);

    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, n_bn, e_bn, NULL);

    int result = RSA_public_encrypt(plaintext_len, plaintext_buf, encrypted_buf, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1)
    {
        char err_msg[130] = {0};
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err_msg);
        fprintf(stderr, "RSA encryption failed: %s\n", err_msg);
        RSA_free(rsa);
        return 0;
    }

    *encrypted_len = result;
    RSA_free(rsa);
    return 1;
}

int rsa_decrypt(RSA_KEY *key, const unsigned char *encrypted_buf, int encrypted_len,
                unsigned char *plaintext_buf, int *plaintext_len)
{
    if (!key || !encrypted_buf || !plaintext_buf || !plaintext_len)
    {
        fprintf(stderr, "Invalid parameters for RSA decryption.\n");
        return -1;
    }

    BIGNUM *n_bn = BN_new(), *d_bn = BN_new();
    BN_gmp_export(n_bn, 0, key->n);
    BN_gmp_export(d_bn, 0, key->d);

    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, n_bn, NULL, d_bn);

    int rsa_size = RSA_size(rsa);
    if (*plaintext_len < rsa_size)
    {
        fprintf(stderr, "Plaintext buffer too small for decryption.\n");
        RSA_free(rsa);
        return -1;
    }

    int result = RSA_private_decrypt(encrypted_len, encrypted_buf, plaintext_buf, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1)
    {
        unsigned long err = ERR_get_error();
        char err_msg[120];
        ERR_error_string(err, err_msg);
        fprintf(stderr, "RSA decryption failed: %s\n", err_msg);
        RSA_free(rsa);
        return -1;
    }

    *plaintext_len = result;
    if (result < rsa_size)
    {
        memset(plaintext_buf + result, 0, rsa_size - result);
    }

    RSA_free(rsa);
    return 0;
}